//! `stellar-agent trustline` subcommand — stablecoin `ChangeTrust` verb.
//!
//! # What this command does
//!
//! Builds, signs, and submits a Stellar `ChangeTrust` classic transaction.
//! Enforces the full ordered trust gate before signing:
//!
//! 1. `resolve_denomination` — USDT hard-refusal + known-lookalike denylist +
//!    pinned-issuer-mismatch + unpinned-bare-code.
//! 2. Live issuer account fetch via `fetch_account` → `AccountFlagsView`
//!    (for the clawback gate).
//! 3. Source account fetch via `fetch_account` (for the policy gate's
//!    `account_view`; sequence number consumed at envelope-build time).
//! 4. Operator policy evaluation — the shared
//!    [`crate::commands::policy_engine::build_v1_policy_engine`]
//!    (V1 `NoopPolicyEngine` / `PolicyEngineV1`; fail-closed on build failures),
//!    now that both views from steps 2-3 are populated. A denial is a clean
//!    refusal that signs nothing and requires no audit setup.
//! 5. Audit pre-flight (fail-closed) — the profile's audit
//!    chain-root key must be acquirable via
//!    [`crate::commands::value_audit::require_value_audit_writer`] before any
//!    later step touches the signer or submits; refuses
//!    `audit.chain_key_unavailable` otherwise. The acquired writer is reused
//!    for the post-confirm row.
//! 6. `clawback_gate(flags, opt_in_present)` where `opt_in_present` is derived
//!    from the wallet-controlled `PendingApprovalStore` (NOT a CLI flag).
//! 7. `TrustlinePreview::build` — the typed preview of the trustline.
//! 8. `RefuseWithWarning` / `Refuse` gate decisions → early return (exit 1).
//! 9. Build `ChangeTrust` envelope via `ClassicOpBuilder::change_trust`.
//! 10. Sign via keyring → submit → wait for confirmation.
//!
//! # Policy engine
//!
//! Uses `commands::policy_engine::build_v1_policy_engine`, shared with the
//! `vault` and `trade` CLI commands. Policy evaluation uses
//! `evaluate_value_moving_policy`; `derive_value_class` derives the `Trustline`
//! leg from `policy_args`. `commands::policy_engine::trustline_policy_args`
//! builds those arguments with the MCP `stellar_trustline` tool's `{from, asset}`
//! dispatch fields.
//! `account_view` is the fetched source account; `identity_view` is `None`
//! (the issuer's on-chain `home_domain` is self-asserted and must not feed
//! allowlist matching, so identity-class criteria configured on this verb
//! fail closed).
//!
//! # Output
//!
//! One JSON envelope on stdout. Returns `0` on success, `1` on error.
//!
//! The typed preview from step 7 is rendered once, as a nested `preview`
//! object, after the step 8 gate decision passes. It sits in `data.preview`
//! beside the submission result on success. It sits in
//! `error.details.preview` when a later stage fails: fee resolution, envelope
//! build, signing, or submission. A refusal up to and including the step 8
//! gate decision carries no preview.
//!
//! # Behavior
//!
//! The denomination resolver pins issuers and refuses USDT. A live issuer-flag
//! fetch feeds a named clawback gate that discloses clawback-enabled issuers.

use std::io::Write;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde_json::json;
use stellar_agent_network::NetworkContext;

use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, DEFAULT_TTL_MS, open_with_retry,
};
use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::schema::{Profile, default_approval_dir};

use crate::commands::policy_engine::{
    build_v1_policy_engine, evaluate_value_moving_policy, trustline_policy_args,
};

use stellar_agent_network::{
    AccountView, Asset, ClassicOpBuilder, StellarRpcClient, SubmissionSignerKind,
    enrolled_keyring_signer, fetch_account, init_platform_keyring_store, parse_classic_fee_choice,
    policy_view::AccountViewAdapter,
    resolve_classic_fee_selection,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, submit_transaction_and_wait},
};

use stellar_agent_network::account::AccountFlagsView;
use stellar_agent_network::keyring::{KeyringOperation, classify_keyring_operation_error};
use stellar_agent_stablecoin::{
    preview::{GateDecisionView, TrustlinePreview},
    resolve::{DenominationInput, ResolvedAsset, resolve_denomination},
};

use crate::common::network::mainnet_write_refusal;
use crate::common::profile_access::{
    ProfileAccessError, injected_profile_load, reconcile_loaded_profile,
};
use crate::common::render::{WithPreview, with_preview_detail, write_envelope};
use crate::common::resolve_profile_name;

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Redacts the issuer half of an asset string for logging.
///
/// For `CODE:ISSUER` form, the issuer is replaced by `redact_strkey_first5_last5`;
/// bare codes (no colon) and C-strkey SAC addresses are returned as-is.
fn redact_asset_for_log(asset: &str) -> String {
    if let Some((code, issuer)) = asset.split_once(':') {
        format!("{}:{}", code, redact_strkey_first5_last5(issuer))
    } else {
        asset.to_owned()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Argument types
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `stellar-agent trustline` subcommand.
///
/// # Ordered trust gate
///
/// 1. Operator policy evaluation (V1 / Noop).
/// 2. `resolve_denomination` — USDT refusal + lookalike denylist +
///    pinned-issuer-mismatch + unpinned-bare-code.
/// 3. Live issuer-flag fetch.  Fetch failure fail-closes.
/// 4. `clawback_gate` — wallet-controlled approval store opt-in lookup.
/// 5. Typed preview, reported in the one output envelope.
/// 6. Build → sign → submit.
///
/// # Asset grammar
///
/// - Bare code `"USDC"` — resolved via the pin table.
/// - `"CODE:ISSUER"` — explicit code+issuer pair.
/// - `"C…"` (56-char C-strkey SAC address) — deferred (returns a typed error).
///
/// # Examples
///
/// ```text
/// stellar-agent trustline \
///   --from  GABC...ACCT \
///   --asset USDC \
///   --profile default
/// ```
#[derive(Debug, Args)]
pub struct TrustlineArgs {
    /// Profile name to load (default: `STELLAR_AGENT_PROFILE` env var, then `"default"`).
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// G-strkey of the account that will hold the trustline.
    #[arg(long)]
    pub from: String,

    /// Asset descriptor.
    ///
    /// Grammar:
    /// - `"USDC"` — bare code, resolved via pin table.
    /// - `"USDC:G…ISSUER"` — explicit code+issuer.
    /// - `"C…"` (56-char) — SAC address (deferred; returns a typed error).
    #[arg(long)]
    pub asset: String,

    /// Optional explicit trustline limit in stroops.
    ///
    /// `0` removes the trustline.  Absent → Stellar default (`i64::MAX`, unlimited).
    #[arg(long)]
    pub limit_stroops: Option<i64>,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    ///
    /// Absent → profile's `classic_fee_per_op_stroops` value.
    #[arg(long = "fee")]
    pub classic_base: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// run
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatches the `stellar-agent trustline` subcommand.
///
/// Returns `0` on success, `1` on error.
///
/// # Errors
///
/// Returns `1` on any gate failure, denomination error, flag-fetch failure,
/// build error, sign error, or submit error.
pub async fn run(args: &TrustlineArgs) -> i32 {
    run_with_dependencies(
        args,
        injected_profile_load,
        init_platform_keyring_store,
        &mut std::io::stdout(),
    )
    .await
}

/// Testable core of [`run`] with the profile loader, the platform-keyring
/// initializer, and the output writer injected.
///
/// Production callers use [`run`], which supplies the real profile loader,
/// [`init_platform_keyring_store`], and stdout. Tests substitute an in-memory
/// profile and a spy initializer, and read the one envelope the command
/// writes from an in-memory writer. They assert the keyring store is
/// registered before signer resolution without touching the OS keychain.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &TrustlineArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
    out: &mut dyn Write,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, profile_loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Resolve the profile name ──────────────────────────────────────────────
    // `--profile`, then `STELLAR_AGENT_PROFILE`, then `"default"`.
    let resolved = resolve_profile_name(args.profile.as_deref());
    let profile_name = resolved.name.clone();

    // ── Load profile ──────────────────────────────────────────────────────────
    // Reconciled in the CALLER of the injected loader: a check placed inside
    // the closure would be bypassed by every test that supplies its own.
    //
    // A load failure keeps this verb's own `trustline.profile_load_failed`
    // code. The protected refusals keep their typed codes: a protected
    // overlay, an implicit mainnet selection, a mainnet profile without
    // `rpc_url`, and an endpoint URL that breaks the endpoint rule.
    // A name mismatch reports the shared `profile.name_mismatch`, the same
    // code every other CLI surface emits for it.
    let profile = match reconcile_loaded_profile(load_profile(&profile_name), &resolved) {
        Ok(p) => p,
        Err(e @ ProfileAccessError::Load(_)) if !e.requires_refusal() => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.profile_load_failed", e.message(&profile_name)),
                1,
            );
        }
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw(e.code(), e.message(&profile_name)),
                1,
            );
        }
    };

    let context = NetworkContext::from_profile(&profile);

    // ── Structural mainnet refusal ────────────────────────────────────────────
    // Before the keyring store, the signer, and any RPC request.
    if let Some(err) = mainnet_write_refusal(context.chain_id) {
        return write_envelope(out, &Envelope::<()>::err(&err), 1);
    }

    // ── Initialise platform keyring store ─────────────────────────────────────
    // The keyring signer loaded before signing requires the process-global
    // default store.  Ordered after the profile load so a missing profile never
    // triggers the store registration.
    if let Err(e) = init_keyring() {
        return write_envelope(out, &Envelope::<()>::err(&e), 1);
    }

    let rpc_url = context.rpc_url.as_str();
    let network_passphrase = context.network_passphrase();
    let chain_id = context.chain_id.caip2_str();

    // ── Validate G-strkey ─────────────────────────────────────────────────────
    if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.from) {
        return write_envelope(
            out,
            &Envelope::<()>::err_raw(
                "trustline.invalid_from",
                format!("invalid from address (expected G-strkey): {err}"),
            ),
            1,
        );
    }

    // ── GATE 1: resolve_denomination (D3 ordered refusal) ────────────────────
    let input = parse_denomination_input(&args.asset);
    let resolved = match resolve_denomination(input, network_passphrase) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(
                subcommand = "trustline",
                chain = %chain_id,
                asset = %redact_asset_for_log(&args.asset),
                error = %e,
                "denomination resolver refused trustline"
            );
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.denomination_refused", e.to_string()),
                1,
            );
        }
    };

    // ── GATE 2: Live issuer account fetch ──────────────────────────────────────
    let rpc_client = match StellarRpcClient::new(rpc_url) {
        Ok(c) => c,
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.rpc_init_failed", e.to_string()),
                1,
            );
        }
    };

    // Fetch the ISSUER account (not the wallet account) for `issuer_flags`
    // (the clawback gate, below). The issuer account is deliberately NOT
    // supplied as the policy gate's `identity_view`: its on-chain
    // `home_domain` is self-asserted, so feeding it to
    // `counterparty_allowlist` HOME_DOMAIN matching would let an issuer alias
    // an allowlisted domain — see the MCP `stellar_trustline` twin. Flag
    // booleans are third-party public facts; log freely.
    let issuer_account_view: Option<AccountView> =
        match fetch_account(&rpc_client, &resolved.issuer, &[]).await {
            Ok(account_view) => {
                let flags_opt = &account_view.account_flags;
                tracing::info!(
                    subcommand = "trustline",
                    issuer = %redact_strkey_first5_last5(&resolved.issuer),
                    auth_required = ?flags_opt.as_ref().map(|f| f.auth_required),
                    auth_revocable = ?flags_opt.as_ref().map(|f| f.auth_revocable),
                    auth_clawback_enabled = ?flags_opt.as_ref().map(|f| f.auth_clawback_enabled),
                    "issuer flags fetched"
                );
                Some(account_view)
            }
            Err(e) => {
                // Fetch failure fail-closes the gate.
                tracing::info!(
                    subcommand = "trustline",
                    issuer = %redact_strkey_first5_last5(&resolved.issuer),
                    error = %e,
                    "issuer flag fetch failed — fail-closing gate"
                );
                None
            }
        };
    let issuer_flags: Option<AccountFlagsView> = issuer_account_view
        .as_ref()
        .and_then(|v| v.account_flags.clone());

    // ── GATE 3: Fetch source account (feeds the policy gate's account_view;
    // sequence number also consumed by the envelope build below) ────────────
    let source_account_view = match fetch_account(&rpc_client, &args.from, &[]).await {
        Ok(v) => v,
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.source_account_fetch_failed", e.to_string()),
                1,
            );
        }
    };
    let source_sequence = source_account_view.sequence_number;

    // Settle the spending-window reservations that have stood long enough to
    // be settleable, before the gate below counts them. A reservation the
    // chain has since answered for should not hold the operator's cap, and one
    // the chain has not is counted as spend.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("wallet.clock_error", e.to_string()),
                1,
            );
        }
    };
    crate::commands::submission_record::reconcile_open_reservations(
        &profile,
        &profile_name,
        crate::common::profile_access::ProfileOrigin::Persisted,
        &rpc_client,
        now_ms,
    )
    .await;

    // ── GATE 4: Operator policy evaluation (args-path; mirrors the MCP
    // `stellar_trustline` twin, which derives its `Trustline` leg from the
    // dispatch args via `derive_value_class` rather than a typed builder) ────
    let policy_engine = match build_v1_policy_engine(
        "trustline",
        &profile.policy.engine,
        &profile,
        &profile_name,
    ) {
        Ok(pe) => pe,
        Err(msg) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.policy_engine_unavailable", msg),
                1,
            );
        }
    };
    let policy_args = trustline_policy_args(&args.from, &args.asset);
    // `account_view` is the fetched source account (feeds `minimum_reserve`).
    // `identity_view` stays `None`, matching the MCP twin: the issuer's
    // self-asserted `home_domain` must not feed allowlist matching, so
    // identity-class criteria configured on this verb fail closed.
    let source_adapter = AccountViewAdapter::new(&source_account_view);
    let trustline_effects = match evaluate_value_moving_policy(
        policy_engine.as_ref(),
        &profile,
        "stellar_trustline",
        stellar_agent_core::policy::ToolValueKind::MovesValue,
        chain_id,
        &policy_args,
        "trustline",
        Some(&source_adapter),
        None,
    ) {
        Ok(effects) => effects,
        Err(envelope) => {
            return write_envelope(out, &envelope, 1);
        }
    };

    // ── Audit pre-flight (fail-closed) ────────────────────────────────────────
    // Proves the profile's audit chain-root key is acquirable AFTER the
    // policy gate (a denial is a clean refusal that signs nothing and needs
    // no audit setup) but BEFORE the signer is loaded (below) or the
    // transaction is submitted. Reused (not re-acquired) for the
    // post-confirm `value_action_submitted` row.
    let audit_writer =
        match crate::commands::value_audit::require_value_audit_writer(&profile, &profile_name) {
            Ok(w) => w,
            Err(e) => {
                return write_envelope(out, &Envelope::<()>::err(&e), 1);
            }
        };

    // ── GATE 5: Wallet-controlled clawback opt-in lookup (HMAC-verified) ────
    //
    // `opt_in_present` is NOT a CLI flag; it is derived from the wallet-controlled
    // approval store only.
    //
    // The lookup MUST be HMAC-verified: `verify_attested_trustline_clawback_opt_in`
    // loads the attestation key from the keyring and calls `verify_attestation`
    // (constant-time HMAC-SHA256).  A presence-only check allows forged blobs.
    //
    // Network key: `context.chain_id.caip2_str()` is canonical and consistent
    // across mint, digest, record, and lookup.
    //
    // Keyring unavailable → fail-closed: opt-in treated as absent.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(ms) => ms,
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.clock_error", e.to_string()),
                1,
            );
        }
    };
    let network_key = context.chain_id.caip2_str();
    let opt_in_present: bool = {
        match load_attestation_key_for_verify(&profile, &profile_name) {
            Ok(key_bytes) => {
                let attestation_key = zeroize::Zeroizing::new(key_bytes);
                default_approval_dir()
                    .ok()
                    .map(|dir| {
                        let store_path = dir.join(format!("{profile_name}.toml"));
                        open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
                            .map(|store| {
                                store.verify_attested_trustline_clawback_opt_in(
                                    &attestation_key,
                                    &stellar_agent_core::approval::AttestationBinding::new(
                                        &profile_name,
                                        context.chain_id.caip2_str(),
                                    ),
                                    network_key,
                                    &resolved.code,
                                    &resolved.issuer,
                                    now_ms,
                                )
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false)
            }
            Err(_) => {
                // Keyring unavailable — fail-closed: treat opt-in as absent.
                tracing::debug!(
                    subcommand = "trustline",
                    "attestation key load failed; treating clawback opt-in as absent (fail-closed)"
                );
                false
            }
        }
    };

    // ── GATE 6: Build trustline preview (includes clawback gate decision) ─────
    let preview = TrustlinePreview::build(
        resolved.clone(),
        args.limit_stroops,
        issuer_flags.as_ref(),
        opt_in_present,
    );

    // ── GATE 7: Clawback gate decision (fail-closed) ──────────────────────────
    //
    // RefuseWithWarning: `auth_clawback_enabled = true` and no VERIFIED opt-in.
    // Mint a `TrustlineClawbackOptIn` pending entry and tell the operator to run
    // `stellar-agent approve --id <nonce> --profile <name>`.  On the next trustline invocation the
    // HMAC-verified opt-in clears the gate.
    match &preview.gate_decision {
        GateDecisionView::Proceed => {
            // Gate passed — proceed to envelope build.
        }
        GateDecisionView::RefuseWithWarning { warning } => {
            tracing::info!(
                subcommand = "trustline",
                chain = %chain_id,
                code = %resolved.code,
                issuer = %redact_strkey_first5_last5(&resolved.issuer),
                warning = %warning,
                "clawback gate RefuseWithWarning — minting opt-in pending entry"
            );
            // Mint the opt-in pending entry so the operator can approve it.
            let uid = match process_uid_for_attestation() {
                Ok(u) => u,
                Err(e) => {
                    return write_envelope(
                        out,
                        &Envelope::<()>::err_raw("trustline.uid_unavailable", e.to_string()),
                        1,
                    );
                }
            };
            match default_approval_dir() {
                Ok(dir) => {
                    if let Err(e) = std::fs::create_dir_all(&dir) {
                        tracing::warn!(
                            subcommand = "trustline",
                            error = %e,
                            "approval dir create_all failed; opt-in entry not minted"
                        );
                    } else {
                        let store_path = dir.join(format!("{profile_name}.toml"));
                        match open_with_retry(
                            &store_path,
                            DEFAULT_RETRY_ATTEMPTS,
                            DEFAULT_RETRY_BACKOFF,
                        ) {
                            Ok(mut store) => {
                                match PendingApproval::new_trustline_clawback_opt_in_pending(
                                    network_key.to_owned(),
                                    resolved.code.clone(),
                                    resolved.issuer.clone(),
                                    uid,
                                    DEFAULT_TTL_MS,
                                ) {
                                    Ok(entry) => {
                                        let opt_in_nonce = entry.approval_nonce.clone();
                                        let opt_in_expires = entry.expires_at_unix_ms;
                                        if let Err(e) = store.insert(entry, now_ms) {
                                            tracing::warn!(
                                                subcommand = "trustline",
                                                error = %e,
                                                "opt-in entry insert failed"
                                            );
                                        } else {
                                            return write_envelope(
                                                out,
                                                &Envelope::ok(serde_json::json!({
                                                    "outcome": "clawback_opt_in_required",
                                                    "warning": warning,
                                                    "opt_in_approval": {
                                                        "approval_nonce": opt_in_nonce,
                                                        "expires_at_unix_ms": opt_in_expires,
                                                        "instructions": "Run `stellar-agent approve \
                                                            --id <approval_nonce>` to record the \
                                                            clawback opt-in, then re-invoke trustline.",
                                                    },
                                                })),
                                                1,
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            subcommand = "trustline",
                                            error = %e,
                                            "new_trustline_clawback_opt_in_pending failed"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    subcommand = "trustline",
                                    error = %e,
                                    "approval store open failed for opt-in entry"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        subcommand = "trustline",
                        error = %e,
                        "approval dir resolution failed; opt-in entry not minted"
                    );
                }
            }
            // Fall-through: render a plain refusal if the store mint failed.
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.clawback_gate_refused", warning),
                1,
            );
        }
        GateDecisionView::Refuse { reason } => {
            tracing::info!(
                subcommand = "trustline",
                chain = %chain_id,
                code = %resolved.code,
                issuer = %redact_strkey_first5_last5(&resolved.issuer),
                reason = %reason,
                "clawback gate Refuse — trustline refused (fail-closed or hard-refusal)"
            );
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.gate_refused", reason),
                1,
            );
        }
    }

    // ── Report every later stage in one envelope carrying the preview ────────
    let preview_view = trustline_preview_view(&preview);
    let outcome = sign_and_submit(GatedTrustline {
        args,
        profile: &profile,
        profile_name: &profile_name,
        rpc_client: &rpc_client,
        network_passphrase,
        chain_id,
        resolved: &resolved,
        source_sequence,
        effects: trustline_effects.as_ref(),
        audit_writer: &audit_writer,
        now_ms,
    })
    .await;
    render_trustline_outcome(out, preview_view, outcome)
}

// ─────────────────────────────────────────────────────────────────────────────
// Stages after the preview
// ─────────────────────────────────────────────────────────────────────────────

/// The inputs the stages after the preview take from the gates before it.
struct GatedTrustline<'a> {
    args: &'a TrustlineArgs,
    profile: &'a Profile,
    profile_name: &'a str,
    rpc_client: &'a StellarRpcClient,
    network_passphrase: &'a str,
    chain_id: &'a str,
    resolved: &'a ResolvedAsset,
    source_sequence: i64,
    effects: Option<&'a stellar_agent_core::policy::v1::ValueEffects>,
    audit_writer: &'a Arc<Mutex<AuditWriter>>,
    now_ms: u64,
}

/// The success payload of a submitted `ChangeTrust` transaction.
#[derive(Debug, serde::Serialize)]
struct TrustlineSubmitted {
    status: &'static str,
    action: &'static str,
    code: String,
    issuer_redacted: String,
    limit_stroops: Option<String>,
    is_pinned: bool,
    tx_hash: String,
    ledger: u32,
}

/// Resolves the fee, then builds, signs, records, and submits the
/// `ChangeTrust` envelope.
///
/// Renders nothing: the caller reports the returned payload or failure
/// envelope in the one envelope that carries the preview.
async fn sign_and_submit(gated: GatedTrustline<'_>) -> Result<TrustlineSubmitted, Envelope<()>> {
    let GatedTrustline {
        args,
        profile,
        profile_name,
        rpc_client,
        network_passphrase,
        chain_id,
        resolved,
        source_sequence,
        effects,
        audit_writer,
        now_ms,
    } = gated;

    // ── Fee resolution ────────────────────────────────────────────────────────
    let fee_choice = parse_classic_fee_choice(args.classic_base.as_deref())
        .map_err(|e| Envelope::<()>::err_raw("trustline.invalid_fee", e.code().to_string()))?;
    // Unwrap Option<u32> with a safe default (100 stroops = testnet safe floor).
    // The MCP path uses the common helper `resolve_classic_fee_per_op_stroops`;
    // the CLI path is equivalent: fallback to 100 when the profile has no explicit
    // fee configured.
    const DEFAULT_CLASSIC_FEE_STROOPS: u32 = 100;
    let default_fee_per_op = profile
        .classic_fee_per_op_stroops
        .unwrap_or(DEFAULT_CLASSIC_FEE_STROOPS);
    let fee_selection = resolve_classic_fee_selection(rpc_client, default_fee_per_op, fee_choice)
        .await
        .map_err(|e| Envelope::<()>::err_raw("trustline.fee_resolution_failed", e.to_string()))?;
    let fee_per_op = fee_selection.per_op_stroops;

    // ── Build unsigned ChangeTrust envelope ───────────────────────────────────
    let asset = Asset::from_code_and_issuer(&resolved.code, &resolved.issuer)
        .map_err(|e| Envelope::<()>::err_raw("trustline.asset_build_failed", e.to_string()))?;
    let envelope_build_failed =
        |e: WalletError| Envelope::<()>::err_raw("trustline.envelope_build_failed", e.to_string());
    let mut builder =
        ClassicOpBuilder::new(&args.from, source_sequence, network_passphrase, fee_per_op);
    builder
        .change_trust(&asset, args.limit_stroops)
        .map_err(envelope_build_failed)?;
    let envelope_xdr = builder.build().map_err(envelope_build_failed)?;

    // NEVER log the envelope XDR at info.
    tracing::debug!(
        subcommand = "trustline",
        chain = %chain_id,
        "ChangeTrust envelope built (XDR at debug only)"
    );

    // ── Drain the audit outbox before the signing key loads ──────────────────
    // The clawback opt-in was read from the approval store after the audit
    // pre-flight. Re-acquiring the keyed writer is a cache hit, which drains
    // the outbox, so a consent row `stellar-agent approve` queued meanwhile is
    // in the log before the key is touched. Fail closed.
    crate::commands::value_audit::drain_consent_rows_before_signing(profile, profile_name)
        .map_err(|e| Envelope::<()>::err(&e))?;

    // ── Load signer from keyring ──────────────────────────────────────────────
    let expected_g = profile.mcp_signer_default.account.as_str();
    let signer_handle = enrolled_keyring_signer(profile_name, profile, expected_g)
        .await
        .map_err(|e| {
            let (code, message) = signer_load_failure_parts(&e);
            Envelope::<()>::err_raw(code, message)
        })?;

    // ── Sign envelope ─────────────────────────────────────────────────────────
    let signed_xdr = attach_signature(&envelope_xdr, &signer_handle, network_passphrase)
        .await
        .map_err(|e| Envelope::<()>::err_raw("trustline.sign_failed", e.to_string()))?;

    // ── Record, then submit ───────────────────────────────────────────────────
    // The recorder writes the receipt, the pending audit row and the
    // spending-window reservation before the bytes leave, and settles all
    // three against what the network answers.
    let submission_failure = |e: WalletError| {
        crate::commands::submission_record::error_envelope_with_fallback(
            &e,
            &signed_xdr,
            "trustline",
            "trustline.submit_failed",
        )
    };
    let recorder = crate::commands::submission_record::build_recorder(
        crate::commands::submission_record::SubmitRecord {
            policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
            profile,
            profile_name: profile_name.to_owned(),
            verb: "trustline",
            tool: "stellar_trustline",
            chain_id,
            effects,
            audit: Some(Arc::clone(audit_writer)),
            now_ms,
        },
    )
    .map_err(submission_failure)?;

    let timeout = std::time::Duration::from_secs(profile.submit_timeout_seconds.unwrap_or(90));
    let SubmissionResult {
        tx_hash, ledger, ..
    } = submit_transaction_and_wait(
        rpc_client,
        &signed_xdr,
        timeout,
        network_passphrase,
        Some(SubmissionSignerKind::Keyring),
        Some(&recorder),
    )
    .await
    .map_err(submission_failure)?;

    let tx_hash_redacted = stellar_agent_network::submit::redact_tx_hash(&tx_hash);
    tracing::info!(
        subcommand = "trustline",
        chain = %chain_id,
        code = %resolved.code,
        issuer = %redact_strkey_first5_last5(&resolved.issuer),
        tx_hash = %tx_hash_redacted,
        ledger = ?ledger,
        "ChangeTrust tx submitted"
    );

    Ok(TrustlineSubmitted {
        status: "submitted",
        action: "change_trust",
        code: resolved.code.clone(),
        issuer_redacted: redact_strkey_first5_last5(&resolved.issuer),
        limit_stroops: args.limit_stroops.map(|v| v.to_string()),
        is_pinned: resolved.is_pinned,
        tx_hash,
        ledger,
    })
}

/// The typed preview as the nested `preview` object of the output envelope.
fn trustline_preview_view(preview: &TrustlinePreview) -> serde_json::Value {
    json!({
        "code": &preview.code,
        "issuer": &preview.issuer,
        "issuer_redacted": redact_strkey_first5_last5(&preview.issuer),
        "limit_stroops": preview.limit_stroops.map(|v| v.to_string()),
        "is_pinned": preview.is_pinned,
        "issuer_flags": &preview.issuer_flags,
        "gate_decision": &preview.gate_decision,
    })
}

/// Writes the outcome of the stages after the preview as one envelope and
/// returns the exit code.
///
/// The preview sits in `data.preview` on success and in
/// `error.details.preview` on failure. An envelope that cannot be written or
/// flushed exits `1` with the failure on stderr, whatever the outcome.
fn render_trustline_outcome<T: serde::Serialize>(
    out: &mut dyn Write,
    preview: serde_json::Value,
    outcome: Result<T, Envelope<()>>,
) -> i32 {
    match outcome {
        Ok(result) => write_envelope(
            out,
            &Envelope::ok(WithPreview {
                result,
                preview: Some(preview),
            }),
            0,
        ),
        Err(envelope) => write_envelope(out, &with_preview_detail(envelope, preview), 1),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Denomination-input parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parses the `--asset` CLI string into a `DenominationInput`.
///
/// Grammar:
/// - Starts with `C` and is 56 chars → `SacAddress`
/// - Contains `:` → `CodeAndIssuer { code, issuer }` (split on first `:`)
/// - Otherwise → `BareCode`
fn parse_denomination_input(asset: &str) -> DenominationInput {
    if asset.len() == 56 && asset.starts_with('C') {
        return DenominationInput::SacAddress(asset.to_owned());
    }
    if let Some(colon) = asset.find(':') {
        let (code, rest) = asset.split_at(colon);
        return DenominationInput::CodeAndIssuer {
            code: code.to_owned(),
            issuer: rest[1..].to_owned(),
        };
    }
    DenominationInput::BareCode(asset.to_owned())
}

// ─────────────────────────────────────────────────────────────────────────────
// Attestation key loader — for HMAC-verified opt-in gate
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the per-profile HMAC-SHA256 attestation key from the platform keyring.
///
/// Returns the raw 32-byte key for use with
/// [`stellar_agent_core::approval::store::PendingApprovalStore::verify_attested_trustline_clawback_opt_in`].
/// The caller MUST wrap the returned bytes in `zeroize::Zeroizing` to
/// guarantee erasure on drop.
///
/// # Errors
///
/// Returns a non-displayable unit error when the keyring entry is missing,
/// base64-decodes to the wrong length, or is unavailable.  The call site treats
/// all failures as fail-closed (opt-in absent).
fn load_attestation_key_for_verify(
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
) -> Result<[u8; 32], ()> {
    use stellar_agent_core::approval::attest::ATTESTATION_KEY_FIELD;
    use stellar_agent_core::profile::owner_key;
    let entry_ref = &profile.attestation_key_id;
    // An owner refusal reads as opt-in absent, like every other failure here;
    // its code is logged at warn because only the operator can fix it.
    let owner_refusal = |e: &WalletError| {
        tracing::warn!(
            profile = %profile_name,
            code = %e.code(),
            "attestation key refused for trustline opt-in verify (fail closed)"
        );
    };
    owner_key::refuse_owner_key_coordinate(entry_ref, ATTESTATION_KEY_FIELD)
        .map_err(|e| owner_refusal(&e))?;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        // Fail-closed: the outward contract is a non-displayable unit error
        // (opt-in absent). The classified cause is preserved at debug for
        // operator forensics only.
        tracing::debug!(
            cause = ?classify_keyring_operation_error(&e, KeyringOperation::Construct, &entry_ref.service),
            "attestation key entry open failed for trustline opt-in verify (fail-closed)"
        );
    })?;
    let raw = entry.get_password().map_err(|e| {
        tracing::debug!(
            cause = ?classify_keyring_operation_error(&e, KeyringOperation::Read, &entry_ref.service),
            "attestation key read failed for trustline opt-in verify (fail-closed)"
        );
    })?;
    let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).map_err(|_| ())?;
    if bytes.len() != 32 {
        return Err(());
    }
    owner_key::refuse_owner_public_key(
        &bytes,
        &owner_key::OwnerKeyContext::for_profile(profile_name, profile),
        ATTESTATION_KEY_FIELD,
    )
    .map_err(|e| owner_refusal(&e))?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn signer_load_failure_parts(e: &WalletError) -> (&'static str, String) {
    match e {
        WalletError::Auth(
            stellar_agent_core::error::AuthError::EnrolledSignerUnpinned { .. }
            | stellar_agent_core::error::AuthError::EnrolledSignerMismatch { .. },
        ) => (e.code(), e.to_string()),
        _ => ("trustline.signer_load_failed", e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only fixture construction"
    )]

    use super::*;

    // ── attestation-key read is fail-closed ───────────────────────────────────

    /// The trustline opt-in attestation-key read is fail-closed: even a
    /// classified environmental keyring failure (a non-interactive Windows
    /// session) surfaces as the opaque unit error (opt-in absent), never a
    /// distinguishable outward error.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_for_verify_is_fail_closed_on_environmental_failure() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let profile = Profile::builder_testnet_named(
            "trustline-attest-no-logon-test",
            "stellar-agent-signer",
            "trustline-attest-no-logon-test",
            "stellar-agent-nonce",
            "trustline-attest-no-logon-test",
        )
        .build();
        let entry_ref = &profile.attestation_key_id;
        stellar_agent_test_support::keyring_mock::inject_no_logon_session(
            &entry_ref.service,
            &entry_ref.account,
        )
        .unwrap();
        assert_eq!(
            load_attestation_key_for_verify(&profile, "trustline-attest-no-logon-test"),
            Err(())
        );
    }

    /// The opt-in verify reads a key equal to the owner public key in the
    /// older form as opt-in absent and logs the code at `warn`, without the
    /// raw value. A G-strkey owner value and an owner-namespace coordinate
    /// read as absent too.
    #[test]
    #[serial_test::serial]
    fn load_attestation_key_for_verify_refuses_owner_key_forms() {
        use stellar_agent_core::profile::schema::KeyringEntryRef;
        stellar_agent_test_support::keyring_mock::install().ok();
        let name = "trustline-attest-owner";
        let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a").build();
        let put = |entry_ref: &KeyringEntryRef, value: &str| {
            KeyringEntry::new(&entry_ref.service, &entry_ref.account)
                .unwrap()
                .set_password(value)
                .unwrap();
        };
        let older_form = URL_SAFE_NO_PAD.encode([0x5e_u8; 32]);
        put(&profile.attestation_key_id, &older_form);
        assert!(load_attestation_key_for_verify(&profile, name).is_ok());

        put(&KeyringEntryRef::default_owner_key(name), &older_form);
        let mut result = Ok([0; 32]);
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            result = load_attestation_key_for_verify(&profile, name);
        });
        assert!(result.is_err(), "the owner key reads as opt-in absent");
        assert!(!logs.contains(&older_form), "the raw value is never logged");
        assert!(logs.contains("WARN"), "{logs}");
        assert!(
            logs.contains("validation.key_matches_owner_public_key"),
            "{logs}"
        );

        put(
            &profile.attestation_key_id,
            &stellar_agent_core::profile::owner_key::encode_owner_public_key(&[0x5e; 32]),
        );
        assert!(
            load_attestation_key_for_verify(&profile, name).is_err(),
            "a G-strkey reads as opt-in absent"
        );

        profile.attestation_key_id = KeyringEntryRef::new("stellar-agent-owner-B", "default");
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            result = load_attestation_key_for_verify(&profile, name);
        });
        assert!(
            result.is_err(),
            "an owner coordinate reads as opt-in absent"
        );
        assert!(
            logs.contains("validation.key_matches_owner_public_key"),
            "{logs}"
        );
    }

    // ── parse_denomination_input variants ─────────────────────────────────────

    #[test]
    fn parse_input_bare_code() {
        let input = parse_denomination_input("USDC");
        assert!(
            matches!(input, DenominationInput::BareCode(ref c) if c == "USDC"),
            "expected BareCode, got: {input:?}"
        );
    }

    #[test]
    fn parse_input_code_issuer() {
        let issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
        let asset = format!("USDC:{issuer}");
        let input = parse_denomination_input(&asset);
        assert!(
            matches!(
                &input,
                DenominationInput::CodeAndIssuer { code, issuer: i }
                if code == "USDC" && i == issuer
            ),
            "expected CodeAndIssuer, got: {input:?}"
        );
    }

    #[test]
    fn parse_input_sac_address() {
        let sac = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let input = parse_denomination_input(sac);
        assert!(
            matches!(input, DenominationInput::SacAddress(_)),
            "expected SacAddress, got: {input:?}"
        );
    }

    #[test]
    fn parse_input_short_c_prefix_is_bare_code() {
        let input = parse_denomination_input("CUPS");
        assert!(
            matches!(input, DenominationInput::BareCode(_)),
            "short C-prefixed string must be BareCode, got: {input:?}"
        );
    }

    // ── USDT refused at resolve step ──────────────────────────────────────────

    #[test]
    fn usdt_bare_code_refused_by_resolver() {
        let input = parse_denomination_input("USDT");
        let result = resolve_denomination(input, "Test SDF Network ; September 2015");
        assert!(
            result.is_err(),
            "USDT bare code must be refused by resolver"
        );
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                stellar_agent_stablecoin::resolve::ResolveError::UsdtRefused { .. }
            ),
            "expected UsdtRefused, got: {err:?}"
        );
    }

    #[test]
    fn usdt_lowercase_refused_by_resolver() {
        let input = parse_denomination_input("usdt");
        let result = resolve_denomination(input, "Test SDF Network ; September 2015");
        assert!(result.is_err(), "USDT (lowercase) must be refused");
    }

    // ── lookalike denylist ────────────────────────────────────────────────────

    #[test]
    fn eurau_lookalike_1_refused_by_resolver() {
        let input = parse_denomination_input(
            "EURAU:GCMHTNLK3N2QYQENZTJAKO34J3GGNL26BILAWPWVRB37JLV7TXDBHNFT",
        );
        let result = resolve_denomination(input, "Test SDF Network ; September 2015");
        assert!(
            matches!(
                result.unwrap_err(),
                stellar_agent_stablecoin::resolve::ResolveError::LookalikeRefused { .. }
            ),
            "EURAU lookalike must be refused"
        );
    }

    // ── bare unknown code refused ─────────────────────────────────────────────

    #[test]
    fn bare_unknown_code_refused_as_unpinned() {
        let input = parse_denomination_input("FOO");
        let result = resolve_denomination(input, "Test SDF Network ; September 2015");
        assert!(
            matches!(
                result.unwrap_err(),
                stellar_agent_stablecoin::resolve::ResolveError::UnpinnedBareCode { .. }
            ),
            "bare unknown code must be refused as unpinned"
        );
    }

    // ── mainnet refusal ahead of the keyring and the endpoint ────────────────

    /// A mainnet profile is refused with exit 1 before the keyring
    /// initialiser, which panics if called, and before any request reaches
    /// the profile's endpoint.
    #[tokio::test]
    async fn run_refuses_mainnet_before_keyring_and_any_request() {
        let rpc = wiremock::MockServer::start().await;
        let args = TrustlineArgs {
            profile: Some("trustline-mainnet".to_owned()),
            from: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned(),
            asset: "USDC".to_owned(),
            limit_stroops: None,
            classic_base: None,
        };
        let code = run_with_dependencies(
            &args,
            |name| {
                Ok(
                    Profile::builder_mainnet_named(name, rpc.uri(), "s", "default", "n", "a")
                        .build(),
                )
            },
            || panic!("a mainnet profile must not initialise the keyring"),
            &mut std::io::sink(),
        )
        .await;
        assert_eq!(code, 1, "a mainnet trustline must exit with code 1");
        assert!(
            rpc.received_requests().await.unwrap().is_empty(),
            "a mainnet trustline must send no request"
        );
    }

    // ── keyring store initialisation ordering ─────────────────────────────────

    #[tokio::test]
    async fn run_initialises_keyring_store_before_signer_resolution() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use stellar_agent_core::error::AuthError;

        // The keyring initialiser must be invoked on the run() path, after the
        // profile load and before the signer is resolved from the keyring.
        // Both dependencies are injected, so no OS keychain or on-disk profile
        // is touched and no process-global keyring store is registered — hence
        // this test needs no `#[serial]`.  The injected initialiser returns an
        // error so the run bails at that step, which proves the store
        // initialisation gates the path ahead of signer resolution.
        let profile_loaded = Arc::new(AtomicBool::new(false));
        let init_invoked = Arc::new(AtomicBool::new(false));

        let loaded_writer = Arc::clone(&profile_loaded);
        let loaded_reader = Arc::clone(&profile_loaded);
        let init_writer = Arc::clone(&init_invoked);

        let args = TrustlineArgs {
            profile: Some("keyring-order-test".to_owned()),
            from: String::new(),
            asset: String::new(),
            limit_stroops: None,
            classic_base: None,
        };

        let code = run_with_dependencies(
            &args,
            move |_name| {
                loaded_writer.store(true, Ordering::SeqCst);
                Ok(Profile::builder_testnet_named(
                    "keyring-order-test",
                    "stellar-agent-signer",
                    "keyring-order-test",
                    "stellar-agent-nonce",
                    "keyring-order-test",
                )
                .build())
            },
            move || {
                assert!(
                    loaded_reader.load(Ordering::SeqCst),
                    "profile must be loaded before the keyring store is initialised"
                );
                init_writer.store(true, Ordering::SeqCst);
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "keyring-order-test-sentinel".to_owned(),
                }))
            },
            &mut std::io::sink(),
        )
        .await;

        assert!(
            init_invoked.load(Ordering::SeqCst),
            "run must initialise the keyring store before resolving the signer"
        );
        assert_eq!(
            code, 1,
            "run must surface the keyring init failure instead of reaching signer resolution"
        );
    }

    // ── One envelope on stdout ────────────────────────────────────────────────

    const ONE_ENVELOPE_FROM: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const ONE_ENVELOPE_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

    /// The preview a `USDC:<issuer>` trustline renders when the issuer sets
    /// no flags.
    fn usdc_preview() -> TrustlinePreview {
        let resolved = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "USDC".to_owned(),
                issuer: ONE_ENVELOPE_ISSUER.to_owned(),
            },
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
        )
        .unwrap();
        TrustlinePreview::build(resolved, None, Some(&AccountFlagsView::from_raw(0)), false)
    }

    /// The success payload of a submitted `USDC` trustline.
    fn submitted_usdc(preview: &TrustlinePreview) -> TrustlineSubmitted {
        TrustlineSubmitted {
            status: "submitted",
            action: "change_trust",
            code: "USDC".to_owned(),
            issuer_redacted: redact_strkey_first5_last5(ONE_ENVELOPE_ISSUER),
            limit_stroops: None,
            is_pinned: preview.is_pinned,
            tx_hash: "ab".repeat(32),
            ledger: 7,
        }
    }

    /// A submitted trustline prints exactly one JSON document: the result
    /// envelope, with the preview nested at `data.preview`.
    #[test]
    fn a_submitted_trustline_prints_one_envelope_with_the_preview_in_data() {
        let preview = usdc_preview();
        let submitted = submitted_usdc(&preview);
        let mut out = Vec::new();
        let code =
            render_trustline_outcome(&mut out, trustline_preview_view(&preview), Ok(submitted));
        assert_eq!(code, 0);
        let envelope = crate::common::render::single_json_document(&out);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let data = &envelope["data"];
        assert_eq!(data["status"], "submitted", "{envelope}");
        assert_eq!(data["tx_hash"], "ab".repeat(32), "{envelope}");
        assert_eq!(data["ledger"], 7, "{envelope}");
        assert_eq!(data["preview"]["code"], "USDC", "{envelope}");
        assert_eq!(data["preview"]["issuer"], ONE_ENVELOPE_ISSUER, "{envelope}");
        assert_eq!(
            data["preview"]["gate_decision"]["kind"], "proceed",
            "{envelope}"
        );
        assert!(data.get("stage").is_none(), "{envelope}");
    }

    /// A submitted trustline whose envelope cannot be written or flushed
    /// exits `1`: the result never reached the caller.
    #[test]
    fn a_submitted_trustline_whose_output_fails_exits_one() {
        use crate::common::render::FailingWriter;
        let preview = usdc_preview();
        for mut writer in [FailingWriter::Write, FailingWriter::Flush] {
            let code = render_trustline_outcome(
                &mut writer,
                trustline_preview_view(&preview),
                Ok(submitted_usdc(&preview)),
            );
            assert_eq!(code, 1, "{writer:?}");
        }
    }

    /// A failure after the preview stage prints exactly one JSON document:
    /// the error envelope, with the preview nested at `error.details.preview`.
    ///
    /// `--fee bogus` passes every gate up to the preview against a mocked
    /// endpoint and fails at the fee parse, before the fee-statistics request
    /// or any submission.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_failure_after_the_preview_prints_one_envelope_with_the_preview_in_details() {
        const NAME: &str = "trustline-one-envelope";

        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let rpc = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let result = match body["method"].as_str().unwrap_or("") {
                    "getLedgerEntries" => {
                        stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[
                            ONE_ENVELOPE_FROM,
                            ONE_ENVELOPE_ISSUER,
                        ])
                    }
                    "getNetwork" => {
                        stellar_agent_test_support::signed_envelope::get_network_result(
                            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                        )
                    }
                    _ => serde_json::json!({}),
                };
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": result,
                }))
            })
            .mount(&rpc)
            .await;
        let mut profile =
            Profile::builder_testnet_named(NAME, "svc-one-envelope", ONE_ENVELOPE_FROM, "n", "a")
                .with_noop_engine()
                .build();
        profile.rpc_url = rpc.uri();
        profile.audit_log_path = home.path().join("audit").join(format!("{NAME}.jsonl"));
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let audit_key = &profile.audit_log_hash_chain_key_id;
        KeyringEntry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x3a; 32]))
            .unwrap();

        let args = TrustlineArgs {
            profile: Some(NAME.to_owned()),
            from: ONE_ENVELOPE_FROM.to_owned(),
            asset: format!("USDC:{ONE_ENVELOPE_ISSUER}"),
            limit_stroops: None,
            classic_base: Some("bogus".to_owned()),
        };
        let mut out = Vec::new();
        let loaded = profile.clone();
        let code =
            run_with_dependencies(&args, move |_| Ok(loaded.clone()), || Ok(()), &mut out).await;

        assert_eq!(code, 1);
        let envelope = crate::common::render::single_json_document(&out);
        assert_eq!(envelope["ok"], false, "{envelope}");
        assert_eq!(
            envelope["error"]["code"], "trustline.invalid_fee",
            "{envelope}"
        );
        let preview = &envelope["error"]["details"]["preview"];
        assert_eq!(preview["code"], "USDC", "{envelope}");
        assert_eq!(preview["issuer"], ONE_ENVELOPE_ISSUER, "{envelope}");
        assert_eq!(preview["gate_decision"]["kind"], "proceed", "{envelope}");
        let methods: Vec<String> = rpc
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .ok()
                    .and_then(|body| body["method"].as_str().map(str::to_owned))
            })
            .collect();
        assert!(
            !methods
                .iter()
                .any(|m| m == "getFeeStats" || m == "sendTransaction"),
            "the fee parse fails before any later request: {methods:?}"
        );
    }
}

#[cfg(test)]
mod enrolled_failure_tests {
    use super::*;
    use stellar_agent_core::error::AuthError;

    #[test]
    fn enrolled_signer_load_failure_codes_pass_through() {
        for error in [
            AuthError::EnrolledSignerUnpinned {
                profile: "mainnet".into(),
                reason: "placeholder",
            },
            AuthError::EnrolledSignerMismatch {
                profile: "mainnet".into(),
                enrolled: "A".into(),
                derived: "B".into(),
            },
        ] {
            let error = WalletError::Auth(error);
            assert_eq!(
                signer_load_failure_parts(&error),
                (error.code(), error.to_string())
            );
        }
        let error = WalletError::Auth(AuthError::KeyringNotFound {
            name: "missing".into(),
        });
        assert_eq!(
            signer_load_failure_parts(&error),
            ("trustline.signer_load_failed", error.to_string())
        );
    }

    // ── A consent row queued after the pre-flight ────────────────────────────

    /// A consent row queued after the audit pre-flight, while the verb reads
    /// the clawback opt-in, is in the log before the signing key loads.
    ///
    /// The writer is cached in-process by an earlier keyed call. A read hook at
    /// the attestation key queues the row during the opt-in read; a read hook
    /// at the signer coordinate records whether the row is in the log when the
    /// signing key loads. No signer is seeded, so the verb refuses there.
    #[tokio::test]
    #[serial_test::serial]
    #[allow(clippy::unwrap_used, reason = "test-only fixture construction")]
    async fn trustline_logs_a_consent_row_queued_after_its_pre_flight_before_the_signer_loads() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        use base64::Engine as _;
        use stellar_agent_core::audit_log::{AuditEntry, AuditOutbox, AuditWriterRegistry};
        use stellar_agent_test_support::keyring_mock::{ReadHook, install_with_read_hooks};

        const NAME: &str = "trustline-drain";
        const FROM: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        const ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let rpc = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(|request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                let result = match body["method"].as_str().unwrap_or("") {
                    "getLedgerEntries" => {
                        stellar_agent_test_support::signed_envelope::ledger_entries_result_for(&[
                            FROM, ISSUER,
                        ])
                    }
                    "getNetwork" => {
                        stellar_agent_test_support::signed_envelope::get_network_result(
                            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                        )
                    }
                    "getFeeStats" => serde_json::json!({}),
                    _ => serde_json::json!({}),
                };
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": result,
                }))
            })
            .mount(&rpc)
            .await;
        let mut profile =
            Profile::builder_testnet_named(NAME, "svc-trustline-drain", FROM, "n-svc", "n-acct")
                .with_noop_engine()
                .build();
        profile.rpc_url = rpc.uri();
        profile.audit_log_path = home.path().join("audit").join(format!("{NAME}.jsonl"));
        let log_path = profile.audit_log_path.clone();

        let queued = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let queue_hook = {
            let queued = Arc::clone(&queued);
            let log_path = log_path.clone();
            Arc::new(move || {
                if queued.swap(true, Ordering::SeqCst) {
                    return;
                }
                AuditOutbox::for_log(&log_path)
                    .append(&AuditEntry::new_approval_attested(
                        "TrustlineClawbackOptIn",
                        "stellar_trustline_commit",
                        None,
                        "queued-trustline-consent",
                        "cli",
                        "queued-consent",
                    ))
                    .unwrap();
            }) as Arc<dyn Fn() + Send + Sync>
        };
        let signer_hook = {
            let seen = Arc::clone(&seen);
            let log_path = log_path.clone();
            Arc::new(move || {
                seen.lock().unwrap().push(
                    std::fs::read_to_string(&log_path)
                        .unwrap_or_default()
                        .contains(r#""kind":"approval_attested""#),
                );
            }) as Arc<dyn Fn() + Send + Sync>
        };
        install_with_read_hooks(vec![
            ReadHook::new(
                &profile.attestation_key_id.service,
                &profile.attestation_key_id.account,
                queue_hook,
            ),
            ReadHook::new(
                &profile.mcp_signer_default.service,
                &profile.mcp_signer_default.account,
                signer_hook,
            ),
        ])
        .unwrap();
        for coord in [
            &profile.audit_log_hash_chain_key_id,
            &profile.attestation_key_id,
        ] {
            keyring_core::Entry::new(&coord.service, &coord.account)
                .unwrap()
                .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x3a; 32]))
                .unwrap();
        }

        // An earlier keyed call caches the writer in this process.
        let _cached = AuditWriterRegistry::get_or_open_keyed(
            NAME,
            &log_path,
            stellar_agent_network::keyring::keyed_audit_access(
                &profile,
                NAME,
                stellar_agent_core::audit_log::BindingCheck::Enforce,
            )
            .unwrap(),
        )
        .unwrap();

        let args = TrustlineArgs {
            profile: Some(NAME.to_owned()),
            from: FROM.to_owned(),
            asset: format!("USDC:{ISSUER}"),
            limit_stroops: None,
            classic_base: None,
        };
        let loaded = profile.clone();
        let code = run_with_dependencies(
            &args,
            move |_| Ok(loaded.clone()),
            || Ok(()),
            &mut std::io::sink(),
        )
        .await;
        assert_eq!(code, 1, "no signer is seeded");
        assert!(
            queued.load(Ordering::SeqCst),
            "the opt-in read loaded the attestation key"
        );
        let seen = seen.lock().unwrap().clone();
        assert!(!seen.is_empty(), "the verb reached the signer load");
        assert!(
            seen.iter().all(|in_log| *in_log),
            "the consent row must be in the log when the signing key loads: {seen:?}"
        );
    }
}
