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
//!    now that both views from steps 2-3 are populated.
//! 5. `clawback_gate(flags, opt_in_present)` where `opt_in_present` is derived
//!    from the wallet-controlled `PendingApprovalStore` (NOT a CLI flag).
//! 6. `TrustlinePreview::build` — typed JSON preview rendered to stdout.
//! 7. `RefuseWithWarning` / `Refuse` gate decisions → early return (exit 1).
//! 8. Build `ChangeTrust` envelope via `ClassicOpBuilder::change_trust`.
//! 9. Sign via keyring → submit → wait for confirmation.
//!
//! # Policy engine
//!
//! Uses the shared `commands::policy_engine::build_v1_policy_engine` builder,
//! same as `lend.rs` / `vault.rs` / `trade.rs`, and gates via the shared
//! `evaluate_value_moving_policy` args-path helper (the `Trustline` leg is
//! derived from `policy_args` by `derive_value_class` — no typed leg builder
//! is needed for this verb).  `policy_args` is built by
//! `commands::policy_engine::trustline_policy_args`, matching the MCP
//! `stellar_trustline` twin's `{from, asset}` dispatch fields.
//! `account_view` is the fetched source account; `identity_view` is `None`
//! (the issuer's on-chain `home_domain` is self-asserted and must not feed
//! allowlist matching, so identity-class criteria configured on this verb
//! fail closed).
//!
//! # Output
//!
//! JSON.  Returns `0` on success, `1` on error.
//!
//! # Behavior
//!
//! The denomination resolver pins issuers and refuses USDT. A live issuer-flag
//! fetch feeds a named clawback gate that discloses clawback-enabled issuers.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use keyring_core::Entry as KeyringEntry;
use serde_json::json;

use stellar_agent_core::approval::store::PendingApproval;
use stellar_agent_core::approval::user_id::process_uid_for_attestation;
use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, DEFAULT_TTL_MS, open_with_retry,
};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::WalletError;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::schema::{Profile, default_approval_dir};

use crate::commands::policy_engine::{
    build_v1_policy_engine, evaluate_value_moving_policy, trustline_policy_args,
};

use stellar_agent_network::{
    AccountView, Asset, ClassicOpBuilder, StellarRpcClient, SubmissionSignerKind, fetch_account,
    init_platform_keyring_store, parse_classic_fee_choice,
    policy_view::AccountViewAdapter,
    resolve_classic_fee_selection, signer_from_keyring,
    signing::envelope_signing::attach_signature,
    submit::{SubmissionResult, submit_transaction_and_wait},
};

use stellar_agent_network::account::AccountFlagsView;
use stellar_agent_stablecoin::{
    preview::{GateDecisionView, TrustlinePreview},
    resolve::{DenominationInput, resolve_denomination},
};

use crate::common::render::render_json;

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
/// 5. Preview to stdout.
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
    /// Profile name to load (default: "default").
    #[arg(long, default_value = "default")]
    pub profile: String,

    /// CAIP-2 chain identifier (e.g. `stellar:testnet`).
    ///
    /// When absent, the value from the loaded profile is used.
    #[arg(long)]
    pub chain_id: Option<String>,

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
        |name| profile_loader::load(name, None),
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and a
/// spy initialiser to assert the keyring store is registered before signer
/// resolution without touching the OS keychain.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &TrustlineArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, profile_loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Load profile ──────────────────────────────────────────────────────────
    let profile = match load_profile(&args.profile) {
        Ok(p) => p,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.profile_load_failed",
                e.to_string(),
            ));
            return 1;
        }
    };

    // ── Initialise platform keyring store ─────────────────────────────────────
    // The keyring signer loaded before signing requires the process-global
    // default store.  Ordered after the profile load so a missing profile never
    // triggers the store registration.
    if let Err(e) = init_keyring() {
        render_json(&Envelope::<()>::err(&e));
        return 1;
    }

    let rpc_url = profile.rpc_url.as_str();
    let network_passphrase = profile.network_passphrase.as_str();
    let chain_id: String = args
        .chain_id
        .clone()
        .unwrap_or_else(|| profile.chain_id.caip2_str().to_owned());
    let chain_id = chain_id.as_str();

    // ── Validate G-strkey ─────────────────────────────────────────────────────
    if let Err(err) = stellar_strkey::ed25519::PublicKey::from_string(&args.from) {
        render_json(&Envelope::<()>::err_raw(
            "trustline.invalid_from",
            format!("invalid from address (expected G-strkey): {err}"),
        ));
        return 1;
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
            render_json(&Envelope::<()>::err_raw(
                "trustline.denomination_refused",
                e.to_string(),
            ));
            return 1;
        }
    };

    // ── GATE 2: Live issuer account fetch ──────────────────────────────────────
    let rpc_client = match StellarRpcClient::new(rpc_url) {
        Ok(c) => c,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.rpc_init_failed",
                e.to_string(),
            ));
            return 1;
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
            render_json(&Envelope::<()>::err_raw(
                "trustline.source_account_fetch_failed",
                e.to_string(),
            ));
            return 1;
        }
    };
    let source_sequence = source_account_view.sequence_number;

    // ── GATE 4: Operator policy evaluation (args-path; mirrors the MCP
    // `stellar_trustline` twin, which derives its `Trustline` leg from the
    // dispatch args via `derive_value_class` rather than a typed builder) ────
    let policy_engine = match build_v1_policy_engine("trustline", &profile.policy.engine, &profile)
    {
        Ok(pe) => pe,
        Err(msg) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.policy_engine_unavailable",
                msg,
            ));
            return 1;
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
            render_json(&envelope);
            return 1;
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
    // Network key: `profile.chain_id.caip2_str()` — canonical and consistent
    // across mint, digest, record, and lookup.
    //
    // Keyring unavailable → fail-closed: opt-in treated as absent.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(ms) => ms,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.clock_error",
                e.to_string(),
            ));
            return 1;
        }
    };
    let network_key = profile.chain_id.caip2_str();
    let opt_in_present: bool = {
        match load_attestation_key_for_verify(&profile) {
            Ok(key_bytes) => {
                let attestation_key = zeroize::Zeroizing::new(key_bytes);
                default_approval_dir()
                    .ok()
                    .map(|dir| {
                        let store_path = dir.join(format!("{}.toml", args.profile));
                        open_with_retry(&store_path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF)
                            .map(|store| {
                                store.verify_attested_trustline_clawback_opt_in(
                                    &attestation_key,
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
    // `stellar-agent approve --id <nonce>`.  On the next trustline invocation the
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
                    render_json(&Envelope::<()>::err_raw(
                        "trustline.uid_unavailable",
                        e.to_string(),
                    ));
                    return 1;
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
                        let store_path = dir.join(format!("{}.toml", args.profile));
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
                                            render_json(&Envelope::ok(serde_json::json!({
                                                "outcome": "clawback_opt_in_required",
                                                "warning": warning,
                                                "opt_in_approval": {
                                                    "approval_nonce": opt_in_nonce,
                                                    "expires_at_unix_ms": opt_in_expires,
                                                    "instructions": "Run `stellar-agent approve \
                                                        --id <approval_nonce>` to record the \
                                                        clawback opt-in, then re-invoke trustline.",
                                                },
                                            })));
                                            return 1;
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
            render_json(&Envelope::<()>::err_raw(
                "trustline.clawback_gate_refused",
                warning,
            ));
            return 1;
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
            render_json(&Envelope::<()>::err_raw("trustline.gate_refused", reason));
            return 1;
        }
    }

    // ── Render preview to stdout (before signing) ─────────────────────────────
    let preview_envelope = Envelope::ok(json!({
        "stage": "preview",
        "code": &preview.code,
        "issuer": &preview.issuer,
        "issuer_redacted": redact_strkey_first5_last5(&preview.issuer),
        "limit_stroops": preview.limit_stroops.map(|v| v.to_string()),
        "is_pinned": preview.is_pinned,
        "issuer_flags": &preview.issuer_flags,
        "gate_decision": &preview.gate_decision,
    }));
    render_json(&preview_envelope);

    // ── Fee resolution ────────────────────────────────────────────────────────
    let fee_choice = match parse_classic_fee_choice(args.classic_base.as_deref()) {
        Ok(fc) => fc,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.invalid_fee",
                e.code().to_string(),
            ));
            return 1;
        }
    };
    // Unwrap Option<u32> with a safe default (100 stroops = testnet safe floor).
    // The MCP path uses the common helper `resolve_classic_fee_per_op_stroops`;
    // the CLI path is equivalent: fallback to 100 when the profile has no explicit
    // fee configured.
    const DEFAULT_CLASSIC_FEE_STROOPS: u32 = 100;
    let default_fee_per_op = profile
        .classic_fee_per_op_stroops
        .unwrap_or(DEFAULT_CLASSIC_FEE_STROOPS);
    let fee_selection =
        match resolve_classic_fee_selection(&rpc_client, default_fee_per_op, fee_choice).await {
            Ok(sel) => sel,
            Err(e) => {
                render_json(&Envelope::<()>::err_raw(
                    "trustline.fee_resolution_failed",
                    e.to_string(),
                ));
                return 1;
            }
        };
    let fee_per_op = fee_selection.per_op_stroops;

    // ── Build unsigned ChangeTrust envelope ───────────────────────────────────
    let asset = match Asset::from_code_and_issuer(&resolved.code, &resolved.issuer) {
        Ok(a) => a,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.asset_build_failed",
                e.to_string(),
            ));
            return 1;
        }
    };

    let mut builder =
        ClassicOpBuilder::new(&args.from, source_sequence, network_passphrase, fee_per_op);
    if let Err(e) = builder.change_trust(&asset, args.limit_stroops) {
        render_json(&Envelope::<()>::err_raw(
            "trustline.envelope_build_failed",
            e.to_string(),
        ));
        return 1;
    }
    let envelope_xdr = match builder.build() {
        Ok(xdr) => xdr,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.envelope_build_failed",
                e.to_string(),
            ));
            return 1;
        }
    };

    // NEVER log the envelope XDR at info.
    tracing::debug!(
        subcommand = "trustline",
        chain = %chain_id,
        "ChangeTrust envelope built (XDR at debug only)"
    );

    // ── Load signer from keyring ──────────────────────────────────────────────
    let signer_entry_ref = &profile.mcp_signer_default;
    let expected_g = signer_entry_ref.account.as_str();
    let signer_handle = match signer_from_keyring(signer_entry_ref, expected_g).await {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.signer_load_failed",
                e.to_string(),
            ));
            return 1;
        }
    };

    // ── Sign envelope ─────────────────────────────────────────────────────────
    let signed_xdr = match attach_signature(&envelope_xdr, &signer_handle, network_passphrase).await
    {
        Ok(s) => s,
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.sign_failed",
                e.to_string(),
            ));
            return 1;
        }
    };

    // ── Submit ────────────────────────────────────────────────────────────────
    let timeout = std::time::Duration::from_secs(profile.submit_timeout_seconds.unwrap_or(90));
    match submit_transaction_and_wait(
        &rpc_client,
        &signed_xdr,
        timeout,
        network_passphrase,
        Some(SubmissionSignerKind::Keyring),
    )
    .await
    {
        Ok(SubmissionResult {
            tx_hash, ledger, ..
        }) => {
            let tx_hash_redacted = format!(
                "{}…{}",
                &tx_hash[..8.min(tx_hash.len())],
                if tx_hash.len() > 8 {
                    &tx_hash[tx_hash.len().saturating_sub(8)..]
                } else {
                    ""
                }
            );
            tracing::info!(
                subcommand = "trustline",
                chain = %chain_id,
                code = %resolved.code,
                issuer = %redact_strkey_first5_last5(&resolved.issuer),
                tx_hash = %tx_hash_redacted,
                ledger = ?ledger,
                "ChangeTrust tx submitted"
            );

            // Non-fatal allow-path audit row carrying the SAME legs the gate
            // sized (single-derivation invariant), recorded on confirmed submit.
            let audit_legs: Vec<stellar_agent_core::audit_log::ValueLegRecord> = trustline_effects
                .as_ref()
                .map(|e| e.legs().iter().map(Into::into).collect())
                .unwrap_or_default();
            let audit_request_id = uuid::Uuid::new_v4().to_string();
            let audit_entry = stellar_agent_core::audit_log::AuditEntry::new_value_action_submitted(
                "stellar_trustline",
                chain_id,
                audit_legs,
                tx_hash_redacted.as_str(),
                ledger,
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                None,
                None,
                &audit_request_id,
            );
            crate::commands::value_audit::emit_value_audit_row(
                &profile,
                &args.profile,
                audit_entry,
            );
            crate::commands::policy_engine::record_confirmed_value_moving_with_engine(
                policy_engine.as_ref(),
                &profile,
                &args.profile,
                "stellar_trustline",
                chain_id,
                trustline_effects.as_ref(),
            );

            render_json(&Envelope::ok(json!({
                "status": "submitted",
                "action": "change_trust",
                "code": resolved.code,
                "issuer_redacted": redact_strkey_first5_last5(&resolved.issuer),
                "limit_stroops": args.limit_stroops.map(|v| v.to_string()),
                "is_pinned": resolved.is_pinned,
                "tx_hash": tx_hash,
                "ledger": ledger,
            })));
            0
        }
        Err(e) => {
            render_json(&Envelope::<()>::err_raw(
                "trustline.submit_failed",
                e.to_string(),
            ));
            1
        }
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
) -> Result<[u8; 32], ()> {
    let entry_ref = &profile.attestation_key_id;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|_| ())?;
    let raw = entry.get_password().map_err(|_| ())?;
    let bytes = URL_SAFE_NO_PAD.decode(raw.trim()).map_err(|_| ())?;
    if bytes.len() != 32 {
        return Err(());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
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
            profile: "keyring-order-test".to_owned(),
            chain_id: None,
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
}
