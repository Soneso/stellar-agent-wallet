//! `stellar-agent trustline` subcommand — stablecoin `ChangeTrust` verb.
//!
//! # What this command does
//!
//! Builds, signs, and submits a Stellar `ChangeTrust` classic transaction.
//! Enforces the full ordered trust gate before signing:
//!
//! 1. `resolve_denomination` — USDT hard-refusal + known-lookalike denylist +
//!    pinned-issuer-mismatch + unpinned-bare-code.
//! 2. Endpoint identity check on the one client that every later read and the
//!    send use, under the profile's [`Profile::submit_timeout`]. An endpoint
//!    serving another network is refused before it answers any read.
//! 3. Live issuer account fetch via `fetch_account` → `AccountFlagsView`
//!    (for the clawback gate).
//! 4. Source account fetch via `fetch_account` (for the policy gate's
//!    `account_view`; sequence number consumed at envelope-build time).
//! 5. Fee resolution, with the profile's per-operation fee as the default
//!    source, and the unsigned `ChangeTrust` envelope via
//!    `ClassicOpBuilder::change_trust`, so the policy counts the fee.
//! 6. Operator policy evaluation: the shared
//!    [`crate::commands::policy_engine::build_v1_policy_engine`]
//!    (V1 `NoopPolicyEngine` / `PolicyEngineV1`; fail-closed on build failures),
//!    once both views from steps 3-4 are populated, with the envelope's total
//!    fee in the arguments. A denial is a clean refusal that signs nothing and
//!    requires no audit setup.
//! 7. Audit pre-flight (fail-closed): the profile's audit
//!    chain-root key must be acquirable via
//!    [`crate::commands::value_audit::require_value_audit_writer`] before any
//!    later step touches the signer or submits; refuses
//!    `audit.chain_key_unavailable` otherwise. The acquired writer is reused
//!    for the post-confirm row.
//! 8. `clawback_gate(flags, opt_in_present)` where `opt_in_present` is derived
//!    from the wallet-controlled `PendingApprovalStore` (NOT a CLI flag).
//! 9. `TrustlinePreview::build`: the typed preview of the trustline.
//! 10. `RefuseWithWarning` / `Refuse` gate decisions → early return (exit 1).
//! 11. The classic fee cap on the built fee.
//! 12. Cross-check witness of the source account and the issuer, before the
//!     signer loads. A disagreement refuses `simulation.divergence`; an
//!     oracle that cannot serve refuses `network.witness_unavailable`.
//! 13. Sign via keyring → submit → wait for confirmation. The submit layer
//!     checks the endpoint of the sending client again before the send.
//!
//! # Mainnet
//!
//! A build without the `mainnet-write` feature refuses a mainnet profile with
//! `network.mainnet_write_forbidden` before the keyring and any request. With
//! the feature, the run takes the stored profile of an explicit `--profile`
//! selection, a verified signed policy with a `[mainnet]` table and its
//! enablement, the enrolled keyring signer, the independent witness, and a
//! confirmation on a terminal where the operator types the profile name. The
//! signed fee cap applies before the audit pre-flight and the clawback gate,
//! and the keyring seed is read only after the authorization is minted.
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
//! The typed preview from step 9 is rendered once, as a nested `preview`
//! object, after the step 10 gate decision passes. It sits in `data.preview`
//! beside the submission result on success. It sits in
//! `error.details.preview` when a later stage fails: the fee cap, the
//! witness, signing, or submission. The fee cap and witness refusals keep
//! their own codes. A refusal up to and including the step 10 gate decision
//! carries no preview.
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
use stellar_agent_core::cross_check::CrossCheckValue;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{FeeSource, NetworkError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::loader as profile_loader;
use stellar_agent_core::profile::schema::{Profile, default_approval_dir};
use stellar_agent_network::cross_check::{
    AccountObservation, CrossCheckView, IssuerObservation, TrustlineWitnessInputs,
    obtain_classic_witness, obtain_classic_witness_bound,
};
use stellar_agent_network::fees::{
    check_classic_fee_cap, check_classic_fee_cap_signed, classic_fee_source,
};
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::{ClassicFeeChoice, MainnetEndpointFlags};

use crate::commands::policy_engine::{
    build_v1_policy_engine, effective_classic_fee_cap, envelope_total_fee, evaluate_mainnet_policy,
    evaluate_value_moving_policy, load_mainnet_policy_engine, trustline_policy_args,
    with_total_fee,
};

use stellar_agent_network::{
    AccountView, Asset, ClassicOpBuilder, StellarRpcClient, SubmissionRecorder,
    SubmissionSignerKind, enrolled_keyring_signer, fetch_account, init_platform_keyring_store,
    is_credential_error, parse_classic_fee_choice,
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

use crate::common::mainnet_write::{
    MainnetWriteRequest, authorize_and_submit, mainnet_context, mainnet_profiles_dir,
    require_v1_engine,
};
use crate::common::network::check_endpoint_identity;
use crate::common::profile_access::{
    ProfileAccessError, injected_profile_load, reconcile_loaded_profile,
};
use crate::common::render::{WithPreview, with_preview_detail, write_envelope};
use crate::common::resolve_profile_name;
use crate::common::signer_ceremony::MainnetSignerChoice;

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
/// 3. Live issuer account fetch. An issuer read error refuses with its own
///    code; an absent issuer yields the gate's `Refuse`.
/// 4. `clawback_gate` — wallet-controlled approval store opt-in lookup.
/// 5. Typed preview, reported in the one output envelope.
/// 6. Fee cap and cross-check witness.
/// 7. Build → sign → submit.
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
/// Returns `1` on any gate failure, denomination error, issuer read error,
/// fee cap or witness refusal, build error, sign error, or submit error.
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
    // `rpc_url`, an endpoint URL that breaks the endpoint rule, or an invalid
    // provider attestation.
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

    // ── Mainnet: its own pipeline from the write context ─────────────────────
    // Before the keyring store, the signer, and any RPC request.
    if context.chain_id.is_mainnet() {
        return run_mainnet_pipeline(args, &resolved, &profile, init_keyring, out).await;
    }

    // ── Initialise platform keyring store ─────────────────────────────────────
    // The keyring signer loaded before signing requires the process-global
    // default store.  Ordered after the profile load so a missing profile never
    // triggers the store registration.
    if let Err(e) = init_keyring() {
        return write_envelope(out, &Envelope::<()>::err(&e), 1);
    }

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
    // A credential failure keeps its own code; a transport refusal of the
    // URL keeps the trustline code.
    let rpc_client = match context.primary_client() {
        Ok(c) => c,
        Err(e) if is_credential_error(&e) => {
            return write_envelope(out, &Envelope::<()>::err(&e), 1);
        }
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.rpc_init_failed", e.to_string()),
                1,
            );
        }
    };

    // The endpoint check precedes the issuer read: the issuer flags feed the
    // clawback gate, and every later read and the send use this client. It
    // gets its own budget of the profile's submit timeout.
    if let Err(e) = check_endpoint_identity(&rpc_client, &context, profile.submit_timeout()).await {
        return write_envelope(out, &Envelope::<()>::err(&e), 1);
    }

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
            Err(WalletError::Network(NetworkError::AccountNotFound { .. })) => None,
            Err(error) => return write_envelope(out, &Envelope::<()>::err(&error), 1),
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

    // ── Fee and unsigned ChangeTrust envelope ─────────────────────────────────
    // Built before the gate, so the policy counts the fee the envelope pays.
    let built = match build_change_trust(
        args,
        &profile,
        &rpc_client,
        context.chain_id,
        &resolved,
        &source_account_view,
    )
    .await
    {
        Ok(built) => built,
        Err(envelope) => return write_envelope(out, &envelope, 1),
    };
    let total_fee = match envelope_total_fee(&built.envelope_xdr) {
        Ok(fee) => fee,
        Err(e) => return write_envelope(out, &Envelope::<()>::err(&e), 1),
    };

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
    let policy_args = with_total_fee(trustline_policy_args(&args.from, &args.asset), total_fee);
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

    let preview = match clawback_gate(
        out,
        &profile,
        &profile_name,
        context.chain_id,
        &resolved,
        issuer_flags.as_ref(),
        args.limit_stroops,
    ) {
        Ok(preview) => preview,
        Err(code) => return code,
    };

    // ── Report every later stage in one envelope carrying the preview ────────
    let preview_view = trustline_preview_view(&preview);
    let outcome = sign_and_submit(
        GatedTrustline {
            args,
            profile: &profile,
            profile_name: &profile_name,
            context: &context,
            rpc_client: &rpc_client,
            network_passphrase,
            chain_id,
            resolved: &resolved,
            source: &source_account_view,
            issuer: IssuerObservation::from_view(&resolved.issuer, issuer_account_view.as_ref()),
            built,
            effects: trustline_effects.as_ref(),
            audit_writer: &audit_writer,
            now_ms,
        },
        submit_transaction_and_wait,
    )
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
    context: &'a NetworkContext,
    rpc_client: &'a StellarRpcClient,
    network_passphrase: &'a str,
    chain_id: &'a str,
    resolved: &'a ResolvedAsset,
    source: &'a AccountView,
    issuer: IssuerObservation,
    built: BuiltTrustline,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cross_check: Option<CrossCheckView>,
}

/// Caps the built fee, obtains the cross-check witness of the source and the
/// issuer, then signs, records, and submits the built `ChangeTrust` envelope.
///
/// `submit_and_wait` is the submission step, with the signature of
/// [`submit_transaction_and_wait`], which production passes. It receives the
/// profile's [`Profile::submit_timeout`].
///
/// Renders nothing: the caller reports the returned payload or failure
/// envelope in the one envelope that carries the preview.
async fn sign_and_submit<S>(
    gated: GatedTrustline<'_>,
    submit_and_wait: S,
) -> Result<TrustlineSubmitted, Envelope<()>>
where
    S: AsyncFnOnce(
        &StellarRpcClient,
        &str,
        std::time::Duration,
        &str,
        Option<SubmissionSignerKind>,
        Option<&dyn SubmissionRecorder>,
    ) -> Result<SubmissionResult, WalletError>,
{
    let GatedTrustline {
        args,
        profile,
        profile_name,
        context,
        rpc_client,
        network_passphrase,
        chain_id,
        resolved,
        source,
        issuer,
        built,
        effects,
        audit_writer,
        now_ms,
    } = gated;

    check_classic_fee_cap(
        built.fee_per_op,
        classic_fee_source(built.fee_choice, FeeSource::ProfileDefault),
        profile,
    )
    .map_err(|error| Envelope::<()>::err(&error))?;
    let cross_check = obtain_classic_witness(
        profile,
        context,
        CrossCheckValue::Unvalued,
        TrustlineWitnessInputs {
            source: AccountObservation::from_view(source)
                .map_err(|error| Envelope::<()>::err(&error))?,
            issuer,
        },
        "stellar_trustline",
    )
    .await
    .map_err(|error| Envelope::<()>::err(&error))?;
    let envelope_xdr = built.envelope_xdr;

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
    .map_err(submission_failure)?
    .with_witness(cross_check.witness());

    let SubmissionResult {
        tx_hash, ledger, ..
    } = submit_and_wait(
        rpc_client,
        &signed_xdr,
        profile.submit_timeout(),
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
        cross_check: Some(cross_check.view()),
    })
}

/// A built, unsigned `ChangeTrust` envelope and the fee it pays.
struct BuiltTrustline {
    /// The unsigned envelope, base64.
    envelope_xdr: String,
    /// The parsed `--fee` choice, which names the fee's source in a cap
    /// refusal.
    fee_choice: ClassicFeeChoice,
    /// The selected per-operation fee.
    fee_per_op: u32,
}

/// Resolves the fee and builds the unsigned `ChangeTrust` envelope of `from`
/// for `resolved`, at the source's current sequence.
///
/// # Errors
///
/// `trustline.invalid_fee`, `trustline.fee_resolution_failed`,
/// `trustline.asset_build_failed` or `trustline.envelope_build_failed`.
async fn build_change_trust(
    args: &TrustlineArgs,
    profile: &Profile,
    rpc_client: &StellarRpcClient,
    chain: stellar_agent_core::profile::caip2::Caip2,
    resolved: &ResolvedAsset,
    source: &AccountView,
) -> Result<BuiltTrustline, Envelope<()>> {
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

    let asset = Asset::from_code_and_issuer(&resolved.code, &resolved.issuer)
        .map_err(|e| Envelope::<()>::err_raw("trustline.asset_build_failed", e.to_string()))?;
    let envelope_build_failed =
        |e: WalletError| Envelope::<()>::err_raw("trustline.envelope_build_failed", e.to_string());
    let mut builder = ClassicOpBuilder::new(
        &args.from,
        source.sequence_number,
        chain.network_passphrase(),
        fee_per_op,
    );
    builder
        .change_trust(&asset, args.limit_stroops)
        .map_err(envelope_build_failed)?;
    let envelope_xdr = builder.build().map_err(envelope_build_failed)?;

    // NEVER log the envelope XDR at info.
    tracing::debug!(
        subcommand = "trustline",
        chain = %chain.caip2_str(),
        "ChangeTrust envelope built (XDR at debug only)"
    );
    Ok(BuiltTrustline {
        envelope_xdr,
        fee_choice,
        fee_per_op,
    })
}

/// Runs the wallet-controlled clawback gate of a trustline to `resolved`.
///
/// Reads the HMAC-verified opt-in from the approval store, builds the
/// preview, and applies its gate decision. A clawback-enabled issuer without
/// a verified opt-in gets an opt-in pending entry and the
/// `clawback_opt_in_required` outcome.
///
/// # Errors
///
/// Returns the exit code after writing the gate's outcome or refusal to
/// `out`.
fn clawback_gate(
    out: &mut dyn Write,
    profile: &Profile,
    profile_name: &str,
    chain: stellar_agent_core::profile::caip2::Caip2,
    resolved: &ResolvedAsset,
    issuer_flags: Option<&AccountFlagsView>,
    limit_stroops: Option<i64>,
) -> Result<TrustlinePreview, i32> {
    // ── GATE 5: Wallet-controlled clawback opt-in lookup (HMAC-verified) ────
    //
    // `opt_in_present` is NOT a CLI flag; it is derived from the wallet-controlled
    // approval store only.
    //
    // The lookup MUST be HMAC-verified: `verify_attested_trustline_clawback_opt_in`
    // loads the attestation key from the keyring and calls `verify_attestation`
    // (constant-time HMAC-SHA256).  A presence-only check allows forged blobs.
    //
    // Network key: `chain.caip2_str()` is canonical and consistent across
    // mint, digest, record, and lookup.
    //
    // Keyring unavailable: fail closed, the opt-in is treated as absent.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(ms) => ms,
        Err(e) => {
            return Err(write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.clock_error", e.to_string()),
                1,
            ));
        }
    };
    let network_key = chain.caip2_str();
    let opt_in_present: bool = {
        match load_attestation_key_for_verify(profile, profile_name) {
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
                                        profile_name,
                                        chain.caip2_str(),
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
                // Keyring unavailable: fail closed, treat the opt-in as absent.
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
        limit_stroops,
        issuer_flags,
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
            // The gate passed; the preview is returned below.
        }
        GateDecisionView::RefuseWithWarning { warning } => {
            tracing::info!(
                subcommand = "trustline",
                chain = %chain.caip2_str(),
                code = %resolved.code,
                issuer = %redact_strkey_first5_last5(&resolved.issuer),
                warning = %warning,
                "clawback gate RefuseWithWarning: minting opt-in pending entry"
            );
            // Mint the opt-in pending entry so the operator can approve it.
            let uid = match process_uid_for_attestation() {
                Ok(u) => u,
                Err(e) => {
                    return Err(write_envelope(
                        out,
                        &Envelope::<()>::err_raw("trustline.uid_unavailable", e.to_string()),
                        1,
                    ));
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
                                            return Err(write_envelope(
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
                                            ));
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
            return Err(write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.clawback_gate_refused", warning),
                1,
            ));
        }
        GateDecisionView::Refuse { reason } => {
            tracing::info!(
                subcommand = "trustline",
                chain = %chain.caip2_str(),
                code = %resolved.code,
                issuer = %redact_strkey_first5_last5(&resolved.issuer),
                reason = %reason,
                "clawback gate Refuse: trustline refused (fail-closed or hard-refusal)"
            );
            return Err(write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.gate_refused", reason),
                1,
            ));
        }
    }
    Ok(preview)
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

/// The keyring loader reports authentication errors under their own codes.
/// The fallback uses `trustline.signer_load_failed` to name the verb for any other error.
/// Both preserve the error message.
fn signer_load_failure_parts(e: &WalletError) -> (&'static str, String) {
    match e {
        WalletError::Auth(_) => (e.code(), e.to_string()),
        _ => ("trustline.signer_load_failed", e.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mainnet pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the trustline on a mainnet profile.
///
/// The stored profile of the explicit selection replaces the merged one at
/// the write context, and every later step reads it from the context. The
/// verb's own steps run up to the clawback gate and the bound witness, and
/// [`authorize_and_submit`] runs the rest with the enrolled keyring signer,
/// calling the authorized submit directly.
async fn run_mainnet_pipeline<InitKeyring>(
    args: &TrustlineArgs,
    resolved: &crate::common::ResolvedProfileName,
    profile: &Profile,
    init_keyring: InitKeyring,
    out: &mut dyn Write,
) -> i32
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let context = match mainnet_context(profile, resolved, MainnetEndpointFlags::default()) {
        Ok(context) => context,
        Err(e) => return write_envelope(out, &Envelope::<()>::err(&e), 1),
    };
    let net_context = context.network_context();
    let profile = context.profile();
    let name = context.profile_name();
    if let Err(envelope) = require_v1_engine("trustline", &context) {
        return write_envelope(out, &envelope, 1);
    }
    if let Err(e) = init_keyring() {
        return write_envelope(out, &Envelope::<()>::err(&e), 1);
    }
    let profiles_dir = match mainnet_profiles_dir() {
        Ok(dir) => dir,
        Err(e) => return write_envelope(out, &Envelope::<()>::err(&e), 1),
    };
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
    let asset = match resolve_denomination(
        parse_denomination_input(&args.asset),
        context.network_passphrase(),
    ) {
        Ok(asset) => asset,
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.denomination_refused", e.to_string()),
                1,
            );
        }
    };

    // One client serves every read, the resolver and the send.
    let client = match context.primary_client() {
        Ok(client) => client,
        Err(e) if is_credential_error(&e) => {
            return write_envelope(out, &Envelope::<()>::err(&e), 1);
        }
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.rpc_init_failed", e.to_string()),
                1,
            );
        }
    };
    if let Err(e) = check_endpoint_identity(&client, &net_context, profile.submit_timeout()).await {
        return write_envelope(out, &Envelope::<()>::err(&e), 1);
    }
    let issuer_account_view = match fetch_account(&client, &asset.issuer, &[]).await {
        Ok(view) => Some(view),
        Err(WalletError::Network(NetworkError::AccountNotFound { .. })) => None,
        Err(error) => return write_envelope(out, &Envelope::<()>::err(&error), 1),
    };
    let issuer_flags: Option<AccountFlagsView> = issuer_account_view
        .as_ref()
        .and_then(|v| v.account_flags.clone());
    let source_account_view = match fetch_account(&client, &args.from, &[]).await {
        Ok(view) => view,
        Err(e) => {
            return write_envelope(
                out,
                &Envelope::<()>::err_raw("trustline.source_account_fetch_failed", e.to_string()),
                1,
            );
        }
    };
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
        profile,
        name,
        crate::common::profile_access::ProfileOrigin::Persisted,
        &client,
        now_ms,
    )
    .await;

    let built = match build_change_trust(
        args,
        profile,
        &client,
        context.chain(),
        &asset,
        &source_account_view,
    )
    .await
    {
        Ok(built) => built,
        Err(envelope) => return write_envelope(out, &envelope, 1),
    };
    let policy = match load_mainnet_policy_engine(
        "trustline",
        "trustline.policy_engine_unavailable",
        &context,
        resolved.source,
        &profiles_dir,
    ) {
        Ok(policy) => policy,
        Err(envelope) => return write_envelope(out, &envelope, 1),
    };
    let total_fee = match envelope_total_fee(&built.envelope_xdr) {
        Ok(fee) => fee,
        Err(e) => return write_envelope(out, &Envelope::<()>::err(&e), 1),
    };
    let policy_args = with_total_fee(trustline_policy_args(&args.from, &args.asset), total_fee);
    let source_adapter = AccountViewAdapter::new(&source_account_view);
    let evaluation = match evaluate_mainnet_policy(
        policy.engine.as_ref(),
        profile,
        "stellar_trustline",
        stellar_agent_core::policy::ToolValueKind::MovesValue,
        context.chain().caip2_str(),
        &policy_args,
        "trustline",
        Some(&source_adapter),
        None,
    ) {
        Ok(evaluation) => evaluation,
        Err(envelope) => return write_envelope(out, &envelope, 1),
    };

    let body = &policy.body;
    if let Err(e) = check_classic_fee_cap_signed(
        built.fee_per_op,
        classic_fee_source(built.fee_choice, FeeSource::ProfileDefault),
        profile,
        Some(body.classic_max_fee_per_op_stroops),
    ) {
        return write_envelope(out, &Envelope::<()>::err(&e), 1);
    }
    let effective_cap = effective_classic_fee_cap(profile, body.classic_max_fee_per_op_stroops);
    if let Err(e) = crate::commands::value_audit::require_value_audit_writer(profile, name) {
        return write_envelope(out, &Envelope::<()>::err(&e), 1);
    }
    // The clawback opt-in is read after the audit pre-flight, as on testnet.
    let preview = match clawback_gate(
        out,
        profile,
        name,
        context.chain(),
        &asset,
        issuer_flags.as_ref(),
        args.limit_stroops,
    ) {
        Ok(preview) => preview,
        Err(code) => return code,
    };
    let preview_view = trustline_preview_view(&preview);

    let thresholds = stellar_agent_core::cross_check::ThresholdSet::from_profile_and_signed(
        profile,
        body.cross_check_thresholds.as_ref(),
    );
    let outcome = async {
        let source = AccountObservation::from_view(&source_account_view)
            .map_err(|error| Envelope::<()>::err(&error))?;
        let cross_check = obtain_classic_witness_bound(
            profile,
            &net_context,
            CrossCheckValue::Unvalued,
            TrustlineWitnessInputs {
                source,
                issuer: IssuerObservation::from_view(&asset.issuer, issuer_account_view.as_ref()),
            },
            &built.envelope_xdr,
            &thresholds,
            "stellar_trustline",
        )
        .await
        .map_err(|error| Envelope::<()>::err(&error))?;
        let submitted = authorize_and_submit(MainnetWriteRequest {
            context: &context,
            profiles_dir: &profiles_dir,
            verb: "trustline",
            tool: "stellar_trustline",
            consumer: MainnetConsumer::CliTrustline,
            unsigned_xdr: &built.envelope_xdr,
            client: &client,
            probe_deadline: profile.submit_timeout(),
            submit_timeout: profile.submit_timeout(),
            source: &args.from,
            signer: MainnetSignerChoice::Keyring,
            policy: &policy,
            evaluation: &evaluation,
            effective_cap,
            witness: cross_check.witness(),
        })
        .await?;
        let SubmissionResult {
            tx_hash, ledger, ..
        } = submitted.result;
        Ok(TrustlineSubmitted {
            status: "submitted",
            action: "change_trust",
            code: asset.code.clone(),
            issuer_redacted: redact_strkey_first5_last5(&asset.issuer),
            limit_stroops: args.limit_stroops.map(|v| v.to_string()),
            is_pinned: asset.is_pinned,
            tx_hash,
            ledger,
            cross_check: Some(cross_check.view()),
        })
    }
    .await;
    render_trustline_outcome(out, preview_view, outcome)
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

    /// Runs a trustline on the mainnet profile `trustline-mainnet`, which the
    /// injected loader answers and nothing persists, and returns the exit
    /// code, the rendered envelope, the requests the endpoint received and
    /// the initializer's calls.
    async fn run_unpersisted_mainnet() -> (i32, serde_json::Value, usize, usize) {
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut output = Vec::new();
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
            crate::test_rpc::ImplicitSelection::loader(&rpc.uri()),
            crate::test_rpc::counting_initializer(&calls),
            &mut output,
        )
        .await;
        let rendered: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let requests = rpc.received_requests().await.unwrap().len();
        (code, rendered, requests, calls.get())
    }

    /// Without `mainnet-write` a mainnet profile is refused at the write
    /// context, before the keyring initializer and before any request.
    #[cfg(not(feature = "mainnet-write"))]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn run_refuses_mainnet_before_keyring_and_any_request() {
        let (code, rendered, requests, calls) = run_unpersisted_mainnet().await;
        assert_eq!(code, 1, "a mainnet trustline must exit with code 1");
        assert_eq!(rendered["error"]["code"], "network.mainnet_write_forbidden");
        assert_eq!(requests, 0, "a mainnet trustline must send no request");
        assert_eq!(calls, 0, "the keyring is never initialized");
    }

    /// With `mainnet-write` the write context loads the stored profile, and
    /// an absent profile file refuses before the keyring initializer and
    /// before any request.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn run_refuses_mainnet_before_keyring_and_any_request() {
        let (code, rendered, requests, calls) = run_unpersisted_mainnet().await;
        assert_eq!(code, 1, "a mainnet trustline must exit with code 1");
        assert_eq!(rendered["error"]["code"], "validation.profile_not_found");
        assert_eq!(requests, 0, "a mainnet trustline must send no request");
        assert_eq!(calls, 0, "the keyring is never initialized");
    }

    /// A mainnet profile selected without `--profile` refuses before the
    /// keyring, in both builds.
    async fn assert_implicit_selection_refused(source: crate::test_rpc::ImplicitSource) {
        let selection = crate::test_rpc::ImplicitSelection::new(source);
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut output = Vec::new();
        let args = TrustlineArgs {
            profile: None,
            from: "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned(),
            asset: "USDC".to_owned(),
            limit_stroops: None,
            classic_base: None,
        };
        let code = run_with_dependencies(
            &args,
            crate::test_rpc::ImplicitSelection::loader("https://rpc.example.invalid"),
            crate::test_rpc::counting_initializer(&calls),
            &mut output,
        )
        .await;
        assert_eq!(code, 1);
        let rendered: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            rendered["error"]["code"], "profile.mainnet_requires_explicit_profile",
            "{}: {rendered}",
            selection.name
        );
        assert_eq!(calls.get(), 0, "the keyring is never initialized");
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn a_mainnet_profile_named_by_the_variable_refuses() {
        assert_implicit_selection_refused(crate::test_rpc::ImplicitSource::Env).await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn a_mainnet_profile_saved_as_default_refuses() {
        assert_implicit_selection_refused(crate::test_rpc::ImplicitSource::Default).await;
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
            cross_check: None,
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
        assert!(data.get("cross_check").is_none());
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

    /// Runs a `USDC` trustline of profile `name` with `--fee fee` against a
    /// mocked endpoint, under a profile fee cap of 1000 stroops, and returns
    /// the one envelope it printed and the methods the endpoint received.
    async fn run_with_fee(name: &str, fee: &str) -> (serde_json::Value, Vec<String>) {
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
            Profile::builder_testnet_named(name, "svc-one-envelope", ONE_ENVELOPE_FROM, "n", "a")
                .with_noop_engine()
                .build();
        profile.rpc_url = rpc.uri();
        profile.classic_max_fee_per_op_stroops = Some(1000);
        profile.audit_log_path = home.path().join("audit").join(format!("{name}.jsonl"));
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let audit_key = &profile.audit_log_hash_chain_key_id;
        KeyringEntry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x3a; 32]))
            .unwrap();

        let args = TrustlineArgs {
            profile: Some(name.to_owned()),
            from: ONE_ENVELOPE_FROM.to_owned(),
            asset: format!("USDC:{ONE_ENVELOPE_ISSUER}"),
            limit_stroops: None,
            classic_base: Some(fee.to_owned()),
        };
        let mut out = Vec::new();
        let loaded = profile.clone();
        let code =
            run_with_dependencies(&args, move |_| Ok(loaded.clone()), || Ok(()), &mut out).await;
        assert_eq!(code, 1);
        let envelope = crate::common::render::single_json_document(&out);
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
        (envelope, methods)
    }

    /// A failure after the preview stage prints exactly one JSON document:
    /// the error envelope, with the preview nested at `error.details.preview`.
    ///
    /// `--fee 5000` above the profile's 1000-stroop cap passes every gate up
    /// to the preview and fails at the fee cap check after it, before any
    /// submission.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_failure_after_the_preview_prints_one_envelope_with_the_preview_in_details() {
        let (envelope, methods) = run_with_fee("trustline-one-envelope", "5000").await;

        assert_eq!(envelope["ok"], false, "{envelope}");
        assert_eq!(
            envelope["error"]["code"], "fees.percentile_exceeds_cap",
            "{envelope}"
        );
        let preview = &envelope["error"]["details"]["preview"];
        assert_eq!(preview["code"], "USDC", "{envelope}");
        assert_eq!(preview["issuer"], ONE_ENVELOPE_ISSUER, "{envelope}");
        assert_eq!(preview["gate_decision"]["kind"], "proceed", "{envelope}");
        assert!(
            !methods
                .iter()
                .any(|m| m == "getFeeStats" || m == "sendTransaction"),
            "the fee cap check fails before any later request: {methods:?}"
        );
    }

    /// The fee is parsed with the envelope build, before the policy and the
    /// preview, so a malformed fee refuses with one envelope that carries no
    /// preview, before the fee-statistics request or any submission.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_malformed_fee_refuses_before_the_preview() {
        let (envelope, methods) = run_with_fee("trustline-malformed-fee", "bogus").await;

        assert_eq!(envelope["ok"], false, "{envelope}");
        assert_eq!(
            envelope["error"]["code"], "trustline.invalid_fee",
            "{envelope}"
        );
        assert!(envelope["error"].get("details").is_none(), "{envelope}");
        assert!(
            !methods
                .iter()
                .any(|m| m == "getFeeStats" || m == "sendTransaction"),
            "the fee parse fails before any later request: {methods:?}"
        );
    }

    // ── Submit timeout ────────────────────────────────────────────────────────

    /// Runs the stages after the preview for a `USDC` trustline of profile
    /// `name` from a seeded keyring signer, with a submission step that
    /// records the timeout it is handed and refuses, and returns that timeout.
    ///
    /// The fee comes from the profile default, so no request reaches the
    /// unroutable endpoint the client names. Each call takes its own profile
    /// name: the process-wide audit registry and the keyring tip anchor bind a
    /// profile name to one audit log.
    async fn forwarded_submit_timeout(name: &str, configured: Option<u64>) -> std::time::Duration {
        const SEED: [u8; 32] = [0x5c; 32];

        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let from = stellar_agent_test_support::signed_envelope::account_id_for_seed(SEED);
        let mut profile =
            Profile::builder_testnet_named(name, "svc-submit-timeout", &from, "n", "a")
                .with_noop_engine()
                .build();
        profile.audit_log_path = home.path().join("audit").join(format!("{name}.jsonl"));
        profile.submit_timeout_seconds = configured;

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let audit_key = &profile.audit_log_hash_chain_key_id;
        KeyringEntry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x3a; 32]))
            .unwrap();
        let signer = &profile.mcp_signer_default;
        KeyringEntry::new(&signer.service, &signer.account)
            .unwrap()
            .set_password(
                &stellar_agent_test_support::testnet_strkeys::strkey_from_seed(
                    stellar_agent_test_support::testnet_strkeys::VERSION_PRIVATE_KEY,
                    &SEED,
                ),
            )
            .unwrap();
        let audit_writer =
            crate::commands::value_audit::require_value_audit_writer(&profile, name).unwrap();

        let args = TrustlineArgs {
            profile: Some(name.to_owned()),
            from: from.clone(),
            asset: format!("USDC:{ONE_ENVELOPE_ISSUER}"),
            limit_stroops: None,
            classic_base: None,
        };
        let resolved = resolve_denomination(
            DenominationInput::CodeAndIssuer {
                code: "USDC".to_owned(),
                issuer: ONE_ENVELOPE_ISSUER.to_owned(),
            },
            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
        )
        .unwrap();
        let rpc_client = StellarRpcClient::new("http://127.0.0.1:9").unwrap();
        let context = NetworkContext::from_profile(&profile);
        let source = AccountView::new(
            from.clone(),
            1,
            0,
            vec![stellar_agent_network::BalanceView::new(
                stellar_agent_network::AssetView::native(),
                "100.0000000".to_owned(),
                None,
                "0.0000000".to_owned(),
                "0.0000000".to_owned(),
            )],
            stellar_agent_network::ThresholdsView::new(1, 0, 0, 0),
            vec![],
            None,
            None,
        );
        let built = build_change_trust(
            &args,
            &profile,
            &rpc_client,
            stellar_agent_core::profile::caip2::Caip2::Testnet,
            &resolved,
            &source,
        )
        .await
        .unwrap();

        let forwarded = Arc::new(Mutex::new(None));
        let seen = Arc::clone(&forwarded);
        let outcome = sign_and_submit(
            GatedTrustline {
                args: &args,
                profile: &profile,
                profile_name: name,
                context: &context,
                rpc_client: &rpc_client,
                network_passphrase: stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                chain_id: "stellar:testnet",
                resolved: &resolved,
                source: &source,
                issuer: IssuerObservation::from_view(ONE_ENVELOPE_ISSUER, None),
                built,
                effects: None,
                audit_writer: &audit_writer,
                now_ms: stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            },
            async move |_client: &StellarRpcClient,
                        _envelope: &str,
                        timeout: std::time::Duration,
                        _passphrase: &str,
                        _signer_kind: Option<SubmissionSignerKind>,
                        _recorder: Option<&dyn SubmissionRecorder>| {
                *seen.lock().unwrap() = Some(timeout);
                Err(WalletError::Network(
                    stellar_agent_core::error::NetworkError::EndpointIdentityUnavailable {
                        url: "http://127.0.0.1:9".to_owned(),
                    },
                ))
            },
        )
        .await;

        assert!(
            outcome.is_err(),
            "the submission step refused, so the stage must fail"
        );
        let forwarded = *forwarded.lock().unwrap();
        forwarded.expect("the stages must reach the submission step")
    }

    // ── Endpoint identity: one client, checked before the issuer read ──────

    /// A persisted `Noop` profile named `name` whose endpoint is `rpc_url`,
    /// with its audit key and the signer of `SEED` seeded in the mock keyring
    /// store, under a temporary data root. Returns the profile, the signer's
    /// G-strkey, and the guards to hold.
    fn seeded_trustline_profile(
        name: &str,
        rpc_url: &str,
    ) -> (
        Profile,
        String,
        tempfile::TempDir,
        stellar_agent_test_support::StellarAgentHomeGuard,
    ) {
        const SEED: [u8; 32] = [0x5d; 32];
        let home = tempfile::tempdir().unwrap();
        let home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let from = stellar_agent_test_support::signed_envelope::account_id_for_seed(SEED);
        let mut profile = Profile::builder_testnet_named(name, "svc-endpoint", &from, "n", "a")
            .with_noop_engine()
            .build();
        profile.rpc_url = rpc_url.to_owned();
        profile.audit_log_path = home.path().join("audit").join(format!("{name}.jsonl"));
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let audit_key = &profile.audit_log_hash_chain_key_id;
        KeyringEntry::new(&audit_key.service, &audit_key.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x3a; 32]))
            .unwrap();
        let signer = &profile.mcp_signer_default;
        KeyringEntry::new(&signer.service, &signer.account)
            .unwrap()
            .set_password(
                &stellar_agent_test_support::testnet_strkeys::strkey_from_seed(
                    stellar_agent_test_support::testnet_strkeys::VERSION_PRIVATE_KEY,
                    &SEED,
                ),
            )
            .unwrap();
        (profile, from, home, home_guard)
    }

    /// A `USDC` trustline builds one client: the endpoint check is its first
    /// request, ahead of the issuer read, and the reads and the send go
    /// through it. The submit layer checks it again, so two `getNetwork`.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_trustline_checks_the_endpoint_first_and_sends_through_one_client() {
        const NAME: &str = "trustline-one-client";
        let from = stellar_agent_test_support::signed_envelope::account_id_for_seed([0x5d; 32]);
        let server = crate::test_rpc::ClassicRpc::testnet(&[&from, ONE_ENVELOPE_ISSUER])
            .serve()
            .await;
        let (profile, from, _home, _home_guard) = seeded_trustline_profile(NAME, &server.uri());
        let args = TrustlineArgs {
            profile: Some(NAME.to_owned()),
            from,
            asset: format!("USDC:{ONE_ENVELOPE_ISSUER}"),
            limit_stroops: None,
            classic_base: Some("auto".to_owned()),
        };
        let mut out = Vec::new();
        let loaded = profile.clone();
        let (code, built) = crate::test_rpc::clients_built_by(run_with_dependencies(
            &args,
            move |_| Ok(loaded.clone()),
            || Ok(()),
            &mut out,
        ))
        .await;
        let envelope = crate::common::render::single_json_document(&out);
        let methods = crate::test_rpc::methods(&server).await;

        assert_eq!(code, 0, "{envelope}");
        assert_eq!(built, 1, "one client reads and sends");
        assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
        assert_eq!(crate::test_rpc::network_checks(&methods), 2, "{methods:?}");
        assert!(
            methods.iter().any(|m| m == "sendTransaction"),
            "{methods:?}"
        );
    }

    /// An endpoint serving another network is refused before the issuer read,
    /// with the mismatch code and no preview.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_endpoint_serving_another_network_is_refused_before_the_issuer_read() {
        const NAME: &str = "trustline-endpoint-mismatch";
        let from = stellar_agent_test_support::signed_envelope::account_id_for_seed([0x5d; 32]);
        let endpoint = crate::test_rpc::ClassicRpc::testnet(&[&from, ONE_ENVELOPE_ISSUER]);
        endpoint.report("Test SDF Future Network ; October 2022");
        let server = endpoint.serve().await;
        let (profile, from, _home, _home_guard) = seeded_trustline_profile(NAME, &server.uri());
        let args = TrustlineArgs {
            profile: Some(NAME.to_owned()),
            from,
            asset: format!("USDC:{ONE_ENVELOPE_ISSUER}"),
            limit_stroops: None,
            classic_base: None,
        };
        let mut out = Vec::new();
        let loaded = profile.clone();
        let code =
            run_with_dependencies(&args, move |_| Ok(loaded.clone()), || Ok(()), &mut out).await;
        let envelope = crate::common::render::single_json_document(&out);

        assert_eq!(code, 1, "{envelope}");
        assert_eq!(
            envelope["error"]["code"], "network.endpoint_network_mismatch",
            "{envelope}"
        );
        assert!(
            envelope["error"].get("details").is_none(),
            "an endpoint refusal carries no preview: {envelope}"
        );
        assert_eq!(
            crate::test_rpc::methods(&server).await,
            ["getNetwork"],
            "the endpoint check precedes the issuer read and every later read"
        );
    }

    /// An unset `submit_timeout_seconds` hands the submission the 60-second
    /// default, and a configured one hands it its own value.
    #[tokio::test]
    #[serial_test::serial]
    async fn sign_and_submit_forwards_the_profile_submit_timeout() {
        assert_eq!(
            forwarded_submit_timeout("trustline-timeout-unset", None).await,
            std::time::Duration::from_secs(60)
        );
        assert_eq!(
            forwarded_submit_timeout("trustline-timeout-set", Some(17)).await,
            std::time::Duration::from_secs(17)
        );
    }

    mod enrolled_failure_tests {
        use super::*;
        use stellar_agent_core::error::{AuthError, NetworkError};

        #[test]
        fn signer_load_failure_codes() {
            let cases: [(WalletError, &str); 5] = [
                (
                    WalletError::Auth(AuthError::EnrolledSignerUnpinned {
                        profile: "mainnet".into(),
                        reason: "placeholder",
                    }),
                    "auth.enrolled_signer_unpinned",
                ),
                (
                    WalletError::Auth(AuthError::EnrolledSignerMismatch {
                        profile: "mainnet".into(),
                        enrolled: "A".into(),
                        derived: "B".into(),
                    }),
                    "auth.enrolled_signer_mismatch",
                ),
                (
                    WalletError::Auth(AuthError::KeyringNotFound {
                        name: "missing".into(),
                    }),
                    "auth.keyring_not_found",
                ),
                (
                    WalletError::Auth(AuthError::KeyringPlatformError {
                        detail: "credential store unavailable".into(),
                    }),
                    "auth.keyring_platform_error",
                ),
                (
                    WalletError::Network(NetworkError::AccountNotFound {
                        account_id: "missing".into(),
                    }),
                    "trustline.signer_load_failed",
                ),
            ];
            for (e, code) in cases {
                assert_eq!(signer_load_failure_parts(&e), (code, e.to_string()));
            }
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
        async fn trustline_logs_a_consent_row_queued_after_its_pre_flight_before_the_signer_loads()
        {
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
                            stellar_agent_test_support::signed_envelope::ledger_entries_result_for(
                                &[FROM, ISSUER],
                            )
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
            let mut profile = Profile::builder_testnet_named(
                NAME,
                "svc-trustline-drain",
                FROM,
                "n-svc",
                "n-acct",
            )
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
                    .set_password(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x3a; 32]),
                    )
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

    mod witness {
        use super::*;
        use crate::test_rpc::{
            ACCOUNT_SEQUENCE, ClassicRpc, PRIMARY_CREDENTIAL, PRIMARY_CREDENTIAL_TOKEN,
            account_key, account_xdr, assert_rows_carry_witness, credential_primary,
            fail_read_of_with_text, methods, sent,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use stellar_agent_test_support::keyring_mock::{ReadHook, install_with_read_hooks};

        #[derive(Debug)]
        enum Case {
            Pass,
            Source,
            Issuer,
            Unavailable,
            Invalid,
            Skipped,
            Cap,
            Transport,
            Absent,
        }

        async fn exercise(case: Case) {
            let from = stellar_agent_test_support::signed_envelope::account_id_for_seed([0x5d; 32]);
            let primary_rpc = ClassicRpc::testnet(&[&from]);
            let primary_rpc = if matches!(case, Case::Absent) {
                primary_rpc
            } else {
                primary_rpc.with_entry(
                    account_key(ONE_ENVELOPE_ISSUER),
                    account_xdr(ONE_ENVELOPE_ISSUER, 0, 0, ""),
                )
            };
            let primary = primary_rpc.serve().await;
            let oracle_rpc = ClassicRpc::testnet(&[])
                .with_entry(
                    account_key(&from),
                    account_xdr(
                        &from,
                        if matches!(case, Case::Source) {
                            ACCOUNT_SEQUENCE + 9
                        } else {
                            ACCOUNT_SEQUENCE
                        },
                        0,
                        "",
                    ),
                )
                .with_entry(
                    account_key(ONE_ENVELOPE_ISSUER),
                    account_xdr(
                        ONE_ENVELOPE_ISSUER,
                        0,
                        if matches!(case, Case::Issuer) { 2 } else { 0 },
                        "",
                    ),
                );
            if matches!(case, Case::Unavailable) {
                oracle_rpc.report(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE);
            }
            let oracle = oracle_rpc.serve().await;
            let name = format!("trustline-witness-{case:?}").to_ascii_lowercase();
            let (mut profile, from, _dir, _home) = seeded_trustline_profile(&name, &primary.uri());
            profile.oracle_provider_url = if matches!(case, Case::Skipped) {
                None
            } else {
                Some(url::Url::parse(&oracle.uri()).unwrap())
            };
            if matches!(case, Case::Invalid) {
                profile.oracle_provider_url = Some(url::Url::parse("ftp://oracle.test").unwrap());
            }
            if matches!(case, Case::Cap) {
                profile.classic_fee_per_op_stroops = Some(101);
                profile.classic_max_fee_per_op_stroops = Some(100);
            }
            let reads = Arc::new(AtomicUsize::new(0));
            let count = reads.clone();
            install_with_read_hooks(vec![ReadHook::new(
                &profile.mcp_signer_default.service,
                &profile.mcp_signer_default.account,
                Arc::new(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                }),
            )])
            .unwrap();
            if matches!(case, Case::Transport) {
                // The primary carries a configured credential, and the issuer
                // read fails with server text that echoes it beside a URL with
                // a path; the scrub is what keeps both out of the output.
                credential_primary(&mut profile);
                fail_read_of_with_text(
                    &primary,
                    &account_key(ONE_ENVELOPE_ISSUER),
                    format!(
                        "upstream {PRIMARY_CREDENTIAL} refused at https://rpc.test/private-route"
                    ),
                )
                .await;
            }
            KeyringEntry::new(
                &profile.audit_log_hash_chain_key_id.service,
                &profile.audit_log_hash_chain_key_id.account,
            )
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x3a; 32]))
            .unwrap();
            KeyringEntry::new(
                &profile.mcp_signer_default.service,
                &profile.mcp_signer_default.account,
            )
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PrivateKey([0x5d; 32])
                    .as_unredacted()
                    .to_string()
                    .as_str(),
            )
            .unwrap();
            let args = TrustlineArgs {
                profile: Some(name),
                from,
                asset: format!("USDC:{ONE_ENVELOPE_ISSUER}"),
                limit_stroops: None,
                classic_base: None,
            };
            let mut out = Vec::new();
            let rc =
                run_with_dependencies(&args, |_| Ok(profile.clone()), || Ok(()), &mut out).await;
            let value = crate::common::render::single_json_document(&out);
            let refusal = match case {
                Case::Source | Case::Issuer => Some("simulation.divergence"),
                Case::Unavailable | Case::Invalid => Some("network.witness_unavailable"),
                Case::Cap => Some("fees.percentile_exceeds_cap"),
                Case::Transport => Some("network.rpc_unreachable"),
                Case::Absent => Some("trustline.gate_refused"),
                _ => None,
            };
            if let Some(code) = refusal {
                assert_eq!(rc, 1, "{value}");
                assert_eq!(value["error"]["code"], code, "{value}");
                assert_eq!(reads.load(Ordering::SeqCst), 0);
                assert!(!sent(&primary).await);
                if !matches!(case, Case::Transport | Case::Absent) {
                    assert_eq!(value["error"]["details"]["preview"]["code"], "USDC");
                }
                let message = value["error"]["message"].as_str().unwrap();
                if matches!(case, Case::Source) {
                    assert!(
                        message.contains("source account sequence (sequence delta 9)"),
                        "{message}"
                    );
                }
                if matches!(case, Case::Issuer) {
                    assert!(message.contains("issuer account flags"), "{message}");
                }
                if matches!(case, Case::Cap) {
                    assert!(methods(&oracle).await.is_empty());
                    assert!(
                        value["error"]["message"]
                            .as_str()
                            .unwrap()
                            .contains("profile's per-operation fee")
                    );
                }
                if matches!(case, Case::Transport) {
                    let rendered = value.to_string();
                    assert!(!rendered.contains(PRIMARY_CREDENTIAL_TOKEN), "{rendered}");
                    assert!(!rendered.contains("private-route"), "{rendered}");
                    // The echoed host remains: the server text reached the
                    // refusal, and the scrub removed the rest.
                    assert!(message.contains("rpc.test"), "{message}");
                }
            } else {
                assert_eq!(rc, 0, "{value}");
                // The signer entry is read twice, both after the witness: once
                // when the signer loads and once when it signs.
                assert_eq!(reads.load(Ordering::SeqCst), 2);
                assert_eq!(
                    value["data"]["cross_check"]["status"],
                    if matches!(case, Case::Skipped) {
                        "skipped"
                    } else {
                        "passed"
                    }
                );
                if matches!(case, Case::Pass) {
                    assert_rows_carry_witness(&profile, &oracle.uri());
                } else {
                    assert!(methods(&oracle).await.is_empty());
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn trustline_witness_records_result_and_rows() {
            exercise(Case::Pass).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn source_disagreement_precedes_signer() {
            exercise(Case::Source).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn issuer_disagreement_keeps_preview() {
            exercise(Case::Issuer).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn unavailable_oracle_precedes_signer() {
            exercise(Case::Unavailable).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn invalid_oracle_precedes_signer() {
            exercise(Case::Invalid).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn no_oracle_reports_skipped() {
            exercise(Case::Skipped).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn profile_fee_cap_keeps_preview_before_witness() {
            exercise(Case::Cap).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn issuer_transport_error_is_scrubbed() {
            exercise(Case::Transport).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn absent_issuer_refuses_gate() {
            exercise(Case::Absent).await;
        }
    }

    /// The mainnet pipeline over the fixture's stored profile, ceremony and
    /// routed endpoints.
    #[cfg(feature = "mainnet-write")]
    mod mainnet_full {
        use super::*;
        use std::sync::Arc;

        use serde_json::Value;
        use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
        use stellar_agent_test_support::signed_envelope::get_network_result;

        use crate::common::mainnet_write::invalidations_on_this_thread;
        use crate::common::mainnet_write_fixture::{
            AGENT_SEED, DESTINATION, ISSUER, MainnetFixture, Spec, TRUSTLINE_ASSET,
            minimum_reserve, trustline_rule,
        };
        use crate::test_rpc::{ACCOUNT_SEQUENCE, ClassicRpc, account_key, account_xdr};

        /// The native balance the mocked endpoints report for every account.
        const BALANCE: i64 = 100_000_000_000;
        /// The protocol reserve of an account without subentries.
        const RESERVE: i64 = 10_000_000;
        /// The issuer flag that enables clawback on the assets it issues.
        const AUTH_CLAWBACK_ENABLED: u32 = 0x8;
        /// The testnet issuer the wallet pins for USDC.
        const TESTNET_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

        fn agent() -> String {
            stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED)
        }

        /// An endpoint funding the agent and the destination, and reporting
        /// the network's USDC issuer with `issuer_flags`.
        fn ledger(mainnet: bool, issuer_flags: u32) -> ClassicRpc {
            let agent = agent();
            let (rpc, issuer) = if mainnet {
                (ClassicRpc::mainnet(&[&agent, DESTINATION]), ISSUER)
            } else {
                (ClassicRpc::testnet(&[&agent, DESTINATION]), TESTNET_ISSUER)
            };
            rpc.with_entry(
                account_key(issuer),
                account_xdr(issuer, ACCOUNT_SEQUENCE, issuer_flags, ""),
            )
        }

        fn spec(name: &'static str) -> Spec {
            Spec::new(name)
                .primary(ledger(true, 0))
                .oracle(ledger(true, 0))
        }

        /// A trustline from the agent to [`TRUSTLINE_ASSET`] on the
        /// fixture's profile.
        fn mainnet_args(fixture: &MainnetFixture) -> TrustlineArgs {
            TrustlineArgs {
                profile: Some(fixture.name.to_owned()),
                from: fixture.agent.g.clone(),
                asset: TRUSTLINE_ASSET.to_owned(),
                limit_stroops: None,
                classic_base: None,
            }
        }

        struct Run {
            code: i32,
            envelope: Value,
        }

        impl Run {
            fn code(&self) -> &str {
                self.envelope["error"]["code"].as_str().unwrap_or("")
            }
            fn message(&self) -> &str {
                self.envelope["error"]["message"].as_str().unwrap_or("")
            }
        }

        async fn run(fixture: &MainnetFixture, args: &TrustlineArgs) -> Run {
            let mut out = Vec::new();
            let code =
                run_with_dependencies(args, fixture.loader(), fixture.initializer(), &mut out)
                    .await;
            Run {
                code,
                envelope: crate::common::render::single_json_document(&out),
            }
        }

        fn now() -> u64 {
            stellar_agent_core::timefmt::now_unix_ms().unwrap()
        }

        fn records(fixture: &MainnetFixture) -> Vec<Value> {
            if !fixture.window_path().exists() {
                return Vec::new();
            }
            fixture.window_body()["authorizations"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        }

        async fn assert_refused_before_confirmation(
            fixture: &MainnetFixture,
            run: &Run,
            code: &str,
        ) {
            assert_eq!(run.code, 1, "{}", run.envelope);
            assert_eq!(run.code(), code, "{}", run.envelope);
            assert!(records(fixture).is_empty(), "no authorization record");
            assert!(
                fixture.pending_entries().is_empty(),
                "no confirmation entry"
            );
            assert!(fixture.sent_envelopes().await.is_empty(), "nothing is sent");
        }

        /// Accept: the trustline is witnessed through the routed oracle,
        /// signed through the keyring handle and sent once.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn accept() {
            let fixture = spec("mainnet-trustline-accept").build().await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            let sent = fixture.sent_envelopes().await;
            assert_eq!(sent.len(), 1);
            fixture.assert_signed_by_agent(&sent[0]);
            {
                use stellar_xdr::{Limits, Preconditions, ReadXdr as _, TransactionEnvelope};
                let TransactionEnvelope::Tx(v1) =
                    TransactionEnvelope::from_xdr_base64(&sent[0], Limits::none()).unwrap()
                else {
                    panic!("not a v1 envelope");
                };
                assert_eq!(v1.tx.cond, Preconditions::None);
            }
            let data = &run.envelope["data"];
            assert_eq!(data["status"], "submitted", "{}", run.envelope);
            assert_eq!(data["action"], "change_trust");
            assert_eq!(data["code"], "USDC");
            assert_eq!(data["ledger"], 1005);
            assert!(!fixture.oracle_methods().await.is_empty());
            assert!(fixture.open_authorizations(now()).is_empty());
            assert!(invalidations_on_this_thread().is_empty());
            let entries = fixture.pending_entries();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].kind_name, "Consumed");
        }

        /// Engine kind: a Noop profile refuses at the engine check.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_noop_engine_refuses_before_the_keyring() {
            let fixture = spec("mainnet-trustline-noop").noop_engine().build().await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(
                run.code(),
                "network.mainnet_write_forbidden",
                "{}",
                run.envelope
            );
            assert!(run.message().contains("Noop"), "{}", run.message());
            assert_eq!(fixture.initializer_calls(), 0);
            assert!(fixture.primary_methods().await.is_empty());
        }

        /// Engine proofs: a signed policy without a `[mainnet]` table refuses
        /// before the confirmation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_policy_without_the_mainnet_table_refuses() {
            let fixture = spec("mainnet-trustline-pre-enable")
                .pre_enable()
                .build()
                .await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_refused_before_confirmation(&fixture, &run, "network.mainnet_write_forbidden")
                .await;
            assert!(run.message().contains("[mainnet]"), "{}", run.message());
            assert!(
                run.message().contains("profile enable-mainnet"),
                "{}",
                run.message()
            );
        }

        /// Engine proofs: a tampered policy signature fails the engine build
        /// with the trustline's code.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_tampered_policy_signature_refuses() {
            let fixture = spec("mainnet-trustline-tampered").build().await;
            fixture.tamper_policy_signature();

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_refused_before_confirmation(
                &fixture,
                &run,
                "trustline.policy_engine_unavailable",
            )
            .await;
        }

        /// Enrollment: a placeholder pin refuses before the confirmation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_placeholder_pin_refuses_before_the_confirmation() {
            let fixture = spec("mainnet-trustline-unpinned").build().await;
            fixture.unpin_signer();

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_refused_before_confirmation(&fixture, &run, "auth.enrolled_signer_unpinned")
                .await;
            fixture.assert_terminal_untouched();
        }

        /// Enrollment: a `--from` other than the enrolled key refuses with the
        /// identity rule.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_holder_other_than_the_enrolled_key_refuses() {
            let fixture = spec("mainnet-trustline-other-holder").build().await;
            let mut args = mainnet_args(&fixture);
            args.from = DESTINATION.to_owned();

            let run = run(&fixture, &args).await;

            assert_refused_before_confirmation(&fixture, &run, "auth.enrolled_identity_unusable")
                .await;
            assert!(
                run.message().contains("public_key_mismatch"),
                "{}",
                run.message()
            );
            fixture.assert_terminal_untouched();
        }

        /// Clawback: a clawback-enabled issuer without an opt-in mints the
        /// opt-in entry and reports the outcome, before any mainnet
        /// confirmation or authorization.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_clawback_issuer_requires_the_opt_in_first() {
            let fixture = Spec::new("mainnet-trustline-clawback")
                .primary(ledger(true, AUTH_CLAWBACK_ENABLED))
                .oracle(ledger(true, AUTH_CLAWBACK_ENABLED))
                .build()
                .await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(run.code, 1, "{}", run.envelope);
            assert_eq!(run.envelope["ok"], true, "{}", run.envelope);
            assert_eq!(run.envelope["data"]["outcome"], "clawback_opt_in_required");
            let entries = fixture.pending_entries();
            assert_eq!(entries.len(), 1, "{entries:?}");
            assert_eq!(entries[0].kind_name, "TrustlineClawbackOptIn");
            assert!(fixture.open_authorizations(now()).is_empty());
            assert!(records(&fixture).is_empty());
            assert!(fixture.prompts().is_empty(), "no mainnet confirmation");
        }

        /// Clawback: an opt-in entry that cannot be written refuses the
        /// trustline.
        #[cfg(unix)]
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn an_unwritable_approval_directory_refuses_the_clawback_gate() {
            use std::os::unix::fs::PermissionsExt as _;
            let fixture = Spec::new("mainnet-trustline-clawback-store")
                .primary(ledger(true, AUTH_CLAWBACK_ENABLED))
                .oracle(ledger(true, AUTH_CLAWBACK_ENABLED))
                .build()
                .await;
            let dir = fixture
                .approval_store_path()
                .parent()
                .unwrap()
                .to_path_buf();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                run.code(),
                "trustline.clawback_gate_refused",
                "{}",
                run.envelope
            );
            assert!(records(&fixture).is_empty());
            assert!(fixture.prompts().is_empty(), "no mainnet confirmation");
        }

        /// Trustline keyring seed: the enrolled proof reads only the identity
        /// record, so a deleted seed entry surfaces at the signing call as
        /// the keyring's refusal, after the mint.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_deleted_seed_entry_is_signer_unavailable() {
            let fixture = spec("mainnet-trustline-seed-deleted").build().await;
            fixture.delete_keyring_entry(&fixture.profile().mcp_signer_default);

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(run.code, 1, "{}", run.envelope);
            assert!(run.code().starts_with("auth."), "{}", run.envelope);
            assert!(
                run.message()
                    .ends_with(" The signature was withheld and nothing was sent."),
                "{}",
                run.message()
            );
            assert_eq!(
                invalidations_on_this_thread(),
                vec![("signer_unavailable", Ok(()))]
            );
            assert!(fixture.sent_envelopes().await.is_empty());
        }

        /// Rendering: a resolver refusal renders the withheld text under the
        /// generic code, never as a submit failure.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_resolver_refusal_renders_the_withheld_text() {
            let fixture = Spec::new("mainnet-trustline-resolver")
                .primary(ledger(true, 0).with_script(|method, index, _| {
                    (method == "getNetwork" && index == 1)
                        .then(|| get_network_result(TESTNET_PASSPHRASE))
                }))
                .oracle(ledger(true, 0))
                .build()
                .await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(
                run.code(),
                "network.mainnet_authorization_refused",
                "{}",
                run.envelope
            );
            assert_eq!(
                run.message(),
                "the mainnet write was refused; the signature was withheld and nothing was sent"
            );
        }

        /// Rendering: a refusal inside the submit renders the after-signing
        /// text under the generic code.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_submit_refusal_renders_the_after_signing_text() {
            let clock = Arc::new(stellar_agent_network::mainnet::clock::set_now_ms_for_test(
                now() + 5_000,
            ));
            // The script lives on in the pooled mock server after the test,
            // so it holds the clock weakly: the override ends with `clock`.
            let advance = Arc::downgrade(&clock);
            let fixture = Spec::new("mainnet-trustline-submit")
                .primary(ledger(true, 0).with_script(move |method, index, _| {
                    if method == "getNetwork"
                        && index == 2
                        && let Some(clock) = advance.upgrade()
                    {
                        clock.set(now() + 3_600_000);
                    }
                    None
                }))
                .oracle(ledger(true, 0))
                .build()
                .await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            drop(clock);
            assert_eq!(
                run.code(),
                "network.mainnet_authorization_refused",
                "{}",
                run.envelope
            );
            assert_eq!(
                run.message(),
                "the mainnet write was refused; the submission was refused after signing and \
                 nothing was sent"
            );
            assert!(fixture.sent_envelopes().await.is_empty());
        }

        /// The margin at which the trustline, which debits nothing, passes
        /// the reserve alone and crosses it with any fee.
        const FEE_CROSSING_MARGIN: i64 = BALANCE - RESERVE;

        /// Fee in the policy arguments, mainnet.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn the_fee_counts_toward_the_reserve_on_mainnet() {
            let fixture = spec("mainnet-trustline-fee-reserve")
                .rules(vec![trustline_rule(&minimum_reserve(FEE_CROSSING_MARGIN))])
                .build()
                .await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_refused_before_confirmation(
                &fixture,
                &run,
                "policy.deny.minimum_reserve_breached",
            )
            .await;
        }

        /// Fee in the policy arguments, testnet.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn the_fee_counts_toward_the_reserve_on_testnet() {
            let testnet_asset = format!("USDC:{TESTNET_ISSUER}");
            let fixture = Spec::new("testnet-trustline-fee-reserve")
                .testnet()
                .primary(ledger(false, 0))
                .rules(vec![
                    trustline_rule(&minimum_reserve(FEE_CROSSING_MARGIN))
                        .replace(TRUSTLINE_ASSET, &testnet_asset),
                ])
                .build()
                .await;
            let mut args = mainnet_args(&fixture);
            args.asset = testnet_asset;

            let run = run(&fixture, &args).await;

            assert_eq!(
                run.code(),
                "policy.deny.minimum_reserve_breached",
                "{}",
                run.envelope
            );
            assert!(fixture.sent_envelopes().await.is_empty());
        }
    }
}
