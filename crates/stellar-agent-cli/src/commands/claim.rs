//! `stellar-agent claim` subcommand — claimable-balance claim spine.
//!
//! Claims a Stellar `ClaimClaimableBalance` operation for a balance the agent
//! already holds the id of. Supports the same three execution stages as `pay`:
//!
//! 1. **Build** (`--build-only`) — fetch the entry, build a typed preview, run
//!    the claim guards, construct the transaction envelope, and emit unsigned
//!    base64 XDR.
//! 2. **Sign** (`--sign-only <base64-xdr>`) — sign a previously-built envelope
//!    and emit signed base64 XDR.
//! 3. **Submit** (`--submit-only <base64-xdr>`) — submit a signed envelope and
//!    poll until confirmation.
//!
//! Default (no stage flag): runs all three stages atomically.
//!
//! # Output
//!
//! One JSON envelope on stdout (`--output json`, the default). The build
//! stage's typed preview is rendered once, as a nested `preview` object. It
//! sits in `data.preview` on success. It sits in `error.details.preview` when
//! a later step fails: a claim guard, the fee resolution, the policy gate, the
//! audit pre-flight, signing, or submission. `--sign-only` and `--submit-only`
//! build no preview. `--output table` prints the preview line before the
//! result or error line.
//!
//! # Claim guards
//!
//! Before signing, the build stage enforces the claim guards in order:
//! claimant membership (`claim.not_claimant`), predicate satisfaction
//! (`claim.predicate_not_satisfied`), non-native trustline state
//! (`claim.trustline_*`), and native-XLM fee affordability
//! (`ledger.insufficient_balance`). Claiming credits the account, so the
//! affordability check covers only the transaction fee, not the claimed amount.
//!
//! # Mainnet rejection
//!
//! `--network testnet` is the only accepted value. Mainnet is structurally
//! rejected at two layers: the CLI `TargetNetwork::Mainnet` variant returns
//! `network.mainnet_write_forbidden` before any RPC call, and
//! `submit_transaction_and_wait` rejects mainnet-looking URLs as defence in
//! depth.
//!
//! # Signer model
//!
//! Signing follows the `pay` model: `--secret-env VAR` (the shared
//! mlock-protected software signing ceremony via
//! `resolve_software_signer_from_env`) or `--sign-with-ledger` (hardware
//! signer; no seed ever in process memory). The public key derived from the
//! signer is compared against `--source` before any signing.
//!
//! # Operator policy evaluation
//!
//! The profile is resolved (and, when it carries `policy.engine = "v1"`, the
//! platform keyring store is initialised) before any RPC call, in every
//! stage. In the full pipeline and `--build-only`, the claim is evaluated
//! after the build stage (guards, preview, envelope construction) and before
//! signing. `--sign-only` and `--submit-only` gate too: each decodes the
//! supplied envelope through
//! [`stellar_agent_core::envelope_decode::decode_authoritative_args`] (the
//! same decoder the MCP `stellar_claim_commit` path uses) and evaluates it
//! before signing or broadcasting — `--submit-only` gates even though the
//! envelope arrives pre-signed, because broadcasting still spends funds. An
//! envelope the decoder cannot classify into a sized shape follows the
//! opaque-signing posture (`policy.deny.unsizable_value_effect` under a
//! matched value rule, unless the rule sets `allow_opaque_signing = true`).
//! Every stage evaluates against the operator-signed `PolicyEngineV1` (V1
//! profiles) or the permissive `NoopPolicyEngine` (`Noop` profiles), mirroring
//! the `stellar_claim` / `stellar_claim_commit` MCP tools' dispatch gates.
//! When NO profile was named and no persisted `default.toml` file exists, an
//! in-memory `Noop`-engine testnet profile is synthesized (tagged
//! [`crate::common::profile_access::ProfileOrigin::Synthesized`]) so the
//! command keeps working without an authored profile file. A profile the
//! operator NAMED — through `--profile` or `STELLAR_AGENT_PROFILE` — but never
//! authored is refused instead.
//!
//! # Audit pre-flight (fail-closed for a persisted profile; fail-open for the
//! synthesized zero-config profile)
//!
//! Every stage that touches a signing key (`--sign-only`, the full pipeline)
//! or submits a transaction (`--submit-only`, the full pipeline) resolves the
//! audit writer via
//! [`crate::commands::value_audit::require_value_audit_writer_for_origin`]
//! BEFORE that signing/submission. For a persisted `<name>.toml` profile this
//! fails closed with `audit.chain_key_unavailable` if the profile's audit
//! chain-root HMAC key is not acquirable — an init-minted profile has no
//! audit key until `stellar-agent profile rotate-audit-key <name>` mints one.
//! For the synthesized zero-config profile the pre-flight stays fail-open
//! (warn-only, no refusal), so an unauthored profile never blocks signing on a
//! key-rotation step the operator never opted into. `--build-only` is exempt:
//! it neither signs nor submits. Where a writer was acquired, it is reused
//! (not re-acquired) for the post-confirm `value_action_submitted` row.

use std::io::Write;
use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{
    AuthError, InternalError, LedgerError, NetworkError, ValidationError, WalletError,
};
use stellar_agent_network::NetworkContext;

use stellar_agent_claimable::entry::{fetch_claimable_balance_entry, fetch_trustline_state};
use stellar_agent_claimable::error::ClaimError;
use stellar_agent_claimable::id::BalanceId;
use stellar_agent_claimable::preview::{
    ClaimPreview, check_trustline, require_claimant, require_predicate_satisfied,
};
use stellar_agent_core::policy::PolicyEngine;
use stellar_agent_core::policy::v1::AccountReservesView;
use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};
use stellar_agent_network::builder::ClassicOpBuilder;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_network::{
    BASE_RESERVE_STROOPS, ClassicFeeSelection, StellarRpcClient, SubmissionResult,
    SubmissionSignerKind, fetch_account, init_platform_keyring_store, parse_classic_fee_choice,
    resolve_classic_fee_selection, submit_transaction_and_wait,
};

use crate::commands::policy_engine::{
    build_v1_policy_engine, claim_policy_args, evaluate_opaque_signing_policy,
    evaluate_value_moving_policy,
};
use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, network_context_for_command,
};
use crate::common::profile_access::{
    ProfileOrigin, injected_profile_load, load_profile_or_synthesize_testnet_with,
};
use crate::common::render::{
    WithPreview, exit_code_after_output, sanitize_for_table, with_preview_detail, write_envelope,
};
use crate::common::signer_ceremony::{
    SignerCeremonyOutcome, require_enrolled_signer, resolve_software_signer_from_env,
};
use crate::common::{ResolvedProfileName, resolve_profile_name};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default fee per operation in stroops (100 stroops × 1 op = 100 stroops).
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// ClaimResult — the structured success payload
// ─────────────────────────────────────────────────────────────────────────────

/// Structured payload returned in the JSON envelope on a successful claim.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClaimResult {
    /// Base64-encoded (signed or unsigned) `TransactionEnvelope` XDR.
    pub envelope_xdr: String,

    /// Transaction hash (64-character hex), present after submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Ledger sequence number, present after confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

    /// The stage that produced this result.
    pub stage: String,

    /// Canonical 72-hex balance id being claimed.
    ///
    /// Present for the build and full-pipeline stages; absent for the
    /// sign-only and submit-only stages, which operate on an opaque envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance_id_hex72: Option<String>,
}

/// The unsigned envelope plus the metadata produced by the build stage.
#[derive(Debug, Clone)]
struct BuiltClaimEnvelope {
    envelope_xdr: String,
    balance_id_hex72: String,
    #[allow(dead_code)]
    fee_selection: ClassicFeeSelection,
    /// The source account's fetched state — reused (not re-fetched) to feed
    /// the policy gate's `account_view`, mirroring the `stellar_claim` MCP
    /// twin's `AccountViewAdapter` wiring exactly.
    account_view: stellar_agent_network::AccountView,
    /// The typed preview the build stage computed before the guards ran.
    preview: ClaimPreview,
}

/// A build-stage failure, with the preview when the failure followed it.
#[derive(Debug)]
struct ClaimBuildFailure {
    error: ClaimError,
    /// `Some` when a claim guard, the fee resolution, or the envelope build
    /// refused after the preview was built. Boxed to keep the failure small.
    preview: Option<Box<ClaimPreview>>,
}

/// What a stage reports: its result and the preview it computed, if any.
///
/// Rendered once, by [`render_claim_outcome`].
struct ClaimOutcome {
    preview: Option<ClaimPreview>,
    result: Result<ClaimResult, Envelope<()>>,
}

impl ClaimOutcome {
    /// A failure before any preview was computed.
    fn failed(envelope: Envelope<()>) -> Self {
        Self {
            preview: None,
            result: Err(envelope),
        }
    }

    /// A failure after the preview was computed.
    fn failed_after_preview(preview: ClaimPreview, envelope: Envelope<()>) -> Self {
        Self {
            preview: Some(preview),
            result: Err(envelope),
        }
    }

    /// A successful stage.
    fn succeeded(preview: Option<ClaimPreview>, result: ClaimResult) -> Self {
        Self {
            preview,
            result: Ok(result),
        }
    }

    /// A build-stage failure, carrying the preview when the failure followed
    /// it.
    fn from_build_failure(failure: ClaimBuildFailure) -> Self {
        Self {
            preview: failure.preview.map(|preview| *preview),
            result: Err(claim_error_envelope(&failure.error)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ClaimArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `claim` subcommand.
///
/// Stage flags (`--build-only`, `--sign-only`, `--submit-only`) and signer
/// flags (`--secret-env`, `--sign-with-ledger`) are each mutually exclusive via
/// an `ArgGroup`.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(ArgGroup::new("stage").args(["build_only", "sign_only", "submit_only"]).required(false)),
    group(ArgGroup::new("signer_group").args(["secret_env", "sign_with_ledger"]).required(false)),
)]
pub struct ClaimArgs {
    /// Profile name to evaluate operator policy against.
    ///
    /// Resolution order: this flag, then `STELLAR_AGENT_PROFILE`, then the
    /// literal `"default"`. When NO profile was named and no `default.toml`
    /// file exists, an in-memory `Noop`-engine testnet profile is synthesized
    /// so the command keeps working without an authored profile file; a named
    /// profile with no file is refused. See
    /// [`crate::common::profile_access::load_profile_or_synthesize_testnet`].
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// Claimable-balance id: a `B...` strkey, canonical 72-hex id, or bare
    /// 64-hex hash.
    #[arg(value_name = "BALANCE_ID")]
    pub balance_id: String,

    /// Claiming (source) account G-strkey. Also the transaction source.
    #[arg(long, value_name = "G_STRKEY")]
    pub source: String,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Name of the environment variable that holds the S-strkey secret key.
    /// The value of the variable is never logged.
    #[arg(long, value_name = "VAR", group = "signer_group")]
    pub secret_env: Option<String>,

    /// Sign using the connected Ledger hardware wallet.
    #[arg(long, group = "signer_group")]
    pub sign_with_ledger: bool,

    /// Ledger BIP-44 account index (default 0).
    #[arg(long, default_value_t = 0_u32, value_name = "INDEX")]
    pub account_index: u32,

    /// Build only: emit unsigned envelope XDR and exit.
    #[arg(long, group = "stage")]
    pub build_only: bool,

    /// Sign only: sign the given base64 XDR envelope and emit signed XDR.
    #[arg(long, value_name = "BASE64_XDR", group = "stage")]
    pub sign_only: Option<String>,

    /// Submit only: submit the given signed base64 XDR envelope.
    #[arg(long, value_name = "BASE64_XDR", group = "stage")]
    pub submit_only: Option<String>,

    /// The network comes from the profile when absent.
    /// When supplied, this flag must equal the profile's chain.
    #[arg(long, value_name = "NETWORK")]
    pub network: Option<TargetNetwork>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Submission timeout in seconds. Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// The RPC endpoint comes from the profile when absent.
    /// On testnet, this flag overrides the profile endpoint.
    /// On mainnet, this flag is refused, including equal values.
    /// URL credentials are refused.
    #[arg(long, value_name = "URL", value_parser = EndpointUrlFlag)]
    pub rpc_url: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `claim` subcommand.
///
/// Dispatches to the appropriate stage (build, sign, submit, or the default
/// full pipeline) and renders the result per `args.output`.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns an `Err` — all errors are captured into the envelope.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &ClaimArgs) -> i32 {
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
/// profile and a spy initializer, and read what the command writes from an
/// in-memory writer. They assert the keyring store is registered before the
/// V1 policy gate's owner-key read (see `run_build_only` /
/// `run_full_pipeline`) without touching the OS keychain.
///
/// Writes exactly one rendered outcome to `out`: [`claim_outcome`] renders
/// nothing, and [`render_claim_outcome`] writes its result once.
///
/// # The injected closure LOADS ONLY
///
/// `load_profile` performs the load and nothing else. Whether a `NotFound`
/// may be replaced by the synthesized zero-config profile is decided by
/// [`load_profile_or_synthesize_testnet_with`], which [`claim_outcome`]
/// calls once, at entry, with the resolved name. Every stage receives the
/// loaded profile. The refusal for a named-but-missing profile therefore runs
/// on the injected path exactly as it does in production. A check placed
/// inside the closure would be bypassed by every test that supplies its own.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
    out: &mut dyn Write,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, stellar_agent_core::profile::loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let outcome = claim_outcome(args, load_profile, init_keyring).await;
    render_claim_outcome(out, args.output, outcome)
}

/// Resolves the profile and the network context, refuses mainnet, and runs
/// the selected stage.
async fn claim_outcome<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> ClaimOutcome
where
    LoadProfile: Fn(&str) -> Result<Profile, stellar_agent_core::profile::loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let resolved = resolve_profile_name(args.profile.as_deref());
    let (profile, origin) = match load_profile_or_synthesize_testnet_with(&resolved, load_profile) {
        Ok(loaded) => loaded,
        Err(e) => {
            return ClaimOutcome::failed(Envelope::<()>::err_raw(
                e.code(),
                e.message(&resolved.name),
            ));
        }
    };
    let context = match network_context_for_command(
        &profile,
        &resolved.name,
        EndpointFlags {
            network: args.network,
            rpc_url: args.rpc_url.as_deref(),
            secondary_rpc_url: None,
        },
    ) {
        Ok(context) => context,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };
    // The resolved name and the input that supplied it are logged together:
    // a report of a run signing against the wrong profile is diagnosable only
    // if the log says which name was used and where it came from. Mirrors the
    // MCP server's startup line.
    tracing::debug!(
        profile = %resolved.name,
        profile_source = resolved.source.as_str(),
        "claim: profile resolved"
    );

    // ── Mainnet structural rejection (first layer) ────────────────────────────
    if context.chain_id.is_mainnet() {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        return ClaimOutcome::failed(Envelope::<()>::err(&err));
    }

    // Every gated stage reads the owner key from the keyring through
    // `build_v1_policy_engine` when the resolved profile is V1, including
    // `--sign-only` and `--submit-only`, which gate the decoded envelope before
    // signing or broadcasting. All four stages therefore receive the loaded
    // profile and the keyring initialiser.
    if args.build_only {
        run_build_only(&context, args, &resolved, &profile, init_keyring).await
    } else if let Some(ref xdr) = args.sign_only {
        run_sign_only(
            &context,
            args,
            &resolved,
            xdr,
            &profile,
            origin,
            init_keyring,
        )
        .await
    } else if let Some(ref xdr) = args.submit_only {
        run_submit_only(
            &context,
            args,
            &resolved,
            xdr,
            &profile,
            origin,
            init_keyring,
        )
        .await
    } else {
        run_full_pipeline(&context, args, &resolved, &profile, origin, init_keyring).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage implementations
// ─────────────────────────────────────────────────────────────────────────────

async fn run_build_only<InitKeyring>(
    context: &NetworkContext,
    args: &ClaimArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    init_keyring: InitKeyring,
) -> ClaimOutcome
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Conditionally initialise the platform keyring ─────────────────────────
    // Must happen before any network build: `build_v1_policy_engine` (invoked
    // from `evaluate_claim_policy` below) reads the owner PUBLIC key from the
    // OS keyring only when `profile.policy.engine == V1`, so the platform
    // keyring store is registered here — and only then — ahead of that read.
    // `--build-only` never calls the audit pre-flight (it neither signs nor
    // submits), so the Noop-engine path genuinely never touches the keyring
    // on this stage, unlike the signing/submitting stages below.
    // `PolicyEngineKind` is `#[non_exhaustive]` (a foreign-crate enum), so this
    // cannot be a wildcard-free exhaustive match. `Noop` is the only engine that
    // reads no owner key; every other engine — `V1` and any future variant —
    // needs the keyring store registered before the gate's owner-key read.
    // Default to initialising (fail toward registering the store) so a
    // newly-added engine is never silently left without it.
    if !matches!(profile.policy.engine, PolicyEngineKind::Noop)
        && let Err(e) = init_keyring()
    {
        return ClaimOutcome::failed(Envelope::<()>::err(&e));
    }

    let built = match build_unsigned_envelope(context, args).await {
        Ok(built) => built,
        Err(failure) => return ClaimOutcome::from_build_failure(failure),
    };
    let chain_id = context.chain_id.caip2_str();
    // Build-only: gate but do not submit, so the gate-sized effects are
    // not recorded (no confirmed on-chain action to attest).
    if let Err(envelope) = evaluate_claim_policy(&built, chain_id, profile, &resolved.name) {
        return ClaimOutcome::failed_after_preview(built.preview, envelope);
    }
    ClaimOutcome::succeeded(
        Some(built.preview),
        ClaimResult {
            envelope_xdr: built.envelope_xdr,
            tx_hash: None,
            ledger: None,
            stage: "build".to_owned(),
            balance_id_hex72: Some(built.balance_id_hex72),
        },
    )
}

async fn run_sign_only<InitKeyring>(
    context: &NetworkContext,
    args: &ClaimArgs,
    resolved: &ResolvedProfileName,
    unsigned_xdr: &str,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> ClaimOutcome
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    if let Err(envelope) = init_keyring_for_origin(resolved, origin, init_keyring) {
        return ClaimOutcome::failed(envelope);
    }
    let chain_id = context.chain_id.caip2_str();
    if let Err(envelope) =
        evaluate_staged_claim_policy(context, unsigned_xdr, chain_id, profile, &resolved.name).await
    {
        return ClaimOutcome::failed(envelope);
    }
    // Origin-aware pre-flight: prove the audit writer is acquirable AFTER the
    // policy gate (a denial is a clean refusal that signs nothing and needs
    // no audit setup) but BEFORE the signing key below is touched, for a
    // persisted profile — fails closed. The synthesized zero-config profile
    // stays fail-open. `--sign-only` never submits, so the returned writer
    // (if any) is not threaded further here — its only purpose on this stage
    // is the refusal.
    if let Err(e) = crate::commands::value_audit::require_value_audit_writer_for_origin(
        profile,
        &resolved.name,
        origin,
    ) {
        return ClaimOutcome::failed(Envelope::<()>::err(&e));
    }

    match sign_envelope(context, args, unsigned_xdr, profile, &resolved.name).await {
        Ok(signed_xdr) => ClaimOutcome::succeeded(
            None,
            ClaimResult {
                envelope_xdr: signed_xdr,
                tx_hash: None,
                ledger: None,
                stage: "sign".to_owned(),
                balance_id_hex72: None,
            },
        ),
        Err(e) => ClaimOutcome::failed(Envelope::<()>::err(&e)),
    }
}

async fn run_submit_only<InitKeyring>(
    context: &NetworkContext,
    args: &ClaimArgs,
    resolved: &ResolvedProfileName,
    signed_xdr: &str,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> ClaimOutcome
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    if let Err(envelope) = init_keyring_for_origin(resolved, origin, init_keyring) {
        return ClaimOutcome::failed(envelope);
    }

    // Establish which network `--rpc-url` actually serves before anything
    // else runs. The staged gate evaluates under the chain id derived from
    // `--network`, so that flag has to describe the endpoint the envelope will
    // reach; the probe is what makes it so, and a mismatch refuses here rather
    // than after a policy decision taken for the wrong chain.
    if let Err(e) = probe_endpoint_network(context, args).await {
        return ClaimOutcome::failed(Envelope::<()>::err(&e));
    }

    // Settle the spending-window reservations that have stood long enough to
    // be settleable, before the gate below counts them. A reservation the
    // chain has since answered for should not hold the operator's cap, and one
    // the chain has not is counted as spend.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            return ClaimOutcome::failed(Envelope::<()>::err_raw(
                "wallet.clock_error",
                e.to_string(),
            ));
        }
    };
    if let Ok(reconcile_client) = StellarRpcClient::new(&context.rpc_url) {
        crate::commands::submission_record::reconcile_open_reservations(
            profile,
            &resolved.name,
            origin,
            &reconcile_client,
            now_ms,
        )
        .await;
    }

    let chain_id = context.chain_id.caip2_str();
    // The envelope arrives pre-signed, but broadcasting it still spends
    // funds — gate here even though signing already happened elsewhere.
    let claim_effects =
        match evaluate_staged_claim_policy(context, signed_xdr, chain_id, profile, &resolved.name)
            .await
        {
            Ok(effects) => effects,
            Err(envelope) => return ClaimOutcome::failed(envelope),
        };
    // Origin-aware pre-flight: prove the audit writer is acquirable AFTER the
    // policy gate (a denial is a clean refusal that submits nothing and
    // needs no audit setup) but BEFORE the transaction below is submitted,
    // for a persisted profile — fails closed. The synthesized zero-config
    // profile stays fail-open, yielding `None` when no writer could be
    // acquired. Where `Some`, the writer is reused (not re-acquired) for the
    // post-confirm emission.
    let audit_writer = match crate::commands::value_audit::require_value_audit_writer_for_origin(
        profile,
        &resolved.name,
        origin,
    ) {
        Ok(w) => w,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };

    let recorder = match crate::commands::submission_record::build_recorder(
        crate::commands::submission_record::SubmitRecord {
            policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
            profile,
            profile_name: resolved.name.clone(),
            verb: "claim",
            tool: "stellar_claim_commit",
            chain_id,
            effects: claim_effects.as_ref(),
            audit: audit_writer.clone(),
            now_ms,
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            return ClaimOutcome::failed(crate::commands::submission_record::error_envelope(
                &e, signed_xdr, "claim",
            ));
        }
    };

    match submit_envelope(context, args, signed_xdr, Some(&recorder)).await {
        Ok((signed_xdr, sub_result)) => ClaimOutcome::succeeded(
            None,
            ClaimResult {
                envelope_xdr: signed_xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "submit".to_owned(),
                balance_id_hex72: None,
            },
        ),
        Err(e) => ClaimOutcome::failed(Envelope::<()>::err(&e)),
    }
}

/// Attempts to initialise the platform keyring store, whatever the policy
/// engine, and decides by the profile's origin whether a failure is fatal.
///
/// The attempt is unconditional, not gated on `profile.policy.engine`. The
/// stages calling this helper (`--sign-only`, `--submit-only`, the full
/// pipeline) next run an origin-aware audit pre-flight. It reads the profile's
/// audit chain-root HMAC key from the platform keyring regardless of the
/// policy engine. A `Noop` engine reads no OWNER key, but the audit key is a
/// separate, engine-independent requirement.
///
/// The outcome of a failed initialisation attempt is origin-aware:
/// [`ProfileOrigin::Persisted`] treats it as fatal — an operator who authored
/// a profile file is expected to have a working platform keyring for both the
/// fail-closed audit pre-flight and the keyring-backed owner-key read.
/// [`ProfileOrigin::Synthesized`] (the zero-config quickstart — no profile
/// file, no keyring ceremony the operator opted into) logs a
/// `tracing::warn!` and continues: the origin-aware audit pre-flight run next
/// already tolerates the SAME acquisition failure for a synthesized profile
/// (see [`crate::commands::value_audit::require_value_audit_writer_for_origin`]),
/// so a host with no platform keyring store (e.g. a container without a
/// Secret Service) never blocks the documented no-setup quickstart.
///
/// # Errors
///
/// Returns the refusal envelope when initialization fails for a persisted
/// profile.
fn init_keyring_for_origin<InitKeyring>(
    resolved: &ResolvedProfileName,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> Result<(), Envelope<()>>
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    if let Err(e) = init_keyring() {
        match origin {
            ProfileOrigin::Persisted => return Err(Envelope::<()>::err(&e)),
            ProfileOrigin::Synthesized => {
                tracing::warn!(
                    profile = %resolved.name,
                    error = %e,
                    "platform keyring store unavailable for the synthesized zero-config \
                     profile; continuing warn-only — the audit pre-flight below already \
                     tolerates this for a synthesized profile"
                );
            }
        }
    }
    Ok(())
}

/// Gates a staged (`--sign-only` / `--submit-only`) envelope before it is
/// signed or broadcast.
///
/// Decodes `envelope_xdr` via the SAME decoder the MCP `stellar_claim_commit`
/// path uses, fetches the source account view, and delegates the decision to
/// [`dispatch_staged_claim_gate`] — the pure, network-free dispatch this
/// function's tests exercise directly. `claim` supplies `identity_view: None`
/// — no destination concept, matching `evaluate_claim_policy`'s established
/// posture.
///
/// # Errors
///
/// Returns the refusal envelope when the engine cannot be built, the source
/// account cannot be fetched, or the gate refuses.
async fn evaluate_staged_claim_policy(
    context: &NetworkContext,
    envelope_xdr: &str,
    chain_id: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, Envelope<()>> {
    let policy_engine =
        build_v1_policy_engine("claim", &profile.policy.engine, profile, profile_name)
            .map_err(|msg| Envelope::<()>::err_raw("policy.engine_unavailable", msg))?;

    let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
        envelope_xdr,
        "stellar_claim_commit",
    );

    // The account view is populated only when the decode succeeded — a
    // bounded fetch of the decoded `source` (feeds `minimum_reserve`),
    // matching `claim`'s established posture.
    let mut source_view_holder = None;
    if let Ok(ref authoritative_args) = decode_result {
        let client =
            StellarRpcClient::new(&context.rpc_url).map_err(|e| Envelope::<()>::err(&e))?;
        let source = authoritative_args
            .get("source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        source_view_holder = Some(
            fetch_account(&client, source, &[])
                .await
                .map_err(|e| Envelope::<()>::err(&e))?,
        );
    }
    let source_adapter = source_view_holder
        .as_ref()
        .map(stellar_agent_network::policy_view::AccountViewAdapter::new);

    dispatch_staged_claim_gate(
        policy_engine.as_ref(),
        profile,
        chain_id,
        decode_result,
        source_adapter
            .as_ref()
            .map(|a| a as &dyn AccountReservesView),
    )
}

/// Pure post-decode dispatch for the staged `claim` gate: no network or
/// keyring access, so it is exercised directly by tests with a hand-built
/// [`PolicyEngineV1`](stellar_agent_core::policy::v1::PolicyEngineV1) and a
/// real (or absent) decode outcome. See `pay::dispatch_staged_pay_gate` for
/// the full mechanism description; `claim` supplies `identity_view: None`
/// unconditionally (no destination concept).
///
/// # Errors
///
/// Returns `Err(envelope)` — a fully-rendered refusal envelope — on deny,
/// approval-required, or an engine error.
fn dispatch_staged_claim_gate(
    policy_engine: &dyn PolicyEngine,
    profile: &Profile,
    chain_id: &str,
    decode_result: Result<
        serde_json::Value,
        stellar_agent_core::envelope_decode::EnvelopeDecodeError,
    >,
    account_view: Option<&dyn AccountReservesView>,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, Envelope<()>> {
    match decode_result {
        Ok(authoritative_args) => evaluate_value_moving_policy(
            policy_engine,
            profile,
            "stellar_claim_commit",
            stellar_agent_core::policy::ToolValueKind::MovesValue,
            chain_id,
            &authoritative_args,
            "claim",
            account_view,
            None,
        ),
        Err(_decode_err) => evaluate_opaque_signing_policy(
            policy_engine,
            profile,
            "stellar_claim_commit",
            chain_id,
            stellar_agent_core::policy::v1::OpaqueReason::RawTransactionSignature,
            "claim",
        )
        .map(|()| None),
    }
}

async fn run_full_pipeline<InitKeyring>(
    context: &NetworkContext,
    args: &ClaimArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> ClaimOutcome
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Unconditionally attempt to initialise the platform keyring ────────────
    // Unconditional (see `init_keyring_for_origin`'s rustdoc). The
    // origin-aware audit pre-flight below reads the profile's audit chain-root
    // HMAC key from the platform keyring whatever the policy engine. The store
    // must therefore be registered before that read, even on a `Noop`-engine
    // profile. A failed attempt is fatal for a persisted profile and warn-only
    // for the synthesized zero-config profile, matching the audit pre-flight's
    // fail-open posture for that origin.
    if let Err(envelope) = init_keyring_for_origin(resolved, origin, init_keyring) {
        return ClaimOutcome::failed(envelope);
    }

    // 1. Build (fetch entry, preview, guards).
    let built = match build_unsigned_envelope(context, args).await {
        Ok(built) => built,
        Err(failure) => return ClaimOutcome::from_build_failure(failure),
    };
    let preview = built.preview.clone();
    let failed = |envelope: Envelope<()>| ClaimOutcome::failed_after_preview(preview, envelope);
    let unsigned_xdr = built.envelope_xdr.clone();

    // Settle the spending-window reservations that have stood long enough to
    // be settleable, before the gate below counts them. A reservation the
    // chain has since answered for should not hold the operator's cap, and one
    // the chain has not is counted as spend.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            return failed(Envelope::<()>::err_raw("wallet.clock_error", e.to_string()));
        }
    };
    if let Ok(reconcile_client) = StellarRpcClient::new(&context.rpc_url) {
        crate::commands::submission_record::reconcile_open_reservations(
            profile,
            &resolved.name,
            origin,
            &reconcile_client,
            now_ms,
        )
        .await;
    }

    // ── Operator policy evaluation (before signing) ───────────────────────────
    let chain_id = context.chain_id.caip2_str();
    let claim_effects = match evaluate_claim_policy(&built, chain_id, profile, &resolved.name) {
        Ok(effects) => effects,
        Err(envelope) => return failed(envelope),
    };

    // Origin-aware pre-flight: prove the audit writer is acquirable AFTER the
    // policy gate (a denial is a clean refusal that signs nothing and needs
    // no audit setup) but BEFORE the signing key is touched below (step 2)
    // and BEFORE the transaction is submitted (step 3), for a persisted
    // profile — fails closed. The synthesized zero-config profile stays
    // fail-open, yielding `None` when no writer could be acquired. Where
    // `Some`, the writer is reused (not re-acquired) for the post-confirm
    // emission.
    let audit_writer = match crate::commands::value_audit::require_value_audit_writer_for_origin(
        profile,
        &resolved.name,
        origin,
    ) {
        Ok(w) => w,
        Err(e) => return failed(Envelope::<()>::err(&e)),
    };

    // 2. Sign.
    let signed_xdr =
        match sign_envelope(context, args, &unsigned_xdr, profile, &resolved.name).await {
            Ok(xdr) => xdr,
            Err(e) => return failed(Envelope::<()>::err(&e)),
        };

    // 3. Record, then submit. The recorder writes the receipt, the pending
    // audit row and the spending-window reservation before the bytes leave,
    // and settles all three against what the network answers.
    let recorder = match crate::commands::submission_record::build_recorder(
        crate::commands::submission_record::SubmitRecord {
            policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
            profile,
            profile_name: resolved.name.clone(),
            verb: "claim",
            tool: "stellar_claim",
            chain_id,
            effects: claim_effects.as_ref(),
            audit: audit_writer.clone(),
            now_ms,
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            return failed(crate::commands::submission_record::error_envelope(
                &e,
                &signed_xdr,
                "claim",
            ));
        }
    };

    match submit_envelope(context, args, &signed_xdr, Some(&recorder)).await {
        Ok((xdr, sub_result)) => ClaimOutcome::succeeded(
            Some(built.preview),
            ClaimResult {
                envelope_xdr: xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "build+sign+submit".to_owned(),
                balance_id_hex72: Some(built.balance_id_hex72),
            },
        ),
        Err(e) => failed(crate::commands::submission_record::error_envelope(
            &e,
            &signed_xdr,
            "claim",
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build helper
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the entry, builds the typed preview, runs the claim guards, and
/// constructs the unsigned envelope XDR.
///
/// The preview is built before the guards run and travels with every later
/// outcome. It is in the built envelope on success, and in the failure when a
/// guard, the fee resolution, or the envelope build refuses. The operator
/// therefore sees the balance disclosure even when a guard refuses.
///
/// # Errors
///
/// Returns a [`ClaimBuildFailure`] carrying the preview when the failure
/// followed it, and no preview when the entry fetch or the preview itself
/// failed.
async fn build_unsigned_envelope(
    context: &NetworkContext,
    args: &ClaimArgs,
) -> Result<BuiltClaimEnvelope, ClaimBuildFailure> {
    let previewed =
        fetch_claim_preview(context, args)
            .await
            .map_err(|error| ClaimBuildFailure {
                error,
                preview: None,
            })?;
    match guard_and_build(context, args, &previewed).await {
        Ok((envelope_xdr, fee_selection)) => Ok(BuiltClaimEnvelope {
            envelope_xdr,
            balance_id_hex72: previewed.id.to_hex72(),
            fee_selection,
            account_view: previewed.account_view,
            preview: previewed.preview,
        }),
        Err(error) => Err(ClaimBuildFailure {
            error,
            preview: Some(Box::new(previewed.preview)),
        }),
    }
}

/// What the preview stage of the build fetched and computed.
struct PreviewedClaim {
    id: BalanceId,
    client: StellarRpcClient,
    account_view: stellar_agent_network::AccountView,
    preview: ClaimPreview,
}

/// Parses the balance id, validates the source, fetches the entry and the
/// source account, and builds the typed preview.
async fn fetch_claim_preview(
    context: &NetworkContext,
    args: &ClaimArgs,
) -> Result<PreviewedClaim, ClaimError> {
    let id = BalanceId::parse(&args.balance_id)?;

    // Validate the source G-strkey up front.
    stellar_strkey::ed25519::PublicKey::from_string(&args.source).map_err(|_| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: args.source.clone(),
        })
    })?;

    let client = StellarRpcClient::new(&context.rpc_url)?;

    let entry = fetch_claimable_balance_entry(&client, &id).await?;

    // Fetch the source account for the sequence number and native balance.
    // Empty trustline-request slice: the trustline guard fetch (below) is a
    // separate call keyed on the balance's own asset.
    let account_view = fetch_account(&client, &args.source, &[]).await?;

    let now_secs = current_unix_secs()?;
    let preview = ClaimPreview::build(&entry, &args.source, now_secs)?;
    Ok(PreviewedClaim {
        id,
        client,
        account_view,
        preview,
    })
}

/// Runs the claim guards against the preview, resolves the fee, checks its
/// affordability, and builds the unsigned envelope.
async fn guard_and_build(
    context: &NetworkContext,
    args: &ClaimArgs,
    previewed: &PreviewedClaim,
) -> Result<(String, ClassicFeeSelection), ClaimError> {
    let PreviewedClaim {
        id,
        client,
        account_view,
        preview,
    } = previewed;

    // ── Claim guards, in order ────────────────────────────────────────────────
    require_claimant(preview, &args.source)?;
    require_predicate_satisfied(preview)?;
    if preview.asset_code.is_some() {
        let code = preview.asset_code.as_deref().unwrap_or_default();
        let issuer = preview.asset_issuer.as_deref().unwrap_or_default();
        let state = fetch_trustline_state(client, &args.source, code, issuer).await?;
        check_trustline(
            &state,
            preview.asset_code.as_deref(),
            preview.asset_issuer.as_deref(),
            preview.amount_stroops,
        )?;
    }

    // ── Fee resolution + affordability ────────────────────────────────────────
    let fee_choice = parse_classic_fee_choice(args.fee.as_deref())?;
    let fee_selection =
        resolve_classic_fee_selection(client, DEFAULT_FEE_STROOPS, fee_choice).await?;
    let fee_per_op = fee_selection.per_op_stroops;
    // Single-operation transaction: the total fee equals the per-operation fee.
    let fee_stroops = i64::from(fee_per_op);

    let native_balance_stroops = account_view
        .balances
        .first()
        .filter(|b| b.asset.asset_type == "native")
        .map(stellar_agent_network::BalanceView::balance_stroops)
        .transpose()?
        .unwrap_or(0);
    let reserves = account_view.reserves_stroops(BASE_RESERVE_STROOPS);
    // saturating_sub: under-reserved accounts yield available = 0, which fails
    // the affordability check as InsufficientBalance rather than underflowing.
    let available = native_balance_stroops.saturating_sub(reserves);
    if available < fee_stroops {
        return Err(ClaimError::from(WalletError::Ledger(
            LedgerError::InsufficientBalance {
                asset: "XLM".to_owned(),
                have: available.to_string(),
                need: fee_stroops.to_string(),
            },
        )));
    }

    // ── Build the unsigned envelope ───────────────────────────────────────────
    // Pass the current on-chain sequence directly; the builder increments it
    // internally (an explicit +1 here would produce CURRENT+2 → TxBadSeq).
    let mut builder = ClassicOpBuilder::new(
        &args.source,
        account_view.sequence_number,
        context.network_passphrase(),
        fee_per_op,
    );
    builder.claim_claimable_balance(&id.to_hex64())?;
    let envelope_xdr = builder.build()?;

    Ok((envelope_xdr, fee_selection))
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator policy gate
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluates operator policy for the built claim, using the same engine path
/// (and `stellar_claim` value descriptor contract) the `stellar_claim` MCP
/// tool's dispatch gate uses.
///
/// Returns the gate-sized effects when the operation is allowed (the caller
/// proceeds to signing).
///
/// `profile` is the profile `claim_outcome` loaded at entry and passed
/// to `run_build_only` / `run_full_pipeline`. This function does not
/// re-resolve it. The platform keyring store the caller initialised therefore
/// stays registered for the `build_v1_policy_engine` owner-key read below.
/// `run_build_only` initialises the store only for a non-`Noop` engine;
/// `run_full_pipeline` always does, ahead of its origin-aware audit pre-flight.
///
/// # Errors
///
/// Returns the refusal envelope when the engine cannot be built or the
/// operation must be refused.
fn evaluate_claim_policy(
    built: &BuiltClaimEnvelope,
    chain_id: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, Envelope<()>> {
    let policy_engine =
        build_v1_policy_engine("claim", &profile.policy.engine, profile, profile_name)
            .map_err(|msg| Envelope::<()>::err_raw("policy.engine_unavailable", msg))?;
    // `derive_value_class` ignores args for `stellar_claim` (a non-debit
    // Claim leg is always emitted); `balance_id` is carried for audit parity
    // with the MCP tool's dispatch args and for any future criterion that
    // reads it.
    let policy_args = claim_policy_args(&built.balance_id_hex72);
    // `account_view` reuses the source-account state `build_unsigned_envelope`
    // already fetched (feeds `minimum_reserve`) — mirroring the MCP
    // `stellar_claim` twin exactly. `identity_view` is `None`: `stellar_claim`
    // has no destination concept, matching the twin.
    let source_adapter =
        stellar_agent_network::policy_view::AccountViewAdapter::new(&built.account_view);
    evaluate_value_moving_policy(
        policy_engine.as_ref(),
        profile,
        "stellar_claim",
        stellar_agent_core::policy::ToolValueKind::MovesValue,
        chain_id,
        &policy_args,
        "claim",
        Some(&source_adapter),
        None,
    )
}

/// Returns the current Unix time in seconds for predicate evaluation.
fn current_unix_secs() -> Result<u64, ClaimError> {
    let ms = stellar_agent_core::timefmt::now_unix_ms().map_err(|e| {
        WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("system clock unavailable: {e}"),
        })
    })?;
    Ok(ms / 1000)
}

// ─────────────────────────────────────────────────────────────────────────────
// Sign helper
// ─────────────────────────────────────────────────────────────────────────────

/// Signs the given base64 XDR envelope using the configured signer.
///
/// Mirrors the `pay` signer model: `--sign-with-ledger` (hardware; no seed in
/// process memory) or `--secret-env VAR` (the shared mlock-protected software
/// signing ceremony, `resolve_software_signer_from_env`). The public key
/// derived from the signer is compared against `--source` before any signing.
///
/// # Errors
///
/// Propagates `WalletError` from seed parsing, `Wallet::unlock`, the pubkey
/// mismatch check, or the signing call. Returns
/// `ValidationError::SignerSourceRequired` when neither signer flag is provided.
async fn sign_envelope(
    context: &NetworkContext,
    args: &ClaimArgs,
    unsigned_xdr: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<String, WalletError> {
    let source = args.source.as_str();
    let passphrase = context.network_passphrase();

    let signer: Box<dyn Signer + Send + Sync> =
        match (args.sign_with_ledger, args.secret_env.as_deref()) {
            (true, _) => Box::new(signer_from_ledger(args.account_index, source).await?),
            (false, Some(var_name)) => {
                let SignerCeremonyOutcome {
                    signer,
                    mlock_degradation: _,
                } = resolve_software_signer_from_env(var_name, "claim-commit", profile).await?;
                let derived = signer.public_key().await?.to_string().to_string();
                if derived != source {
                    return Err(AuthError::SignerKeyMismatch {
                        expected: source.to_owned(),
                        got: derived,
                    }
                    .into());
                }
                Box::new(signer)
            }
            (false, None) => {
                return Err(ValidationError::SignerSourceRequired {
                    detail:
                        "no signer flag specified; pass --secret-env <VAR> or --sign-with-ledger"
                            .to_owned(),
                }
                .into());
            }
        };
    require_enrolled_signer(profile_name, profile, signer.as_ref()).await?;
    attach_signature(unsigned_xdr, signer.as_ref(), passphrase).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Submit helper
// ─────────────────────────────────────────────────────────────────────────────

/// Asks `--rpc-url` which network it serves and requires it to be the one
/// `--network` names.
///
/// `--sign-only` does not call this: it sends nothing, so no endpoint answers
/// for it.
async fn probe_endpoint_network(
    context: &NetworkContext,
    args: &ClaimArgs,
) -> Result<(), WalletError> {
    let client = StellarRpcClient::new(&context.rpc_url)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout_seconds);
    client
        .verify_network_passphrase(context.network_passphrase(), deadline)
        .await
}

async fn submit_envelope(
    context: &NetworkContext,
    args: &ClaimArgs,
    signed_xdr: &str,
    recorder: Option<&dyn stellar_agent_network::SubmissionRecorder>,
) -> Result<(String, SubmissionResult), WalletError> {
    let client = StellarRpcClient::new(&context.rpc_url)?;
    let timeout = Duration::from_secs(args.timeout_seconds);
    let passphrase = context.network_passphrase();
    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        timeout,
        passphrase,
        Some(SubmissionSignerKind::Software),
        recorder,
    )
    .await?;
    Ok((signed_xdr.to_owned(), result))
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds an error envelope from a [`ClaimError`], preserving its stable
/// `claim.*` / delegated wire code and its (secret-free) display message.
fn claim_error_envelope(err: &ClaimError) -> Envelope<()> {
    Envelope::<()>::err_raw(err.code(), err.to_string())
}

/// Writes `outcome` to `out` per `format` and returns the exit code.
///
/// JSON output is one envelope: the success data carries the preview at
/// `data.preview`, a failure after the preview carries it at
/// `error.details.preview`. Table output prints the preview line before the
/// result or error line. Output that cannot be written or flushed exits `1`
/// with the failure on stderr, whatever the outcome.
fn render_claim_outcome(out: &mut dyn Write, format: OutputFormat, outcome: ClaimOutcome) -> i32 {
    let ClaimOutcome { preview, result } = outcome;
    let exit_code = if result.is_ok() { 0 } else { 1 };
    if format == OutputFormat::Table {
        return exit_code_after_output(
            render_claim_table(out, preview.as_ref(), &result),
            exit_code,
        );
    }
    let preview = preview.as_ref().map(claim_preview_view);
    match result {
        Ok(result) => write_envelope(
            out,
            &Envelope::ok(WithPreview { result, preview }),
            exit_code,
        ),
        Err(envelope) => {
            let envelope = match preview {
                Some(preview) => with_preview_detail(envelope, preview),
                None => envelope,
            };
            write_envelope(out, &envelope, exit_code)
        }
    }
}

/// The typed preview as the nested `preview` object of the output envelope.
fn claim_preview_view(preview: &ClaimPreview) -> serde_json::Value {
    serde_json::json!({
        "balance_id_hex72": &preview.balance_id_hex72,
        "balance_id_strkey": &preview.balance_id_strkey,
        "asset_code": &preview.asset_code,
        "asset_issuer": &preview.asset_issuer,
        "amount_stroops": preview.amount_stroops.to_string(),
        "amount_display": &preview.amount_display,
        "claimants": &preview.claimants,
        "is_claimant": preview.is_claimant,
        "predicate_satisfied": preview.predicate_satisfied,
        "window": &preview.window,
        "clawback_enabled": preview.clawback_enabled,
    })
}

/// Writes the table form of `result`, after the preview line when a preview
/// was computed, and flushes it.
///
/// # Errors
///
/// Returns the I/O error when a line cannot be written or the output cannot
/// be flushed.
fn render_claim_table(
    out: &mut dyn Write,
    preview: Option<&ClaimPreview>,
    result: &Result<ClaimResult, Envelope<()>>,
) -> std::io::Result<()> {
    let mut lines = Vec::new();
    if let Some(preview) = preview {
        lines.push(format!(
            "[preview] balance {}  asset {}  amount {}  is_claimant {}",
            preview.balance_id_strkey,
            preview.asset_code.as_deref().unwrap_or("XLM"),
            preview.amount_display,
            preview.is_claimant
        ));
    }
    match result {
        Ok(result) => match (&result.tx_hash, &result.ledger) {
            (Some(hash), Some(ledger)) => {
                use stellar_agent_network::submit::redact_tx_hash;
                lines.push(format!(
                    "Claim submitted: tx_hash {}  ledger {}",
                    redact_tx_hash(hash),
                    ledger
                ));
            }
            _ => {
                let prefix: String = result.envelope_xdr.chars().take(32).collect();
                lines.push(format!(
                    "[{}] envelope_xdr (first 32 chars): {}...",
                    result.stage, prefix
                ));
            }
        },
        Err(envelope) => {
            if let Some(err) = &envelope.error {
                let safe_msg = sanitize_for_table(&err.message);
                lines.push(format!("Error: {} — {}", err.code, safe_msg));
            }
        }
    }
    for line in &lines {
        writeln!(out, "{line}")?;
    }
    out.flush()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;
    use crate::common::signer_ceremony::test_fixtures::{
        EnrolledPin, assert_enrolled_outcome, enrolled_mainnet_profile, enrolled_test_g,
        enrolled_test_secret,
    };
    use stellar_agent_claimable::entry::TrustlineState;

    const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const ISSUER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const HEX64: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    fn base_args() -> Vec<String> {
        vec![
            "claim".to_owned(),
            HEX64.to_owned(),
            "--source".to_owned(),
            SOURCE_G.to_owned(),
        ]
    }

    fn try_parse_claim(args: &[String]) -> Result<ClaimArgs, clap::Error> {
        use clap::Parser;
        #[derive(Debug, clap::Parser)]
        struct TestClaim {
            #[command(flatten)]
            args: ClaimArgs,
        }
        TestClaim::try_parse_from(args).map(|t| t.args)
    }

    fn minimal_args() -> ClaimArgs {
        ClaimArgs {
            // Zero-config group: `None` is "no profile named", the path that
            // still synthesizes. `Some("default")` would be an explicitly
            // named profile and would refuse instead.
            profile: None,
            balance_id: HEX64.to_owned(),
            source: SOURCE_G.to_owned(),
            fee: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            build_only: false,
            sign_only: None,
            submit_only: None,
            network: Some(TargetNetwork::Testnet),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(crate::common::network::TESTNET_RPC_URL.to_owned()),
        }
    }

    // ── Clap three-stage mutual exclusivity ───────────────────────────────────

    #[test]
    fn clap_build_only_and_sign_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--build-only".to_owned(),
            "--sign-only".to_owned(),
            "AAAA==".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_build_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--build-only".to_owned(),
            "--submit-only".to_owned(),
            "AAAA==".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_sign_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--sign-only".to_owned(),
            "AAAA==".to_owned(),
            "--submit-only".to_owned(),
            "AAAA==".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_secret_env_and_sign_with_ledger_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend([
            "--secret-env".to_owned(),
            "MY_SECRET".to_owned(),
            "--sign-with-ledger".to_owned(),
        ]);
        let err = try_parse_claim(&args).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn clap_base_args_parse_and_default_to_full_pipeline() {
        let parsed = try_parse_claim(&base_args()).expect("base args must parse");
        assert_eq!(parsed.balance_id, HEX64);
        assert_eq!(parsed.source, SOURCE_G);
        assert!(!parsed.build_only);
        assert!(parsed.sign_only.is_none());
        assert!(parsed.submit_only.is_none());
        assert_eq!(parsed.network, None);
        assert_eq!(parsed.rpc_url, None);
        let mut explicit = base_args();
        explicit.extend(
            ["--network", "mainnet", "--rpc-url", "https://flags.example"].map(str::to_owned),
        );
        let parsed = try_parse_claim(&explicit).expect("explicit endpoint flags parse");
        assert_eq!(parsed.network, Some(TargetNetwork::Mainnet));
        assert_eq!(parsed.rpc_url.as_deref(), Some("https://flags.example"));
    }

    // ── Trustline guard refusal paths (hand-built TrustlineState) ─────────────
    //
    // TrustlineState is a plain (non-exhaustive-free) struct, so the trustline
    // guard's refusal codes are exercised directly here. The claimant and
    // predicate guards operate on `ClaimPreview`, which is `#[non_exhaustive]`
    // and therefore only constructible inside `stellar-agent-claimable`, where
    // those guards are already unit-tested.

    #[test]
    fn check_trustline_missing_refuses() {
        let state = TrustlineState {
            exists: false,
            authorized: false,
            limit: 0,
            balance: 0,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("missing trustline must refuse");
        assert_eq!(err.code(), "claim.trustline_missing");
    }

    #[test]
    fn check_trustline_not_authorized_refuses() {
        let state = TrustlineState {
            exists: true,
            authorized: false,
            limit: 1_000,
            balance: 0,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("unauthorized trustline must refuse");
        assert_eq!(err.code(), "claim.trustline_not_authorized");
    }

    #[test]
    fn check_trustline_limit_refuses() {
        let state = TrustlineState {
            exists: true,
            authorized: true,
            limit: 1_000,
            balance: 950,
        };
        let err = check_trustline(&state, Some("USDC"), Some(ISSUER_G), 100)
            .expect_err("amount over headroom must refuse");
        assert_eq!(err.code(), "claim.trustline_limit");
    }

    // ── Fee-affordability error mapping ───────────────────────────────────────

    #[test]
    fn fee_unaffordable_maps_to_insufficient_balance() {
        let err = ClaimError::from(WalletError::Ledger(LedgerError::InsufficientBalance {
            asset: "XLM".to_owned(),
            have: "0".to_owned(),
            need: "100".to_owned(),
        }));
        assert_eq!(err.code(), "ledger.insufficient_balance");
    }

    // ── Invalid balance id maps to the claim wire code ────────────────────────

    #[test]
    fn invalid_balance_id_error_code() {
        let err = BalanceId::parse("not-a-balance-id").expect_err("must refuse");
        let envelope = claim_error_envelope(&err);
        assert_eq!(
            envelope.error.as_ref().map(|e| e.code.as_str()),
            Some("claim.invalid_balance_id")
        );
    }

    // ── Mainnet rejected at run boundary ──────────────────────────────────────

    /// Mainnet is rejected at the `run` boundary: the keyring initializer is
    /// never invoked and no request reaches the profile's endpoint.
    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_rejected_at_run_boundary() {
        let guard_rpc = wiremock::MockServer::start().await;
        let counter =
            stellar_agent_test_support::ConnectionCounter::start().expect("connection counter");
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(
                &counter.https_uri(),
            );
        let mut args = minimal_args();
        args.network = Some(TargetNetwork::Mainnet);
        args.profile = Some("guard-mainnet".into());
        args.rpc_url = None;
        let exit = run_with_dependencies(
            &args,
            |name| {
                Ok(
                    Profile::builder_mainnet_named(name, guard_rpc.uri(), "s", "default", "n", "a")
                        .build(),
                )
            },
            || panic!("mainnet must not initialize the keyring"),
            &mut std::io::sink(),
        )
        .await;
        assert_eq!(exit, 1, "mainnet must exit with code 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
        assert_eq!(
            counter.accepted().expect("connection count"),
            0,
            "no connection may reach the persisted profile's endpoint"
        );
    }

    /// `--network mainnet` with no profile refuses before the keyring
    /// initializer runs and before any request reaches `--rpc-url`.
    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_rejected_at_run_boundary_network_flag_without_profile_refuses() {
        let guard_rpc = wiremock::MockServer::start().await;
        let guard_home = tempfile::tempdir().expect("home");
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        let _guard_env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let mut args = minimal_args();
        args.network = Some(TargetNetwork::Mainnet);
        args.rpc_url = Some(guard_rpc.uri());
        let exit = run_with_dependencies(
            &args,
            |name| {
                Err(
                    stellar_agent_core::profile::loader::ProfileLoadError::NotFound {
                        name: name.into(),
                        path: std::path::PathBuf::from("absent"),
                    },
                )
            },
            || panic!("network mismatch must not initialize the keyring"),
            &mut std::io::sink(),
        )
        .await;
        assert_eq!(exit, 1, "mainnet must exit with code 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    // ── keyring store initialisation ordering (issue #41) ────────────────────

    /// The platform keyring store must be initialised before the V1 policy
    /// gate's owner-key read (`build_v1_policy_engine`), on both gated
    /// stages (`--build-only` here). Both dependencies are injected, so no
    /// OS keychain or on-disk profile is touched and no process-global
    /// keyring store is registered — hence this test needs no `#[serial]`.
    /// The injected initialiser returns an error so the run bails at that
    /// step, before `build_unsigned_envelope` (and its RPC calls) ever runs,
    /// proving the initialisation happens ahead of any network build.
    #[tokio::test]
    async fn run_initialises_keyring_store_before_policy_gate() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let profile_loaded = Arc::new(AtomicBool::new(false));
        let init_invoked = Arc::new(AtomicBool::new(false));

        let loaded_writer = Arc::clone(&profile_loaded);
        let loaded_reader = Arc::clone(&profile_loaded);
        let init_writer = Arc::clone(&init_invoked);

        let mut args = minimal_args();
        args.build_only = true;

        let code = run_with_dependencies(
            &args,
            move |name| {
                loaded_writer.store(true, Ordering::SeqCst);
                // Built under the name it is LOADED BY, as `profile init`
                // writes it: the profile-access choke point refuses a file
                // whose owner coordinate names a different profile, and this
                // test is about the keyring-init ordering, not that refusal.
                let profile = Profile::builder_testnet_named(
                    name,
                    "stellar-agent-signer",
                    name,
                    "stellar-agent-nonce",
                    name,
                )
                .policy_engine(PolicyEngineKind::V1)
                .build();
                Ok(profile)
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
            "run must initialise the keyring store before the V1 policy gate's owner-key read"
        );
        assert_eq!(
            code, 1,
            "run must surface the keyring init failure instead of reaching the network build"
        );
    }

    /// When the resolved profile's engine is `Noop` (the zero-config
    /// default), the keyring initialiser must NOT be invoked — the `Noop`
    /// engine never reads the owner key from the keyring.
    #[tokio::test]
    async fn run_does_not_initialise_keyring_when_engine_is_noop() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let init_invoked = Arc::new(AtomicBool::new(false));
        let init_writer = Arc::clone(&init_invoked);

        // `--build-only` with a syntactically-invalid balance id:
        // `build_unsigned_envelope` refuses on `BalanceId::parse` before any
        // RPC client construction, so this stays network-free.
        let mut args = minimal_args();
        args.build_only = true;
        args.balance_id = "not-a-balance-id".to_owned();

        let code = run_with_dependencies(
            &args,
            |name| {
                // Built under the name it is LOADED BY: the profile-access
                // choke point refuses a file whose owner coordinate names a
                // different profile, and this test is about the keyring-init
                // ordering under a Noop engine, not that refusal.
                let profile = Profile::builder_testnet_named(
                    name,
                    "stellar-agent-signer",
                    name,
                    "stellar-agent-nonce",
                    name,
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build();
                Ok(profile)
            },
            move || {
                init_writer.store(true, Ordering::SeqCst);
                Ok(())
            },
            &mut std::io::sink(),
        )
        .await;

        assert!(
            !init_invoked.load(Ordering::SeqCst),
            "the Noop engine must never trigger the keyring store initialisation"
        );
        assert_eq!(
            code, 1,
            "invalid balance id must still refuse (unrelated to the keyring gate)"
        );
    }

    // ── init_keyring_for_origin: origin-aware keyring-init failure ────────────
    //
    // `init_keyring_for_origin` backs `run_sign_only`, `run_submit_only`, and
    // `run_full_pipeline`.
    // These tests call it directly (sync, no RPC or gate involved), because
    // the Synthesized/Persisted split is the whole behavior under test. A
    // direct call pins it without the RPC-mocked surface of a full
    // `--sign-only` run.

    /// A synthesized profile must tolerate a platform keyring-init failure
    /// and return `Ok` — not refuse — matching the zero-config quickstart's
    /// fail-open posture. The tolerance is origin-scoped, not unconditional:
    /// making it fatal for every origin would break `claim --secret-env ...`
    /// with no profile file on any host without a platform keyring (e.g. a
    /// container without a Secret Service).
    ///
    /// The origin is produced by the real choke point, not injected: the
    /// loader reports the file is absent and `minimal_args` names no profile
    /// (zero-config group), so the synthesis decision under test actually runs.
    #[test]
    #[serial_test::serial]
    fn init_keyring_for_origin_synthesized_tolerates_init_failure() {
        // `resolve_profile_name` reads the ambient `STELLAR_AGENT_PROFILE`; an
        // exported value would make the name explicit and turn the synthesis
        // branch under test into a refusal. Process-global, hence `#[serial]`.
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let args = minimal_args();
        let resolved = resolve_profile_name(args.profile.as_deref());
        let (_profile, origin) = load_profile_or_synthesize_testnet_with(&resolved, |name| {
            Err(
                stellar_agent_core::profile::loader::ProfileLoadError::NotFound {
                    name: name.to_owned(),
                    path: std::path::PathBuf::from("/nonexistent"),
                },
            )
        })
        .expect("profile");
        let result = init_keyring_for_origin(&resolved, origin, || {
            Err(WalletError::Auth(AuthError::KeyringNotFound {
                name: "init-keyring-for-origin-synthesized-sentinel".to_owned(),
            }))
        });
        result.expect("a synthesized zero-config profile must tolerate a keyring-init failure");
        assert_eq!(origin, ProfileOrigin::Synthesized);
    }

    /// The same absent profile file, but NAMED through `--profile`, refuses
    /// before the keyring-init step is ever reached. The injected loader is
    /// byte-identical to the test above: only the provenance of the resolved
    /// name differs, which is exactly what the choke point keys on.
    #[tokio::test]
    #[serial_test::serial]
    async fn named_absent_profile_refuses_before_keyring_init() {
        // Serialised with its sibling above: both mutate/read the same
        // process-global `STELLAR_AGENT_PROFILE`.
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let mut args = minimal_args();
        args.profile = Some("claim-named-never-authored".to_owned());
        let init_invoked = std::cell::Cell::new(false);
        let code = run_with_dependencies(
            &args,
            |name| {
                Err(
                    stellar_agent_core::profile::loader::ProfileLoadError::NotFound {
                        name: name.to_owned(),
                        path: std::path::PathBuf::from("/nonexistent"),
                    },
                )
            },
            || {
                init_invoked.set(true);
                Ok(())
            },
            &mut std::io::sink(),
        )
        .await;
        assert_eq!(code, 1, "a named-but-missing profile must refuse");
        assert!(
            !init_invoked.get(),
            "the refusal must precede the keyring-init step"
        );
    }

    /// A [`ProfileOrigin::Persisted`] profile must refuse with the keyring
    /// error's envelope when the platform keyring store fails to initialize.
    /// An operator who authored a profile file is expected to have a working
    /// platform keyring for the fail-closed audit pre-flight and the
    /// keyring-backed owner-key read, so this failure stays fatal.
    #[test]
    #[serial_test::serial]
    fn init_keyring_for_origin_persisted_fails_on_init_failure() {
        // Serialised with its siblings above for the same reason.
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let args = minimal_args();
        let resolved = resolve_profile_name(args.profile.as_deref());
        let (_profile, origin) = load_profile_or_synthesize_testnet_with(&resolved, |name| {
            Ok(Profile::builder_testnet_named(
                name,
                "stellar-agent-signer",
                name,
                "stellar-agent-nonce",
                name,
            )
            .policy_engine(PolicyEngineKind::Noop)
            .build())
        })
        .expect("profile");
        let result = init_keyring_for_origin(&resolved, origin, || {
            Err(WalletError::Auth(AuthError::KeyringNotFound {
                name: "init-keyring-for-origin-persisted-sentinel".to_owned(),
            }))
        });
        match result {
            Err(envelope) => assert_eq!(
                envelope.error.as_ref().map(|e| e.code.as_str()),
                Some("auth.keyring_not_found"),
                "a persisted profile must refuse with the keyring error when the platform \
                 keyring store cannot be initialised"
            ),
            Ok(_) => panic!(
                "a persisted profile must refuse when the platform keyring store cannot be \
                 initialised, not fall back to the zero-config warn-only posture"
            ),
        }
    }

    // ── staged sign/submit-only gate tests ───────────────────────────────────
    //
    // `dispatch_staged_claim_gate` is network- and keyring-free, so these
    // tests exercise it directly with hand-built XDR fixtures and a
    // hand-built `PolicyEngineV1`. `run_sign_only` and `run_submit_only` both
    // call this SAME function with the SAME arguments (only the subsequent
    // sign-vs-submit action differs), so exercising it once here proves both
    // staged stages gate identically.

    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::PolicyEngineV1;
    use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
    use stellar_xdr::{
        AccountId, ClaimClaimableBalanceOp, ClaimableBalanceId, CreateAccountOp, Hash, Limits,
        MuxedAccount, Operation, OperationBody, Preconditions, PublicKey as XdrPublicKey,
        SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
        Uint256, VecM, WriteXdr,
    };

    fn g_to_bytes(g: &str) -> [u8; 32] {
        stellar_strkey::ed25519::PublicKey::from_string(g)
            .expect("valid G-strkey in test fixture")
            .0
    }

    fn g_to_muxed(g: &str) -> MuxedAccount {
        MuxedAccount::Ed25519(Uint256(g_to_bytes(g)))
    }

    fn g_to_account_id(g: &str) -> AccountId {
        AccountId(XdrPublicKey::PublicKeyTypeEd25519(Uint256(g_to_bytes(g))))
    }

    fn build_envelope_b64(tx_source: &str, op: Operation) -> String {
        let tx = Transaction {
            source_account: g_to_muxed(tx_source),
            fee: 100,
            seq_num: SequenceNumber(101),
            cond: Preconditions::None,
            memo: stellar_xdr::Memo::None,
            operations: vec![op].try_into().expect("single op vec"),
            ext: TransactionExt::V0,
        };
        let env = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        });
        env.to_xdr_base64(Limits::none())
            .expect("XDR encoding must succeed")
    }

    /// A `stellar_claim`-shaped envelope: a single `ClaimClaimableBalance`
    /// operation from `SOURCE_G`.
    fn claim_envelope_b64() -> String {
        let op = Operation {
            source_account: None,
            body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab_u8; 32])),
            }),
        };
        build_envelope_b64(SOURCE_G, op)
    }

    /// An envelope the claim decoder cannot classify: a `CreateAccount`
    /// operation presented where a `ClaimClaimableBalance` is expected.
    fn unclassifiable_envelope_b64() -> String {
        let op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(ISSUER_G),
                starting_balance: 10_000_000,
            }),
        };
        build_envelope_b64(SOURCE_G, op)
    }

    fn per_tx_cap_engine(allow_opaque_signing: bool) -> PolicyEngineV1 {
        // `stellar_claim` derives a non-debit Claim leg (never sized by
        // per_tx_cap), so this rule's presence alone proves the
        // `NotApplicable` vs `Deny(UnsizableValueEffect)` split rather than a
        // cap comparison — the decodable-envelope test asserts Allow, the
        // unclassifiable-envelope tests assert the opaque posture.
        let rule = PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_claim_commit".to_owned(),
                chain: "*".to_owned(),
            },
            criteria: vec![Box::new(PerTxCapCriterion::new(
                "native".to_owned(),
                1_000_000_000_i128,
            ))],
            decision: Decision::Allow,
            allow_opaque_signing,
        };
        let doc = PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            rules: vec![rule],
            signature: None,
        };
        PolicyEngineV1::new(doc, "alice".to_owned())
    }

    fn staged_test_profile() -> Profile {
        Profile::builder_testnet(
            "stellar-agent-signer",
            "alice",
            "stellar-agent-nonce",
            "alice",
        )
        .build()
    }

    fn envelope_code(
        result: &Result<Option<stellar_agent_core::policy::v1::ValueEffects>, Envelope<()>>,
    ) -> &str {
        result
            .as_ref()
            .expect_err("expected a refusal envelope")
            .error
            .as_ref()
            .expect("refusal envelope must carry an error block")
            .code
            .as_str()
    }

    /// A decodable claim envelope under a rule whose criterion does not
    /// apply to the non-debit `Claim` leg allows.
    #[test]
    fn dispatch_staged_claim_gate_decodable_envelope_allows() {
        let engine = per_tx_cap_engine(false);
        let profile = staged_test_profile();
        let xdr = claim_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &xdr,
            "stellar_claim_commit",
        );
        assert!(decode_result.is_ok(), "fixture must decode as a claim");
        let result =
            dispatch_staged_claim_gate(&engine, &profile, "stellar:testnet", decode_result, None);
        assert!(
            result.is_ok(),
            "a decodable claim envelope must allow, got {result:?}"
        );
    }

    /// An envelope the decoder cannot classify, under a matched value rule,
    /// denies `policy.deny.unsizable_value_effect`.
    #[test]
    fn dispatch_staged_claim_gate_unclassifiable_envelope_denies_unsizable() {
        let engine = per_tx_cap_engine(false);
        let profile = staged_test_profile();
        let xdr = unclassifiable_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &xdr,
            "stellar_claim_commit",
        );
        assert!(
            decode_result.is_err(),
            "fixture must be undecodable as a claim"
        );
        let result =
            dispatch_staged_claim_gate(&engine, &profile, "stellar:testnet", decode_result, None);
        assert_eq!(
            envelope_code(&result),
            "policy.deny.unsizable_value_effect",
            "an unclassifiable staged envelope under a matched value rule must deny \
             unsizable, got {result:?}"
        );
    }

    /// The same unclassifiable envelope, under a rule with
    /// `allow_opaque_signing = true`, proceeds (allows).
    #[test]
    fn dispatch_staged_claim_gate_unclassifiable_envelope_with_allow_opaque_signing_allows() {
        let engine = per_tx_cap_engine(true);
        let profile = staged_test_profile();
        let xdr = unclassifiable_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &xdr,
            "stellar_claim_commit",
        );
        let result =
            dispatch_staged_claim_gate(&engine, &profile, "stellar:testnet", decode_result, None);
        assert!(
            result.is_ok(),
            "allow_opaque_signing = true must let the unclassifiable envelope proceed, \
             got {result:?}"
        );
        assert_eq!(
            result.expect("checked is_ok above"),
            None,
            "an opaque allow surfaces no gate-sized effects"
        );
    }

    /// The no-op engine allows every staged flow unconditionally, decodable
    /// or not.
    #[test]
    fn dispatch_staged_claim_gate_noop_engine_allows_regardless_of_decodability() {
        let engine = stellar_agent_core::policy::NoopPolicyEngine;
        let profile = staged_test_profile();

        let decodable = claim_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &decodable,
            "stellar_claim_commit",
        );
        let result =
            dispatch_staged_claim_gate(&engine, &profile, "stellar:testnet", decode_result, None);
        assert!(
            result.is_ok(),
            "Noop engine must allow a decodable envelope"
        );

        let undecodable = unclassifiable_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &undecodable,
            "stellar_claim_commit",
        );
        let result =
            dispatch_staged_claim_gate(&engine, &profile, "stellar:testnet", decode_result, None);
        assert!(
            result.is_ok(),
            "Noop engine must allow an undecodable (opaque) envelope too"
        );
    }

    #[allow(unsafe_code, reason = "serialized test seed variable")]
    async fn enrolled_signing_case(pin: EnrolledPin) {
        let g = enrolled_test_g();
        let var = "ENROLLED_CLAIM_TEST_SEED";
        unsafe {
            std::env::set_var(var, enrolled_test_secret());
        }
        let mut profile = enrolled_mainnet_profile(pin);
        let server = mount_claim_rpc(&g).await;
        profile.rpc_url = server.uri();
        let context = NetworkContext::from_profile(&profile);
        let mut args = minimal_args();
        args.source = g;
        args.secret_env = Some(var.into());
        args.fee = Some("100".into());
        args.balance_id = CLAIM_RPC_BALANCE_HEX64.to_owned();
        let built = build_unsigned_envelope(&context, &args)
            .await
            .expect("build against mock");
        let result =
            sign_envelope(&context, &args, &built.envelope_xdr, &profile, "enrolled").await;
        unsafe {
            std::env::remove_var(var);
        }
        assert_enrolled_outcome(pin, result);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_signing_equal() {
        enrolled_signing_case(EnrolledPin::Derived).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_signing_placeholder() {
        enrolled_signing_case(EnrolledPin::Placeholder).await;
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn enrolled_signing_mismatch() {
        enrolled_signing_case(EnrolledPin::Other).await;
    }

    /// The 64-hex hash of the claimable balance [`mount_claim_rpc`] serves.
    const CLAIM_RPC_BALANCE_HEX64: &str =
        "abababababababababababababababababababababababababababababababab";

    /// Starts an RPC mock whose `getLedgerEntries` serves an unconditional
    /// 10 XLM claimable balance for `claimant` and a funded `claimant`
    /// account. Every other method gets an empty result.
    async fn mount_claim_rpc(claimant: &str) -> wiremock::MockServer {
        use stellar_xdr::{
            ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt, Claimant, ClaimantV0,
            LedgerEntryData, LedgerKey, LedgerKeyClaimableBalance,
        };
        let server = wiremock::MockServer::start().await;
        let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
        let claim_key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
            balance_id: balance_id.clone(),
        })
        .to_xdr_base64(Limits::none())
        .expect("key");
        let entry = ClaimableBalanceEntry {
            balance_id,
            claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
                destination: g_to_account_id(claimant),
                predicate: ClaimPredicate::Unconditional,
            })]
            .try_into()
            .expect("claimants"),
            asset: stellar_xdr::Asset::Native,
            amount: 100_000_000,
            ext: ClaimableBalanceEntryExt::V0,
        };
        let claim_xdr = LedgerEntryData::ClaimableBalance(entry)
            .to_xdr_base64(Limits::none())
            .expect("claim XDR");
        let account_xdr = enrolled_account_xdr(claimant);
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let value: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("RPC JSON");
                let result = match value["params"]["keys"][0].as_str() {
                    Some(key) if value["method"] == "getLedgerEntries" => {
                        let xdr = if key == claim_key {
                            &claim_xdr
                        } else {
                            &account_xdr
                        };
                        serde_json::json!({
                            "entries": [{"key": key, "xdr": xdr, "lastModifiedLedgerSeq": 1000}],
                            "latestLedger": 1001,
                        })
                    }
                    _ => serde_json::json!({}),
                };
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": value["id"],
                    "result": result,
                }))
            })
            .mount(&server)
            .await;
        server
    }

    /// The JSON-RPC methods `server` received, in order.
    async fn received_methods(server: &wiremock::MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .expect("request recording")
            .iter()
            .filter_map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body)
                    .ok()
                    .and_then(|body| body["method"].as_str().map(str::to_owned))
            })
            .collect()
    }

    /// Arguments for claiming the balance [`mount_claim_rpc`] serves at
    /// `server`, under a persisted `Noop` profile.
    fn one_envelope_args(server: &wiremock::MockServer, fee: &str) -> ClaimArgs {
        let mut args = minimal_args();
        args.profile = Some("claim-one-envelope".to_owned());
        args.balance_id = CLAIM_RPC_BALANCE_HEX64.to_owned();
        args.fee = Some(fee.to_owned());
        args.rpc_url = Some(server.uri());
        args
    }

    /// Loads a persisted `Noop`-engine testnet profile under the requested
    /// name.
    fn noop_profile(
        name: &str,
    ) -> Result<Profile, stellar_agent_core::profile::loader::ProfileLoadError> {
        Ok(Profile::builder_testnet_named(
            name,
            "stellar-agent-signer",
            name,
            "stellar-agent-nonce",
            name,
        )
        .policy_engine(PolicyEngineKind::Noop)
        .build())
    }

    /// A successful `--build-only` claim prints exactly one JSON document:
    /// the result envelope, with the preview nested at `data.preview`.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_built_claim_prints_one_envelope_with_the_preview_in_data() {
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let server = mount_claim_rpc(SOURCE_G).await;
        let mut args = one_envelope_args(&server, "100");
        args.build_only = true;
        let mut out = Vec::new();
        let code = run_with_dependencies(&args, noop_profile, || Ok(()), &mut out).await;

        assert_eq!(code, 0, "{}", String::from_utf8_lossy(&out));
        let envelope = crate::common::render::single_json_document(&out);
        assert_eq!(envelope["ok"], true, "{envelope}");
        let data = &envelope["data"];
        assert_eq!(data["stage"], "build", "{envelope}");
        assert!(
            data["envelope_xdr"].as_str().is_some_and(|x| !x.is_empty()),
            "{envelope}"
        );
        let balance_id_hex72 = format!("00000000{CLAIM_RPC_BALANCE_HEX64}");
        assert_eq!(data["balance_id_hex72"], balance_id_hex72, "{envelope}");
        assert_eq!(
            data["preview"]["balance_id_hex72"], balance_id_hex72,
            "{envelope}"
        );
        assert_eq!(data["preview"]["is_claimant"], true, "{envelope}");
        assert_eq!(data["preview"]["amount_stroops"], "100000000", "{envelope}");
        assert!(data["preview"].get("stage").is_none(), "{envelope}");
    }

    /// A failure after the preview prints exactly one JSON document: the
    /// error envelope, with the preview nested at `error.details.preview`.
    ///
    /// `--fee bogus` passes the entry fetch, the preview, and the claim
    /// guards against the mock, then fails at the fee parse, before the
    /// fee-statistics request, signing, or any submission.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_failure_after_the_preview_prints_one_envelope_with_the_preview_in_details() {
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let server = mount_claim_rpc(SOURCE_G).await;
        let args = one_envelope_args(&server, "bogus");
        let mut out = Vec::new();
        let code = run_with_dependencies(&args, noop_profile, || Ok(()), &mut out).await;

        assert_eq!(code, 1, "{}", String::from_utf8_lossy(&out));
        let envelope = crate::common::render::single_json_document(&out);
        assert_eq!(envelope["ok"], false, "{envelope}");
        assert_eq!(
            envelope["error"]["code"], "validation.amount_malformed",
            "{envelope}"
        );
        let preview = &envelope["error"]["details"]["preview"];
        assert_eq!(
            preview["balance_id_hex72"],
            format!("00000000{CLAIM_RPC_BALANCE_HEX64}"),
            "{envelope}"
        );
        assert_eq!(preview["is_claimant"], true, "{envelope}");
        let methods = received_methods(&server).await;
        assert!(
            methods.iter().all(|m| m == "getLedgerEntries"),
            "the fee parse fails before any later request: {methods:?}"
        );
    }

    /// A failure before the preview prints one envelope without a preview.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_failure_before_the_preview_prints_one_envelope_without_a_preview() {
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let server = mount_claim_rpc(SOURCE_G).await;
        let mut args = one_envelope_args(&server, "100");
        args.balance_id = "not-a-balance-id".to_owned();
        let mut out = Vec::new();
        let code = run_with_dependencies(&args, noop_profile, || Ok(()), &mut out).await;

        assert_eq!(code, 1);
        let envelope = crate::common::render::single_json_document(&out);
        assert_eq!(
            envelope["error"]["code"], "claim.invalid_balance_id",
            "{envelope}"
        );
        assert!(envelope["error"].get("details").is_none(), "{envelope}");
    }

    /// A successful claim whose output cannot be written or flushed exits
    /// `1`, in JSON and in table output: the result never reached the caller.
    #[test]
    fn a_successful_claim_whose_output_fails_exits_one() {
        use crate::common::render::FailingWriter;
        let built = || {
            ClaimOutcome::succeeded(
                None,
                ClaimResult {
                    envelope_xdr: "AAAA".to_owned(),
                    tx_hash: None,
                    ledger: None,
                    stage: "build".to_owned(),
                    balance_id_hex72: None,
                },
            )
        };
        for format in [OutputFormat::Json, OutputFormat::Table] {
            for mut writer in [FailingWriter::Write, FailingWriter::Flush] {
                let code = render_claim_outcome(&mut writer, format, built());
                assert_eq!(code, 1, "{format:?} {writer:?}");
            }
            assert_eq!(
                render_claim_outcome(&mut Vec::new(), format, built()),
                0,
                "{format:?}"
            );
        }
    }

    /// Table output prints the preview line, then the error line, for a
    /// failure after the preview.
    #[tokio::test]
    #[serial_test::serial]
    async fn table_output_prints_the_preview_line_before_the_error_line() {
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let server = mount_claim_rpc(SOURCE_G).await;
        let mut args = one_envelope_args(&server, "bogus");
        args.output = OutputFormat::Table;
        let mut out = Vec::new();
        let code = run_with_dependencies(&args, noop_profile, || Ok(()), &mut out).await;

        assert_eq!(code, 1);
        let text = String::from_utf8(out).expect("UTF-8 table output");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].starts_with("[preview] balance B"), "{text}");
        assert!(
            lines[1].starts_with("Error: validation.amount_malformed"),
            "{text}"
        );
    }

    fn enrolled_account_xdr(account_id: &str) -> String {
        use stellar_xdr::{
            AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
            SequenceNumber, String32, Thresholds, Uint256, WriteXdr,
        };
        let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
            .expect("valid account_id")
            .0;
        let entry = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
            balance: 100_000_000_000,
            seq_num: SequenceNumber(100),
            num_sub_entries: 0,
            inflation_dest: None,
            flags: 0,
            home_domain: String32::default(),
            thresholds: Thresholds([1, 0, 0, 0]),
            signers: vec![].try_into().expect("empty signers"),
            ext: AccountEntryExt::V0,
        };
        LedgerEntryData::Account(entry)
            .to_xdr_base64(Limits::none())
            .expect("XDR encoding must succeed")
    }
}
