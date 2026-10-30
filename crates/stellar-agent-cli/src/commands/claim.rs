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
//! # Mainnet
//!
//! On a mainnet profile only the full pipeline runs: `--build-only`,
//! `--sign-only` and `--submit-only` refuse with
//! `network.mainnet_write_forbidden` before the write context, the keyring
//! and any request; the profile and the selection variable are read earlier.
//! A build without the `mainnet-write` feature refuses every mainnet run with
//! that code. With the feature, the run takes the stored profile of an
//! explicit `--profile` selection, a verified signed policy with a
//! `[mainnet]` table and its enablement, the enrolled signer, the independent
//! witness the effective witness rule requires, and browser consent with an
//! owner-pinned passkey. The seed is read and the Ledger opened only after
//! the authorization is minted, and the submit layer checks the endpoint and
//! passphrase again.
//!
//! # Endpoint identity
//!
//! A stage that reads from the endpoint builds one client and asks the
//! endpoint which network it serves before its first read. Every later read
//! and the send use that same client. The full pipeline and `--build-only`
//! check after the balance id and the source parse, before the entry read.
//! `--submit-only` checks before the reservation reconcile. `--sign-only`
//! checks before the account read of an envelope it can decode, and signs an
//! envelope it cannot decode without any request. A refusal there carries no
//! preview. The submit layer checks the sending client again before the send.
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
//! # Fee cap and cross-check witness
//!
//! After the policy gate, every stage checks the per-operation fee against
//! the profile's `classic_max_fee_per_op_stroops`: the selected fee in the
//! full pipeline and `--build-only`, the decoded envelope fee in
//! `--sign-only` and `--submit-only`. A mainnet profile without the cap
//! refuses. The signing and submitting stages then obtain the cross-check
//! witness, unvalued because a claim credits the source: the full pipeline
//! compares the source account, the claimable-balance record as a whole, and
//! the trustline of an issued asset; the staged stages compare the source
//! account they re-read. Both checks refuse before the audit pre-flight, the
//! signer, and the send; the outcome is the result's `cross_check` field and
//! travels into the pending and submitted audit rows. `--build-only` obtains
//! no witness.
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
    AuthError, FeeSource, InternalError, LedgerError, ValidationError, WalletError,
};
use stellar_agent_network::mainnet::MainnetConsumer;
use stellar_agent_network::{MainnetEndpointFlags, NetworkContext};

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
use stellar_agent_network::cross_check::{
    AccountObservation, ClaimWitnessInputs, ClaimableBalanceObservation, CrossCheckOutcome,
    CrossCheckView, TrustlineObservation, obtain_classic_witness, obtain_classic_witness_bound,
};
use stellar_agent_network::fees::{check_classic_fee_cap_signed, classic_fee_source};
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_network::{
    BASE_RESERVE_STROOPS, CLASSIC_SINGLE_OPERATION_COUNT, ClassicFeeChoice, ClassicFeeSelection,
    StellarRpcClient, SubmissionResult, SubmissionSignerKind, check_built_fee_cap,
    check_classic_fee_cap, fetch_account, init_platform_keyring_store, parse_classic_fee_choice,
    resolve_classic_fee_selection, submit_transaction_and_wait,
};

use crate::commands::policy_engine::{
    build_v1_policy_engine, claim_policy_args, effective_classic_fee_cap, envelope_total_fee,
    evaluate_mainnet_policy, evaluate_opaque_signing_policy, evaluate_value_moving_policy,
    load_mainnet_policy_engine, with_total_fee,
};
use crate::common::mainnet_write::{
    MainnetWriteRequest, authorize_and_submit, mainnet_context, mainnet_profiles_dir,
    require_v1_engine,
};
use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, check_endpoint_identity, mainnet_mode_refusal,
    network_context_for_command,
};
use crate::common::profile_access::{
    ProfileOrigin, injected_profile_load, load_profile_or_synthesize_testnet_with,
};
use crate::common::render::{
    WithPreview, exit_code_after_output, sanitize_for_table, with_preview_detail, write_envelope,
};
use crate::common::signer_ceremony::{
    MainnetSignerChoice, SignerCeremonyOutcome, require_enrolled_signer,
    resolve_software_signer_from_env,
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

    /// Outcome of the cross-check witness a signing or submitting stage
    /// obtained before it signed or sent.
    ///
    /// Absent for `--build-only`, which neither signs nor sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_check: Option<CrossCheckView>,
}

/// The unsigned envelope plus the metadata produced by the build stage.
#[derive(Debug, Clone)]
struct BuiltClaimEnvelope {
    envelope_xdr: String,
    balance_id_hex72: String,
    /// The balance id the envelope claims.
    id: BalanceId,
    /// The resolved per-operation fee the envelope pays.
    fee_selection: ClassicFeeSelection,
    /// The parsed `--fee` choice the selection came from; it names the fee's
    /// source in a fee-cap refusal.
    fee_choice: ClassicFeeChoice,
    /// The claimable-balance record the preview and the guards read; the
    /// witness compares it whole.
    record: stellar_xdr::ClaimableBalanceEntry,
    /// The raw trustline entry the trustline guard read for an issued
    /// asset; `None` for a native balance or an absent trustline.
    trustline: Option<stellar_xdr::TrustLineEntry>,
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

    /// Timeout in seconds for the endpoint check and, separately, for the
    /// submission. Default: 60.
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

/// Resolves the profile and the network context, refuses the staged modes on
/// mainnet, and runs the selected stage; full mode on mainnet runs the
/// authorized mainnet pipeline.
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
    claim_outcome_loaded(args, &resolved, &profile, origin, init_keyring).await
}

/// Runs the command on a loaded profile: the network context, the refusal of
/// the staged modes on mainnet, the authorized mainnet dispatch of full mode,
/// and the stage dispatch.
async fn claim_outcome_loaded<InitKeyring>(
    args: &ClaimArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> ClaimOutcome
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let context = match network_context_for_command(
        profile,
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

    // ── Mainnet: the staged modes are refused, full mode runs its own pipeline ─
    // The mode check is pure, so a refused stage reads no file, keyring entry
    // or environment variable.
    let full_mode = !args.build_only && args.sign_only.is_none() && args.submit_only.is_none();
    if let Some(err) = mainnet_mode_refusal(context.chain_id, full_mode) {
        return ClaimOutcome::failed(Envelope::<()>::err(&err));
    }
    if context.chain_id.is_mainnet() {
        return run_mainnet_pipeline(args, resolved, profile, init_keyring).await;
    }

    // Every gated stage reads the owner key from the keyring through
    // `build_v1_policy_engine` when the resolved profile is V1, including
    // `--sign-only` and `--submit-only`, which gate the decoded envelope before
    // signing or broadcasting. All four stages therefore receive the loaded
    // profile and the keyring initialiser.
    if args.build_only {
        run_build_only(&context, args, resolved, profile, init_keyring).await
    } else if let Some(ref xdr) = args.sign_only {
        run_sign_only(&context, args, resolved, xdr, profile, origin, init_keyring).await
    } else if let Some(ref xdr) = args.submit_only {
        run_submit_only(&context, args, resolved, xdr, profile, origin, init_keyring).await
    } else {
        run_full_pipeline(&context, args, resolved, profile, origin, init_keyring).await
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

    // The balance id and the source need no request, so they are checked
    // before the client is built.
    let id = match claim_inputs(args) {
        Ok(id) => id,
        Err(error) => return ClaimOutcome::failed(claim_error_envelope(&error)),
    };
    let client = match context.primary_client() {
        Ok(client) => client,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };
    let built = match build_unsigned_envelope(&client, context, args, id).await {
        Ok(built) => built,
        Err(failure) => return ClaimOutcome::from_build_failure(failure),
    };
    let chain_id = context.chain_id.caip2_str();
    let total_fee = match envelope_total_fee(&built.envelope_xdr) {
        Ok(fee) => fee,
        Err(e) => {
            return ClaimOutcome::failed_after_preview(built.preview, Envelope::<()>::err(&e));
        }
    };
    // Build-only: gate but do not submit, so the gate-sized effects are
    // not recorded (no confirmed on-chain action to attest).
    if let Err(envelope) =
        evaluate_claim_policy(&built, chain_id, profile, &resolved.name, total_fee)
    {
        return ClaimOutcome::failed_after_preview(built.preview, envelope);
    }
    if let Err(e) = check_built_fee_cap(
        built.fee_selection.per_op_stroops,
        built.fee_choice,
        profile,
    ) {
        return ClaimOutcome::failed_after_preview(built.preview, Envelope::<()>::err(&e));
    }
    ClaimOutcome::succeeded(
        Some(built.preview),
        ClaimResult {
            envelope_xdr: built.envelope_xdr,
            tx_hash: None,
            ledger: None,
            stage: "build".to_owned(),
            balance_id_hex72: Some(built.balance_id_hex72),
            cross_check: None,
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
    let gate = match evaluate_staged_claim_policy(
        None,
        context,
        args,
        unsigned_xdr,
        profile,
        &resolved.name,
    )
    .await
    {
        Ok(gate) => gate,
        Err(envelope) => return ClaimOutcome::failed(envelope),
    };
    // A decoded claim's fee is checked against the cap and the oracle
    // re-reads the source the gate read, before the audit pre-flight and the
    // signer. An opaque envelope reads nothing and has no witness.
    let cross_check = match &gate.claim {
        Some(claim) => {
            match witness_staged_claim(context, profile, claim, "stellar_claim_commit").await {
                Ok(outcome) => Some(outcome),
                Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
            }
        }
        None => None,
    };
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
                cross_check: cross_check.as_ref().map(CrossCheckOutcome::view),
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
    // else runs, on the client that reconciles, reads the gate's account
    // view, and sends. The staged gate evaluates under the chain id derived
    // from `--network`, so that flag has to describe the endpoint the
    // envelope will reach. The check makes it so, and a mismatch refuses here
    // rather than after a policy decision taken for the wrong chain.
    let client = match checked_client(context, args).await {
        Ok(client) => client,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };

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
    crate::commands::submission_record::reconcile_open_reservations(
        profile,
        &resolved.name,
        origin,
        &client,
        crate::commands::submission_record::settlement_oracle(profile).as_ref(),
        now_ms,
    )
    .await;

    let chain_id = context.chain_id.caip2_str();
    // The envelope arrives pre-signed, but broadcasting it still spends
    // funds — gate here even though signing already happened elsewhere.
    let gate = match evaluate_staged_claim_policy(
        Some(&client),
        context,
        args,
        signed_xdr,
        profile,
        &resolved.name,
    )
    .await
    {
        Ok(gate) => gate,
        Err(envelope) => return ClaimOutcome::failed(envelope),
    };
    let claim_effects = gate.effects;
    // A decoded claim's fee is checked against the cap and the oracle
    // re-reads the source the gate read, before the audit pre-flight and the
    // send.
    let cross_check = match &gate.claim {
        Some(claim) => {
            match witness_staged_claim(context, profile, claim, "stellar_claim_commit").await {
                Ok(outcome) => Some(outcome),
                Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
            }
        }
        None => None,
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
        Ok(r) => r.with_witness(cross_check.as_ref().and_then(CrossCheckOutcome::witness)),
        Err(e) => {
            return ClaimOutcome::failed(crate::commands::submission_record::error_envelope(
                &e, signed_xdr, "claim",
            ));
        }
    };

    match submit_envelope(&client, context, args, signed_xdr, Some(&recorder)).await {
        Ok((signed_xdr, sub_result)) => ClaimOutcome::succeeded(
            None,
            ClaimResult {
                envelope_xdr: signed_xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "submit".to_owned(),
                balance_id_hex72: None,
                cross_check: cross_check.as_ref().map(CrossCheckOutcome::view),
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
/// `sending_client` is the checked client `--submit-only` sends through, and
/// the view is read on it. `--sign-only` passes `None`: it builds a client and
/// checks its endpoint only when the envelope decodes, so an envelope the
/// decoder cannot classify reaches the opaque-signing posture without any
/// request.
///
/// # Errors
///
/// Returns the refusal envelope when the engine cannot be built, the endpoint
/// check refuses, the source account cannot be fetched, or the gate refuses.
/// On allow, the gate carries the gate-sized effects and, for an envelope the
/// decoder classifies, the decoded fee and the source view it read.
async fn evaluate_staged_claim_policy(
    sending_client: Option<&StellarRpcClient>,
    context: &NetworkContext,
    args: &ClaimArgs,
    envelope_xdr: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<StagedClaimGate, Envelope<()>> {
    let chain_id = context.chain_id.caip2_str();
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
        let checked;
        let client = match sending_client {
            Some(client) => client,
            None => {
                checked = checked_client(context, args)
                    .await
                    .map_err(|e| Envelope::<()>::err(&e))?;
                &checked
            }
        };
        let source = authoritative_args
            .get("source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        source_view_holder = Some(
            fetch_account(client, source, &[])
                .await
                .map_err(|e| Envelope::<()>::err(&e))?,
        );
    }
    let source_adapter = source_view_holder
        .as_ref()
        .map(stellar_agent_network::policy_view::AccountViewAdapter::new);

    let total_fee_stroops = decode_result
        .as_ref()
        .ok()
        .and_then(|decoded| decoded.get("total_fee_stroops"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|fee| u32::try_from(fee).ok());
    let effects = dispatch_staged_claim_gate(
        policy_engine.as_ref(),
        profile,
        chain_id,
        decode_result,
        source_adapter
            .as_ref()
            .map(|a| a as &dyn AccountReservesView),
    )?;
    let claim = match (source_view_holder, total_fee_stroops) {
        (Some(source_view), Some(total_fee_stroops)) => Some(StagedClaim {
            source_view,
            total_fee_stroops,
        }),
        (Some(_), None) => {
            return Err(Envelope::<()>::err(&WalletError::Protocol(
                stellar_agent_core::error::ProtocolError::XdrCodecFailed {
                    detail: "the decoded claim carries no total_fee_stroops".to_owned(),
                },
            )));
        }
        (None, _) => None,
    };
    Ok(StagedClaimGate { effects, claim })
}

/// The staged claim gate's decision and what it read.
struct StagedClaimGate {
    /// The gate-sized effects (`None` for the no-op engine or an opaque allow).
    effects: Option<stellar_agent_core::policy::v1::ValueEffects>,
    /// The decoded claim and the source view; `None` for an opaque envelope,
    /// which the gate reads nothing for.
    claim: Option<StagedClaim>,
}

/// A decoded staged claim and the source view the gate evaluated.
///
/// The staged stages re-read only the source: the record and the trustline
/// are checked by the chain at apply time.
struct StagedClaim {
    /// The source account view (decoded G account).
    source_view: stellar_agent_network::AccountView,
    /// The decoded transaction fee in stroops.
    total_fee_stroops: u32,
}

/// Obtains the cross-check witness of a built claim: the source, the record
/// the preview and the guards read (compared whole), and, for an issued
/// asset, the source's trustline the trustline guard read.
///
/// A claim moves no value from the source, so the witness is unvalued.
///
/// # Errors
///
/// Returns `validation.asset_invalid` for a record asset outside the
/// canonical classic alphabet, the observation build failure, and every
/// refusal of [`obtain_classic_witness`].
async fn witness_built_claim(
    context: &NetworkContext,
    profile: &Profile,
    built: &BuiltClaimEnvelope,
    tool: &'static str,
) -> Result<CrossCheckOutcome, WalletError> {
    obtain_classic_witness(
        profile,
        context,
        stellar_agent_core::cross_check::CrossCheckValue::Unvalued,
        claim_witness_inputs(built)?,
        tool,
    )
    .await
}

/// The observations a built claim's witness compares: the source, the
/// trustline of an issued balance, and the balance record.
///
/// # Errors
///
/// Returns `validation.asset_invalid` for a balance asset outside the
/// canonical classic alphabet, and the observation build failure.
fn claim_witness_inputs(built: &BuiltClaimEnvelope) -> Result<ClaimWitnessInputs, WalletError> {
    let source = AccountObservation::from_view(&built.account_view)?;
    let trustline = match (&built.preview.asset_code, &built.preview.asset_issuer) {
        (Some(code), Some(issuer)) => {
            let asset = stellar_agent_network::Asset::Credit {
                code: code.clone(),
                issuer: issuer.clone(),
            }
            .to_canonical()?;
            Some(TrustlineObservation::from_entry(
                &built.account_view.account_id,
                asset,
                built.trustline.as_ref(),
            )?)
        }
        _ => None,
    };
    Ok(ClaimWitnessInputs {
        source,
        trustline,
        balance: Some(ClaimableBalanceObservation {
            balance_id: built.id.hash(),
            entry: Some(built.record.clone()),
        }),
    })
}

/// Checks a staged claim's fee against the cap and obtains the witness of
/// the source the gate read.
///
/// # Errors
///
/// Returns the fee-cap refusal, the observation build failure, and the
/// refusals of [`obtain_classic_witness`].
async fn witness_staged_claim(
    context: &NetworkContext,
    profile: &Profile,
    claim: &StagedClaim,
    tool: &'static str,
) -> Result<CrossCheckOutcome, WalletError> {
    check_classic_fee_cap(
        claim.total_fee_stroops / CLASSIC_SINGLE_OPERATION_COUNT,
        stellar_agent_core::error::FeeSource::Envelope,
        profile,
    )?;
    obtain_classic_witness(
        profile,
        context,
        stellar_agent_core::cross_check::CrossCheckValue::Unvalued,
        ClaimWitnessInputs {
            source: AccountObservation::from_view(&claim.source_view)?,
            trustline: None,
            balance: None,
        },
        tool,
    )
    .await
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

    // The balance id and the source need no request, so they are checked
    // before the client is built. One client then carries the endpoint
    // check, the build reads, the reconcile, and the send.
    let id = match claim_inputs(args) {
        Ok(id) => id,
        Err(error) => return ClaimOutcome::failed(claim_error_envelope(&error)),
    };
    let client = match context.primary_client() {
        Ok(client) => client,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };

    // 1. Build (endpoint check, fetch entry, preview, guards).
    let built = match build_unsigned_envelope(&client, context, args, id).await {
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
    crate::commands::submission_record::reconcile_open_reservations(
        profile,
        &resolved.name,
        origin,
        &client,
        crate::commands::submission_record::settlement_oracle(profile).as_ref(),
        now_ms,
    )
    .await;

    // ── Operator policy evaluation (before signing) ───────────────────────────
    let chain_id = context.chain_id.caip2_str();
    let total_fee = match envelope_total_fee(&built.envelope_xdr) {
        Ok(fee) => fee,
        Err(e) => return failed(Envelope::<()>::err(&e)),
    };
    let claim_effects =
        match evaluate_claim_policy(&built, chain_id, profile, &resolved.name, total_fee) {
            Ok(effects) => effects,
            Err(envelope) => return failed(envelope),
        };

    // The fee is checked against the profile cap, then the oracle re-reads
    // the record, the source, and the trustline the decision used. Both
    // refuse before the audit pre-flight, the signer, and the send.
    if let Err(e) = check_built_fee_cap(
        built.fee_selection.per_op_stroops,
        built.fee_choice,
        profile,
    ) {
        return failed(Envelope::<()>::err(&e));
    }
    let cross_check = match witness_built_claim(context, profile, &built, "stellar_claim").await {
        Ok(outcome) => outcome,
        Err(e) => return failed(Envelope::<()>::err(&e)),
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
        Ok(r) => r.with_witness(cross_check.witness()),
        Err(e) => {
            return failed(crate::commands::submission_record::error_envelope(
                &e,
                &signed_xdr,
                "claim",
            ));
        }
    };

    match submit_envelope(&client, context, args, &signed_xdr, Some(&recorder)).await {
        Ok((xdr, sub_result)) => ClaimOutcome::succeeded(
            Some(built.preview),
            ClaimResult {
                envelope_xdr: xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "build+sign+submit".to_owned(),
                balance_id_hex72: Some(built.balance_id_hex72),
                cross_check: Some(cross_check.view()),
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
/// `id` is the balance id [`claim_inputs`] parsed. Every read goes through
/// `client`, whose endpoint [`fetch_claim_preview`] checks before the first
/// of them.
///
/// # Errors
///
/// Returns a [`ClaimBuildFailure`] carrying the preview when the failure
/// followed it, and no preview when the endpoint check, the entry fetch, or
/// the preview itself failed.
async fn build_unsigned_envelope(
    client: &StellarRpcClient,
    context: &NetworkContext,
    args: &ClaimArgs,
    id: BalanceId,
) -> Result<BuiltClaimEnvelope, ClaimBuildFailure> {
    let previewed = fetch_claim_preview(client, context, args, id)
        .await
        .map_err(|error| ClaimBuildFailure {
            error,
            preview: None,
        })?;
    match guard_and_build(client, context, args, &previewed).await {
        Ok(guarded) => Ok(BuiltClaimEnvelope {
            envelope_xdr: guarded.envelope_xdr,
            balance_id_hex72: previewed.id.to_hex72(),
            id: previewed.id,
            fee_selection: guarded.fee_selection,
            fee_choice: guarded.fee_choice,
            record: previewed.record,
            trustline: guarded.trustline,
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
    account_view: stellar_agent_network::AccountView,
    preview: ClaimPreview,
    /// The claimable-balance record the preview was built from.
    record: stellar_xdr::ClaimableBalanceEntry,
}

/// Parses the balance id and validates the source G-strkey: the claim
/// arguments that need no request.
///
/// A stage runs this before it builds its client, so an invalid argument
/// refuses on its own code whatever the endpoint URL holds.
///
/// # Errors
///
/// Returns the balance-id parse refusal, or `validation.address_invalid`
/// when the source is not a G-strkey.
fn claim_inputs(args: &ClaimArgs) -> Result<BalanceId, ClaimError> {
    let id = BalanceId::parse(&args.balance_id)?;
    stellar_strkey::ed25519::PublicKey::from_string(&args.source).map_err(|_| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: args.source.clone(),
        })
    })?;
    Ok(id)
}

/// Checks the endpoint of `client`, fetches the entry of the balance `id` and
/// the source account, and builds the typed preview.
///
/// The endpoint check gets a fresh budget of `--timeout-seconds`.
async fn fetch_claim_preview(
    client: &StellarRpcClient,
    context: &NetworkContext,
    args: &ClaimArgs,
    id: BalanceId,
) -> Result<PreviewedClaim, ClaimError> {
    check_endpoint_identity(client, context, Duration::from_secs(args.timeout_seconds)).await?;

    let entry = fetch_claimable_balance_entry(client, &id).await?;

    // Fetch the source account for the sequence number and native balance.
    // Empty trustline-request slice: the trustline guard fetch (below) is a
    // separate call keyed on the balance's own asset.
    let account_view = fetch_account(client, &args.source, &[]).await?;

    let now_secs = current_unix_secs()?;
    let preview = ClaimPreview::build(&entry, &args.source, now_secs)?;
    Ok(PreviewedClaim {
        id,
        account_view,
        preview,
        record: entry,
    })
}

/// What the guards read and the build produced.
struct GuardedClaim {
    envelope_xdr: String,
    fee_selection: ClassicFeeSelection,
    fee_choice: ClassicFeeChoice,
    /// The raw trustline entry the trustline guard read; `None` for a native
    /// balance or an absent trustline.
    trustline: Option<stellar_xdr::TrustLineEntry>,
}

/// Runs the claim guards against the preview, resolves the fee, checks its
/// affordability, and builds the unsigned envelope.
async fn guard_and_build(
    client: &StellarRpcClient,
    context: &NetworkContext,
    args: &ClaimArgs,
    previewed: &PreviewedClaim,
) -> Result<GuardedClaim, ClaimError> {
    let PreviewedClaim {
        id,
        account_view,
        preview,
        ..
    } = previewed;

    // ── Claim guards, in order ────────────────────────────────────────────────
    require_claimant(preview, &args.source)?;
    require_predicate_satisfied(preview)?;
    let mut trustline = None;
    if preview.asset_code.is_some() {
        let code = preview.asset_code.as_deref().unwrap_or_default();
        let issuer = preview.asset_issuer.as_deref().unwrap_or_default();
        let (state, entry) = fetch_trustline_state(client, &args.source, code, issuer).await?;
        check_trustline(
            &state,
            preview.asset_code.as_deref(),
            preview.asset_issuer.as_deref(),
            preview.amount_stroops,
        )?;
        trustline = entry;
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

    Ok(GuardedClaim {
        envelope_xdr,
        fee_selection,
        fee_choice,
        trustline,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator policy gate
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluates operator policy for the built claim, using the same engine path
/// (and `stellar_claim` value descriptor contract) the `stellar_claim` MCP
/// tool's dispatch gate uses.
///
/// Returns the gate-sized effects when the operation is allowed.
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
    total_fee: u32,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, Envelope<()>> {
    let policy_engine =
        build_v1_policy_engine("claim", &profile.policy.engine, profile, profile_name)
            .map_err(|msg| Envelope::<()>::err_raw("policy.engine_unavailable", msg))?;
    // `derive_value_class` ignores args for `stellar_claim` (a non-debit
    // Claim leg is always emitted); `balance_id` is carried for audit parity
    // with the MCP tool's dispatch args and for any future criterion that
    // reads it. The args also carry the built envelope's total fee, which
    // `minimum_reserve` counts: both `--build-only` and the full pipeline
    // gate the envelope they built, so the reserve check sees what that
    // envelope spends once signed.
    let policy_args = with_total_fee(claim_policy_args(&built.balance_id_hex72), total_fee);
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

/// Builds the client a staged stage reads and sends through, and checks that
/// its endpoint serves the network of `context`, under a fresh budget of
/// `--timeout-seconds`.
///
/// # Errors
///
/// Returns the construction failure or the refusal of
/// [`check_endpoint_identity`].
async fn checked_client(
    context: &NetworkContext,
    args: &ClaimArgs,
) -> Result<StellarRpcClient, WalletError> {
    let client = context.primary_client()?;
    check_endpoint_identity(&client, context, Duration::from_secs(args.timeout_seconds)).await?;
    Ok(client)
}

/// Submits `signed_xdr` through `client`, the client the stage checked and
/// read through, under a fresh budget of `--timeout-seconds`.
async fn submit_envelope(
    client: &StellarRpcClient,
    context: &NetworkContext,
    args: &ClaimArgs,
    signed_xdr: &str,
    recorder: Option<&dyn stellar_agent_network::SubmissionRecorder>,
) -> Result<(String, SubmissionResult), WalletError> {
    let timeout = Duration::from_secs(args.timeout_seconds);
    let passphrase = context.network_passphrase();
    let result = submit_transaction_and_wait(
        client,
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
                lines.extend(result.cross_check.as_ref().map(CrossCheckView::text_line));
            }
            _ => {
                let prefix: String = result.envelope_xdr.chars().take(32).collect();
                lines.push(format!(
                    "[{}] envelope_xdr (first 32 chars): {}...",
                    result.stage, prefix
                ));
                lines.extend(result.cross_check.as_ref().map(CrossCheckView::text_line));
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
// Mainnet pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the full pipeline on a mainnet profile.
///
/// The stored profile of the explicit selection replaces the merged one at
/// the write context, and every later step reads it from the context. The
/// claim builds before its reconcile, as on testnet, with the context's
/// primary client; the probe runs inside the build. The verified policy with
/// the built fee, the signed fee cap, the audit pre-flight and the bound
/// witness follow, and [`authorize_and_submit`] runs the rest.
async fn run_mainnet_pipeline<InitKeyring>(
    args: &ClaimArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    init_keyring: InitKeyring,
) -> ClaimOutcome
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let context = match mainnet_context(
        profile,
        resolved,
        MainnetEndpointFlags {
            network: args.network.map(TargetNetwork::caip2),
            rpc_url: args.rpc_url.is_some(),
            secondary_rpc_url: false,
        },
    ) {
        Ok(context) => context,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };
    let net_context = context.network_context();
    let profile = context.profile();
    let name = context.profile_name();
    if let Err(envelope) = require_v1_engine("claim", &context) {
        return ClaimOutcome::failed(envelope);
    }
    if let Err(e) = init_keyring() {
        return ClaimOutcome::failed(Envelope::<()>::err(&e));
    }
    let profiles_dir = match mainnet_profiles_dir() {
        Ok(dir) => dir,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };

    let id = match claim_inputs(args) {
        Ok(id) => id,
        Err(error) => return ClaimOutcome::failed(claim_error_envelope(&error)),
    };
    // One client serves every read, the resolver and the send.
    let client = match context.primary_client() {
        Ok(client) => client,
        Err(e) => return ClaimOutcome::failed(Envelope::<()>::err(&e)),
    };
    let built = match build_unsigned_envelope(&client, &net_context, args, id).await {
        Ok(built) => built,
        Err(failure) => return ClaimOutcome::from_build_failure(failure),
    };
    let preview = built.preview.clone();
    let failed = |envelope: Envelope<()>| ClaimOutcome::failed_after_preview(preview, envelope);

    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            return failed(Envelope::<()>::err_raw("wallet.clock_error", e.to_string()));
        }
    };
    crate::commands::submission_record::reconcile_open_reservations(
        profile,
        name,
        ProfileOrigin::Persisted,
        &client,
        crate::commands::submission_record::settlement_oracle_in(profile, &net_context).as_ref(),
        now_ms,
    )
    .await;

    let policy = match load_mainnet_policy_engine(
        "claim",
        "policy.engine_unavailable",
        &context,
        resolved.source,
        &profiles_dir,
    ) {
        Ok(policy) => policy,
        Err(envelope) => return failed(envelope),
    };
    let total_fee = match envelope_total_fee(&built.envelope_xdr) {
        Ok(fee) => fee,
        Err(e) => return failed(Envelope::<()>::err(&e)),
    };
    let policy_args = with_total_fee(claim_policy_args(&built.balance_id_hex72), total_fee);
    let source_adapter =
        stellar_agent_network::policy_view::AccountViewAdapter::new(&built.account_view);
    let evaluation = match evaluate_mainnet_policy(
        policy.engine.as_ref(),
        profile,
        "stellar_claim",
        stellar_agent_core::policy::ToolValueKind::MovesValue,
        context.chain().caip2_str(),
        &policy_args,
        "claim",
        Some(&source_adapter),
        None,
    ) {
        Ok(evaluation) => evaluation,
        Err(envelope) => return failed(envelope),
    };

    let body = &policy.body;
    if let Err(e) = check_classic_fee_cap_signed(
        built.fee_selection.per_op_stroops,
        classic_fee_source(built.fee_choice, FeeSource::CommandDefault),
        profile,
        Some(body.classic_max_fee_per_op_stroops),
    ) {
        return failed(Envelope::<()>::err(&e));
    }
    let effective_cap = effective_classic_fee_cap(profile, body.classic_max_fee_per_op_stroops);
    if let Err(e) = crate::commands::value_audit::require_value_audit_writer_for_origin(
        profile,
        name,
        ProfileOrigin::Persisted,
    ) {
        return failed(Envelope::<()>::err(&e));
    }
    let thresholds = stellar_agent_core::cross_check::ThresholdSet::from_profile_and_signed(
        profile,
        body.cross_check_thresholds.as_ref(),
    );
    let inputs = match claim_witness_inputs(&built) {
        Ok(inputs) => inputs,
        Err(e) => return failed(Envelope::<()>::err(&e)),
    };
    let cross_check = match obtain_classic_witness_bound(
        profile,
        &net_context,
        stellar_agent_core::cross_check::CrossCheckValue::Unvalued,
        inputs,
        &built.envelope_xdr,
        &thresholds,
        "stellar_claim",
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => return failed(Envelope::<()>::err(&e)),
    };

    let signer = match MainnetSignerChoice::from_flags(
        args.sign_with_ledger,
        args.account_index,
        args.secret_env.as_deref(),
        "claim-commit",
    ) {
        Ok(signer) => signer,
        Err(e) => return failed(Envelope::<()>::err(&e)),
    };
    let timeout = Duration::from_secs(args.timeout_seconds);
    match authorize_and_submit(MainnetWriteRequest {
        context: &context,
        profiles_dir: &profiles_dir,
        verb: "claim",
        tool: "stellar_claim",
        consumer: MainnetConsumer::CliClaim,
        unsigned_xdr: &built.envelope_xdr,
        client: &client,
        probe_deadline: timeout,
        submit_timeout: timeout,
        source: &args.source,
        signer,
        policy: &policy,
        evaluation: &evaluation,
        effective_cap,
        witness: cross_check.witness(),
    })
    .await
    {
        Ok(submitted) => ClaimOutcome::succeeded(
            Some(built.preview),
            ClaimResult {
                envelope_xdr: submitted.signed_xdr,
                tx_hash: Some(submitted.result.tx_hash.clone()),
                ledger: Some(submitted.result.ledger),
                stage: "build+sign+submit".to_owned(),
                balance_id_hex72: Some(built.balance_id_hex72),
                cross_check: Some(cross_check.view()),
            },
        ),
        Err(envelope) => failed(envelope),
    }
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
        EnrolledPin, assert_enrolled_mainnet_signing_outcome, enrolled_mainnet_profile,
        enrolled_test_g, enrolled_test_secret,
    };
    use crate::test_rpc::{EnvSigner, absent_profile_file, zero_config};
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

    /// A mainnet profile is refused before the keyring initializer runs and
    /// before any request reaches an endpoint. Without `mainnet-write` the
    /// write context refuses the build; with it, the injected loader's `http`
    /// endpoint differs from the stored profile's `https` one, so the write
    /// context refuses the merged view. Both refuse with
    /// `network.mainnet_write_forbidden`.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn mainnet_rejected_at_run_boundary() {
        let mut output = Vec::new();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let resolutions = crate::common::signer_ceremony::signer_resolutions_on_this_thread();
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
            crate::test_rpc::counting_initializer(&calls),
            &mut output,
        )
        .await;
        assert_eq!(exit, 1, "mainnet must exit with code 1");
        assert_eq!(calls.get(), 0, "the keyring is never initialized");
        assert_eq!(
            crate::common::signer_ceremony::signer_resolutions_on_this_thread(),
            resolutions
        );
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
        let rendered: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(rendered["error"]["code"], "network.mainnet_write_forbidden");
    }

    /// `--network mainnet` against an absent profile, which synthesizes a
    /// testnet profile, refuses as a network-flag mismatch before the keyring
    /// initializer runs and before any request reaches `--rpc-url`. It is the
    /// control for the flag check, which runs before any mainnet step.
    #[tokio::test]
    #[serial_test::serial]
    async fn mainnet_rejected_at_run_boundary_network_flag_without_profile_refuses() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
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
            crate::test_rpc::counting_initializer(&calls),
            &mut std::io::sink(),
        )
        .await;
        assert_eq!(exit, 1, "mainnet must exit with code 1");
        assert_eq!(calls.get(), 0, "the keyring is never initialized");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    /// A staged mode on a mainnet profile refuses before the keyring and
    /// before any request in a build without mainnet writes. `name` is the
    /// fixture profile of a build with mainnet writes; this build refuses
    /// every mainnet profile and uses the guard fixture's.
    #[cfg(not(feature = "mainnet-write"))]
    async fn assert_mode_refused(name: &'static str, stage: impl FnOnce(&mut ClaimArgs)) {
        let _ = name;
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let resolutions = crate::common::signer_ceremony::signer_resolutions_on_this_thread();
        let guard_rpc = wiremock::MockServer::start().await;
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(
                "https://rpc.example.invalid",
            );
        let mut args = minimal_args();
        args.profile = Some("guard-mainnet".to_owned());
        args.network = None;
        args.rpc_url = None;
        args.secret_env = Some("CLAIM_MODE_REFUSAL_SK".to_owned());
        stage(&mut args);
        let mut output = Vec::new();
        let exit = run_with_dependencies(
            &args,
            crate::test_rpc::ImplicitSelection::loader(&guard_rpc.uri()),
            crate::test_rpc::counting_initializer(&calls),
            &mut output,
        )
        .await;
        assert_eq!(exit, 1);
        let rendered = crate::common::render::single_json_document(&output);
        assert_eq!(rendered["error"]["code"], "network.mainnet_write_forbidden");
        assert_eq!(calls.get(), 0, "the keyring is never initialized");
        assert!(guard_rpc.received_requests().await.unwrap().is_empty());
        assert_eq!(
            crate::common::signer_ceremony::signer_resolutions_on_this_thread(),
            resolutions
        );
    }

    /// A staged mode on the fixture's mainnet profile, whose every proof is
    /// valid and whose full-mode run would submit, refuses before the keyring
    /// and before any request. `name` is the fixture's profile, unique in
    /// the process because the audit writer registry is process-wide.
    #[cfg(feature = "mainnet-write")]
    async fn assert_mode_refused(name: &'static str, stage: impl FnOnce(&mut ClaimArgs)) {
        let fixture = crate::common::mainnet_write_fixture::Spec::new(name)
            .build()
            .await;
        let resolutions = crate::common::signer_ceremony::signer_resolutions_on_this_thread();
        let mut args = mainnet_full::mainnet_args(&fixture);
        stage(&mut args);
        let mut output = Vec::new();
        let exit =
            run_with_dependencies(&args, fixture.loader(), fixture.initializer(), &mut output)
                .await;
        let rendered = crate::common::render::single_json_document(&output);
        assert_eq!(exit, 1, "{rendered}");
        assert_eq!(
            rendered["error"]["code"], "network.mainnet_write_forbidden",
            "{rendered}"
        );
        assert_eq!(
            fixture.initializer_calls(),
            0,
            "the keyring is never initialized"
        );
        assert!(fixture.primary_methods().await.is_empty());
        assert!(fixture.oracle_methods().await.is_empty());
        assert_eq!(
            crate::common::signer_ceremony::signer_resolutions_on_this_thread(),
            resolutions
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn build_only_is_refused_on_mainnet() {
        assert_mode_refused("mainnet-claim-build-only", |args| args.build_only = true).await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn sign_only_is_refused_on_mainnet() {
        let envelope =
            stellar_agent_test_support::signed_envelope::SignedTestEnvelope::builder([0x61; 32])
                .claim_claimable_balance([0xab; 32])
                .unsigned()
                .build();
        assert_mode_refused("mainnet-claim-sign-only", |args| {
            args.sign_only = Some(envelope.envelope_xdr().to_owned())
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn submit_only_is_refused_on_mainnet() {
        let envelope =
            stellar_agent_test_support::signed_envelope::SignedTestEnvelope::builder([0x61; 32])
                .claim_claimable_balance([0xab; 32])
                .build();
        assert_mode_refused("mainnet-claim-submit-only", |args| {
            args.submit_only = Some(envelope.envelope_xdr().to_owned())
        })
        .await;
    }

    /// A mainnet profile selected without `--profile` refuses before the
    /// keyring, in both builds.
    async fn assert_implicit_selection_refused(source: crate::test_rpc::ImplicitSource) {
        let selection = crate::test_rpc::ImplicitSelection::new(source);
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let mut args = minimal_args();
        args.profile = None;
        args.network = None;
        args.rpc_url = None;
        args.secret_env = Some("CLAIM_IMPLICIT_SK".to_owned());
        let mut output = Vec::new();
        let exit = run_with_dependencies(
            &args,
            crate::test_rpc::ImplicitSelection::loader("https://rpc.example.invalid"),
            crate::test_rpc::counting_initializer(&calls),
            &mut output,
        )
        .await;
        assert_eq!(exit, 1);
        let rendered = crate::common::render::single_json_document(&output);
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
        // `claim_inputs` refuses on `BalanceId::parse` before any RPC client
        // construction, so this stays network-free.
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
        // The load runs the key-scope check, which lists the profiles
        // directory; keep that read inside a temporary data root.
        let home = tempfile::tempdir().expect("valid test fixture");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
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
        // The load runs the key-scope check, which lists the profiles
        // directory; keep that read inside a temporary data root.
        let home = tempfile::tempdir().expect("valid test fixture");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
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
        // The envelope is only the input to the signing step under test. It is
        // built under a testnet context, which the mock's endpoint check
        // accepts; the transaction bytes carry no network.
        let build_context = NetworkContext::new(
            stellar_agent_core::profile::caip2::Caip2::Testnet,
            server.uri(),
        );
        let client = StellarRpcClient::new(&build_context.rpc_url).expect("mock client");
        let id = claim_inputs(&args).expect("valid claim arguments");
        let built = build_unsigned_envelope(&client, &build_context, &args, id)
            .await
            .expect("build against mock");
        let result =
            sign_envelope(&context, &args, &built.envelope_xdr, &profile, "enrolled").await;
        unsafe {
            std::env::remove_var(var);
        }
        assert_enrolled_mainnet_signing_outcome(pin, result);
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

    /// Returns the ledger key and the entry XDR of an unconditional 10 XLM
    /// native claimable balance with id `CLAIM_RPC_BALANCE_HEX64`, whose one
    /// claimant is `claimant`.
    fn claimable_entry_for(claimant: &str) -> (String, String) {
        claimable_entry_with(claimant, 100_000_000)
    }

    /// Returns the ledger key and the entry XDR of an unconditional native
    /// claimable balance of `amount` stroops with id
    /// `CLAIM_RPC_BALANCE_HEX64`, whose one claimant is `claimant`.
    fn claimable_entry_with(claimant: &str, amount: i64) -> (String, String) {
        use stellar_xdr::{
            ClaimPredicate, ClaimableBalanceEntry, ClaimableBalanceEntryExt, Claimant, ClaimantV0,
            LedgerEntryData, LedgerKey, LedgerKeyClaimableBalance,
        };
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
            amount,
            ext: ClaimableBalanceEntryExt::V0,
        };
        let claim_xdr = LedgerEntryData::ClaimableBalance(entry)
            .to_xdr_base64(Limits::none())
            .expect("claim XDR");
        (claim_key, claim_xdr)
    }

    /// Starts an RPC mock whose `getLedgerEntries` serves the claimable
    /// balance of [`claimable_entry_for`] and a funded `claimant` account, and
    /// whose `getNetwork` reports testnet. Every other method gets an empty
    /// result.
    async fn mount_claim_rpc(claimant: &str) -> wiremock::MockServer {
        let server = wiremock::MockServer::start().await;
        let (claim_key, claim_xdr) = claimable_entry_for(claimant);
        let account_xdr = enrolled_account_xdr(claimant);
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let value: serde_json::Value =
                    serde_json::from_slice(&request.body).expect("RPC JSON");
                let result = match value["params"]["keys"][0].as_str() {
                    _ if value["method"] == "getNetwork" => {
                        stellar_agent_test_support::signed_envelope::get_network_result(
                            stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                        )
                    }
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
        assert_eq!(
            methods.first().map(String::as_str),
            Some("getNetwork"),
            "the endpoint check precedes every read: {methods:?}"
        );
        assert!(
            methods.len() > 1 && methods[1..].iter().all(|m| m == "getLedgerEntries"),
            "only ledger reads follow the endpoint check, and the fee parse \
             fails before any later request: {methods:?}"
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
                    cross_check: None,
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

    // ── Endpoint identity: one client per stage, checked before its reads ──

    /// An endpoint reporting testnet that answers for `claimant`'s account and
    /// for the claimable balance it may claim.
    fn claim_endpoint(claimant: &str) -> crate::test_rpc::ClassicRpc {
        let (key, entry) = claimable_entry_for(claimant);
        crate::test_rpc::ClassicRpc::testnet(&[claimant]).with_entry(key, entry)
    }

    /// Arguments claiming the balance of [`claimable_entry_for`] as
    /// `claimant` through the endpoint at `rpc_url`.
    fn claim_args(claimant: &EnvSigner, rpc_url: &str) -> ClaimArgs {
        let mut args = minimal_args();
        args.balance_id = CLAIM_RPC_BALANCE_HEX64.to_owned();
        args.source = claimant.g.clone();
        args.secret_env = Some(claimant.var.to_owned());
        args.rpc_url = Some(rpc_url.to_owned());
        args
    }

    /// Runs `args` on the zero-config profile, returning the exit code, the
    /// one envelope printed, and the number of clients the run built.
    async fn run_counted(args: &ClaimArgs) -> (i32, serde_json::Value, usize) {
        let mut out = Vec::new();
        let (code, built) = crate::test_rpc::clients_built_by(run_with_dependencies(
            args,
            absent_profile_file,
            || Ok(()),
            &mut out,
        ))
        .await;
        (
            code,
            crate::common::render::single_json_document(&out),
            built,
        )
    }

    /// The full pipeline builds one client: the endpoint check is its first
    /// request, after the balance id and the source parse, and the build
    /// reads, the reconcile, and the send go through it. The submit layer
    /// checks it again, so two `getNetwork` requests.
    #[tokio::test]
    #[serial_test::serial]
    async fn the_full_pipeline_checks_the_endpoint_first_and_sends_through_one_client() {
        let _zero_config = zero_config();
        let claimant = EnvSigner::new([0x71; 32], "CLAIM_ONE_CLIENT_FULL_SK");
        let server = claim_endpoint(&claimant.g).serve().await;

        let (code, envelope, built) = run_counted(&claim_args(&claimant, &server.uri())).await;
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

    /// `--build-only` builds one client and checks its endpoint once, before
    /// the entry read.
    #[tokio::test]
    #[serial_test::serial]
    async fn build_only_checks_the_endpoint_once_on_its_one_client() {
        let _zero_config = zero_config();
        let claimant = EnvSigner::new([0x72; 32], "CLAIM_ONE_CLIENT_BUILD_SK");
        let server = claim_endpoint(&claimant.g).serve().await;
        let mut args = claim_args(&claimant, &server.uri());
        args.build_only = true;

        let (code, envelope, built) = run_counted(&args).await;
        let methods = crate::test_rpc::methods(&server).await;

        assert_eq!(code, 0, "{envelope}");
        assert_eq!(built, 1);
        assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
        assert_eq!(crate::test_rpc::network_checks(&methods), 1, "{methods:?}");
    }

    /// `--sign-only` with an envelope it decodes builds one client and checks
    /// its endpoint once, before the account read its gate takes.
    #[tokio::test]
    #[serial_test::serial]
    async fn sign_only_of_a_decoded_envelope_checks_the_endpoint_once() {
        let _zero_config = zero_config();
        let claimant = EnvSigner::new([0x73; 32], "CLAIM_ONE_CLIENT_SIGN_SK");
        let server = claim_endpoint(&claimant.g).serve().await;
        let mut args = claim_args(&claimant, &server.uri());
        args.sign_only = Some(build_envelope_b64(
            &claimant.g,
            Operation {
                source_account: None,
                body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                    balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab_u8; 32])),
                }),
            },
        ));

        let (code, envelope, built) = run_counted(&args).await;
        let methods = crate::test_rpc::methods(&server).await;

        assert_eq!(code, 0, "{envelope}");
        assert_eq!(built, 1);
        assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
        assert_eq!(crate::test_rpc::network_checks(&methods), 1, "{methods:?}");
    }

    /// `--sign-only` with an envelope the decoder cannot classify signs it
    /// under the opaque-signing posture without building a client or making
    /// any request.
    #[tokio::test]
    #[serial_test::serial]
    async fn sign_only_of_an_opaque_envelope_makes_no_request() {
        let _zero_config = zero_config();
        let claimant = EnvSigner::new([0x74; 32], "CLAIM_ONE_CLIENT_OPAQUE_SK");
        let server = claim_endpoint(&claimant.g).serve().await;
        let mut args = claim_args(&claimant, &server.uri());
        args.sign_only = Some(build_envelope_b64(
            &claimant.g,
            Operation {
                source_account: None,
                body: OperationBody::CreateAccount(CreateAccountOp {
                    destination: g_to_account_id(ISSUER_G),
                    starting_balance: 10_000_000,
                }),
            },
        ));

        let (code, envelope, built) = run_counted(&args).await;

        assert_eq!(code, 0, "the opaque envelope is signed: {envelope}");
        assert_eq!(
            built, 0,
            "no client for an envelope the gate reads nothing for"
        );
        assert!(
            crate::test_rpc::methods(&server).await.is_empty(),
            "an opaque envelope is signed without any request"
        );
    }

    /// `--submit-only` builds one client: the endpoint check is its first
    /// request and the send goes through it. The submit layer checks it again.
    #[tokio::test]
    #[serial_test::serial]
    async fn submit_only_checks_the_endpoint_first_and_sends_through_one_client() {
        let _zero_config = zero_config();
        let envelope = stellar_agent_test_support::SignedTestEnvelope::builder([0x75; 32])
            .claim_claimable_balance([0xab; 32])
            .build();
        let server = crate::test_rpc::ClassicRpc::testnet(&[envelope.source()])
            .serve()
            .await;
        let mut args = minimal_args();
        args.balance_id = CLAIM_RPC_BALANCE_HEX64.to_owned();
        args.source = envelope.source().to_owned();
        args.rpc_url = Some(server.uri());
        args.submit_only = Some(envelope.envelope_xdr().to_owned());

        let (code, printed, built) = run_counted(&args).await;
        let methods = crate::test_rpc::methods(&server).await;

        assert_eq!(code, 0, "{printed}");
        assert_eq!(built, 1, "one client reads and sends");
        assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
        assert_eq!(crate::test_rpc::network_checks(&methods), 2, "{methods:?}");
        assert!(
            methods.iter().any(|m| m == "sendTransaction"),
            "{methods:?}"
        );
    }

    /// An endpoint serving another network refuses the full pipeline,
    /// `--build-only`, and `--sign-only` of a decoded envelope before any
    /// read, with the mismatch code and no preview.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_endpoint_serving_another_network_is_refused_before_any_read() {
        const FUTURENET: &str = "Test SDF Future Network ; October 2022";
        let _zero_config = zero_config();
        let claimant = EnvSigner::new([0x76; 32], "CLAIM_ENDPOINT_MISMATCH_SK");
        let decoded_claim = build_envelope_b64(
            &claimant.g,
            Operation {
                source_account: None,
                body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                    balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab_u8; 32])),
                }),
            },
        );
        for (stage, fee) in [
            ("full", None),
            ("full", Some("auto")),
            ("build-only", None),
            ("build-only", Some("auto")),
            ("sign-only", None),
        ] {
            let endpoint = claim_endpoint(&claimant.g);
            endpoint.report(FUTURENET);
            let server = endpoint.serve().await;
            let mut args = claim_args(&claimant, &server.uri());
            args.fee = fee.map(str::to_owned);
            match stage {
                "build-only" => args.build_only = true,
                "sign-only" => args.sign_only = Some(decoded_claim.clone()),
                _ => {}
            }

            let (code, envelope, _built) = run_counted(&args).await;

            assert_eq!(code, 1, "{stage} fee {fee:?}: {envelope}");
            assert_eq!(
                envelope["error"]["code"], "network.endpoint_network_mismatch",
                "{stage} fee {fee:?}: {envelope}"
            );
            assert!(
                envelope["error"].get("details").is_none(),
                "{stage} fee {fee:?}: an endpoint refusal carries no preview: {envelope}"
            );
            assert_eq!(
                crate::test_rpc::methods(&server).await,
                ["getNetwork"],
                "{stage} fee {fee:?}: the endpoint check precedes every read"
            );
        }
    }

    /// The full pipeline and `--build-only` check the balance id and the
    /// source before they build their client. The profile's endpoint URL
    /// passes the endpoint rule the loader applies but fails client
    /// construction, so each invalid argument must still end on its own code.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_invalid_claim_argument_refuses_ahead_of_a_client_the_url_cannot_build() {
        const NAME: &str = "claim-unbuildable-url";
        const URL: &str = "http://127.0.0.1:9/a b";
        let dir = tempfile::TempDir::new().expect("tempdir");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
        let profile = Profile::builder_testnet_named(
            NAME,
            "stellar-agent-signer",
            NAME,
            "stellar-agent-nonce",
            NAME,
        )
        .policy_engine(PolicyEngineKind::Noop)
        .rpc_url(URL)
        .build();
        assert!(
            profile.validate_endpoint_urls().is_ok(),
            "the endpoint rule of the profile loader accepts the URL"
        );
        assert!(
            StellarRpcClient::new(URL).is_err(),
            "client construction refuses the URL"
        );
        stellar_agent_core::profile::loader::save_to_dir(
            NAME,
            &profile,
            &dir.path().join("profiles"),
        )
        .expect("profile saved");
        let claimant = EnvSigner::new([0x77; 32], "CLAIM_UNBUILDABLE_URL_SK");

        for build_only in [false, true] {
            for (label, balance_id, source, expected) in [
                (
                    "valid arguments",
                    CLAIM_RPC_BALANCE_HEX64,
                    claimant.g.as_str(),
                    "network.rpc_unreachable",
                ),
                (
                    "an invalid balance id",
                    "not-a-balance-id",
                    claimant.g.as_str(),
                    "claim.invalid_balance_id",
                ),
                (
                    "an invalid source",
                    CLAIM_RPC_BALANCE_HEX64,
                    "not-a-g-strkey",
                    "validation.address_invalid",
                ),
            ] {
                let mut args = minimal_args();
                args.profile = Some(NAME.to_owned());
                args.network = None;
                args.rpc_url = None;
                args.balance_id = balance_id.to_owned();
                args.source = source.to_owned();
                args.secret_env = Some(claimant.var.to_owned());
                args.build_only = build_only;
                let mut out = Vec::new();

                let code = run_with_dependencies(
                    &args,
                    crate::common::profile_access::injected_profile_load,
                    || Ok(()),
                    &mut out,
                )
                .await;
                let envelope = crate::common::render::single_json_document(&out);

                assert_eq!(code, 1, "build-only {build_only}, {label}: {envelope}");
                assert_eq!(
                    envelope["error"]["code"], expected,
                    "build-only {build_only}, {label}: {envelope}"
                );
            }
        }
    }

    /// The `cross_check` field is omitted when absent, round-trips when set,
    /// and a result written without the field deserializes to `None`.
    #[test]
    fn claim_result_cross_check_field_shape() {
        let mut result = ClaimResult {
            envelope_xdr: "AAAA".to_owned(),
            tx_hash: Some("ab".repeat(32)),
            ledger: Some(7),
            stage: "build+sign+submit".to_owned(),
            balance_id_hex72: Some("00".repeat(36)),
            cross_check: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("cross_check").is_none(), "{json}");

        result.cross_check = Some(CrossCheckView {
            status: "skipped".to_owned(),
            reason: Some("oracle_not_configured".to_owned()),
            provider: None,
            ledger: None,
        });
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(
            json["cross_check"],
            serde_json::json!({"status": "skipped", "reason": "oracle_not_configured"})
        );
        let back: ClaimResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.cross_check, result.cross_check);

        let legacy = serde_json::json!({
            "envelope_xdr": "AAAA",
            "tx_hash": "ab".repeat(32),
            "ledger": 7,
            "stage": "build+sign+submit",
            "balance_id_hex72": "00".repeat(36)
        });
        let legacy: ClaimResult =
            serde_json::from_value(legacy).expect("a result without cross_check deserializes");
        assert_eq!(legacy.cross_check, None);
    }

    /// The table renderer prints the cross-check line after the result line
    /// when the outcome carries one.
    #[test]
    fn table_output_prints_the_cross_check_line() {
        let outcome = ClaimOutcome::succeeded(
            None,
            ClaimResult {
                envelope_xdr: "AAAA".to_owned(),
                tx_hash: Some("ab".repeat(32)),
                ledger: Some(7),
                stage: "build+sign+submit".to_owned(),
                balance_id_hex72: None,
                cross_check: Some(CrossCheckView {
                    status: "passed".to_owned(),
                    reason: None,
                    provider: Some("https://oracle.example".to_owned()),
                    ledger: Some(1001),
                }),
            },
        );
        let mut out = Vec::new();
        assert_eq!(
            render_claim_outcome(&mut out, OutputFormat::Table, outcome),
            0
        );
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.last().copied(),
            Some("Cross-check: passed (oracle https://oracle.example, ledger 1001)"),
            "{text}"
        );
    }

    /// A sign-stage result prints the cross-check line after the envelope line.
    #[test]
    fn sign_table_output_prints_the_cross_check_line() {
        let outcome = ClaimOutcome::succeeded(
            None,
            ClaimResult {
                envelope_xdr: "AAAA".to_owned(),
                tx_hash: None,
                ledger: None,
                stage: "sign".to_owned(),
                balance_id_hex72: None,
                cross_check: Some(CrossCheckView {
                    status: "passed".to_owned(),
                    reason: None,
                    provider: Some("https://oracle.example".to_owned()),
                    ledger: Some(1001),
                }),
            },
        );
        let mut out = Vec::new();
        assert_eq!(
            render_claim_outcome(&mut out, OutputFormat::Table, outcome),
            0
        );
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.last().copied(),
            Some("Cross-check: passed (oracle https://oracle.example, ledger 1001)"),
            "{text}"
        );
    }

    // ── Cross-check witness ──────────────────────────────────────────────────

    mod witness {
        use super::*;
        use crate::test_rpc::{
            ClassicRpc, account_key, account_xdr, assert_rows_carry_witness, audit_rows, methods,
            profile_name_for, sent, signers_resolved_by, trustline_xdr, witness_profile,
        };
        use stellar_xdr::{
            ClaimClaimableBalanceOp, ClaimPredicate, ClaimableBalanceEntry,
            ClaimableBalanceEntryExt, Claimant, ClaimantV0, LedgerEntryData, LedgerKey,
            LedgerKeyClaimableBalance, MuxedAccountMed25519,
        };

        /// The issuer of the USD balances.
        const ISSUER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

        struct Run {
            code: i32,
            envelope: serde_json::Value,
            signers: usize,
        }

        async fn run_stage(args: &ClaimArgs, profile: &Profile) -> Run {
            let (outcome, signers) = signers_resolved_by(claim_outcome_loaded(
                args,
                &resolve_profile_name(args.profile.as_deref()),
                profile,
                ProfileOrigin::Persisted,
                || Ok(()),
            ))
            .await;
            let mut out = Vec::new();
            let code = render_claim_outcome(&mut out, args.output, outcome);
            Run {
                code,
                envelope: crate::common::render::single_json_document(&out),
                signers,
            }
        }

        async fn assert_refused(run: &Run, code: &str, primary: &wiremock::MockServer) {
            assert_eq!(run.code, 1, "{}", run.envelope);
            assert_eq!(run.envelope["error"]["code"], code, "{}", run.envelope);
            assert_eq!(run.signers, 0, "the refusal precedes the signer");
            assert!(!sent(primary).await, "nothing is sent");
        }

        fn args_for(claimant: &EnvSigner, primary: &wiremock::MockServer) -> ClaimArgs {
            let mut args = claim_args(claimant, &primary.uri());
            args.profile = Some(profile_name_for(claimant));
            args
        }

        fn profile_for(
            claimant: &EnvSigner,
            primary: &wiremock::MockServer,
            oracle: Option<&wiremock::MockServer>,
            audit: &tempfile::TempDir,
        ) -> Profile {
            witness_profile(
                &profile_name_for(claimant),
                &primary.uri(),
                oracle.map(wiremock::MockServer::uri).as_deref(),
                audit.path(),
            )
        }

        /// A claimable balance of `amount` in `asset` with id `0xab..`, whose
        /// one claimant is `claimant`.
        fn record(claimant: &str, asset: stellar_xdr::Asset, amount: i64) -> (String, String) {
            let balance_id = ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32]));
            let key = LedgerKey::ClaimableBalance(LedgerKeyClaimableBalance {
                balance_id: balance_id.clone(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            let entry = LedgerEntryData::ClaimableBalance(ClaimableBalanceEntry {
                balance_id,
                claimants: vec![Claimant::ClaimantTypeV0(ClaimantV0 {
                    destination: g_to_account_id(claimant),
                    predicate: ClaimPredicate::Unconditional,
                })]
                .try_into()
                .unwrap(),
                asset,
                amount,
                ext: ClaimableBalanceEntryExt::V0,
            })
            .to_xdr_base64(Limits::none())
            .unwrap();
            (key, entry)
        }

        fn usd() -> stellar_xdr::Asset {
            stellar_xdr::Asset::CreditAlphanum4(stellar_xdr::AlphaNum4 {
                asset_code: stellar_xdr::AssetCode4(*b"USD\0"),
                issuer: g_to_account_id(ISSUER),
            })
        }

        /// The claimant's account and a native balance of 10 XLM.
        fn native_ledger(claimant: &str, amount: i64) -> ClassicRpc {
            let (key, entry) = record(claimant, stellar_xdr::Asset::Native, amount);
            ClassicRpc::testnet(&[claimant]).with_entry(key, entry)
        }

        /// The claimant's account, a USD balance, and the claimant's USD
        /// trustline with `balance`.
        fn credit_ledger(claimant: &str, trustline_balance: i64) -> ClassicRpc {
            let (key, entry) = record(claimant, usd(), 50_000_000);
            let (tl_key, tl_entry) = trustline_xdr(
                claimant,
                "USD",
                ISSUER,
                trustline_balance,
                10_000_000_000,
                1,
            );
            ClassicRpc::testnet(&[claimant])
                .with_entry(key, entry)
                .with_entry(tl_key, tl_entry)
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_witness_passes_and_rows_carry_it() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa1; 32], "CLAIM_WITNESS_FULL_PASS_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = native_ledger(&claimant.g, 100_000_000).serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);

            let run = run_stage(&args_for(&claimant, &primary), &profile).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            let view = &run.envelope["data"]["cross_check"];
            assert_eq!(view["status"], "passed", "{}", run.envelope);
            assert_eq!(view["provider"], oracle.uri());
            assert_eq!(methods(&oracle).await, ["getNetwork", "getLedgerEntries"]);
            assert_rows_carry_witness(&profile, &oracle.uri());
            let kinds = &audit_rows(&profile, "value_action_submitted")[0]["witness"]["kinds"];
            assert_eq!(
                *kinds,
                serde_json::json!(["source_account", "claimable_balance"])
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_record_disagreement_refuses_before_the_signer() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa2; 32], "CLAIM_WITNESS_FULL_RECORD_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = native_ledger(&claimant.g, 100_000_001).serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);

            let run = run_stage(&args_for(&claimant, &primary), &profile).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
            let message = run.envelope["error"]["message"].as_str().unwrap();
            assert!(message.contains("claimable balance record"), "{message}");
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_trustline_disagreement_refuses_before_the_signer() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa3; 32], "CLAIM_WITNESS_FULL_TRUSTLINE_SK");
            let primary = credit_ledger(&claimant.g, 1_000).serve().await;
            let oracle = credit_ledger(&claimant.g, 1_001).serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);

            let run = run_stage(&args_for(&claimant, &primary), &profile).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
            let message = run.envelope["error"]["message"].as_str().unwrap();
            assert!(message.contains("source trustline balance"), "{message}");
        }

        /// A matching credit claim compares the trustline too.
        #[tokio::test]
        #[serial_test::serial]
        async fn full_credit_witness_covers_the_trustline() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa4; 32], "CLAIM_WITNESS_FULL_CREDIT_SK");
            let primary = credit_ledger(&claimant.g, 1_000).serve().await;
            let oracle = credit_ledger(&claimant.g, 1_000).serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);

            let run = run_stage(&args_for(&claimant, &primary), &profile).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            let kinds = &audit_rows(&profile, "value_action_submitted")[0]["witness"]["kinds"];
            assert_eq!(
                *kinds,
                serde_json::json!(["source_account", "source_trustline", "claimable_balance"])
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_without_oracle_skips_on_testnet() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa5; 32], "CLAIM_WITNESS_FULL_SKIP_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let profile = profile_for(&claimant, &primary, None, &audit);

            let run = run_stage(&args_for(&claimant, &primary), &profile).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(
                run.envelope["data"]["cross_check"],
                serde_json::json!({"status": "skipped", "reason": "oracle_not_configured"})
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_oracle_identity_refusal_is_witness_unavailable() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa6; 32], "CLAIM_WITNESS_FULL_IDENTITY_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle_rpc = native_ledger(&claimant.g, 100_000_000);
            oracle_rpc.report("Test SDF Future Network ; October 2022");
            let oracle = oracle_rpc.serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);

            let run = run_stage(&args_for(&claimant, &primary), &profile).await;

            assert_refused(&run, "network.witness_unavailable", &primary).await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_fee_above_cap_refuses_before_the_witness() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa7; 32], "CLAIM_WITNESS_FULL_CAP_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = native_ledger(&claimant.g, 100_000_000).serve().await;
            let mut profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            profile.classic_max_fee_per_op_stroops = Some(50);

            let run = run_stage(&args_for(&claimant, &primary), &profile).await;

            assert_refused(&run, "fees.percentile_exceeds_cap", &primary).await;
            assert_eq!(
                run.envelope["error"]["message"],
                "the default per-operation fee 100 stroops exceeds the profile cap of 50 \
                 stroops; pass an explicit fee within the cap or raise \
                 classic_max_fee_per_op_stroops"
            );
            assert!(methods(&oracle).await.is_empty());
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn build_only_makes_no_oracle_request() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xa8; 32], "CLAIM_WITNESS_BUILD_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = native_ledger(&claimant.g, 100_000_000).serve().await;
            let mut profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            let mut args = args_for(&claimant, &primary);
            args.build_only = true;

            let run = run_stage(&args, &profile).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert!(
                run.envelope["data"].get("cross_check").is_none(),
                "{}",
                run.envelope
            );
            assert!(methods(&oracle).await.is_empty());

            profile.classic_max_fee_per_op_stroops = Some(50);
            args.fee = Some("auto:p90".to_owned());
            let run = run_stage(&args, &profile).await;
            assert_eq!(run.code, 1, "{}", run.envelope);
            assert_eq!(run.envelope["error"]["code"], "fees.percentile_exceeds_cap");
            assert!(
                run.envelope["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("auto-selected per-operation fee 100 stroops (percentile p90)"),
                "{}",
                run.envelope
            );
            assert!(methods(&oracle).await.is_empty());
        }

        // ── staged ──

        fn claim_envelope(source: MuxedAccount, fee: u32) -> String {
            let tx = Transaction {
                source_account: source,
                fee,
                seq_num: SequenceNumber(101),
                cond: Preconditions::None,
                memo: stellar_xdr::Memo::None,
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::ClaimClaimableBalance(ClaimClaimableBalanceOp {
                        balance_id: ClaimableBalanceId::ClaimableBalanceIdTypeV0(Hash([0xab; 32])),
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionExt::V0,
            };
            TransactionEnvelope::Tx(TransactionV1Envelope {
                tx,
                signatures: VecM::default(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap()
        }

        async fn signed(xdr: &str, seed: [u8; 32]) -> String {
            attach_signature(
                xdr,
                &stellar_agent_network::SoftwareSigningKey::new_from_bytes(seed),
                stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
            )
            .await
            .unwrap()
        }

        async fn sign_only(
            claimant: &EnvSigner,
            primary: &wiremock::MockServer,
            profile: &Profile,
            xdr: String,
        ) -> Run {
            let mut args = args_for(claimant, primary);
            args.sign_only = Some(xdr);
            run_stage(&args, profile).await
        }

        async fn submit_only(
            claimant: &EnvSigner,
            primary: &wiremock::MockServer,
            profile: &Profile,
            xdr: String,
        ) -> Run {
            let mut args = args_for(claimant, primary);
            args.secret_env = None;
            args.submit_only = Some(xdr);
            run_stage(&args, profile).await
        }

        /// The staged stages re-read only the source; the oracle answers for
        /// the source alone.
        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_witnesses_the_source_only() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb1; 32], "CLAIM_WITNESS_SIGN_PASS_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = ClassicRpc::testnet(&[&claimant.g]).serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);

            let run = sign_only(
                &claimant,
                &primary,
                &profile,
                claim_envelope(g_to_muxed(&claimant.g), 100),
            )
            .await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(run.signers, 1);
            assert_eq!(run.envelope["data"]["cross_check"]["status"], "passed");
            assert_eq!(methods(&oracle).await, ["getNetwork", "getLedgerEntries"]);
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_source_disagreement_refuses_before_signing() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb2; 32], "CLAIM_WITNESS_SIGN_DIVERGE_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = ClassicRpc::testnet(&[])
                .with_entry(
                    account_key(&claimant.g),
                    account_xdr(&claimant.g, 999, 0, ""),
                )
                .serve()
                .await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);

            let run = sign_only(
                &claimant,
                &primary,
                &profile,
                claim_envelope(g_to_muxed(&claimant.g), 100),
            )
            .await;

            assert_refused(&run, "simulation.divergence", &primary).await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_without_oracle_skips_on_testnet() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb3; 32], "CLAIM_WITNESS_SIGN_SKIP_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let profile = profile_for(&claimant, &primary, None, &audit);

            let run = sign_only(
                &claimant,
                &primary,
                &profile,
                claim_envelope(g_to_muxed(&claimant.g), 100),
            )
            .await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(
                run.envelope["data"]["cross_check"],
                serde_json::json!({"status": "skipped", "reason": "oracle_not_configured"})
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_oracle_construction_failure_is_witness_unavailable() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb4; 32], "CLAIM_WITNESS_SIGN_CONSTRUCTION_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let mut profile = profile_for(&claimant, &primary, None, &audit);
            profile.oracle_provider_url = Some(url::Url::parse("ftp://oracle.example").unwrap());

            let run = sign_only(
                &claimant,
                &primary,
                &profile,
                claim_envelope(g_to_muxed(&claimant.g), 100),
            )
            .await;

            assert_refused(&run, "network.witness_unavailable", &primary).await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_fee_above_cap_refuses_before_the_witness() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb5; 32], "CLAIM_WITNESS_SIGN_CAP_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = ClassicRpc::testnet(&[&claimant.g]).serve().await;
            let mut profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            profile.classic_max_fee_per_op_stroops = Some(400);

            let run = sign_only(
                &claimant,
                &primary,
                &profile,
                claim_envelope(g_to_muxed(&claimant.g), 500),
            )
            .await;

            assert_refused(&run, "fees.percentile_exceeds_cap", &primary).await;
            assert_eq!(
                run.envelope["error"]["message"],
                "the envelope's per-operation fee 500 stroops exceeds the profile cap of 400 \
                 stroops; prepare the transaction again with a fee within the cap"
            );
            assert!(methods(&oracle).await.is_empty());
        }

        /// A muxed staged source is witnessed on its G account.
        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_muxed_source_witnesses_the_g_account() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb6; 32], "CLAIM_WITNESS_SIGN_MUXED_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = ClassicRpc::testnet(&[&claimant.g]).serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            let muxed = MuxedAccount::MuxedEd25519(MuxedAccountMed25519 {
                id: 11,
                ed25519: Uint256(g_to_bytes(&claimant.g)),
            });

            let run = sign_only(&claimant, &primary, &profile, claim_envelope(muxed, 100)).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(run.envelope["data"]["cross_check"]["status"], "passed");
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_witness_passes_and_rows_carry_it() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb7; 32], "CLAIM_WITNESS_SUBMIT_PASS_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = ClassicRpc::testnet(&[&claimant.g]).serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            let xdr = signed(&claim_envelope(g_to_muxed(&claimant.g), 100), [0xb7; 32]).await;

            let run = submit_only(&claimant, &primary, &profile, xdr).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(run.envelope["data"]["cross_check"]["status"], "passed");
            assert!(sent(&primary).await);
            assert_rows_carry_witness(&profile, &oracle.uri());
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_source_disagreement_refuses_before_the_send() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb8; 32], "CLAIM_WITNESS_SUBMIT_DIVERGE_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = ClassicRpc::testnet(&[])
                .with_entry(
                    account_key(&claimant.g),
                    account_xdr(&claimant.g, 999, 0, ""),
                )
                .serve()
                .await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            let xdr = signed(&claim_envelope(g_to_muxed(&claimant.g), 100), [0xb8; 32]).await;

            let run = submit_only(&claimant, &primary, &profile, xdr).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_without_oracle_skips_on_testnet() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xb9; 32], "CLAIM_WITNESS_SUBMIT_SKIP_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let profile = profile_for(&claimant, &primary, None, &audit);
            let xdr = signed(&claim_envelope(g_to_muxed(&claimant.g), 100), [0xb9; 32]).await;

            let run = submit_only(&claimant, &primary, &profile, xdr).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(
                run.envelope["data"]["cross_check"],
                serde_json::json!({"status": "skipped", "reason": "oracle_not_configured"})
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_oracle_identity_refusal_is_witness_unavailable() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xba; 32], "CLAIM_WITNESS_SUBMIT_IDENTITY_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle_rpc = ClassicRpc::testnet(&[&claimant.g]);
            oracle_rpc.report("Test SDF Future Network ; October 2022");
            let oracle = oracle_rpc.serve().await;
            let profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            let xdr = signed(&claim_envelope(g_to_muxed(&claimant.g), 100), [0xba; 32]).await;

            let run = submit_only(&claimant, &primary, &profile, xdr).await;

            assert_refused(&run, "network.witness_unavailable", &primary).await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_fee_above_cap_refuses_before_the_witness() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let claimant = EnvSigner::new([0xbb; 32], "CLAIM_WITNESS_SUBMIT_CAP_SK");
            let primary = native_ledger(&claimant.g, 100_000_000).serve().await;
            let oracle = ClassicRpc::testnet(&[&claimant.g]).serve().await;
            let mut profile = profile_for(&claimant, &primary, Some(&oracle), &audit);
            profile.classic_max_fee_per_op_stroops = Some(400);
            let xdr = signed(&claim_envelope(g_to_muxed(&claimant.g), 500), [0xbb; 32]).await;

            let run = submit_only(&claimant, &primary, &profile, xdr).await;

            assert_refused(&run, "fees.percentile_exceeds_cap", &primary).await;
            assert!(methods(&oracle).await.is_empty());
        }
    }

    /// The mainnet pipeline over the fixture's stored profile, ceremony and
    /// routed endpoints.
    #[cfg(feature = "mainnet-write")]
    mod mainnet_full {
        use super::*;
        use std::rc::Rc;

        use serde_json::Value;

        use crate::common::mainnet_write::{
            bound_recorders_on_this_thread, invalidations_on_this_thread,
        };
        use crate::common::mainnet_write_fixture::{
            AGENT_SEED, AGENT_VAR, DESTINATION, ISSUER, MainnetFixture, Spec, claim_rule,
            install_ledger_double, minimum_reserve, open_authorizations_of,
        };
        use crate::test_rpc::ClassicRpc;

        /// The native balance the mocked endpoints report for every account.
        const BALANCE: i64 = 100_000_000_000;
        /// The protocol reserve of an account without subentries.
        const RESERVE: i64 = 10_000_000;

        fn agent() -> String {
            stellar_agent_test_support::signed_envelope::account_id_for_seed(AGENT_SEED)
        }

        /// An endpoint on `passphrase` funding the agent and holding the
        /// agent's claimable balance of `amount` stroops.
        fn ledger(mainnet: bool, amount: i64) -> ClassicRpc {
            let agent = agent();
            let (key, entry) = claimable_entry_with(&agent, amount);
            let rpc = if mainnet {
                ClassicRpc::mainnet(&[&agent, DESTINATION, ISSUER])
            } else {
                ClassicRpc::testnet(&[&agent, DESTINATION, ISSUER])
            };
            rpc.with_entry(key, entry)
        }

        /// The fixture `name` whose endpoints hold the agent's 10 XLM
        /// claimable balance.
        fn spec(name: &'static str) -> Spec {
            Spec::new(name)
                .primary(ledger(true, 100_000_000))
                .oracle(ledger(true, 100_000_000))
        }

        /// A claim of the agent's balance on the fixture's profile, signed
        /// from [`AGENT_VAR`].
        pub(super) fn mainnet_args(fixture: &MainnetFixture) -> ClaimArgs {
            let mut args = minimal_args();
            args.profile = Some(fixture.name.to_owned());
            args.network = None;
            args.rpc_url = None;
            args.balance_id = CLAIM_RPC_BALANCE_HEX64.to_owned();
            args.source = fixture.agent.g.clone();
            args.secret_env = Some(AGENT_VAR.to_owned());
            args
        }

        struct Run {
            code: i32,
            envelope: Value,
        }

        impl Run {
            fn code(&self) -> &str {
                self.envelope["error"]["code"].as_str().unwrap_or("")
            }
        }

        async fn run(fixture: &MainnetFixture, args: &ClaimArgs) -> Run {
            let mut out = Vec::new();
            let code =
                run_with_dependencies(args, fixture.loader(), fixture.initializer(), &mut out)
                    .await;
            Run {
                code,
                envelope: crate::common::render::single_json_document(&out),
            }
        }

        /// A real browser listener gates the signer, authorization, and submission.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn direct_mainnet_confirmation_requires_uv_before_signing() {
            for (name, flags) in [("claim-browser-no-uv", 1), ("claim-browser-uv", 5)] {
                let mut fixture = spec(name).build().await;
                fixture.present_in_browser(flags);
                let before = crate::common::signer_ceremony::signer_resolutions_on_this_thread();
                let result = run(&fixture, &mainnet_args(&fixture)).await;
                if flags == 1 {
                    assert_eq!(
                        result.code(),
                        "approval.presence_invalid",
                        "{}",
                        result.envelope
                    );
                    assert!(records(&fixture).is_empty());
                    assert!(fixture.sent_envelopes().await.is_empty());
                    assert!(fixture.audit_rows("approval_attested").is_empty());
                    assert_eq!(
                        crate::common::signer_ceremony::signer_resolutions_on_this_thread(),
                        before
                    );
                } else {
                    assert_eq!(result.code, 0, "{}", result.envelope);
                    assert_eq!(fixture.sent_envelopes().await.len(), 1);
                    assert_eq!(fixture.audit_rows("approval_attested").len(), 1);
                }
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

        /// Accept: the claim is witnessed through the routed oracle, sent
        /// once with the enrolled key's signature, and settles its
        /// authorization and its confirmation entry.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn accept() {
            let fixture = spec("mainnet-claim-accept").build().await;

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
            assert_eq!(
                run.envelope["data"]["envelope_xdr"], sent[0],
                "{}",
                run.envelope
            );
            assert_eq!(run.envelope["data"]["ledger"], 1005, "{}", run.envelope);
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
            let fixture = spec("mainnet-claim-noop").noop_engine().build().await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(
                run.code(),
                "network.mainnet_write_forbidden",
                "{}",
                run.envelope
            );
            assert!(
                run.envelope["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("Noop")
            );
            assert_eq!(fixture.initializer_calls(), 0);
            assert!(fixture.primary_methods().await.is_empty());
        }

        /// Engine proofs: a signed policy without a `[mainnet]` table
        /// refuses before the confirmation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_policy_without_the_mainnet_table_refuses() {
            let fixture = spec("mainnet-claim-pre-enable").pre_enable().build().await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_refused_before_confirmation(&fixture, &run, "network.mainnet_write_forbidden")
                .await;
            let message = run.envelope["error"]["message"].as_str().unwrap();
            assert!(message.contains("[mainnet]"), "{message}");
            assert!(message.contains("profile enable-mainnet"), "{message}");
        }

        /// Enrollment: a placeholder pin refuses before the confirmation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_placeholder_pin_refuses_before_the_confirmation() {
            let fixture = spec("mainnet-claim-unpinned").build().await;
            fixture.unpin_signer();

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_refused_before_confirmation(&fixture, &run, "auth.enrolled_signer_unpinned")
                .await;
            fixture.assert_no_consent_ceremony();
        }

        /// Enrollment: a source other than the enrolled key refuses with the
        /// identity rule.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_source_other_than_the_enrolled_key_refuses() {
            let endpoint = || {
                let (key, entry) = claimable_entry_with(DESTINATION, 100_000_000);
                ClassicRpc::mainnet(&[&agent(), DESTINATION]).with_entry(key, entry)
            };
            let fixture = Spec::new("mainnet-claim-other-source")
                .primary(endpoint())
                .oracle(endpoint())
                .build()
                .await;
            let mut args = mainnet_args(&fixture);
            args.source = DESTINATION.to_owned();

            let run = run(&fixture, &args).await;

            assert_refused_before_confirmation(&fixture, &run, "auth.enrolled_identity_unusable")
                .await;
            assert!(
                run.envelope["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("public_key_mismatch")
            );
            fixture.assert_no_consent_ceremony();
        }

        /// Claim confirmation: the prompt shows the asset and the amount as
        /// not known before the claim; the entry the confirmation writes
        /// carries the decoded envelope and no value, and the authorization
        /// is minted for the claim from it before the device opens.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn the_claim_confirmation_shows_the_value_as_unknown() {
            let fixture = spec("mainnet-claim-confirmation").build().await;
            let observed = Rc::new(std::cell::RefCell::new(Vec::new()));
            let seen = Rc::clone(&observed);
            let name = fixture.name;
            let store = fixture.approval_store_path();
            let (_ledger, calls) = install_ledger_double(
                move || {
                    let pending = stellar_agent_core::approval::open_with_retry(
                        &store,
                        stellar_agent_core::approval::DEFAULT_RETRY_ATTEMPTS,
                        stellar_agent_core::approval::DEFAULT_RETRY_BACKOFF,
                    )
                    .unwrap();
                    let entries = pending.snapshot(now());
                    drop(pending);
                    seen.borrow_mut()
                        .push((entries, open_authorizations_of(name, now())));
                    Ok(())
                },
                || Ok(()),
            );
            let mut args = mainnet_args(&fixture);
            args.secret_env = None;
            args.sign_with_ledger = true;

            let run = run(&fixture, &args).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(fixture.sent_envelopes().await.len(), 1);
            let observed = observed.borrow();
            assert_eq!(observed.len(), 1);
            let (entries, open) = &observed[0];
            assert_eq!(entries.len(), 1, "{entries:?}");
            assert_eq!(entries[0].kind_name, "ClaimSimulated");
            let stellar_agent_core::approval::view::ApprovalSummaryView::Claim {
                balance_id_strkey,
                source,
                fee_stroops,
                ..
            } = &entries[0].summary
            else {
                panic!("{:?}", entries[0].summary);
            };
            assert_eq!(*source, fixture.agent.g);
            assert_eq!(*fee_stroops, 100);
            assert_eq!(open.len(), 1, "{open:?}");
            assert_eq!(open[0].consumer, MainnetConsumer::CliClaim);
            let summaries = fixture.summaries();
            assert_eq!(summaries.len(), 1);
            assert_eq!(fixture.ceremonies().len(), 1);
            let prompt = &summaries[0];
            assert!(prompt.contains(balance_id_strkey.as_str()), "{prompt}");
            assert!(prompt.contains(&fixture.agent.g), "{prompt}");
            assert!(prompt.contains("Fee: 100 stroops"), "{prompt}");
            assert_eq!(
                prompt
                    .matches("not known to the wallet before the claim")
                    .count(),
                2,
                "{prompt}"
            );
            assert_eq!(
                *calls.lock().unwrap(),
                ["construct", "public_key", "sign_tx_payload"]
            );
            let after = fixture.pending_entries();
            assert_eq!(after.len(), 1);
            let stellar_agent_core::approval::view::ApprovalSummaryView::Consumed {
                original_kind_name,
                ..
            } = &after[0].summary
            else {
                panic!("{:?}", after[0].summary);
            };
            assert_eq!(original_kind_name, "ClaimSimulated");
        }

        /// Pre-flight before the witness: without the audit chain key the
        /// claim refuses before the oracle and before the confirmation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn the_audit_preflight_runs_before_the_witness() {
            let fixture = spec("mainnet-claim-audit-preflight").build().await;
            fixture.delete_keyring_entry(&fixture.profile().audit_log_hash_chain_key_id);

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(run.code, 1, "{}", run.envelope);
            assert!(run.code().starts_with("audit."), "{}", run.envelope);
            assert!(fixture.oracle_methods().await.is_empty());
            assert!(fixture.pending_entries().is_empty());
        }

        /// Witness divergence: an oracle reporting another balance refuses
        /// with the bound producer's code before the confirmation.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_diverging_witness_refuses_before_the_confirmation() {
            let fixture = Spec::new("mainnet-claim-divergence")
                .primary(ledger(true, 100_000_000))
                .oracle(ledger(true, 100_000_001))
                .build()
                .await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_refused_before_confirmation(&fixture, &run, "simulation.divergence").await;
        }

        /// Ledger order: the device is opened after the mint.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn the_ledger_is_opened_after_the_mint() {
            let fixture = spec("mainnet-claim-ledger-order").build().await;
            let open = Rc::new(std::cell::RefCell::new(Vec::new()));
            let seen = Rc::clone(&open);
            let name = fixture.name;
            let (_ledger, calls) = install_ledger_double(
                move || {
                    seen.borrow_mut().push(open_authorizations_of(name, now()));
                    Ok(())
                },
                || Ok(()),
            );
            let mut args = mainnet_args(&fixture);
            args.secret_env = None;
            args.sign_with_ledger = true;

            let run = run(&fixture, &args).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            let open = open.borrow();
            assert_eq!(open[0].len(), 1);
            assert_eq!(open[0][0].consumer, MainnetConsumer::CliClaim);
            assert_eq!(
                *calls.lock().unwrap(),
                ["construct", "public_key", "sign_tx_payload"]
            );
        }

        /// Sizing: a claim rule whose one window criterion is a rate limit
        /// sizes one entry.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn a_rate_limited_claim_sizes_one_entry() {
            let fixture = spec("mainnet-claim-sizing").build().await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            let bound = bound_recorders_on_this_thread();
            assert_eq!(bound.len(), 1);
            assert!(bound[0].contains("window_entry_count: 1"), "{}", bound[0]);
        }

        /// The margin at which the claim, which debits nothing, passes the
        /// reserve alone and crosses it with any fee.
        const FEE_CROSSING_MARGIN: i64 = BALANCE - RESERVE;

        /// Fee in the policy arguments, mainnet.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn the_fee_counts_toward_the_reserve_on_mainnet() {
            let fixture = spec("mainnet-claim-fee-reserve")
                .rules(vec![claim_rule(&minimum_reserve(FEE_CROSSING_MARGIN))])
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
            let fixture = Spec::new("testnet-claim-fee-reserve")
                .testnet()
                .primary(ledger(false, 100_000_000))
                .rules(vec![claim_rule(&minimum_reserve(FEE_CROSSING_MARGIN))])
                .build()
                .await;

            let run = run(&fixture, &mainnet_args(&fixture)).await;

            assert_eq!(
                run.code(),
                "policy.deny.minimum_reserve_breached",
                "{}",
                run.envelope
            );
            assert!(fixture.sent_envelopes().await.is_empty());
        }

        /// The total fee of every envelope the mocked endpoints build: one
        /// operation at the 100-stroop default fee.
        const ENVELOPE_FEE: i64 = 100;

        /// A testnet `--build-only` claim of the agent's balance, under a
        /// `minimum_reserve` rule with `margin_stroops`.
        async fn build_only_under_margin(name: &'static str, margin_stroops: i64) -> Run {
            let fixture = Spec::new(name)
                .testnet()
                .primary(ledger(false, 100_000_000))
                .rules(vec![claim_rule(&minimum_reserve(margin_stroops))])
                .build()
                .await;
            let mut args = mainnet_args(&fixture);
            args.build_only = true;
            args.secret_env = None;

            let run = run(&fixture, &args).await;
            assert!(fixture.sent_envelopes().await.is_empty(), "nothing is sent");
            run
        }

        /// Asserts a build-only `minimum_reserve` refusal that returned no
        /// envelope.
        fn assert_build_only_reserve_refusal(run: &Run) {
            assert_eq!(run.code, 1, "{}", run.envelope);
            assert_eq!(
                run.code(),
                "policy.deny.minimum_reserve_breached",
                "{}",
                run.envelope
            );
            assert!(
                run.envelope["data"].get("envelope_xdr").is_none(),
                "{}",
                run.envelope
            );
        }

        /// Fee in the policy arguments, build-only: the envelope it returns
        /// is signed later and spends its fee, so the same rule denies it.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn build_only_counts_the_fee_toward_the_reserve() {
            let run =
                build_only_under_margin("testnet-claim-build-only-reserve", FEE_CROSSING_MARGIN)
                    .await;

            assert_build_only_reserve_refusal(&run);
        }

        /// Build-only control: a margin lower by exactly the envelope fee
        /// admits the envelope, so the refusal above comes from the fee.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn build_only_admits_the_margin_that_leaves_room_for_the_fee() {
            let run = build_only_under_margin(
                "testnet-claim-build-only-reserve-control",
                FEE_CROSSING_MARGIN - ENVELOPE_FEE,
            )
            .await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            let xdr = run.envelope["data"]["envelope_xdr"]
                .as_str()
                .unwrap_or_else(|| panic!("{}", run.envelope));
            assert_eq!(
                i64::from(envelope_total_fee(xdr).unwrap()),
                ENVELOPE_FEE,
                "the returned envelope carries the fee the margin leaves room for"
            );
        }

        /// Build-only boundary: a margin that leaves room for one stroop less
        /// than the envelope fee denies the envelope.
        #[tokio::test(flavor = "current_thread")]
        #[serial_test::serial]
        async fn build_only_refuses_the_margin_one_stroop_short_of_the_fee() {
            let run = build_only_under_margin(
                "testnet-claim-build-only-reserve-deficit",
                FEE_CROSSING_MARGIN - (ENVELOPE_FEE - 1),
            )
            .await;

            assert_build_only_reserve_refusal(&run);
        }
    }
}
