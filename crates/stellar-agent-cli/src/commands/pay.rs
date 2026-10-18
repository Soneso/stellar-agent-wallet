//! `stellar-agent pay` subcommand — payment spine.
//!
//! Supports three execution stages that may be chained or used independently:
//!
//! 1. **Build** (`--build-only`) — constructs the transaction envelope, runs
//!    SEP-29 memo-required enforcement, and emits unsigned base64 XDR.
//! 2. **Sign** (`--sign-only <base64-xdr>`) — signs a previously-built envelope
//!    and emits signed base64 XDR.
//! 3. **Submit** (`--submit-only <base64-xdr>`) — submits a signed envelope and
//!    polls until confirmation.
//!
//! Default (no stage flag): runs all three stages atomically.
//!
//! # Stage flag mutual exclusivity
//!
//! `--build-only`, `--sign-only`, and `--submit-only` are structurally
//! mutually exclusive via a `clap` argument group. Passing more than one
//! is a parse error before `run` is called.
//!
//! # Mainnet rejection
//!
//! `--network testnet` is the only accepted value. Mainnet is structurally
//! rejected at two layers:
//! - CLI: the `TargetNetwork::Mainnet` variant returns
//!   `network.mainnet_write_forbidden` before any RPC call.
//! - Submit layer: `submit_transaction_and_wait` rejects mainnet-looking URLs
//!   as a defence-in-depth measure.
//!
//! # Endpoint identity
//!
//! A stage that reads from the endpoint builds one client and asks the
//! endpoint which network it serves before its first read. Every later read
//! and the send use that same client. The full pipeline and `--submit-only`
//! check before the reservation reconcile, and `--build-only` before the fee
//! and sequence reads. `--sign-only` checks before the account reads of an
//! envelope it can decode, and signs an envelope it cannot decode without any
//! request. The submit layer checks the sending client again before the send.
//!
//! # Secret-material policy
//!
//! `--secret-env VAR` reads the secret key from the environment variable
//! named `VAR` through the shared
//! [`crate::common::signer_ceremony::resolve_software_signer_from_env`]
//! ceremony: the value is wrapped in `Zeroizing<String>` immediately, loaded
//! into a [`stellar_agent_core::wallet::Wallet`] via
//! [`stellar_agent_core::wallet::Wallet::unlock`], and consumed by
//! [`stellar_agent_network::signing::wallet::signer_from_wallet`].  The
//! `LockedSeed` (mlock-protected) is held only for the duration of the parse
//! and derive; the `SoftwareSigningKey` returned to this module drops at the
//! end of the signing block, ensuring zeroization fires on every exit path.
//!
//! # mlock-protected signing window
//!
//! The `--secret-env` path routes through the shared ceremony
//! (`Wallet::unlock` → `LockedSeed` → `signer_from_wallet` → dispose) →
//! `attach_signature` → drop. The `--sign-with-ledger` path uses
//! `signer_from_ledger` (hardware signer; no seed ever in memory).
//!
//! # Operator policy evaluation
//!
//! The profile is resolved (and, when it carries `policy.engine = "v1"`, the
//! platform keyring store is initialised) before any network build, in every
//! stage. In the full pipeline and `--build-only`, the resolved
//! amount/asset/destination are evaluated after the envelope is built and
//! before signing. `--sign-only` and `--submit-only` gate too: each decodes
//! the supplied envelope through
//! [`stellar_agent_core::envelope_decode::decode_authoritative_args`] (the
//! same decoder the MCP `stellar_pay_commit` path uses) and evaluates the
//! decoded fields before signing or broadcasting — `--submit-only` gates even
//! though the envelope arrives pre-signed, because broadcasting still spends
//! funds. An envelope the decoder cannot classify into a sized shape follows
//! the opaque-signing posture (`policy.deny.unsizable_value_effect` under a
//! matched value rule, unless the rule sets `allow_opaque_signing = true`).
//! Every stage evaluates against the operator-signed `PolicyEngineV1` (V1
//! profiles) or the permissive `NoopPolicyEngine` (`Noop` profiles), mirroring
//! the `stellar_pay` / `stellar_pay_commit` MCP tools' dispatch gates. When NO
//! profile was named and no persisted `default.toml` file exists, an in-memory
//! `Noop`-engine testnet profile is synthesized (tagged
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
//!
//! # Fee cap and cross-check witness
//!
//! After the policy gate, every stage checks the per-operation fee against
//! the profile's `classic_max_fee_per_op_stroops`: the selected fee in the
//! full pipeline and `--build-only`, the decoded envelope fee in
//! `--sign-only` and `--submit-only`. A mainnet profile without the cap
//! refuses. The signing and submitting stages then obtain the cross-check
//! witness: the oracle re-reads the source account, the destination, the
//! SEP-29 flag when it was read, and the source trustline of an issued send
//! asset, valued on the source debit leg. A staged envelope's SEP-29 flag is
//! read on the primary only when the decoded transaction carries no memo and
//! pays a plain G destination. Both checks refuse before the audit
//! pre-flight, the signer, and the send; the outcome is the result's
//! `cross_check` field and travels into the pending and submitted audit rows.
//! `--build-only` obtains no witness.
//!
//! # Behavior
//!
//! All network calls go through Stellar RPC. SEP-29 on-chain data-entry
//! enforcement runs before signing. Ledger signing is available via
//! `--sign-with-ledger`. The `--secret-env` path uses an mlock-protected
//! signing window.

use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::StellarAmount;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{AuthError, NetworkError, ValidationError, WalletError};
use stellar_agent_core::policy::PolicyEngine;
use stellar_agent_core::policy::v1::{AccountIdentityView, AccountReservesView};
use stellar_agent_network::NetworkContext;
use stellar_xdr::Memo;

use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::cross_check::{
    AccountObservation, CrossCheckOutcome, CrossCheckView, DestinationObservation, MemoObservation,
    PayWitnessInputs, TrustlineObservation, obtain_classic_witness,
};
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_network::{
    CLASSIC_SINGLE_OPERATION_COUNT, ClassicFeeChoice, ClassicFeeSelection, StellarRpcClient,
    SubmissionResult, SubmissionSignerKind, check_built_fee_cap, check_classic_fee_cap,
    init_platform_keyring_store, parse_classic_fee_choice, parse_memo_fields,
    resolve_classic_fee_selection, submit_transaction_and_wait,
};

use crate::commands::policy_engine::{
    build_v1_policy_engine, evaluate_opaque_signing_policy, evaluate_value_moving_policy,
    pay_policy_args,
};
use crate::common::network::{
    EndpointFlags, EndpointUrlFlag, TargetNetwork, check_endpoint_identity,
    network_context_for_command,
};
use crate::common::profile_access::{
    ProfileOrigin, injected_profile_load, load_profile_or_synthesize_testnet_with,
};
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::signer_ceremony::{
    SignerCeremonyOutcome, require_enrolled_signer, resolve_software_signer_from_env,
};
use crate::common::{ResolvedProfileName, resolve_profile_name};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default fee per operation in stroops (100 stroops × 1 op = 100 stroops).
const DEFAULT_FEE_STROOPS: u32 = 100;

/// AGPL-3.0 disclosure text emitted to stderr when `--use-oz-relayer` is set.
///
/// This is the informed-consent banner. The text is conditional (WOULD subject
/// / links no AGPL code) because the path discloses and then REFUSES — no
/// relayer actually runs at this point. The phrase "links no AGPL code" is
/// legally load-bearing and must not be changed without a decision record.
pub const RELAYER_AGPL_DISCLOSURE: &str = "\
NOTICE: --use-oz-relayer is the opt-in for routing submission through a \
self-hosted OpenZeppelin Relayer Channels Plugin. That relayer is AGPL-3.0; \
self-hosting it WOULD subject your deployment to AGPL-3.0 source-disclosure \
obligations. This wallet is Apache-2.0 and links no AGPL code. Relayer submission \
is not implemented in this build; the default in-process path requires no such \
dependency \u{2014} re-run without --use-oz-relayer.";

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

// ─────────────────────────────────────────────────────────────────────────────
// PayResult — the structured success payload
// ─────────────────────────────────────────────────────────────────────────────

/// Structured payload returned in the JSON envelope on a successful payment.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PayResult {
    /// Base64-encoded signed `TransactionEnvelope` XDR.
    ///
    /// Present for build-only and sign-only stages; the full pipeline also
    /// includes this field so callers have the XDR for auditing.
    pub envelope_xdr: String,

    /// Transaction hash (64-character hex), present after submission.
    ///
    /// Absent for `--build-only` and `--sign-only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Ledger sequence number, present after confirmation.
    ///
    /// Absent for `--build-only` and `--sign-only`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

    /// The stage that produced this result.
    pub stage: String,

    /// Selected per-operation fee in stroops.
    ///
    /// Encoded as a decimal string on the wire (`serde(with =
    /// "stellar_agent_core::wire_stroops::u32_opt")`). The Rust field type
    /// stays `Option<u32>`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "stellar_agent_core::wire_stroops::u32_opt"
    )]
    pub selected_fee_per_op_stroops: Option<u32>,

    /// Fee selection source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_fee_percentile: Option<String>,

    /// Outcome of the cross-check witness a signing or submitting stage
    /// obtained before it signed or sent.
    ///
    /// Absent for `--build-only`, which neither signs nor sends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_check: Option<CrossCheckView>,
}

#[derive(Debug, Clone)]
struct BuiltPaymentEnvelope {
    envelope_xdr: String,
    fee_selection: ClassicFeeSelection,
    /// The parsed `--fee` choice the selection came from; it names the fee's
    /// source in a fee-cap refusal.
    fee_choice: ClassicFeeChoice,
    /// The parsed asset the payment sends; the source debit leg the witness
    /// values and keys the source trustline to.
    asset: Asset,
    /// The SEP-29 observation of the build: the destination's flag when the
    /// payment carries no memo.
    memo_observation: MemoObservation,
    /// Resolved payment amount in stroops. Feeds the policy gate's
    /// `amount_stroops` field — identical key and value the `stellar_pay` MCP
    /// tool's dispatch args carry.
    amount_stroops: i64,
    /// The asset string exactly as supplied on the CLI (`args.asset`,
    /// unreformatted). The `stellar_pay` MCP tool's dispatch args also carry
    /// the raw caller-supplied asset string — `asset_normalise` performs the
    /// only normalisation either side applies, so passing the raw string here
    /// keeps both sides identical.
    asset_raw: String,
    /// The destination G-strkey exactly as supplied on the CLI.
    destination: String,
    /// The source account's fetched state — reused (not re-fetched) to feed
    /// the policy gate's `account_view`, mirroring the `stellar_pay` MCP
    /// twin's `AccountViewAdapter` wiring exactly.
    source_account_view: stellar_agent_network::AccountView,
    /// The destination account's fetched state, if the destination exists on
    /// chain — feeds the policy gate's `identity_view`. `None` when the
    /// destination does not exist (a not-yet-created account); any other read
    /// error refuses the build (see [`read_destination`]).
    dest_account_view: Option<stellar_agent_network::AccountView>,
}

// ─────────────────────────────────────────────────────────────────────────────
// PayArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `pay` subcommand.
///
/// Stage flags (`--build-only`, `--sign-only`, `--submit-only`) are
/// mutually exclusive via an `ArgGroup`. Memo flags are also mutually
/// exclusive via a separate `ArgGroup`.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(ArgGroup::new("stage").args(["build_only", "sign_only", "submit_only"]).required(false)),
    group(ArgGroup::new("memo_group").args(["memo_text", "memo_id", "memo_hash_hex", "memo_return_hex"]).required(false)),
    group(ArgGroup::new("signer_group").args(["secret_env", "sign_with_ledger"]).required(false)),
)]
pub struct PayArgs {
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

    /// Destination account G-strkey.
    #[arg(value_name = "DESTINATION")]
    pub destination: String,

    /// Amount to send with explicit units, e.g. `"10 XLM"` or `"10.0000000 XLM"`.
    /// For non-native assets: `"10.5 USDC"` etc. Raw stroop numeric strings
    /// are not accepted; use `"0.0000001 XLM"` for the minimum unit.
    #[arg(value_name = "AMOUNT")]
    pub amount: String,

    /// Asset descriptor: `native`, `XLM`, or `CODE:ISSUER_GSTRKEY`.
    /// Defaults to `native`.
    #[arg(value_name = "ASSET", default_value = "native")]
    pub asset: String,

    /// Memo text (UTF-8, ≤28 bytes).
    #[arg(long, value_name = "STRING", group = "memo_group")]
    pub memo_text: Option<String>,

    /// Memo ID (u64 decimal).
    #[arg(long, value_name = "U64", group = "memo_group")]
    pub memo_id: Option<u64>,

    /// Memo hash (64 hex characters → 32 bytes).
    #[arg(long = "memo-hash", value_name = "64_HEX", group = "memo_group")]
    pub memo_hash_hex: Option<String>,

    /// Memo return hash (64 hex characters → 32 bytes).
    #[arg(long = "memo-return", value_name = "64_HEX", group = "memo_group")]
    pub memo_return_hex: Option<String>,

    /// Classic fee per operation: `<stroops>`, `auto`, or `auto:pNN`.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Source account G-strkey. Required for signing.
    #[arg(long, value_name = "G_STRKEY")]
    pub source: Option<String>,

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

    /// Opt in to routing submission through a self-hosted OZ Relayer Channels
    /// Plugin (AGPL-3.0); not implemented in this build — emits an AGPL-3.0
    /// disclosure and declines the operation.
    #[arg(long, default_value_t = false)]
    pub use_oz_relayer: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `pay` subcommand.
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
pub async fn run(args: &PayArgs) -> i32 {
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and
/// a spy initialiser to assert the keyring store is registered before the V1
/// policy gate's owner-key read (see `run_build_only` / `run_full_pipeline`)
/// without touching the OS keychain.
///
/// # The injected closure LOADS ONLY
///
/// `load_profile` performs the load and nothing else. Whether a `NotFound`
/// may be replaced by the synthesized zero-config profile is decided by
/// [`load_profile_or_synthesize_testnet_with`], which this function calls once,
/// at entry, with the resolved name. Every stage receives the loaded profile.
/// The refusal for a named-but-missing profile therefore runs on the injected
/// path exactly as it does in production. A check placed inside the closure
/// would be bypassed by every test that supplies its own.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &PayArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, stellar_agent_core::profile::loader::ProfileLoadError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let resolved = resolve_profile_name(args.profile.as_deref());
    let (profile, origin) = match load_profile_or_synthesize_testnet_with(&resolved, load_profile) {
        Ok(loaded) => loaded,
        Err(e) => {
            print_error(
                &Envelope::<()>::err_raw(e.code(), e.message(&resolved.name)),
                args.output,
            );
            return 1;
        }
    };
    run_loaded(args, &resolved, &profile, origin, init_keyring).await
}

/// Runs the command on a loaded profile: the network context, the structural
/// mainnet refusal, the relayer gate, and the stage dispatch.
async fn run_loaded<InitKeyring>(
    args: &PayArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> i32
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
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };
    // The resolved name and the input that supplied it are logged together:
    // a report of a run signing against the wrong profile is diagnosable only
    // if the log says which name was used and where it came from. Mirrors the
    // MCP server's startup line.
    tracing::debug!(
        profile = %resolved.name,
        profile_source = resolved.source.as_str(),
        "pay: profile resolved"
    );

    // ── Mainnet structural rejection (first layer) ────────────────────────────
    if context.chain_id.is_mainnet() {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // ── OZ Relayer opt-in gate ────────────────────────────────────────────────
    // Fires AFTER network-validation but BEFORE any keyring/signer touch or
    // RPC client construction — the refuse path provably loads no secret and
    // makes no network call.
    if let Err(e) = check_relayer_opt_in(args) {
        let envelope = Envelope::<()>::err(&e);
        print_error(&envelope, args.output);
        return 1;
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
    args: &PayArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    init_keyring: InitKeyring,
) -> i32
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Conditionally initialise the platform keyring ─────────────────────────
    // Must happen before any network build: `build_v1_policy_engine` (invoked
    // from `evaluate_pay_policy` below) reads the owner PUBLIC key from the
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
        print_error(&Envelope::<()>::err(&e), args.output);
        return 1;
    }

    let built = match checked_client_and_build_inputs(context, args).await {
        Ok((client, inputs)) => build_unsigned_envelope(&client, context, args, inputs).await,
        Err(e) => Err(e),
    };
    match built {
        Ok(built) => {
            let chain_id = context.chain_id.caip2_str();
            // Build-only: gate but do not submit, so the gate-sized effects are
            // not recorded (no confirmed on-chain action to attest).
            if let Err(code) = evaluate_pay_policy(args, &built, chain_id, profile, &resolved.name)
            {
                return code;
            }
            if let Err(e) = check_built_fee_cap(
                built.fee_selection.per_op_stroops,
                built.fee_choice,
                profile,
            ) {
                print_error(&Envelope::<()>::err(&e), args.output);
                return 1;
            }
            let result = PayResult {
                envelope_xdr: built.envelope_xdr,
                tx_hash: None,
                ledger: None,
                stage: "build".to_owned(),
                selected_fee_per_op_stroops: Some(built.fee_selection.per_op_stroops),
                selected_fee_percentile: Some(built.fee_selection.selected_fee_percentile),
                cross_check: None,
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            1
        }
    }
}

async fn run_sign_only<InitKeyring>(
    context: &NetworkContext,
    args: &PayArgs,
    resolved: &ResolvedProfileName,
    unsigned_xdr: &str,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> i32
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    match init_keyring_for_origin(args, resolved, origin, init_keyring) {
        Ok(()) => (),
        Err(code) => return code,
    };
    let gate = match evaluate_staged_pay_policy(
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
        Err(code) => return code,
    };
    // A decoded payment's fee is checked against the cap and the oracle
    // re-reads what the gate read, before the audit pre-flight and the
    // signer. An opaque envelope reads nothing and has no witness.
    let cross_check = match &gate.payment {
        Some(payment) => {
            match witness_staged_payment(
                context,
                profile,
                unsigned_xdr,
                payment,
                "stellar_pay_commit",
            )
            .await
            {
                Ok(outcome) => Some(outcome),
                Err(e) => {
                    print_error(&Envelope::<()>::err(&e), args.output);
                    return 1;
                }
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
        print_error(&Envelope::<()>::err(&e), args.output);
        return 1;
    }

    match sign_envelope(context, args, unsigned_xdr, profile, &resolved.name).await {
        Ok(signed_xdr) => {
            let result = PayResult {
                envelope_xdr: signed_xdr,
                tx_hash: None,
                ledger: None,
                stage: "sign".to_owned(),
                selected_fee_per_op_stroops: None,
                selected_fee_percentile: None,
                cross_check: cross_check.as_ref().map(CrossCheckOutcome::view),
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            1
        }
    }
}

async fn run_submit_only<InitKeyring>(
    context: &NetworkContext,
    args: &PayArgs,
    resolved: &ResolvedProfileName,
    signed_xdr: &str,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> i32
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    match init_keyring_for_origin(args, resolved, origin, init_keyring) {
        Ok(()) => (),
        Err(code) => return code,
    };
    // Establish which network `--rpc-url` actually serves before anything
    // else runs, on the client that reconciles, reads the gate's account
    // views, and sends. The staged gate evaluates under the chain id derived
    // from `--network`, so that flag has to describe the endpoint the
    // envelope will reach. The check makes it so, and a mismatch refuses here
    // rather than after a policy decision taken for the wrong chain.
    let client = match checked_client(context, args).await {
        Ok(client) => std::sync::Arc::new(client),
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };

    // Settle the spending-window reservations that have stood long enough to
    // be settleable, before the gate below counts them. A reservation the
    // chain has since answered for should not hold the operator's cap, and one
    // the chain has not is counted as spend.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            print_error(
                &Envelope::<()>::err_raw("wallet.clock_error", e.to_string()),
                args.output,
            );
            return 1;
        }
    };
    crate::commands::submission_record::reconcile_open_reservations(
        profile,
        &resolved.name,
        origin,
        &client,
        now_ms,
    )
    .await;

    let chain_id = context.chain_id.caip2_str();
    // The envelope arrives pre-signed, but broadcasting it still spends
    // funds — gate here even though signing already happened elsewhere.
    let gate = match evaluate_staged_pay_policy(
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
        Err(code) => return code,
    };
    let pay_effects = gate.effects;
    // A decoded payment's fee is checked against the cap and the oracle
    // re-reads what the gate read, before the audit pre-flight and the send.
    let cross_check = match &gate.payment {
        Some(payment) => match witness_staged_payment(
            context,
            profile,
            signed_xdr,
            payment,
            "stellar_pay_commit",
        )
        .await
        {
            Ok(outcome) => Some(outcome),
            Err(e) => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return 1;
            }
        },
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
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };

    let recorder = match crate::commands::submission_record::build_recorder(
        crate::commands::submission_record::SubmitRecord {
            policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
            profile,
            profile_name: resolved.name.clone(),
            verb: "pay",
            tool: "stellar_pay_commit",
            chain_id,
            effects: pay_effects.as_ref(),
            audit: audit_writer.clone(),
            now_ms,
        },
    ) {
        Ok(r) => r.with_witness(cross_check.as_ref().and_then(CrossCheckOutcome::witness)),
        Err(e) => {
            print_error(
                &crate::commands::submission_record::error_envelope(&e, signed_xdr, "pay"),
                args.output,
            );
            return 1;
        }
    };

    match submit_envelope(&client, context, args, signed_xdr, Some(&recorder)).await {
        Ok((signed_xdr, sub_result)) => {
            let result = PayResult {
                envelope_xdr: signed_xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "submit".to_owned(),
                selected_fee_per_op_stroops: None,
                selected_fee_percentile: None,
                cross_check: cross_check.as_ref().map(CrossCheckOutcome::view),
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            print_error(
                &crate::commands::submission_record::error_envelope(&e, signed_xdr, "pay"),
                args.output,
            );
            1
        }
    }
}

/// Attempts to initialise the platform keyring store, whatever the policy
/// engine, and decides by the profile's origin whether a failure is fatal.
///
/// Unconditional (not gated on `profile.policy.engine`): the origin-aware
/// audit pre-flight both stages calling this helper (`--sign-only`,
/// `--submit-only`) run next reads the profile's audit chain-root HMAC key
/// from the platform keyring regardless of the policy engine — a `Noop`
/// engine reads no OWNER key, but the audit key is a separate, engine-independent
/// requirement.
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
fn init_keyring_for_origin<InitKeyring>(
    args: &PayArgs,
    resolved: &ResolvedProfileName,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> Result<(), i32>
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    if let Err(e) = init_keyring() {
        match origin {
            ProfileOrigin::Persisted => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return Err(1);
            }
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
/// Decodes `envelope_xdr` via the SAME decoder the MCP `stellar_pay_commit`
/// path uses ([`stellar_agent_core::decode_authoritative_args`]), fetches the account views the
/// decoded fields need, and delegates the decision to
/// [`dispatch_staged_pay_gate`] — the pure, network-free dispatch this
/// function's tests exercise directly. Returns `Ok(gate)` on allow: the
/// gate-sized effects (`Some` when the envelope decoded into a sized shape,
/// `None` for the no-op engine or an opaque allow) and, for an envelope the
/// decoder classifies, the decoded payment with the views the gate read;
/// returns `Err(exit_code)`, with the refusal envelope already rendered, on
/// any refusal.
///
/// `sending_client` is the checked client `--submit-only` sends through, and
/// the views are read on it. `--sign-only` passes `None`: it builds a client
/// and checks its endpoint only when the envelope decodes, so an envelope the
/// decoder cannot classify reaches the opaque-signing posture without any
/// request. The built client travels in the returned payment, so the stage's
/// witness reads go through it too.
async fn evaluate_staged_pay_policy(
    sending_client: Option<&std::sync::Arc<StellarRpcClient>>,
    context: &NetworkContext,
    args: &PayArgs,
    envelope_xdr: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<StagedPayGate, i32> {
    let chain_id = context.chain_id.caip2_str();
    let policy_engine =
        match build_v1_policy_engine("pay", &profile.policy.engine, profile, profile_name) {
            Ok(pe) => pe,
            Err(msg) => {
                print_error(
                    &Envelope::<()>::err_raw("policy.engine_unavailable", msg),
                    args.output,
                );
                return Err(1);
            }
        };

    let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
        envelope_xdr,
        "stellar_pay_commit",
    );

    // Views are populated only when the decode succeeded — a bounded fetch of
    // the decoded `source` (feeds `minimum_reserve`) and the
    // destination-derived `identity_view` (feeds `home_domain_resolved`),
    // matching `pay`'s established posture (`evaluate_pay_policy`). Held in
    // owned locals so their borrows outlive the `dispatch_staged_pay_gate`
    // call below.
    let mut source_view_holder = None;
    let mut dest_view_holder = None;
    let mut built_client = None;
    if let Ok(ref authoritative_args) = decode_result {
        let client = built_client.insert(match sending_client {
            Some(client) => std::sync::Arc::clone(client),
            None => match checked_client(context, args).await {
                Ok(client) => std::sync::Arc::new(client),
                Err(e) => {
                    print_error(&Envelope::<()>::err(&e), args.output);
                    return Err(1);
                }
            },
        });
        let source = authoritative_args
            .get("source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let destination = authoritative_args
            .get("destination")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        source_view_holder = match stellar_agent_network::fetch_account(client, source, &[]).await {
            Ok(v) => Some(v),
            Err(e) => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return Err(1);
            }
        };
        // An absent destination is not an error, matching
        // `evaluate_pay_policy`; any other read error refuses.
        dest_view_holder = match read_destination(client, destination).await {
            Ok(view) => view,
            Err(e) => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return Err(1);
            }
        };
    }
    let source_adapter = source_view_holder
        .as_ref()
        .map(stellar_agent_network::policy_view::AccountViewAdapter::new);
    let dest_adapter = dest_view_holder
        .as_ref()
        .map(stellar_agent_network::policy_view::AccountViewAdapter::new);

    let decoded = decode_result.as_ref().ok().cloned();
    let effects = match dispatch_staged_pay_gate(
        policy_engine.as_ref(),
        profile,
        chain_id,
        decode_result,
        source_adapter
            .as_ref()
            .map(|a| a as &dyn AccountReservesView),
        dest_adapter.as_ref().map(|a| a as &dyn AccountIdentityView),
    ) {
        Ok(effects) => effects,
        Err(envelope) => {
            print_error(&envelope, args.output);
            return Err(1);
        }
    };
    let payment = match (decoded, source_view_holder, built_client) {
        (Some(decoded), Some(source_view), Some(client)) => {
            match StagedPayment::from_decoded(&decoded, client, source_view, dest_view_holder) {
                Ok(payment) => Some(payment),
                Err(e) => {
                    print_error(&Envelope::<()>::err(&e), args.output);
                    return Err(1);
                }
            }
        }
        _ => None,
    };
    Ok(StagedPayGate { effects, payment })
}

/// The staged gate's decision and what it read.
struct StagedPayGate {
    /// The gate-sized effects (`None` for the no-op engine or an opaque allow).
    effects: Option<stellar_agent_core::policy::v1::ValueEffects>,
    /// The decoded payment and its primary views; `None` for an opaque
    /// envelope, which the gate reads nothing for.
    payment: Option<StagedPayment>,
}

/// A decoded staged payment and the primary views the gate evaluated.
struct StagedPayment {
    /// The client used for the gate's primary reads and the witness reads.
    client: std::sync::Arc<StellarRpcClient>,
    /// The source account view (decoded G account).
    source_view: stellar_agent_network::AccountView,
    /// The destination view, `None` when the destination does not exist.
    dest_view: Option<stellar_agent_network::AccountView>,
    /// The decoded destination G account.
    destination: String,
    /// The decoded send asset: the source debit leg.
    asset: Asset,
    /// The decoded source debit in the send asset's base units.
    amount_stroops: i64,
    /// The decoded transaction fee in stroops.
    total_fee_stroops: u32,
}

impl StagedPayment {
    /// Takes the decoded send leg, destination, and fee of a payment.
    ///
    /// # Errors
    ///
    /// Returns `protocol.xdr_codec_failed` when a decoded field is missing or
    /// out of range, which the decoder never produces, and the refusal of
    /// [`Asset::parse`] for the send asset.
    fn from_decoded(
        decoded: &serde_json::Value,
        client: std::sync::Arc<StellarRpcClient>,
        source_view: stellar_agent_network::AccountView,
        dest_view: Option<stellar_agent_network::AccountView>,
    ) -> Result<Self, WalletError> {
        let field = |name: &str| {
            decoded.get(name).ok_or_else(|| {
                WalletError::Protocol(stellar_agent_core::error::ProtocolError::XdrCodecFailed {
                    detail: format!("the decoded payment carries no {name}"),
                })
            })
        };
        let unusable = |name: &str| {
            WalletError::Protocol(stellar_agent_core::error::ProtocolError::XdrCodecFailed {
                detail: format!("the decoded payment's {name} is out of range"),
            })
        };
        let destination = field("destination")?
            .as_str()
            .ok_or_else(|| unusable("destination"))?
            .to_owned();
        let asset = Asset::parse(field("asset")?.as_str().ok_or_else(|| unusable("asset"))?)?;
        let amount_stroops = field("amount_stroops")?
            .as_str()
            .and_then(|amount| amount.parse::<i64>().ok())
            .ok_or_else(|| unusable("amount_stroops"))?;
        let total_fee_stroops = field("total_fee_stroops")?
            .as_u64()
            .and_then(|fee| u32::try_from(fee).ok())
            .ok_or_else(|| unusable("total_fee_stroops"))?;
        Ok(Self {
            client,
            source_view,
            dest_view,
            destination,
            asset,
            amount_stroops,
            total_fee_stroops,
        })
    }
}

/// Checks a staged payment's fee against the cap, reads the destination's
/// SEP-29 flag when the envelope carries no memo, and obtains the witness.
///
/// The memo decision is taken from the decoded transaction: only `Memo::None`
/// with a plain G destination reads the flag. A muxed destination carries
/// its memo in the muxed id, so its flag is not read.
///
/// # Errors
///
/// Returns the fee-cap refusal, `validation.memo_required` when the
/// destination requires a memo the envelope lacks, the primary read errors,
/// and the refusals of [`witness_payment`].
async fn witness_staged_payment(
    context: &NetworkContext,
    profile: &Profile,
    envelope_xdr: &str,
    payment: &StagedPayment,
    tool: &'static str,
) -> Result<CrossCheckOutcome, WalletError> {
    let per_op = payment.total_fee_stroops / CLASSIC_SINGLE_OPERATION_COUNT;
    check_classic_fee_cap(
        per_op,
        stellar_agent_core::error::FeeSource::Envelope,
        profile,
    )?;
    let shape = stellar_agent_core::envelope_decode::payment_memo_shape(envelope_xdr, tool)
        .map_err(|e| {
            WalletError::Protocol(stellar_agent_core::error::ProtocolError::XdrCodecFailed {
                detail: e.to_string(),
            })
        })?;
    let memo = if shape.memo == stellar_agent_core::envelope_decode::MemoKind::None
        && !shape.destination_muxed
    {
        stellar_agent_network::sep29::check_memo_required(
            &payment.client,
            &payment.destination,
            false,
        )
        .await?
    } else {
        MemoObservation::NotRead
    };
    witness_payment(
        &payment.client,
        context,
        profile,
        PaymentObservations {
            source_view: &payment.source_view,
            destination: &payment.destination,
            dest_view: payment.dest_view.as_ref(),
            memo,
            asset: &payment.asset,
            amount_stroops: payment.amount_stroops,
        },
        tool,
    )
    .await
}

/// Pure post-decode dispatch for the staged `pay` gate: no network or
/// keyring access, so it is exercised directly by tests with a hand-built
/// [`PolicyEngineV1`](stellar_agent_core::policy::v1::PolicyEngineV1) and a
/// real (or absent) decode outcome.
///
/// `decode_result` is the outcome of decoding the staged envelope via
/// [`stellar_agent_core::decode_authoritative_args`] under `"stellar_pay_commit"`. `Ok` evaluates
/// the decoded fields through [`evaluate_value_moving_policy`] under the same
/// tool name — the same rule-matching scope and wire codes the commit-phase
/// MCP twin uses, so sizing comes from the ENVELOPE, not caller-supplied
/// args. `Err` (an envelope the decoder cannot classify: not a
/// `TransactionV1`, wrong operation count, or an operation kind other than a
/// payment) follows the opaque-signing posture via
/// [`evaluate_opaque_signing_policy`]: denies
/// `policy.deny.unsizable_value_effect` under a matched value rule unless it
/// sets `allow_opaque_signing = true`.
///
/// # Errors
///
/// Returns `Err(envelope)` — a fully-rendered refusal envelope — on deny,
/// approval-required, or an engine error.
fn dispatch_staged_pay_gate(
    policy_engine: &dyn PolicyEngine,
    profile: &Profile,
    chain_id: &str,
    decode_result: Result<
        serde_json::Value,
        stellar_agent_core::envelope_decode::EnvelopeDecodeError,
    >,
    account_view: Option<&dyn AccountReservesView>,
    identity_view: Option<&dyn AccountIdentityView>,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, Envelope<()>> {
    match decode_result {
        Ok(authoritative_args) => evaluate_value_moving_policy(
            policy_engine,
            profile,
            "stellar_pay_commit",
            stellar_agent_core::policy::ToolValueKind::MovesValue,
            chain_id,
            &authoritative_args,
            "pay",
            account_view,
            identity_view,
        ),
        Err(_decode_err) => evaluate_opaque_signing_policy(
            policy_engine,
            profile,
            "stellar_pay_commit",
            chain_id,
            stellar_agent_core::policy::v1::OpaqueReason::RawTransactionSignature,
            "pay",
        )
        .map(|()| None),
    }
}

async fn run_full_pipeline<InitKeyring>(
    context: &NetworkContext,
    args: &PayArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> i32
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // Require both source and a signer for the full pipeline.
    if args.source.is_none() {
        let err =
            WalletError::Validation(stellar_agent_core::error::ValidationError::AddressInvalid {
                input: "--source is required for signing".to_owned(),
            });
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // ── Unconditionally attempt to initialise the platform keyring ────────────
    // Unconditional (see `init_keyring_for_origin`'s rustdoc). The
    // origin-aware audit pre-flight below reads the profile's audit chain-root
    // HMAC key from the platform keyring whatever the policy engine. The store
    // must therefore be registered before that read, even on a `Noop`-engine
    // profile. A failed attempt is fatal for a persisted profile and warn-only
    // for the synthesized zero-config profile, matching the audit pre-flight's
    // fail-open posture for that origin.
    if let Err(e) = init_keyring() {
        match origin {
            ProfileOrigin::Persisted => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return 1;
            }
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

    // Settle the spending-window reservations that have stood long enough to
    // be settleable, before the gate below counts them. A reservation the
    // chain has since answered for should not hold the operator's cap, and one
    // the chain has not is counted as spend.
    let now_ms = match stellar_agent_core::timefmt::now_unix_ms() {
        Ok(v) => v,
        Err(e) => {
            print_error(
                &Envelope::<()>::err_raw("wallet.clock_error", e.to_string()),
                args.output,
            );
            return 1;
        }
    };
    // The endpoint check precedes the reconcile, the first request whose
    // answer shapes the policy decision; the same client carries the build
    // reads and the send. The reconcile settles reservations whatever the
    // build arguments say, so the `--source` and `--fee` checks follow it.
    let client = match checked_client(context, args).await {
        Ok(client) => client,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };
    crate::commands::submission_record::reconcile_open_reservations(
        profile,
        &resolved.name,
        origin,
        &client,
        now_ms,
    )
    .await;

    // 1. Build (includes SEP-29 check).
    let built = match build_inputs(args) {
        Ok(inputs) => build_unsigned_envelope(&client, context, args, inputs).await,
        Err(e) => Err(e),
    };
    let built = match built {
        Ok(built) => built,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };
    // ── Operator policy evaluation (before signing) ───────────────────────────
    // Runs while `built` is still owned so its fields can be moved out (not
    // cloned) once the gate allows.
    let chain_id = context.chain_id.caip2_str();
    let pay_effects = match evaluate_pay_policy(args, &built, chain_id, profile, &resolved.name) {
        Ok(effects) => effects,
        Err(code) => return code,
    };

    // The fee is checked against the profile cap, then the oracle re-reads
    // the entries the decision used. Both refuse before the audit pre-flight,
    // the signer, and the send.
    if let Err(e) = check_built_fee_cap(
        built.fee_selection.per_op_stroops,
        built.fee_choice,
        profile,
    ) {
        print_error(&Envelope::<()>::err(&e), args.output);
        return 1;
    }
    let cross_check = match witness_payment(
        &client,
        context,
        profile,
        PaymentObservations {
            source_view: &built.source_account_view,
            destination: &built.destination,
            dest_view: built.dest_account_view.as_ref(),
            memo: built.memo_observation,
            asset: &built.asset,
            amount_stroops: built.amount_stroops,
        },
        "stellar_pay",
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
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
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };

    let unsigned_xdr = built.envelope_xdr;
    let fee_selection = built.fee_selection;

    // 2. Sign.
    let signed_xdr =
        match sign_envelope(context, args, &unsigned_xdr, profile, &resolved.name).await {
            Ok(xdr) => xdr,
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        };

    // 3. Record, then submit. The recorder writes the receipt, the pending
    // audit row and the spending-window reservation before the bytes leave,
    // and settles all three against what the network answers.
    let recorder = match crate::commands::submission_record::build_recorder(
        crate::commands::submission_record::SubmitRecord {
            policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
            profile,
            profile_name: resolved.name.clone(),
            verb: "pay",
            tool: "stellar_pay",
            chain_id,
            effects: pay_effects.as_ref(),
            audit: audit_writer.clone(),
            now_ms,
        },
    ) {
        Ok(r) => r.with_witness(cross_check.witness()),
        Err(e) => {
            print_error(
                &crate::commands::submission_record::error_envelope(&e, &signed_xdr, "pay"),
                args.output,
            );
            return 1;
        }
    };

    match submit_envelope(&client, context, args, &signed_xdr, Some(&recorder)).await {
        Ok((xdr, sub_result)) => {
            let result = PayResult {
                envelope_xdr: xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "build+sign+submit".to_owned(),
                selected_fee_per_op_stroops: Some(fee_selection.per_op_stroops),
                selected_fee_percentile: Some(fee_selection.selected_fee_percentile),
                cross_check: Some(cross_check.view()),
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(e) => {
            print_error(
                &crate::commands::submission_record::error_envelope(&e, &signed_xdr, "pay"),
                args.output,
            );
            1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build helper
// ─────────────────────────────────────────────────────────────────────────────

/// The build arguments a stage checks before its first request.
#[derive(Debug, Clone, Copy)]
struct BuildInputs<'a> {
    /// The `--source` account.
    source: &'a str,
    /// The parsed `--fee` choice.
    fee_choice: ClassicFeeChoice,
}

/// Checks the build arguments that need no request: `--source` is present and
/// `--fee` parses.
///
/// # Errors
///
/// Returns `validation.address_invalid` when `--source` is absent, or the
/// refusal of [`parse_classic_fee_choice`].
fn build_inputs(args: &PayArgs) -> Result<BuildInputs<'_>, WalletError> {
    let source = args.source.as_deref().ok_or_else(|| {
        WalletError::Validation(stellar_agent_core::error::ValidationError::AddressInvalid {
            input: "--source is required for building a transaction".to_owned(),
        })
    })?;
    let fee_choice = parse_classic_fee_choice(args.fee.as_deref())?;
    Ok(BuildInputs { source, fee_choice })
}

/// Builds the client a stage reads and sends through, and checks that its
/// endpoint serves the network of `context`, under a fresh budget of
/// `--timeout-seconds`.
///
/// # Errors
///
/// Returns the construction failure or the refusal of
/// [`check_endpoint_identity`].
async fn checked_client(
    context: &NetworkContext,
    args: &PayArgs,
) -> Result<StellarRpcClient, WalletError> {
    let client = context.primary_client()?;
    check_endpoint_identity(&client, context, Duration::from_secs(args.timeout_seconds)).await?;
    Ok(client)
}

/// Checks the build arguments, then builds and checks the client of
/// `--build-only`.
///
/// The argument checks need no request, and `--build-only` has no reconcile,
/// so they keep their place ahead of the endpoint check.
///
/// # Errors
///
/// Returns the refusal of [`build_inputs`] or of [`checked_client`].
async fn checked_client_and_build_inputs<'a>(
    context: &NetworkContext,
    args: &'a PayArgs,
) -> Result<(StellarRpcClient, BuildInputs<'a>), WalletError> {
    let inputs = build_inputs(args)?;
    let client = checked_client(context, args).await?;
    Ok((client, inputs))
}

/// Constructs and returns the unsigned transaction envelope XDR.
///
/// Reads the fee, the source sequence, the SEP-29 data entry, and the
/// destination view through `client`, whose endpoint the caller has checked.
/// Runs SEP-29 memo-required check before building.
async fn build_unsigned_envelope(
    client: &StellarRpcClient,
    context: &NetworkContext,
    args: &PayArgs,
    inputs: BuildInputs<'_>,
) -> Result<BuiltPaymentEnvelope, WalletError> {
    let BuildInputs { source, fee_choice } = inputs;
    let fee_selection =
        resolve_classic_fee_selection(client, DEFAULT_FEE_STROOPS, fee_choice).await?;

    // Fetch source account to get sequence number and verify it exists.
    // Pass empty slice: pay only needs the account sequence number (native balance
    // is sufficient); no trustlines are queried here.
    let source_account = stellar_agent_network::fetch_account(client, source, &[]).await?;
    // Pass the current on-chain sequence directly; `stellar_baselib::TransactionBuilder::build`
    // calls `Account::increment_sequence_number` internally. An explicit +1
    // here would produce CURRENT+2 → TxBadSeq.
    let sequence_number = source_account.sequence_number;

    // Boundary discipline: parse_with_unit is the only permitted parser for
    // human-supplied amounts at CLI boundaries. Raw stroop numeric strings are
    // explicitly rejected to enforce unit discipline. If stroop-level input is
    // required in the future, add a dedicated `--amount-in-stroops` flag.
    let amount = StellarAmount::parse_with_unit(&args.amount).map_err(|_| {
        WalletError::Validation(ValidationError::AmountMalformed {
            input: args.amount.clone(),
        })
    })?;

    // Parse asset.
    let asset = Asset::parse(&args.asset)?;

    // Parse memo.
    let memo = parse_memo(args)?;
    let memo_present = !matches!(memo, Memo::None);

    // SEP-29: check memo-required BEFORE signing. The observation feeds the
    // witness, which compares the flag on the oracle.
    let memo_observation =
        stellar_agent_network::sep29::check_memo_required(client, &args.destination, memo_present)
            .await?;

    // Build.
    let mut builder = ClassicOpBuilder::new(
        source,
        sequence_number,
        context.network_passphrase(),
        fee_selection.per_op_stroops,
    );

    builder.payment(&args.destination, amount, &asset)?;
    builder.memo(&memo)?;

    let envelope_xdr = builder.build()?;

    // Destination-derived identity view for the policy gate's
    // `home_domain_resolved` criterion, read on the SAME client (same RPC
    // timeout budget as the source fetch above). An absent destination is
    // `None`: a not-yet-created destination has no on-chain state to resolve
    // `home_domain` from.
    let dest_account_view = read_destination(client, &args.destination).await?;

    Ok(BuiltPaymentEnvelope {
        envelope_xdr,
        fee_selection,
        fee_choice,
        asset,
        memo_observation,
        amount_stroops: amount.as_stroops(),
        asset_raw: args.asset.clone(),
        destination: args.destination.clone(),
        source_account_view: source_account,
        dest_account_view,
    })
}

/// Reads the destination account on the primary.
///
/// Only `AccountNotFound` means absence; any other read error refuses with
/// its own code, so a transient primary failure is never taken for an absent
/// destination and compared against the oracle as such.
///
/// # Errors
///
/// Returns every read error other than `network.account_not_found`.
async fn read_destination(
    client: &StellarRpcClient,
    destination: &str,
) -> Result<Option<stellar_agent_network::AccountView>, WalletError> {
    match stellar_agent_network::fetch_account(client, destination, &[]).await {
        Ok(view) => Ok(Some(view)),
        Err(WalletError::Network(NetworkError::AccountNotFound { .. })) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The primary observations a payment stage's decision used.
struct PaymentObservations<'a> {
    /// The source account view the build or the staged gate read.
    source_view: &'a stellar_agent_network::AccountView,
    /// The destination G account.
    destination: &'a str,
    /// The destination view, `None` when the destination does not exist.
    dest_view: Option<&'a stellar_agent_network::AccountView>,
    /// The SEP-29 observation.
    memo: MemoObservation,
    /// The asset the source sends.
    asset: &'a Asset,
    /// The source debit in the send asset's base units.
    amount_stroops: i64,
}

/// Obtains the cross-check witness of a payment stage.
///
/// The witness is valued on the source debit leg, and for an issued send
/// asset it reads the source's trustline on the primary and compares it with
/// the oracle alongside the source, the destination, and the SEP-29 flag.
///
/// # Errors
///
/// Returns `validation.asset_invalid` for a send asset outside the canonical
/// classic alphabet, the primary trustline read's refusal, and every refusal
/// of [`obtain_classic_witness`].
async fn witness_payment(
    client: &StellarRpcClient,
    context: &NetworkContext,
    profile: &Profile,
    observed: PaymentObservations<'_>,
    tool: &'static str,
) -> Result<CrossCheckOutcome, WalletError> {
    let canonical = observed.asset.to_canonical()?;
    let source = AccountObservation::from_view(observed.source_view)?;
    let trustline = TrustlineObservation::read_send_asset(
        client,
        &observed.source_view.account_id,
        observed.asset,
    )
    .await?;
    obtain_classic_witness(
        profile,
        context,
        stellar_agent_core::cross_check::CrossCheckValue::Amount {
            asset: &canonical,
            base_units: i128::from(observed.amount_stroops),
        },
        PayWitnessInputs {
            source,
            destination: DestinationObservation::from_view(
                observed.destination,
                observed.dest_view,
            ),
            memo: observed.memo,
            trustline,
        },
        tool,
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator policy gate
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluates operator policy for the built payment leg, using the same
/// engine path (and `stellar_pay` value descriptor contract) the
/// `stellar_pay` MCP tool's dispatch gate uses.
///
/// Returns `None` when the operation is allowed (the caller proceeds to
/// signing); returns `Some(exit_code)` — with the refusal envelope already
/// rendered — when the operation must be refused.
///
/// `profile` is the profile `run_with_dependencies` loaded at entry and passed
/// to `run_build_only` / `run_full_pipeline`. This function does not
/// re-resolve it. The platform keyring store the caller initialised therefore
/// stays registered for the `build_v1_policy_engine` owner-key read below.
/// `run_build_only` initialises the store only for a non-`Noop` engine;
/// `run_full_pipeline` always does, ahead of its origin-aware audit pre-flight.
fn evaluate_pay_policy(
    args: &PayArgs,
    built: &BuiltPaymentEnvelope,
    chain_id: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, i32> {
    let policy_engine =
        match build_v1_policy_engine("pay", &profile.policy.engine, profile, profile_name) {
            Ok(pe) => pe,
            Err(msg) => {
                print_error(
                    &Envelope::<()>::err_raw("policy.engine_unavailable", msg),
                    args.output,
                );
                return Err(1);
            }
        };
    // Mirrors the `stellar_pay` MCP tool's dispatch args exactly: resolved
    // stroops, the raw (unreformatted) asset string, and the destination.
    let policy_args = pay_policy_args(built.amount_stroops, &built.asset_raw, &built.destination);
    // `account_view` reuses the source-account state `build_unsigned_envelope`
    // already fetched (feeds `minimum_reserve`); `identity_view` reuses the
    // destination-account state the same function fetched (`.ok()`-optional,
    // `None` when the destination does not yet exist) (feeds
    // `home_domain_resolved`) — mirroring the `stellar_pay` MCP twin exactly.
    let source_adapter =
        stellar_agent_network::policy_view::AccountViewAdapter::new(&built.source_account_view);
    let dest_adapter = built
        .dest_account_view
        .as_ref()
        .map(stellar_agent_network::policy_view::AccountViewAdapter::new);
    match evaluate_value_moving_policy(
        policy_engine.as_ref(),
        profile,
        "stellar_pay",
        stellar_agent_core::policy::ToolValueKind::MovesValue,
        chain_id,
        &policy_args,
        "pay",
        Some(&source_adapter),
        dest_adapter.as_ref().map(|a| a as &dyn AccountIdentityView),
    ) {
        Ok(effects) => Ok(effects),
        Err(envelope) => {
            print_error(&envelope, args.output);
            Err(1)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sign helper
// ─────────────────────────────────────────────────────────────────────────────

/// Signs the given base64 XDR envelope using the configured signer.
///
/// # Signing path selection
///
/// - `--sign-with-ledger`: delegates to `signer_from_ledger` (hardware; no
///   seed ever held in process memory).
/// - `--secret-env VAR`: derives a `SoftwareSigningKey` via the shared
///   [`crate::common::signer_ceremony::resolve_software_signer_from_env`]
///   ceremony (mlock-protected `Wallet` unlock, `signer_from_wallet`, wallet
///   dispose), then calls `attach_signature` once and drops the key.
///
/// # Public-key verification
///
/// For the `--secret-env` path, the public key derived from the seed is
/// compared against `--source` BEFORE any signing or RPC call, mirroring
/// the invariant in `signing::source::signer_from_s_strkey`.
///
/// # Errors
///
/// Propagates `WalletError` from seed parsing, `Wallet::unlock`, signing, or
/// mlock failures. Returns `ValidationError::SignerSourceRequired` when neither
/// signer flag is provided.
async fn sign_envelope(
    context: &NetworkContext,
    args: &PayArgs,
    unsigned_xdr: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<String, WalletError> {
    let source = args.source.as_deref().ok_or_else(|| {
        WalletError::Validation(stellar_agent_core::error::ValidationError::AddressInvalid {
            input: "--source is required for signing".to_owned(),
        })
    })?;

    let passphrase = context.network_passphrase();

    let signer: Box<dyn Signer + Send + Sync> =
        match (args.sign_with_ledger, args.secret_env.as_deref()) {
            (true, _) => Box::new(signer_from_ledger(args.account_index, source).await?),
            (false, Some(var_name)) => {
                let SignerCeremonyOutcome {
                    signer,
                    mlock_degradation: _,
                } = resolve_software_signer_from_env(var_name, "pay-commit", profile).await?;
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

/// Submits `signed_xdr` through `client`, the client the stage checked and
/// read through, under a fresh budget of `--timeout-seconds`.
async fn submit_envelope(
    client: &StellarRpcClient,
    context: &NetworkContext,
    args: &PayArgs,
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
// Memo parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parses memo arguments into an XDR `Memo`.
///
/// Delegates to [`stellar_agent_network::parse_memo_fields`], the shared
/// implementation for both the CLI pay command and the `stellar_pay` MCP tool.
fn parse_memo(args: &PayArgs) -> Result<Memo, WalletError> {
    parse_memo_fields(
        args.memo_text.as_deref(),
        args.memo_id,
        args.memo_hash_hex.as_deref(),
        args.memo_return_hex.as_deref(),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Relayer opt-in gate
// ─────────────────────────────────────────────────────────────────────────────

/// Checks whether `--use-oz-relayer` was set and, if so, emits the AGPL-3.0
/// disclosure banner to stderr and returns a typed refuse error.
///
/// This function is the **sole** enforcement point for the informed-consent
/// discipline. It must be called AFTER network/arg validation gates (e.g.
/// mainnet reject) but BEFORE any keyring/signer touch or RPC client
/// construction, so that the refuse path provably loads no secret and performs
/// no network call.
///
/// When `args.use_oz_relayer` is `false`, returns `Ok(())` and the call site
/// continues normally.
///
/// # Errors
///
/// Returns `Err(WalletError::Validation(ValidationError::RelayerNotImplemented))`
/// when `args.use_oz_relayer` is `true`.
pub fn check_relayer_opt_in(args: &PayArgs) -> Result<(), WalletError> {
    if args.use_oz_relayer {
        #[allow(
            clippy::print_stderr,
            reason = "AGPL-3.0 disclosure for the relayer opt-in"
        )]
        {
            eprintln!();
            eprintln!("{}", RELAYER_AGPL_DISCLOSURE);
            eprintln!();
        }
        return Err(WalletError::Validation(
            ValidationError::RelayerNotImplemented,
        ));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn print_success(envelope: &Envelope<PayResult>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(result) = &envelope.data {
                match (&result.tx_hash, &result.ledger) {
                    (Some(hash), Some(ledger)) => {
                        // Use redact_tx_hash from stellar-agent-network::submit.
                        use stellar_agent_network::submit::redact_tx_hash;
                        let selected_fee = crate::render::table::render_selected_fee_line(
                            result.selected_fee_per_op_stroops,
                            result.selected_fee_percentile.as_deref(),
                        );
                        println!(
                            "Payment submitted: tx_hash {}  ledger {}\n{}",
                            redact_tx_hash(hash),
                            ledger,
                            selected_fee
                        );
                        if let Some(cross_check) = &result.cross_check {
                            println!("{}", cross_check.text_line());
                        }
                    }
                    _ => {
                        // Build or sign stage. Use chars().take(32) to avoid a
                        // byte-boundary panic on multi-byte UTF-8 input.
                        let prefix: String = result.envelope_xdr.chars().take(32).collect();
                        let selected_fee = crate::render::table::render_selected_fee_line(
                            result.selected_fee_per_op_stroops,
                            result.selected_fee_percentile.as_deref(),
                        );
                        println!(
                            "[{}] envelope_xdr (first 32 chars): {}...\n{}",
                            result.stage, prefix, selected_fee
                        );
                        if let Some(cross_check) = &result.cross_check {
                            println!("{}", cross_check.text_line());
                        }
                    }
                }
            }
        }
        // Json and all unknown formats: delegate to shared render_json.
        _ => render_json(envelope),
    }
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                // Sanitize to strip terminal-escape sequences from the message.
                let safe_msg = sanitize_for_table(&err.message);
                println!("Error: {} — {}", err.code, safe_msg);
            }
        }
        // Json and all unknown formats: delegate to shared render_json.
        _ => render_json(envelope),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, reason = "test spies reject keyring access")]
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use std::sync::Arc;

    use super::*;
    use crate::common::signer_ceremony::test_fixtures::{
        EnrolledPin, assert_enrolled_outcome, enrolled_mainnet_profile, enrolled_test_g,
        enrolled_test_secret,
    };
    use crate::test_rpc::{EnvSigner, absent_profile_file, zero_config};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

    const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    struct PayBuildRpcResponder {
        account_key_xdr: String,
        account_xdr: String,
        fee_stats: Arc<serde_json::Value>,
    }

    impl PayBuildRpcResponder {
        fn new(account_key_xdr: String, account_xdr: String, fee_stats: serde_json::Value) -> Self {
            Self {
                account_key_xdr,
                account_xdr,
                fee_stats: Arc::new(fee_stats),
            }
        }
    }

    #[async_trait::async_trait]
    impl Respond for PayBuildRpcResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let request_value = serde_json::from_slice::<serde_json::Value>(&request.body)
                .unwrap_or_else(|_| serde_json::json!({}));
            let req_id = request_value
                .get("id")
                .cloned()
                .unwrap_or_else(|| serde_json::json!(1));
            let method = request_value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            let result = match method {
                "getNetwork" => stellar_agent_test_support::signed_envelope::get_network_result(
                    stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE,
                ),
                "getFeeStats" => (*self.fee_stats).clone(),
                "getLedgerEntries" => {
                    let body = String::from_utf8_lossy(&request.body);
                    if body.contains(&self.account_key_xdr) {
                        serde_json::json!({
                            "entries": [{
                                "key": self.account_key_xdr,
                                "xdr": self.account_xdr,
                                "lastModifiedLedgerSeq": 1000
                            }],
                            "latestLedger": 1001
                        })
                    } else {
                        serde_json::json!({
                            "entries": [],
                            "latestLedger": 1001
                        })
                    }
                }
                _ => serde_json::json!({}),
            };

            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": result,
                }))
                .insert_header("content-type", "application/json")
        }
    }

    fn account_entry_xdr_with_balance(account_id: &str, balance_stroops: i64) -> String {
        use stellar_xdr::{
            AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
            SequenceNumber, String32, Thresholds, Uint256, WriteXdr,
        };
        let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
            .expect("valid account_id")
            .0;
        let entry = AccountEntry {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
            balance: balance_stroops,
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

    fn account_ledger_key_xdr(account_id: &str) -> String {
        use stellar_xdr::{
            AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
        };
        let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id)
            .expect("valid account_id")
            .0;
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        });
        key.to_xdr_base64(Limits::none())
            .expect("XDR encoding must succeed")
    }

    fn fee_stat_json(p95: &str, p99: &str) -> serde_json::Value {
        serde_json::json!({
            "max": "1000",
            "min": "100",
            "mode": "100",
            "p10": "100",
            "p20": "110",
            "p30": "120",
            "p40": "130",
            "p50": "140",
            "p60": "150",
            "p70": "160",
            "p80": "170",
            "p90": "180",
            "p95": p95,
            "p99": p99,
            "transactionCount": "12",
            "ledgerCount": "5"
        })
    }

    fn fee_stats_result(p95: &str, p99: &str) -> serde_json::Value {
        serde_json::json!({
            "sorobanInclusionFee": fee_stat_json("300", "400"),
            "inclusionFee": fee_stat_json(p95, p99),
            "latestLedger": "12345"
        })
    }

    fn tx_fee_from_envelope_xdr(envelope_xdr: &str) -> u32 {
        use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

        let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none())
            .expect("valid transaction envelope");
        assert!(
            matches!(envelope, TransactionEnvelope::Tx(_)),
            "expected v1 transaction envelope"
        );
        if let TransactionEnvelope::Tx(env) = envelope {
            env.tx.fee
        } else {
            0
        }
    }

    /// Builds the envelope through a client of its own, without the endpoint
    /// check a stage runs first: these tests are about what the build reads
    /// and produces.
    async fn build_with_client(
        context: &NetworkContext,
        args: &PayArgs,
    ) -> Result<BuiltPaymentEnvelope, WalletError> {
        let client = StellarRpcClient::new(&context.rpc_url)?;
        build_unsigned_envelope(&client, context, args, build_inputs(args)?).await
    }

    async fn mount_pay_build_rpc(p95: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(PayBuildRpcResponder::new(
                account_ledger_key_xdr(SOURCE_G),
                account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
                fee_stats_result(p95, "999"),
            ))
            .mount(&server)
            .await;
        server
    }

    // ── Clap three-stage and memo/signer mutex tests ─────────────────────────

    /// Helper: build a minimal arg list for PayArgs.
    fn base_args() -> Vec<&'static str> {
        vec![
            "pay",
            "GDEST1234567890ABCDEF1234567890ABCDEF1234567890ABCDEFGH",
            "10 XLM",
        ]
    }

    /// Parse `PayArgs` from a vec of string slices via the Command interface.
    fn try_parse_pay(args: &[&str]) -> Result<PayArgs, clap::Error> {
        use clap::Parser;

        // We need a wrapper struct to act as the top-level parser.
        #[derive(Debug, clap::Parser)]
        struct TestPay {
            #[command(flatten)]
            args: PayArgs,
        }

        TestPay::try_parse_from(args).map(|t| t.args)
    }

    #[test]
    fn clap_build_only_and_sign_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--build-only", "--sign-only", "AAAAAA=="]);
        let result = try_parse_pay(&args);
        assert!(
            result.is_err(),
            "--build-only + --sign-only must conflict: {result:?}"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "expected ArgumentConflict, got: {err}"
        );
    }

    #[test]
    fn clap_build_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--build-only", "--submit-only", "AAAAAA=="]);
        let result = try_parse_pay(&args);
        assert!(
            result.is_err(),
            "--build-only + --submit-only must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_sign_only_and_submit_only_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--sign-only", "AAAAAA==", "--submit-only", "AAAAAA=="]);
        let result = try_parse_pay(&args);
        assert!(result.is_err(), "--sign-only + --submit-only must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_memo_text_and_memo_id_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--memo-text", "hello", "--memo-id", "42"]);
        let result = try_parse_pay(&args);
        assert!(result.is_err(), "--memo-text + --memo-id must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_memo_text_and_memo_hash_are_mutually_exclusive() {
        let mut args = base_args();
        let hash = "0".repeat(64);
        args.push("--memo-text");
        args.push("hello");
        args.push("--memo-hash");
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut args_owned2 = args_owned;
        args_owned2.push(hash);
        let result: Result<PayArgs, clap::Error> = {
            use clap::Parser;
            #[derive(Debug, clap::Parser)]
            struct TestPay {
                #[command(flatten)]
                args: PayArgs,
            }
            TestPay::try_parse_from(&args_owned2).map(|t| t.args)
        };
        assert!(result.is_err(), "--memo-text + --memo-hash must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn clap_secret_env_and_sign_with_ledger_are_mutually_exclusive() {
        let mut args = base_args();
        args.extend(["--secret-env", "MY_SECRET", "--sign-with-ledger"]);
        let result = try_parse_pay(&args);
        assert!(
            result.is_err(),
            "--secret-env + --sign-with-ledger must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    // ── Network / amount tests ────────────────────────────────────────────────

    #[test]
    fn target_network_variant_rejects_unknown_network_string() {
        use std::str::FromStr;
        assert!(TargetNetwork::from_str("futurenet").is_err());
    }

    #[test]
    fn target_network_variant_round_trips() {
        use std::str::FromStr;
        assert_eq!(
            TargetNetwork::from_str("testnet").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("TESTNET").unwrap(),
            TargetNetwork::Testnet
        );
        assert_eq!(
            TargetNetwork::from_str("mainnet").unwrap(),
            TargetNetwork::Mainnet
        );
    }

    /// The mainnet-write-forbidden error code is `"network.mainnet_write_forbidden"`.
    ///
    /// This test would fail if the `MainnetWriteForbidden` variant were removed
    /// or its wire code changed, ensuring the refusal produces the correct
    /// structured error downstream tooling relies on.
    #[test]
    fn mainnet_write_forbidden_error_has_correct_code() {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        assert_eq!(
            err.code(),
            "network.mainnet_write_forbidden",
            "wire code must be 'network.mainnet_write_forbidden'"
        );
        assert!(
            matches!(
                err,
                WalletError::Network(NetworkError::MainnetWriteForbidden)
            ),
            "must be WalletError::Network(NetworkError::MainnetWriteForbidden)"
        );
    }

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
        let args = PayArgs {
            profile: Some("guard-mainnet".into()),
            destination: "GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH".to_owned(),
            amount: "10 XLM".to_owned(),
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            fee: None,
            source: Some("GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH".to_owned()),
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            build_only: false,
            sign_only: None,
            submit_only: None,
            network: Some(TargetNetwork::Mainnet),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: None,
            use_oz_relayer: false,
        };
        let exit = run_with_dependencies(
            &args,
            |name| {
                Ok(
                    Profile::builder_mainnet_named(name, guard_rpc.uri(), "s", "default", "n", "a")
                        .build(),
                )
            },
            || panic!("mainnet must not initialize the keyring"),
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
        let args = PayArgs {
            profile: None,
            destination: "GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH".to_owned(),
            amount: "10 XLM".to_owned(),
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            fee: None,
            source: Some("GABC1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGH".to_owned()),
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            build_only: false,
            sign_only: None,
            submit_only: None,
            network: Some(TargetNetwork::Mainnet),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(guard_rpc.uri()),
            use_oz_relayer: false,
        };
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

    // Note: decode_32_hex_bytes and hex_nibble are now in
    // stellar_agent_network::memo; their unit tests live there.
    // The parse_memo tests below exercise the thin CLI wrapper.

    #[test]
    fn parse_memo_none() {
        let args = minimal_args();
        let memo = parse_memo(&args).unwrap();
        assert!(matches!(memo, Memo::None));
    }

    #[test]
    fn parse_memo_text() {
        let mut args = minimal_args();
        args.memo_text = Some("hello".to_owned());
        let memo = parse_memo(&args).unwrap();
        assert!(matches!(memo, Memo::Text(_)));
    }

    #[test]
    fn parse_memo_text_too_long() {
        let mut args = minimal_args();
        args.memo_text = Some("a".repeat(29));
        assert!(parse_memo(&args).is_err());
    }

    #[test]
    fn parse_memo_id() {
        let mut args = minimal_args();
        args.memo_id = Some(42);
        let memo = parse_memo(&args).unwrap();
        assert!(matches!(memo, Memo::Id(_)));
    }

    #[tokio::test]
    async fn pay_cli_explicit_fee_surfaces_metadata() {
        let server = mount_pay_build_rpc("333").await;
        let mut args = minimal_args();
        args.source = Some(SOURCE_G.to_owned());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.fee = Some("250".to_owned());
        args.rpc_url = Some(server.uri());

        let built = build_with_client(&flag_context(&args), &args)
            .await
            .expect("explicit fee build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, 250);
        assert_eq!(built.fee_selection.selected_fee_percentile, "explicit");
        assert_eq!(tx_fee_from_envelope_xdr(&built.envelope_xdr), 250);

        let result = PayResult {
            envelope_xdr: built.envelope_xdr,
            tx_hash: None,
            ledger: None,
            stage: "build".to_owned(),
            selected_fee_per_op_stroops: Some(built.fee_selection.per_op_stroops),
            selected_fee_percentile: Some(built.fee_selection.selected_fee_percentile),
            cross_check: None,
        };
        let json = serde_json::to_value(result).expect("PayResult serialises");
        assert_eq!(json["selected_fee_per_op_stroops"], "250");
        assert_eq!(json["selected_fee_percentile"], "explicit");
    }

    #[test]
    fn pay_result_selected_fee_per_op_stroops_none_round_trips() {
        // The `with = "...::u32_opt"` custom deserializer suppresses serde's
        // implicit missing-field-means-None for `Option<T>`; `#[serde(default)]`
        // restores it. Without it, deserializing this None-produced,
        // field-omitted JSON would fail with "missing field
        // `selected_fee_per_op_stroops`".
        let result = PayResult {
            envelope_xdr: "AAAA".to_owned(),
            tx_hash: None,
            ledger: None,
            stage: "build".to_owned(),
            selected_fee_per_op_stroops: None,
            selected_fee_percentile: None,
            cross_check: None,
        };
        let json = serde_json::to_value(&result).expect("PayResult serialises");
        assert!(json.get("selected_fee_per_op_stroops").is_none());

        let round_tripped: PayResult = serde_json::from_value(json)
            .expect("omitted selected_fee_per_op_stroops must deserialize back to None");
        assert_eq!(round_tripped.selected_fee_per_op_stroops, None);
    }

    /// The `cross_check` field is omitted when absent, round-trips when set,
    /// and a result written without the field deserializes to `None`.
    #[test]
    fn pay_result_cross_check_field_shape() {
        let mut result = PayResult {
            envelope_xdr: "AAAA".to_owned(),
            tx_hash: Some("ab".repeat(32)),
            ledger: Some(7),
            stage: "build+sign+submit".to_owned(),
            selected_fee_per_op_stroops: Some(100),
            selected_fee_percentile: Some("profile_default".to_owned()),
            cross_check: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("cross_check").is_none(), "{json}");

        result.cross_check = Some(CrossCheckView {
            status: "passed".to_owned(),
            reason: None,
            provider: Some("https://oracle.example".to_owned()),
            ledger: Some(1001),
        });
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(
            json["cross_check"],
            serde_json::json!({"status": "passed", "provider": "https://oracle.example",
                "ledger": 1001})
        );
        let back: PayResult = serde_json::from_value(json).unwrap();
        assert_eq!(back.cross_check, result.cross_check);

        let legacy = serde_json::json!({
            "envelope_xdr": "AAAA",
            "tx_hash": "ab".repeat(32),
            "ledger": 7,
            "stage": "build+sign+submit",
            "selected_fee_per_op_stroops": "100",
            "selected_fee_percentile": "profile_default"
        });
        let legacy: PayResult =
            serde_json::from_value(legacy).expect("a result without cross_check deserializes");
        assert_eq!(legacy.cross_check, None);
        assert_eq!(legacy.ledger, Some(7));
    }

    #[tokio::test]
    async fn pay_cli_default_fee_surfaces_profile_default() {
        let server = mount_pay_build_rpc("333").await;
        let mut args = minimal_args();
        args.source = Some(SOURCE_G.to_owned());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.rpc_url = Some(server.uri());

        let built = build_with_client(&flag_context(&args), &args)
            .await
            .expect("default fee build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, DEFAULT_FEE_STROOPS);
        assert_eq!(
            built.fee_selection.selected_fee_percentile,
            "profile_default"
        );
    }

    #[tokio::test]
    async fn pay_builder_uses_context_endpoint() {
        let primary = mount_pay_build_rpc("333").await;
        let ignored = mount_pay_build_rpc("333").await;
        let mut args = minimal_args();
        args.source = Some(SOURCE_G.to_owned());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.rpc_url = Some(ignored.uri());
        let mut profile = stellar_agent_core::profile::Profile::builder_testnet(
            "signer", "default", "nonce", "default",
        )
        .build();
        profile.rpc_url = primary.uri();
        let context = NetworkContext::from_profile(&profile);
        let (client, inputs) = checked_client_and_build_inputs(&context, &args)
            .await
            .expect("the context endpoint passes the endpoint check");
        build_unsigned_envelope(&client, &context, &args, inputs)
            .await
            .expect("context endpoint builds");
        let methods: Vec<String> = primary
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            methods.first().map(String::as_str),
            Some("getNetwork"),
            "the context endpoint must answer the endpoint check first: {methods:?}"
        );
        assert!(
            methods.iter().any(|m| m == "getLedgerEntries"),
            "the context endpoint must receive the account fetch: {methods:?}"
        );
        assert!(
            ignored.received_requests().await.unwrap().is_empty(),
            "the args endpoint must remain unused"
        );
    }

    #[tokio::test]
    async fn pay_cli_auto_fee_surfaces_p95() {
        let server = mount_pay_build_rpc("333").await;
        let mut args = minimal_args();
        args.source = Some(SOURCE_G.to_owned());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.fee = Some("auto".to_owned());
        args.rpc_url = Some(server.uri());

        let built = build_with_client(&flag_context(&args), &args)
            .await
            .expect("auto fee build succeeds");
        assert_eq!(built.fee_selection.per_op_stroops, 333);
        assert_eq!(built.fee_selection.selected_fee_percentile, "p95");
        assert_eq!(tx_fee_from_envelope_xdr(&built.envelope_xdr), 333);
    }

    /// Constructs a minimal `PayArgs` with default values for fields not under test.
    fn minimal_args() -> PayArgs {
        PayArgs {
            // Zero-config group: `None` is "no profile named", the path that
            // still synthesizes. `Some("default")` would be an explicitly
            // named profile and would refuse instead.
            profile: None,
            destination: "GABC".to_owned(),
            amount: "10 XLM".to_owned(),
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            fee: None,
            source: None,
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
            use_oz_relayer: false,
        }
    }

    /// The context a testnet profile yields for the endpoint flags of `args`.
    fn flag_context(args: &PayArgs) -> NetworkContext {
        NetworkContext::new(
            args.network.unwrap_or(TargetNetwork::Testnet).caip2(),
            args.rpc_url
                .clone()
                .unwrap_or_else(|| crate::common::network::TESTNET_RPC_URL.to_owned()),
        )
    }

    // ── --use-oz-relayer opt-in gate ──────────────────────────────────────────

    /// `--use-oz-relayer` parses into `PayArgs.use_oz_relayer == true`.
    #[test]
    fn clap_use_oz_relayer_flag_parses_true() {
        let mut args = base_args();
        args.push("--use-oz-relayer");
        let parsed = try_parse_pay(&args).expect("--use-oz-relayer must parse");
        assert!(parsed.use_oz_relayer, "use_oz_relayer must be true");
    }

    /// Absent `--use-oz-relayer` defaults to `false`.
    #[test]
    fn clap_use_oz_relayer_flag_absent_defaults_false() {
        let args = base_args();
        let parsed = try_parse_pay(&args).expect("base args must parse");
        assert!(
            !parsed.use_oz_relayer,
            "use_oz_relayer must default to false"
        );
    }

    /// `--use-oz-relayer` is NOT mutually exclusive with `--secret-env` or
    /// `--build-only`; it parses successfully alongside them.
    #[test]
    fn clap_use_oz_relayer_not_exclusive_with_signer_flags() {
        let mut args = base_args();
        args.extend(["--use-oz-relayer", "--secret-env", "MY_KEY"]);
        let parsed = try_parse_pay(&args).expect("--use-oz-relayer + --secret-env must parse");
        assert!(parsed.use_oz_relayer);
        assert_eq!(parsed.secret_env.as_deref(), Some("MY_KEY"));
    }

    /// `--use-oz-relayer` is NOT mutually exclusive with `--build-only`.
    #[test]
    fn clap_use_oz_relayer_not_exclusive_with_build_only() {
        let mut args = base_args();
        args.extend(["--use-oz-relayer", "--build-only"]);
        let parsed = try_parse_pay(&args).expect("--use-oz-relayer + --build-only must parse");
        assert!(parsed.use_oz_relayer);
        assert!(parsed.build_only);
    }

    /// When `use_oz_relayer` is set, `check_relayer_opt_in` returns the typed
    /// refuse error without loading any secret or performing any network call.
    #[test]
    fn check_relayer_opt_in_returns_relayer_not_implemented_when_set() {
        let mut args = minimal_args();
        args.use_oz_relayer = true;
        let result = check_relayer_opt_in(&args);
        assert!(
            result.is_err(),
            "must return Err when use_oz_relayer is true"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.code(),
            "validation.relayer_not_implemented",
            "wire code must be 'validation.relayer_not_implemented'"
        );
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::RelayerNotImplemented)
            ),
            "must be WalletError::Validation(ValidationError::RelayerNotImplemented)"
        );
    }

    /// When `use_oz_relayer` is `false`, `check_relayer_opt_in` returns `Ok(())`.
    #[test]
    fn check_relayer_opt_in_returns_ok_when_not_set() {
        let args = minimal_args();
        assert!(
            check_relayer_opt_in(&args).is_ok(),
            "must return Ok when use_oz_relayer is false"
        );
    }

    /// The `run()` path with `use_oz_relayer = true` returns exit code 1 and
    /// does NOT perform any network call (non-routable RPC address ensures any
    /// accidental call would fail with a connection error rather than silently
    /// succeeding).  The refuse gate is wired before any stage dispatch.
    #[tokio::test]
    async fn relayer_opt_in_exits_nonzero_without_network_call() {
        let mut args = minimal_args();
        args.use_oz_relayer = true;
        // Non-routable address: any accidental RPC call would produce a
        // connection error, making an accidentally-passing test impossible.
        args.rpc_url = Some("http://127.0.0.1:1".to_owned());
        let exit = run(&args).await;
        assert_eq!(exit, 1, "relayer opt-in must exit with code 1");
    }

    /// The AGPL-3.0 disclosure constant contains the required claims that
    /// must be preserved by any future wording update.
    #[test]
    fn relayer_disclosure_constant_contains_required_claims() {
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("AGPL-3.0"),
            "disclosure must mention AGPL-3.0"
        );
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("WOULD subject"),
            "disclosure must use conditional phrasing 'WOULD subject'"
        );
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("links no AGPL code"),
            "legally load-bearing claim 'links no AGPL code' must be present verbatim"
        );
        assert!(
            RELAYER_AGPL_DISCLOSURE.contains("not implemented in this build"),
            "disclosure must state relayer is not implemented in this build"
        );
    }

    // ── keyring store initialisation ordering (issue #41) ────────────────────

    /// The platform keyring store must be initialised before the V1 policy
    /// gate's owner-key read (`build_v1_policy_engine`), on both gated
    /// stages (`--build-only` here). Both dependencies are injected, so no
    /// OS keychain or on-disk profile is touched and no process-global
    /// keyring store is registered — hence this test needs no `#[serial]`.
    /// The injected initialiser returns an error so the run bails at that
    /// step, before `build_unsigned_envelope` ever runs, proving the
    /// initialisation happens ahead of any network build.
    #[tokio::test]
    async fn run_initialises_keyring_store_before_policy_gate() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let profile_loaded = Arc::new(AtomicBool::new(false));
        let init_invoked = Arc::new(AtomicBool::new(false));

        let loaded_writer = Arc::clone(&profile_loaded);
        let loaded_reader = Arc::clone(&profile_loaded);
        let init_writer = Arc::clone(&init_invoked);

        // `--build-only`: reaches `run_build_only`, which resolves the
        // profile and conditionally initialises the keyring store BEFORE
        // `build_unsigned_envelope` is called (`--source` is not consulted
        // until then), so the injected initialiser's error bails the run
        // before any network build.
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
    /// default), the keyring initialiser must NOT be invoked — the
    /// `Noop` engine never reads the owner key from the keyring.
    #[tokio::test]
    async fn run_does_not_initialise_keyring_when_engine_is_noop() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let init_invoked = Arc::new(AtomicBool::new(false));
        let init_writer = Arc::clone(&init_invoked);

        // `--build-only` with no `--source`: the profile loads (Noop engine)
        // and the keyring gate is skipped, then `build_unsigned_envelope`
        // refuses immediately on the missing `--source` — before any RPC
        // client construction — so this stays network-free.
        let mut args = minimal_args();
        args.build_only = true;

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
        )
        .await;

        assert!(
            !init_invoked.load(Ordering::SeqCst),
            "the Noop engine must never trigger the keyring store initialisation"
        );
        assert_eq!(
            code, 1,
            "missing --source must still refuse (unrelated to the keyring gate)"
        );
    }

    // ── Zero-config quickstart e2e: the synthesized profile stays fail-open ──

    /// Generates a fresh ed25519 keypair and returns `(G-strkey, S-strkey)`.
    fn fresh_keypair_strkeys() -> (String, String) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let g_strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
            .to_string()
            .to_string();
        let s_strkey = stellar_strkey::ed25519::PrivateKey(signing_key.to_bytes())
            .as_unredacted()
            .to_string()
            .to_string();
        (g_strkey, s_strkey)
    }

    /// The documented no-profile quickstart (`pay --secret-env ...` with no
    /// `<name>.toml` file) keeps working end to end even when the profile's
    /// audit chain-root key was never minted — proving the zero-config
    /// synthesized profile's audit pre-flight stays fail-open (ARCH B-1),
    /// unlike a persisted profile, which fails closed under the identical
    /// condition (see `value_audit::tests::for_origin_persisted_refuses_when_key_unminted`).
    ///
    /// Drives `run_with_dependencies` through `--sign-only` with the injected
    /// loader reporting `NotFound` and NO profile named (`args.profile` is
    /// `None` — the zero-config group), so the synthesis runs in the real
    /// choke point rather than being handed in ready-made: `Noop` engine, no
    /// audit chain-root key ever seeded at its keyring coordinate.
    /// `run_sign_only`'s gate still performs its source/destination account
    /// fetches (mocked here), so this exercises the real gate path, not merely
    /// the pure `dispatch_staged_pay_gate`.
    #[tokio::test]
    #[serial_test::serial]
    async fn zero_config_synthesized_profile_sign_only_succeeds_with_unminted_audit_key() {
        let _isolation = zero_config();
        let (source_g, source_s) = fresh_keypair_strkeys();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(PayBuildRpcResponder::new(
                account_ledger_key_xdr(&source_g),
                account_entry_xdr_with_balance(&source_g, 100_000_000_000),
                fee_stats_result("100", "200"),
            ))
            .mount(&server)
            .await;

        let mut args = minimal_args();
        args.source = Some(source_g.clone());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.rpc_url = Some(server.uri());

        let built = build_with_client(&flag_context(&args), &args)
            .await
            .expect("build must succeed against the mocked RPC");

        let var = "PAY_ZERO_CONFIG_E2E_TEST_SK";
        #[allow(
            unsafe_code,
            reason = "test-only process environment mutation; the variable name is unique \
                      to this test"
        )]
        // SAFETY: the variable name is unique to this test; no other test reads or
        // writes it.
        unsafe {
            std::env::set_var(var, &source_s);
        }
        args.secret_env = Some(var.to_owned());
        args.sign_only = Some(built.envelope_xdr);

        // The loader reports the profile file is absent; because no profile
        // was named, the choke point synthesizes the `Noop`-engine testnet
        // profile. Its audit chain-root key is unminted in the in-memory
        // keyring store `isolate_zero_config` installed, so the acquisition
        // genuinely fails and the synthesized-origin pre-flight is exercised
        // on its fail-open branch rather than short-circuiting on a key that
        // happens to exist on the host.
        let code = run_with_dependencies(&args, absent_profile_file, || Ok(())).await;

        #[allow(unsafe_code, reason = "test-only env cleanup")]
        // SAFETY: same as above.
        unsafe {
            std::env::remove_var(var);
        }

        assert_eq!(
            code, 0,
            "the zero-config quickstart must keep signing even though the \
             synthesized profile's audit chain-root key was never minted"
        );
    }

    /// Same zero-config quickstart as
    /// [`zero_config_synthesized_profile_sign_only_succeeds_with_unminted_audit_key`],
    /// but the injected `init_keyring` itself errors — modelling a host with
    /// no platform keyring store at all (e.g. a container without a Secret
    /// Service), not merely an unminted audit key. `init_keyring_for_origin`
    /// warns and continues for a synthesized profile, so the quickstart signs
    /// on a host without a platform keyring.
    #[tokio::test]
    #[serial_test::serial]
    async fn zero_config_synthesized_profile_sign_only_succeeds_when_keyring_init_fails() {
        let _isolation = zero_config();
        let (source_g, source_s) = fresh_keypair_strkeys();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(PayBuildRpcResponder::new(
                account_ledger_key_xdr(&source_g),
                account_entry_xdr_with_balance(&source_g, 100_000_000_000),
                fee_stats_result("100", "200"),
            ))
            .mount(&server)
            .await;

        let mut args = minimal_args();
        args.source = Some(source_g.clone());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.rpc_url = Some(server.uri());

        let built = build_with_client(&flag_context(&args), &args)
            .await
            .expect("build must succeed against the mocked RPC");

        let var = "PAY_ZERO_CONFIG_KEYRING_INIT_FAIL_TEST_SK";
        #[allow(
            unsafe_code,
            reason = "test-only process environment mutation; the variable name is unique \
                      to this test"
        )]
        // SAFETY: the variable name is unique to this test; no other test reads or
        // writes it.
        unsafe {
            std::env::set_var(var, &source_s);
        }
        args.secret_env = Some(var.to_owned());
        args.sign_only = Some(built.envelope_xdr);

        let code = run_with_dependencies(&args, absent_profile_file, || {
            Err(WalletError::Auth(AuthError::KeyringNotFound {
                name: "zero-config-keyring-init-failure-sentinel".to_owned(),
            }))
        })
        .await;

        #[allow(unsafe_code, reason = "test-only env cleanup")]
        // SAFETY: same as above.
        unsafe {
            std::env::remove_var(var);
        }

        assert_eq!(
            code, 0,
            "the zero-config quickstart must keep signing even when the platform \
             keyring store itself fails to initialise, not merely when the audit \
             chain-root key is unminted"
        );
    }

    /// A [`ProfileOrigin::Persisted`] profile's `--sign-only` run refuses when
    /// the platform keyring store cannot be initialised. It is the counterpart
    /// of the two zero-config tests above. An operator who authored a profile
    /// file is expected to have a working platform keyring, so
    /// `init_keyring_for_origin` treats this failure as fatal regardless
    /// of the resolved engine. `init_keyring_for_origin` returns before
    /// the injected `--sign-only` XDR is ever decoded, so the dummy value
    /// below is never parsed and no RPC client is constructed.
    #[tokio::test]
    async fn persisted_profile_sign_only_fails_when_keyring_init_fails() {
        let mut args = minimal_args();
        args.sign_only = Some("AAAAAA==".to_owned());

        let code = run_with_dependencies(
            &args,
            |name| {
                Ok(Profile::builder_testnet_named(
                    name,
                    "stellar-agent-signer",
                    name,
                    "stellar-agent-nonce",
                    name,
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build())
            },
            || {
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "persisted-profile-keyring-init-failure".to_owned(),
                }))
            },
        )
        .await;

        assert_eq!(
            code, 1,
            "a persisted profile must refuse when the platform keyring store \
             cannot be initialised, even though the resolved engine is Noop"
        );
    }

    // ── staged sign/submit-only gate tests ───────────────────────────────────
    //
    // `dispatch_staged_pay_gate` is network- and keyring-free, so these tests
    // exercise it directly with hand-built XDR fixtures and a hand-built
    // `PolicyEngineV1` — the same construction convention
    // `commands::policy_engine`'s own gate-parity tests use. `run_sign_only`
    // and `run_submit_only` both call this SAME function with the SAME
    // arguments (only the subsequent sign-vs-submit action differs), so
    // exercising it once here proves both staged stages gate identically.

    use stellar_agent_core::policy::Decision;
    use stellar_agent_core::policy::v1::PolicyEngineV1;
    use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
    use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
    use stellar_xdr::{
        AccountId, Asset, CreateAccountOp, Limits, MuxedAccount, Operation, OperationBody,
        PaymentOp, Preconditions, PublicKey as XdrPublicKey, SequenceNumber, Transaction,
        TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
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

    /// A `stellar_pay`-shaped envelope: a single native `Payment` operation
    /// for `amount_stroops` from `SOURCE_G` to `DEST_G`.
    fn pay_envelope_b64(amount_stroops: i64) -> String {
        let op = Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: g_to_muxed(DEST_G),
                asset: Asset::Native,
                amount: amount_stroops,
            }),
        };
        build_envelope_b64(SOURCE_G, op)
    }

    /// An envelope the pay decoder cannot classify: a `CreateAccount`
    /// operation presented where a `Payment` is expected.
    fn unclassifiable_envelope_b64() -> String {
        let op = Operation {
            source_account: None,
            body: OperationBody::CreateAccount(CreateAccountOp {
                destination: g_to_account_id(DEST_G),
                starting_balance: 10_000_000,
            }),
        };
        build_envelope_b64(SOURCE_G, op)
    }

    fn per_tx_cap_engine(max_stroops: i64, allow_opaque_signing: bool) -> PolicyEngineV1 {
        let rule = PolicyRule {
            r#match: RuleMatch {
                tool: "stellar_pay_commit".to_owned(),
                chain: "*".to_owned(),
            },
            criteria: vec![Box::new(PerTxCapCriterion::new(
                "native".to_owned(),
                i128::from(max_stroops),
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

    /// A within-cap envelope under a satisfied `per_tx_cap` rule allows.
    #[test]
    fn dispatch_staged_pay_gate_within_cap_allows() {
        let engine = per_tx_cap_engine(1_000_000_000, false); // 100 XLM cap
        let profile = staged_test_profile();
        let xdr = pay_envelope_b64(500_000_000); // 50 XLM
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &xdr,
            "stellar_pay_commit",
        );
        let result = dispatch_staged_pay_gate(
            &engine,
            &profile,
            "stellar:testnet",
            decode_result,
            None,
            None,
        );
        assert!(
            result.is_ok(),
            "a within-cap staged envelope must allow, got {result:?}"
        );
    }

    /// An over-cap envelope denies with the cap's wire code — proving the
    /// sizing came from the ENVELOPE (the decoded amount), not any
    /// caller-supplied args (none are passed to `dispatch_staged_pay_gate`
    /// at all on the `Ok` branch other than the decoded fields).
    #[test]
    fn dispatch_staged_pay_gate_over_cap_denies_with_envelope_derived_amount() {
        let engine = per_tx_cap_engine(1_000_000_000, false); // 100 XLM cap
        let profile = staged_test_profile();
        let xdr = pay_envelope_b64(1_500_000_000); // 150 XLM
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &xdr,
            "stellar_pay_commit",
        );
        let result = dispatch_staged_pay_gate(
            &engine,
            &profile,
            "stellar:testnet",
            decode_result,
            None,
            None,
        );
        assert_eq!(
            envelope_code(&result),
            "policy.deny.per_tx_cap_exceeded",
            "an over-cap staged envelope must deny with the cap's wire code, sized from the \
             decoded envelope amount"
        );
    }

    /// An envelope the decoder cannot classify, under a matched value rule,
    /// denies `policy.deny.unsizable_value_effect`.
    #[test]
    fn dispatch_staged_pay_gate_unclassifiable_envelope_denies_unsizable() {
        let engine = per_tx_cap_engine(1_000_000_000, false);
        let profile = staged_test_profile();
        let xdr = unclassifiable_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &xdr,
            "stellar_pay_commit",
        );
        assert!(
            decode_result.is_err(),
            "fixture must be undecodable as a payment"
        );
        let result = dispatch_staged_pay_gate(
            &engine,
            &profile,
            "stellar:testnet",
            decode_result,
            None,
            None,
        );
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
    fn dispatch_staged_pay_gate_unclassifiable_envelope_with_allow_opaque_signing_allows() {
        let engine = per_tx_cap_engine(1_000_000_000, true);
        let profile = staged_test_profile();
        let xdr = unclassifiable_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &xdr,
            "stellar_pay_commit",
        );
        let result = dispatch_staged_pay_gate(
            &engine,
            &profile,
            "stellar:testnet",
            decode_result,
            None,
            None,
        );
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
    /// or not — matching the default pipeline's conditionality (the gate
    /// only bites under `policy.engine = v1`).
    #[test]
    fn dispatch_staged_pay_gate_noop_engine_allows_regardless_of_decodability() {
        let engine = stellar_agent_core::policy::NoopPolicyEngine;
        let profile = staged_test_profile();

        let decodable = pay_envelope_b64(1_500_000_000);
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &decodable,
            "stellar_pay_commit",
        );
        let result = dispatch_staged_pay_gate(
            &engine,
            &profile,
            "stellar:testnet",
            decode_result,
            None,
            None,
        );
        assert!(
            result.is_ok(),
            "Noop engine must allow a decodable envelope"
        );

        let undecodable = unclassifiable_envelope_b64();
        let decode_result = stellar_agent_core::envelope_decode::decode_authoritative_args(
            &undecodable,
            "stellar_pay_commit",
        );
        let result = dispatch_staged_pay_gate(
            &engine,
            &profile,
            "stellar:testnet",
            decode_result,
            None,
            None,
        );
        assert!(
            result.is_ok(),
            "Noop engine must allow an undecodable (opaque) envelope too"
        );
    }

    #[allow(unsafe_code, reason = "serialized test seed variable")]
    async fn enrolled_signing_case(pin: EnrolledPin) {
        let g = enrolled_test_g();
        let var = "ENROLLED_PAY_TEST_SEED";
        unsafe {
            std::env::set_var(var, enrolled_test_secret());
        }
        let mut profile = enrolled_mainnet_profile(pin);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(PayBuildRpcResponder::new(
                account_ledger_key_xdr(&g),
                account_entry_xdr_with_balance(&g, 100_000_000_000),
                fee_stats_result("100", "100"),
            ))
            .mount(&server)
            .await;
        profile.rpc_url = server.uri();
        let context = NetworkContext::from_profile(&profile);
        let mut args = minimal_args();
        args.source = Some(g);
        args.destination = DEST_G.into();
        args.secret_env = Some(var.into());
        args.fee = Some("100".into());
        let built = build_with_client(&context, &args)
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

    // ── Endpoint identity: one client per stage, checked before its reads ──

    /// Arguments for a 1 XLM payment from `signer` to `DEST_G` through the
    /// endpoint at `rpc_url`.
    fn signed_payment_args(signer: &EnvSigner, rpc_url: &str) -> PayArgs {
        let mut args = minimal_args();
        args.source = Some(signer.g.clone());
        args.destination = DEST_G.to_owned();
        args.amount = "1 XLM".to_owned();
        args.secret_env = Some(signer.var.to_owned());
        args.rpc_url = Some(rpc_url.to_owned());
        args
    }

    /// An unsigned payment envelope from `signer`, built against an endpoint
    /// of its own so the endpoint under test sees only the stage's requests.
    async fn unsigned_payment_from(signer: &EnvSigner) -> String {
        let fixture = crate::test_rpc::ClassicRpc::testnet(&[&signer.g])
            .serve()
            .await;
        let args = signed_payment_args(signer, &fixture.uri());
        build_with_client(&flag_context(&args), &args)
            .await
            .expect("fixture build")
            .envelope_xdr
    }

    /// The full pipeline builds one client: the endpoint check is its first
    /// request, and the build reads and the send go through it. The submit
    /// layer checks it again before the send, so two `getNetwork` requests.
    #[tokio::test]
    #[serial_test::serial]
    async fn the_full_pipeline_checks_the_endpoint_first_and_sends_through_one_client() {
        for fee in [None, Some("auto")] {
            let _isolation = zero_config();
            let signer = EnvSigner::new([0x61; 32], "PAY_ONE_CLIENT_FULL_SK");
            let server = crate::test_rpc::ClassicRpc::testnet(&[&signer.g, DEST_G])
                .serve()
                .await;
            let mut args = signed_payment_args(&signer, &server.uri());
            args.fee = fee.map(str::to_owned);

            let (code, built) = crate::test_rpc::clients_built_by(run_with_dependencies(
                &args,
                absent_profile_file,
                || Ok(()),
            ))
            .await;
            let methods = crate::test_rpc::methods(&server).await;

            assert_eq!(code, 0, "fee {fee:?}: {methods:?}");
            assert_eq!(built, 1, "fee {fee:?}: one client reads and sends");
            assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
            assert_eq!(crate::test_rpc::network_checks(&methods), 2, "{methods:?}");
            assert!(
                methods.iter().any(|m| m == "sendTransaction"),
                "{methods:?}"
            );
        }
    }

    /// `--build-only` builds one client and checks its endpoint once, before
    /// the fee and sequence reads.
    #[tokio::test]
    #[serial_test::serial]
    async fn build_only_checks_the_endpoint_once_on_its_one_client() {
        for fee in [None, Some("auto")] {
            let _isolation = zero_config();
            let signer = EnvSigner::new([0x62; 32], "PAY_ONE_CLIENT_BUILD_SK");
            let server = crate::test_rpc::ClassicRpc::testnet(&[&signer.g, DEST_G])
                .serve()
                .await;
            let mut args = signed_payment_args(&signer, &server.uri());
            args.fee = fee.map(str::to_owned);
            args.build_only = true;

            let (code, built) = crate::test_rpc::clients_built_by(run_with_dependencies(
                &args,
                absent_profile_file,
                || Ok(()),
            ))
            .await;
            let methods = crate::test_rpc::methods(&server).await;

            assert_eq!(code, 0, "fee {fee:?}: {methods:?}");
            assert_eq!(built, 1, "fee {fee:?}");
            assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
            assert_eq!(crate::test_rpc::network_checks(&methods), 1, "{methods:?}");
        }
    }

    /// `--sign-only` with an envelope it decodes builds one client and checks
    /// its endpoint once, before the account reads its gate takes.
    #[tokio::test]
    #[serial_test::serial]
    async fn sign_only_of_a_decoded_envelope_checks_the_endpoint_once() {
        let _isolation = zero_config();
        let signer = EnvSigner::new([0x63; 32], "PAY_ONE_CLIENT_SIGN_SK");
        let envelope = unsigned_payment_from(&signer).await;
        let server = crate::test_rpc::ClassicRpc::testnet(&[&signer.g, DEST_G])
            .serve()
            .await;
        let mut args = signed_payment_args(&signer, &server.uri());
        args.sign_only = Some(envelope);

        let (code, built) = crate::test_rpc::clients_built_by(run_with_dependencies(
            &args,
            absent_profile_file,
            || Ok(()),
        ))
        .await;
        let methods = crate::test_rpc::methods(&server).await;

        assert_eq!(code, 0, "{methods:?}");
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
        let _isolation = zero_config();
        let signer = EnvSigner::new([0x64; 32], "PAY_ONE_CLIENT_OPAQUE_SK");
        let server = crate::test_rpc::ClassicRpc::testnet(&[&signer.g, DEST_G])
            .serve()
            .await;
        let mut args = signed_payment_args(&signer, &server.uri());
        args.sign_only = Some(build_envelope_b64(
            &signer.g,
            Operation {
                source_account: None,
                body: OperationBody::CreateAccount(CreateAccountOp {
                    destination: g_to_account_id(DEST_G),
                    starting_balance: 10_000_000,
                }),
            },
        ));

        let (code, built) = crate::test_rpc::clients_built_by(run_with_dependencies(
            &args,
            absent_profile_file,
            || Ok(()),
        ))
        .await;

        assert_eq!(code, 0, "the opaque envelope is signed");
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
    /// request, the reconcile and the gate reads follow, and the send goes
    /// through it. The submit layer checks it again before the send.
    #[tokio::test]
    #[serial_test::serial]
    async fn submit_only_checks_the_endpoint_first_and_sends_through_one_client() {
        let _isolation = zero_config();
        let envelope = stellar_agent_test_support::SignedTestEnvelope::for_source([0x61; 32]);
        let server =
            crate::test_rpc::ClassicRpc::testnet(&[envelope.source(), envelope.destination()])
                .serve()
                .await;
        let mut args = minimal_args();
        args.source = Some(envelope.source().to_owned());
        args.destination = envelope.destination().to_owned();
        args.rpc_url = Some(server.uri());
        args.submit_only = Some(envelope.envelope_xdr().to_owned());

        let (code, built) = crate::test_rpc::clients_built_by(run_with_dependencies(
            &args,
            absent_profile_file,
            || Ok(()),
        ))
        .await;
        let methods = crate::test_rpc::methods(&server).await;

        assert_eq!(code, 0, "{methods:?}");
        assert_eq!(built, 1, "one client reads and sends");
        assert_eq!(methods.first().map(String::as_str), Some("getNetwork"));
        assert_eq!(crate::test_rpc::network_checks(&methods), 2, "{methods:?}");
        assert!(
            methods.iter().any(|m| m == "sendTransaction"),
            "{methods:?}"
        );
    }

    // ── Cross-check witness of the full pipeline ──────────────────────────────

    mod witness_full {
        use super::*;
        use crate::test_rpc::{
            ClassicRpc, account_key, account_xdr, assert_rows_carry_witness, audit_rows,
            fail_read_of, last_rendered, memo_required_xdr, methods, profile_name_for, sent,
            signers_resolved_by, thresholds, trustline_xdr, witness_profile,
        };

        /// The issuer of the credit asset the credit cases send.
        pub(super) const ISSUER: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

        /// One full-pipeline run against `primary` and `oracle`.
        pub(super) struct Run {
            pub(super) code: i32,
            pub(super) envelope: serde_json::Value,
            pub(super) signers: usize,
        }

        pub(super) async fn run_stage(args: &PayArgs, profile: &Profile) -> Run {
            crate::common::render::take_rendered_for_test();
            let (code, signers) = signers_resolved_by(run_loaded(
                args,
                &crate::common::resolve_profile_name(args.profile.as_deref()),
                profile,
                ProfileOrigin::Persisted,
                || Ok(()),
            ))
            .await;
            Run {
                code,
                envelope: last_rendered(),
                signers,
            }
        }

        /// Asserts a refusal with `code` before any signing key was loaded and
        /// before anything was sent.
        pub(super) async fn assert_refused(run: &Run, code: &str, primary: &MockServer) {
            assert_eq!(run.code, 1, "{}", run.envelope);
            assert_eq!(run.envelope["error"]["code"], code, "{}", run.envelope);
            assert_eq!(run.signers, 0, "the refusal precedes the signer");
            assert!(!sent(primary).await, "nothing is sent");
        }

        /// A memo-less 1 XLM payment from `signer` to `DEST_G`, under the
        /// profile named for `signer`.
        pub(super) fn args(signer: &EnvSigner, primary: &MockServer) -> PayArgs {
            let mut args = signed_payment_args(signer, &primary.uri());
            args.profile = Some(profile_name_for(signer));
            args
        }

        /// The witness profile named for `signer`.
        pub(super) fn profile_for(
            signer: &EnvSigner,
            primary: &MockServer,
            oracle: Option<&MockServer>,
            audit: &tempfile::TempDir,
        ) -> Profile {
            witness_profile(
                &profile_name_for(signer),
                &primary.uri(),
                oracle.map(MockServer::uri).as_deref(),
                audit.path(),
            )
        }

        fn credit(args: &mut PayArgs) {
            args.asset = format!("USD:{ISSUER}");
            args.amount = "5 XLM".to_owned();
        }

        /// The source's USD trustline as the primary reports it.
        fn source_trustline(
            signer: &EnvSigner,
            balance: i64,
            limit: i64,
            flags: u32,
        ) -> (String, String) {
            trustline_xdr(&signer.g, "USD", ISSUER, balance, limit, flags)
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_witness_passes_and_rows_carry_it() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x71; 32], "PAY_WITNESS_FULL_PASS_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            let view = &run.envelope["data"]["cross_check"];
            assert_eq!(view["status"], "passed", "{}", run.envelope);
            assert_eq!(view["provider"], oracle.uri());
            assert_eq!(view["ledger"], 1001);
            assert_eq!(methods(&oracle).await, ["getNetwork", "getLedgerEntries"]);
            assert!(sent(&primary).await);
            assert_rows_carry_witness(&profile, &oracle.uri());
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_source_disagreement_refuses_before_the_signer() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x72; 32], "PAY_WITNESS_FULL_DIVERGE_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[DEST_G])
                .with_entry(account_key(&signer.g), account_xdr(&signer.g, 999, 0, ""))
                .serve()
                .await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
            assert!(audit_rows(&profile, "value_action_pending").is_empty());
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_without_oracle_skips_on_testnet() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x73; 32], "PAY_WITNESS_FULL_SKIP_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, None, &audit);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(
                run.envelope["data"]["cross_check"],
                serde_json::json!({"status": "skipped", "reason": "oracle_not_configured"})
            );
            let pending = audit_rows(&profile, "value_action_pending");
            assert_eq!(pending.len(), 1);
            assert!(pending[0].get("witness").is_none(), "{}", pending[0]);
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_oracle_identity_refusal_is_witness_unavailable() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x74; 32], "PAY_WITNESS_FULL_IDENTITY_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle_rpc = ClassicRpc::testnet(&[&signer.g, DEST_G]);
            oracle_rpc.report("Test SDF Future Network ; October 2022");
            let oracle = oracle_rpc.serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_refused(&run, "network.witness_unavailable", &primary).await;
            assert_eq!(methods(&oracle).await, ["getNetwork"]);
        }

        /// The oracle reports the destination with `home_domain` and `flags`;
        /// the primary reports neither.
        async fn destination_disagreement(
            seed: u8,
            var: &'static str,
            flags: u32,
            domain: &str,
            field: &str,
        ) {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([seed; 32], var);
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g])
                .with_entry(account_key(DEST_G), account_xdr(DEST_G, 100, flags, domain))
                .serve()
                .await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
            let message = run.envelope["error"]["message"].as_str().unwrap();
            assert!(
                message.contains(&format!("destination account {field}")),
                "{message}"
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_destination_home_domain_disagreement_refuses() {
            destination_disagreement(
                0x75,
                "PAY_WITNESS_FULL_DOMAIN_SK",
                0,
                "example.org",
                "home domain",
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_destination_flags_disagreement_refuses() {
            destination_disagreement(0x76, "PAY_WITNESS_FULL_FLAGS_SK", 1, "", "flags").await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_memo_flag_disagreement_is_rpc_divergence() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x77; 32], "PAY_WITNESS_FULL_MEMO_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let (memo_key, memo_entry) = memo_required_xdr(DEST_G);
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G])
                .with_entry(memo_key, memo_entry)
                .serve()
                .await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_refused(&run, "network.rpc_divergence", &primary).await;
        }

        /// The primary and the oracle report the source's USD trustline with
        /// different `(balance, limit, flags)`.
        async fn trustline_disagreement(
            seed: u8,
            var: &'static str,
            oracle_state: (i64, i64, u32),
            field: &str,
        ) {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([seed; 32], var);
            let (key, entry) = source_trustline(&signer, 500_000_000, 10_000_000_000, 1);
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G])
                .with_entry(key, entry)
                .serve()
                .await;
            let (key, entry) =
                source_trustline(&signer, oracle_state.0, oracle_state.1, oracle_state.2);
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G])
                .with_entry(key, entry)
                .serve()
                .await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            let mut args = args(&signer, &primary);
            credit(&mut args);

            let run = run_stage(&args, &profile).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
            let message = run.envelope["error"]["message"].as_str().unwrap();
            assert!(
                message.contains(&format!("source trustline {field}")),
                "{message}"
            );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_source_trustline_balance_disagreement_refuses() {
            trustline_disagreement(
                0x78,
                "PAY_WITNESS_FULL_TL_BALANCE_SK",
                (500_000_001, 10_000_000_000, 1),
                "balance",
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_source_trustline_limit_disagreement_refuses() {
            trustline_disagreement(
                0x79,
                "PAY_WITNESS_FULL_TL_LIMIT_SK",
                (500_000_000, 9_000_000_000, 1),
                "limit",
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn full_source_trustline_flags_disagreement_refuses() {
            trustline_disagreement(
                0x7a,
                "PAY_WITNESS_FULL_TL_FLAGS_SK",
                (500_000_000, 10_000_000_000, 0),
                "flags",
            )
            .await;
        }

        /// A payment with a memo is witnessed by value alone: the send leg in
        /// USD reaches the USD threshold and needs the witness, and one base
        /// unit less needs none.
        #[tokio::test]
        #[serial_test::serial]
        async fn full_witness_values_the_send_leg() {
            for (amount, expected, var) in [
                ("5 XLM", "passed", "PAY_WITNESS_FULL_VALUE_AT_SK"),
                (
                    "4.9999999 XLM",
                    "not_required",
                    "PAY_WITNESS_FULL_VALUE_BELOW_SK",
                ),
            ] {
                let _isolation = zero_config();
                let audit = tempfile::tempdir().unwrap();
                let signer = EnvSigner::new([0x7b; 32], var);
                let (key, entry) = source_trustline(&signer, 500_000_000, 10_000_000_000, 1);
                let primary = ClassicRpc::testnet(&[&signer.g, DEST_G])
                    .with_entry(key.clone(), entry.clone())
                    .serve()
                    .await;
                let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G])
                    .with_entry(key, entry)
                    .serve()
                    .await;
                let mut profile = profile_for(&signer, &primary, Some(&oracle), &audit);
                profile.cross_check_thresholds = thresholds(&format!("USD:{ISSUER}"), 50_000_000);
                let mut args = args(&signer, &primary);
                credit(&mut args);
                args.amount = amount.to_owned();
                args.memo_text = Some("invoice".to_owned());

                let run = run_stage(&args, &profile).await;

                assert_eq!(run.code, 0, "{amount}: {}", run.envelope);
                assert_eq!(
                    run.envelope["data"]["cross_check"]["status"], expected,
                    "{amount}: {}",
                    run.envelope
                );
                let oracle_methods = methods(&oracle).await;
                if expected == "passed" {
                    assert_eq!(oracle_methods, ["getNetwork", "getLedgerEntries"]);
                } else {
                    assert!(oracle_methods.is_empty(), "{oracle_methods:?}");
                }
            }
        }

        /// A fee above the cap refuses before the oracle is asked and before
        /// the signer, with the command-default text when no fee is given.
        #[tokio::test]
        #[serial_test::serial]
        async fn full_fee_above_cap_refuses_before_the_witness() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x7c; 32], "PAY_WITNESS_FULL_CAP_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let mut profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            profile.classic_max_fee_per_op_stroops = Some(50);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_refused(&run, "fees.percentile_exceeds_cap", &primary).await;
            assert_eq!(
                run.envelope["error"]["message"],
                "the default per-operation fee 100 stroops exceeds the profile cap of 50 \
                 stroops; pass an explicit fee within the cap or raise \
                 classic_max_fee_per_op_stroops"
            );
            assert!(
                methods(&oracle).await.is_empty(),
                "the cap precedes the witness"
            );
        }

        /// An explicit fee above the cap names the explicit fee.
        #[tokio::test]
        #[serial_test::serial]
        async fn full_explicit_fee_above_cap_names_the_explicit_fee() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x7d; 32], "PAY_WITNESS_FULL_CAP_EXPLICIT_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let mut profile = profile_for(&signer, &primary, None, &audit);
            profile.classic_max_fee_per_op_stroops = Some(150);
            let mut args = args(&signer, &primary);
            args.fee = Some("200".to_owned());

            let run = run_stage(&args, &profile).await;

            assert_refused(&run, "fees.percentile_exceeds_cap", &primary).await;
            assert!(
                run.envelope["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("the explicit per-operation fee 200 stroops"),
                "{}",
                run.envelope
            );
        }

        /// A destination read that fails refuses with the read's own code: the
        /// destination is not taken for absent and compared with the oracle.
        #[tokio::test]
        #[serial_test::serial]
        async fn full_destination_read_error_refuses_with_its_code() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x7e; 32], "PAY_WITNESS_FULL_READ_ERROR_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            fail_read_of(&primary, &account_key(DEST_G)).await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = run_stage(&args(&signer, &primary), &profile).await;

            assert_refused(&run, "network.rpc_unreachable", &primary).await;
            assert!(methods(&oracle).await.is_empty());
        }

        /// `--build-only` neither asks the oracle nor reports a cross-check,
        /// and an auto-selected fee above the cap names its percentile.
        #[tokio::test]
        #[serial_test::serial]
        async fn build_only_makes_no_oracle_request() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x7f; 32], "PAY_WITNESS_BUILD_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let mut profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            let mut args = args(&signer, &primary);
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
            args.fee = Some("auto".to_owned());
            let run = run_stage(&args, &profile).await;
            assert_eq!(run.code, 1, "{}", run.envelope);
            assert_eq!(run.envelope["error"]["code"], "fees.percentile_exceeds_cap");
            assert!(
                run.envelope["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("auto-selected per-operation fee 100 stroops (percentile p95)"),
                "{}",
                run.envelope
            );
            assert!(methods(&oracle).await.is_empty());
        }
    }

    // ── Cross-check witness of the staged stages ──────────────────────────────

    mod witness_staged {
        use super::witness_full::{ISSUER, Run, args, assert_refused, profile_for, run_stage};
        use super::*;
        use crate::test_rpc::{
            ClassicRpc, account_key, account_xdr, assert_rows_carry_witness, fail_read_of,
            memo_required_xdr, methods, sent, thresholds, trustline_xdr,
        };
        use stellar_xdr::{
            AccountId as XdrAccountId, AlphaNum4, Asset as XdrAsset, AssetCode4, Hash, Limits,
            Memo, MuxedAccount as XdrMuxed, MuxedAccountMed25519, Operation as XdrOperation,
            OperationBody as XdrBody, PathPaymentStrictReceiveOp, PathPaymentStrictSendOp,
            PaymentOp as XdrPaymentOp, Preconditions as XdrPreconditions, PublicKey as XdrPk,
            SequenceNumber as XdrSeq, Transaction as XdrTransaction,
            TransactionEnvelope as XdrEnvelope, TransactionExt as XdrTxExt,
            TransactionV1Envelope as XdrV1, Uint256 as XdrUint256, VecM as XdrVecM, WriteXdr,
        };

        fn key_bytes(g: &str) -> [u8; 32] {
            stellar_strkey::ed25519::PublicKey::from_string(g)
                .unwrap()
                .0
        }

        pub(super) fn plain(g: &str) -> XdrMuxed {
            XdrMuxed::Ed25519(XdrUint256(key_bytes(g)))
        }

        pub(super) fn muxed(g: &str) -> XdrMuxed {
            XdrMuxed::MuxedEd25519(MuxedAccountMed25519 {
                id: 7,
                ed25519: XdrUint256(key_bytes(g)),
            })
        }

        fn usd() -> XdrAsset {
            XdrAsset::CreditAlphanum4(AlphaNum4 {
                asset_code: AssetCode4(*b"USD\0"),
                issuer: XdrAccountId(XdrPk::PublicKeyTypeEd25519(XdrUint256(key_bytes(ISSUER)))),
            })
        }

        fn payment(destination: XdrMuxed, asset: XdrAsset, amount: i64) -> XdrBody {
            XdrBody::Payment(XdrPaymentOp {
                destination,
                asset,
                amount,
            })
        }

        /// A single-operation v1 envelope from `source`.
        pub(super) fn envelope(source: XdrMuxed, body: XdrBody, memo: Memo, fee: u32) -> String {
            XdrEnvelope::Tx(XdrV1 {
                tx: XdrTransaction {
                    source_account: source,
                    fee,
                    seq_num: XdrSeq(101),
                    cond: XdrPreconditions::None,
                    memo,
                    operations: vec![XdrOperation {
                        source_account: None,
                        body,
                    }]
                    .try_into()
                    .unwrap(),
                    ext: XdrTxExt::V0,
                },
                signatures: XdrVecM::default(),
            })
            .to_xdr_base64(Limits::none())
            .unwrap()
        }

        /// A memo-less 1 XLM payment from the signer to `DEST_G`.
        fn native_envelope(signer: &EnvSigner) -> String {
            envelope(
                plain(&signer.g),
                payment(plain(DEST_G), XdrAsset::Native, 10_000_000),
                Memo::None,
                100,
            )
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
            signer: &EnvSigner,
            primary: &MockServer,
            profile: &Profile,
            xdr: String,
        ) -> Run {
            let mut args = args(signer, primary);
            args.sign_only = Some(xdr);
            run_stage(&args, profile).await
        }

        async fn submit_only(
            signer: &EnvSigner,
            primary: &MockServer,
            profile: &Profile,
            xdr: String,
        ) -> Run {
            let mut args = args(signer, primary);
            args.secret_env = None;
            args.submit_only = Some(xdr);
            run_stage(&args, profile).await
        }

        /// The base64 ledger keys of every `getLedgerEntries` `server` received.
        async fn requested_keys(server: &MockServer) -> Vec<String> {
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
                .filter(|body| body["method"] == "getLedgerEntries")
                .flat_map(|body| {
                    body["params"]["keys"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|k| k.as_str().map(str::to_owned))
                })
                .collect()
        }

        // ── --sign-only ──

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_witness_passes_and_reports_it() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x81; 32], "PAY_WITNESS_SIGN_PASS_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = sign_only(&signer, &primary, &profile, native_envelope(&signer)).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(run.signers, 1);
            let view = &run.envelope["data"]["cross_check"];
            assert_eq!(view["status"], "passed", "{}", run.envelope);
            assert_eq!(view["provider"], oracle.uri());
            assert_eq!(methods(&oracle).await, ["getNetwork", "getLedgerEntries"]);
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_source_disagreement_refuses_before_signing() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x82; 32], "PAY_WITNESS_SIGN_DIVERGE_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[DEST_G])
                .with_entry(account_key(&signer.g), account_xdr(&signer.g, 999, 0, ""))
                .serve()
                .await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = sign_only(&signer, &primary, &profile, native_envelope(&signer)).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_without_oracle_skips_on_testnet() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x83; 32], "PAY_WITNESS_SIGN_SKIP_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, None, &audit);

            let run = sign_only(&signer, &primary, &profile, native_envelope(&signer)).await;

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
            let signer = EnvSigner::new([0x84; 32], "PAY_WITNESS_SIGN_CONSTRUCTION_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile =
                witness_profile_with_oracle_url(&signer, &primary, "ftp://oracle.example", &audit);

            let run = sign_only(&signer, &primary, &profile, native_envelope(&signer)).await;

            assert_refused(&run, "network.witness_unavailable", &primary).await;
        }

        /// A profile whose oracle URL the client cannot be built for.
        fn witness_profile_with_oracle_url(
            signer: &EnvSigner,
            primary: &MockServer,
            oracle: &str,
            audit: &tempfile::TempDir,
        ) -> Profile {
            let mut profile = profile_for(signer, primary, None, audit);
            profile.oracle_provider_url = Some(url::Url::parse(oracle).unwrap());
            profile
        }

        async fn sign_only_disagreement(
            seed: u8,
            var: &'static str,
            credit: bool,
            oracle_rpc: impl FnOnce(&str) -> ClassicRpc,
            code: &str,
            message: Option<&str>,
        ) {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([seed; 32], var);
            let (tl_key, tl_entry) =
                trustline_xdr(&signer.g, "USD", ISSUER, 500_000_000, 10_000_000_000, 1);
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G])
                .with_entry(tl_key, tl_entry)
                .serve()
                .await;
            let oracle = oracle_rpc(&signer.g).serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            let asset = if credit { usd() } else { XdrAsset::Native };
            let xdr = envelope(
                plain(&signer.g),
                payment(plain(DEST_G), asset, 10_000_000),
                Memo::None,
                100,
            );

            let run = sign_only(&signer, &primary, &profile, xdr).await;

            assert_refused(&run, code, &primary).await;
            if let Some(expected) = message {
                let text = run.envelope["error"]["message"].as_str().unwrap();
                assert!(text.contains(expected), "{text}");
            }
        }

        fn oracle_trustline(source: &str, balance: i64, limit: i64, flags: u32) -> ClassicRpc {
            let (key, entry) = trustline_xdr(source, "USD", ISSUER, balance, limit, flags);
            ClassicRpc::testnet(&[source, DEST_G]).with_entry(key, entry)
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_destination_home_domain_disagreement_refuses() {
            sign_only_disagreement(
                0x85,
                "PAY_WITNESS_SIGN_DOMAIN_SK",
                false,
                |g| {
                    ClassicRpc::testnet(&[g]).with_entry(
                        account_key(DEST_G),
                        account_xdr(DEST_G, 100, 0, "example.org"),
                    )
                },
                "simulation.divergence",
                Some("destination account home domain"),
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_destination_flags_disagreement_refuses() {
            sign_only_disagreement(
                0x86,
                "PAY_WITNESS_SIGN_FLAGS_SK",
                false,
                |g| {
                    ClassicRpc::testnet(&[g])
                        .with_entry(account_key(DEST_G), account_xdr(DEST_G, 100, 1, ""))
                },
                "simulation.divergence",
                Some("destination account flags"),
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_memo_flag_disagreement_is_rpc_divergence() {
            sign_only_disagreement(
                0x87,
                "PAY_WITNESS_SIGN_MEMO_SK",
                false,
                |g| {
                    let (key, entry) = memo_required_xdr(DEST_G);
                    ClassicRpc::testnet(&[g, DEST_G]).with_entry(key, entry)
                },
                "network.rpc_divergence",
                None,
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_source_trustline_balance_disagreement_refuses() {
            sign_only_disagreement(
                0x88,
                "PAY_WITNESS_SIGN_TL_BALANCE_SK",
                true,
                |g| oracle_trustline(g, 500_000_001, 10_000_000_000, 1),
                "simulation.divergence",
                Some("source trustline balance"),
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_source_trustline_limit_disagreement_refuses() {
            sign_only_disagreement(
                0x89,
                "PAY_WITNESS_SIGN_TL_LIMIT_SK",
                true,
                |g| oracle_trustline(g, 500_000_000, 9_000_000_000, 1),
                "simulation.divergence",
                Some("source trustline limit"),
            )
            .await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_source_trustline_flags_disagreement_refuses() {
            sign_only_disagreement(
                0x8a,
                "PAY_WITNESS_SIGN_TL_FLAGS_SK",
                true,
                |g| oracle_trustline(g, 500_000_000, 10_000_000_000, 0),
                "simulation.divergence",
                Some("source trustline flags"),
            )
            .await;
        }

        /// A staged path payment with a memo is witnessed on its send leg:
        /// the USD debit reaches the USD threshold, while the receive leg is
        /// one XLM, far below the native floor. One base unit below the USD
        /// threshold needs no witness.
        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_witness_values_the_send_leg() {
            let receive = |send_max: i64| {
                XdrBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
                    send_asset: usd(),
                    send_max,
                    destination: plain(DEST_G),
                    dest_asset: XdrAsset::Native,
                    dest_amount: 10_000_000,
                    path: XdrVecM::default(),
                })
            };
            let send = |send_amount: i64| {
                XdrBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
                    send_asset: usd(),
                    send_amount,
                    destination: plain(DEST_G),
                    dest_asset: XdrAsset::Native,
                    dest_min: 10_000_000,
                    path: XdrVecM::default(),
                })
            };
            for (body, expected, var) in [
                (
                    receive(50_000_000),
                    "passed",
                    "PAY_WITNESS_SIGN_VALUE_RECEIVE_SK",
                ),
                (send(50_000_000), "passed", "PAY_WITNESS_SIGN_VALUE_SEND_SK"),
                (
                    receive(49_999_999),
                    "not_required",
                    "PAY_WITNESS_SIGN_VALUE_BELOW_SK",
                ),
            ] {
                let _isolation = zero_config();
                let audit = tempfile::tempdir().unwrap();
                let signer = EnvSigner::new([0x8b; 32], var);
                let (key, entry) =
                    trustline_xdr(&signer.g, "USD", ISSUER, 500_000_000, 10_000_000_000, 1);
                let primary = ClassicRpc::testnet(&[&signer.g, DEST_G])
                    .with_entry(key.clone(), entry.clone())
                    .serve()
                    .await;
                let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G])
                    .with_entry(key, entry)
                    .serve()
                    .await;
                let mut profile = profile_for(&signer, &primary, Some(&oracle), &audit);
                profile.cross_check_thresholds = thresholds(&format!("USD:{ISSUER}"), 50_000_000);
                let text: stellar_xdr::StringM<28> = b"invoice".to_vec().try_into().unwrap();
                let xdr = envelope(plain(&signer.g), body, Memo::Text(text), 100);

                let run = sign_only(&signer, &primary, &profile, xdr).await;

                assert_eq!(run.code, 0, "{var}: {}", run.envelope);
                assert_eq!(
                    run.envelope["data"]["cross_check"]["status"], expected,
                    "{var}: {}",
                    run.envelope
                );
                let oracle_methods = methods(&oracle).await;
                if expected == "passed" {
                    assert_eq!(oracle_methods, ["getNetwork", "getLedgerEntries"]);
                } else {
                    assert!(oracle_methods.is_empty(), "{var}: {oracle_methods:?}");
                }
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_fee_above_cap_refuses_before_the_witness() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x8c; 32], "PAY_WITNESS_SIGN_CAP_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let mut profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            profile.classic_max_fee_per_op_stroops = Some(400);
            let xdr = envelope(
                plain(&signer.g),
                payment(plain(DEST_G), XdrAsset::Native, 10_000_000),
                Memo::None,
                500,
            );

            let run = sign_only(&signer, &primary, &profile, xdr).await;

            assert_refused(&run, "fees.percentile_exceeds_cap", &primary).await;
            assert_eq!(
                run.envelope["error"]["message"],
                "the envelope's per-operation fee 500 stroops exceeds the profile cap of 400 \
                 stroops; prepare the transaction again with a fee within the cap"
            );
            assert!(methods(&oracle).await.is_empty());
        }

        /// Only a memo-less envelope paying a plain G destination reads the
        /// destination's SEP-29 flag; a text, id, hash, or return memo, and a
        /// muxed destination, read nothing.
        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_reads_sep29_only_for_a_memo_less_g_destination() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x8d; 32], "PAY_WITNESS_SIGN_MEMO_KINDS_SK");
            let setup = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &setup, None, &audit);
            let (memo_key, _) = memo_required_xdr(DEST_G);
            let text: stellar_xdr::StringM<28> = b"memo".to_vec().try_into().unwrap();
            for (label, destination, memo, reads) in [
                ("none", plain(DEST_G), Memo::None, true),
                ("text", plain(DEST_G), Memo::Text(text), false),
                ("id", plain(DEST_G), Memo::Id(9), false),
                ("hash", plain(DEST_G), Memo::Hash(Hash([1; 32])), false),
                ("return", plain(DEST_G), Memo::Return(Hash([2; 32])), false),
                ("none, muxed destination", muxed(DEST_G), Memo::None, false),
            ] {
                let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
                let xdr = envelope(
                    plain(&signer.g),
                    payment(destination, XdrAsset::Native, 10_000_000),
                    memo,
                    100,
                );

                let run = sign_only(&signer, &primary, &profile, xdr).await;

                assert_eq!(run.code, 0, "{label}: {}", run.envelope);
                assert_eq!(
                    requested_keys(&primary).await.contains(&memo_key),
                    reads,
                    "{label}"
                );
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_memo_required_refuses_before_signing() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x8e; 32], "PAY_WITNESS_SIGN_MEMO_REQUIRED_SK");
            let (key, entry) = memo_required_xdr(DEST_G);
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G])
                .with_entry(key, entry)
                .serve()
                .await;
            let profile = profile_for(&signer, &primary, None, &audit);

            let run = sign_only(&signer, &primary, &profile, native_envelope(&signer)).await;

            assert_refused(&run, "validation.memo_required", &primary).await;
        }

        /// A muxed source and a muxed destination are witnessed on their G
        /// accounts.
        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_muxed_accounts_witness_on_the_g_accounts() {
            for (label, source_muxed, var) in [
                ("muxed source", true, "PAY_WITNESS_SIGN_MUXED_SOURCE_SK"),
                ("muxed destination", false, "PAY_WITNESS_SIGN_MUXED_DEST_SK"),
            ] {
                let _isolation = zero_config();
                let audit = tempfile::tempdir().unwrap();
                let signer = EnvSigner::new([0x8f; 32], var);
                let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
                let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
                let profile = profile_for(&signer, &primary, Some(&oracle), &audit);
                // The muxed destination carries its memo in the muxed id, so
                // its payment is witnessed by value: 2000 XLM reaches the
                // native floor.
                let xdr = if source_muxed {
                    envelope(
                        muxed(&signer.g),
                        payment(plain(DEST_G), XdrAsset::Native, 10_000_000),
                        Memo::None,
                        100,
                    )
                } else {
                    envelope(
                        plain(&signer.g),
                        payment(muxed(DEST_G), XdrAsset::Native, 20_000_000_000),
                        Memo::None,
                        100,
                    )
                };

                let run = sign_only(&signer, &primary, &profile, xdr).await;

                assert_eq!(run.code, 0, "{label}: {}", run.envelope);
                assert_eq!(
                    run.envelope["data"]["cross_check"]["status"], "passed",
                    "{label}: {}",
                    run.envelope
                );
                let keys = requested_keys(&oracle).await;
                assert!(keys.contains(&account_key(&signer.g)), "{label}");
                assert!(keys.contains(&account_key(DEST_G)), "{label}");
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn sign_only_destination_read_error_refuses_with_its_code() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x90; 32], "PAY_WITNESS_SIGN_READ_ERROR_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            fail_read_of(&primary, &account_key(DEST_G)).await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);

            let run = sign_only(&signer, &primary, &profile, native_envelope(&signer)).await;

            assert_refused(&run, "network.rpc_unreachable", &primary).await;
            assert!(methods(&oracle).await.is_empty());
        }

        // ── --submit-only ──

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_witness_passes_and_rows_carry_it() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x91; 32], "PAY_WITNESS_SUBMIT_PASS_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            let xdr = signed(&native_envelope(&signer), [0x91; 32]).await;

            let run = submit_only(&signer, &primary, &profile, xdr).await;

            assert_eq!(run.code, 0, "{}", run.envelope);
            assert_eq!(run.envelope["data"]["cross_check"]["status"], "passed");
            assert_eq!(
                run.envelope["data"]["cross_check"]["provider"],
                oracle.uri()
            );
            assert!(sent(&primary).await);
            assert_rows_carry_witness(&profile, &oracle.uri());
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_source_disagreement_refuses_before_the_send() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x92; 32], "PAY_WITNESS_SUBMIT_DIVERGE_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[DEST_G])
                .with_entry(account_key(&signer.g), account_xdr(&signer.g, 999, 0, ""))
                .serve()
                .await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            let xdr = signed(&native_envelope(&signer), [0x92; 32]).await;

            let run = submit_only(&signer, &primary, &profile, xdr).await;

            assert_refused(&run, "simulation.divergence", &primary).await;
            assert!(crate::test_rpc::audit_rows(&profile, "value_action_pending").is_empty());
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_without_oracle_skips_on_testnet() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x93; 32], "PAY_WITNESS_SUBMIT_SKIP_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let profile = profile_for(&signer, &primary, None, &audit);
            let xdr = signed(&native_envelope(&signer), [0x93; 32]).await;

            let run = submit_only(&signer, &primary, &profile, xdr).await;

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
            let signer = EnvSigner::new([0x94; 32], "PAY_WITNESS_SUBMIT_IDENTITY_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle_rpc = ClassicRpc::testnet(&[&signer.g, DEST_G]);
            oracle_rpc.report("Test SDF Future Network ; October 2022");
            let oracle = oracle_rpc.serve().await;
            let profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            let xdr = signed(&native_envelope(&signer), [0x94; 32]).await;

            let run = submit_only(&signer, &primary, &profile, xdr).await;

            assert_refused(&run, "network.witness_unavailable", &primary).await;
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn submit_only_fee_above_cap_refuses_before_the_witness() {
            let _isolation = zero_config();
            let audit = tempfile::tempdir().unwrap();
            let signer = EnvSigner::new([0x95; 32], "PAY_WITNESS_SUBMIT_CAP_SK");
            let primary = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let oracle = ClassicRpc::testnet(&[&signer.g, DEST_G]).serve().await;
            let mut profile = profile_for(&signer, &primary, Some(&oracle), &audit);
            profile.classic_max_fee_per_op_stroops = Some(400);
            let unsigned = envelope(
                plain(&signer.g),
                payment(plain(DEST_G), XdrAsset::Native, 10_000_000),
                Memo::None,
                500,
            );
            let xdr = signed(&unsigned, [0x95; 32]).await;

            let run = submit_only(&signer, &primary, &profile, xdr).await;

            assert_refused(&run, "fees.percentile_exceeds_cap", &primary).await;
            assert!(
                run.envelope["error"]["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("the envelope's per-operation fee 500 stroops"),
                "{}",
                run.envelope
            );
            assert!(methods(&oracle).await.is_empty());
        }
    }
}
