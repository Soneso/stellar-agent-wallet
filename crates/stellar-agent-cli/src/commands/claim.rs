//! `stellar-agent claim` subcommand — claimable-balance claim spine.
//!
//! Claims a Stellar `ClaimClaimableBalance` operation for a balance the agent
//! already holds the id of. Supports the same three execution stages as `pay`:
//!
//! 1. **Build** (`--build-only`) — fetch the entry, render a typed preview, run
//!    the claim guards, construct the transaction envelope, and emit unsigned
//!    base64 XDR.
//! 2. **Sign** (`--sign-only <base64-xdr>`) — sign a previously-built envelope
//!    and emit signed base64 XDR.
//! 3. **Submit** (`--submit-only <base64-xdr>`) — submit a signed envelope and
//!    poll until confirmation.
//!
//! Default (no stage flag): runs all three stages atomically.
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
//! When `--profile` names no persisted `<name>.toml` file, an in-memory
//! `Noop`-engine testnet profile is synthesized (tagged
//! [`crate::commands::policy_engine::ProfileOrigin::Synthesized`]) so the
//! command keeps working without an authored profile file.
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

use std::time::Duration;

use clap::{ArgGroup, Args};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{
    AuthError, InternalError, LedgerError, NetworkError, ValidationError, WalletError,
};

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
    ProfileOrigin, build_v1_policy_engine, caip2_chain_id_for_network, claim_policy_args,
    evaluate_opaque_signing_policy, evaluate_value_moving_policy,
    load_profile_or_synthesize_testnet,
};
use crate::common::network::TargetNetwork;
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::signer_ceremony::{SignerCeremonyOutcome, resolve_software_signer_from_env};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default fee per operation in stroops (100 stroops × 1 op = 100 stroops).
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Stellar testnet RPC endpoint (SDF operated).
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

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
    /// Profile name to evaluate operator policy against (default: "default").
    ///
    /// When no `<name>.toml` profile file exists, an in-memory `Noop`-engine
    /// testnet profile is synthesized so the command keeps working without an
    /// authored profile file; see [`crate::commands::policy_engine::load_profile_or_synthesize_testnet`].
    #[arg(long, default_value = "default")]
    pub profile: String,

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

    /// Network to target. `mainnet` parses but is structurally refused before
    /// any RPC call or signing (wire code `network.mainnet_write_forbidden`).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Submission timeout in seconds. Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Override the Stellar RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,
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
        load_profile_or_synthesize_testnet,
        init_platform_keyring_store,
    )
    .await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies
/// [`load_profile_or_synthesize_testnet`] and [`init_platform_keyring_store`].
/// Tests substitute an in-memory profile and a spy initialiser to assert the
/// keyring store is registered before the V1 policy gate's owner-key read
/// (see `run_build_only` / `run_full_pipeline`) without touching the OS
/// keychain.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<(Profile, ProfileOrigin), String>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Mainnet structural rejection (first layer) ────────────────────────────
    if args.network == TargetNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        print_error(&Envelope::<()>::err(&err), args.output);
        return 1;
    }

    // Every gated stage reads the owner key from the keyring via
    // `build_v1_policy_engine` when the resolved profile is V1 — including
    // `--sign-only` / `--submit-only`, which now gate the decoded envelope
    // before signing/broadcasting — so all four stages receive the
    // injected profile-loader/keyring-initialiser pair.
    if args.build_only {
        run_build_only(args, load_profile, init_keyring).await
    } else if let Some(ref xdr) = args.sign_only {
        run_sign_only(args, xdr, load_profile, init_keyring).await
    } else if let Some(ref xdr) = args.submit_only {
        run_submit_only(args, xdr, load_profile, init_keyring).await
    } else {
        run_full_pipeline(args, load_profile, init_keyring).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage implementations
// ─────────────────────────────────────────────────────────────────────────────

async fn run_build_only<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<(Profile, ProfileOrigin), String>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Resolve profile & conditionally initialise the platform keyring ──────
    // Must happen before any network build: `build_v1_policy_engine` (invoked
    // from `evaluate_claim_policy` below) reads the owner PUBLIC key from the
    // OS keyring only when `profile.policy.engine == V1`, so the platform
    // keyring store is registered here — and only then — ahead of that read.
    // `--build-only` never calls the audit pre-flight (it neither signs nor
    // submits), so the Noop-engine path genuinely never touches the keyring
    // on this stage, unlike the signing/submitting stages below.
    let (profile, _origin) = match load_profile(&args.profile) {
        Ok(p) => p,
        Err(msg) => {
            print_error(
                &Envelope::<()>::err_raw("profile.load_failed", msg),
                args.output,
            );
            return 1;
        }
    };
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

    match build_unsigned_envelope(args).await {
        Ok(built) => {
            let chain_id = caip2_chain_id_for_network(args.network);
            // Build-only: gate but do not submit, so the gate-sized effects are
            // not recorded (no confirmed on-chain action to attest).
            if let Err(code) = evaluate_claim_policy(args, &built, chain_id, &profile) {
                return code;
            }
            let result = ClaimResult {
                envelope_xdr: built.envelope_xdr,
                tx_hash: None,
                ledger: None,
                stage: "build".to_owned(),
                balance_id_hex72: Some(built.balance_id_hex72),
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&claim_error_envelope(&e), args.output);
            1
        }
    }
}

async fn run_sign_only<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    unsigned_xdr: &str,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<(Profile, ProfileOrigin), String>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let (profile, origin) = match resolve_profile_and_keyring(args, load_profile, init_keyring) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let chain_id = caip2_chain_id_for_network(args.network);
    if let Err(code) = evaluate_staged_claim_policy(args, unsigned_xdr, chain_id, &profile).await {
        return code;
    }
    // Origin-aware pre-flight: prove the audit writer is acquirable AFTER the
    // policy gate (a denial is a clean refusal that signs nothing and needs
    // no audit setup) but BEFORE the signing key below is touched, for a
    // persisted profile — fails closed. The synthesized zero-config profile
    // stays fail-open. `--sign-only` never submits, so the returned writer
    // (if any) is not threaded further here — its only purpose on this stage
    // is the refusal.
    if let Err(e) = crate::commands::value_audit::require_value_audit_writer_for_origin(
        &profile,
        &args.profile,
        origin,
    ) {
        print_error(&Envelope::<()>::err(&e), args.output);
        return 1;
    }

    match sign_envelope(args, unsigned_xdr).await {
        Ok(signed_xdr) => {
            let result = ClaimResult {
                envelope_xdr: signed_xdr,
                tx_hash: None,
                ledger: None,
                stage: "sign".to_owned(),
                balance_id_hex72: None,
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            1
        }
    }
}

async fn run_submit_only<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    signed_xdr: &str,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<(Profile, ProfileOrigin), String>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let (profile, origin) = match resolve_profile_and_keyring(args, load_profile, init_keyring) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let chain_id = caip2_chain_id_for_network(args.network);
    // The envelope arrives pre-signed, but broadcasting it still spends
    // funds — gate here even though signing already happened elsewhere.
    let claim_effects =
        match evaluate_staged_claim_policy(args, signed_xdr, chain_id, &profile).await {
            Ok(effects) => effects,
            Err(code) => return code,
        };
    // Origin-aware pre-flight: prove the audit writer is acquirable AFTER the
    // policy gate (a denial is a clean refusal that submits nothing and
    // needs no audit setup) but BEFORE the transaction below is submitted,
    // for a persisted profile — fails closed. The synthesized zero-config
    // profile stays fail-open, yielding `None` when no writer could be
    // acquired. Where `Some`, the writer is reused (not re-acquired) for the
    // post-confirm emission.
    let audit_writer = match crate::commands::value_audit::require_value_audit_writer_for_origin(
        &profile,
        &args.profile,
        origin,
    ) {
        Ok(w) => w,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };

    match submit_envelope(args, signed_xdr).await {
        Ok((signed_xdr, sub_result)) => {
            // Non-fatal allow-path audit row: the SAME legs the gate sized
            // (single-derivation invariant), on confirmed submit. Skipped
            // entirely when no writer was acquired (the synthesized
            // zero-config profile with an unminted audit key).
            if let Some(writer) = &audit_writer {
                crate::commands::value_audit::emit_value_action_submitted_row_with_writer(
                    writer,
                    &args.profile,
                    "stellar_claim_commit",
                    chain_id,
                    claim_effects.as_ref(),
                    &sub_result.tx_hash,
                    sub_result.ledger,
                );
            }
            crate::commands::policy_engine::record_confirmed_value_moving(
                "claim",
                &profile,
                &args.profile,
                "stellar_claim_commit",
                chain_id,
                claim_effects.as_ref(),
            );

            let result = ClaimResult {
                envelope_xdr: signed_xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "submit".to_owned(),
                balance_id_hex72: None,
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            1
        }
    }
}

/// Resolves the profile and unconditionally attempts to initialise the
/// platform keyring store.
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
fn resolve_profile_and_keyring<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> Result<(Profile, ProfileOrigin), i32>
where
    LoadProfile: Fn(&str) -> Result<(Profile, ProfileOrigin), String>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let (profile, origin) = load_profile(&args.profile).map_err(|msg| {
        print_error(
            &Envelope::<()>::err_raw("profile.load_failed", msg),
            args.output,
        );
        1
    })?;
    if let Err(e) = init_keyring() {
        match origin {
            ProfileOrigin::Persisted => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return Err(1);
            }
            ProfileOrigin::Synthesized => {
                tracing::warn!(
                    profile = %args.profile,
                    error = %e,
                    "platform keyring store unavailable for the synthesized zero-config \
                     profile; continuing warn-only — the audit pre-flight below already \
                     tolerates this for a synthesized profile"
                );
            }
        }
    }
    Ok((profile, origin))
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
async fn evaluate_staged_claim_policy(
    args: &ClaimArgs,
    envelope_xdr: &str,
    chain_id: &str,
    profile: &Profile,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, i32> {
    let policy_engine = match build_v1_policy_engine("claim", &profile.policy.engine, profile) {
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
        "stellar_claim_commit",
    );

    // The account view is populated only when the decode succeeded — a
    // bounded fetch of the decoded `source` (feeds `minimum_reserve`),
    // matching `claim`'s established posture.
    let mut source_view_holder = None;
    if let Ok(ref authoritative_args) = decode_result {
        let client = match StellarRpcClient::new(&args.rpc_url) {
            Ok(c) => c,
            Err(e) => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return Err(1);
            }
        };
        let source = authoritative_args
            .get("source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        source_view_holder = match fetch_account(&client, source, &[]).await {
            Ok(v) => Some(v),
            Err(e) => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return Err(1);
            }
        };
    }
    let source_adapter = source_view_holder
        .as_ref()
        .map(stellar_agent_network::policy_view::AccountViewAdapter::new);

    match dispatch_staged_claim_gate(
        policy_engine.as_ref(),
        profile,
        chain_id,
        decode_result,
        source_adapter
            .as_ref()
            .map(|a| a as &dyn AccountReservesView),
    ) {
        Ok(effects) => Ok(effects),
        Err(envelope) => {
            print_error(&envelope, args.output);
            Err(1)
        }
    }
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

async fn run_full_pipeline<LoadProfile, InitKeyring>(
    args: &ClaimArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<(Profile, ProfileOrigin), String>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // ── Resolve profile & unconditionally attempt to initialise the platform
    // keyring ──────────────────────────────────────────────────────────────
    // Unconditional (see `resolve_profile_and_keyring`'s rustdoc): the
    // origin-aware audit pre-flight below reads the profile's audit
    // chain-root HMAC key from the platform keyring regardless of the policy
    // engine, so the store must be registered before that read even on a
    // `Noop`-engine profile. A failed attempt is origin-aware: fatal for a
    // persisted profile; warn-only for the synthesized zero-config profile,
    // matching the audit pre-flight's fail-open posture for that origin (see
    // `resolve_profile_and_keyring`'s rustdoc for the full rationale).
    let (profile, origin) = match load_profile(&args.profile) {
        Ok(p) => p,
        Err(msg) => {
            print_error(
                &Envelope::<()>::err_raw("profile.load_failed", msg),
                args.output,
            );
            return 1;
        }
    };
    if let Err(e) = init_keyring() {
        match origin {
            ProfileOrigin::Persisted => {
                print_error(&Envelope::<()>::err(&e), args.output);
                return 1;
            }
            ProfileOrigin::Synthesized => {
                tracing::warn!(
                    profile = %args.profile,
                    error = %e,
                    "platform keyring store unavailable for the synthesized zero-config \
                     profile; continuing warn-only — the audit pre-flight below already \
                     tolerates this for a synthesized profile"
                );
            }
        }
    }

    // 1. Build (fetch entry, preview, guards).
    let built = match build_unsigned_envelope(args).await {
        Ok(built) => built,
        Err(e) => {
            print_error(&claim_error_envelope(&e), args.output);
            return 1;
        }
    };
    let unsigned_xdr = built.envelope_xdr.clone();

    // ── Operator policy evaluation (before signing) ───────────────────────────
    let chain_id = caip2_chain_id_for_network(args.network);
    let claim_effects = match evaluate_claim_policy(args, &built, chain_id, &profile) {
        Ok(effects) => effects,
        Err(code) => return code,
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
        &profile,
        &args.profile,
        origin,
    ) {
        Ok(w) => w,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };

    // 2. Sign.
    let signed_xdr = match sign_envelope(args, &unsigned_xdr).await {
        Ok(xdr) => xdr,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };

    // 3. Submit.
    match submit_envelope(args, &signed_xdr).await {
        Ok((xdr, sub_result)) => {
            // Non-fatal allow-path audit row: the SAME legs the gate sized
            // (single-derivation invariant), on confirmed submit. Skipped
            // entirely when no writer was acquired (the synthesized
            // zero-config profile with an unminted audit key).
            if let Some(writer) = &audit_writer {
                crate::commands::value_audit::emit_value_action_submitted_row_with_writer(
                    writer,
                    &args.profile,
                    "stellar_claim",
                    chain_id,
                    claim_effects.as_ref(),
                    &sub_result.tx_hash,
                    sub_result.ledger,
                );
            }
            crate::commands::policy_engine::record_confirmed_value_moving(
                "claim",
                &profile,
                &args.profile,
                "stellar_claim",
                chain_id,
                claim_effects.as_ref(),
            );

            let result = ClaimResult {
                envelope_xdr: xdr,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                stage: "build+sign+submit".to_owned(),
                balance_id_hex72: Some(built.balance_id_hex72),
            };
            print_success(&Envelope::ok(result), args.output);
            0
        }
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            1
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build helper
// ─────────────────────────────────────────────────────────────────────────────

/// Fetches the entry, renders a typed preview, runs the claim guards, and
/// constructs the unsigned envelope XDR.
///
/// The preview is rendered to stdout before the guards run so the operator sees
/// the balance disclosure even when a guard subsequently refuses.
async fn build_unsigned_envelope(args: &ClaimArgs) -> Result<BuiltClaimEnvelope, ClaimError> {
    let id = BalanceId::parse(&args.balance_id)?;

    // Validate the source G-strkey up front.
    stellar_strkey::ed25519::PublicKey::from_string(&args.source).map_err(|_| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: args.source.clone(),
        })
    })?;

    let client = StellarRpcClient::new(&args.rpc_url)?;

    let entry = fetch_claimable_balance_entry(&client, &id).await?;

    // Fetch the source account for the sequence number and native balance.
    // Empty trustline-request slice: the trustline guard fetch (below) is a
    // separate call keyed on the balance's own asset.
    let account_view = fetch_account(&client, &args.source, &[]).await?;

    let now_secs = current_unix_secs()?;
    let preview = ClaimPreview::build(&entry, &args.source, now_secs)?;

    // ── Render the typed preview before running the guards ────────────────────
    render_preview(&preview, args.output);

    // ── Claim guards, in order ────────────────────────────────────────────────
    require_claimant(&preview, &args.source)?;
    require_predicate_satisfied(&preview)?;
    if preview.asset_code.is_some() {
        let code = preview.asset_code.as_deref().unwrap_or_default();
        let issuer = preview.asset_issuer.as_deref().unwrap_or_default();
        let state = fetch_trustline_state(&client, &args.source, code, issuer).await?;
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
        resolve_classic_fee_selection(&client, DEFAULT_FEE_STROOPS, fee_choice).await?;
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
        args.network.passphrase(),
        fee_per_op,
    );
    builder.claim_claimable_balance(&id.to_hex64())?;
    let envelope_xdr = builder.build()?;

    Ok(BuiltClaimEnvelope {
        envelope_xdr,
        balance_id_hex72: id.to_hex72(),
        fee_selection,
        account_view,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator policy gate
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluates operator policy for the built claim, using the same engine path
/// (and `stellar_claim` value descriptor contract) the `stellar_claim` MCP
/// tool's dispatch gate uses.
///
/// Returns `None` when the operation is allowed (the caller proceeds to
/// signing); returns `Some(exit_code)` — with the refusal envelope already
/// rendered — when the operation must be refused.
///
/// `profile` is the already-resolved profile from the caller's top-of-gated-
/// path load (see `run_build_only` / `run_full_pipeline`); this function does
/// not re-resolve it, so the platform keyring store the caller already
/// initialised (conditionally on `run_build_only`; unconditionally on
/// `run_full_pipeline`, ahead of its origin-aware audit pre-flight) remains
/// registered for the `build_v1_policy_engine` owner-key read below.
fn evaluate_claim_policy(
    args: &ClaimArgs,
    built: &BuiltClaimEnvelope,
    chain_id: &str,
    profile: &Profile,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, i32> {
    let policy_engine = match build_v1_policy_engine("claim", &profile.policy.engine, profile) {
        Ok(pe) => pe,
        Err(msg) => {
            print_error(
                &Envelope::<()>::err_raw("policy.engine_unavailable", msg),
                args.output,
            );
            return Err(1);
        }
    };
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
    match evaluate_value_moving_policy(
        policy_engine.as_ref(),
        profile,
        "stellar_claim",
        stellar_agent_core::policy::ToolValueKind::MovesValue,
        chain_id,
        &policy_args,
        "claim",
        Some(&source_adapter),
        None,
    ) {
        Ok(effects) => Ok(effects),
        Err(envelope) => {
            print_error(&envelope, args.output);
            Err(1)
        }
    }
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
/// mismatch check, or the signing call. Returns `AuthError::KeyringLocked` when
/// neither signer flag is provided.
async fn sign_envelope(args: &ClaimArgs, unsigned_xdr: &str) -> Result<String, WalletError> {
    let source = args.source.as_str();
    let passphrase = args.network.passphrase();

    if args.sign_with_ledger {
        let signer = signer_from_ledger(args.account_index, source).await?;
        return attach_signature(unsigned_xdr, &signer, passphrase).await;
    }

    if let Some(ref var_name) = args.secret_env {
        // mlock-protected signing window (shared ceremony, identical
        // discipline to `pay`). A degraded mlock unlock is a separate,
        // orthogonal concern from the audit pre-flight the caller already ran
        // before this function; see `pay::sign_envelope` for the same
        // rationale.
        let SignerCeremonyOutcome {
            signer,
            mlock_degradation: _,
        } = resolve_software_signer_from_env(var_name, "claim-commit", None).await?;

        // Public-key verification before signing.
        let signer_pk = signer.public_key().await?;
        let signer_gstrkey = signer_pk.to_string().to_string();
        if signer_gstrkey != source {
            return Err(WalletError::Auth(AuthError::SignerKeyMismatch {
                expected: source.to_owned(),
                got: signer_gstrkey,
            }));
        }

        let signed_xdr = attach_signature(unsigned_xdr, &signer, passphrase).await?;
        drop(signer);

        return Ok(signed_xdr);
    }

    Err(WalletError::Auth(AuthError::KeyringLocked))
}

// ─────────────────────────────────────────────────────────────────────────────
// Submit helper
// ─────────────────────────────────────────────────────────────────────────────

async fn submit_envelope(
    args: &ClaimArgs,
    signed_xdr: &str,
) -> Result<(String, SubmissionResult), WalletError> {
    let client = StellarRpcClient::new(&args.rpc_url)?;
    let timeout = Duration::from_secs(args.timeout_seconds);
    let passphrase = args.network.passphrase();
    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        timeout,
        passphrase,
        Some(SubmissionSignerKind::Software),
    )
    .await?;
    Ok((signed_xdr.to_owned(), result))
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Renders the typed claim preview to stdout (JSON), before the guards run.
fn render_preview(preview: &ClaimPreview, format: OutputFormat) {
    let envelope = Envelope::ok(serde_json::json!({
        "stage": "preview",
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
    }));
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            {
                println!(
                    "[preview] balance {}  asset {}  amount {}  is_claimant {}",
                    preview.balance_id_strkey,
                    preview.asset_code.as_deref().unwrap_or("XLM"),
                    preview.amount_display,
                    preview.is_claimant
                );
            }
        }
        _ => render_json(&envelope),
    }
}

/// Builds an error envelope from a [`ClaimError`], preserving its stable
/// `claim.*` / delegated wire code and its (secret-free) display message.
fn claim_error_envelope(err: &ClaimError) -> Envelope<()> {
    Envelope::<()>::err_raw(err.code(), err.to_string())
}

fn print_success(envelope: &Envelope<ClaimResult>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(result) = &envelope.data {
                match (&result.tx_hash, &result.ledger) {
                    (Some(hash), Some(ledger)) => {
                        use stellar_agent_network::submit::redact_tx_hash;
                        println!(
                            "Claim submitted: tx_hash {}  ledger {}",
                            redact_tx_hash(hash),
                            ledger
                        );
                    }
                    _ => {
                        let prefix: String = result.envelope_xdr.chars().take(32).collect();
                        println!(
                            "[{}] envelope_xdr (first 32 chars): {}...",
                            result.stage, prefix
                        );
                    }
                }
            }
        }
        _ => render_json(envelope),
    }
}

fn print_error(envelope: &Envelope<()>, format: OutputFormat) {
    match format {
        OutputFormat::Table =>
        {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(err) = &envelope.error {
                let safe_msg = sanitize_for_table(&err.message);
                println!("Error: {} — {}", err.code, safe_msg);
            }
        }
        _ => render_json(envelope),
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
            profile: "default".to_owned(),
            balance_id: HEX64.to_owned(),
            source: SOURCE_G.to_owned(),
            fee: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            build_only: false,
            sign_only: None,
            submit_only: None,
            network: TargetNetwork::Testnet,
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: TESTNET_RPC_URL.to_owned(),
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
        assert_eq!(parsed.network, TargetNetwork::Testnet);
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

    /// Mainnet is rejected at the `run` boundary before any RPC call. The
    /// non-routable RPC address ensures an accidental call would fail with a
    /// connection error rather than silently succeeding.
    #[tokio::test]
    async fn mainnet_rejected_at_run_boundary() {
        let mut args = minimal_args();
        args.network = TargetNetwork::Mainnet;
        args.rpc_url = "http://127.0.0.1:1".to_owned();
        let exit = run(&args).await;
        assert_eq!(exit, 1, "mainnet must exit with code 1");
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
            move |_name| {
                loaded_writer.store(true, Ordering::SeqCst);
                let profile = Profile::builder_testnet_named(
                    "keyring-order-test",
                    "stellar-agent-signer",
                    "keyring-order-test",
                    "stellar-agent-nonce",
                    "keyring-order-test",
                )
                .policy_engine(PolicyEngineKind::V1)
                .build();
                Ok((profile, ProfileOrigin::Persisted))
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
            |_name| {
                let profile = Profile::builder_testnet_named(
                    "keyring-order-test-noop",
                    "stellar-agent-signer",
                    "keyring-order-test-noop",
                    "stellar-agent-nonce",
                    "keyring-order-test-noop",
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build();
                Ok((profile, ProfileOrigin::Persisted))
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
            "invalid balance id must still refuse (unrelated to the keyring gate)"
        );
    }

    // ── resolve_profile_and_keyring — origin-aware keyring-init failure (#88) ─
    //
    // `resolve_profile_and_keyring` backs `run_sign_only` / `run_submit_only`
    // and is exercised directly here (sync, no RPC or gate involved): the
    // Synthesized/Persisted split is the WHOLE behavior under test, so a
    // direct call pins it precisely without the extra RPC-mocked surface a
    // full `--sign-only` run would add.

    /// A [`ProfileOrigin::Synthesized`] profile must tolerate a platform
    /// keyring-init failure and return `Ok` — not refuse — matching the
    /// zero-config quickstart's fail-open posture. Catches the regression
    /// where this failure was unconditionally fatal regardless of origin,
    /// which would break `claim --secret-env ...` with no profile file on any
    /// host without a platform keyring (e.g. a container without a Secret
    /// Service).
    #[test]
    fn resolve_profile_and_keyring_synthesized_tolerates_init_failure() {
        let args = minimal_args();
        let result = resolve_profile_and_keyring(
            &args,
            |name| {
                let profile = Profile::builder_testnet_named(
                    name,
                    "stellar-agent-signer",
                    name,
                    "stellar-agent-nonce",
                    name,
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build();
                Ok((profile, ProfileOrigin::Synthesized))
            },
            || {
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "resolve-profile-and-keyring-synthesized-sentinel".to_owned(),
                }))
            },
        );
        let (_profile, origin) =
            result.expect("a synthesized zero-config profile must tolerate a keyring-init failure");
        assert_eq!(origin, ProfileOrigin::Synthesized);
    }

    /// A [`ProfileOrigin::Persisted`] profile must refuse (`Err(1)`) when the
    /// platform keyring store fails to initialise: an operator who authored a
    /// profile file is expected to have a working platform keyring for both
    /// the fail-closed audit pre-flight and the keyring-backed owner-key
    /// read, so this failure stays fatal.
    #[test]
    fn resolve_profile_and_keyring_persisted_fails_on_init_failure() {
        let args = minimal_args();
        let result = resolve_profile_and_keyring(
            &args,
            |name| {
                let profile = Profile::builder_testnet_named(
                    name,
                    "stellar-agent-signer",
                    name,
                    "stellar-agent-nonce",
                    name,
                )
                .policy_engine(PolicyEngineKind::Noop)
                .build();
                Ok((profile, ProfileOrigin::Persisted))
            },
            || {
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "resolve-profile-and-keyring-persisted-sentinel".to_owned(),
                }))
            },
        );
        match result {
            Err(code) => assert_eq!(
                code, 1,
                "a persisted profile must refuse with exit code 1 when the platform \
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
}
