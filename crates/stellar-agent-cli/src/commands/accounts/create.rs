//! `stellar-agent accounts create` subcommand — account creation.
//!
//! Creates or funds a Stellar account on-chain in one of two mutually-exclusive
//! modes:
//!
//! ## Mode A — sponsored `CreateAccount`
//!
//! Required flags: `--sponsor <G-strkey>`, a signer source
//! (`--secret-env <VAR>` or `--sign-with-ledger`), and
//! `--starting-balance <amount>`.
//!
//! The new account public key is supplied as a positional `<new-G-strkey>`
//! argument OR generated in-process with `--generate`. The sponsor's public
//! key must match the signer-derived public key (same guard as the `pay`
//! command). Submits a `CreateAccount` op via `ClassicOpBuilder` and the
//! sign + submit pipeline.
//!
//! ## Mode B — Friendbot
//!
//! Required flag: `--fund-with-friendbot`. The account public key is
//! supplied as a positional argument or generated with `--generate`.
//! Friendbot creates a missing account and pays an existing account whose
//! balance is below the Friendbot starting balance. At or above the Friendbot
//! starting balance, it refuses funding.
//! Structurally refused on mainnet at two layers:
//!
//! 1. CLI enum: `TargetNetwork::Mainnet` returns
//!    `network.friendbot_mainnet_forbidden` before any HTTP call.
//! 2. Network layer: `fund_with_friendbot` rejects mainnet passphrases.
//!
//! ## Keypair generation (`--generate`)
//!
//! When `--generate` is present, a fresh ed25519 keypair is generated
//! in-process using `SigningKey::generate(&mut OsRng)`. Both the G-strkey
//! (public) and S-strkey (secret) are included in the output envelope's
//! `data.secret_key` field. The S-strkey is NEVER emitted in table-mode
//! output or in any `tracing` event.
//!
//! ## Mutual exclusivity
//!
//! - `--fund-with-friendbot` and `--sponsor` are mutually exclusive
//!   (verified at argument-group level by clap).
//! - `--generate` and the positional `<new-G-strkey>` are mutually exclusive.
//! - Providing neither mode is a missing-required-group parse error.
//!
//! # mlock-protected signing window
//!
//! The `--secret-env` sponsored-mode path routes through the shared
//! `resolve_software_signer_from_env` ceremony (`Wallet::unlock` →
//! `LockedSeed` mlock-protected page → `signer_from_wallet` → dispose) →
//! `attach_signature` → drop. The `--sign-with-ledger` path uses
//! `signer_from_ledger` (hardware signer; no seed ever held in process memory).
//!
//! # Operator policy evaluation (sponsored mode only)
//!
//! After `--starting-balance` and the new account's public key are resolved,
//! the profile is resolved (and, when it carries `policy.engine = "v1"`, the
//! platform keyring store is initialised) before `sponsored_create` builds
//! any network request, signs, or submits. The sponsored `CreateAccount` is
//! then evaluated against the operator-signed `PolicyEngineV1` (V1 profiles)
//! or the permissive `NoopPolicyEngine` (`Noop` profiles), mirroring the
//! `stellar_create_account` MCP tool's dispatch gate. When NO profile was
//! named and no persisted `default.toml` file exists, an in-memory
//! `Noop`-engine testnet profile is synthesized (tagged
//! [`crate::common::profile_access::ProfileOrigin::Synthesized`]) so
//! sponsored mode keeps working without an authored profile file; a profile
//! the operator NAMED — through `--profile` or `STELLAR_AGENT_PROFILE` — but
//! never authored is refused instead. Friendbot
//! mode is not gated: it funds an eligible account from the external Friendbot
//! faucet and debits no wallet-held funds, and touches no keyring.
//!
//! # Halted profile (both modes)
//!
//! Right after the profile resolves, a halted profile refuses both modes with
//! `profile.halted`, or `profile.halt_unreadable` for a marker that cannot be
//! read, before any keyring access, signer read, or network request. The MCP
//! `stellar_friendbot` tool refuses the same way.
//!
//! # Audit pre-flight (sponsored mode only; fail-closed for a persisted
//! profile, fail-open for the synthesized zero-config profile)
//!
//! Before `sponsored_create` touches the signer or submits, sponsored mode
//! resolves the audit writer via
//! [`crate::commands::value_audit::require_value_audit_writer_for_origin`].
//! For a persisted `<name>.toml` profile this fails closed with
//! `audit.chain_key_unavailable` if the profile's audit chain-root HMAC key
//! is not acquirable — an init-minted profile has no audit key until
//! `stellar-agent profile rotate-audit-key <name>` mints one. For the
//! synthesized zero-config profile the pre-flight stays fail-open (warn-only,
//! no refusal). Friendbot mode signs nothing and emits no audit row, so it is
//! exempt (same rationale as the policy gate above). Where a writer was
//! acquired, it is reused (not re-acquired) for the post-confirm
//! `value_action_submitted` row.
//!
//! # Endpoint identity (sponsored mode)
//!
//! Sponsored mode builds one client and asks the endpoint which network it
//! serves before the sponsor read. That one sponsor observation feeds the
//! policy gate, the witness and the envelope sequence. The reconcile, the fee
//! read and the send use the same client. The submit layer checks the sending
//! client again before the send, and it separately reads the sponsor's signer
//! set to verify the signature binding.
//!
//! # Behavior
//!
//! - All RPC calls go through Stellar RPC.
//! - Ledger signing is available via `--sign-with-ledger`.
//! - The `--secret-env` path holds the seed only inside an mlock-protected
//!   signing window.

use std::time::Duration;

use clap::{ArgGroup, Args};
use rand_core::OsRng;
use stellar_agent_core::StellarAmount;
use stellar_agent_core::asset_id::CanonicalAsset;
use stellar_agent_core::cross_check::CrossCheckValue;
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{AuthError, NetworkError, ValidationError, WalletError};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::NetworkContext;
use stellar_agent_network::cross_check::{
    AccountObservation, CreateAccountWitnessInputs, CrossCheckView, obtain_classic_witness,
};
use stellar_agent_network::fees::check_built_fee_cap;
use zeroize::Zeroizing;

use stellar_agent_network::builder::ClassicOpBuilder;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_network::{
    ClassicFeeChoice, ClassicFeeSelection, StellarRpcClient, SubmissionResult,
    SubmissionSignerKind, init_platform_keyring_store, parse_classic_fee_choice,
    resolve_classic_fee_selection, submit_transaction_and_wait,
};
use stellar_agent_network::{FriendbotResult, fund_with_friendbot};

use crate::commands::policy_engine::{
    build_v1_policy_engine, create_policy_args, evaluate_value_moving_policy,
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

/// Default fee per operation in stroops.
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Default Friendbot URL for testnet (SDF operated).
const DEFAULT_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// CreateMode — typed mode discriminant (replaces mode: String)
// ─────────────────────────────────────────────────────────────────────────────

/// Discriminant for the account-creation mode used in [`CreateAccountResult`].
///
/// Serialises to `"sponsored"` / `"friendbot"` (lowercase). Round-trip tests
/// verify the serialised form.
///
/// `#[non_exhaustive]` is applied because future modes may be added
/// (e.g. `multisig`, `passkey`). The `print_success` match arm covers the
/// `_` arm for forward-compat with an explicit `render_json` fallback and a
/// comment explaining why.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CreateMode {
    /// Account created via a sponsored `CreateAccount` operation.
    Sponsored,
    /// Account funded via the Stellar Friendbot HTTP endpoint.
    Friendbot,
}

// ─────────────────────────────────────────────────────────────────────────────
// CreateAccountResult — the structured success payload
// ─────────────────────────────────────────────────────────────────────────────

/// Structured payload returned in the JSON envelope on a successful account
/// creation.
///
/// # Secret-key discipline
///
/// `secret_key` is populated only when `--generate` is used. It is captured
/// by the caller from the JSON output; it is **never** emitted in table-mode
/// output and **never** passed through any `tracing` event. The operator is
/// responsible for storing the S-strkey securely after capturing it from the
/// JSON envelope.
#[non_exhaustive]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreateAccountResult {
    /// The new account's G-strkey.
    pub account_id: String,

    /// The generated S-strkey for the new account.
    ///
    /// Populated only when `--generate` is passed; `None` when the caller
    /// supplied a positional `<new-G-strkey>`.
    ///
    /// Captured by the caller; never logged.
    ///
    /// # Capture warning
    ///
    /// This field is the operator's only copy of the newly-generated private
    /// key. On its way to the operator it transits multiple non-zeroised
    /// heap allocations (serde serialisation buffers, the `String` passed
    /// to `println!`, OS stdout buffers). Operational consequences:
    ///
    /// - **Terminal scrollback** retains the S-strkey until cleared.
    /// - **Shell history** captures it if the command was run interactively
    ///   without output redirection.
    /// - **Log aggregators** that ingest stdout keep the secret indefinitely.
    /// - **Core dumps** may capture the serialisation buffers verbatim.
    ///
    /// Recommended capture pattern: pipe the JSON output directly to a
    /// restrictive-permission file or a secret-manager CLI, never interactively.
    /// For example, `umask 077 && stellar-agent accounts create --generate ... >
    /// secret.json` places the output under the caller's umask without
    /// touching shell history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,

    /// Which mode produced this result.
    pub mode: CreateMode,

    /// Transaction hash (64-character hex), present after sponsored
    /// submission or from the Friendbot response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,

    /// Confirmed ledger sequence number (sponsored mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger: Option<u32>,

    /// The Friendbot endpoint URL that was called (friendbot mode only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub friendbot_url_used: Option<String>,

    /// Selected per-operation fee in stroops for sponsored mode.
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

    /// Fee selection source for sponsored mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_fee_percentile: Option<String>,

    /// Transaction-specific cross-check outcome for sponsored creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cross_check: Option<CrossCheckView>,
}

/// A failed sponsored create. `signed_xdr` is `Some` only once the envelope
/// is signed, so the error details carry an envelope hash only then.
struct SponsoredCreateFailure {
    error: WalletError,
    signed_xdr: Option<String>,
}

impl From<WalletError> for SponsoredCreateFailure {
    fn from(error: WalletError) -> Self {
        Self {
            error,
            signed_xdr: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CreateArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `accounts create` subcommand.
///
/// Two mutually-exclusive mode groups:
/// - **sponsored**: `--sponsor` + (`--secret-env` | `--sign-with-ledger`) +
///   `--starting-balance`. Positional `<new-G-strkey>` or `--generate`.
/// - **friendbot**: `--fund-with-friendbot`. Positional `<new-G-strkey>` or
///   `--generate`.
///
/// The `mode_group` ArgGroup enforces that at least one mode flag is present
/// and that the two modes are mutually exclusive. The `account_group` enforces
/// that exactly one of positional `<new-G-strkey>` or `--generate` is used.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("mode_group")
            .args(["sponsor", "fund_with_friendbot"])
            .required(true)
    ),
    group(
        ArgGroup::new("account_group")
            .args(["new_account", "generate"])
            .required(true)
    ),
    group(
        ArgGroup::new("signer_group")
            .args(["secret_env", "sign_with_ledger"])
            .required(false)
    ),
)]
pub struct CreateArgs {
    /// Profile supplying the chain and endpoints for either funding mode.
    ///
    /// Resolution order: this flag, then `STELLAR_AGENT_PROFILE`, then the
    /// literal `"default"`. When NO profile was named and no `default.toml`
    /// file exists, an in-memory `Noop`-engine testnet profile is synthesized
    /// so sponsored mode keeps working without an authored profile file; a
    /// named profile with no file is refused. See
    /// [`crate::common::profile_access::load_profile_or_synthesize_testnet`].
    #[arg(long = "profile", value_name = "NAME")]
    pub profile: Option<String>,

    /// New account G-strkey. Mutually exclusive with `--generate`.
    #[arg(value_name = "NEW_G_STRKEY", group = "account_group")]
    pub new_account: Option<String>,

    /// Generate a fresh ed25519 keypair in-process.
    ///
    /// Returns both the G-strkey and S-strkey in the JSON envelope.
    /// Mutually exclusive with the positional `<new-G-strkey>` argument.
    #[arg(long, group = "account_group")]
    pub generate: bool,

    /// Starting balance for the new account (e.g. `"5 XLM"`).
    ///
    /// Required for sponsored mode. Bare numeric inputs are rejected; units
    /// are mandatory.
    #[arg(long, value_name = "AMOUNT")]
    pub starting_balance: Option<String>,

    /// Sponsor G-strkey — source account for the `CreateAccount` op.
    ///
    /// Required for sponsored mode. Mutually exclusive with
    /// `--fund-with-friendbot`.
    #[arg(long, value_name = "G_STRKEY", group = "mode_group")]
    pub sponsor: Option<String>,

    /// Name of the environment variable holding the sponsor's S-strkey.
    ///
    /// The value is never logged.
    #[arg(long, value_name = "VAR", group = "signer_group")]
    pub secret_env: Option<String>,

    /// Sign using the connected Ledger hardware wallet.
    #[arg(long, group = "signer_group")]
    pub sign_with_ledger: bool,

    /// Ledger BIP-44 account index (default 0).
    #[arg(long, default_value_t = 0_u32, value_name = "INDEX")]
    pub account_index: u32,

    /// Fund using the Stellar Friendbot HTTP endpoint.
    ///
    /// Testnet only. Structurally refused on mainnet.
    /// Mutually exclusive with `--sponsor`.
    #[arg(long, group = "mode_group")]
    pub fund_with_friendbot: bool,

    /// The network comes from the profile when absent.
    /// When supplied, this flag must equal the profile's chain.
    #[arg(long, value_name = "NETWORK")]
    pub network: Option<TargetNetwork>,

    /// Friendbot endpoint URL.
    #[arg(
        long,
        default_value = DEFAULT_FRIENDBOT_URL,
        value_name = "URL"
    )]
    pub friendbot_url: String,

    /// Classic fee per operation for sponsored mode: `<stroops>`, `auto`, or `auto:pNN`.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Timeout in seconds for the endpoint check and, separately, for the
    /// submission (sponsored mode). Default: 60.
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

/// Runs the `accounts create` subcommand.
///
/// Dispatches to sponsored mode or Friendbot mode based on the provided flags,
/// then renders the result per `args.output`.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — all errors are captured into the envelope.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &CreateArgs) -> i32 {
    run_with_dependencies(args, injected_profile_load, init_platform_keyring_store).await
}

/// Testable core of [`run`] with the profile loader and the platform-keyring
/// initialiser injected.
///
/// Production callers use [`run`], which supplies the real profile loader and
/// [`init_platform_keyring_store`]. Tests substitute an in-memory profile and
/// a spy initialiser to assert the keyring store is registered before the V1
/// policy gate's owner-key read (see `run_sponsored`) without touching the OS
/// keychain. Both arms receive the loaded profile; only the sponsored arm
/// receives the keyring initialiser, because Friendbot mode is not gated (see
/// the module-level doc comment) and touches no keyring.
///
/// # The injected closure LOADS ONLY
///
/// `load_profile` performs the load and nothing else. Whether a `NotFound`
/// may be replaced by the synthesized zero-config profile is decided by
/// [`load_profile_or_synthesize_testnet_with`], which this function calls once,
/// at entry, with the resolved name. The refusal for a named-but-missing
/// profile therefore runs on the injected path exactly as it does in
/// production. A check placed inside the closure would be bypassed by every
/// test that supplies its own.
async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &CreateArgs,
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
    // Halt check, both modes: a halted profile refuses the sponsored creation
    // and the Friendbot funding before any keyring access, signer read, or
    // network request, as the MCP `stellar_friendbot` tool refuses.
    if let Err(e) = stellar_agent_core::profile::halt::ensure_not_halted(&resolved.name) {
        print_error(&Envelope::<()>::err(&e), args.output);
        return 1;
    }
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
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };
    tracing::debug!(profile = %resolved.name, profile_source = resolved.source.as_str(), "accounts create: profile resolved");
    if args.fund_with_friendbot {
        run_friendbot(&context, args).await
    } else {
        run_sponsored(&context, args, &resolved, &profile, origin, init_keyring).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Keypair resolution
// ─────────────────────────────────────────────────────────────────────────────

/// The resolved new-account identity: G-strkey plus an optional S-strkey.
///
/// `secret` is `Some` only when `--generate` was passed. It is handled as a
/// `Zeroizing<String>` so the heap allocation is cleared when this struct
/// drops.
///
/// Implements `Debug` via `Zeroizing<String>`'s redacting `Debug` impl
/// (prints `"[REDACTED]"` for the secret content) — safe to use in
/// `assert!` / `unwrap_err` contexts without leaking secret bytes.
#[derive(Debug)]
struct NewAccount {
    /// G-strkey of the new account.
    pub g_strkey: String,
    /// S-strkey — present only when generated in-process.
    ///
    /// Captured by the caller; never logged.
    pub secret: Option<Zeroizing<String>>,
}

/// Resolves or generates the new account keypair.
///
/// When `--generate` is set, generates a fresh ed25519 keypair using
/// `OsRng`. Otherwise, parses and validates the positional G-strkey.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] wrapping [`ValidationError::AddressInvalid`]
/// if the positional argument is not a valid G-strkey.
fn resolve_new_account(args: &CreateArgs) -> Result<NewAccount, WalletError> {
    if args.generate {
        // Generate a fresh ed25519 keypair in-process.
        // `SigningKey` is `ZeroizeOnDrop` via ed25519-dalek's `zeroize` feature.
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let g_strkey = stellar_strkey::ed25519::PublicKey(verifying_key.to_bytes())
            .to_string()
            .to_string();

        // Seed-to-strkey zeroisation — mirrors the pay.rs pattern.
        // stellar-strkey 0.0.16's `PrivateKey` is `Copy` with no `Drop`/
        // `Zeroize` impl. Wrap the seed in `Zeroizing` so the stack copy is
        // cleared on drop; copy into `PrivateKey`; stringify inside
        // `Zeroizing`; then explicitly zeroise the `PrivateKey.0` Copy residue
        // before it falls out of scope.
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
        let mut private_key = stellar_strkey::ed25519::PrivateKey(*seed);
        let s_strkey: Zeroizing<String> =
            Zeroizing::new(private_key.as_unredacted().to_string().as_str().to_owned());
        zeroize::Zeroize::zeroize(&mut private_key.0);
        // signing_key drops here via ZeroizeOnDrop.
        drop(signing_key);

        Ok(NewAccount {
            g_strkey,
            secret: Some(s_strkey),
        })
    } else {
        // Positional arg — validate it is a G-strkey.
        let addr = args.new_account.as_deref().unwrap_or(""); // clap enforces account_group required; empty is unreachable.

        stellar_strkey::ed25519::PublicKey::from_string(addr).map_err(|_| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: addr.to_owned(),
            })
        })?;

        Ok(NewAccount {
            g_strkey: addr.to_owned(),
            secret: None,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Friendbot mode
// ─────────────────────────────────────────────────────────────────────────────

async fn run_friendbot(context: &NetworkContext, args: &CreateArgs) -> i32 {
    // No operator-policy gate here: Friendbot mode funds the account from
    // the external testnet faucet and debits no wallet-held funds, so there is
    // no value-moving leg for the policy engine to evaluate.
    // First layer: structural mainnet rejection.
    if context.chain_id.is_mainnet() {
        let err = WalletError::Network(NetworkError::FriendbotMainnetForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    let new_account = match resolve_new_account(args) {
        Ok(a) => a,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let passphrase = context.network_passphrase();

    // Second layer: fund_with_friendbot rejects mainnet passphrase.
    match fund_with_friendbot(
        &args.friendbot_url,
        &new_account.g_strkey,
        passphrase,
        &context.rpc_url,
    )
    .await
    {
        Ok(fb_result) => {
            let result = build_friendbot_result(&new_account, &fb_result);
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

fn build_friendbot_result(new_account: &NewAccount, fb: &FriendbotResult) -> CreateAccountResult {
    // secret_key: clone out of Zeroizing<String> only for JSON output.
    // The cloned String value is stored in the envelope; the Zeroizing
    // wrapper on `new_account.secret` continues to hold its copy and
    // zeroes it on drop when the NewAccount goes out of scope.
    let secret_key = new_account.secret.as_ref().map(|s| s.as_str().to_owned());

    CreateAccountResult {
        account_id: new_account.g_strkey.clone(),
        secret_key,
        mode: CreateMode::Friendbot,
        tx_hash: Some(fb.tx_hash.clone()),
        ledger: None,
        friendbot_url_used: Some(fb.friendbot_url_used.clone()),
        selected_fee_per_op_stroops: None,
        selected_fee_percentile: None,
        cross_check: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator policy gate (sponsored mode only)
// ─────────────────────────────────────────────────────────────────────────────

/// Evaluates operator policy for the resolved sponsored `CreateAccount`,
/// using the same engine path (and `stellar_create_account` value descriptor
/// contract) the `stellar_create_account` MCP tool's dispatch gate uses.
///
/// Returns `Ok(value_effects)` when the operation is allowed (the caller
/// proceeds to signing) — the gate-sized effects the caller records on
/// confirmed submit (`Some` for the value-moving allow, `None` for the no-op
/// engine); returns `Err(exit_code)` — with the refusal envelope already
/// rendered — when the operation must be refused.
///
/// `profile` is the profile `run_with_dependencies` loaded at entry. This
/// function does not re-resolve it. The platform keyring store that
/// `run_sponsored` initialised ahead of its origin-aware audit pre-flight
/// therefore stays registered for the `build_v1_policy_engine` owner-key read
/// below.
fn evaluate_create_policy(
    args: &CreateArgs,
    profile: &Profile,
    profile_name: &str,
    starting_balance_stroops: i64,
    new_account_g_strkey: &str,
    chain_id: &str,
    sponsor_account_view: &stellar_agent_network::AccountView,
) -> Result<Option<stellar_agent_core::policy::v1::ValueEffects>, i32> {
    let policy_engine = match build_v1_policy_engine(
        "accounts create",
        &profile.policy.engine,
        profile,
        profile_name,
    ) {
        Ok(pe) => pe,
        Err(msg) => {
            print_error(
                &Envelope::<()>::err_raw("policy.engine_unavailable", msg),
                args.output,
            );
            return Err(1);
        }
    };
    // `derive_value_class` forces the asset to native for `stellar_create_account`
    // — no "asset" key is needed here.
    let policy_args = create_policy_args(starting_balance_stroops, new_account_g_strkey);
    // `account_view` feeds `minimum_reserve` on the SPONSOR (the source
    // account debited for the starting balance), mirroring the
    // `stellar_create_account` MCP twin. `identity_view` is `None`: the new
    // account does not yet exist, so it has no on-chain `home_domain` to
    // resolve — matching the twin exactly.
    let sponsor_adapter =
        stellar_agent_network::policy_view::AccountViewAdapter::new(sponsor_account_view);
    match evaluate_value_moving_policy(
        policy_engine.as_ref(),
        profile,
        "stellar_create_account",
        stellar_agent_core::policy::ToolValueKind::MovesValue,
        chain_id,
        &policy_args,
        "accounts create",
        Some(&sponsor_adapter),
        None,
    ) {
        Ok(effects) => Ok(effects),
        Err(envelope) => {
            print_error(&envelope, args.output);
            Err(1)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sponsored mode
// ─────────────────────────────────────────────────────────────────────────────

async fn run_sponsored<InitKeyring>(
    context: &NetworkContext,
    args: &CreateArgs,
    resolved: &ResolvedProfileName,
    profile: &Profile,
    origin: ProfileOrigin,
    init_keyring: InitKeyring,
) -> i32
where
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // Sponsored mode — mainnet write forbidden.
    if context.chain_id.is_mainnet() {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    let sponsor = match &args.sponsor {
        Some(s) => s.clone(),
        None => {
            // clap mode_group enforces at least one of sponsor/fund_with_friendbot;
            // reaching this branch is structurally impossible at runtime. Surface as
            // internal state rather than silently doing nothing.
            let err = WalletError::Validation(ValidationError::AddressInvalid {
                input: "--sponsor is required for sponsored mode".to_owned(),
            });
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let starting_balance_str = match &args.starting_balance {
        Some(s) => s.clone(),
        None => {
            let err = WalletError::Validation(ValidationError::AmountMalformed {
                input: "--starting-balance is required for sponsored mode".to_owned(),
            });
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    // Boundary discipline: parse_with_unit is the only permitted parser for
    // human-supplied amounts at CLI boundaries.
    let starting_balance = match StellarAmount::parse_with_unit(&starting_balance_str) {
        Ok(a) => a,
        Err(_) => {
            let err = WalletError::Validation(ValidationError::AmountMalformed {
                input: starting_balance_str.clone(),
            });
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let new_account = match resolve_new_account(args) {
        Ok(a) => a,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    // ── Resolve profile & unconditionally attempt to initialise the platform
    // keyring ──────────────────────────────────────────────────────────────
    // Must happen before `sponsored_create`'s network build. Unconditional
    // (not gated on `profile.policy.engine`): the origin-aware audit
    // pre-flight below reads the profile's audit chain-root HMAC key from the
    // platform keyring regardless of the policy engine — a `Noop` engine
    // reads no OWNER key, but the audit key is a separate, engine-independent
    // requirement — so the store must be registered before that read even on
    // a `Noop`-engine profile.
    //
    // A failed initialisation attempt is origin-aware: [`ProfileOrigin::Persisted`]
    // treats it as fatal — an operator who authored a profile file is
    // expected to have a working platform keyring for both the fail-closed
    // audit pre-flight and the keyring-backed owner-key read.
    // [`ProfileOrigin::Synthesized`] (the zero-config quickstart — no profile
    // file, no keyring ceremony the operator opted into) logs a
    // `tracing::warn!` and continues: the origin-aware audit pre-flight run
    // next already tolerates the SAME acquisition failure for a synthesized
    // profile, so a host with no platform keyring store (e.g. a container
    // without a Secret Service) never blocks the documented no-setup
    // quickstart.
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

    // One primary sponsor observation feeds policy, the witness, and the builder.
    // The checked client also resolves the fee and submits the transaction.
    let client = match context.primary_client() {
        Ok(c) => c,
        Err(e) => {
            print_error(&Envelope::<()>::err(&e), args.output);
            return 1;
        }
    };
    if let Err(e) =
        check_endpoint_identity(&client, context, Duration::from_secs(args.timeout_seconds)).await
    {
        print_error(&Envelope::<()>::err(&e), args.output);
        return 1;
    }
    let sponsor_account_view =
        match stellar_agent_network::fetch_account(&client, &sponsor, &[]).await {
            Ok(v) => v,
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

    // ── Operator policy evaluation (before signing/submission) ───────────────
    let chain_id = context.chain_id.caip2_str();
    let starting_balance_stroops = starting_balance.as_stroops();
    let create_effects = match evaluate_create_policy(
        args,
        profile,
        &resolved.name,
        starting_balance_stroops,
        &new_account.g_strkey,
        chain_id,
        &sponsor_account_view,
    ) {
        Ok(effects) => effects,
        Err(code) => return code,
    };

    let (fee_choice, fee_selection) = match select_create_fee(&client, args).await {
        Ok(selection) => selection,
        Err(error) => {
            print_error(&Envelope::<()>::err(&error), args.output);
            return 1;
        }
    };
    if let Err(error) = check_built_fee_cap(fee_selection.per_op_stroops, fee_choice, profile) {
        print_error(&Envelope::<()>::err(&error), args.output);
        return 1;
    }
    let source = match AccountObservation::from_view(&sponsor_account_view) {
        Ok(source) => source,
        Err(error) => {
            print_error(&Envelope::<()>::err(&error), args.output);
            return 1;
        }
    };
    let cross_check = match obtain_classic_witness(
        profile,
        context,
        CrossCheckValue::Amount {
            asset: &CanonicalAsset::Native,
            base_units: i128::from(starting_balance_stroops),
        },
        CreateAccountWitnessInputs { source },
        "stellar_create_account",
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            print_error(&Envelope::<()>::err(&error), args.output);
            return 1;
        }
    };

    // ── Audit pre-flight (sponsored mode only; fail-closed for a persisted
    // profile, fail-open for the synthesized zero-config profile) ───────────
    // Friendbot mode signs nothing and is not gated — see the module doc
    // comment. Proves the audit writer is acquirable AFTER the policy gate
    // (a denial is a clean refusal that signs nothing and needs no audit
    // setup) but BEFORE `sponsored_create` touches the signer or submits.
    // Where `Some`, the writer is reused (not re-acquired) for the
    // post-confirm `value_action_submitted` row.
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

    // Record, then sign and submit. The recorder writes the receipt, the
    // pending audit row and the spending-window reservation before the bytes
    // leave, and settles all three against what the network answers.
    // Sponsored mode only: the Friendbot path is not policy-gated.
    let recorder = match crate::commands::submission_record::build_recorder(
        crate::commands::submission_record::SubmitRecord {
            policy_decision: stellar_agent_core::audit_log::PolicyDecision::Allow,
            profile,
            profile_name: resolved.name.clone(),
            verb: "accounts create",
            tool: "stellar_create_account",
            chain_id,
            effects: create_effects.as_ref(),
            audit: audit_writer.clone(),
            now_ms,
        },
    ) {
        Ok(r) => r.with_witness(cross_check.witness()),
        Err(e) => {
            print_error(
                &crate::commands::submission_record::error_envelope(&e, "", "accounts create"),
                args.output,
            );
            return 1;
        }
    };

    match sponsored_create(
        &client,
        context,
        args,
        SignedBy {
            profile,
            profile_name: &resolved.name,
        },
        SponsoredAccount {
            sponsor: &sponsor,
            new_account: &new_account.g_strkey,
            starting_balance,
            sequence_number: sponsor_account_view.sequence_number,
            fee_per_op: fee_selection.per_op_stroops,
        },
        Some(&recorder),
    )
    .await
    {
        Ok(sub_result) => {
            let secret_key = new_account.secret.as_ref().map(|s| s.as_str().to_owned());

            let result = CreateAccountResult {
                account_id: new_account.g_strkey.clone(),
                secret_key,
                mode: CreateMode::Sponsored,
                tx_hash: Some(sub_result.tx_hash.clone()),
                ledger: Some(sub_result.ledger),
                friendbot_url_used: None,
                selected_fee_per_op_stroops: Some(fee_selection.per_op_stroops),
                selected_fee_percentile: Some(fee_selection.selected_fee_percentile),
                cross_check: Some(cross_check.view()),
            };
            let envelope = Envelope::ok(result);
            print_success(&envelope, args.output);
            0
        }
        Err(failure) => {
            print_error(
                &crate::commands::submission_record::error_envelope(
                    &failure.error,
                    failure.signed_xdr.as_deref().unwrap_or_default(),
                    "accounts create",
                ),
                args.output,
            );
            1
        }
    }
}

async fn sign_envelope(
    context: &NetworkContext,
    args: &CreateArgs,
    unsigned_xdr: &str,
    sponsor: &str,
    profile: &Profile,
    profile_name: &str,
) -> Result<String, WalletError> {
    let passphrase = context.network_passphrase();

    let signer: Box<dyn Signer + Send + Sync> =
        match (args.sign_with_ledger, args.secret_env.as_deref()) {
            (true, _) => Box::new(signer_from_ledger(args.account_index, sponsor).await?),
            (false, Some(var_name)) => {
                let SignerCeremonyOutcome {
                    signer,
                    mlock_degradation: _,
                } = resolve_software_signer_from_env(var_name, "create-account-commit", profile)
                    .await?;
                let derived = signer.public_key().await?.to_string().to_string();
                if derived != sponsor {
                    return Err(AuthError::SignerKeyMismatch {
                        expected: sponsor.to_owned(),
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

/// The loaded profile whose enrolled signer signs the transaction.
#[derive(Clone, Copy)]
struct SignedBy<'a> {
    profile: &'a Profile,
    profile_name: &'a str,
}

/// The account the sponsor creates, and with what balance.
#[derive(Clone, Copy)]
struct SponsoredAccount<'a> {
    sponsor: &'a str,
    new_account: &'a str,
    starting_balance: StellarAmount,
    sequence_number: i64,
    fee_per_op: u32,
}

/// Builds, signs, and submits the `CreateAccount` transaction.
///
/// `client` is the client whose endpoint the caller checked before the
/// sponsor read; the send uses that checked client.
///
/// # Signing path
///
/// - `--sign-with-ledger`: hardware signer; seed never in process memory.
/// - `--secret-env VAR`: mlock-protected signing window. The S-strkey is
///   parsed from the env var, moved into a `Wallet` (LockedSeed), and consumed
///   by `signer_from_wallet`. Both the `SoftwareSigningKey` and the `Wallet`
///   drop after `attach_signature`, triggering SecretBox zeroization and
///   LockedSeed munlock.
///
/// # Errors
///
/// Propagates errors from account fetch, signing, or submission.
async fn sponsored_create(
    client: &StellarRpcClient,
    context: &NetworkContext,
    args: &CreateArgs,
    signed_by: SignedBy<'_>,
    account: SponsoredAccount<'_>,
    recorder: Option<&dyn stellar_agent_network::SubmissionRecorder>,
) -> Result<SubmissionResult, SponsoredCreateFailure> {
    let SignedBy {
        profile,
        profile_name,
    } = signed_by;
    let SponsoredAccount {
        sponsor,
        new_account,
        starting_balance,
        sequence_number,
        fee_per_op,
    } = account;
    let envelope_xdr = build_sponsored_unsigned_envelope(
        context,
        sponsor,
        sequence_number,
        new_account,
        starting_balance,
        fee_per_op,
    )?;

    let signed_xdr =
        sign_envelope(context, args, &envelope_xdr, sponsor, profile, profile_name).await?;
    let passphrase = context.network_passphrase();

    // Submit and wait for confirmation.
    let timeout = Duration::from_secs(args.timeout_seconds);
    submit_transaction_and_wait(
        client,
        &signed_xdr,
        timeout,
        passphrase,
        Some(SubmissionSignerKind::Software),
        recorder,
    )
    .await
    .map_err(|error| SponsoredCreateFailure {
        error,
        signed_xdr: Some(signed_xdr),
    })
}

/// Resolves the command's fee choice before the cap and witness.
async fn select_create_fee(
    client: &StellarRpcClient,
    args: &CreateArgs,
) -> Result<(ClassicFeeChoice, ClassicFeeSelection), WalletError> {
    let choice = parse_classic_fee_choice(args.fee.as_deref())?;
    let selection = resolve_classic_fee_selection(client, DEFAULT_FEE_STROOPS, choice).await?;
    Ok((choice, selection))
}

/// Builds with the sponsor observation and fee the command checks before signing.
///
/// `sequence_number` is the sponsor's current sequence: the builder
/// increments it, so passing the sequence plus one yields `TxBadSeq`.
fn build_sponsored_unsigned_envelope(
    context: &NetworkContext,
    sponsor: &str,
    sequence_number: i64,
    new_account: &str,
    starting_balance: StellarAmount,
    fee_per_op: u32,
) -> Result<String, WalletError> {
    let mut builder = ClassicOpBuilder::new(
        sponsor,
        sequence_number,
        context.network_passphrase(),
        fee_per_op,
    );
    builder.create_account(new_account, starting_balance)?;
    builder.build()
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn sponsored_success_lines(result: &CreateAccountResult) -> Vec<String> {
    let hash = result
        .tx_hash
        .as_deref()
        .map(stellar_agent_network::submit::redact_tx_hash)
        .unwrap_or_default();
    let ledger = result.ledger.unwrap_or_default();
    let mut lines = vec![
        format!(
            "Account created (sponsored): {}  tx_hash {hash}  ledger {ledger}",
            result.account_id
        ),
        crate::render::table::render_selected_fee_line(
            result.selected_fee_per_op_stroops,
            result.selected_fee_percentile.as_deref(),
        ),
    ];
    if let Some(cross_check) = &result.cross_check {
        lines.push(cross_check.text_line());
    }
    lines
}

fn print_success(envelope: &Envelope<CreateAccountResult>, format: OutputFormat) {
    match format {
        OutputFormat::Table => {
            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            if let Some(result) = &envelope.data {
                match &result.mode {
                    CreateMode::Sponsored => {
                        println!("{}", sponsored_success_lines(result).join("\n"));
                    }
                    CreateMode::Friendbot => {
                        use stellar_agent_network::submit::redact_tx_hash;
                        let hash = result
                            .tx_hash
                            .as_deref()
                            .map(redact_tx_hash)
                            .unwrap_or_default();
                        println!(
                            "Account created (friendbot): {}  tx_hash {}",
                            result.account_id, hash
                        );
                        // secret_key is NEVER emitted in table mode.
                    } // `CreateMode` is `#[non_exhaustive]` but defined same-crate;
                      // the compiler enforces exhaustiveness here without a `_` arm.
                      // A future variant added in this crate forces an explicit
                      // table-arm decision rather than silently falling through to
                      // JSON.
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
    #![allow(clippy::panic, reason = "test spies reject keyring access")]
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use std::sync::Arc;

    use stellar_agent_core::profile::schema::PolicyEngineKind;

    use super::*;
    use crate::common::signer_ceremony::test_fixtures::{
        EnrolledPin, assert_enrolled_outcome, enrolled_mainnet_profile, enrolled_test_g,
        enrolled_test_secret,
    };
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

    const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
    const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

    struct CreateBuildRpcResponder {
        account_key_xdr: String,
        account_xdr: String,
        fee_stats: Arc<serde_json::Value>,
    }

    impl CreateBuildRpcResponder {
        fn new(account_key_xdr: String, account_xdr: String, fee_stats: serde_json::Value) -> Self {
            Self {
                account_key_xdr,
                account_xdr,
                fee_stats: Arc::new(fee_stats),
            }
        }
    }

    #[async_trait::async_trait]
    impl Respond for CreateBuildRpcResponder {
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

    async fn mount_create_build_rpc(p95: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(CreateBuildRpcResponder::new(
                account_ledger_key_xdr(SOURCE_G),
                account_entry_xdr_with_balance(SOURCE_G, 100_000_000_000),
                fee_stats_result(p95, "999"),
            ))
            .mount(&server)
            .await;
        server
    }

    // ── Clap mutex tests ─────────────────────────────────────────────────────

    /// Parses `CreateArgs` from a vec of string slices via the Command interface.
    fn try_parse_create(args: &[&str]) -> Result<CreateArgs, clap::Error> {
        use clap::Parser;

        #[derive(Debug, clap::Parser)]
        struct TestCreate {
            #[command(flatten)]
            args: CreateArgs,
        }

        TestCreate::try_parse_from(args).map(|t| t.args)
    }

    /// Helper: a minimal valid friendbot invocation arg list.
    fn friendbot_args() -> Vec<&'static str> {
        vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "--fund-with-friendbot",
        ]
    }

    /// Helper: a minimal valid sponsored invocation arg list.
    fn sponsored_args() -> Vec<&'static str> {
        vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "--sponsor",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
            "--secret-env",
            "SPONSOR_SECRET",
            "--starting-balance",
            "5 XLM",
        ]
    }

    #[test]
    fn friendbot_and_sponsor_are_mutually_exclusive() {
        let mut args = friendbot_args();
        args.extend([
            "--sponsor",
            "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
        ]);
        let result = try_parse_create(&args);
        assert!(
            result.is_err(),
            "--fund-with-friendbot + --sponsor must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn generate_and_positional_are_mutually_exclusive() {
        let args = vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
            "--generate",
            "--fund-with-friendbot",
        ];
        let result = try_parse_create(&args);
        assert!(result.is_err(), "positional + --generate must conflict");
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn no_mode_flag_is_rejected() {
        // Neither --fund-with-friendbot nor --sponsor → clap missing-required-group.
        let args = vec![
            "create",
            "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
        ];
        let result = try_parse_create(&args);
        assert!(result.is_err(), "no mode flag must be rejected");
    }

    #[test]
    fn no_account_flag_is_rejected() {
        // Neither positional nor --generate → missing account_group.
        let args = vec!["create", "--fund-with-friendbot"];
        let result = try_parse_create(&args);
        assert!(result.is_err(), "no account source must be rejected");
    }

    #[test]
    fn secret_env_and_sign_with_ledger_are_mutually_exclusive() {
        let mut args = sponsored_args();
        args.push("--sign-with-ledger");
        let result = try_parse_create(&args);
        assert!(
            result.is_err(),
            "--secret-env + --sign-with-ledger must conflict"
        );
        assert_eq!(
            result.unwrap_err().kind(),
            clap::error::ErrorKind::ArgumentConflict
        );
    }

    #[test]
    fn friendbot_args_parse_successfully() {
        let args = friendbot_args();
        let parsed = try_parse_create(&args).expect("friendbot args must parse");
        assert!(parsed.fund_with_friendbot);
        assert_eq!(
            parsed.new_account.as_deref(),
            Some("GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL")
        );
    }

    #[test]
    fn sponsored_args_parse_successfully() {
        let args = sponsored_args();
        let parsed = try_parse_create(&args).expect("sponsored args must parse");
        assert_eq!(
            parsed.sponsor.as_deref(),
            Some("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY")
        );
        assert_eq!(parsed.secret_env.as_deref(), Some("SPONSOR_SECRET"));
        assert_eq!(parsed.starting_balance.as_deref(), Some("5 XLM"));
    }

    // ── Network / mainnet rejection tests ────────────────────────────────────

    /// The friendbot arm on a mainnet profile exits 1 before any request
    /// reaches the profile's endpoint. The binary tests in
    /// `tests/cli/profile_env_var_resolution.rs` pin the refusal's wire code.
    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn friendbot_mainnet_profile_reaches_no_endpoint() {
        crate::common::render::take_rendered_for_test();
        let guard_rpc = wiremock::MockServer::start().await;
        let counter =
            stellar_agent_test_support::ConnectionCounter::start().expect("connection counter");
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(
                &counter.https_uri(),
            );
        let args = CreateArgs {
            profile: Some("guard-mainnet".into()),
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: Some(TargetNetwork::Mainnet),
            // Non-routable, so no request leaves the host.
            friendbot_url: "http://127.0.0.1:1".to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: None,
            fee: None,
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
        assert_eq!(exit, 1, "mainnet friendbot must exit with code 1");
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
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(
            rendered[0]["error"]["code"],
            "network.friendbot_mainnet_forbidden"
        );
    }

    /// `--network mainnet` with no profile exits 1 on the friendbot arm before
    /// any request reaches the endpoint `--rpc-url` names.
    #[tokio::test]
    #[serial_test::serial]
    async fn friendbot_mainnet_flag_without_profile_reaches_no_endpoint() {
        let guard_rpc = wiremock::MockServer::start().await;
        let guard_home = tempfile::tempdir().expect("home");
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        let _guard_env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let args = CreateArgs {
            profile: None,
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: Some(TargetNetwork::Mainnet),
            // Non-routable, so no request leaves the host.
            friendbot_url: "http://127.0.0.1:1".to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(guard_rpc.uri()),
            fee: None,
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
        assert_eq!(exit, 1, "mainnet friendbot must exit with code 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial_test::serial]
    async fn sponsored_mainnet_rejected_before_rpc_call() {
        crate::common::render::take_rendered_for_test();
        let guard_rpc = wiremock::MockServer::start().await;
        let counter =
            stellar_agent_test_support::ConnectionCounter::start().expect("connection counter");
        let (_guard_dir, _guard_home, _guard_env) =
            crate::common::profile_access::test_fixtures::mainnet_guard_fixture(
                &counter.https_uri(),
            );
        let args = CreateArgs {
            profile: Some("guard-mainnet".into()),
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: Some("5 XLM".to_owned()),
            sponsor: Some("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned()),
            secret_env: Some("SPONSOR_SECRET".to_owned()),
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: false,
            network: Some(TargetNetwork::Mainnet),
            friendbot_url: "http://127.0.0.1:1".to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: None,
            fee: None,
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
        assert_eq!(exit, 1, "mainnet sponsored must exit with code 1");
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
        let rendered = crate::common::render::take_rendered_for_test();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(
            rendered[0]["error"]["code"],
            "network.mainnet_write_forbidden"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn sponsored_mainnet_rejected_before_rpc_call_network_flag_without_profile_refuses() {
        let guard_rpc = wiremock::MockServer::start().await;
        let guard_home = tempfile::tempdir().expect("home");
        let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
        let _guard_env = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let args = CreateArgs {
            profile: None,
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: Some("5 XLM".to_owned()),
            sponsor: Some("GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned()),
            secret_env: Some("SPONSOR_SECRET".to_owned()),
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: false,
            network: Some(TargetNetwork::Mainnet),
            friendbot_url: "http://127.0.0.1:1".to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(guard_rpc.uri()),
            fee: None,
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
        assert_eq!(exit, 1, "mainnet sponsored must exit with code 1");
        assert!(
            guard_rpc
                .received_requests()
                .await
                .expect("requests")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn accounts_create_cli_explicit_fee_surfaces_metadata() {
        let server = mount_create_build_rpc("333").await;
        let mut args = minimal_sponsored_args();
        args.fee = Some("250".to_owned());
        args.rpc_url = Some(server.uri());
        let starting_balance =
            StellarAmount::parse_with_unit("1 XLM").expect("test amount with unit must parse");

        let context = flag_context(&args);
        let client = StellarRpcClient::new(&context.rpc_url).expect("mock client");
        let (_, selection) = select_create_fee(&client, &args).await.unwrap();
        let built = build_sponsored_unsigned_envelope(
            &context,
            SOURCE_G,
            0,
            DEST_G,
            starting_balance,
            selection.per_op_stroops,
        )
        .expect("explicit fee create-account build succeeds");
        assert_eq!(selection.per_op_stroops, 250);
        assert_eq!(selection.selected_fee_percentile, "explicit");
        assert_eq!(tx_fee_from_envelope_xdr(&built), 250);

        let result = CreateAccountResult {
            account_id: DEST_G.to_owned(),
            secret_key: None,
            mode: CreateMode::Sponsored,
            tx_hash: None,
            ledger: None,
            friendbot_url_used: None,
            selected_fee_per_op_stroops: Some(selection.per_op_stroops),
            selected_fee_percentile: Some(selection.selected_fee_percentile),
            cross_check: None,
        };
        let json = serde_json::to_value(result).expect("CreateAccountResult serialises");
        assert_eq!(json["selected_fee_per_op_stroops"], "250");
        assert_eq!(json["selected_fee_percentile"], "explicit");
    }

    #[test]
    fn create_account_result_selected_fee_per_op_stroops_none_round_trips() {
        // The `with = "...::u32_opt"` custom deserializer suppresses serde's
        // implicit missing-field-means-None for `Option<T>`; `#[serde(default)]`
        // restores it. Without it, deserializing this None-produced,
        // field-omitted JSON would fail with "missing field
        // `selected_fee_per_op_stroops`".
        let result = CreateAccountResult {
            account_id: DEST_G.to_owned(),
            secret_key: None,
            mode: CreateMode::Sponsored,
            tx_hash: None,
            ledger: None,
            friendbot_url_used: None,
            selected_fee_per_op_stroops: None,
            selected_fee_percentile: None,
            cross_check: None,
        };
        let json = serde_json::to_value(&result).expect("CreateAccountResult serialises");
        assert!(json.get("selected_fee_per_op_stroops").is_none());
        assert!(json.get("cross_check").is_none());

        let round_tripped: CreateAccountResult = serde_json::from_value(json)
            .expect("omitted selected_fee_per_op_stroops must deserialize back to None");
        assert_eq!(round_tripped.selected_fee_per_op_stroops, None);
        assert!(round_tripped.cross_check.is_none());
    }

    #[tokio::test]
    async fn accounts_create_cli_default_fee_surfaces_profile_default() {
        let server = mount_create_build_rpc("333").await;
        let mut args = minimal_sponsored_args();
        args.rpc_url = Some(server.uri());
        let starting_balance =
            StellarAmount::parse_with_unit("1 XLM").expect("test amount with unit must parse");

        let context = flag_context(&args);
        let client = StellarRpcClient::new(&context.rpc_url).expect("mock client");
        let (_, selection) = select_create_fee(&client, &args).await.unwrap();
        let built = build_sponsored_unsigned_envelope(
            &context,
            SOURCE_G,
            0,
            DEST_G,
            starting_balance,
            selection.per_op_stroops,
        )
        .expect("default fee create-account build succeeds");
        assert_eq!(selection.per_op_stroops, DEFAULT_FEE_STROOPS);
        assert_eq!(tx_fee_from_envelope_xdr(&built), DEFAULT_FEE_STROOPS);
        assert_eq!(selection.selected_fee_percentile, "profile_default");
    }

    #[tokio::test]
    async fn accounts_create_cli_auto_fee_surfaces_p95() {
        let server = mount_create_build_rpc("333").await;
        let mut args = minimal_sponsored_args();
        args.fee = Some("auto".to_owned());
        args.rpc_url = Some(server.uri());
        let starting_balance =
            StellarAmount::parse_with_unit("1 XLM").expect("test amount with unit must parse");

        let context = flag_context(&args);
        let client = StellarRpcClient::new(&context.rpc_url).expect("mock client");
        let (_, selection) = select_create_fee(&client, &args).await.unwrap();
        let built = build_sponsored_unsigned_envelope(
            &context,
            SOURCE_G,
            0,
            DEST_G,
            starting_balance,
            selection.per_op_stroops,
        )
        .expect("auto fee create-account build succeeds");
        assert_eq!(selection.per_op_stroops, 333);
        assert_eq!(selection.selected_fee_percentile, "p95");
        assert_eq!(tx_fee_from_envelope_xdr(&built), 333);
    }

    // ── Network FromStr round-trips ──────────────────────────────────────────

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

    // ── Keypair generation ────────────────────────────────────────────────────

    /// `--generate` produces a G/S pair where the secret actually derives the
    /// returned public key.
    ///
    /// This test would fail if `resolve_new_account` returned a mismatched
    /// G/S pair (e.g. generated two independent keypairs and took the public
    /// key from one and the secret from the other).
    #[test]
    fn resolve_new_account_generate_produces_valid_strkeys() {
        let args = CreateArgs {
            // Zero-config group: `None` is "no profile named", the path that
            // still synthesizes. `Some("default")` would be an explicitly
            // named profile and would refuse instead.
            profile: None,
            new_account: None,
            generate: true,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: Some(TargetNetwork::Testnet),
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(crate::common::network::TESTNET_RPC_URL.to_owned()),
            fee: None,
        };
        let acc = resolve_new_account(&args).expect("generate must succeed");

        // Decode G-strkey to raw 32-byte public key.
        let pub_key = stellar_strkey::ed25519::PublicKey::from_string(&acc.g_strkey)
            .expect("generated G-strkey must be valid");

        // S-strkey must be present and valid.
        let secret = acc
            .secret
            .expect("secret must be present when --generate is set");
        let priv_key = stellar_strkey::ed25519::PrivateKey::from_string(&secret)
            .expect("generated S-strkey must be valid");

        // Reconstruct the verifying key from the secret seed and confirm it
        // matches the returned G-strkey.  This assertion fails if the returned
        // G/S pair is mismatched (two independent keypairs).
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_key.0);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            pub_key.0,
            "secret seed must derive the returned public key"
        );
    }

    #[test]
    fn resolve_new_account_positional_invalid_returns_error() {
        let args = CreateArgs {
            // Zero-config group: `None` is "no profile named", the path that
            // still synthesizes. `Some("default")` would be an explicitly
            // named profile and would refuse instead.
            profile: None,
            new_account: Some("NOTASTRKEY".to_owned()),
            generate: false,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: Some(TargetNetwork::Testnet),
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(crate::common::network::TESTNET_RPC_URL.to_owned()),
            fee: None,
        };
        let result = resolve_new_account(&args);
        assert!(result.is_err(), "invalid G-strkey must return an error");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                WalletError::Validation(ValidationError::AddressInvalid { .. })
            ),
            "expected AddressInvalid, got: {err:?}"
        );
    }

    /// When `--generate` is not set, the `NewAccount.secret` field is `None`,
    /// which causes `CreateAccountResult.secret_key` to be `None`.
    #[test]
    fn secret_key_absent_when_not_generating() {
        let args = CreateArgs {
            // Zero-config group: `None` is "no profile named", the path that
            // still synthesizes. `Some("default")` would be an explicitly
            // named profile and would refuse instead.
            profile: None,
            new_account: Some(
                "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL".to_owned(),
            ),
            generate: false,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: Some(TargetNetwork::Testnet),
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(crate::common::network::TESTNET_RPC_URL.to_owned()),
            fee: None,
        };
        let acc = resolve_new_account(&args).expect("positional G-strkey must resolve");
        assert!(
            acc.secret.is_none(),
            "secret must be None when --generate is not set"
        );
    }

    /// When `--generate` is set, the `NewAccount.secret` field is `Some` and
    /// the secret seed derives the returned G-strkey public key.
    ///
    /// This test would fail if `resolve_new_account` returned a mismatched
    /// G/S pair or if the secret field were absent.
    #[test]
    fn secret_key_present_when_generating() {
        let args = CreateArgs {
            // Zero-config group: `None` is "no profile named", the path that
            // still synthesizes. `Some("default")` would be an explicitly
            // named profile and would refuse instead.
            profile: None,
            new_account: None,
            generate: true,
            starting_balance: None,
            sponsor: None,
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: true,
            network: Some(TargetNetwork::Testnet),
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(crate::common::network::TESTNET_RPC_URL.to_owned()),
            fee: None,
        };
        let acc = resolve_new_account(&args).expect("--generate must succeed");
        assert!(
            acc.secret.is_some(),
            "secret must be Some when --generate is set"
        );

        // Decode both strkeys and verify the secret derives the public key.
        let secret = acc.secret.unwrap();
        let priv_key = stellar_strkey::ed25519::PrivateKey::from_string(&secret)
            .expect("generated S-strkey must be valid");
        let pub_key = stellar_strkey::ed25519::PublicKey::from_string(&acc.g_strkey)
            .expect("generated G-strkey must be valid");

        // Reconstruct the verifying key from the secret seed and confirm it
        // matches the returned G-strkey.  This assertion fails if the returned
        // G/S pair is mismatched (two independent keypairs).
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_key.0);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            pub_key.0,
            "secret seed must derive the returned public key"
        );
    }

    // ── CreateMode wire-format round-trip ────────────────────────────────────

    /// `CreateMode` must serialise to exactly `"sponsored"` / `"friendbot"`.
    #[test]
    fn create_mode_serialises_to_lowercase_strings() {
        let sponsored = serde_json::to_string(&CreateMode::Sponsored).unwrap();
        let friendbot = serde_json::to_string(&CreateMode::Friendbot).unwrap();
        assert_eq!(sponsored, "\"sponsored\"");
        assert_eq!(friendbot, "\"friendbot\"");
    }

    /// Round-trip: deserialise the lowercase `"sponsored"` / `"friendbot"`
    /// strings back into `CreateMode`.
    #[test]
    fn create_mode_deserialises_from_lowercase_strings() {
        let sponsored: CreateMode = serde_json::from_str("\"sponsored\"").unwrap();
        let friendbot: CreateMode = serde_json::from_str("\"friendbot\"").unwrap();
        assert!(matches!(sponsored, CreateMode::Sponsored));
        assert!(matches!(friendbot, CreateMode::Friendbot));
    }

    #[test]
    fn sanitize_for_table_strips_control_chars() {
        use crate::common::render::sanitize_for_table;
        let input = "hello\x1b[1mworld\x07";
        let sanitized = sanitize_for_table(input);
        assert!(!sanitized.contains('\x1b'), "escape must be stripped");
        assert!(!sanitized.contains('\x07'), "bell must be stripped");
        assert!(sanitized.contains("hello"), "printable chars must survive");
    }

    fn minimal_sponsored_args() -> CreateArgs {
        CreateArgs {
            // Zero-config group: `None` is "no profile named", the path that
            // still synthesizes. `Some("default")` would be an explicitly
            // named profile and would refuse instead.
            profile: None,
            new_account: Some(DEST_G.to_owned()),
            generate: false,
            starting_balance: Some("1 XLM".to_owned()),
            sponsor: Some(SOURCE_G.to_owned()),
            secret_env: None,
            sign_with_ledger: false,
            account_index: 0,
            fund_with_friendbot: false,
            network: Some(TargetNetwork::Testnet),
            friendbot_url: DEFAULT_FRIENDBOT_URL.to_owned(),
            output: OutputFormat::Json,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            rpc_url: Some(crate::common::network::TESTNET_RPC_URL.to_owned()),
            fee: None,
        }
    }

    /// The context a testnet profile yields for the endpoint flags of `args`.
    fn flag_context(args: &CreateArgs) -> NetworkContext {
        NetworkContext::new(
            args.network.unwrap_or(TargetNetwork::Testnet).caip2(),
            args.rpc_url
                .clone()
                .unwrap_or_else(|| crate::common::network::TESTNET_RPC_URL.to_owned()),
        )
    }

    // ── keyring store initialisation ordering (issue #41) ────────────────────

    /// The platform keyring store must be initialised before the V1 policy
    /// gate's owner-key read (`build_v1_policy_engine`), on the sponsored
    /// path (`run_sponsored`). Both dependencies are injected, so no OS
    /// keychain or on-disk profile is touched and no process-global keyring
    /// store is registered. The halt check before the keyring initialiser
    /// reads the marker under the data root, so the test redirects the data
    /// root to a temporary directory and clears the profile variable; both
    /// are process-global, hence `#[serial]`. The injected initialiser returns
    /// an error so the run bails at that step, before `sponsored_create` (and
    /// its RPC calls) ever runs, proving the initialisation happens ahead of
    /// any network build.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_initialises_keyring_store_before_policy_gate() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let home = tempfile::tempdir().expect("home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let profile_loaded = Arc::new(AtomicBool::new(false));
        let init_invoked = Arc::new(AtomicBool::new(false));

        let loaded_writer = Arc::clone(&profile_loaded);
        let loaded_reader = Arc::clone(&profile_loaded);
        let init_writer = Arc::clone(&init_invoked);

        let args = minimal_sponsored_args();

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

    /// Even when the resolved profile's engine is `Noop`, the keyring
    /// initialiser IS invoked — the origin-aware audit pre-flight
    /// (`require_value_audit_writer_for_origin`) reads the profile's audit
    /// chain-root HMAC key from the platform keyring regardless of the policy
    /// engine, so `run_sponsored` registers the store unconditionally. The
    /// halt check reads the marker under the data root, so the data root is a
    /// temporary directory and the profile variable is cleared, under
    /// `#[serial]`.
    #[tokio::test]
    #[serial_test::serial]
    async fn run_initialises_keyring_even_when_engine_is_noop() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let home = tempfile::tempdir().expect("home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        let init_invoked = Arc::new(AtomicBool::new(false));
        let init_writer = Arc::clone(&init_invoked);

        let args = minimal_sponsored_args();

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
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "keyring-order-test-noop-sentinel".to_owned(),
                }))
            },
        )
        .await;

        assert!(
            init_invoked.load(Ordering::SeqCst),
            "a Noop-engine profile must still trigger keyring store initialisation, \
             because the audit pre-flight reads the audit key regardless of engine"
        );
        assert_eq!(
            code, 1,
            "run must surface the keyring init failure instead of reaching the network build"
        );
    }

    /// A synthesized profile's sponsored run must NOT exit
    /// fatally at the keyring-init step: it warns and continues past both the
    /// keyring-init failure and the origin-aware audit pre-flight, reaching
    /// the sponsor-account RPC fetch and the later "no signer configured"
    /// refusal (`ValidationError::SignerSourceRequired`, raised only once
    /// `sponsored_create` reaches its signing branch) — a DIFFERENT, later
    /// error than the injected keyring-init failure
    /// (`AuthError::KeyringNotFound`). The `received_requests` assertion is
    /// what makes this an ordering proof rather than a tautology: if the
    /// keyring-init failure were still unconditionally fatal, the run would
    /// exit before the mock server ever recorded a request. Catches the
    /// regression where this failure was fatal regardless of origin, which
    /// would break the zero-config quickstart on any host without a platform
    /// keyring (e.g. a container without a Secret Service).
    #[tokio::test]
    #[serial_test::serial]
    async fn run_synthesized_profile_tolerates_keyring_init_failure() {
        // The synthesized profile is named by the RESOLVED name, which with no
        // flag and no variable is the literal `default` — so its
        // `audit_log_path` and audit chain-root keyring coordinate are the
        // real `default` profile's. Redirect the data root and the keyring
        // store, and clear the variable the resolver reads, so the run touches
        // neither the operator's audit log nor a host key that would let the
        // pre-flight succeed instead of exercising its fail-open branch.
        // Process-global, hence `#[serial]`.
        let _dir = tempfile::TempDir::new().expect("tempdir");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(_dir.path());
        let _profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
        stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");

        let server = mount_create_build_rpc("333").await;
        let mut args = minimal_sponsored_args();
        args.rpc_url = Some(server.uri());

        // The loader reports the profile file is absent; `minimal_sponsored_args`
        // names no profile, so the choke point synthesizes (zero-config group).
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
                Err(WalletError::Auth(AuthError::KeyringNotFound {
                    name: "create-zero-config-keyring-init-failure-sentinel".to_owned(),
                }))
            },
        )
        .await;

        assert_eq!(
            code, 1,
            "the run must still refuse for lack of a configured signer, not for the \
             tolerated keyring-init failure"
        );
        let methods: Vec<String> = server
            .received_requests()
            .await
            .expect("request recording is enabled by default")
            .iter()
            .map(|request| {
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap()["method"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            crate::test_rpc::last_rendered()["error"]["code"],
            "validation.signer_source_required",
        );
        assert_eq!(methods, ["getNetwork", "getLedgerEntries"]);
    }

    #[allow(unsafe_code, reason = "serialized test seed variable")]
    async fn enrolled_signing_case(pin: EnrolledPin) {
        let g = enrolled_test_g();
        let var = "ENROLLED_ACCOUNTS_CREATE_TEST_SEED";
        unsafe {
            std::env::set_var(var, enrolled_test_secret());
        }
        let mut profile = enrolled_mainnet_profile(pin);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(CreateBuildRpcResponder::new(
                account_ledger_key_xdr(&g),
                account_entry_xdr_with_balance(&g, 100_000_000_000),
                fee_stats_result("100", "100"),
            ))
            .mount(&server)
            .await;
        profile.rpc_url = server.uri();
        let context = NetworkContext::from_profile(&profile);
        let mut args = minimal_sponsored_args();
        args.sponsor = Some(g.clone());
        args.secret_env = Some(var.into());
        args.fee = Some("100".into());
        let client = StellarRpcClient::new(&context.rpc_url).expect("mock client");
        let (_, selection) = select_create_fee(&client, &args).await.unwrap();
        let built = build_sponsored_unsigned_envelope(
            &context,
            &g,
            0,
            DEST_G,
            StellarAmount::parse_with_unit("1 XLM").expect("amount"),
            selection.per_op_stroops,
        )
        .expect("build against mock");
        let result = sign_envelope(&context, &args, &built, &g, &profile, "enrolled").await;
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

    // ── Endpoint identity: one client, checked before the sponsor read ─────

    /// Runs a sponsored creation by the account of `seed` on the zero-config
    /// profile against `server`, with the sponsor's secret in `var`, and
    /// returns the exit code and the number of clients the run built.
    async fn sponsored_run(
        seed: [u8; 32],
        var: &'static str,
        server: &MockServer,
        fee: Option<&str>,
    ) -> (i32, usize) {
        let sponsor = crate::test_rpc::EnvSigner::new(seed, var);
        let mut args = minimal_sponsored_args();
        args.sponsor = Some(sponsor.g.clone());
        args.secret_env = Some(sponsor.var.to_owned());
        args.rpc_url = Some(server.uri());
        args.fee = fee.map(str::to_owned);
        crate::test_rpc::clients_built_by(run_with_dependencies(
            &args,
            crate::test_rpc::absent_profile_file,
            || Ok(()),
        ))
        .await
    }

    /// A sponsored creation builds one client: the endpoint check is its
    /// first request, ahead of the sponsor read, and the reconcile, the build
    /// reads, and the send go through it. The submit layer checks it again,
    /// so two `getNetwork` requests.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_sponsored_creation_checks_the_endpoint_first_and_sends_through_one_client() {
        for fee in [None, Some("auto")] {
            let _zero_config = crate::test_rpc::zero_config();
            let seed = [0x81; 32];
            let sponsor = stellar_agent_test_support::signed_envelope::account_id_for_seed(seed);
            let server = crate::test_rpc::ClassicRpc::testnet(&[&sponsor])
                .serve()
                .await;

            let (code, built) = sponsored_run(seed, "CREATE_ONE_CLIENT_SK", &server, fee).await;
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

    /// An endpoint serving another network refuses a sponsored creation
    /// before the sponsor read, with the fixed fee and the automatic fee.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_sponsored_creation_refuses_another_network_before_any_read() {
        for fee in [None, Some("auto")] {
            let _zero_config = crate::test_rpc::zero_config();
            let seed = [0x82; 32];
            let sponsor = stellar_agent_test_support::signed_envelope::account_id_for_seed(seed);
            let endpoint = crate::test_rpc::ClassicRpc::testnet(&[&sponsor]);
            endpoint.report("Test SDF Future Network ; October 2022");
            let server = endpoint.serve().await;

            let (code, built) =
                sponsored_run(seed, "CREATE_ENDPOINT_MISMATCH_SK", &server, fee).await;

            assert_eq!(code, 1, "fee {fee:?}");
            assert_eq!(built, 1, "fee {fee:?}");
            assert_eq!(
                crate::test_rpc::methods(&server).await,
                ["getNetwork"],
                "fee {fee:?}: the endpoint check precedes every read"
            );
        }
    }
    #[test]
    fn sponsored_text_includes_the_witness() {
        let result: CreateAccountResult = serde_json::from_value(serde_json::json!({
            "account_id": DEST_G, "mode": "sponsored",
            "cross_check": {"status": "passed", "provider": "oracle.test", "ledger": 1001}
        }))
        .unwrap();
        let view = result.cross_check.as_ref().unwrap();
        assert!(sponsored_success_lines(&result).contains(&view.text_line()));
        assert_eq!(
            serde_json::to_value(&result).unwrap()["cross_check"]["status"],
            "passed"
        );
    }

    #[test]
    fn unsigned_failure_has_no_envelope_hash() {
        let failure =
            SponsoredCreateFailure::from(WalletError::Network(NetworkError::AccountNotFound {
                account_id: SOURCE_G.to_owned(),
            }));
        assert!(failure.signed_xdr.is_none());
        let envelope = crate::commands::submission_record::error_envelope(
            &failure.error,
            failure.signed_xdr.as_deref().unwrap_or_default(),
            "accounts create",
        );
        let value = serde_json::to_value(envelope).unwrap();
        assert!(value["error"]["details"].get("envelope_hash").is_none());
    }

    mod witness {
        use super::*;
        use crate::test_rpc::{
            ClassicRpc, EnvSigner, account_key, account_xdr, assert_rows_carry_witness,
            last_rendered, methods, sent, signers_resolved_by, witness_profile, zero_config,
        };

        #[derive(Debug)]
        enum Case {
            Pass,
            Divergent,
            Unavailable,
            InvalidOracle,
            Skipped,
            BelowFloor,
            ExplicitCap,
            DefaultCap,
            Timeout,
            Unsigned,
        }

        async fn exercise(case: Case) {
            let _isolation = zero_config();
            let signer = EnvSigner::new([0x71; 32], "CREATE_WITNESS_SIGNER");
            let primary = ClassicRpc::testnet(&[])
                .with_entry(account_key(&signer.g), account_xdr(&signer.g, 44, 0, ""))
                .serve()
                .await;
            let oracle_rpc = ClassicRpc::testnet(&[]).with_entry(
                account_key(&signer.g),
                account_xdr(
                    &signer.g,
                    if matches!(case, Case::Divergent) {
                        45
                    } else {
                        44
                    },
                    0,
                    "",
                ),
            );
            if matches!(case, Case::Unavailable) {
                oracle_rpc.report(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE);
            }
            let oracle = oracle_rpc.serve().await;
            let dir = tempfile::TempDir::new().unwrap();
            let name = format!("create-witness-{case:?}").to_ascii_lowercase();
            let mut profile =
                witness_profile(&name, &primary.uri(), Some(&oracle.uri()), dir.path());
            if matches!(case, Case::Skipped) {
                profile.oracle_provider_url = None;
            }
            if matches!(case, Case::InvalidOracle) {
                profile.oracle_provider_url = Some(url::Url::parse("ftp://oracle.test").unwrap());
            }
            let mut args = minimal_sponsored_args();
            args.profile = Some(name);
            args.sponsor = Some(signer.g.clone());
            args.secret_env = Some(signer.var.to_owned());
            args.starting_balance = Some(
                if matches!(case, Case::BelowFloor) {
                    "999 XLM"
                } else {
                    "1000 XLM"
                }
                .to_owned(),
            );
            args.fee = Some("250".to_owned());
            if matches!(case, Case::ExplicitCap | Case::DefaultCap) {
                profile.classic_max_fee_per_op_stroops = Some(99);
            }
            if matches!(case, Case::DefaultCap) {
                args.fee = None;
            }
            if matches!(case, Case::Unsigned) {
                args.secret_env = None;
            }
            if matches!(case, Case::Timeout) {
                args.timeout_seconds = 1;
                Mock::given(method("POST"))
                    .and(wiremock::matchers::body_partial_json(serde_json::json!({
                        "method": "getTransaction"
                    })))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "jsonrpc": "2.0", "id": 1, "result": {
                            "status": "NOT_FOUND", "latestLedger": 1006, "oldestLedger": 1,
                            "latestLedgerCloseTime": "1700000005",
                            "oldestLedgerCloseTime": "1700000000"
                        }
                    })))
                    .with_priority(1)
                    .mount(&primary)
                    .await;
            }
            crate::common::render::take_rendered_for_test();
            let context = NetworkContext::from_profile(&profile);
            let (rc, resolutions) = signers_resolved_by(run_sponsored(
                &context,
                &args,
                &resolve_profile_name(args.profile.as_deref()),
                &profile,
                ProfileOrigin::Persisted,
                || Ok(()),
            ))
            .await;
            let value = last_rendered();
            let refusal = match case {
                Case::Divergent => Some("simulation.divergence"),
                Case::Unavailable | Case::InvalidOracle => Some("network.witness_unavailable"),
                Case::ExplicitCap | Case::DefaultCap => Some("fees.percentile_exceeds_cap"),
                Case::Timeout => Some("submission.tx_timeout"),
                Case::Unsigned => Some("validation.signer_source_required"),
                _ => None,
            };
            // Before signing, the primary answers the endpoint check and one
            // sponsor read, which feeds the policy, the witness and the
            // builder. A run that signs then reaches the submit layer, which
            // checks the endpoint again and reads the signer set to verify the
            // signature binding before the send.
            let primary_methods = methods(&primary).await;
            let signed = matches!(
                case,
                Case::Pass | Case::Skipped | Case::BelowFloor | Case::Timeout
            );
            if signed {
                assert_eq!(
                    primary_methods[..5],
                    [
                        "getNetwork",
                        "getLedgerEntries",
                        "getNetwork",
                        "getLedgerEntries",
                        "sendTransaction"
                    ],
                    "the sponsor is read once before signing: {primary_methods:?}"
                );
                assert!(
                    primary_methods.len() > 5
                        && primary_methods[5..].iter().all(|m| m == "getTransaction"),
                    "{primary_methods:?}"
                );
            } else {
                assert_eq!(
                    primary_methods,
                    ["getNetwork", "getLedgerEntries"],
                    "the sponsor is read once and nothing is sent"
                );
            }
            if let Some(code) = refusal {
                assert_eq!(rc, 1, "{value}");
                assert_eq!(value["error"]["code"], code, "{value}");
                if matches!(case, Case::Divergent) {
                    let message = value["error"]["message"].as_str().unwrap();
                    assert!(
                        message.contains("source account sequence (sequence delta 1)"),
                        "{message}"
                    );
                }
                if matches!(case, Case::Timeout) {
                    let requests = primary.received_requests().await.unwrap();
                    let body: serde_json::Value = requests
                        .iter()
                        .map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap())
                        .find(|v| v["method"] == "sendTransaction")
                        .unwrap();
                    let signed = body["params"]["transaction"].as_str().unwrap();
                    assert_eq!(
                        value["error"]["details"]["envelope_hash"],
                        stellar_agent_network::submit::envelope_hash_hex(signed)
                    );
                    assert!(!value.to_string().contains(signed));
                } else {
                    assert_eq!(resolutions, 0, "{value}");
                    assert!(!sent(&primary).await);
                    assert!(value["error"]["details"].get("envelope_hash").is_none());
                }
                if matches!(case, Case::ExplicitCap | Case::DefaultCap) {
                    assert!(methods(&oracle).await.is_empty());
                    let text = value["error"]["message"].as_str().unwrap();
                    assert!(
                        text.contains(if matches!(case, Case::DefaultCap) {
                            "default per-operation fee"
                        } else {
                            "explicit per-operation fee"
                        }),
                        "{text}"
                    );
                }
            } else {
                assert_eq!(rc, 0, "{value}");
                assert_eq!(resolutions, 1);
                let status = match case {
                    Case::Skipped => "skipped",
                    Case::BelowFloor => "not_required",
                    _ => "passed",
                };
                assert_eq!(value["data"]["cross_check"]["status"], status, "{value}");
                if status == "passed" {
                    assert_rows_carry_witness(&profile, &oracle.uri());
                } else {
                    assert!(methods(&oracle).await.is_empty());
                }
                let requests = primary.received_requests().await.unwrap();
                let body: serde_json::Value = requests
                    .iter()
                    .map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap())
                    .find(|v| v["method"] == "sendTransaction")
                    .unwrap();
                use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};
                let envelope = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let TransactionEnvelope::Tx(tx) = envelope else {
                    panic!("v1 envelope")
                };
                assert_eq!(tx.tx.seq_num.0, 45);
                assert_eq!(tx.tx.fee, 250);
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn create_witness_at_floor_records_and_forwards_sequence_and_fee() {
            exercise(Case::Pass).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn divergent_sponsor_refuses_before_signing() {
            exercise(Case::Divergent).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn unavailable_oracle_refuses_before_signing() {
            exercise(Case::Unavailable).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn invalid_oracle_refuses_before_signing() {
            exercise(Case::InvalidOracle).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn missing_oracle_reports_skipped() {
            exercise(Case::Skipped).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn below_floor_makes_no_oracle_request() {
            exercise(Case::BelowFloor).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn explicit_fee_cap_precedes_witness() {
            exercise(Case::ExplicitCap).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn command_default_fee_cap_precedes_witness() {
            exercise(Case::DefaultCap).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn signed_timeout_reports_only_the_envelope_hash() {
            exercise(Case::Timeout).await;
        }
        #[tokio::test]
        #[serial_test::serial]
        async fn unsigned_refusal_reports_no_envelope_hash() {
            exercise(Case::Unsigned).await;
        }
    }
}
