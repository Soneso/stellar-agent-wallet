//! `stellar-agent accounts deploy-c` subcommand — smart-account deployment.
//!
//! Deploys a new OpenZeppelin smart-account (C-account) contract instance on Soroban
//! via `CreateContractV2`. Supports two mutually-exclusive deployer-source modes:
//!
//! ## Mode A — `--deployer-secret-env <VAR>`
//!
//! Reads the deployer S-strkey from the named environment variable. The deployer
//! G-strkey is derived from the secret; must be pre-funded with at least the
//! deployment fee.
//!
//! ## Mode B — `--sign-with-ledger`
//!
//! Uses a Ledger hardware wallet at the specified `--account-index`. The Ledger
//! device must have the Stellar app open.
//!
//! ## Mainnet rejection
//!
//! Deployment on mainnet is structurally refused at two layers:
//!
//! 1. CLI enum: `TargetNetwork::Mainnet` returns `MainnetWriteForbidden` before
//!    any RPC or signing call.
//! 2. Network passphrase: `submit_transaction_and_wait` will reject mainnet
//!    passphrases at the ledger level.
//!
//! ## Dry-run mode (`--dry-run`)
//!
//! Computes the derived C-strkey without any network access. Returns the JSON
//! envelope with `tx_hash: null`, `ledger: null`. Useful for interop
//! verification: the same deployer + salt recovers the same C-strkey.
//!
//! # Behavior
//!
//! - Deploys a C-account contract instance (CLI verb).
//! - `--dry-run` performs deterministic address derivation without network
//!   access.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{ArgGroup, Args};
use keyring_core::Entry as KeyringEntry;
use rand_core::{OsRng, RngCore};
use stellar_agent_core::audit_log::writer::{AuditWriter, AuditWriterRegistry};
use stellar_agent_core::envelope::{Envelope, OutputFormat};
use stellar_agent_core::error::{
    AuthError, InternalError, NetworkError, ValidationError, WalletError,
};
use stellar_agent_core::profile::{loader, schema::Profile};
use stellar_agent_core::wallet::MlockDegradation;
use stellar_agent_network::keyring::init_platform_keyring_store;
use stellar_agent_network::{
    StellarRpcClient, parse_classic_fee_choice, resolve_classic_fee_selection,
};
use stellar_agent_smart_account::deployment::{
    DeployerKeypair, DeploymentArgs, DeploymentResult, ResolvedFeePerOp, deploy_smart_account,
};
use stellar_agent_smart_account::managers::credentials::CredentialsManager;
use stellar_agent_smart_account::managers::rules::parse_c_strkey_to_smart_account;
use stellar_agent_smart_account::managers::signers::build_external_signer_scval;
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::common::network::TargetNetwork;
use crate::common::render::{render_json, sanitize_for_table};
use crate::common::signer_ceremony::{
    SignerCeremonyOutcome, record_mlock_degradation, resolve_software_signer_from_env,
};
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default base fee per operation in stroops.
///
/// 100 stroops is the universal Stellar SDK default for the profile-default choice.
/// Soroban resource fees are computed by simulation and added by `prepare_transaction`;
/// this constant is only the base fee applied before simulation. Pass `--fee auto`
/// to select a fee via `getFeeStats` percentile (p95 default).
const DEFAULT_FEE_STROOPS: u32 = 100;

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Stellar testnet Soroban RPC endpoint (SDF operated).
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// DeployCArgs
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `accounts deploy-c` subcommand.
///
/// Three mutually-exclusive deployer-source modes; one required (clap enforces).
/// One required initial-signer flag. Optional salt override; default is fresh-random.
///
/// # Clap arg-groups
///
/// - `deployer_group` — exactly one of `--deployer-secret-env`,
///   `--sign-with-ledger`. Required.
/// - `salt_group` — at most one of `--salt-hex`, `--salt-random`
///   (default `--salt-random` if neither is specified).
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(
        ArgGroup::new("deployer_group")
            .args(["deployer_secret_env", "sign_with_ledger"])
            .required(true)
    ),
    group(
        ArgGroup::new("salt_group")
            .args(["salt_hex", "salt_random"])
            .required(false)
    ),
    group(
        ArgGroup::new("genesis_signer_source")
            .args(["initial_signer", "signer_webauthn", "signer_ed25519", "signer_external"])
            .required(true)
            .multiple(false)
    ),
)]
pub struct DeployCArgs {
    /// Initial signer G-strkey to install via `__constructor` (current
    /// default behavior).
    ///
    /// This G-strkey becomes the `Signer::Delegated(Address)` argument in the
    /// OZ `__constructor(signers, policies)` call. Any funded ed25519 G-strkey
    /// is accepted. Mutually exclusive with `--signer-webauthn`,
    /// `--signer-ed25519`, and `--signer-external`.
    #[arg(long, value_name = "G_STRKEY", group = "genesis_signer_source")]
    pub initial_signer: Option<String>,

    /// Credential name from the local passkeys registry to install as the
    /// GENESIS signer.
    ///
    /// Encodes as OZ `Signer::External(verifier, key_data)`. The verifier
    /// contract address resolves from the `VerifierRegistry` for the target
    /// network (deploy one via `smart-account deploy-webauthn-verifier`).
    /// Mutually exclusive with `--initial-signer`, `--signer-ed25519`, and
    /// `--signer-external`. Implies the `--accept-no-delegated-fallback`
    /// guard (see below) unless the fallback is otherwise satisfied — a
    /// passkey-only genesis has no CLI secret-env signing path.
    #[arg(long, value_name = "CREDENTIAL_NAME", group = "genesis_signer_source")]
    pub signer_webauthn: Option<String>,

    /// 64-hex-character raw Ed25519 public key of a first-class external
    /// signer to install as the GENESIS signer.
    ///
    /// Encodes as OZ `Signer::External(verifier, key_data)` where `key_data`
    /// is the raw 32-byte public key. The verifier resolves from `--verifier`
    /// when supplied, else from the `VerifierRegistry`'s registered Ed25519
    /// verifier for the target network. Mutually exclusive with
    /// `--initial-signer`, `--signer-webauthn`, and `--signer-external`.
    #[arg(long, value_name = "HEX_PUBKEY_64", group = "genesis_signer_source")]
    pub signer_ed25519: Option<String>,

    /// Ed25519 verifier contract C-strkey override for `--signer-ed25519`.
    ///
    /// Only meaningful with `--signer-ed25519`.
    #[arg(long, value_name = "C_STRKEY", requires = "signer_ed25519")]
    pub verifier: Option<String>,

    /// C-strkey of the deployed verifier contract for a raw External genesis
    /// signer (escape hatch).
    ///
    /// Must be paired with `--signer-key-data`. Mutually exclusive with
    /// `--initial-signer`, `--signer-webauthn`, and `--signer-ed25519`.
    #[arg(
        long,
        value_name = "C_STRKEY",
        requires = "signer_key_data",
        group = "genesis_signer_source"
    )]
    pub signer_external: Option<String>,

    /// Hex-encoded raw key-data for the raw External genesis signer.
    ///
    /// Required when `--signer-external` is supplied.
    #[arg(long, value_name = "HEX", requires = "signer_external")]
    pub signer_key_data: Option<String>,

    /// Acknowledge that the genesis signer has no delegated (ed25519)
    /// fallback and the passkey/external authenticator is the sole signing
    /// authority for the account's first rule.
    ///
    /// Required when `--signer-webauthn`, `--signer-ed25519`, or
    /// `--signer-external` is chosen for the genesis signer (mirrors
    /// `smart-account rules create`'s external-only refusal). If omitted, the
    /// command is refused before any RPC or signing call.
    #[arg(long)]
    pub accept_no_delegated_fallback: bool,

    /// Name of the environment variable holding the deployer S-strkey.
    ///
    /// Mutually exclusive with `--sign-with-ledger`.
    /// The deployer G-strkey is derived from the S-strkey; the deployer account
    /// must be pre-funded.
    #[arg(long, value_name = "VAR", group = "deployer_group")]
    pub deployer_secret_env: Option<String>,

    /// Use the connected Ledger hardware wallet as the deployer.
    ///
    /// Mutually exclusive with `--deployer-secret-env`.
    /// The Ledger device must have the Stellar app open.
    #[arg(long, group = "deployer_group")]
    pub sign_with_ledger: bool,

    /// BIP-44 account index for Ledger derivation path (default 0).
    #[arg(long, default_value_t = 0_u32, value_name = "INDEX")]
    pub account_index: u32,

    /// 32-byte salt in 64-char lowercase hex. Mutually exclusive with `--salt-random`.
    ///
    /// Used to re-deploy at a known C-strkey (migration / recovery flows). Must be
    /// exactly 64 hex characters (32 bytes).
    #[arg(long, value_name = "HEX64", group = "salt_group")]
    pub salt_hex: Option<String>,

    /// Profile whose audit-log writer should receive deployment entries.
    ///
    /// When omitted, deployment preserves the legacy profile-agnostic behavior
    /// and does not emit deploy-c audit entries from the CLI handler.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Generate a fresh random 32-byte salt (default when `--salt-hex` is absent).
    ///
    /// Each invocation with `--salt-random` produces a distinct C-strkey. Mutually
    /// exclusive with `--salt-hex`.
    #[arg(long, group = "salt_group")]
    pub salt_random: bool,

    /// Network to target.
    ///
    /// `mainnet` parses but deployment structurally refuses it
    /// (`network.mainnet_write_forbidden`). Default: `testnet`.
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    ///
    /// Default: `https://soroban-testnet.stellar.org`.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Base fee per operation in stroops, or `auto` / `auto:pNN` for `getFeeStats`
    /// automatic selection.
    ///
    /// Accepts:
    /// - `<integer>` — use that value as the explicit per-op fee in stroops.
    /// - `auto` — fetch `getFeeStats` and use the p95 percentile.
    /// - `auto:p50` / `auto:p75` / `auto:p95` / `auto:p99` — explicit percentile.
    /// - absent — use the profile default (100 stroops; Soroban resource fees
    ///   are set by simulation and are additional to this base).
    ///
    /// The base fee is applied before simulation. `prepare_transaction` adds the
    /// Soroban resource fee on top; the effective on-chain fee is always at least
    /// the simulated resource fee regardless of this value.
    #[arg(long, value_name = "STROOPS|auto[:pNN]")]
    pub fee: Option<String>,

    /// Submission timeout in seconds. Default: 60.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,

    /// Output format: `json` (default) or `table`.
    #[arg(long, default_value_t = OutputFormat::DEFAULT, value_name = "FORMAT")]
    pub output: OutputFormat,

    /// Compute the derived C-strkey without any network access.
    ///
    /// Returns a JSON envelope with `smart_account`, `salt_hex`,
    /// `deployer_pubkey`, `wasm_hash`, and `initial_signer` populated.
    /// `tx_hash` and `ledger` are `null`. No signing, no RPC traffic.
    ///
    /// Primary interop-verification tool: the same deployer + salt re-derives
    /// the same C-strkey.
    #[arg(long)]
    pub dry_run: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// run — main dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the `accounts deploy-c` subcommand.
///
/// Validates inputs, resolves the deployer keypair, resolves the salt, then
/// delegates to `deploy_smart_account`. Renders the result per `args.output`.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — all errors are captured into the envelope and the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &DeployCArgs) -> i32 {
    run_with_dependencies(args, load_profile_for_deploy, init_platform_keyring_store).await
}

async fn run_with_dependencies<LoadProfile, InitKeyring>(
    args: &DeployCArgs,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> i32
where
    LoadProfile: Fn(&str) -> Result<Profile, WalletError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    // First layer: structural mainnet rejection before any key access.
    if args.network == TargetNetwork::Mainnet {
        let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // GUARD: an External-only genesis signer set (no delegated fallback) has
    // no CLI secret-env signing path for the account's first rule. Checked
    // directly against the args (before any registry/credential resolution)
    // so the refusal fires fast and independent of whether the referenced
    // verifier/credential actually resolves. Mirrors the `smart-account
    // rules create` external-only refusal precedent — a hard refusal, not a
    // warning.
    let genesis_is_external_shaped = args.signer_webauthn.is_some()
        || args.signer_ed25519.is_some()
        || args.signer_external.is_some();
    if genesis_is_external_shaped && !args.accept_no_delegated_fallback {
        let err = WalletError::Validation(ValidationError::PasskeyOnlyRuleNoDelegatedFallback {
            credential_count: 1,
        });
        let envelope = Envelope::<()>::err(&err);
        print_error(&envelope, args.output);
        return 1;
    }

    // ── Resolve the genesis signer source ─────────────────────────────────────
    //
    // Exactly one of `initial_signer` / `signer_webauthn` / `signer_ed25519` /
    // `signer_external` is non-None, enforced by the `genesis_signer_source`
    // ArgGroup at parse time.
    let (initial_signer_display, genesis_signer_scval_override) =
        match resolve_genesis_signer_source(args).await {
            Ok(pair) => pair,
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        };

    // Resolve the 32-byte salt.
    let salt = match resolve_salt(args) {
        Ok(s) => s,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    // Resolve the deployer keypair.
    let (deployer, deployer_mlock_degradation) = match resolve_deployer(args).await {
        Ok(d) => d,
        Err(e) => {
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };

    let passphrase = args.network.passphrase();

    // Resolve the fee via ClassicFeeChoice. For dry-run mode we skip the RPC call
    // (no network access) and fall back to the profile default.
    let resolved_fee = if args.dry_run {
        // dry-run: no network access; fee resolution skipped.
        ResolvedFeePerOp {
            stroops: DEFAULT_FEE_STROOPS,
            percentile_label: "profile_default".to_owned(),
        }
    } else {
        let fee_choice = match parse_classic_fee_choice(args.fee.as_deref()) {
            Ok(c) => c,
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        };

        // Only construct the RPC client when needed (non-dry-run). This avoids an
        // unnecessary network dependency in dry-run mode.
        let fee_client = match StellarRpcClient::new(&args.rpc_url) {
            Ok(c) => c,
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        };

        match resolve_classic_fee_selection(&fee_client, DEFAULT_FEE_STROOPS, fee_choice).await {
            Ok(sel) => ResolvedFeePerOp {
                stroops: sel.per_op_stroops,
                percentile_label: sel.selected_fee_percentile,
            },
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        }
    };

    let deploy_args = DeploymentArgs {
        deployer,
        initial_signer: initial_signer_display,
        salt,
        network_passphrase: passphrase.to_owned(),
        rpc_url: args.rpc_url.clone(),
        timeout: Duration::from_secs(args.timeout_seconds),
        fee: resolved_fee,
        dry_run: args.dry_run,
        genesis_signer_scval_override,
    };

    let audit_writer_arc =
        match resolve_audit_writer(args.profile.as_deref(), load_profile, init_keyring) {
            Ok(writer) => writer,
            Err(e) => {
                let envelope = Envelope::<()>::err(&e);
                print_error(&envelope, args.output);
                return 1;
            }
        };

    // Record any `mlock` degradation from the deployer ceremony now, before
    // `guard` below takes an exclusive lock on the same writer (recording
    // after that point would deadlock on the non-reentrant Mutex).
    if let Some(writer) = &audit_writer_arc {
        record_mlock_degradation(
            writer,
            deployer_mlock_degradation.as_ref(),
            &resolve_profile_name(args.profile.as_deref()),
            &Uuid::new_v4().to_string(),
        );
    }

    // Lock the Arc<Mutex<AuditWriter>> for the duration of the deployment call
    // so we can pass `Option<&mut AuditWriter>` to `deploy_smart_account`.
    let mut guard = match audit_writer_arc.as_ref().map(|arc| arc.lock()).transpose() {
        Ok(g) => g,
        Err(_poison) => {
            let e = WalletError::Internal(InternalError::UnexpectedState {
                detail: "audit.writer_mutex_poisoned".to_owned(),
            });
            let envelope = Envelope::<()>::err(&e);
            print_error(&envelope, args.output);
            return 1;
        }
    };
    let audit_writer_ref: Option<&mut AuditWriter> = guard.as_deref_mut();

    match deploy_smart_account(deploy_args, audit_writer_ref).await {
        Ok(result) => {
            // Emit tracing info with redacted fields.
            info!(
                smart_account = %stellar_agent_core::observability::redact_strkey_first5_last5(&result.smart_account),
                deployer = %stellar_agent_core::observability::redact_strkey_first5_last5(&result.deployer_pubkey),
                wasm_hash = %stellar_agent_core::hex::redact_hex_first8_last8(&result.wasm_hash),
                wasm_uploaded = result.wasm_uploaded,
                dry_run = args.dry_run,
                "deploy-c: smart-account deployment complete"
            );
            let envelope = Envelope::ok(result.clone());
            print_success(&result, &envelope, args.output);
            0
        }
        Err(e) => {
            // Map SaError to WalletError::SmartAccount, preserving the typed
            // wire code in the JSON envelope. WalletError::SmartAccount carries
            // wire_code: &'static str from SaError::wire_code() so the envelope
            // emits "sa.deployment_failed" (or any other sa.* code) in the
            // "error.code" field, rather than collapsing all SaError variants
            // into a single validation code and losing the discriminant.
            let err = WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: e.to_string(),
            };
            let envelope = Envelope::<()>::err(&err);
            print_error(&envelope, args.output);
            1
        }
    }
}

// -----------------------------------------------------------------------------
// Audit writer resolution
// -----------------------------------------------------------------------------

/// Resolves the optional profile-backed audit writer for deploy-c.
///
/// The smart-account deployment substrate emits `SaRawInvocation` on non-dry-run
/// success and failure, and `SmartAccountDeployed` on non-dry-run success. The
/// CLI supplies a writer only when `--profile <name>` is provided, preserving
/// profile-agnostic deploy-c behavior for callers that do not opt into profile
/// resolution.
///
/// Delegates to [`AuditWriterRegistry::get_or_open`] so the same
/// `Arc<Mutex<AuditWriter>>` is returned for every call with the same
/// `profile_name` within the process, preventing multiple writers from racing
/// to open the same file (single-writer invariant).
fn resolve_audit_writer<LoadProfile, InitKeyring>(
    profile_name: Option<&str>,
    load_profile: LoadProfile,
    init_keyring: InitKeyring,
) -> Result<Option<Arc<Mutex<AuditWriter>>>, WalletError>
where
    LoadProfile: Fn(&str) -> Result<Profile, WalletError>,
    InitKeyring: Fn() -> Result<(), WalletError>,
{
    let Some(profile_name) = profile_name else {
        return Ok(None);
    };

    let profile = load_profile(profile_name)?;
    init_keyring()?;
    open_profile_audit_writer_via_registry(profile_name, &profile).map(Some)
}

/// Loads the named profile and maps loader errors into the CLI envelope model.
fn load_profile_for_deploy(profile_name: &str) -> Result<Profile, WalletError> {
    loader::load(profile_name, None).map_err(|e| match e {
        loader::ProfileLoadError::NotFound { name, .. } => {
            WalletError::Validation(ValidationError::ProfileNotFound { name })
        }
        _ => {
            tracing::debug!(profile = %profile_name, error = %e, "profile load failed for deploy-c");
            WalletError::Validation(ValidationError::ProfileNotFound {
                name: profile_name.to_owned(),
            })
        }
    })
}

/// Opens or retrieves the cached audit writer for `profile_name` via the
/// [`AuditWriterRegistry`], loading the HMAC key from keyring first.
///
/// Using the registry instead of `AuditWriter::open` directly ensures the
/// single-writer invariant: if another call site in
/// the same process already holds an `Arc<Mutex<AuditWriter>>` for this
/// profile, the same handle is returned rather than a second open attempt that
/// would receive `FileLocked`.
fn open_profile_audit_writer_via_registry(
    profile_name: &str,
    profile: &Profile,
) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
    let hmac_key = load_audit_hmac_key(profile)?;
    AuditWriterRegistry::get_or_open(profile_name, &profile.audit_log_path, Some(hmac_key)).map_err(
        |e| {
            tracing::debug!(
                error = %e,
                path = %profile.audit_log_path.display(),
                "deploy-c audit writer open failed"
            );
            WalletError::Internal(InternalError::UnexpectedState {
                detail: format!("audit.writer_open_failed: {e}"),
            })
        },
    )
}

/// Loads and decodes the profile's audit-log HMAC key from keyring.
fn load_audit_hmac_key(profile: &Profile) -> Result<Zeroizing<[u8; 32]>, WalletError> {
    let entry_ref = &profile.audit_log_hash_chain_key_id;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "keyring Entry::new failed for deploy-c audit HMAC key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
    })?;

    let secret_b64 = Zeroizing::new(entry.get_password().map_err(|e| {
        tracing::debug!(
            error = %e,
            service = %entry_ref.service,
            "get_password failed for deploy-c audit HMAC key"
        );
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("{}:{}", entry_ref.service, entry_ref.account),
        })
    })?);

    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(secret_b64.as_bytes()).map_err(|e| {
        tracing::debug!(error = %e, "deploy-c audit HMAC key base64 decode failed");
        WalletError::Internal(InternalError::UnexpectedState {
            detail: "audit.key_decode_failed: audit HMAC key is not valid base64".to_owned(),
        })
    })?);

    if decoded.len() != 32 {
        return Err(WalletError::Internal(InternalError::UnexpectedState {
            detail: format!(
                "audit.key_length_error: audit HMAC key must be 32 bytes, got {}",
                decoded.len()
            ),
        }));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(decoded.as_slice());
    Ok(key)
}

// ─────────────────────────────────────────────────────────────────────────────
// Genesis-signer resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the GENESIS signer source into a display label and, for the
/// External-shaped modes, a pre-built `Signer::External(verifier, key_data)`
/// `ScVal` override for [`DeploymentArgs::genesis_signer_scval_override`].
///
/// Returns `(display_label, None)` for `--initial-signer` (the existing
/// `Signer::Delegated` path, built downstream from `initial_signer` as
/// before) and `(display_label, Some(scval))` for the three External-shaped
/// modes (`--signer-webauthn`, `--signer-ed25519`, `--signer-external`).
///
/// # Errors
///
/// Returns [`WalletError::Validation`] for a malformed G-strkey, credential
/// lookup failure, or missing verifier registration; wraps
/// [`SaError`](stellar_agent_smart_account::error::SaError) encode failures
/// as [`WalletError::SmartAccount`].
async fn resolve_genesis_signer_source(
    args: &DeployCArgs,
) -> Result<(String, Option<stellar_xdr::ScVal>), WalletError> {
    if let Some(g_strkey) = &args.initial_signer {
        if let Err(e) = stellar_strkey::ed25519::PublicKey::from_string(g_strkey) {
            return Err(WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--initial-signer: {e}"),
            }));
        }
        return Ok((g_strkey.clone(), None));
    }

    if let Some(credential_name) = &args.signer_webauthn {
        let verifier_registry = VerifierRegistry::open().map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("could not open verifier registry: {e}"),
            })
        })?;
        let network_passphrase = args.network.passphrase();
        let verifier_entry = verifier_registry
            .webauthn_verifier_for(network_passphrase)
            .ok_or_else(|| {
                WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "no WebAuthn verifier deployed for network '{network_passphrase}'; \
                         run: smart-account deploy-webauthn-verifier"
                    ),
                })
            })?;
        let verifier_sc_addr =
            parse_c_strkey_to_smart_account(&verifier_entry.address).map_err(|e| {
                WalletError::SmartAccount {
                    wire_code: e.wire_code(),
                    message: format!(
                        "verifier registry address '{}' is not a valid C-strkey: {e}",
                        verifier_entry.address
                    ),
                }
            })?;

        let profile = resolve_profile_name(args.profile.as_deref());
        validate_path_component_ascii_safe(&profile).map_err(|reason| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("invalid profile name '{profile}': {reason}"),
            })
        })?;
        let creds_mgr =
            CredentialsManager::from_defaults_readonly(&profile, "localhost").map_err(|e| {
                WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("could not open passkeys registry: {e}"),
                })
            })?;
        let metadata = creds_mgr.show(credential_name).map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--signer-webauthn '{credential_name}': {e}"),
            })
        })?;
        if metadata.public_key_sec1_b64.is_empty() {
            return Err(WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "--signer-webauthn '{credential_name}': credential is missing \
                     public_key_sec1_b64 (delete and re-register)"
                ),
            }));
        }
        let pubkey_bytes = URL_SAFE_NO_PAD
            .decode(&metadata.public_key_sec1_b64)
            .map_err(|_| {
                WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "--signer-webauthn '{credential_name}': public_key_sec1_b64 is not \
                         valid base64url"
                    ),
                })
            })?;
        if pubkey_bytes.len() != 65 {
            return Err(WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "--signer-webauthn '{credential_name}': public_key_sec1_b64 decodes to \
                     {} bytes, expected 65",
                    pubkey_bytes.len()
                ),
            }));
        }
        let credential_id_bytes = URL_SAFE_NO_PAD
            .decode(&metadata.credential_id_b64url)
            .map_err(|_| {
                WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!(
                        "--signer-webauthn '{credential_name}': credential_id_b64url is not \
                         valid base64url"
                    ),
                })
            })?;
        let mut key_data = Vec::with_capacity(65 + credential_id_bytes.len());
        key_data.extend_from_slice(&pubkey_bytes);
        key_data.extend_from_slice(&credential_id_bytes);

        let scval = build_external_signer_scval(verifier_sc_addr, &key_data).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!("--signer-webauthn ScVal encode: {e}"),
            }
        })?;
        return Ok((credential_name.clone(), Some(scval)));
    }

    if let Some(hex_pubkey) = &args.signer_ed25519 {
        let key_data = hex::decode(hex_pubkey).map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--signer-ed25519 is not valid hex: {e}"),
            })
        })?;
        if key_data.len() != 32 {
            return Err(WalletError::Validation(ValidationError::AddressInvalid {
                input: format!(
                    "--signer-ed25519 must decode to exactly 32 bytes (a raw Ed25519 public \
                     key), got {} bytes",
                    key_data.len()
                ),
            }));
        }

        let verifier_c_strkey = if let Some(explicit) = &args.verifier {
            explicit.clone()
        } else {
            let verifier_registry = VerifierRegistry::open().map_err(|e| {
                WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("could not open verifier registry: {e}"),
                })
            })?;
            let network_passphrase = args.network.passphrase();
            verifier_registry
                .ed25519_verifier_for(network_passphrase)
                .map(|entry| entry.address.clone())
                .ok_or_else(|| {
                    WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "no Ed25519 verifier registered for network \
                             '{network_passphrase}'; run: smart-account \
                             deploy-ed25519-verifier (or pass --verifier)"
                        ),
                    })
                })?
        };
        let verifier_sc_addr =
            parse_c_strkey_to_smart_account(&verifier_c_strkey).map_err(|e| {
                WalletError::SmartAccount {
                    wire_code: e.wire_code(),
                    message: format!("--signer-ed25519 verifier '{verifier_c_strkey}': {e}"),
                }
            })?;
        let scval = build_external_signer_scval(verifier_sc_addr, &key_data).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!("--signer-ed25519 ScVal encode: {e}"),
            }
        })?;
        return Ok((hex_pubkey.clone(), Some(scval)));
    }

    if let Some(verifier_c_strkey) = &args.signer_external {
        let key_data_hex = args.signer_key_data.as_deref().unwrap_or("");
        let key_data = hex::decode(key_data_hex).map_err(|e| {
            WalletError::Validation(ValidationError::AddressInvalid {
                input: format!("--signer-key-data is not valid hex: {e}"),
            })
        })?;
        if key_data.is_empty() {
            return Err(WalletError::Validation(ValidationError::AddressInvalid {
                input: "--signer-key-data must be non-empty".to_owned(),
            }));
        }
        let verifier_sc_addr = parse_c_strkey_to_smart_account(verifier_c_strkey).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!("--signer-external: {e}"),
            }
        })?;
        let scval = build_external_signer_scval(verifier_sc_addr, &key_data).map_err(|e| {
            WalletError::SmartAccount {
                wire_code: e.wire_code(),
                message: format!("--signer-external ScVal encode: {e}"),
            }
        })?;
        return Ok((verifier_c_strkey.clone(), Some(scval)));
    }

    // Unreachable: the `genesis_signer_source` ArgGroup requires exactly one
    // of the four flags above.
    Err(WalletError::Validation(ValidationError::AddressInvalid {
        input: "no genesis signer source supplied".to_owned(),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Salt resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the 32-byte salt from `--salt-hex` or generates a fresh-random one.
///
/// # Errors
///
/// Returns [`WalletError::Validation`] wrapping [`ValidationError::ConfigInvalid`]
/// if `--salt-hex` is provided but is not valid 64-char lowercase hex.
fn resolve_salt(args: &DeployCArgs) -> Result<[u8; 32], WalletError> {
    if let Some(hex) = &args.salt_hex {
        decode_hex32(hex).map_err(|()| {
            WalletError::Validation(ValidationError::ConfigInvalid {
                component: "--salt-hex",
                reason: format!(
                    "must be exactly 64 lowercase hex characters (32 bytes); got {} chars",
                    hex.len()
                ),
            })
        })
    } else {
        // Fresh-random salt via OS CSPRNG.
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        Ok(salt)
    }
}

/// Decodes a 64-char hex string into exactly 32 bytes.
///
/// Delegates to [`stellar_agent_core::hex::decode_hex32`].
///
/// Returns `Err(())` for backwards compatibility with `resolve_salt`'s error mapping.
fn decode_hex32(hex: &str) -> Result<[u8; 32], ()> {
    stellar_agent_core::hex::decode_hex32(hex).map_err(|_| ())
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployer resolution
// ─────────────────────────────────────────────────────────────────────────────

/// Resolves the deployer keypair from the CLI flags.
///
/// Returns the keypair alongside any `mlock` degradation the secret-env
/// ceremony reported (`None` for the Ledger path, which never touches
/// `Wallet::unlock`); the caller records it once its audit writer is open.
///
/// # Errors
///
/// - [`WalletError::Auth`] — env var not set, S-strkey invalid, or Ledger not connected.
/// - [`WalletError::Auth`] wrapping [`stellar_agent_core::error::AuthError::SignerKeyMismatch`]
///   for Ledger public-key mismatch.
async fn resolve_deployer(
    args: &DeployCArgs,
) -> Result<(DeployerKeypair, Option<MlockDegradation>), WalletError> {
    if args.sign_with_ledger {
        // Ledger mode: we don't yet know the expected G-strkey before fetching it from
        // the device. The `signer_from_ledger` key-match check requires the expected
        // G-strkey; for deployer-from-Ledger we defer the key-match check — the
        // deployer IS the Ledger-derived G-strkey. We fetch the public key first via a
        // no-check path. Use a temporary HardwareSigningKey and derive the G-strkey
        // from it, then wrap it in DeployerKeypair::Ledger without a source-account
        // comparison. The deployment flow will fail at submission if the Ledger key
        // doesn't match the fetched account-sequence (fee-account must match signer).
        use stellar_agent_network::signing::hardware::HardwareSigningKey;
        let hw_key = HardwareSigningKey::native()
            .map_err(|e| {
                WalletError::Auth(stellar_agent_core::error::AuthError::KeyringNotFound {
                    name: format!("Ledger not found or Stellar app not open: {e}"),
                })
            })?
            .with_account_index(args.account_index);

        let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> = Box::new(hw_key);
        return Ok((
            DeployerKeypair::Ledger {
                account_index: args.account_index,
                signer,
            },
            None,
        ));
    }

    // SecretEnv mode.
    let var_name = args
        .deployer_secret_env
        .as_deref()
        .ok_or(WalletError::Auth(
            stellar_agent_core::error::AuthError::KeyringLocked,
        ))?;

    // We need the G-strkey to pass to signer_from_env for the key-match check.
    // At deploy-c time, the deployer G-strkey is derived from the env-var S-strkey.
    // Unlike `create` (which has an explicit `--sponsor` G-strkey), `deploy-c` derives
    // the deployer G-strkey from the secret. We construct the signer first without
    // the mismatch check, then wrap in DeployerKeypair::SecretEnv.
    let profile_name = resolve_profile_name(args.profile.as_deref());
    let SignerCeremonyOutcome {
        signer,
        mlock_degradation,
    } = resolve_software_signer_from_env(var_name, "deploy-c", Some(&profile_name)).await?;
    let signer: Box<dyn stellar_agent_network::Signer + Send + Sync> = Box::new(signer);

    Ok((
        DeployerKeypair::SecretEnv {
            var_name: var_name.to_owned(),
            signer,
        },
        mlock_degradation,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// Output helpers
// ─────────────────────────────────────────────────────────────────────────────

fn print_success(
    result: &DeploymentResult,
    envelope: &Envelope<DeploymentResult>,
    format: OutputFormat,
) {
    match format {
        OutputFormat::Table => {
            use stellar_agent_core::observability::redact_strkey_first5_last5;
            use stellar_agent_network::submit::redact_tx_hash;

            #[allow(clippy::print_stdout, reason = "CLI binary intentional user output")]
            {
                let smart_account = redact_strkey_first5_last5(&result.smart_account);
                let deployer = redact_strkey_first5_last5(&result.deployer_pubkey);
                println!("Smart account deployed: {smart_account}  (deployer {deployer})");

                // Redact salt to first-8-last-8. When salt is derived as
                // SHA256(credential_id) it is privacy-sensitive.
                let salt_display =
                    stellar_agent_core::hex::redact_hex_first8_last8(&result.salt_hex);
                println!("  salt_hex   {salt_display}");

                let wasm_display =
                    stellar_agent_core::hex::redact_hex_first8_last8(&result.wasm_hash);
                let uploaded = if result.wasm_uploaded { "yes" } else { "no" };
                println!("  wasm_hash  {wasm_display}  (uploaded: {uploaded})");

                if let Some(ref upload_tx) = result.upload_tx_hash {
                    println!("  upload_tx  {}", redact_tx_hash(upload_tx));
                }

                if let Some(ref tx_hash) = result.tx_hash {
                    println!("  tx_hash    {}", redact_tx_hash(tx_hash));
                } else {
                    println!("  tx_hash    (dry-run)");
                }

                if let Some(ledger) = result.ledger {
                    println!("  ledger     {ledger}");
                } else {
                    println!("  ledger     (dry-run)");
                }

                println!(
                    "  fee/op     {} stroops  ({})",
                    result.selected_fee_per_op_stroops, result.selected_fee_percentile
                );
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::fs;
    use std::path::{Path, PathBuf};

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use serde_json::Value;
    use serial_test::serial;
    use stellar_agent_core::profile::schema::Profile;
    use tempfile::TempDir;

    use super::*;

    const INITIAL_SIGNER_G: &str = "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N";

    fn profile_with_audit_path(name: &str, audit_path: PathBuf) -> Profile {
        Profile::builder_testnet_named(
            name,
            "stellar-agent-signer",
            name,
            "stellar-agent-nonce",
            name,
        )
        .audit_log_path(audit_path)
        .build()
    }

    fn install_audit_key(profile: &Profile) {
        let entry_ref = &profile.audit_log_hash_chain_key_id;
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        entry
            .set_password(&URL_SAFE_NO_PAD.encode([0x42u8; 32]))
            .unwrap();
    }

    const TEST_DEPLOYER_ENV_VAR: &str = "__STELLAR_AGENT_TEST_DEPLOY_C_SKEY";

    // A deterministic, testnet-only deployer S-strkey derived at runtime from a
    // fixed seed, so no secret-shaped literal is committed to source. The
    // deploy_c dry-run only needs a valid source key; it does not assert any
    // specific deployer address.
    fn test_deployer_skey() -> String {
        stellar_strkey::ed25519::PrivateKey::from_payload(&[0x42u8; 32])
            .expect("32-byte test seed must encode as S-strkey")
            .as_unredacted()
            .to_string()
            .as_str()
            .to_owned()
    }

    /// RAII guard that sets an environment variable for the duration of a test
    /// and removes it on drop.  Tests using this guard must be annotated with
    /// `#[serial]` to prevent concurrent env mutation.
    struct EnvGuard {
        var: &'static str,
    }

    #[allow(
        unsafe_code,
        reason = "test-only process environment override; #[serial] prevents sibling mutation"
    )]
    impl EnvGuard {
        fn set(var: &'static str, value: &str) -> Self {
            // SAFETY: serialised by #[serial]; no concurrent env access.
            unsafe {
                std::env::set_var(var, value);
            }
            Self { var }
        }
    }

    #[allow(
        unsafe_code,
        reason = "test-only environment cleanup; panic-safe via Drop"
    )]
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: same as set(); serialised by #[serial].
            unsafe {
                std::env::remove_var(self.var);
            }
        }
    }

    fn deploy_args(profile: Option<String>, dry_run: bool) -> (DeployCArgs, EnvGuard) {
        let guard = EnvGuard::set(TEST_DEPLOYER_ENV_VAR, &test_deployer_skey());
        let args = DeployCArgs {
            initial_signer: Some(INITIAL_SIGNER_G.to_owned()),
            signer_webauthn: None,
            signer_ed25519: None,
            verifier: None,
            signer_external: None,
            signer_key_data: None,
            accept_no_delegated_fallback: false,
            deployer_secret_env: Some(TEST_DEPLOYER_ENV_VAR.to_owned()),
            sign_with_ledger: false,
            account_index: 0,
            salt_hex: Some("11".repeat(32)),
            profile,
            salt_random: false,
            network: TargetNetwork::Testnet,
            rpc_url: "http://127.0.0.1:9".to_owned(),
            fee: Some("100".to_owned()),
            timeout_seconds: 1,
            output: OutputFormat::DEFAULT,
            dry_run,
        };
        (args, guard)
    }

    fn read_jsonl(path: &Path) -> Vec<Value> {
        let content = fs::read_to_string(path).unwrap_or_default();
        content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// `--signer-ed25519` (External-shaped genesis) without
    /// `--accept-no-delegated-fallback` is refused before any RPC, registry,
    /// or credential lookup.
    #[tokio::test]
    #[serial]
    async fn deploy_c_external_genesis_without_ack_is_refused() {
        stellar_agent_test_support::keyring_mock::install().ok();
        let (mut args, _env_guard) = deploy_args(None, true);
        args.initial_signer = None;
        args.signer_ed25519 = Some("11".repeat(32));
        args.accept_no_delegated_fallback = false;

        let code = run_with_dependencies(&args, |_| unreachable!(), || Ok(())).await;
        assert_eq!(
            code, 1,
            "External-only genesis without the ack flag must be refused"
        );
    }

    /// `--signer-external` without `--signer-key-data` is a clap grammar
    /// error (the `requires` constraint), not a runtime refusal.
    #[test]
    fn deploy_c_args_signer_external_requires_key_data() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Harness {
            #[command(flatten)]
            args: DeployCArgs,
        }
        let result = Harness::try_parse_from([
            "test",
            "--signer-external",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--accept-no-delegated-fallback",
            "--deployer-secret-env",
            "__STELLAR_AGENT_DEPLOY_C_DUMMY",
        ]);
        assert!(
            result.is_err(),
            "--signer-external without --signer-key-data must be a clap parse error"
        );
    }

    /// The `genesis_signer_source` ArgGroup refuses supplying both
    /// `--initial-signer` and `--signer-ed25519`.
    #[test]
    fn deploy_c_args_genesis_signer_source_is_mutually_exclusive() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct Harness {
            #[command(flatten)]
            args: DeployCArgs,
        }
        let result = Harness::try_parse_from([
            "test",
            "--initial-signer",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "--signer-ed25519",
            "11".repeat(32).as_str(),
            "--accept-no-delegated-fallback",
            "--deployer-secret-env",
            "__STELLAR_AGENT_DEPLOY_C_DUMMY",
        ]);
        assert!(
            result.is_err(),
            "--initial-signer and --signer-ed25519 must be mutually exclusive"
        );
    }

    #[test]
    #[serial]
    fn open_profile_audit_writer_uses_profile_keyring_and_path() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let dir = TempDir::new().unwrap();
        let profile_name = "deploy-c-audit-open-test";
        let profile =
            profile_with_audit_path(profile_name, dir.path().join("deploy-c-audit.jsonl"));
        install_audit_key(&profile);

        let writer = open_profile_audit_writer_via_registry(profile_name, &profile).unwrap();
        drop(writer);

        assert!(
            profile.audit_log_path.exists(),
            "audit writer should create the profile audit log path"
        );
    }

    #[tokio::test]
    #[serial]
    async fn deploy_c_dry_run_with_profile_opens_writer_but_emits_no_entries() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let dir = TempDir::new().unwrap();
        let profile = profile_with_audit_path(
            "deploy-c-audit-dry-run-test",
            dir.path().join("deploy-c-dry-run.jsonl"),
        );
        install_audit_key(&profile);

        let (args, _env_guard) = deploy_args(Some("deploy-c-audit-dry-run-test".to_owned()), true);
        let profile_for_loader = profile.clone();
        let code = run_with_dependencies(
            &args,
            move |name| {
                assert_eq!(name, "deploy-c-audit-dry-run-test");
                Ok(profile_for_loader.clone())
            },
            || Ok(()),
        )
        .await;

        assert_eq!(code, 0);
        assert!(
            profile.audit_log_path.exists(),
            "profile-backed dry-run should still open the audit writer"
        );
        let entries = read_jsonl(&profile.audit_log_path);
        assert!(
            entries.is_empty(),
            "deploy_smart_account dry-run invariant remains no audit entries: {entries:#?}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn deploy_c_profile_writer_emits_sa_raw_invocation_on_rpc_failure() {
        stellar_agent_test_support::keyring_mock::install().ok();

        let dir = TempDir::new().unwrap();
        let profile = profile_with_audit_path(
            "deploy-c-audit-failure-test",
            dir.path().join("deploy-c-failure.jsonl"),
        );
        install_audit_key(&profile);

        let (args, _env_guard) = deploy_args(Some("deploy-c-audit-failure-test".to_owned()), false);
        let profile_for_loader = profile.clone();
        let code = run_with_dependencies(
            &args,
            move |name| {
                assert_eq!(name, "deploy-c-audit-failure-test");
                Ok(profile_for_loader.clone())
            },
            || Ok(()),
        )
        .await;

        assert_eq!(code, 1);
        let entries = read_jsonl(&profile.audit_log_path);
        let raw_invocations: Vec<_> = entries
            .iter()
            .filter(|entry| entry["kind"] == "sa_raw_invocation")
            .collect();
        assert_eq!(
            raw_invocations.len(),
            1,
            "profile writer should receive exactly one failure audit entry: {entries:#?}"
        );
        assert_eq!(raw_invocations[0]["result"], "pre_submission_refused");
        assert!(
            raw_invocations[0]["wire_code"]
                .as_str()
                .is_some_and(|wire_code| wire_code.starts_with("sa.")),
            "wire_code should preserve the smart-account error namespace"
        );
    }
}
