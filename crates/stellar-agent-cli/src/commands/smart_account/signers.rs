//! `stellar-agent smart-account signers` — signer-set lifecycle subcommands.
//!
//! CLI surface for
//! [`stellar_agent_smart_account::managers::signers::SignersManager`].
//!
//! # Subcommands
//!
//! - [`ListArgs`] — `smart-account signers list` — reads on-chain signer set; writes
//!   a `SaSignerSetBaselined` audit row if no prior baseline exists.
//! - [`RefreshArgs`] — `smart-account signers refresh` — unconditionally writes a new
//!   `SaSignerSetBaselined` row (programmatic re-anchor after intentional
//!   out-of-band mutation).
//! - [`AddArgs`] — `smart-account signers add` — adds one signer to a context rule via
//!   OZ `add_signer`; emits `SaSignerAdded`. Accepts three mutually-exclusive
//!   signer-source flags:
//!   - `--signer-delegated <G-strkey>` — ed25519 delegated signer.
//!   - `--signer-external <verifier-C-strkey> --signer-key-data <hex>` — custom
//!     external-verifier signer with raw key-data.
//!   - `--signer-webauthn <credential-name>` — WebAuthn passkey signer resolved
//!     from the credential store and `VerifierRegistry`.
//! - [`RemoveArgs`] — `smart-account signers remove` — removes one signer by `signer_id`
//!   via OZ `remove_signer`; emits `SaSignerRemoved`. Refuses operations that
//!   would violate `signer_count >= threshold` with `safe_ordering_hint`.
//! - [`SetThresholdArgs`] — `smart-account signers set-threshold` — changes the
//!   signing threshold via OZ `ThresholdPolicyContract::set_threshold`; emits
//!   `SaThresholdChanged`.
//!
//! # Signer-source modes (mirror of `smart-account rules`)
//!
//! Write subcommands accept exactly one of:
//! - `--signer-secret-env <VAR>` — read S-strkey from env var.
//! - `--sign-with-ledger` — Ledger hardware wallet (BIP-44 `--account-index`).
//!
//! Read subcommands (`list`, `refresh`) also accept these modes because the
//! manager requires a `source_account_strkey` for the fee-paying envelope.
//!
//! # Mainnet defence
//!
//! All subcommands (including `list` and `refresh`, which trigger baseline-write
//! audit rows) structurally refuse mainnet before any RPC or signing call.
//!
//! # Inverse-bypass discipline
//!
//! All write paths invoke `Signer::sign_auth_digest` exclusively via the
//! `SignersManager`'s `complete_authorization_entry` call site.
//!
//! # Wire codes rendered
//!
//! - `sa.threshold_unreachable` — `SaError::ThresholdUnreachable`
//! - `sa.signer_set_missing_baseline` — `SaError::SignerSetMissingBaseline`
//! - `sa.signer_set_diverged` — `SaError::SignerSetDiverged`
//! - `network.rpc_divergence` — `SaError::NetworkRpcDivergence`
//! - `sa.threshold_policy_not_installed` — `SaError::ThresholdPolicyNotInstalled`
//! - `sa.threshold_policy_identification_failed` — `SaError::ThresholdPolicyIdentificationFailed`

use base64::Engine as _;
use clap::{ArgGroup, Args, Subcommand};
use serde::{Deserialize, Serialize};
use stellar_agent_core::audit_log::signer_set::SignerPubkey;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{CapKind, NetworkError, ValidationError, WalletError};
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::credentials::CredentialsManager;
use stellar_agent_smart_account::managers::rules::{
    OZ_MAX_SIGNERS, decode_signer_count_from_scval, parse_c_strkey_to_smart_account,
};
use stellar_agent_smart_account::managers::signers::{
    build_delegated_signer_scval, build_external_signer_scval,
};
use stellar_agent_smart_account::verifiers::VerifierRegistry;
use tracing::info;
use uuid::Uuid;

use crate::commands::smart_account::common::{
    CommonArgsView, CommonHandlerContext, SignerSourceFlags,
};
use crate::common::network::TargetNetwork;
use crate::common::render::render_json;
use crate::common::{resolve_profile_name, validate_path_component_ascii_safe};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default submission timeout in seconds.
const DEFAULT_TIMEOUT_SECONDS: u64 = 60;

/// Default Stellar testnet Soroban RPC endpoint.
const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";

// ─────────────────────────────────────────────────────────────────────────────
// Cap-enforcement helper
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `Err(ContextRuleCapsExceeded { kind: Signer, attempted, … })` when
/// `attempted > OZ_MAX_SIGNERS`.  `attempted` is the signer count that would
/// result from adding one signer to a rule that currently has
/// `current_signer_count` signers (`attempted = current + 1`).  The on-chain
/// `TooManySigners = 3010` error is the authoritative last-line defence; this
/// check produces an actionable error before the simulate/submit cycle.
fn enforce_add_signer_cap(attempted: u32) -> Result<(), ValidationError> {
    if attempted > OZ_MAX_SIGNERS {
        return Err(ValidationError::ContextRuleCapsExceeded {
            kind: CapKind::Signer,
            attempted,
            max: OZ_MAX_SIGNERS,
        });
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for the `smart-account signers` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct SignersArgs {
    /// The signers subcommand to run.
    #[command(subcommand)]
    pub subcommand: SignersSubcommand,
}

/// Subcommands of `stellar-agent smart-account signers`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum SignersSubcommand {
    /// List the on-chain signer set for a context rule.
    ///
    /// Reads the current signer set from the primary RPC (two-RPC consultation
    /// for agreement). Emits a `SaSignerSetBaselined` audit row if no prior
    /// baseline or state-change row exists for this `(rule_id, smart_account)`
    /// pair — establishing the baseline for future divergence detection.
    List(Box<ListArgs>),

    /// Unconditionally write a fresh `SaSignerSetBaselined` audit row.
    ///
    /// Call this after an intentional out-of-band signer change to re-anchor
    /// the wallet's divergence-detection view. Idempotent: always writes a new
    /// row regardless of prior baseline state.
    Refresh(Box<RefreshArgs>),

    /// Add a signer to a context rule.
    ///
    /// Constructs and submits an `InvokeHostFunctionOp` calling OZ
    /// `add_signer(rule_id, new_signer)`. Emits `SaSignerAdded`.
    ///
    /// Refuses operations that would violate `threshold <= signer_count`
    /// with `SaError::ThresholdUnreachable` + `safe_ordering_hint`.
    ///
    /// Accepts exactly one of:
    /// - `--signer-delegated <G-strkey>` — ed25519 delegated signer.
    /// - `--signer-external <verifier-C-strkey> --signer-key-data <hex>` —
    ///   external-verifier signer with raw hex key-data.
    /// - `--signer-webauthn <credential-name>` — WebAuthn passkey signer.
    /// - `--signer-ed25519 <64-hex-pubkey> [--verifier <C-strkey>]` — first-class
    ///   Ed25519 external signer (verifier resolved from the registry when
    ///   `--verifier` is omitted).
    Add(Box<AddArgs>),

    /// Remove a signer from a context rule.
    ///
    /// Constructs and submits an `InvokeHostFunctionOp` calling OZ
    /// `remove_signer(rule_id, signer_id)`. Emits `SaSignerRemoved`.
    ///
    /// Refuses if removing the signer would drop `signer_count` below
    /// `threshold` — error includes `safe_ordering_hint` naming the safe
    /// two-command sequence (lower threshold first, then remove).
    Remove(Box<RemoveArgs>),

    /// Change the signing threshold for a context rule.
    ///
    /// Constructs and submits an `InvokeHostFunctionOp` calling the OZ
    /// threshold-policy contract's `set_threshold(rule_id, new_threshold)`.
    /// Emits `SaThresholdChanged`.
    ///
    /// The threshold-policy contract is identified by wasm-hash allowlist
    /// lookup (`THRESHOLD_POLICY_WASM_HASHES`); zero or multiple matches
    /// refuse with `sa.threshold_policy_identification_failed`.
    SetThreshold(Box<SetThresholdArgs>),
}

/// Runs the `smart-account signers` subcommand group.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &SignersArgs) -> i32 {
    match &args.subcommand {
        SignersSubcommand::List(a) => list_run(a).await,
        SignersSubcommand::Refresh(a) => refresh_run(a).await,
        SignersSubcommand::Add(a) => add_run(a).await,
        SignersSubcommand::Remove(a) => remove_run(a).await,
        SignersSubcommand::SetThreshold(a) => set_threshold_run(a).await,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers list`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers list`.
///
/// Reads on-chain signer set; writes `SaSignerSetBaselined` if no prior
/// baseline exists. Mainnet is structurally refused.
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    override_usage = "stellar-agent smart-account signers list [OPTIONS] --account <C_STRKEY> --rule-id <U32>"
)]
pub struct ListArgs {
    /// Smart-account contract C-strkey to query.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to query.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation. Defaults to `--rpc-url`
    /// (degrades to single-RPC; both will agree trivially).
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers list`.
///
/// This envelope intentionally omits a `baselined` field: `list_signers` does
/// not yet expose a first-observation signal from the manager, so any such
/// field would be hard-coded and would misreport in the JSON output. The field
/// will be re-introduced when the manager exposes the signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResult {
    /// Smart-account C-strkey (caller-supplied; not fetched from chain).
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// Number of signers in the rule.
    pub signer_count: u32,
    /// Threshold required for rule invocation.
    pub threshold: u32,
    /// Signer IDs (parallel to `signer_kinds`).
    pub signer_ids: Vec<u32>,
    /// Human-readable signer-kind labels (parallel to `signer_ids`).
    pub signer_kinds: Vec<String>,
}

async fn list_run(args: &ListArgs) -> i32 {
    let request_id = new_request_id();

    // Mainnet defence.
    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                &request_id,
            );
        }
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers list: querying on-chain signer set"
    );

    match manager
        .list_signers(
            ctx.smart_account,
            args.rule_id,
            Some(&source_account_strkey),
            request_id.clone(),
        )
        .await
    {
        Ok(observed) => {
            let signer_kinds = observed
                .signer_pubkeys
                .iter()
                .map(signer_kind_label)
                .collect::<Vec<_>>();
            let result = ListResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                signer_count: observed.signer_count,
                threshold: observed.threshold,
                signer_ids: observed.signer_ids,
                signer_kinds,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers refresh`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers refresh`.
///
/// Unconditionally fetches signer set and writes `SaSignerSetBaselined`.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct RefreshArgs {
    /// Smart-account contract C-strkey to baseline.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to baseline.
    #[arg(long, value_name = "U32", required = true)]
    pub rule_id: u32,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers refresh`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// Number of signers in the rule at refresh time.
    pub signer_count: u32,
    /// Threshold at refresh time.
    pub threshold: u32,
}

async fn refresh_run(args: &RefreshArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                &request_id,
            );
        }
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers refresh: writing fresh baseline"
    );

    match manager
        .refresh_signer_baseline(
            ctx.smart_account,
            args.rule_id,
            Some(&source_account_strkey),
            request_id.clone(),
        )
        .await
    {
        Ok(observed) => {
            let result = RefreshResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                signer_count: observed.signer_count,
                threshold: observed.threshold,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers add`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers add`.
///
/// Adds one signer to a context rule via OZ `add_signer`.
///
/// Exactly one of `--signer-delegated`, `--signer-external` /
/// `--signer-key-data`, or `--signer-webauthn` MUST be supplied (enforced by
/// the `new_signer_source` `ArgGroup`).
///
/// # Signer-source paths
///
/// - `--signer-delegated <G-strkey>` — ed25519 delegated signer; encoded as
///   OZ `Signer::Delegated(Address)`.
/// - `--signer-external <verifier-C-strkey> --signer-key-data <hex>` — custom
///   external-verifier signer; encoded as OZ `Signer::External(Address, Bytes)`.
/// - `--signer-webauthn <credential-name>` — WebAuthn passkey signer; resolved
///   from the local credential store. key_data is `pubkey_65_bytes ||
///   credential_id_bytes` per the OZ WebAuthn verifier
///   (`canonicalize_key` strips credential ID at verify time; full concat stored).
///   The verifier address is read from the `VerifierRegistry` for the target network.
/// - `--signer-ed25519 <64-hex-pubkey>` — first-class Ed25519 external signer;
///   encoded as OZ `Signer::External(verifier, key_data)` where `key_data` is the
///   raw 32-byte Ed25519 public key. The verifier address resolves from
///   `--verifier <C-strkey>` when supplied, else from the `VerifierRegistry`'s
///   registered Ed25519 verifier for the target network (fail-closed if neither).
#[non_exhaustive]
#[derive(Debug, Args)]
#[command(
    group(ArgGroup::new("new_signer_source")
        .args(["signer_delegated", "signer_external", "signer_webauthn", "signer_ed25519"])
        .required(true)
        .multiple(false))
)]
pub struct AddArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID to add the signer to.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// G-strkey of the delegated ed25519 signer to add.
    ///
    /// Encodes as OZ `Signer::Delegated(Address)` on-chain.
    /// Mutually exclusive with `--signer-external` and `--signer-webauthn`.
    #[arg(
        long = "signer-delegated",
        visible_alias = "new-signer",
        value_name = "G_STRKEY",
        group = "new_signer_source"
    )]
    pub signer_delegated: Option<String>,

    /// C-strkey of the deployed verifier contract for an external signer.
    ///
    /// Must be paired with `--signer-key-data`. Together they encode as
    /// OZ `Signer::External(verifier, key_data)` on-chain.
    /// Mutually exclusive with `--signer-delegated` and `--signer-webauthn`.
    #[arg(
        long = "signer-external",
        value_name = "C_STRKEY",
        requires = "signer_key_data",
        group = "new_signer_source"
    )]
    pub signer_external: Option<String>,

    /// Hex-encoded raw key-data for an external signer.
    ///
    /// Required when `--signer-external` is supplied.
    #[arg(
        long = "signer-key-data",
        value_name = "HEX",
        requires = "signer_external"
    )]
    pub signer_key_data: Option<String>,

    /// Credential name from the local passkeys registry to add as a WebAuthn
    /// signer.
    ///
    /// The verifier contract address is read from the `VerifierRegistry` for
    /// the target network (written by `smart-account deploy-webauthn-verifier`).
    /// key_data is constructed as `pubkey_65_bytes || credential_id_bytes` per
    /// the OZ WebAuthn verifier's expected layout.
    /// Mutually exclusive with `--signer-delegated` and `--signer-external`.
    #[arg(
        long = "signer-webauthn",
        value_name = "CREDENTIAL_NAME",
        group = "new_signer_source"
    )]
    pub signer_webauthn: Option<String>,

    /// 64-hex-character raw Ed25519 public key of a first-class external signer.
    ///
    /// Decoded to exactly 32 bytes (invalid hex or a non-64-char length is
    /// refused fail-closed, never silently truncated or padded) and encoded as
    /// OZ `Signer::External(verifier, key_data)` where `key_data` is the raw
    /// public key. The verifier contract address resolves from `--verifier` when
    /// supplied, else from the `VerifierRegistry`'s registered Ed25519 verifier
    /// for the target network (deploy one via
    /// `smart-account deploy-ed25519-verifier`).
    /// Mutually exclusive with `--signer-delegated`, `--signer-external`, and
    /// `--signer-webauthn`.
    #[arg(
        long = "signer-ed25519",
        value_name = "HEX_PUBKEY_64",
        group = "new_signer_source"
    )]
    pub signer_ed25519: Option<String>,

    /// Ed25519 verifier contract C-strkey override for `--signer-ed25519`.
    ///
    /// When omitted, the verifier address resolves from the `VerifierRegistry`
    /// for the target network. Only meaningful with `--signer-ed25519`.
    #[arg(
        long = "verifier",
        value_name = "C_STRKEY",
        requires = "signer_ed25519"
    )]
    pub verifier: Option<String>,

    /// Profile name for audit-log path resolution and credential store lookup
    /// (used by `--signer-webauthn`).
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers add`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// On-chain ID assigned to the new signer.
    pub new_signer_id: u32,
    /// Human-readable signer-source type label.
    ///
    /// One of `"delegated"`, `"external"`, `"webauthn"`, or `"ed25519"`.
    pub signer_source: String,
    /// Display string for the added signer (G-strkey for delegated; verifier
    /// C-strkey for external/webauthn; redacted to first-5-last-5 for
    /// external/webauthn in log output, but full value returned to the caller
    /// for confirmation).
    pub new_signer: String,
}

async fn add_run(args: &AddArgs) -> i32 {
    let request_id = new_request_id();

    // Mainnet defence.
    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    // ── Resolve signer-source: build ScVal + SignerPubkey for each path ───────
    //
    // Exactly one of `signer_delegated` / `signer_external` / `signer_webauthn`
    // is non-None, enforced by the `new_signer_source` ArgGroup at parse time.

    let (new_signer_scval, new_signer_pubkey, signer_source_label, new_signer_display) =
        if let Some(g_strkey) = &args.signer_delegated {
            // ── Delegated (ed25519) ───────────────────────────────────────────
            // Encoded as OZ `Signer::Delegated(Address)`.
            let scval = match build_delegated_signer_scval(g_strkey) {
                Ok(v) => v,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("--signer-delegated: {e}"),
                        }),
                        &request_id,
                    );
                }
            };
            let pubkey = match build_ed25519_signer_pubkey(g_strkey) {
                Ok(pk) => pk,
                Err(e) => return emit_error(&e, &request_id),
            };
            (scval, pubkey, "delegated".to_owned(), g_strkey.clone())
        } else if let Some(verifier_c_strkey) = &args.signer_external {
            // ── External (custom verifier) ────────────────────────────────────
            // Encoded as OZ `Signer::External(Address, Bytes)`.
            // key_data is operator-supplied raw hex; no canonicalisation applied here
            // (operator takes responsibility for correct layout matching the verifier).
            let key_data_hex = args.signer_key_data.as_deref().unwrap_or("");
            let key_data = match hex::decode(key_data_hex) {
                Ok(b) => b,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("--signer-key-data is not valid hex: {e}"),
                        }),
                        &request_id,
                    );
                }
            };
            if key_data.is_empty() {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: "--signer-key-data must be non-empty".to_owned(),
                    }),
                    &request_id,
                );
            }
            let verifier_sc_addr = match parse_c_strkey_to_smart_account(verifier_c_strkey) {
                Ok(addr) => addr,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: format!("--signer-external: {e}"),
                        },
                        &request_id,
                    );
                }
            };
            let scval = match build_external_signer_scval(verifier_sc_addr, &key_data) {
                Ok(v) => v,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: format!("--signer-external ScVal encode: {e}"),
                        },
                        &request_id,
                    );
                }
            };
            // key_data_first16 for audit-log display.
            let key_data_first16: [u8; 16] = {
                let mut arr = [0u8; 16];
                let len = key_data.len().min(16);
                arr[..len].copy_from_slice(&key_data[..len]);
                arr
            };
            let pubkey = SignerPubkey::External {
                verifier_contract: verifier_c_strkey.clone(),
                key_data_first16,
            };
            (
                scval,
                pubkey,
                "external".to_owned(),
                verifier_c_strkey.clone(),
            )
        } else if let Some(credential_name) = &args.signer_webauthn {
            // ── WebAuthn passkey ──────────────────────────────────────────────
            // key_data = pubkey_65_bytes || credential_id_bytes, matching the OZ
            // WebAuthn verifier (`canonicalize_key` strips the credential-ID
            // suffix at verify time; the full concat is stored on-chain).
            // Verifier address is read from `VerifierRegistry` for the target network.

            let verifier_registry = match VerifierRegistry::open() {
                Ok(r) => r,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("could not open verifier registry: {e}"),
                        }),
                        &request_id,
                    );
                }
            };

            let network_passphrase = args.network.passphrase();
            let verifier_entry = match verifier_registry.webauthn_verifier_for(network_passphrase) {
                Some(e) => e,
                None => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!(
                                "no WebAuthn verifier deployed for network '{network_passphrase}'; \
                                 run: smart-account deploy-webauthn-verifier"
                            ),
                        }),
                        &request_id,
                    );
                }
            };

            let verifier_sc_addr = match parse_c_strkey_to_smart_account(&verifier_entry.address) {
                Ok(addr) => addr,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: format!(
                                "verifier registry address '{}' is not a valid C-strkey: {e}",
                                verifier_entry.address
                            ),
                        },
                        &request_id,
                    );
                }
            };

            let profile = resolve_profile_name(args.profile.as_deref());
            if let Err(reason) = validate_path_component_ascii_safe(&profile) {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!("invalid profile name '{profile}': {reason}"),
                    }),
                    &request_id,
                );
            }

            let creds_mgr = match CredentialsManager::from_defaults_readonly(&profile, "localhost")
            {
                Ok(m) => m,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("could not open passkeys registry: {e}"),
                        }),
                        &request_id,
                    );
                }
            };

            let metadata = match creds_mgr.show(credential_name) {
                Ok(m) => m,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("--signer-webauthn '{credential_name}': {e}"),
                        }),
                        &request_id,
                    );
                }
            };

            if metadata.public_key_sec1_b64.is_empty() {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-webauthn '{credential_name}': credential is missing \
                             public_key_sec1_b64 (delete and re-register)"
                        ),
                    }),
                    &request_id,
                );
            }

            // Decode public key (65-byte uncompressed SEC1 P-256 point).
            let pubkey_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&metadata.public_key_sec1_b64)
            {
                Ok(b) => b,
                Err(_) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!(
                                "--signer-webauthn '{credential_name}': \
                                 public_key_sec1_b64 is not valid base64url"
                            ),
                        }),
                        &request_id,
                    );
                }
            };
            if pubkey_bytes.len() != 65 {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-webauthn '{credential_name}': public_key_sec1_b64 \
                             decodes to {} bytes, expected 65",
                            pubkey_bytes.len()
                        ),
                    }),
                    &request_id,
                );
            }

            // Decode credential_id bytes.
            let credential_id_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&metadata.credential_id_b64url)
            {
                Ok(b) => b,
                Err(_) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!(
                                "--signer-webauthn '{credential_name}': \
                                 credential_id_b64url is not valid base64url"
                            ),
                        }),
                        &request_id,
                    );
                }
            };
            if credential_id_bytes.is_empty() {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-webauthn '{credential_name}': credential_id_b64url is empty \
                             (corrupted credential store entry; delete and re-register)"
                        ),
                    }),
                    &request_id,
                );
            }

            // key_data = pubkey_65_bytes || credential_id_bytes.
            // Canonical layout expected by the OZ WebAuthn verifier:
            //   `canonicalize_key` reads bytes 0..65 as the public key; the credential-ID
            //   suffix at bytes 65+ is metadata used for credential lookup on the off-chain
            //   side and ignored by the on-chain verifier.
            let mut key_data = Vec::with_capacity(65 + credential_id_bytes.len());
            key_data.extend_from_slice(&pubkey_bytes);
            key_data.extend_from_slice(&credential_id_bytes);

            let scval = match build_external_signer_scval(verifier_sc_addr, &key_data) {
                Ok(v) => v,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: format!("--signer-webauthn ScVal encode: {e}"),
                        },
                        &request_id,
                    );
                }
            };

            let credential_id_first16: [u8; 16] = {
                let mut arr = [0u8; 16];
                let len = credential_id_bytes.len().min(16);
                arr[..len].copy_from_slice(&credential_id_bytes[..len]);
                arr
            };
            let pubkey = SignerPubkey::WebAuthn {
                credential_id_first16,
            };
            (
                scval,
                pubkey,
                "webauthn".to_owned(),
                credential_name.clone(),
            )
        } else if let Some(hex_pubkey) = &args.signer_ed25519 {
            // ── First-class Ed25519 external signer ───────────────────────────
            // key_data is the raw 32-byte Ed25519 public key; encoded as OZ
            // `Signer::External(verifier, key_data)` — the same on-chain shape as
            // `--signer-external`, resolved through the same
            // `build_external_signer_scval`. The OZ Ed25519 verifier's
            // `canonicalize_key` returns the 32-byte key verbatim
            // (`packages/accounts/src/verifiers/ed25519.rs`, SHA `a9c4216`).

            // Decode exactly 32 bytes; fail closed on invalid hex or wrong length.
            let key_data = match hex::decode(hex_pubkey) {
                Ok(b) => b,
                Err(e) => {
                    return emit_error(
                        &WalletError::Validation(ValidationError::AddressInvalid {
                            input: format!("--signer-ed25519 is not valid hex: {e}"),
                        }),
                        &request_id,
                    );
                }
            };
            if key_data.len() != 32 {
                return emit_error(
                    &WalletError::Validation(ValidationError::AddressInvalid {
                        input: format!(
                            "--signer-ed25519 must decode to exactly 32 bytes (a raw Ed25519 \
                             public key), got {} bytes",
                            key_data.len()
                        ),
                    }),
                    &request_id,
                );
            }

            // Resolve the verifier address: explicit `--verifier` override, else
            // the network's registered Ed25519 verifier. Fail closed if neither
            // is available.
            let verifier_c_strkey = if let Some(explicit) = &args.verifier {
                explicit.clone()
            } else {
                let verifier_registry = match VerifierRegistry::open() {
                    Ok(r) => r,
                    Err(e) => {
                        return emit_error(
                            &WalletError::Validation(ValidationError::AddressInvalid {
                                input: format!("could not open verifier registry: {e}"),
                            }),
                            &request_id,
                        );
                    }
                };
                let network_passphrase = args.network.passphrase();
                match verifier_registry.ed25519_verifier_for(network_passphrase) {
                    Some(entry) => entry.address.clone(),
                    None => {
                        return emit_error(
                            &WalletError::Validation(ValidationError::AddressInvalid {
                                input: format!(
                                    "no Ed25519 verifier registered for network \
                                     '{network_passphrase}'; run: \
                                     smart-account deploy-ed25519-verifier (or pass --verifier)"
                                ),
                            }),
                            &request_id,
                        );
                    }
                }
            };

            let verifier_sc_addr = match parse_c_strkey_to_smart_account(&verifier_c_strkey) {
                Ok(addr) => addr,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: format!(
                                "--signer-ed25519 verifier '{verifier_c_strkey}': {e}"
                            ),
                        },
                        &request_id,
                    );
                }
            };

            let scval = match build_external_signer_scval(verifier_sc_addr, &key_data) {
                Ok(v) => v,
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: format!("--signer-ed25519 ScVal encode: {e}"),
                        },
                        &request_id,
                    );
                }
            };

            // key_data_first16 for audit-log display (an Ed25519 external signer
            // IS an OZ `Signer::External`; reuse the External audit representation).
            let key_data_first16: [u8; 16] = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&key_data[..16]);
                arr
            };
            let pubkey = SignerPubkey::External {
                verifier_contract: verifier_c_strkey.clone(),
                key_data_first16,
            };
            (scval, pubkey, "ed25519".to_owned(), verifier_c_strkey)
        } else {
            // ArgGroup enforces that one of the four is always set; this branch
            // is unreachable at runtime but required for exhaustive match.
            unreachable!("ArgGroup `new_signer_source` guarantees one signer-source flag is set")
        };

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    // Pre-simulate cap check: fetch the current rule's signer count via
    // `get_rule` and refuse fail-CLOSED if adding one more signer would exceed
    // OZ_MAX_SIGNERS.
    // TOCTOU note: the fetch is non-atomic. A concurrent mutation landing
    // between fetch and submit surfaces as `SaError::DeploymentFailed` with
    // `[OZ:TooManySigners]`. Retry via `smart-account rules get` + re-submit.
    let source_account_strkey = match ctx.signer.public_key().await {
        Ok(pk) => pk.to_string(),
        Err(e) => {
            return emit_error(
                &WalletError::Validation(ValidationError::AddressInvalid {
                    input: format!("signer.public_key(): {e}"),
                }),
                &request_id,
            );
        }
    };

    let cr_manager = match ctx.context_rule_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    let smart_account_for_cap_check = ctx.smart_account.clone();

    match cr_manager
        .get_rule(
            smart_account_for_cap_check,
            args.rule_id,
            &source_account_strkey,
        )
        .await
    {
        Ok(Some(scval)) => {
            // Decode the current signer count from the returned ContextRule ScVal.
            // `decode_signer_count_from_scval` reads the `signer_ids` field of
            // the OZ context-rule storage layout.
            match decode_signer_count_from_scval(&scval) {
                Ok(current_signer_count) => {
                    let attempted = current_signer_count.saturating_add(1);
                    if let Err(e) = enforce_add_signer_cap(attempted) {
                        return emit_error(&WalletError::Validation(e), &request_id);
                    }
                }
                Err(e) => {
                    return emit_error(
                        &WalletError::SmartAccount {
                            wire_code: e.wire_code(),
                            message: e.to_string(),
                        },
                        &request_id,
                    );
                }
            }
        }
        Ok(None) => {
            // Rule not found. Let the `add_signer` call below surface the
            // `ContextRuleNotFound` (discriminant 3000) error at simulate time.
        }
        Err(e) => {
            return emit_error(
                &WalletError::SmartAccount {
                    wire_code: e.wire_code(),
                    message: e.to_string(),
                },
                &request_id,
            );
        }
    }

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        account = %redact_strkey_first5_last5(&args.account),
        signer_source = %signer_source_label,
        "smart-account signers add: submitting add_signer"
    );

    match manager
        .add_signer(
            ctx.smart_account,
            args.rule_id,
            new_signer_scval,
            new_signer_pubkey,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(new_signer_id) => {
            let result = AddResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_signer_id,
                signer_source: signer_source_label,
                new_signer: new_signer_display,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers remove`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers remove`.
///
/// Removes a signer by its on-chain `signer_id`.  Use `smart-account signers list`
/// to obtain the current signer IDs.
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID from which to remove the signer.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// On-chain signer ID to remove (from `smart-account signers list`).
    #[arg(long = "signer-id", value_name = "U32", required = true)]
    pub signer_id: u32,

    /// Profile name for audit-log path resolution.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers remove`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// The signer ID that was removed.
    pub removed_signer_id: u32,
}

async fn remove_run(args: &RemoveArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        signer_id = args.signer_id,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers remove: submitting remove_signer"
    );

    match manager
        .remove_signer(
            ctx.smart_account,
            args.rule_id,
            args.signer_id,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let result = RemoveResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                removed_signer_id: args.signer_id,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// `smart-account signers set-threshold`
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `smart-account signers set-threshold`.
///
/// Changes the threshold of a context rule's threshold-policy contract.
/// The policy is identified via wasm-hash allowlist lookup; single-match
/// required (zero / multi-match refuse with
/// `sa.threshold_policy_identification_failed`).
#[non_exhaustive]
#[derive(Debug, Args)]
pub struct SetThresholdArgs {
    /// Smart-account contract C-strkey.
    #[arg(long, value_name = "C_STRKEY", required = true)]
    pub account: String,

    /// Context rule ID whose threshold to change.
    #[arg(long = "rule-id", value_name = "U32", required = true)]
    pub rule_id: u32,

    /// New threshold value (`1 <= new_threshold <= signer_count`).
    #[arg(long = "new-threshold", value_name = "U32", required = true)]
    pub new_threshold: u32,

    /// Profile name for audit-log path resolution.
    ///
    /// Note: there is no `--auth-rule-id` flag. The manager internally sets
    /// `auth_rule_ids = vec![rule_id]`; there is no supported override path at
    /// this CLI surface.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    #[command(flatten)]
    pub signer_source: SignerSourceFlags,

    /// Network to target (testnet / mainnet).
    #[arg(long, default_value_t = TargetNetwork::Testnet, value_name = "NETWORK")]
    pub network: TargetNetwork,

    /// Soroban RPC endpoint URL.
    #[arg(long, default_value = TESTNET_RPC_URL, value_name = "URL")]
    pub rpc_url: String,

    /// Secondary RPC URL for two-RPC consultation.
    #[arg(long, value_name = "URL")]
    pub secondary_rpc_url: Option<String>,

    /// Submission timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECONDS, value_name = "SECONDS")]
    pub timeout_seconds: u64,
}

/// Result envelope for `smart-account signers set-threshold`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetThresholdResult {
    /// Smart-account C-strkey.
    pub smart_account: String,
    /// Context rule ID.
    pub rule_id: u32,
    /// The new threshold value that was applied.
    pub new_threshold: u32,
}

macro_rules! impl_common_args_view {
    ($ty:ty) => {
        impl CommonArgsView for $ty {
            fn account(&self) -> &str {
                &self.account
            }

            fn profile(&self) -> Option<&str> {
                self.profile.as_deref()
            }

            fn signer_source(&self) -> &SignerSourceFlags {
                &self.signer_source
            }

            fn network(&self) -> TargetNetwork {
                self.network
            }

            fn rpc_url(&self) -> &str {
                &self.rpc_url
            }

            fn secondary_rpc_url(&self) -> Option<&str> {
                self.secondary_rpc_url.as_deref()
            }

            fn timeout_seconds(&self) -> u64 {
                self.timeout_seconds
            }
        }
    };
}

impl_common_args_view!(ListArgs);
impl_common_args_view!(RefreshArgs);
impl_common_args_view!(AddArgs);
impl_common_args_view!(RemoveArgs);
impl_common_args_view!(SetThresholdArgs);

async fn set_threshold_run(args: &SetThresholdArgs) -> i32 {
    let request_id = new_request_id();

    if args.network == TargetNetwork::Mainnet {
        return emit_error(
            &WalletError::Network(NetworkError::MainnetWriteForbidden),
            &request_id,
        );
    }

    let ctx = match CommonHandlerContext::new(args).await {
        Ok(ctx) => ctx,
        Err(e) => return emit_error(&e, &request_id),
    };

    let manager = match ctx.signers_manager() {
        Ok(m) => m,
        Err(e) => return emit_error(&e, &request_id),
    };

    info!(
        rule_id = args.rule_id,
        new_threshold = args.new_threshold,
        account = %redact_strkey_first5_last5(&args.account),
        "smart-account signers set-threshold: submitting set_threshold"
    );

    match manager
        .set_threshold(
            ctx.smart_account,
            args.rule_id,
            args.new_threshold,
            ctx.signer.as_ref(),
            request_id.clone(),
        )
        .await
    {
        Ok(()) => {
            let result = SetThresholdResult {
                smart_account: args.account.clone(),
                rule_id: args.rule_id,
                new_threshold: args.new_threshold,
            };
            emit_success(&result, &request_id)
        }
        Err(e) => emit_error_sa(&e, &request_id),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a fresh UUID-v4 request-id for audit-log forensic correlation.
fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

/// Returns a human-readable label for a [`SignerPubkey`] variant.
fn signer_kind_label(pk: &SignerPubkey) -> String {
    match pk {
        SignerPubkey::Ed25519 { .. } => "delegated_ed25519".to_owned(),
        SignerPubkey::External { .. } => "external".to_owned(),
        SignerPubkey::WebAuthn { .. } => "webauthn".to_owned(),
        // SignerPubkey is #[non_exhaustive]; future variants are rendered as "unknown".
        _ => "unknown".to_owned(),
    }
}

/// Builds an ed25519 `SignerPubkey` from a G-strkey.
fn build_ed25519_signer_pubkey(g_strkey: &str) -> Result<SignerPubkey, WalletError> {
    let pk = stellar_strkey::ed25519::PublicKey::from_string(g_strkey).map_err(|e| {
        WalletError::Validation(ValidationError::AddressInvalid {
            input: format!("--signer-delegated G-strkey decode: {e}"),
        })
    })?;
    Ok(SignerPubkey::Ed25519 { pubkey: pk.0 })
}

/// Renders an envelope around an `Ok` result.
fn emit_success<T: Serialize>(result: &T, request_id: &str) -> i32 {
    let envelope = Envelope::ok_with_request_id(result, request_id.to_owned());
    render_json(&envelope);
    0
}

/// Renders an envelope around a [`WalletError`].
fn emit_error(err: &WalletError, request_id: &str) -> i32 {
    let envelope = Envelope::<()>::err_with_request_id(err, request_id.to_owned());
    render_json(&envelope);
    1
}

/// Maps an [`SaError`] into the `WalletError::SmartAccount { wire_code, message }`
/// envelope shape, threading `request_id`.
fn emit_error_sa(err: &SaError, request_id: &str) -> i32 {
    let wrapped = WalletError::SmartAccount {
        wire_code: err.wire_code(),
        message: err.to_string(),
    };
    emit_error(&wrapped, request_id)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only assertions"
    )]

    use super::*;
    use clap::Parser;
    use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
    use stellar_xdr::{ScMap, ScMapEntry, ScSymbol, ScVal, ScVec};

    // ── Per-rule signer cap at `smart-account signers add` ──────────────────────────
    //
    // The `add_run` handler pre-fetches the current rule via `get_rule`,
    // decodes the signer count from the returned ScVal, and refuses fail-CLOSED
    // when `current_signer_count + 1 > OZ_MAX_SIGNERS`.
    //
    // These tests exercise `decode_signer_count_from_scval` + the
    // `ContextRuleCapsExceeded` error construction directly (the async `add_run`
    // path would require a live RPC or a full wiremock harness).

    /// Helper: builds a minimal `ContextRule` ScVal::Map with a given number of
    /// signer IDs in the `signer_ids` field.
    ///
    /// Layout per the OZ context-rule storage: the `signer_ids`
    /// field is a `ScVal::Vec(Some(ScVec([...])))` of `ScVal::U32` values.
    fn make_rule_scval(signer_id_count: usize) -> ScVal {
        let signer_ids: Vec<ScVal> = (0..signer_id_count as u32).map(ScVal::U32).collect();
        ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol("signer_ids".try_into().unwrap())),
                val: ScVal::Vec(Some(ScVec(signer_ids.try_into().unwrap()))),
            }]
            .try_into()
            .unwrap(),
        )))
    }

    /// `signer_count = 15` → cap exceeded, error returned.
    ///
    /// Decodes the count from a real ScVal (exercising production code) then
    /// feeds `attempted = 16` to `enforce_add_signer_cap`.  The helper must
    /// return `Err(ContextRuleCapsExceeded { kind: Signer, attempted: 16, max: 15 })`.
    /// If the `>` predicate in the helper were inverted or deleted this test
    /// would fail.
    #[test]
    fn signers_add_on_full_rule_returns_cap_error() {
        let scval = make_rule_scval(15);
        let current = decode_signer_count_from_scval(&scval).unwrap();
        assert_eq!(current, 15);

        let attempted = current.saturating_add(1);
        // Call the real guard — NOT the predicate directly.
        let err = enforce_add_signer_cap(attempted)
            .expect_err("enforce_add_signer_cap must return Err for attempted=16");
        let wallet_err = WalletError::Validation(err);
        assert_eq!(wallet_err.code(), "validation.context_rule_caps_exceeded");
        let msg = wallet_err.to_string();
        assert!(
            msg.contains("cannot add Signer #16"),
            "error must name kind and attempted; got: {msg}"
        );
        assert!(
            msg.contains("current cap: 15"),
            "error must name the cap; got: {msg}"
        );
    }

    /// `signer_count = 14` → NOT at cap; error NOT triggered.
    ///
    /// Boundary condition: `attempted = 15`, which equals `OZ_MAX_SIGNERS`.
    /// `enforce_add_signer_cap` must return `Ok(())` — the guard allows exactly
    /// `OZ_MAX_SIGNERS`.  If the predicate were `>=` instead of `>` this
    /// assertion would fail.
    #[test]
    fn signers_add_on_14_signer_rule_does_not_trigger_cap() {
        let scval = make_rule_scval(14);
        let current = decode_signer_count_from_scval(&scval).unwrap();
        assert_eq!(current, 14);

        let attempted = current.saturating_add(1);
        assert_eq!(attempted, 15, "14 + 1 = 15");
        // Must be Ok — adding to a 14-signer rule yields attempted=15 which is within cap.
        enforce_add_signer_cap(attempted)
            .expect("enforce_add_signer_cap must return Ok(()) for attempted=15");
    }

    // ── list ─────────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct ListArgsHarness {
        #[command(flatten)]
        args: ListArgs,
    }

    #[test]
    fn list_args_parse_minimal() {
        let parsed = ListArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 1);
        assert_eq!(parsed.args.network, TargetNetwork::Testnet);
    }

    #[test]
    fn list_args_accepts_secondary_rpc_url() {
        let parsed = ListArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "0",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--secondary-rpc-url",
            "https://soroban-testnet.stellar.org",
        ]);
        assert_eq!(
            parsed.args.secondary_rpc_url.as_deref(),
            Some("https://soroban-testnet.stellar.org")
        );
    }

    #[test]
    fn list_args_reject_output() {
        let err = ListArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── refresh ───────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct RefreshArgsHarness {
        #[command(flatten)]
        args: RefreshArgs,
    }

    #[test]
    fn refresh_args_parse_minimal() {
        let parsed = RefreshArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 2);
    }

    #[test]
    fn refresh_args_reject_output() {
        let err = RefreshArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── add ───────────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct AddArgsHarness {
        #[command(flatten)]
        args: AddArgs,
    }

    // ── add: --signer-delegated (renamed from --new-signer; alias kept) ─────────

    #[test]
    fn add_args_parse_signer_delegated() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 1);
        assert_eq!(
            parsed.args.signer_delegated.as_deref(),
            Some(SIMULATE_SENTINEL_G)
        );
        assert!(parsed.args.signer_external.is_none());
        assert!(parsed.args.signer_webauthn.is_none());
    }

    /// `--new-signer` alias must still parse so existing scripts continue to work.
    #[test]
    fn add_args_parse_legacy_new_signer_alias() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-signer",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        // The visible_alias maps --new-signer to signer_delegated.
        assert_eq!(
            parsed.args.signer_delegated.as_deref(),
            Some(SIMULATE_SENTINEL_G)
        );
    }

    // ── add: --signer-external --signer-key-data ──────────────────────────────

    #[test]
    fn add_args_parse_signer_external() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-external",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--signer-key-data",
            "deadbeef01020304",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 2);
        assert!(parsed.args.signer_delegated.is_none());
        assert_eq!(
            parsed.args.signer_external.as_deref(),
            Some("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM")
        );
        assert_eq!(
            parsed.args.signer_key_data.as_deref(),
            Some("deadbeef01020304")
        );
        assert!(parsed.args.signer_webauthn.is_none());
    }

    /// `--signer-external` without `--signer-key-data` must be rejected.
    #[test]
    fn add_args_external_requires_key_data() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "2",
            "--signer-external",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("--signer-external without --signer-key-data should be rejected");
        // clap emits MissingRequiredArgument when the requires constraint fails.
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    // ── add: --signer-webauthn ────────────────────────────────────────────────

    #[test]
    fn add_args_parse_signer_webauthn() {
        let parsed = AddArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "3",
            "--signer-webauthn",
            "my-passkey",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.rule_id, 3);
        assert!(parsed.args.signer_delegated.is_none());
        assert!(parsed.args.signer_external.is_none());
        assert_eq!(parsed.args.signer_webauthn.as_deref(), Some("my-passkey"));
    }

    // ── add: mutual-exclusion ─────────────────────────────────────────────────

    /// Supplying both `--signer-delegated` and `--signer-external` must be rejected.
    #[test]
    fn add_args_reject_delegated_and_external_together() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-external",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--signer-key-data",
            "deadbeef",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("two signer-source flags should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// Supplying both `--signer-delegated` and `--signer-webauthn` must be rejected.
    #[test]
    fn add_args_reject_delegated_and_webauthn_together() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-webauthn",
            "my-passkey",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("two signer-source flags should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// Supplying no signer-source flag must be rejected.
    #[test]
    fn add_args_reject_no_signer_source() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ])
        .err()
        .expect("no signer-source flag should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn add_args_reject_output() {
        let err = AddArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-delegated",
            SIMULATE_SENTINEL_G,
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── remove ────────────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct RemoveArgsHarness {
        #[command(flatten)]
        args: RemoveArgs,
    }

    #[test]
    fn remove_args_parse_minimal() {
        let parsed = RemoveArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-id",
            "0",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.signer_id, 0);
    }

    #[test]
    fn remove_args_reject_output() {
        let err = RemoveArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--signer-id",
            "0",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── set-threshold ─────────────────────────────────────────────────────────

    #[derive(Parser)]
    struct SetThresholdArgsHarness {
        #[command(flatten)]
        args: SetThresholdArgs,
    }

    #[test]
    fn set_threshold_args_parse_minimal() {
        let parsed = SetThresholdArgsHarness::parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-threshold",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
        ]);
        assert_eq!(parsed.args.new_threshold, 2);
        assert_eq!(parsed.args.rule_id, 1);
    }

    #[test]
    fn set_threshold_args_reject_output() {
        let err = SetThresholdArgsHarness::try_parse_from([
            "test",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--rule-id",
            "1",
            "--new-threshold",
            "2",
            "--signer-secret-env",
            "__STELLAR_AGENT_SIGNERS_TEST_DUMMY_VAR",
            "--output",
            "json",
        ])
        .err()
        .expect("--output should be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    // ── signer_kind_label ─────────────────────────────────────────────────────

    #[test]
    fn signer_kind_label_ed25519() {
        let pk = SignerPubkey::Ed25519 { pubkey: [0u8; 32] };
        assert_eq!(signer_kind_label(&pk), "delegated_ed25519");
    }

    #[test]
    fn signer_kind_label_webauthn() {
        let pk = SignerPubkey::WebAuthn {
            credential_id_first16: [
                0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
        };
        assert_eq!(signer_kind_label(&pk), "webauthn");
    }

    // ── list_result round-trip ────────────────────────────────────────────────

    #[test]
    fn list_result_json_round_trip() {
        let result = ListResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 1,
            signer_count: 2,
            threshold: 1,
            signer_ids: vec![0, 1],
            signer_kinds: vec!["delegated_ed25519".to_owned(), "webauthn".to_owned()],
        };
        let json = serde_json::to_string(&result).unwrap();
        let rt: ListResult = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.signer_count, 2);
        assert_eq!(rt.threshold, 1);
    }

    #[test]
    fn list_result_does_not_contain_baselined_field() {
        // `baselined` is intentionally absent because it would have to be
        // hard-coded to false. Verify that the serialised JSON does not contain
        // the field so callers that expect it get a clear schema signal
        // (missing field rather than a misleading false).
        let result = ListResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 1,
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_kinds: vec!["delegated_ed25519".to_owned()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(
            !json.contains("baselined"),
            "ListResult JSON must not contain the removed baselined field"
        );
    }

    // ── signers add --signer-ed25519 tests ───────────────────────────────────

    /// A canonical all-zeros verifier C-strkey fixture (never a real verifier;
    /// only exercises the encode path).
    const ED25519_TEST_VERIFIER: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    fn add_args_ed25519(hex_pubkey: &str, verifier: Option<String>) -> AddArgs {
        AddArgs {
            account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            rule_id: 1,
            signer_delegated: None,
            signer_external: None,
            signer_key_data: None,
            signer_webauthn: None,
            signer_ed25519: Some(hex_pubkey.to_owned()),
            verifier,
            profile: None,
            signer_source: SignerSourceFlags {
                signer_secret_env: Some("__STELLAR_AGENT_SIGNERS_ED25519_DUMMY".to_owned()),
                sign_with_ledger: false,
                account_index: Some(0),
            },
            network: TargetNetwork::Testnet,
            rpc_url: TESTNET_RPC_URL.to_owned(),
            secondary_rpc_url: None,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }

    /// The typed `--signer-ed25519` attach produces the exact same on-chain
    /// `Signer::External(verifier, key_data)` ScVal as the raw
    /// `--signer-external <C> --signer-key-data <same-hex>` escape hatch, because
    /// both funnel through `build_external_signer_scval` with identical inputs.
    /// The wire shape is byte-asserted so the equivalence is not tautological.
    #[test]
    fn signer_ed25519_scval_equals_raw_external_scval() {
        use stellar_xdr::ScBytes;

        let pubkey_hex = "ab".repeat(32); // 64 hex chars → 32 bytes.

        // ed25519 branch decode: exactly 32 bytes.
        let kd_ed25519 = hex::decode(&pubkey_hex).unwrap();
        assert_eq!(kd_ed25519.len(), 32);

        // raw --signer-external branch decode: same hex, any non-empty length.
        let kd_external = hex::decode(&pubkey_hex).unwrap();

        let addr_ed25519 = parse_c_strkey_to_smart_account(ED25519_TEST_VERIFIER).unwrap();
        let addr_external = parse_c_strkey_to_smart_account(ED25519_TEST_VERIFIER).unwrap();

        let sc_ed25519 = build_external_signer_scval(addr_ed25519.clone(), &kd_ed25519).unwrap();
        let sc_external = build_external_signer_scval(addr_external, &kd_external).unwrap();

        assert_eq!(
            sc_ed25519, sc_external,
            "typed ed25519 attach must produce byte-identical ScVal to raw external"
        );

        // Byte-exact OZ External wire shape: Vec([Symbol("External"), Address, Bytes]).
        let ScVal::Vec(Some(ScVec(elems))) = &sc_ed25519 else {
            panic!("expected ScVal::Vec, got {sc_ed25519:?}");
        };
        assert_eq!(elems.len(), 3, "External encodes as a 3-element Vec");
        let ScVal::Symbol(tag) = &elems[0] else {
            panic!("expected Symbol tag, got {:?}", elems[0]);
        };
        assert_eq!(tag.to_utf8_string_lossy(), "External");
        assert!(
            matches!(&elems[1], ScVal::Address(a) if *a == addr_ed25519),
            "vec[1] must be the verifier Address"
        );
        let ScVal::Bytes(ScBytes(b)) = &elems[2] else {
            panic!("expected Bytes payload, got {:?}", elems[2]);
        };
        assert_eq!(b.as_slice(), &kd_ed25519[..], "key_data bytes must match");
    }

    /// `--signer-ed25519` with invalid hex is refused fail-closed before any
    /// network call.
    #[tokio::test]
    async fn signer_ed25519_rejects_invalid_hex() {
        let args = add_args_ed25519(&"zz".repeat(32), Some(ED25519_TEST_VERIFIER.to_owned()));
        let code = add_run(&args).await;
        assert_eq!(code, 1, "invalid hex must be refused");
    }

    /// `--signer-ed25519` that decodes to a non-32-byte length is refused
    /// fail-closed (never silently truncated or padded) before any network call.
    #[tokio::test]
    async fn signer_ed25519_rejects_wrong_length() {
        // 62 hex chars → 31 bytes.
        let args = add_args_ed25519(&"ab".repeat(31), Some(ED25519_TEST_VERIFIER.to_owned()));
        let code = add_run(&args).await;
        assert_eq!(code, 1, "a 31-byte key must be refused");
    }

    /// `--signer-ed25519` with no `--verifier` and no registered Ed25519 verifier
    /// for the network fails closed before any network call.
    #[tokio::test]
    #[serial_test::serial]
    async fn signer_ed25519_missing_verifier_and_registry_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("networks.toml");

        // SAFETY: serialised by #[serial]; no concurrent env access.
        #[allow(unsafe_code, reason = "test-only env override; #[serial] serialises")]
        unsafe {
            std::env::set_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
                &registry_path,
            );
        }

        let args = add_args_ed25519(&"ab".repeat(32), None);
        let code = add_run(&args).await;

        // SAFETY: same as set; serialised by #[serial].
        #[allow(unsafe_code, reason = "test-only env cleanup; #[serial] serialises")]
        unsafe {
            std::env::remove_var(
                stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            );
        }

        assert_eq!(
            code, 1,
            "missing verifier and empty registry must fail closed"
        );
    }
}
