//! OZ smart-account deployment via Soroban `CreateContractV2` host function.
//!
//! Implements the full deployment flow: WASM pre-flight check, optional
//! `UploadContractWasm`, `CreateContractV2` with `__constructor` args,
//! simulation + assembly + signing + submission, and post-deploy WASM-hash
//! verification.
//!
//! The deployed contract exposes
//! `pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>)`.
//!
//! # Security
//!
//! - Malformed-XDR insulation: ledger-entry XDR returned by the RPC is decoded
//!   with `LedgerEntryData::from_xdr_base64`, which returns `Err` on malformed
//!   input rather than panicking, so a malicious 200-OK cannot crash the deploy path.
//! - Post-deploy WASM-hash verification closes the RPC-substitution-via-pre-flight-lie vector.

use std::time::Duration;

// sha2 is only used inside the #[cfg(debug_assertions)] supply-chain integrity block below.
// Gating the import avoids an unused-imports warning in release builds.
#[cfg(debug_assertions)]
use sha2::{Digest, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::SaInvocationResult;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::error::{SubmissionError, WalletError};
#[cfg(any(test, feature = "test-helpers"))]
use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_network::{
    Signer, StellarRpcClient, fetch_account, signing::envelope_signing::attach_signature,
    submit_transaction_and_wait,
};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::{Transaction, TransactionBehavior};
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::{Client, LedgerEntryResult};
use stellar_strkey::Contract as ContractStrkey;
use stellar_xdr::{
    AccountId, BytesM, ContractDataDurability, ContractExecutable, ContractId, ContractIdPreimage,
    ContractIdPreimageFromAddress, CreateContractArgsV2, Hash, HostFunction, InvokeHostFunctionOp,
    LedgerEntryData, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limits, Operation,
    OperationBody, PublicKey as XdrPublicKey, ReadXdr, ScAddress, ScMap, ScSymbol, ScVal, ScVec,
    SorobanAuthorizationEntry, Uint256, VecM, WriteXdr,
};
use tracing::info;

use crate::SaError;
use crate::deployment::address::derive_smart_account_address;

#[cfg(any(test, feature = "test-helpers"))]
use crate::deployment::address::derive_interop_deployer_seed;

// ── Vendored WASM ─────────────────────────────────────────────────────────────

/// The deployable OZ smart-account multisig contract WASM.
///
/// Embedded at compile time from `vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm`.
/// SHA-256 verified by `build.rs` at compile time and at `cargo test` by
/// `tests::multisig_account_wasm_sha256_matches_provenance`.
///
/// Do NOT rename the file without re-running the build.sh step and updating PROVENANCE.md.
///
/// The embedded contract exposes
/// `pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>)`.
pub const MULTISIG_ACCOUNT_WASM: &[u8] = include_bytes!(
    "../../../../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm"
);

/// SHA-256 of [`MULTISIG_ACCOUNT_WASM`], pinned at build time.
///
/// Pinned here, in `build.rs`, and in
/// `vendor/oz-smart-account-multisig/v0.7.1/PROVENANCE.md`. The compile-time
/// integrity gate is `build.rs`; the `multisig_account_wasm_sha256_matches_provenance`
/// test in `deployment/deploy.rs::tests` and a `debug_assert!` at the entry of
/// `deploy_smart_account()` remain as defense in depth.
///
/// # Security
///
/// A supply-chain attacker who modifies the vendored WASM without also flipping this const
/// will be caught at the next `debug_assert!` runtime invocation. An attacker who modifies
/// both would produce a diff detectable by reviewer attention to the binary WASM diff and
/// the adjacent const change.
pub const MULTISIG_ACCOUNT_WASM_SHA256: &str =
    "06186e938a0ba1585a5d8a6d2ec802f3d184aaf9ec298d8c8aece50ca56cb239";

// ── Public types ──────────────────────────────────────────────────────────────

/// The deployer keypair source for `wallet accounts deploy-c`.
///
/// All three variants expose the same `Box<dyn Signer + Send + Sync>` dispatch
/// shape so the signing call site is uniform across modes. Variant-specific
/// metadata (var_name, account_index) is retained alongside for tracing and
/// audit-log purposes.
#[non_exhaustive]
pub enum DeployerKeypair {
    /// Branded deployer from `--deployer-secret-env <VAR>` (production).
    ///
    /// The signer is constructed via `stellar_agent_network::signer_from_env` at the
    /// CLI handler boundary and erased to the trait object here.
    SecretEnv {
        /// Environment-variable name that held the secret (for tracing/diagnostics).
        var_name: String,
        /// Erased signer for uniform dispatch.
        signer: Box<dyn Signer + Send + Sync>,
    },

    /// Ledger-resident deployer from `--sign-with-ledger` (production hardware-secured).
    ///
    /// The signer is a `HardwareSigningKey` erased to the trait object.
    Ledger {
        /// BIP-44 account index for the Ledger device derivation path.
        account_index: u32,
        /// Erased signer for uniform dispatch.
        signer: Box<dyn Signer + Send + Sync>,
    },

    /// In-process deployer constructed from an arbitrary signer (test / integration code).
    ///
    /// Used by `DeployerKeypair::from_signer` to wrap an in-process signer without
    /// conflating it with the `SecretEnv` variant (which semantically asserts that the
    /// secret was loaded from an environment variable). The `label` field is a
    /// caller-supplied diagnostic string (e.g. `"test-key"` or `"integration-signer"`).
    ///
    /// Using `InProcess` (not `SecretEnv`) makes the signer origin explicit and
    /// avoids `var_name` being misread as a real environment-variable name.
    InProcess {
        /// Caller-supplied diagnostic label (not a real env-var name).
        label: String,
        /// Erased signer for uniform dispatch.
        signer: Box<dyn Signer + Send + Sync>,
    },
}

impl DeployerKeypair {
    /// Wraps an arbitrary in-process signer as an `InProcess` deployer.
    ///
    /// Used in integration tests where the signing key is constructed in-process
    /// rather than loaded from an environment variable. Using `InProcess` (not
    /// `SecretEnv`) makes the origin explicit and avoids `var_name` being misread
    /// as a real environment-variable name in diagnostics.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let deployer = DeployerKeypair::from_signer("test-key".into(), signer_box);
    /// ```
    ///
    #[must_use]
    pub fn from_signer(label: String, signer: Box<dyn Signer + Send + Sync>) -> Self {
        Self::InProcess { label, signer }
    }

    /// Returns a reference to the underlying signer.
    ///
    /// `pub(crate)` so sibling deployment modules (`deploy_webauthn_verifier`) can
    /// call `attach_signature` with the signer without duplicating the match.
    pub(crate) fn signer(&self) -> &dyn Signer {
        match self {
            Self::SecretEnv { signer, .. }
            | Self::Ledger { signer, .. }
            | Self::InProcess { signer, .. } => signer.as_ref(),
        }
    }

    /// Returns the deployer's G-strkey by calling `public_key()` on the signer.
    pub(crate) async fn deployer_pubkey(&self) -> Result<String, WalletError> {
        self.signer().public_key().await.map(|pk| format!("{pk}"))
    }

    /// Returns a short description for tracing (does not carry secret material).
    fn description(&self) -> &str {
        match self {
            Self::SecretEnv { var_name, .. } => var_name.as_str(),
            Self::Ledger { .. } => "ledger",
            Self::InProcess { label, .. } => label.as_str(),
        }
    }
}

/// Constructs a `DeployerKeypair` from the well-known interop seed.
///
/// Test-only: the well-known deployer is a publicly-reproducible keypair used
/// for testnet cross-tool address matching, not a production deployer.
#[cfg(any(test, feature = "test-helpers"))]
#[must_use]
pub fn interop_deployer() -> DeployerKeypair {
    let seed = derive_interop_deployer_seed();
    let signer: Box<dyn Signer + Send + Sync> =
        Box::new(SoftwareSigningKey::new_from_zeroizing(seed));
    DeployerKeypair::from_signer("interop".to_owned(), signer)
}

/// Pre-resolved fee for the deployment transaction.
///
/// Populated by the CLI caller via `resolve_classic_fee_selection` from
/// `stellar-agent-network`; carried into `DeploymentArgs` to avoid a second
/// RPC round-trip inside the body.
#[derive(Debug, Clone)]
pub struct ResolvedFeePerOp {
    /// Fee in stroops per operation.
    pub stroops: u32,
    /// Selection label for the `selected_fee_percentile` result field.
    ///
    /// One of `"explicit"`, `"profile_default"`, or a percentile label like `"p95"`.
    pub percentile_label: String,
}

/// Arguments for `deploy_smart_account`.
pub struct DeploymentArgs {
    /// The deployer keypair source (determines signing and account-id).
    pub deployer: DeployerKeypair,
    /// The initial signer G-strkey installed by `__constructor`.
    ///
    /// Encodes the signers argument as a single-element vec.
    /// Installs exactly one `Signer::Delegated(Address)`.
    pub initial_signer: String,
    /// 32-byte salt for contract-id derivation.
    ///
    /// For WebAuthn deployment, the salt is `SHA256(credential_id)`.
    /// For ed25519-only deployment, the salt is fresh-random.
    pub salt: [u8; 32],
    /// Network passphrase (e.g. `"Test SDF Network ; September 2015"`).
    pub network_passphrase: String,
    /// Soroban RPC URL.
    pub rpc_url: String,
    /// Polling timeout for `submit_transaction_and_wait`.
    pub timeout: Duration,
    /// Pre-resolved base fee per operation in stroops.
    pub fee: ResolvedFeePerOp,
    /// If `true`, compute and return the derived address without any network access.
    pub dry_run: bool,
}

/// Result of a successful `deploy_smart_account` call.
///
/// All fields are JSON-serialisable. The `smart_account` field carries the FULL
/// C-strkey (not redacted); callers that emit to logs or table-mode output MUST
/// apply `redact_strkey_first5_last5` before printing.
#[derive(Debug, Clone, serde::Serialize)]
#[non_exhaustive]
pub struct DeploymentResult {
    /// The deployed smart-account C-strkey (full, not redacted).
    pub smart_account: String,
    /// Salt used for derivation, 64-char lowercase hex (full, not redacted in JSON).
    pub salt_hex: String,
    /// Deployer G-strkey (full, not redacted in JSON).
    pub deployer_pubkey: String,
    /// SHA-256 of the deployed WASM, 64-char lowercase hex.
    pub wasm_hash: String,
    /// Whether the WASM was uploaded by THIS invocation (`true`) or was already on-chain.
    pub wasm_uploaded: bool,
    /// Transaction hash of the WASM upload transaction, 64-char lowercase hex.
    ///
    /// `None` when the WASM was already on-chain (no upload transaction was submitted),
    /// or in dry-run mode.
    ///
    /// When `wasm_uploaded` is `true` this carries the upload tx hash; the deploy
    /// transaction hash is in `tx_hash`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_tx_hash: Option<String>,
    /// Transaction hash of the `CreateContractV2` deploy transaction, 64-char lowercase hex.
    ///
    /// `None` in dry-run mode.
    pub tx_hash: Option<String>,
    /// Confirmed ledger sequence of the deploy transaction. `None` in dry-run mode.
    pub ledger: Option<u32>,
    /// Selected fee per op in stroops.
    pub selected_fee_per_op_stroops: u32,
    /// Fee selection label (`"explicit"`, `"profile_default"`, or `"p50"`/`"p95"` etc.).
    pub selected_fee_percentile: String,
    /// Initial signer G-strkey installed by `__constructor`.
    pub initial_signer: String,
}

// ── Private helpers ───────────────────────────────────────────────────────────

// ── Hex helpers (delegated to stellar-agent-core::hex) ───────────────────────
//
// The triplicate decode_hex32 / char_to_nibble / to_hex is eliminated by delegating
// all sites to stellar_agent_core::hex. The thin wrappers below keep internal
// call sites unchanged.

/// Encodes `bytes` as lowercase hex.
///
/// Thin wrapper for naming clarity: internal callers read as
/// `to_hex(bytes)` rather than the fully-qualified path. Delegates to
/// `stellar_agent_core::hex::encode`.
///
/// `pub(crate)` so sibling deployment modules (`deploy_webauthn_verifier`) can
/// share the same hex-encode helper without duplicating it.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    stellar_agent_core::hex::encode(bytes)
}

/// Extracts `min_resource_fee` from a simulation response as u32.
///
/// stellar-rpc-client exposes `min_resource_fee` as u64 (default 0 when absent).
/// Deployment transactions fit within u32 range; a cast failure indicates an
/// unexpected RPC response.
pub(crate) fn parse_min_resource_fee_deploy(
    sim: &stellar_rpc_client::SimulateTransactionResponse,
) -> Result<u32, SaError> {
    u32::try_from(sim.min_resource_fee).map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("min_resource_fee u64->u32 cast failed: {e}"),
    })
}

/// Decodes a 64-char hex string into exactly 32 bytes.
///
/// Adapts the typed `HexDecodeError` from
/// `stellar_agent_core::hex::decode_hex32` to the `()` error type expected
/// by call sites that map errors directly to `SaError::DeploymentFailed`
/// without needing the typed error detail.
///
/// `pub(crate)` so sibling deployment modules can share this helper.
pub(crate) fn decode_hex32(hex: &str) -> Result<[u8; 32], ()> {
    stellar_agent_core::hex::decode_hex32(hex).map_err(|_| ())
}

/// Returns the CAIP-2 chain identifier for the given Stellar network passphrase.
///
/// Maps well-known passphrases to their canonical CAIP-2 forms; unknown passphrases
/// (custom networks, private testnets) fall back to `"stellar:unknown"`.
/// Used for the `chain_id` field in audit-log entries.
///
/// `pub(crate)` so sibling deployment modules (`deploy_webauthn_verifier`) share a
/// single source of truth — adding a network in one site without the other would
/// silently emit `"stellar:unknown"` for the wrong subset of audit-log entries.
pub(crate) fn caip2_chain_id_for_passphrase(passphrase: &str) -> String {
    match passphrase {
        "Test SDF Network ; September 2015" => "stellar:testnet".to_owned(),
        "Public Global Stellar Network ; September 2015" => "stellar:mainnet".to_owned(),
        "Test SDF Future Network ; October 2022" => "stellar:futurenet".to_owned(),
        _ => "stellar:unknown".to_owned(),
    }
}

/// Maps a deployment outcome to the `SaInvocationResult` wire enum.
///
/// Phase semantics:
/// - `phase ∈ {"upload", "deploy", "submit", "post_deploy_verification"}` → `OnChainRejected`:
///   the transaction reached the network layer (or post-submission check) and was refused.
///   `"upload"` failures occur after the upload transaction is submitted to the network,
///   so they are network-layer failures.
/// - All other phases (`"build"`, `"simulate"`, `"constructor"`) →
///   `PreSubmissionRefused`: client-side validation failure; no transaction was submitted.
/// - Non-`DeploymentFailed` `SaError` variants → `PreSubmissionRefused`.
/// - `Ok(_)` → `Success`.
///
/// Extracted as a named helper so the mapping is unit-tested independently of the async
/// emission path (the phase literals here must stay a subset of
/// `crate::deployment::ON_CHAIN_REJECTED_PHASES`).
pub(crate) fn map_sa_invocation_result(
    outcome: &Result<DeploymentResult, SaError>,
) -> SaInvocationResult {
    match outcome {
        Ok(_) => SaInvocationResult::Success,
        Err(SaError::DeploymentFailed {
            phase: "upload" | "deploy" | "submit" | "post_deploy_verification",
            ..
        }) => SaInvocationResult::OnChainRejected,
        Err(_) => SaInvocationResult::PreSubmissionRefused,
    }
}

/// Generates a short unique request-ID for audit-log correlation.
///
/// Returns 16 random lowercase hex chars (8 bytes from `OsRng`).
/// This is not a UUIDv4 but is sufficient for single-deployment correlation
/// without a `uuid` dep.
///
/// `pub(crate)` so sibling deployment modules (`deploy_webauthn_verifier`) can
/// share this helper for audit-log request-ID generation.
pub(crate) fn uuid_v4_hex() -> String {
    use rand_core::RngCore as _;
    let mut bytes = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut bytes);
    stellar_agent_core::hex::encode(&bytes)
}

/// Redacts a salt hex string to first-8-last-8 for tracing output.
///
/// The salt is NOT secret for pure ed25519 deployment with a random salt, but is
/// redacted pre-emptively for WebAuthn deployments where `salt = SHA256(credential_id)`
/// makes the salt privacy-sensitive.
///
/// Delegates to `stellar_agent_core::hex::redact_hex_first8_last8`.
fn redact_salt(salt_hex: &str) -> String {
    stellar_agent_core::hex::redact_hex_first8_last8(salt_hex)
}

/// Redacts a WASM hash hex string to first-8-last-8 for tracing/table output.
///
/// Exception: the `post_deploy_verification` mismatch error carries
/// first-8 of both observed and expected for operator triage.
///
/// Delegates to `stellar_agent_core::hex::redact_hex_first8_last8`.
pub(crate) fn redact_wasm_hash(wasm_hash_hex: &str) -> String {
    stellar_agent_core::hex::redact_hex_first8_last8(wasm_hash_hex)
}

/// Builds the `ScVal` encoding for `Signer::Delegated(addr)` per the OZ `#[contracttype]`
/// wire format.
///
/// The `Signer` enum is defined by the OpenZeppelin smart-account contract as a
/// `#[contracttype]` with `Delegated(Address)` and `External(Address, Bytes)`
/// variants. The `#[contracttype]` proc-macro serialises enum variants as a 2-element vec:
/// `[Symbol("VariantName"), payload_ScVal]`.
///
/// The canonical multi-signer auth payload produces this exact 2-element structure.
fn build_signer_delegated_scval(g_strkey: &str) -> Result<ScVal, SaError> {
    let pk = stellar_strkey::ed25519::PublicKey::from_string(g_strkey).map_err(|_| {
        SaError::DeploymentFailed {
            phase: "constructor",
            redacted_reason: "initial_signer is not a valid G-strkey".to_owned(),
        }
    })?;

    let sc_address =
        ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(Uint256(pk.0))));

    // Signer::Delegated(Address) serialised as ScVal::Vec([Symbol("Delegated"), ScAddress]).
    let variant_name = ScSymbol::try_from("Delegated").map_err(|e| SaError::DeploymentFailed {
        phase: "constructor",
        redacted_reason: format!("ScSymbol::try_from('Delegated') failed: {e:?}"),
    })?;

    let inner_vec: VecM<ScVal> = vec![ScVal::Symbol(variant_name), ScVal::Address(sc_address)]
        .try_into()
        .map_err(|_| SaError::DeploymentFailed {
            phase: "constructor",
            redacted_reason: "VecM conversion for Signer::Delegated failed".to_owned(),
        })?;

    Ok(ScVal::Vec(Some(ScVec(inner_vec))))
}

/// Verifies that a post-deploy `LedgerEntryResult` carries a `ContractInstance` whose
/// `ContractExecutable::Wasm(Hash)` byte-matches `expected_hash_hex`.
///
/// This helper is factored out to provide a test seam.
/// `LedgerEntryResult` has private fields and no public constructor; the only external
/// construction path is `serde_json::from_value(...)`.
///
/// `derived_smart_account` is the C-strkey of the deployed account. On hash mismatch it
/// is included in `redacted_reason` (first-5-last-5) for operator triage.
///
/// Returns `Ok(())` on byte-match. Returns
/// `Err(SaError::DeploymentFailed { phase: "post_deploy_verification", .. })` on:
/// - malformed ledger-entry XDR (decoded via `from_xdr_base64`, returns `Err`);
/// - `LedgerEntryData` discriminant other than `ContractData`;
/// - `ScVal` discriminant other than `ContractInstance`;
/// - `ContractExecutable::StellarAsset` (deployed contract is not a WASM contract);
/// - `expected_hash_hex` not parseable as 32-byte hex (programmer error);
/// - hash mismatch (the substantive substitution check; `redacted_reason` carries
///   redacted C-strkey + first-8 hex of observed AND expected for operator triage).
///
/// # Errors
///
/// Returns `DeploymentFailed` when the ledger-entry XDR is malformed. The XDR is
/// decoded with `LedgerEntryData::from_xdr_base64`, which returns `Err` rather than
/// panicking, so a malicious 200-OK carrying invalid XDR is rejected as a typed error.
pub(crate) fn verify_post_deploy_wasm_hash(
    entry: &LedgerEntryResult,
    expected_hash_hex: &str,
    derived_smart_account: &str,
) -> Result<(), SaError> {
    // Decode the XDR from the LedgerEntryResult. stellar-rpc-client exposes
    // `entry.xdr: String` (base64); decode via LedgerEntryData::from_xdr_base64.
    // A malicious 200-OK carrying invalid base64/malformed XDR returns Err (not panic).
    let entry_data = LedgerEntryData::from_xdr_base64(
        &entry.xdr,
        stellar_agent_xdr_limits::untrusted_decode_limits(entry.xdr.len()),
    )
    .map_err(|_| SaError::DeploymentFailed {
        phase: "post_deploy_verification",
        redacted_reason: "rpc_returned_malformed_ledger_entry_xdr".to_owned(),
    })?;

    let LedgerEntryData::ContractData(contract_data_entry) = entry_data else {
        return Err(SaError::DeploymentFailed {
            phase: "post_deploy_verification",
            redacted_reason: "ledger entry was not ContractData".to_owned(),
        });
    };

    let observed_wasm_hash: [u8; 32] = match &contract_data_entry.val {
        ScVal::ContractInstance(instance) => match &instance.executable {
            ContractExecutable::Wasm(Hash(bytes)) => *bytes,
            ContractExecutable::StellarAsset => {
                return Err(SaError::DeploymentFailed {
                    phase: "post_deploy_verification",
                    redacted_reason: "deployed executable was StellarAsset, not Wasm".to_owned(),
                });
            }
        },
        _ => {
            return Err(SaError::DeploymentFailed {
                phase: "post_deploy_verification",
                redacted_reason: "ledger entry val was not ContractInstance".to_owned(),
            });
        }
    };

    let expected_wasm_hash: [u8; 32] =
        decode_hex32(expected_hash_hex).map_err(|()| SaError::DeploymentFailed {
            phase: "post_deploy_verification",
            redacted_reason: "expected_hash_hex not parseable as 32-byte hex".to_owned(),
        })?;

    if observed_wasm_hash != expected_wasm_hash {
        // First-8 hex of both observed and expected are included in `redacted_reason`
        // for operator triage (distinguishes RPC-substitution from salt-collision
        // deployment scenarios). The C-strkey is redacted first-5-last-5.
        let observed_first8 = to_hex(&observed_wasm_hash[..4]);
        let expected_first8 = to_hex(&expected_wasm_hash[..4]);
        let sa_redacted =
            stellar_agent_core::observability::redact_strkey_first5_last5(derived_smart_account);
        return Err(SaError::DeploymentFailed {
            phase: "post_deploy_verification",
            redacted_reason: format!(
                "post-deploy WASM-hash mismatch on {sa_redacted}: \
                 observed first-8 hex {observed_first8}, expected first-8 hex {expected_first8}"
            ),
        });
    }

    Ok(())
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Deploys a new OZ smart-account contract instance via Soroban `CreateContractV2`.
///
/// # Flow
///
/// 1. Derive the deployer G-strkey and the pre-derived C-strkey.
/// 2. If `args.dry_run`, return immediately with the derived address (no network access).
/// 3. Check whether the WASM is already on-chain via `getLedgerEntries`.
/// 4. If WASM not on-chain: build + simulate + sign + submit an `UploadContractWasm`
///    single-op transaction; re-fetch the deployer account sequence number afterward.
/// 5. Build + simulate + sign + submit a `CreateContractV2` single-op transaction
///    with `__constructor` args.
/// 6. Post-deploy WASM-hash verification via `verify_post_deploy_wasm_hash`.
/// 7. Emit audit-log events (`SaRawInvocation` always; `SmartAccountDeployed` on success).
/// 8. Return `DeploymentResult`.
///
/// # Two-transaction design
///
/// The Soroban RPC endpoint requires exactly one `InvokeHostFunction` operation
/// per transaction. A combined `UploadContractWasm + CreateContractV2` two-op
/// transaction is rejected by the simulate call. The design uses two sequential
/// single-op transactions with a deployer-account sequence re-fetch between them.
///
/// # Audit-log emission
///
/// If `audit_writer` is `Some(writer)`, two entries MAY be emitted:
///
/// - **Always (non-dry-run):** `EventKind::SaRawInvocation { wire_code,
///   auth_digest_prefix: None, context_rule_ids_count: 0, result }` — the `wire_code`
///   is `"sa.ok"` on success or the `SaError::wire_code()` on failure.
///   `result` is `Success` on success; `PreSubmissionRefused` for errors whose `phase`
///   is one of `"build" | "simulate" | "constructor"`; `OnChainRejected` for errors
///   at `phase ∈ {"upload", "deploy", "submit", "post_deploy_verification"}`.
/// - **On success only (non-dry-run):** `EventKind::SmartAccountDeployed { smart_account,
///   deployer, wasm_hash_prefix, wasm_uploaded, tx_hash_redacted, ledger }` — all fields
///   pre-redacted. `tx_hash_redacted` carries the deploy tx hash (not the
///   upload tx hash); the upload tx hash is in `DeploymentResult::upload_tx_hash`.
///
/// Both entries share the same `request_id` for forensic correlation.
/// Dry-run invocations skip all audit emission.
/// Write failures are logged at `warn` level; they do NOT abort the return value.
///
/// # Errors
///
/// Returns `SaError::DeploymentFailed { phase, redacted_reason }` where `phase` is one of
/// the 7-value canonical set: `"build"`, `"simulate"`, `"upload"`, `"deploy"`,
/// `"constructor"`, `"submit"`, `"post_deploy_verification"`.
///
/// # Panics
///
/// Never panics in release mode. `debug_assert!` fires in debug builds if the embedded
/// WASM bytes do not match `MULTISIG_ACCOUNT_WASM_SHA256` (supply-chain integrity gate).
pub async fn deploy_smart_account(
    args: DeploymentArgs,
    audit_writer: Option<&mut AuditWriter>,
) -> Result<DeploymentResult, SaError> {
    // Capture chain_id and dry_run before args is consumed.
    let chain_id = caip2_chain_id_for_passphrase(&args.network_passphrase);
    let is_dry_run = args.dry_run;

    // Pre-derive the C-strkey before consuming args so it is available on the failure
    // audit path. Failures before this point use "unknown" as a fallback — that case
    // covers only keypair-resolve failures which have no computable C-strkey.
    //
    // Gate on audit_writer presence and non-dry-run so that Ledger deployers don't pay
    // an extra USB roundtrip when no audit entry will be emitted.
    let pre_derived_smart_account: Option<String> = if audit_writer.is_some() && !is_dry_run {
        match args.deployer.deployer_pubkey().await {
            Ok(pk) => derive_smart_account_address(&pk, &args.salt, &args.network_passphrase)
                .ok()
                .map(|c| stellar_agent_core::observability::redact_strkey_first5_last5(&c)),
            Err(_) => None,
        }
    } else {
        None
    };

    // Run the inner deployment body (no writer — audit emission is handled here).
    let outcome = deploy_smart_account_body(args).await;

    // Audit-log emission. Emits on both success and error paths.
    //
    // SaRawInvocation: always emitted with the operation wire_code and outcome.
    // SmartAccountDeployed: emitted on success AND non-dry-run only.
    //
    // Dry-run is developer-only; no audit emission on dry-run paths.
    // Both entries share one request_id for forensic correlation.
    //
    // A write failure is logged at warn level and does NOT affect the return value —
    // on success the deployment is already confirmed on-chain; on error the error is
    // propagated regardless of audit write success.
    if let Some(writer) = audit_writer {
        // Skip audit emission on dry-run paths.
        if is_dry_run {
            return outcome;
        }

        // Single request_id shared across both entries from this operation.
        let request_id = uuid_v4_hex();

        // Delegate phase-to-result mapping to the named helper.
        // See `map_sa_invocation_result` doc for the 7-phase rule.
        let sa_result = map_sa_invocation_result(&outcome);
        let (wire_code, smart_account_for_audit) = match &outcome {
            Ok(result) => (
                "sa.ok",
                stellar_agent_core::observability::redact_strkey_first5_last5(
                    &result.smart_account,
                ),
            ),
            Err(e) => {
                // Use pre-derived C-strkey when available.
                let sa = pre_derived_smart_account
                    .clone()
                    .unwrap_or_else(|| "unknown".to_owned());
                (e.wire_code(), sa)
            }
        };

        let ra_entry = AuditEntry::new_sa_raw_invocation(
            smart_account_for_audit,
            wire_code,
            None, // auth_digest_prefix: None (deployer's source-account sig)
            0,    // context_rule_ids_count: 0 (no context rules at deploy time)
            sa_result,
            &chain_id,
            &request_id,
        );
        if let Err(e) = writer.write_entry(ra_entry) {
            tracing::warn!(error = %e, "deploy_smart_account: SaRawInvocation audit write failed");
        }

        // SmartAccountDeployed: emitted on success only (dry-run already guarded above).
        if let Ok(result) = &outcome {
            // Delegate wasm_hash_prefix to the existing redact_wasm_hash helper.
            let wasm_hash_prefix = redact_wasm_hash(&result.wasm_hash);
            // The dry-run guard at the top of this block ensures tx_hash is Some on the
            // non-dry-run success path. Fail fast on programming-invariant violation.
            #[allow(
                clippy::expect_used,
                reason = "programming invariant: non-dry-run success path always \
                          has tx_hash from deploy_smart_account_body"
            )]
            let tx_hash_redacted = stellar_agent_network::redact_tx_hash(
                result
                    .tx_hash
                    .as_deref()
                    .expect("invariant: non-dry-run success path always has tx_hash from submit"),
            );
            // ledger is always Some(submission.ledger) on the success path; fail fast on
            // invariant violation.
            #[allow(
                clippy::expect_used,
                reason = "programming invariant: non-dry-run success path always \
                          has ledger from deploy_smart_account_body"
            )]
            let ledger = result
                .ledger
                .expect("invariant: non-dry-run success path always has ledger from submit");
            let deployed_entry = AuditEntry::new_smart_account_deployed(
                stellar_agent_core::observability::redact_strkey_first5_last5(
                    &result.smart_account,
                ),
                stellar_agent_core::observability::redact_strkey_first5_last5(
                    &result.deployer_pubkey,
                ),
                wasm_hash_prefix,
                result.wasm_uploaded,
                tx_hash_redacted,
                ledger,
                &chain_id,
                // Same request_id as the SaRawInvocation entry above.
                &request_id,
            );
            if let Err(e) = writer.write_entry(deployed_entry) {
                tracing::warn!(
                    error = %e,
                    "deploy_smart_account: SmartAccountDeployed audit write failed (deployment already confirmed)"
                );
            }
        }
    }

    outcome
}

/// Core deployment body — no audit-log writes.
///
/// All audit-log emission is handled by the public `deploy_smart_account` wrapper
/// after this function returns, so the `audit_writer` borrow is not held during
/// the async RPC calls. This avoids lifetime conflicts between the `&mut AuditWriter`
/// reference and the `await` points inside the body.
async fn deploy_smart_account_body(args: DeploymentArgs) -> Result<DeploymentResult, SaError> {
    // Re-verify embedded WASM hash on every invocation in debug builds.
    // This catches a tampered vendor/ file that was not also updated in tests.
    #[cfg(debug_assertions)]
    {
        let mut hasher = Sha256::new();
        hasher.update(MULTISIG_ACCOUNT_WASM);
        let observed = to_hex(&hasher.finalize());
        debug_assert_eq!(
            observed, MULTISIG_ACCOUNT_WASM_SHA256,
            "MULTISIG_ACCOUNT_WASM bytes do not match MULTISIG_ACCOUNT_WASM_SHA256 const; \
             local supply-chain integrity is compromised. Re-build via build.sh."
        );
    }

    // Parse the expected WASM hash bytes from the pinned const once.
    let wasm_hash_bytes: [u8; 32] =
        decode_hex32(MULTISIG_ACCOUNT_WASM_SHA256).map_err(|()| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: "MULTISIG_ACCOUNT_WASM_SHA256 const is not valid 64-char hex \
                             (programmer error)"
                .to_owned(),
        })?;
    let wasm_hash_hex = MULTISIG_ACCOUNT_WASM_SHA256.to_owned();

    // Step 1: resolve the deployer G-strkey.
    let deployer_pubkey =
        args.deployer
            .deployer_pubkey()
            .await
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("failed to obtain deployer pubkey: {e}"),
            })?;

    // Step 2: derive the expected C-strkey (pure, no network).
    let derived_smart_account =
        derive_smart_account_address(&deployer_pubkey, &args.salt, &args.network_passphrase)
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("address derivation failed: {e}"),
            })?;

    let salt_hex = to_hex(&args.salt);

    // Dry-run: return without any network access.
    if args.dry_run {
        return Ok(DeploymentResult {
            smart_account: derived_smart_account,
            salt_hex,
            deployer_pubkey,
            wasm_hash: wasm_hash_hex,
            wasm_uploaded: false,
            upload_tx_hash: None,
            tx_hash: None,
            ledger: None,
            selected_fee_per_op_stroops: args.fee.stroops,
            selected_fee_percentile: args.fee.percentile_label,
            initial_signer: args.initial_signer,
        });
    }

    // Step 3: construct the RPC clients.
    // The stellar-rpc-client Client is used for simulate + getLedgerEntries.
    // The StellarRpcClient is used for fetch_account and submit_transaction_and_wait.
    let rpc_server = Client::new(&args.rpc_url).map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("rpc-server construction failed: {e}"),
    })?;

    // Construct the wallet-substrate RPC client.
    // Routes deployer-account sequence fetch through stellar-agent-network::fetch_account.
    // Reused for submit_transaction_and_wait (avoids a second construction).
    let network_client =
        StellarRpcClient::new(&args.rpc_url).map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("StellarRpcClient construction failed: {e}"),
        })?;

    // Step 4: fetch the deployer's account-id sequence via the wallet substrate.
    let deployer_view = fetch_account(&network_client, &deployer_pubkey, &[])
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("deployer account fetch failed: {e}"),
        })?;

    // Construct the baselib Account from the returned sequence.
    let mut deployer_account =
        BaselibAccount::new(&deployer_pubkey, &deployer_view.sequence_number.to_string()).map_err(
            |e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("BaselibAccount::new failed: {e:?}"),
            },
        )?;

    // Step 5: check whether the WASM is already on-chain.
    let wasm_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash_bytes),
    });

    let wasm_query_resp = rpc_server
        .get_ledger_entries(&[wasm_key])
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("getLedgerEntries (wasm pre-flight) failed: {e}"),
        })?;

    // Explicit match: `entries` is `None` when the RPC response contains no `entries` field,
    // which means the WASM is not on-chain (same semantic as an empty vec).
    let wasm_already_on_chain = match wasm_query_resp.entries.as_ref() {
        Some(entries) => !entries.is_empty(),
        None => false,
    };

    if wasm_already_on_chain {
        info!(
            wasm_hash = %redact_wasm_hash(&wasm_hash_hex),
            "deploy_smart_account: WASM already on-chain; skipping upload"
        );
    } else {
        info!(
            wasm_hash = %redact_wasm_hash(&wasm_hash_hex),
            "deploy_smart_account: WASM not on-chain; will upload in deployment tx"
        );
    }

    let base_fee = args.fee.stroops;

    // Step 6a: Upload transaction (single-op, conditional).
    //
    // Each transaction carries exactly one `InvokeHostFunction` operation.
    // A combined `UploadContractWasm + CreateContractV2` transaction is rejected
    // by the network. The upload and deploy are therefore submitted as two
    // sequential single-op transactions.
    //
    // All XDR types use stellar_xdr to match the crate-wide xdr-27 stack.
    let upload_tx_hash: Option<String> = if wasm_already_on_chain {
        None
    } else {
        // Build the upload operation.
        let wasm_bytes: BytesM =
            MULTISIG_ACCOUNT_WASM
                .to_vec()
                .try_into()
                .map_err(|_| SaError::DeploymentFailed {
                    phase: "build",
                    redacted_reason: "WASM exceeds BytesM maximum length".to_owned(),
                })?;
        let upload_op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::UploadContractWasm(wasm_bytes),
                auth: VecM::default(),
            }),
        };

        // Build the upload transaction (single op).
        let mut upload_tx_builder =
            TransactionBuilder::new(&mut deployer_account, &args.network_passphrase, None);
        upload_tx_builder.fee(base_fee);
        upload_tx_builder.add_operation(upload_op);
        let upload_tx: Transaction = upload_tx_builder.build_for_simulation();

        // Simulate the upload transaction.
        let upload_envelope = upload_tx
            .to_envelope()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("upload to_envelope (pre-sim) failed: {e}"),
            })?;
        let upload_sim = rpc_server
            .simulate_transaction_envelope(&upload_envelope, None)
            .await
            .map_err(|e| SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("upload simulate_transaction_envelope failed: {e}"),
            })?;

        // Panic-insulation pre-check.
        if let Some(sim_error) = &upload_sim.error {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("upload simulation returned error: {sim_error}"),
            });
        }
        if upload_sim.min_resource_fee == 0 || upload_sim.transaction_data.is_empty() {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: "upload rpc returned response without simulation result \
                    (no error field and no min_resource_fee/transaction_data)"
                    .to_owned(),
            });
        }

        // Assemble the prepared upload transaction from simulation results.
        let upload_resource_fee = parse_min_resource_fee_deploy(&upload_sim)?;
        let mut prepared_upload = upload_tx.clone();
        prepared_upload.fee = prepared_upload.fee.saturating_add(upload_resource_fee);
        prepared_upload.soroban_data =
            Some(
                upload_sim
                    .transaction_data()
                    .map_err(|e| SaError::DeploymentFailed {
                        phase: "simulate",
                        redacted_reason: format!("upload transaction_data decode failed: {e}"),
                    })?,
            );

        // Sign the upload transaction.
        let signed_upload_xdr = attach_signature(
            &prepared_upload
                .to_envelope()
                .map_err(|e| SaError::DeploymentFailed {
                    phase: "build",
                    redacted_reason: format!("upload to_envelope failed: {e}"),
                })?
                .to_xdr_base64(Limits::none())
                .map_err(|e| SaError::DeploymentFailed {
                    phase: "build",
                    redacted_reason: format!("upload XDR encode failed: {e}"),
                })?,
            args.deployer.signer(),
            &args.network_passphrase,
        )
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("upload signing failed: {e}"),
        })?;

        info!(
            deployer = %stellar_agent_core::observability::redact_strkey_first5_last5(&deployer_pubkey),
            wasm_hash = %redact_wasm_hash(&wasm_hash_hex),
            "deploy_smart_account: submitting WASM upload transaction"
        );

        // Submit the upload transaction and wait for confirmation.
        let upload_submission = submit_transaction_and_wait(
            &network_client,
            &signed_upload_xdr,
            args.timeout,
            &args.network_passphrase,
            None,
        )
        .await
        .map_err(|e| {
            // Map upload-tx envelope rejections to phase "submit". The match is
            // intentionally asymmetric with the deploy-side classifier below: the
            // upload-side retains a SequenceNumberStale arm defensively, while the
            // deploy-side omits it because txBadSeq strings flow through
            // TxMalformed::detail in submit::map_send_error.
            let reason = e.to_string();
            let phase = match &e {
                WalletError::Submission(
                    SubmissionError::TxMalformed { .. } | SubmissionError::SequenceNumberStale,
                ) => "submit",
                _ => "upload",
            };
            SaError::DeploymentFailed {
                phase,
                redacted_reason: format!("upload submission failed: {reason}"),
            }
        })?;

        info!(
            upload_tx_hash = %stellar_agent_network::redact_tx_hash(&upload_submission.tx_hash),
            ledger = upload_submission.ledger,
            "deploy_smart_account: WASM uploaded successfully"
        );

        // Re-fetch the deployer account sequence number after the upload transaction
        // has been confirmed. The sequence number is consumed by the upload transaction
        // and must be refreshed before building the deploy transaction.
        let deployer_view_post_upload = fetch_account(&network_client, &deployer_pubkey, &[])
            .await
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("deployer account re-fetch after upload failed: {e}"),
            })?;
        deployer_account = BaselibAccount::new(
            &deployer_pubkey,
            &deployer_view_post_upload.sequence_number.to_string(),
        )
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("BaselibAccount::new (post-upload) failed: {e:?}"),
        })?;

        Some(upload_submission.tx_hash)
    };

    // Step 6b: Build the CreateContractV2 deploy transaction (single op).
    // Build the deployer ScAddress for the contract-id preimage.
    let deployer_pk =
        stellar_strkey::ed25519::PublicKey::from_string(&deployer_pubkey).map_err(|_| {
            SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: "deployer G-strkey parse failed after fetch_account succeeded \
                                  (unexpected internal inconsistency)"
                    .to_owned(),
            }
        })?;

    let deployer_sc_address = ScAddress::Account(AccountId(XdrPublicKey::PublicKeyTypeEd25519(
        Uint256(deployer_pk.0),
    )));

    // Build the constructor arguments ScVec.
    // The signers argument is a single-element vec; the policies argument is an empty map.
    let signer_scval = build_signer_delegated_scval(&args.initial_signer)?;

    // signers: Vec<Signer> — wrap the single signer in a ScVec.
    let signers_vec: VecM<ScVal> =
        vec![signer_scval]
            .try_into()
            .map_err(|_| SaError::DeploymentFailed {
                phase: "constructor",
                redacted_reason: "VecM conversion for signers arg failed".to_owned(),
            })?;

    // policies: Map<Address, Val> — empty map.
    let constructor_args: VecM<ScVal> = vec![
        ScVal::Vec(Some(ScVec(signers_vec))),
        ScVal::Map(Some(ScMap::default())),
    ]
    .try_into()
    .map_err(|_| SaError::DeploymentFailed {
        phase: "constructor",
        redacted_reason: "VecM conversion for constructor_args failed".to_owned(),
    })?;

    // Build the CreateContractV2 host function.
    let create_contract_fn = HostFunction::CreateContractV2(CreateContractArgsV2 {
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: deployer_sc_address,
            salt: Uint256(args.salt),
        }),
        executable: ContractExecutable::Wasm(Hash(wasm_hash_bytes)),
        constructor_args,
    });

    let create_op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: create_contract_fn,
            auth: VecM::default(),
        }),
    };

    // Assemble the deploy transaction (single op).
    let mut tx_builder = TransactionBuilder::new(
        &mut deployer_account,
        &args.network_passphrase,
        None, // no time bounds
    );
    tx_builder.fee(base_fee);
    tx_builder.add_operation(create_op);
    let tx: Transaction = tx_builder.build_for_simulation();

    // Step 7: simulate + assemble the deploy transaction (panic-insulation pre-check).
    let deploy_envelope_pre = tx.to_envelope().map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("deploy to_envelope (pre-sim) failed: {e}"),
    })?;
    let sim_response = rpc_server
        .simulate_transaction_envelope(&deploy_envelope_pre, None)
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("deploy simulate_transaction_envelope failed: {e}"),
        })?;

    // Panic-insulation pre-check.
    // Check sim_response.error FIRST: when the RPC returns a simulation error (low fee,
    // resource limit exceeded, contract panic, etc.), `error` is Some and
    // `min_resource_fee`/`transaction_data` are absent.
    if let Some(sim_error) = &sim_response.error {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("deploy simulation returned error: {sim_error}"),
        });
    }
    if sim_response.min_resource_fee == 0 || sim_response.transaction_data.is_empty() {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "deploy rpc returned response without simulation result \
                (no error field and no min_resource_fee/transaction_data)"
                .to_owned(),
        });
    }

    // Assemble the prepared deploy transaction from simulation results.
    let deploy_resource_fee = parse_min_resource_fee_deploy(&sim_response)?;
    // CreateContractV2 from the deployer address requires the SourceAccount-credential
    // authorization entry the simulation computes. Attach the simulated auth entries to
    // the single InvokeHostFunction operation before signing; without them the on-chain
    // host-function execution is unauthorized and traps.
    let deploy_sim_auth: VecM<SorobanAuthorizationEntry> = sim_response
        .results()
        .ok()
        .and_then(|rs| rs.into_iter().next())
        .map(|r| r.auth)
        .unwrap_or_default()
        .try_into()
        .map_err(|e| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: format!("deploy auth VecM encode failed: {e:?}"),
        })?;
    let mut prepared_tx = tx.clone();
    prepared_tx.fee = prepared_tx.fee.saturating_add(deploy_resource_fee);
    prepared_tx.soroban_data =
        Some(
            sim_response
                .transaction_data()
                .map_err(|e| SaError::DeploymentFailed {
                    phase: "simulate",
                    redacted_reason: format!("deploy transaction_data decode failed: {e}"),
                })?,
        );
    if let Some(op) = prepared_tx
        .operations
        .as_mut()
        .and_then(|ops| ops.get_mut(0))
        && let OperationBody::InvokeHostFunction(ihf) = &mut op.body
    {
        ihf.auth = deploy_sim_auth;
    }

    // Step 8: sign the deploy transaction with the deployer keypair.
    let signed_xdr = attach_signature(
        &prepared_tx
            .to_envelope()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("deploy to_envelope failed: {e}"),
            })?
            .to_xdr_base64(Limits::none())
            .map_err(|e| SaError::DeploymentFailed {
                phase: "build",
                redacted_reason: format!("deploy XDR encode failed: {e}"),
            })?,
        args.deployer.signer(),
        &args.network_passphrase,
    )
    .await
    .map_err(|e| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason: format!("deploy signing failed: {e}"),
    })?;

    info!(
        deployer = %stellar_agent_core::observability::redact_strkey_first5_last5(&deployer_pubkey),
        deployer_mode = args.deployer.description(),
        salt = %redact_salt(&salt_hex),
        wasm_hash = %redact_wasm_hash(&wasm_hash_hex),
        "deploy_smart_account: submitting deploy transaction"
    );

    // Step 9: submit + poll the deploy transaction via the existing primitive.
    let submission = submit_transaction_and_wait(
        &network_client,
        &signed_xdr,
        args.timeout,
        &args.network_passphrase,
        None,
    )
    .await
    .map_err(|e| {
        // Map RPC envelope-rejection failures to phase "submit". `TxMalformed`
        // wraps the RPC client's `txMalformed`-class responses, including the
        // `TxBadSeq` and `TxBadAuth` Debug-formatted result strings packed into
        // `TxMalformed::detail`. On-chain post-submission failures
        // (`LedgerError::OpFailed`, including `op_bad_auth`) fall through to phase
        // "deploy" because the transaction reached the network and was executed.
        let reason = e.to_string();
        let phase = match &e {
            // The direct stale-sequence submission variant is wrapped in
            // TxMalformed::detail by submit::map_send_error today; if a future
            // direct-mapping path is added, extend this arm to match.
            WalletError::Submission(SubmissionError::TxMalformed { .. }) => "submit",
            _ => "deploy",
        };
        SaError::DeploymentFailed {
            phase,
            redacted_reason: format!("deploy submission failed: {reason}"),
        }
    })?;

    // Step 10: post-deploy WASM-hash verification.
    // Build the LedgerKey for the contract-instance entry.
    let c_strkey_decoded = ContractStrkey::from_string(&derived_smart_account).map_err(|e| {
        SaError::DeploymentFailed {
            phase: "post_deploy_verification",
            redacted_reason: format!("c-strkey decode failed: {e}"),
        }
    })?;

    let contract_sc_address = ScAddress::Contract(ContractId(Hash(c_strkey_decoded.0)));
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract_sc_address,
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });

    let post_deploy_resp = rpc_server
        .get_ledger_entries(&[instance_key])
        .await
        .map_err(|e| SaError::DeploymentFailed {
            phase: "post_deploy_verification",
            redacted_reason: format!("get_ledger_entries (post-deploy) failed: {e}"),
        })?;

    // `entries` is `None` when `getLedgerEntries` returns a response with no entries field;
    // the `ok_or_else` below handles the no-entry case with a typed error.
    let entries = post_deploy_resp.entries.unwrap_or_default();
    let entry = entries.first().ok_or_else(|| SaError::DeploymentFailed {
        phase: "post_deploy_verification",
        redacted_reason: format!(
            "rpc returned no contract-instance entry for newly-deployed account {}",
            stellar_agent_core::observability::redact_strkey_first5_last5(&derived_smart_account)
        ),
    })?;

    // Delegate panic-insulation + destructuring + hash-comparison to the helper.
    verify_post_deploy_wasm_hash(entry, MULTISIG_ACCOUNT_WASM_SHA256, &derived_smart_account)?;

    // Step 11: log and return result.
    // Audit-log emission is handled by the public `deploy_smart_account` wrapper.
    info!(
        smart_account = %stellar_agent_core::observability::redact_strkey_first5_last5(&derived_smart_account),
        deployer = %stellar_agent_core::observability::redact_strkey_first5_last5(&deployer_pubkey),
        tx_hash = %stellar_agent_network::redact_tx_hash(&submission.tx_hash),
        ledger = submission.ledger,
        wasm_hash = %redact_wasm_hash(&wasm_hash_hex),
        wasm_uploaded = !wasm_already_on_chain,
        "deploy_smart_account: smart-account deployed successfully"
    );

    Ok(DeploymentResult {
        smart_account: derived_smart_account,
        salt_hex,
        deployer_pubkey,
        wasm_hash: wasm_hash_hex,
        wasm_uploaded: !wasm_already_on_chain,
        upload_tx_hash,
        tx_hash: Some(submission.tx_hash),
        ledger: Some(submission.ledger),
        selected_fee_per_op_stroops: args.fee.stroops,
        selected_fee_percentile: args.fee.percentile_label,
        initial_signer: args.initial_signer,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    // All XDR types in tests MUST come from `stellar_xdr` so that the encoded
    // bytes are decodable by `LedgerEntryData::from_xdr_base64(...)` from the same
    // crate version used at runtime, ensuring the post-deploy verification gate
    // operates on consistent XDR encoding.
    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use stellar_xdr::{
        ContractDataDurability, ContractDataEntry, ExtensionPoint,
        LedgerEntryData as SorobanLedgerEntryData,
    };

    use super::*;

    /// Asserts that `SHA256(MULTISIG_ACCOUNT_WASM)` matches the pinned `MULTISIG_ACCOUNT_WASM_SHA256`.
    ///
    /// This is the runtime supply-chain integrity gate equivalent to the `wasm_sha256_matches_provenance`
    /// test in `bindings.rs`. Verifies the vendored WASM bytes match both the const and PROVENANCE.md.
    #[test]
    fn multisig_account_wasm_sha256_matches_provenance() {
        let mut hasher = Sha256::new();
        hasher.update(MULTISIG_ACCOUNT_WASM);
        let actual_hex = to_hex(&hasher.finalize());
        assert_eq!(
            actual_hex, MULTISIG_ACCOUNT_WASM_SHA256,
            "SHA-256 of embedded MULTISIG_ACCOUNT_WASM must match MULTISIG_ACCOUNT_WASM_SHA256 const"
        );
    }

    /// Asserts the embedded WASM starts with the WASM binary magic bytes `\0asm`.
    #[test]
    fn multisig_account_wasm_has_correct_magic_bytes() {
        assert_eq!(
            &MULTISIG_ACCOUNT_WASM[..4],
            b"\0asm",
            "MULTISIG_ACCOUNT_WASM must start with WASM magic bytes"
        );
    }

    /// Regression gate: a `LedgerEntryResult` with malformed `xdr` field does NOT panic the
    /// wallet; the typed-error path is taken via `from_xdr_base64` returning `Err`
    /// inside `verify_post_deploy_wasm_hash`.
    ///
    /// Architecture: `LedgerEntryResult` has private fields and no public constructor; the only
    /// external construction path is `serde_json::from_value(...)`.
    ///
    /// NOTE: the `extXdr` field is omitted from this JSON shape.
    /// `LedgerEntryResult.ext_xdr` is typed `Option<String>` WITHOUT a `#[serde(default)]`
    /// attribute. serde-derive's impl special-cases `Option<T>` to deserialize a missing field as
    /// `None` automatically, so the omission is sound — do NOT add `"extXdr": null` defensively
    /// (it would conflate "absent" with "explicitly null" if the upstream type ever switches to a
    /// non-Option representation).
    #[test]
    fn post_deploy_verification_aborts_on_malformed_ledger_entry_xdr() {
        let synthetic: LedgerEntryResult = serde_json::from_value(json!({
            "key": "AAAABgAAAAAA",
            "xdr": "INVALID-MALFORMED-XDR-BASE64",
            "lastModifiedLedgerSeq": 1,
            "liveUntilLedgerSeq": 1
        }))
        .expect("constructed via Deserialize impl");

        let result = verify_post_deploy_wasm_hash(
            &synthetic,
            "5603378c6039b5ccd4038d04a261d5f08467d5f68046e863b40ca85e4d779322",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        );

        assert!(
            matches!(
                result,
                Err(SaError::DeploymentFailed {
                    phase: "post_deploy_verification",
                    ref redacted_reason
                }) if redacted_reason == "rpc_returned_malformed_ledger_entry_xdr"
            ),
            "expected post_deploy_verification error for malformed xdr; got: {result:?}"
        );
    }

    /// Regression gate: a `LedgerEntryResult` with a valid XDR field but a non-matching WASM hash
    /// causes `verify_post_deploy_wasm_hash` to return a typed mismatch error carrying first-8 hex
    /// prefixes of both observed and expected.
    #[test]
    fn post_deploy_verification_aborts_on_wasm_hash_mismatch() {
        // Build a synthetic ContractData entry with a non-matching wasm hash.
        // All types from stellar_xdr so the encoded bytes are decodable by
        // LedgerEntryData::from_xdr_base64 at runtime.
        let bogus_hash = [0u8; 32];
        use stellar_xdr::ScContractInstance as SorobanScContractInstance;
        let instance = SorobanScContractInstance {
            executable: ContractExecutable::Wasm(Hash(bogus_hash)),
            storage: Some(ScMap::default()),
        };
        let contract_data = ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(instance),
        };
        let led = SorobanLedgerEntryData::ContractData(contract_data);
        let xdr_b64 = led.to_xdr_base64(Limits::none()).unwrap();

        let synthetic: LedgerEntryResult = serde_json::from_value(json!({
            "key": "AAAABgAAAAAA",
            "xdr": xdr_b64,
            "lastModifiedLedgerSeq": 1,
            "liveUntilLedgerSeq": 1
        }))
        .expect("constructed via Deserialize impl");

        // Use the all-zeros C-strkey as the derived_smart_account for this test.
        // Its first-5-last-5 redacted form is "CAAAA...AAAD2" (from the all-zeros
        // contract ID, which encodes to "CAAAA...AAAD2KM").
        let test_c_strkey = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

        let result = verify_post_deploy_wasm_hash(
            &synthetic,
            // A different expected hash (MULTISIG_ACCOUNT_WASM_SHA256 starts with "0618...").
            "5603378c6039b5ccd4038d04a261d5f08467d5f68046e863b40ca85e4d779322",
            test_c_strkey,
        );

        let Err(SaError::DeploymentFailed {
            phase,
            redacted_reason,
        }) = result
        else {
            panic!("expected mismatch error; got: {result:?}");
        };
        assert_eq!(phase, "post_deploy_verification");
        assert!(
            redacted_reason.starts_with("post-deploy WASM-hash mismatch on "),
            "redacted_reason should start with mismatch literal: {redacted_reason}"
        );
        // The redacted C-strkey should be present.
        let redacted_sa =
            stellar_agent_core::observability::redact_strkey_first5_last5(test_c_strkey);
        assert!(
            redacted_reason.contains(&redacted_sa),
            "redacted_reason should carry redacted C-strkey '{redacted_sa}': {redacted_reason}"
        );
        // first-8 hex of [0u8; 32]
        assert!(
            redacted_reason.contains("00000000"),
            "redacted_reason should carry observed first-8 hex: {redacted_reason}"
        );
        // first-8 hex of the expected hash (5603378c...)
        assert!(
            redacted_reason.contains("5603378c"),
            "redacted_reason should carry expected first-8 hex: {redacted_reason}"
        );
    }

    // ── map_sa_invocation_result unit tests ──
    //
    // One test per canonical phase value + the success arm.
    // Each constructs the appropriate `Result`, calls the helper, and asserts the
    // expected `SaInvocationResult` variant. These tests are compile-linked to the
    // phase mapping via `ON_CHAIN_REJECTED_PHASES` (defined in mod.rs).

    fn deployment_err(phase: &'static str) -> Result<DeploymentResult, SaError> {
        Err(SaError::DeploymentFailed {
            phase,
            redacted_reason: "test".to_owned(),
        })
    }

    fn deployment_ok() -> Result<DeploymentResult, SaError> {
        Ok(DeploymentResult {
            smart_account: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM".to_owned(),
            salt_hex: "00".repeat(32),
            deployer_pubkey: "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N".to_owned(),
            wasm_hash: MULTISIG_ACCOUNT_WASM_SHA256.to_owned(),
            wasm_uploaded: false,
            upload_tx_hash: None,
            tx_hash: Some("aa".repeat(32)),
            ledger: Some(100_000),
            selected_fee_per_op_stroops: 100,
            selected_fee_percentile: "profile_default".to_owned(),
            initial_signer: "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N".to_owned(),
        })
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_build_to_pre_submission_refused() {
        assert!(matches!(
            map_sa_invocation_result(&deployment_err("build")),
            SaInvocationResult::PreSubmissionRefused
        ));
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_simulate_to_pre_submission_refused() {
        assert!(matches!(
            map_sa_invocation_result(&deployment_err("simulate")),
            SaInvocationResult::PreSubmissionRefused
        ));
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_upload_to_on_chain_rejected() {
        // The upload transaction is submitted to the network before this phase can fail.
        // An upload-phase failure is therefore `OnChainRejected`, not `PreSubmissionRefused`.
        assert!(matches!(
            map_sa_invocation_result(&deployment_err("upload")),
            SaInvocationResult::OnChainRejected
        ));
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_constructor_to_pre_submission_refused() {
        assert!(matches!(
            map_sa_invocation_result(&deployment_err("constructor")),
            SaInvocationResult::PreSubmissionRefused
        ));
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_deploy_to_on_chain_rejected() {
        assert!(matches!(
            map_sa_invocation_result(&deployment_err("deploy")),
            SaInvocationResult::OnChainRejected
        ));
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_submit_to_on_chain_rejected() {
        assert!(matches!(
            map_sa_invocation_result(&deployment_err("submit")),
            SaInvocationResult::OnChainRejected
        ));
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_post_deploy_verification_to_on_chain_rejected() {
        assert!(matches!(
            map_sa_invocation_result(&deployment_err("post_deploy_verification")),
            SaInvocationResult::OnChainRejected
        ));
    }

    #[test]
    fn phase_to_sa_invocation_result_maps_success_to_success() {
        assert!(matches!(
            map_sa_invocation_result(&deployment_ok()),
            SaInvocationResult::Success
        ));
    }

    /// Every phase in `ON_CHAIN_REJECTED_PHASES` must also appear in `ALL_EMITTED_PHASES`.
    /// Catches a drift where a new on-chain-rejected phase is added to the mapping but not
    /// registered in the closed-phase inventory.
    #[test]
    fn on_chain_rejected_phases_subset_of_all_emitted_phases() {
        use crate::deployment::{ALL_EMITTED_PHASES, ON_CHAIN_REJECTED_PHASES};
        for phase in ON_CHAIN_REJECTED_PHASES {
            assert!(
                ALL_EMITTED_PHASES.contains(phase),
                "ON_CHAIN_REJECTED_PHASES entry '{phase}' is not in ALL_EMITTED_PHASES"
            );
        }
    }
}
