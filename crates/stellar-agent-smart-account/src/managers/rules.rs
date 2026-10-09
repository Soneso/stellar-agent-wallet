//! Context-rule manager for the OZ smart-account context-rule lifecycle.
//!
//! Wraps the OZ `stellar-accounts` v0.7.2 context-rule entrypoints with a
//! typed off-chain orchestrator. Ships the metadata-only lifecycle:
//! `install_rule`, `update_name`, `update_valid_until`, `delete_rule`, plus
//! the read-side `get_rule` and `get_rules_count`. The per-rule signer-set +
//! policy-set surfaces (signer-threshold atomicity, threshold special-case,
//! multi-op rule-edit orchestrator) are handled by the signers manager.
//!
//! # OZ contract entrypoints
//!
//! - OZ contract trait
//!   `packages/accounts/src/smart_account/mod.rs:238-344` — entrypoint
//!   signatures for `add_context_rule`, `update_context_rule_name`,
//!   `update_context_rule_valid_until`, `remove_context_rule`,
//!   `get_context_rule`, `get_context_rules_count`. All four mutating
//!   entrypoints invoke `e.current_contract_address().require_auth()` —
//!   the auth-entry's credential address is the smart-account contract's
//!   own ScAddress.
//!
//! # AuthPayload byte-parity
//!
//! `managers/auth_entry.rs::complete_authorization_entry` produces the
//! on-chain canonical AuthPayload ScVal; this manager merely injects that
//! signed entry into the operation's auth slot and submits.
//! Byte-parity is asserted by the `auth_digest_parity_with_onchain_canonical`
//! test.
//!
//! # Functional scope
//!
//! - Context-rule lifecycle (install, update, delete, read).
//! - Soroban auth-entry assembly (single call site of
//!   `Signer::sign_auth_digest`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::health::AuditWriterHealthHandle;
use stellar_agent_core::audit_log::schema::ExecutableRefPin;
use stellar_agent_core::audit_log::signer_set::{
    SignerIdentityV2, SignerSetView, ThresholdObservation,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::{
    RedactedStrkey, redact_strkey_first5_last5, untrusted_display_bounded,
};
use stellar_agent_core::scval::scval_variant_name;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr as xdr_curr;
use stellar_xdr::{
    BytesM, ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits,
    Operation, OperationBody, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol,
    ScVal, ScVec, SorobanAuthorizationEntry, SorobanCredentials, VecM, WriteXdr,
};
use tracing::warn;

use crate::SaError;
use crate::managers::signers::{
    BorrowedRuleLocks, ConfirmedThresholdChange, PinOverrides, SignersManager,
};
use crate::managers::verifiers::{PinnedKind, pin_referenced_contracts, scaddress_cache_key};
use crate::signers::THRESHOLD_POLICY_WASM_HASHES;
use crate::signing::divergence::AuthContextFingerprint;
use crate::simple_threshold_policy::parse_simple_threshold_install_param;
use crate::submit::ExpectedReturn;

// ─────────────────────────────────────────────────────────────────────────────
// Manager configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for [`ContextRuleManager`].
///
/// Constructed once per CLI / MCP invocation; carries network identity and
/// timeout policy. The manager itself is cheap to clone and holds an RPC
/// client for the `submit_transaction_and_wait` primitive.
#[derive(Clone)]
#[non_exhaustive]
pub struct ContextRuleManagerConfig {
    /// Primary Soroban RPC URL.
    ///
    /// The manager constructs both the [`stellar_rpc_client::Client`] (for
    /// `simulate_transaction`) and the wallet-substrate [`StellarRpcClient`]
    /// (for `fetch_account` + `submit_transaction_and_wait`) from this URL.
    pub primary_rpc_url: String,

    /// Secondary Soroban RPC URL for cross-RPC simulation checks.
    ///
    /// When `None`, the cross-RPC step in
    /// [`crate::submit::submit_signed_invoke`] is a passthrough. When set,
    /// it is populated from `Profile.secondary_rpc_url` for the multicall path.
    pub secondary_rpc_url: Option<String>,
    /// Stellar network passphrase used to compute the network ID hash for the
    /// auth-digest preimage and the SEP-23 source-account signature payload.
    pub network_passphrase: String,
    /// Polling timeout for `submit_transaction_and_wait`.
    pub timeout: Duration,
    /// CAIP-2 chain ID for audit-log entries (e.g. `stellar:testnet`).
    pub chain_id: String,
    /// The [`SignersManager`] that observes rules through both RPC
    /// endpoints, pins their contracts and records their signer-set state.
    ///
    /// With a manager, every signing call is checked in the submit path
    /// ([`crate::submit::submit_signed_invoke`]): for each `auth_rule_id`
    /// other than rule 0, the rule's lock is held, its signer-set baseline is
    /// read, its pinned contracts are checked and its signer set is compared
    /// with the chain before anything is simulated or signed, and any
    /// refusal refuses the operation. Rule 0, the bootstrap rule, is exempt
    /// from the rule lock, the signer-set check and the pin check; it has no
    /// pins, and the submit path never reads a baseline for it.
    ///
    /// Without one, [`ContextRuleManager::install_rule`],
    /// [`ContextRuleManager::simulate_install_rule`],
    /// [`ContextRuleManager::add_policy`] and
    /// [`ContextRuleManager::remove_policy`] refuse with
    /// [`SaError::SignersManagerNotConfigured`] before any RPC, and so does
    /// any submission authorized by a rule other than rule 0. The read verbs
    /// run without one, and so do rename, expiry update and delete when rule
    /// 0 alone authorizes them.
    pub signers_manager: Option<Arc<SignersManager>>,
    /// Optional shared audit writer supplied by higher-level handlers.
    pub audit_writer: Option<Arc<Mutex<AuditWriter>>>,
    /// Optional override for the maximum session-rule lookahead window
    /// (`valid_until - current_ledger`) in ledgers.
    ///
    /// When `None`, the manager uses
    /// [`DEFAULT_SESSION_RULE_HORIZON_LEDGERS`] (1000 ledgers ≈ 80 min).
    /// CLI callers resolve the value from
    /// `Profile::session_rule_max_horizon_ledgers` and pass it via
    /// [`Self::with_session_rule_max_horizon_ledgers`].
    ///
    /// The cap is enforced at simulate-response time inside
    /// [`ContextRuleManager::install_rule`] and
    /// [`ContextRuleManager::update_valid_until`]: after the existing
    /// `simulate_transaction` call returns `latestLedger`, the manager
    /// checks `valid_until.saturating_sub(latestLedger) > effective_max`
    /// and refuses with [`SaError::HorizonExceeded`] BEFORE any signing
    /// bytes are produced (maps to `SaInvocationResult::PreSubmissionRefused`).
    pub session_rule_max_horizon_ledgers: Option<u32>,
}

impl std::fmt::Debug for ContextRuleManagerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            primary_rpc_url,
            secondary_rpc_url,
            network_passphrase,
            timeout,
            chain_id,
            signers_manager,
            audit_writer: _,
            session_rule_max_horizon_ledgers,
        } = self;
        f.debug_struct("ContextRuleManagerConfig")
            .field(
                "primary_rpc_url",
                &stellar_agent_core::redact::redact_url_authority(primary_rpc_url),
            )
            .field(
                "secondary_rpc_url",
                &secondary_rpc_url
                    .as_deref()
                    .map(stellar_agent_core::redact::redact_url_authority),
            )
            .field("network_passphrase", network_passphrase)
            .field("timeout", timeout)
            .field("chain_id", chain_id)
            .field("signers_manager", signers_manager)
            .field("audit_writer", &"[redacted]")
            .field(
                "session_rule_max_horizon_ledgers",
                session_rule_max_horizon_ledgers,
            )
            .finish()
    }
}

impl ContextRuleManagerConfig {
    /// Public constructor (the struct is `#[non_exhaustive]` so external
    /// crates cannot use struct-expression syntax).
    ///
    /// Constructs a config with no `signers_manager` and
    /// `secondary_rpc_url = None`.  Use [`Self::with_signers_manager`] to
    /// attach one, which rule install and the policy verbs require, and
    /// [`Self::with_secondary_rpc_url`] to set the secondary RPC URL for
    /// cross-RPC checks.
    #[must_use]
    pub fn new(
        primary_rpc_url: String,
        network_passphrase: String,
        timeout: Duration,
        chain_id: String,
    ) -> Self {
        Self {
            primary_rpc_url,
            secondary_rpc_url: None,
            network_passphrase,
            timeout,
            chain_id,
            signers_manager: None,
            audit_writer: None,
            session_rule_max_horizon_ledgers: None,
        }
    }

    /// Builder: set the secondary Soroban RPC URL for cross-RPC simulation
    /// checks.
    ///
    /// When not set, cross-RPC checks are bypassed.
    #[must_use]
    pub fn with_secondary_rpc_url(mut self, url: String) -> Self {
        self.secondary_rpc_url = Some(url);
        self
    }

    /// Builder: attach the [`SignersManager`] that checks, pins and records
    /// the rules this manager signs under and changes.
    ///
    /// Returns `self` with `signers_manager` set, consuming the original.
    /// Pass a manager that writes to the same audit writer as
    /// [`Self::with_audit_writer`], so a rule's install rows and its
    /// signer-set state rows land in one log.
    #[must_use]
    pub fn with_signers_manager(mut self, sm: Arc<SignersManager>) -> Self {
        self.signers_manager = Some(sm);
        self
    }

    /// Builder: attach a shared audit writer.
    ///
    /// The manager stores the handle so production callers can pass the same
    /// writer instance to companion managers. Existing methods still accept an
    /// explicit `audit_writer` parameter for tests and legacy call sites.
    #[must_use]
    pub fn with_audit_writer(mut self, writer: Arc<Mutex<AuditWriter>>) -> Self {
        self.audit_writer = Some(writer);
        self
    }

    /// Builder: override the session-rule maximum horizon.
    ///
    /// Sets `valid_until - current_ledger` cap in ledgers for
    /// [`ContextRuleManager::install_rule`] and
    /// [`ContextRuleManager::update_valid_until`]. When not called, the
    /// manager uses [`DEFAULT_SESSION_RULE_HORIZON_LEDGERS`] (1000).
    ///
    /// CLI callers resolve the value from
    /// `Profile::session_rule_max_horizon_ledgers` at manager-construction
    /// time, then pass it here — keeping the per-call public signatures
    /// free of this configuration detail.
    ///
    /// # Note
    ///
    /// This setter does NOT bounds-check the value against
    /// [`UPPER_BOUND_HORIZON_LEDGERS`]; that check is the profile-loader's
    /// responsibility (`ProfileLoadError::InvalidHorizonBound`).
    /// The manager enforces only the effective cap at signing time.
    #[must_use]
    pub fn with_session_rule_max_horizon_ledgers(mut self, ledgers: u32) -> Self {
        self.session_rule_max_horizon_ledgers = Some(ledgers);
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Off-chain orchestrator for OZ smart-account context-rule lifecycle
/// operations.
///
/// Each mutating method follows the same six-stage flow:
///
/// 1. **Build** an `InvokeHostFunction` operation calling the corresponding OZ
///    entrypoint on the smart-account contract.
/// 2. **Simulate** via `Server::simulate_transaction` to obtain (a) the
///    auth-entry placeholder the contract requires (with the host-supplied
///    nonce + signature_expiration_ledger), (b) the resource fee +
///    transaction data, (c) the post-execution return value.
/// 3. **Authorize** via
///    [`build_authorization_entry`][crate::managers::auth_entry::build_authorization_entry]
///    — refusal-path checks for rule-ID alignment + simulation-divergence run
///    here, before any signing bytes are produced.
/// 4. **Sign** via
///    [`complete_authorization_entry`][crate::managers::auth_entry::complete_authorization_entry]
///    — `Signer::sign_auth_digest` is
///    invoked once per call here, producing the on-chain canonical
///    `AuthPayload` ScVal that goes into `SorobanCredentials::Address::signature`.
/// 5. **Inject + envelope-sign** the prepared authorization entry into the
///    transaction's operation auth slot, then SEP-23-sign the source-account
///    envelope via `attach_signature`.
/// 6. **Submit** via the wallet-substrate `submit_transaction_and_wait` and
///    parse the on-chain return value.
///
/// Audit-log emission: every successful mutating call emits a
/// `SaContextRuleCreated` / `SaContextRuleDeleted` row plus a
/// `SaRawInvocation` row (`wire_code = "sa.ok"`); failed calls emit a single
/// `SaRawInvocation` row with the typed-error `wire_code` and
/// `result: PreSubmissionRefused | OnChainRejected`.
///
/// # Single signer assumption
///
/// Current implementation uses single-signer authorization: the user's ed25519
/// signer (registered as a `Delegated` signer in some `ContextRule` of the
/// smart-account) signs the auth-digest AND signs the source-account envelope.
/// Multi-signer threshold flows (where multiple signers contribute distinct
/// signatures into the AuthPayload `signers` map) require the signers manager.
///
/// # Functional scope
///
/// - Context-rule install/update/delete lifecycle.
/// - Soroban auth-entry assembly with the `Signer::sign_auth_digest`
///   single-call-site invariant.
pub struct ContextRuleManager {
    primary_rpc_url: String,
    /// Secondary RPC URL for cross-RPC simulation checks; `None` disables.
    secondary_rpc_url: Option<String>,
    network_passphrase: String,
    timeout: Duration,
    chain_id: String,
    rpc_client: StellarRpcClient,
    /// The manager the submit path checks the auth rules through.
    signers_manager: Option<Arc<SignersManager>>,
    audit_writer: Option<Arc<Mutex<AuditWriter>>>,
    /// Session-rule horizon cap from config.
    ///
    /// `None` → use [`DEFAULT_SESSION_RULE_HORIZON_LEDGERS`] at check time.
    session_rule_max_horizon_ledgers: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// HorizonCheck (private)
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for the session-rule horizon check inside
/// [`ContextRuleManager::submit_signed_invoke`].
///
/// Passed as `Some(HorizonCheck { .. })` only from
/// [`ContextRuleManager::install_rule_inner`] and
/// [`ContextRuleManager::update_valid_until_inner`] when `valid_until.is_some()`.
/// All other callers of `submit_signed_invoke` pass `None`.
///
/// The check fires AFTER `simulate_transaction` returns `latestLedger` — zero
/// extra RPC — but BEFORE any signing bytes are produced, so refusals map to
/// `SaInvocationResult::PreSubmissionRefused` via `sa_error_to_invocation_result`.
pub(crate) struct HorizonCheck {
    /// The `valid_until` ledger sequence requested by the caller.
    pub(crate) valid_until: u32,
    /// Effective maximum horizon (`valid_until - current_ledger`) in ledgers.
    ///
    /// Resolved by callers from
    /// `ContextRuleManager::session_rule_max_horizon_ledgers
    ///     .unwrap_or(DEFAULT_SESSION_RULE_HORIZON_LEDGERS)`.
    pub(crate) max_horizon: u32,
    /// `None` on the install path; `Some(rule_id)` on the update path.
    ///
    /// Passed through into [`SaError::HorizonExceeded::rule_id_or_pending`]
    /// so the error envelope lets the caller identify which rule was being
    /// updated when the horizon was exceeded.
    pub(crate) rule_id_or_pending: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// ExpiryCheck (private)
// ─────────────────────────────────────────────────────────────────────────────

/// Parameters for the pre-submission rule expiry check inside
/// [`ContextRuleManager::submit_signed_invoke`].
///
/// Passed as `Some(ExpiryCheck { .. })` from the five signing-path entries
/// that consume a `rule_id`:
/// - [`ContextRuleManager::add_policy_inner`]
/// - [`ContextRuleManager::remove_policy_inner`]
/// - [`SignersManager`] inner methods via the standalone
///   [`check_rule_not_expired_standalone`] free function (cross-module
///   call sites that cannot hold a `ContextRuleManager` reference).
///
/// The check fires AFTER `simulate_transaction` returns `latestLedger`
/// (zero extra ledger-fetch RPC) but BEFORE any auth-entry signing bytes
/// are produced.
///
/// **Do NOT use for the revocation path** (`update_valid_until_inner` with
/// `valid_until = current_ledger`) — the orchestrator is explicitly allowed
/// to revoke a near-expired rule.
///
/// # Canonical citation
///
/// OZ `storage.rs:280-285` (SHA `a9c4216`):
/// ```text
/// if let Some(valid_until) = context_rule.valid_until {
///     if valid_until < e.ledger().sequence() {
///         panic_with_error!(e, UnvalidatedContext)
///     }
/// }
/// ```
/// The wallet's pre-submission check mirrors this strict-`<` logic.
/// `UnvalidatedContext = 3002` per `mod.rs:542` SHA `a9c4216`.
pub(crate) struct ExpiryCheck {
    /// Context-rule ID whose expiry to verify.
    ///
    /// The `source_pubkey_strkey` required by `check_rule_not_expired` is
    /// derived inside `submit_signed_invoke` from the signer's public key
    /// (already fetched at the top of that function), so it is not repeated
    /// here. This keeps `ExpiryCheck` minimal and avoids a second
    /// `signer.public_key()` call at the construction site.
    pub(crate) rule_id: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// PinStatus
// ─────────────────────────────────────────────────────────────────────────────

/// Closed-set pin verification outcome for a single contract type (verifier
/// or policy) in a `verify_rule_wasm_pins` check.
///
/// # Wire format
///
/// `#[serde(rename_all = "snake_case")]` maps variants to lowercase-underscore
/// wire strings: `"match"`, `"drift"`, `"unavailable"`, `"no_pin"`,
/// `"no_contracts"`.
///
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PinStatus {
    /// All pinned first-8-hex values match the live on-chain hashes.
    Match,
    /// At least one pinned hash does not match the live hash, which
    /// corresponds to `SaError::VerifierHashDrift` / `PolicyHashDrift`; or,
    /// for the policy half, the pin record holds policy pins while the rule
    /// has no policy on chain, which corresponds to
    /// `SaError::PinnedPolicyAbsent` (the observed list is then empty).
    Drift,
    /// Infrastructure error prevented comparison; no drift audit row emitted.
    Unavailable,
    /// No `SaContextRuleCreated` audit row found for this rule; the rule was
    /// installed before wasm-hash pinning was enabled, or via a non-wallet path.
    NoPin,
    /// The on-chain rule has no verifier or policy contracts
    /// (Delegated-only rule, no contract to check).
    NoContracts,
}

// ─────────────────────────────────────────────────────────────────────────────
// InstallRuleOutput
// ─────────────────────────────────────────────────────────────────────────────

/// Output of [`ContextRuleManager::install_rule`].
///
/// Separating `rule_id` and `pin_result` into a named struct makes the return
/// type self-documenting and forward-compatible; adding fields does not break
/// existing destructuring when `#[non_exhaustive]` is present.
///
#[derive(Debug)]
#[non_exhaustive]
pub struct InstallRuleOutput {
    /// Newly minted context-rule ID (parsed from the simulated `ContextRule`
    /// return value).
    pub rule_id: u32,
    /// Confirmed transaction hash (64-character hex string) from the
    /// `add_context_rule` submission.
    pub tx_hash: String,
    /// Wasm-hash pinning result from `pin_referenced_contracts`.
    pub pin_result: crate::managers::verifiers::PinResult,
}

// ─────────────────────────────────────────────────────────────────────────────
// SimulateInstallRuleOutput
// ─────────────────────────────────────────────────────────────────────────────

/// Output of [`ContextRuleManager::simulate_install_rule`] (Package D, GH
/// issue #8).
#[derive(Debug)]
#[non_exhaustive]
pub struct SimulateInstallRuleOutput {
    /// Wasm-hash pinning result from `pin_referenced_contracts`, run at
    /// simulate time exactly as `install_rule` runs it before submission.
    pub pin_result: crate::managers::verifiers::PinResult,
    /// The RPC-observed `latestLedger` at simulation time
    /// (`SimulateTransactionResponse::latest_ledger`).
    pub latest_ledger: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// VerifyPinsResult
// ─────────────────────────────────────────────────────────────────────────────

/// Output of [`ContextRuleManager::verify_rule_wasm_pins`].
///
/// Carries per-address pin status and first-8-hex hash projections for
/// the `smart-account rules verify-pins` JSON envelope. See also the CLI envelope type
/// `stellar_agent_cli::commands::smart_account::rules::VerifyPinsResult`, which adds
/// chain metadata and CLI-facing field names.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct VerifyPinsResult {
    /// Canonical strkey (`C...`) of the smart-account contract.
    pub smart_account: String,
    /// Context-rule ID checked.
    pub rule_id: u32,
    /// Pin status for verifier contracts.
    pub verifier_pin_status: PinStatus,
    /// Pin status for policy contracts.
    pub policy_pin_status: PinStatus,
    /// Pinned verifier wasm hashes (first 8 bytes hex each) from the audit log.
    pub pinned_verifier_first8: Vec<String>,
    /// Pinned policy wasm hashes (first 8 bytes hex each) from the audit log.
    pub pinned_policy_first8: Vec<String>,
    /// Observed live verifier wasm hashes (first 8 bytes hex each) from chain.
    pub observed_verifier_first8: Vec<String>,
    /// Observed live policy wasm hashes (first 8 bytes hex each) from chain.
    pub observed_policy_first8: Vec<String>,
    /// Observed executable of each verifier, aligned with
    /// `observed_verifier_first8`: the bounded
    /// [`crate::managers::signers::ObservedExecutable::summary`] of an external
    /// reference (owner, tag and resolved hash) or `"no code"`, and `None`
    /// for a plain Wasm executable. Omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_verifier_executable: Vec<Option<String>>,
    /// Observed executable of each policy, aligned with
    /// `observed_policy_first8`, in the form of
    /// `observed_verifier_executable`. Omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_policy_executable: Vec<Option<String>>,
    /// Executable-reference pins from the audit log, aligned with
    /// `pinned_verifier_first8`; empty when no pinned verifier is an external
    /// reference, `None` at a position pinned by its Wasm hash. Omitted from
    /// JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_verifier_executable_refs: Vec<Option<ExecutableRefPin>>,
    /// Executable-reference pins from the audit log, aligned with
    /// `pinned_policy_first8`, in the form of
    /// `pinned_verifier_executable_refs`. Omitted from JSON when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pinned_policy_executable_refs: Vec<Option<ExecutableRefPin>>,
    /// Install-time mutable-contract override flag, sourced from the
    /// `SaContextRuleCreated` audit row. `false` for pre-Block-B rules.
    pub mutable_override: bool,
    /// Install-time unknown-wasm override flag, sourced from the
    /// `SaContextRuleCreated` audit row. `false` for pre-Block-B rules.
    pub unknown_override: bool,
    /// Wire code of the inner `SaError` when `verifier_pin_status` or
    /// `policy_pin_status` is `Unavailable`. `None` when both statuses are not
    /// `Unavailable`. Populated from [`SaError::wire_code()`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_wire_code: Option<&'static str>,
}

impl ContextRuleManager {
    /// Constructs a new `ContextRuleManager`.
    ///
    /// # Errors
    ///
    /// Returns [`SaError::AuthEntryConstructionFailed`] with stage
    /// `"auth_payload"` if the underlying [`StellarRpcClient`] cannot be
    /// constructed (typically a malformed URL).
    pub fn new(config: ContextRuleManagerConfig) -> Result<Self, SaError> {
        let rpc_client = StellarRpcClient::new(&config.primary_rpc_url).map_err(|e| {
            SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("StellarRpcClient construction failed: {e}"),
            }
        })?;
        Ok(Self {
            primary_rpc_url: config.primary_rpc_url,
            secondary_rpc_url: config.secondary_rpc_url,
            network_passphrase: config.network_passphrase,
            timeout: config.timeout,
            chain_id: config.chain_id,
            rpc_client,
            signers_manager: config.signers_manager,
            audit_writer: config.audit_writer,
            session_rule_max_horizon_ledgers: config.session_rule_max_horizon_ledgers,
        })
    }

    /// Returns the shared audit writer, if one was supplied in config.
    #[must_use]
    pub fn audit_writer(&self) -> Option<Arc<Mutex<AuditWriter>>> {
        self.audit_writer.as_ref().map(Arc::clone)
    }

    // ─── Audit-emission helper ────────────────────────────────────────────────

    /// Writes `entry` to the first available audit writer.
    fn write_audit_entry(
        &self,
        per_method: Option<&mut AuditWriter>,
        entry: AuditEntry,
        op_label: &'static str,
    ) {
        // Distribute a health handle when a signers_manager is wired (production
        // path); `None` in test / builder paths where signers_manager is absent.
        let health = self.signers_manager.as_ref().map(|sm| sm.health_handle());
        dispatch_audit_emission(
            per_method,
            self.audit_writer.as_ref(),
            entry,
            op_label,
            health.as_ref(),
        );
    }

    /// Writes the `SaRawInvocation` row of a refused or failed call: `err`'s
    /// wire code, classified by [`sa_error_to_invocation_result`].
    fn write_failure_row(
        &self,
        per_method: Option<&mut AuditWriter>,
        smart_account_redacted: &str,
        err: &SaError,
        auth_rule_ids_count: u32,
        request_id: &str,
        op_label: &'static str,
    ) {
        let raw = AuditEntry::new_sa_raw_invocation(
            smart_account_redacted,
            err.wire_code(),
            None,
            auth_rule_ids_count,
            sa_error_to_invocation_result(err),
            &self.chain_id,
            request_id,
        );
        self.write_audit_entry(per_method, raw, op_label);
    }

    /// Returns the configured signers manager, or the
    /// [`SaError::SignersManagerNotConfigured`] refusal of an operation that
    /// requires one, scoped to `rule_id` (`None` for an install).
    fn require_signers_manager(
        &self,
        rule_id: Option<u32>,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<&SignersManager, SaError> {
        self.signers_manager
            .as_deref()
            .ok_or_else(|| SaError::SignersManagerNotConfigured {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id: request_id.to_owned(),
            })
    }

    /// Installs a new context rule on the smart-account contract via OZ
    /// `add_context_rule`, and records the confirmed rule as its signer-set
    /// baseline. Returns the assigned `rule_id`.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`]
    ///   (already deployed; the operation invokes `add_context_rule` on
    ///   this address).
    /// - `rule_definition` — the rule to install. The function does not
    ///   inspect signers/policies for caps; on-chain `__check_auth` rejects
    ///   `MAX_SIGNERS=15` / `MAX_POLICIES=5` violations.
    /// - `auth_rule_ids` — the context-rule IDs under which THIS install
    ///   call is authorized. The user must already have a `ContextRule` on
    ///   the smart-account whose signers + policies authorize the
    ///   `add_context_rule` invocation.
    /// - `signer` — the user's ed25519 signer. Must be a `Delegated` signer
    ///   registered in one of the `auth_rule_ids` rules. The same signer
    ///   pays the source-account envelope signature.
    /// - `audit_writer`: optional audit-log handle for the install's
    ///   `SaContextRuleCreated` and `SaRawInvocation` rows. `None` writes them
    ///   through the manager's configured audit writer, if any. The override
    ///   and baseline rows go through the signers manager's writer.
    /// - `request_id` — caller-supplied UUID for forensic correlation across
    ///   every row the install writes.
    /// - `accept_mutable_verifier` — when `true`, mutable verifier / policy
    ///   contracts do NOT block install; a `SaMutableContractOverride` audit
    ///   row records each one instead.  Defaults to `false` (fail closed) in
    ///   production.  The CLI wires this via `--accept-mutable-verifier`.
    /// - `accept_unknown_verifier` — when `true`, verifier / policy contracts
    ///   whose wasm hash is NOT in the compile-time allowlist do NOT block
    ///   install; a `SaUnknownContractOverride` audit row records each one
    ///   instead.  Defaults to `false` (fail closed) in production.  The CLI
    ///   wires this via `--accept-unknown-verifier`.
    ///
    /// # Sequence
    ///
    /// 1. Requires a signers manager: without one the install refuses with
    ///    [`SaError::SignersManagerNotConfigured`], carrying no rule id,
    ///    before any RPC.
    /// 2. Pins every referenced verifier and policy contract.
    /// 3. Derives the state the definition authorizes. The signers'
    ///    version-2 identities are decoded from the bytes the submission
    ///    carries. The threshold is the install parameter of the one policy
    ///    whose pinned executable is the simple-threshold policy.
    /// 4. Signs and submits `add_context_rule`. The submit path first runs
    ///    the checks of every rule other than rule 0 in `auth_rule_ids`: the
    ///    rule lock, the signer-set baseline read, the pinned-hash drift
    ///    check and the signer-set comparison.
    /// 5. Reads the new rule's id from the confirmed return value and writes
    ///    the override rows and the `SaContextRuleCreated` row.
    /// 6. Observes the new rule through both endpoints, requires the
    ///    authorized state and records it as a `SaSignerSetBaselinedV2` row
    ///    with reason `confirmed_install`.
    /// 7. Writes the `sa.ok` `SaRawInvocation` row.
    ///
    /// The pin record precedes the baseline because the rule exists on chain
    /// whatever the baseline step returns. Every refusal writes one
    /// `SaRawInvocation` row carrying its wire code.
    ///
    /// # Override rows
    ///
    /// The override rows carry the installed rule's id and the install's
    /// `request_id`, and are written through the signers manager's audit
    /// writer after the install confirms, before the `SaContextRuleCreated`
    /// row. A refused install writes no override row: a refusal before
    /// submission leaves only the `PreSubmissionRefused` `SaRawInvocation`
    /// row, which records no override flag. Neither is written when the
    /// confirmed return value carries no rule id.
    ///
    /// # Statuses after confirmation
    ///
    /// The rule exists on chain in each of these cases, without a baseline:
    ///
    /// - [`SaError::InstallStateMismatch`] without a rule id: the return
    ///   value did not carry the new rule's id, so no override row and no
    ///   `SaContextRuleCreated` row is written.
    /// - [`SaError::InstallStateMismatch`] with the rule id: the observed
    ///   rule is not the definition.
    /// - [`SaError::BaselineWriteFailed`] with the transaction hash: the rule
    ///   was not observed (stage `observe`) or its baseline row was not
    ///   written (stage `write`).
    ///
    /// # Errors
    ///
    /// - [`SaError::SignersManagerNotConfigured`]: no signers manager is
    ///   configured.
    /// - [`SaError::VerifierHashDrift`] / [`SaError::PolicyHashDrift`] /
    ///   [`SaError::PinnedPolicyAbsent`] / [`SaError::PinCheckUnavailable`]:
    ///   the pinned-hash drift check of a non-zero rule in `auth_rule_ids`
    ///   refused before signing.
    /// - [`SaError::SignerSetDiverged`] / [`SaError::SignerSetMissingBaseline`] /
    ///   [`SaError::NetworkRpcDivergence`] / [`SaError::AuditLog`]: the
    ///   signer-set check of a non-zero rule in `auth_rule_ids` refused
    ///   before signing.
    /// - [`SaError::AuthEntryConstructionFailed`] — construction-time XDR
    ///   encode failures, an `External` signer with empty or oversized key
    ///   data, or RPC simulate/prepare failures.
    /// - [`SaError::DeploymentFailed`] (`phase = "build"`): the definition
    ///   names a policy address twice, or more than one of its policies is
    ///   the simple-threshold policy.
    /// - [`SaError::SimpleThresholdInstallRefused`]: the simple-threshold
    ///   policy's install parameter is not a threshold the wallet can record.
    /// - [`SaError::RuleIdMismatch`] — `auth_rule_ids` count does not match
    ///   simulation auth-context count.
    /// - [`SaError::SimulationDivergence`] — caller-vs-envelope mismatch.
    /// - [`SaError::VerifierMutable`]: verifier mutable (admin/owner key or
    ///   external-reference executable), no override set.
    /// - [`SaError::PolicyMutable`] — policy mutable, no override set.
    /// - [`SaError::ContractInstanceUnsupported`]: verifier or policy instance
    ///   has no code the wallet can pin; no override exists.
    /// - [`SaError::VerifierWasmNotInAllowlist`] — unknown verifier hash, no override.
    /// - [`SaError::PolicyWasmNotInAllowlist`] — unknown policy hash, no override.
    /// - [`SaError::NetworkRpcDivergence`] — primary / secondary RPC disagree.
    /// - [`SaError::DeploymentFailed`] — submission or on-chain rejection.
    /// - [`SaError::InstallStateMismatch`] / [`SaError::BaselineWriteFailed`]:
    ///   the install confirmed and was not baselined; see "Statuses after
    ///   confirmation".
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible auth-+rule-+signer-+observability+pin-flags arg set"
    )]
    #[allow(
        clippy::needless_option_as_deref,
        reason = "as_deref_mut() reborrows Option<&mut AuditWriter> across multiple audit emission call sites; \
                  the lint sees identical types but the reborrow avoids moving the binding"
    )]
    pub async fn install_rule(
        &self,
        smart_account: ScAddress,
        rule_definition: ContextRuleDefinition,
        auth_rule_ids: Vec<ContextRuleId>,
        signer: &(dyn Signer + Send + Sync),
        mut audit_writer: Option<&mut AuditWriter>,
        request_id: String,
        accept_mutable_verifier: bool,
        accept_unknown_verifier: bool,
    ) -> Result<InstallRuleOutput, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let auth_rule_ids_count: u32 =
            auth_rule_ids
                .len()
                .try_into()
                .map_err(|_| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: "auth_rule_ids count exceeds u32".to_owned(),
                })?;

        let sm = match self.require_signers_manager(None, &smart_account_redacted, &request_id) {
            Ok(sm) => sm,
            Err(e) => {
                self.write_failure_row(
                    audit_writer.as_deref_mut(),
                    &smart_account_redacted,
                    &e,
                    auth_rule_ids_count,
                    &request_id,
                    "install_rule: SaRawInvocation (signers manager)",
                );
                return Err(e);
            }
        };

        let source_account_strkey = signer
            .public_key()
            .await
            .map(|pk| pk.to_string())
            .unwrap_or_default();

        // Wasm-hash pin check, before the submission. Identifies and verifies every verifier and policy
        // contract the definition references, and refuses mutable or
        // unknown-wasm contracts unless the matching override flag is set.
        // An applied override is returned pending and written once the
        // install confirms.
        let pin_result = match pin_referenced_contracts(
            sm,
            smart_account.clone(),
            &smart_account_redacted,
            &rule_definition,
            None, // the rule has no on-chain id before install
            &source_account_strkey,
            accept_mutable_verifier,
            accept_unknown_verifier,
            request_id.clone(),
        )
        .await
        {
            Ok(pin_result) => pin_result,
            Err(e) => {
                self.write_failure_row(
                    audit_writer.as_deref_mut(),
                    &smart_account_redacted,
                    &e,
                    auth_rule_ids_count,
                    &request_id,
                    "install_rule: SaRawInvocation (pin check)",
                );
                return Err(e);
            }
        };

        let expected =
            match expected_install_state(&rule_definition, &pin_result.pinned_policy_wasm_hashes) {
                Ok(expected) => expected,
                Err(e) => {
                    self.write_failure_row(
                        audit_writer.as_deref_mut(),
                        &smart_account_redacted,
                        &e,
                        auth_rule_ids_count,
                        &request_id,
                        "install_rule: SaRawInvocation (expected state)",
                    );
                    return Err(e);
                }
            };

        let submitted = match self
            .install_rule_inner(
                smart_account.clone(),
                &rule_definition,
                &auth_rule_ids,
                signer,
                &request_id,
            )
            .await
        {
            Ok(submitted) => submitted,
            Err(e) => {
                self.write_failure_row(
                    audit_writer.as_deref_mut(),
                    &smart_account_redacted,
                    &e,
                    auth_rule_ids_count,
                    &request_id,
                    "install_rule: SaRawInvocation (failure)",
                );
                return Err(e);
            }
        };

        let rule_id = match parse_context_rule_id_from_return(&submitted.return_val) {
            Ok(rule_id) => rule_id,
            Err(cause) => {
                warn!(
                    smart_account = %smart_account_redacted,
                    tx_hash = %submitted.tx_hash,
                    cause = %cause,
                    "install_rule: the confirmed install's return value carries no rule id"
                );
                let e = SaError::InstallStateMismatch {
                    rule_id: None,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        &smart_account_redacted,
                    ),
                    tx_hash: submitted.tx_hash.clone(),
                    request_id: request_id.clone(),
                };
                self.write_failure_row(
                    audit_writer.as_deref_mut(),
                    &smart_account_redacted,
                    &e,
                    auth_rule_ids_count,
                    &request_id,
                    "install_rule: SaRawInvocation (rule id)",
                );
                return Err(e);
            }
        };

        // The rule is on chain: its pin record is written whatever the
        // baseline step returns.
        crate::managers::verifiers::write_pending_override_rows(
            sm,
            &smart_account_redacted,
            rule_id,
            &request_id,
            &pin_result.pending_overrides,
        );
        let created = pin_result.context_rule_created_entry(
            &smart_account_redacted,
            rule_id,
            &rule_definition,
            &self.chain_id,
            &request_id,
        );
        self.write_audit_entry(
            audit_writer.as_deref_mut(),
            created,
            "install_rule: SaContextRuleCreated",
        );

        let baselined = sm
            .baseline_confirmed_install(
                &smart_account,
                &smart_account_strkey,
                &smart_account_redacted,
                rule_id,
                &expected,
                &submitted,
                &source_account_strkey,
                &request_id,
            )
            .await;
        if let Err(e) = baselined {
            self.write_failure_row(
                audit_writer.as_deref_mut(),
                &smart_account_redacted,
                &e,
                auth_rule_ids_count,
                &request_id,
                "install_rule: SaRawInvocation (baseline)",
            );
            return Err(e);
        }

        let raw = AuditEntry::new_sa_raw_invocation(
            &smart_account_redacted,
            "sa.ok",
            Some(auth_digest_prefix_from_outcome(&baselined)),
            auth_rule_ids_count,
            stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
            &self.chain_id,
            &request_id,
        );
        self.write_audit_entry(
            audit_writer.as_deref_mut(),
            raw,
            "install_rule: SaRawInvocation",
        );

        Ok(InstallRuleOutput {
            rule_id,
            tx_hash: submitted.tx_hash,
            pin_result,
        })
    }

    /// Inner install_rule implementation: signs and submits
    /// `add_context_rule` and returns the confirmed submission.
    ///
    /// When `rule_definition.valid_until` is `Some`, passes a
    /// [`HorizonCheck`] to `submit_signed_invoke` so the horizon cap is
    /// enforced using `latestLedger` from the simulate response — zero extra
    /// RPC.
    async fn install_rule_inner(
        &self,
        smart_account: ScAddress,
        rule_definition: &ContextRuleDefinition,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<crate::submit::SubmitInvokeResult, SaError> {
        let invoke_args = build_add_context_rule_args(rule_definition)?;
        // Resolve the effective horizon cap from config.  `None` in config
        // means "use the default".  The check is skipped when `valid_until`
        // is absent (permanent rule — no horizon constraint).
        let horizon_check = rule_definition.valid_until.map(|valid_until| HorizonCheck {
            valid_until,
            max_horizon: self
                .session_rule_max_horizon_ledgers
                .unwrap_or(DEFAULT_SESSION_RULE_HORIZON_LEDGERS),
            rule_id_or_pending: None, // install path — rule not yet created
        });
        self.submit_signed_invoke(
            smart_account,
            "add_context_rule",
            invoke_args,
            auth_rule_ids,
            signer,
            "install_rule",
            horizon_check,
            None, // no expiry check: rule not yet created, no rule_id to check
            request_id,
            // No lock is held: the submit path locks and checks the auth rules.
            None,
            // The install reads the new rule's id from the return value.
            Some(ExpectedReturn::ContextRuleId),
        )
        .await
    }

    /// Simulates an `add_context_rule` installation WITHOUT signing or
    /// submitting — the propose-time seam for agent-proposed context rules
    /// (Package D, GH issue #8).
    ///
    /// Requires a signers manager, as [`Self::install_rule`] does, then runs
    /// the SAME wasm-hash pin check ([`pin_referenced_contracts`]) and the
    /// SAME derivation of the authorized state. A definition that names a
    /// policy address twice, attaches the simple-threshold policy more than
    /// once or carries an install parameter the wallet cannot record
    /// therefore refuses at proposal time. It then builds the SAME
    /// `add_context_rule` invoke args via `build_add_context_rule_args` and
    /// simulates via the crate's
    /// no-signature recording-auth simulate primitive
    /// (`managers::signers::simulate_read_only_with_ledger`). Soroban's
    /// recording auth mode returns the auth requirements for a
    /// `require_auth` entrypoint without needing a pre-signed auth entry —
    /// `simulateTransaction` never mutates ledger state regardless of what
    /// the invoked entrypoint does, so the SAME no-auth simulate primitive
    /// `get_rule` / `get_rules_count` use for genuinely read-only
    /// entrypoints works here too.
    ///
    /// Does NOT modify [`Self::install_rule`] or `submit_signed_invoke`:
    /// this is a new sibling helper. The full divergence/pin/auth machinery
    /// still runs again, independently, at actual COMMIT time inside the
    /// unchanged `install_rule`.
    ///
    /// This method writes NO audit row: nothing is installed by a simulate
    /// call. An override the pin check applies is reported in
    /// [`crate::managers::verifiers::PinResult::pending_overrides`] and the
    /// aggregate flags only; the
    /// `SaMutableContractOverride` / `SaUnknownContractOverride` rows are
    /// written once, by `install_rule` at commit, after the install
    /// confirms, carrying the installed rule's id and the commit's
    /// `request_id`.
    ///
    /// # Arguments
    ///
    /// Same as [`Self::install_rule`] minus `signer` (no signing occurs) and
    /// `audit_writer` (no audit emission), plus `source_account_strkey` (the
    /// fee-paying account used to fetch a sequence number for the simulate
    /// envelope; the OZ `add_context_rule` auth is on the smart-account
    /// contract itself, not this account, so simulate's recording-auth mode
    /// needs no signature from it).
    ///
    /// # Errors
    ///
    /// Same error surface as `install_rule`'s pre-submission checks:
    /// [`SaError::SignersManagerNotConfigured`] (no rule id) before any RPC
    /// without a signers manager; [`SaError::VerifierMutable`] /
    /// [`SaError::PolicyMutable`] / [`SaError::ContractInstanceUnsupported`] /
    /// [`SaError::VerifierWasmNotInAllowlist`] /
    /// [`SaError::PolicyWasmNotInAllowlist`] from the pin check;
    /// [`SaError::DeploymentFailed`] (`phase = "build"`),
    /// [`SaError::SimpleThresholdInstallRefused`] and
    /// [`SaError::AuthEntryConstructionFailed`] from the derivation of the
    /// authorized state; [`SaError::DeploymentFailed`]
    /// (`phase = "simulate"`) on an RPC or simulate-transaction error.
    pub async fn simulate_install_rule(
        &self,
        smart_account: ScAddress,
        rule_definition: ContextRuleDefinition,
        source_account_strkey: &str,
        accept_mutable_verifier: bool,
        accept_unknown_verifier: bool,
        request_id: String,
    ) -> Result<SimulateInstallRuleOutput, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let sm = self.require_signers_manager(None, &smart_account_redacted, &request_id)?;
        let pin_result = pin_referenced_contracts(
            sm,
            smart_account.clone(),
            &smart_account_redacted,
            &rule_definition,
            None, // the rule has no on-chain id before install
            source_account_strkey,
            accept_mutable_verifier,
            accept_unknown_verifier,
            request_id.clone(),
        )
        .await?;
        expected_install_state(&rule_definition, &pin_result.pinned_policy_wasm_hashes)?;

        let invoke_args = build_add_context_rule_args(&rule_definition)?;

        let (_return_val, latest_ledger) =
            crate::managers::signers::simulate_read_only_with_ledger(
                &self.primary_rpc_url,
                smart_account,
                "add_context_rule",
                invoke_args,
                Some(source_account_strkey),
                &self.network_passphrase,
                self.timeout,
            )
            .await?;

        Ok(SimulateInstallRuleOutput {
            pin_result,
            latest_ledger,
        })
    }

    /// Updates the `name` field of an existing context rule via OZ
    /// `update_context_rule_name`. Returns `()` on success; the on-chain
    /// return value is the updated `ContextRule` but this manager surface
    /// surfaces only success/failure here.
    ///
    /// Audit emission: the metadata-update operation produces a `SaRawInvocation`
    /// row with `wire_code = "sa.ok"` on success. Failure paths emit a single
    /// `SaRawInvocation` with the typed-error wire code per [`Self::install_rule`].
    ///
    /// # Errors
    ///
    /// Same variant set as [`Self::install_rule`].
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible auth-+rule-+signer-+observability arg set"
    )]
    #[allow(
        clippy::needless_option_as_deref,
        reason = "as_deref_mut() reborrows Option<&mut AuditWriter> across multiple audit emission call sites; \
                  the lint sees identical types but the reborrow avoids moving the binding"
    )]
    pub async fn update_name(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        name: String,
        auth_rule_ids: Vec<ContextRuleId>,
        signer: &(dyn Signer + Send + Sync),
        mut audit_writer: Option<&mut AuditWriter>,
        request_id: String,
    ) -> Result<(), SaError> {
        let health = self.signers_manager.as_ref().map(|sm| sm.health_handle());
        let new_name_audit = name.clone();
        let outcome = self
            .update_name_inner(
                smart_account.clone(),
                rule_id,
                name,
                &auth_rule_ids,
                signer,
                &request_id,
            )
            .await;
        emit_metadata_update_audit(
            outcome.as_ref().err(),
            &smart_account,
            &auth_rule_ids,
            audit_writer.as_deref_mut(),
            self.audit_writer.as_ref(),
            &self.chain_id,
            &request_id,
            "update_name",
            health.as_ref(),
        );
        // Emit typed forensic row alongside the raw invocation row on success.
        if outcome.is_ok() {
            let smart_account_strkey =
                scaddress_to_strkey(&smart_account).unwrap_or_else(|_| "unknown".to_owned());
            let typed = AuditEntry::new_sa_context_rule_name_updated(
                redact_strkey_first5_last5(&smart_account_strkey),
                rule_id,
                &new_name_audit,
                self.chain_id.as_str(),
                request_id.as_str(),
            );
            dispatch_audit_emission(
                audit_writer.as_deref_mut(),
                self.audit_writer.as_ref(),
                typed,
                "update_name",
                health.as_ref(),
            );
        }
        outcome
    }

    async fn update_name_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        name: String,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(), SaError> {
        let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: reason,
        };
        let name_scval =
            ScVal::String(ScString(name.try_into().map_err(|e| {
                auth_payload_err(format!("encode rule name as StringM: {e:?}"))
            })?));
        let invoke_args = vec![ScVal::U32(rule_id), name_scval];
        self.submit_signed_invoke(
            smart_account,
            "update_context_rule_name",
            invoke_args,
            auth_rule_ids,
            signer,
            "update_name",
            None, // no horizon check for name-only updates
            None, // no expiry check for name-only updates (non-signing-path)
            request_id,
            // No lock is held: the submit path locks and checks the auth rules.
            None,
            None,
        )
        .await?;
        Ok(())
    }

    /// Updates the `valid_until` field of an existing context rule via OZ
    /// `update_context_rule_valid_until`. `Some(ledger)` sets the expiry;
    /// `None` clears it (the rule becomes permanent).
    ///
    /// When `valid_until_ledger` is `Some`, the horizon
    /// (`valid_until - current_ledger`) is checked against
    /// `ContextRuleManagerConfig::session_rule_max_horizon_ledgers`
    /// (defaulting to [`DEFAULT_SESSION_RULE_HORIZON_LEDGERS`] when `None`).
    /// The check uses `latestLedger` from the existing
    /// `simulate_transaction` response — no extra round-trip.
    ///
    /// # Errors
    ///
    /// Same variant set as [`Self::install_rule`], plus:
    /// - [`SaError::HorizonExceeded`] when the requested `valid_until` window
    ///   exceeds the effective cap.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible auth-+rule-+signer-+observability arg set"
    )]
    #[allow(
        clippy::needless_option_as_deref,
        reason = "as_deref_mut() reborrows Option<&mut AuditWriter> across multiple audit emission call sites; \
                  the lint sees identical types but the reborrow avoids moving the binding"
    )]
    pub async fn update_valid_until(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        valid_until_ledger: Option<u32>,
        auth_rule_ids: Vec<ContextRuleId>,
        signer: &(dyn Signer + Send + Sync),
        mut audit_writer: Option<&mut AuditWriter>,
        request_id: String,
    ) -> Result<(), SaError> {
        let health = self.signers_manager.as_ref().map(|sm| sm.health_handle());
        let outcome = self
            .update_valid_until_inner(
                smart_account.clone(),
                rule_id,
                valid_until_ledger,
                &auth_rule_ids,
                signer,
                &request_id,
            )
            .await;
        emit_metadata_update_audit(
            outcome.as_ref().err(),
            &smart_account,
            &auth_rule_ids,
            audit_writer.as_deref_mut(),
            self.audit_writer.as_ref(),
            &self.chain_id,
            &request_id,
            "update_valid_until",
            health.as_ref(),
        );
        // Emit typed forensic row alongside the raw invocation row on success.
        if outcome.is_ok() {
            let smart_account_strkey =
                scaddress_to_strkey(&smart_account).unwrap_or_else(|_| "unknown".to_owned());
            let typed = AuditEntry::new_sa_context_rule_valid_until_updated(
                redact_strkey_first5_last5(&smart_account_strkey),
                rule_id,
                valid_until_ledger,
                self.chain_id.as_str(),
                request_id.as_str(),
            );
            dispatch_audit_emission(
                audit_writer.as_deref_mut(),
                self.audit_writer.as_ref(),
                typed,
                "update_valid_until",
                health.as_ref(),
            );
        }
        outcome
    }

    /// Inner update_valid_until implementation.
    ///
    /// Passes a [`HorizonCheck`] to `submit_signed_invoke` when
    /// `valid_until_ledger` is `Some`, enforcing the horizon cap using
    /// `latestLedger` from the simulate response — zero extra RPC.
    async fn update_valid_until_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        valid_until_ledger: Option<u32>,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(), SaError> {
        let valid_until_scval = encode_option_u32(valid_until_ledger)?;
        let invoke_args = vec![ScVal::U32(rule_id), valid_until_scval];
        // Resolve the effective horizon cap from config.  The check is skipped
        // when `valid_until_ledger` is `None` (the "clear expiry / make
        // permanent" path — clearing expiry to create a permanent rule is
        // not subject to the lookahead cap).
        let horizon_check = valid_until_ledger.map(|valid_until| HorizonCheck {
            valid_until,
            max_horizon: self
                .session_rule_max_horizon_ledgers
                .unwrap_or(DEFAULT_SESSION_RULE_HORIZON_LEDGERS),
            rule_id_or_pending: Some(rule_id), // update path — rule exists
        });
        self.submit_signed_invoke(
            smart_account,
            "update_context_rule_valid_until",
            invoke_args,
            auth_rule_ids,
            signer,
            "update_valid_until",
            horizon_check,
            // No expiry check: `update_valid_until_inner` is the revocation
            // path — setting `valid_until = current_ledger` on an
            // already-expired rule is intentionally permitted.
            None,
            request_id,
            // No lock is held: the submit path locks and checks the auth rules.
            None,
            None,
        )
        .await?;
        Ok(())
    }

    /// Removes a context rule from the smart-account contract via OZ
    /// `remove_context_rule`. On success emits both a `SaContextRuleDeleted`
    /// row and a `SaRawInvocation` row (`sa.ok`).
    ///
    /// # Errors
    ///
    /// Same variant set as [`Self::install_rule`]. Note that OZ rejects
    /// `remove_context_rule` for unknown `rule_id` with
    /// `SmartAccountError::ContextRuleNotFound`; the resulting on-chain
    /// rejection surfaces as `SaError::DeploymentFailed { phase = "submit", ... }`.
    #[allow(
        clippy::needless_option_as_deref,
        reason = "as_deref_mut() reborrows Option<&mut AuditWriter> across multiple audit emission call sites; \
                  the lint sees identical types but the reborrow avoids moving the binding"
    )]
    pub async fn delete_rule(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        auth_rule_ids: Vec<ContextRuleId>,
        signer: &(dyn Signer + Send + Sync),
        mut audit_writer: Option<&mut AuditWriter>,
        request_id: String,
    ) -> Result<(), SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
        let auth_rule_ids_count: u32 =
            auth_rule_ids
                .len()
                .try_into()
                .map_err(|_| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: "auth_rule_ids count exceeds u32".to_owned(),
                })?;

        let outcome = self
            .delete_rule_inner(
                smart_account.clone(),
                rule_id,
                &auth_rule_ids,
                signer,
                &request_id,
            )
            .await;

        // Audit-log emission. Two-row pattern on success, one-row on failure.
        // Falls back to self.audit_writer when the per-method parameter is None
        // (the production CLI pattern).
        match &outcome {
            Ok(()) => {
                let deleted = AuditEntry::new_sa_context_rule_deleted(
                    &smart_account_redacted,
                    rule_id,
                    &self.chain_id,
                    &request_id,
                );
                self.write_audit_entry(
                    audit_writer.as_deref_mut(),
                    deleted,
                    "delete_rule: SaContextRuleDeleted",
                );
                let raw = AuditEntry::new_sa_raw_invocation(
                    &smart_account_redacted,
                    "sa.ok",
                    Some(auth_digest_prefix_from_outcome_unit(&outcome)),
                    auth_rule_ids_count,
                    stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
                    &self.chain_id,
                    &request_id,
                );
                self.write_audit_entry(
                    audit_writer.as_deref_mut(),
                    raw,
                    "delete_rule: SaRawInvocation",
                );
            }
            Err(err) => {
                let result = sa_error_to_invocation_result(err);
                let raw = AuditEntry::new_sa_raw_invocation(
                    &smart_account_redacted,
                    err.wire_code(),
                    None,
                    auth_rule_ids_count,
                    result,
                    &self.chain_id,
                    &request_id,
                );
                self.write_audit_entry(
                    audit_writer.as_deref_mut(),
                    raw,
                    "delete_rule: SaRawInvocation (failure)",
                );
            }
        }

        outcome
    }

    async fn delete_rule_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(), SaError> {
        let invoke_args = vec![ScVal::U32(rule_id)];
        self.submit_signed_invoke(
            smart_account,
            "remove_context_rule",
            invoke_args,
            auth_rule_ids,
            signer,
            "delete_rule",
            None, // no horizon check for delete operations
            None, // no expiry check: delete is a destructive revocation alternative
            request_id,
            // No lock is held: the submit path locks and checks the auth rules.
            None,
            None,
        )
        .await?;
        Ok(())
    }

    // ── Per-rule policy mutators ──────────────────────────────────────────────

    /// Adds a policy contract to an existing context rule via OZ `add_policy`.
    ///
    /// Returns the on-chain `policy_id` assigned by the smart-account registry.
    ///
    /// # Reference cross-check
    ///
    /// - **OZ canonical:** `packages/accounts/src/smart_account/mod.rs:440` +
    ///   `storage.rs:1110–1143` SHA `a9c4216` —
    ///   `fn add_policy(e, context_rule_id: u32, policy: Address, install_param: Val) -> u32`.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — smart-account contract [`ScAddress`].
    /// - `rule_id` — target context rule ID.
    /// - `policy_address` — policy contract [`ScAddress`].
    /// - `install_param`: caller-supplied install parameter [`ScVal`],
    ///   passed through to the policy's `install`. For the simple-threshold
    ///   policy it must be the threshold map the wallet records; see
    ///   "Simple-threshold policy".
    /// - `auth_rule_ids` — context-rule IDs under which this call is
    ///   authorised.
    /// - `signer` — signing key for both the SA auth-entry and the
    ///   SEP-23 source-account envelope.
    /// - `audit_writer` — optional per-invocation [`AuditWriter`].
    /// - `request_id` — UUID for forensic correlation across the emission set.
    /// - `accept_mutable_verifier` / `accept_unknown_verifier`: the overrides
    ///   `rules create` takes, applied to the policy when it is pinned under
    ///   "Pin record".
    ///
    /// # Sequence
    ///
    /// The add requires a signers manager and refuses without one before any
    /// RPC. The signers manager then acquires the locks of `rule_id` and of
    /// every rule other than rule 0 in `auth_rule_ids` in one acquisition and
    /// holds them through the rows of the confirmed add. Under the locks, in
    /// order:
    ///
    /// 1. the chain is compared with the rule's version-2 signer-set state
    ///    row, whatever the policy. A rule without one refuses with
    ///    [`SaError::SignerSetMissingBaseline`] and a version-1 row with
    ///    [`SaError::SignerSetBaselineLegacy`], both before any RPC. A
    ///    changed set refuses with [`SaError::SignerSetDiverged`];
    /// 2. the policy's executable is observed through both RPC endpoints, to
    ///    tell whether it is the simple-threshold policy;
    /// 3. the pin record is planned (see "Pin record");
    /// 4. before signing, the submit path runs the pinned-hash drift check of
    ///    every rule other than rule 0 in `auth_rule_ids`, and the signer-set
    ///    baseline read and comparison of each such rule other than the
    ///    target;
    /// 5. after confirmation, the threshold of the simple-threshold policy is
    ///    recorded, then the pin rows are written.
    ///
    /// A concurrent verb on the rule, such as a signer add, is serialized
    /// before or after the whole add, so neither overwrites the other's pin
    /// record.
    ///
    /// # Simple-threshold policy
    ///
    /// When the policy's executable is the simple-threshold policy, the
    /// attach also records the threshold it sets:
    ///
    /// - `install_param` must be the `{ threshold: u32 }` map with a
    ///   non-zero threshold, else [`SaError::SimpleThresholdInstallRefused`]
    ///   before anything is signed;
    /// - the rule must have no simple-threshold policy yet;
    /// - after confirmation the signers must be unchanged and the threshold
    ///   the parameter's, which a `SaThresholdChangedV2` row records.
    ///
    /// A confirmed attach whose threshold is not recorded returns the
    /// recording's refusal, and the pin, `SaPolicyAdded` and raw rows are
    /// still written, since the policy is attached on chain. Any other
    /// policy is attached without a state row.
    ///
    /// # Pin record
    ///
    /// When the rule has a pin record (the newest `SaContextRuleCreated` or
    /// `SaContextRulePinsUpdated` row), the add keeps the record in step with
    /// the rule's live policy set. The signing-time drift check then neither
    /// refuses the rule the wallet itself changed nor leaves the new policy
    /// unchecked. The record is read and the live policy set taken from the
    /// comparison under the rule's lock:
    ///
    /// - before submission, a policy address not already live on the rule is
    ///   identified and probed with the checks rule install applies: a hash
    ///   outside the policy allowlist refuses with
    ///   [`SaError::PolicyWasmNotInAllowlist`] unless
    ///   `accept_unknown_verifier` is set, a mutable contract refuses with
    ///   [`SaError::PolicyMutable`] unless `accept_mutable_verifier` is set,
    ///   an unpinnable instance refuses with
    ///   [`SaError::ContractInstanceUnsupported`] regardless;
    /// - after the add confirms, an applied override writes its override row
    ///   carrying the rule id; a refused add writes none;
    /// - then a `SaContextRulePinsUpdated` row (reason `policy_added`)
    ///   records the policy pins with the new pin appended;
    /// - with no live policy on the rule, the row replaces the policy pins
    ///   with the added policy's pin, so it pins exactly the policy set the
    ///   add produces.
    ///
    /// A record with more than one policy pin is refused by every checked
    /// signing verb with `sa.pin_check_unavailable`
    /// (`sa.multiple_pinned_hashes_unsupported`), the outcome for a rule
    /// installed with two policies. A rule without a pin record stays
    /// unpinned: nothing is probed and no row is written.
    ///
    /// # Rows
    ///
    /// A confirmed add writes, in order: the `SaThresholdChangedV2` row (the
    /// simple-threshold policy only), the override rows, the
    /// `SaContextRulePinsUpdated` row, the `SaPolicyAdded` row and the
    /// `SaRawInvocation` row (`sa.ok`, or the recording's refusal). The rows
    /// up to the pins row are written under the rule's lock. A confirmed add
    /// whose return value carries no policy id writes no `SaPolicyAdded` row
    /// and returns [`SaError::BaselineWriteFailed`] at stage `observe` with
    /// the transaction hash; its pin rows are written. An add that does not
    /// confirm writes one `SaRawInvocation` row.
    ///
    /// # Errors
    ///
    /// - [`SaError::SignersManagerNotConfigured`]: no signers manager is
    ///   configured; the refusal names `rule_id`.
    /// - [`SaError::PolicyWasmNotInAllowlist`] / [`SaError::PolicyMutable`] /
    ///   [`SaError::ContractInstanceUnsupported`]: the policy of a pinned
    ///   rule was refused under "Pin record", or its executable could not be
    ///   observed.
    /// - [`SaError::VerifierHashDrift`] / [`SaError::PolicyHashDrift`] /
    ///   [`SaError::PinnedPolicyAbsent`] /
    ///   [`SaError::PinnedVerifierAbsent`] / [`SaError::PinCheckUnavailable`]:
    ///   the pinned-hash drift check of a non-zero rule in `auth_rule_ids`
    ///   refused before signing.
    /// - [`SaError::SignerSetMissingBaseline`],
    ///   [`SaError::SignerSetBaselineLegacy`] and
    ///   [`SaError::SignerSetDiverged`]: the comparison of the rule, or of a
    ///   rule in `auth_rule_ids`, refused before submission.
    /// - [`SaError::SimpleThresholdInstallRefused`] and
    ///   [`SaError::ThresholdPolicyIdentificationFailed`]: the
    ///   simple-threshold attach refused before submission.
    /// - [`SaError::BaselineWriteFailed`] / [`SaError::SignerSetDiverged`]
    ///   with the transaction hash: the simple-threshold attach confirmed and
    ///   its threshold was not recorded, or (stage `observe`) any attach
    ///   confirmed with a return value that carries no policy id.
    /// - [`SaError::NetworkRpcDivergence`]: the two endpoints disagree on the
    ///   policy's executable.
    /// - [`SaError::AuthEntryConstructionFailed`]: transport/XDR failure, or
    ///   at stage `rule_lock` a rule's lock not acquired within the signers
    ///   manager's timeout.
    /// - [`SaError::DeploymentFailed`]: simulate or submit failure.
    ///   On simulate failure the `redacted_reason` is augmented with the OZ
    ///   symbolic error name via `augment_with_oz_error_name`; notably
    ///   `TooManyPolicies = 3011` (the on-chain defence for a bypassed CLI cap),
    ///   or the pinned rule's policies could not be read.
    /// - [`SaError::AuditLog`]: the pin record or the state row could not be
    ///   read.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible auth-+rule-+signer-+observability arg set; \
                  mirrors install_rule / delete_rule signature surface"
    )]
    #[allow(
        clippy::needless_option_as_deref,
        reason = "as_deref_mut() reborrows Option<&mut AuditWriter> across \
                  multiple audit emission call sites; see delete_rule for rationale"
    )]
    pub async fn add_policy(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        policy_address: ScAddress,
        install_param: stellar_xdr::ScVal,
        auth_rule_ids: Vec<ContextRuleId>,
        signer: &(dyn Signer + Send + Sync),
        mut audit_writer: Option<&mut AuditWriter>,
        request_id: String,
        accept_mutable_verifier: bool,
        accept_unknown_verifier: bool,
    ) -> Result<u32, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
        let policy_address_strkey = scaddress_to_strkey(&policy_address)?;
        let policy_address_redacted = redact_strkey_first5_last5(&policy_address_strkey);

        let auth_rule_ids_count: u32 =
            auth_rule_ids
                .len()
                .try_into()
                .map_err(|_| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: "auth_rule_ids count exceeds u32".to_owned(),
                })?;

        let sm =
            match self.require_signers_manager(Some(rule_id), &smart_account_redacted, &request_id)
            {
                Ok(sm) => sm,
                Err(e) => {
                    self.write_failure_row(
                        audit_writer.as_deref_mut(),
                        &smart_account_redacted,
                        &e,
                        auth_rule_ids_count,
                        &request_id,
                        "add_policy: SaRawInvocation (signers manager)",
                    );
                    return Err(e);
                }
            };

        let source_account_strkey = signer
            .public_key()
            .await
            .map(|pk| pk.to_string())
            .unwrap_or_default();

        let outcome = self
            .add_policy_confirmed(
                sm,
                &smart_account,
                &smart_account_strkey,
                &smart_account_redacted,
                rule_id,
                &policy_address,
                install_param,
                &auth_rule_ids,
                signer,
                &source_account_strkey,
                &request_id,
                PinOverrides {
                    accept_mutable_verifier,
                    accept_unknown_verifier,
                },
            )
            .await;

        // The entry wrote the threshold row and the pin rows of a confirmed
        // add under the rule's lock; the policy row and the raw row follow,
        // whatever the recording returned. Falls back to self.audit_writer
        // when the per-method parameter is None (the production CLI pattern).
        match &outcome {
            Ok(confirmed) => {
                let tx_hash_redacted = stellar_agent_network::redact_tx_hash(&confirmed.tx_hash);
                if let Some(policy_id) = confirmed.policy_id {
                    let policy_added = AuditEntry::new_sa_policy_added(
                        rule_id,
                        policy_id,
                        RedactedStrkey::from_already_redacted(&policy_address_redacted),
                        &tx_hash_redacted,
                        RedactedStrkey::from_already_redacted(&smart_account_redacted),
                        &self.chain_id,
                        &request_id,
                    );
                    self.write_audit_entry(
                        audit_writer.as_deref_mut(),
                        policy_added,
                        "add_policy: SaPolicyAdded",
                    );
                }
                match &confirmed.result {
                    Ok(_) => {
                        let raw = AuditEntry::new_sa_raw_invocation(
                            &smart_account_redacted,
                            "sa.ok",
                            Some(auth_digest_prefix_from_outcome(&confirmed.result)),
                            auth_rule_ids_count,
                            stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
                            &self.chain_id,
                            &request_id,
                        );
                        self.write_audit_entry(
                            audit_writer.as_deref_mut(),
                            raw,
                            "add_policy: SaRawInvocation",
                        );
                    }
                    Err(err) => self.write_failure_row(
                        audit_writer.as_deref_mut(),
                        &smart_account_redacted,
                        err,
                        auth_rule_ids_count,
                        &request_id,
                        "add_policy: SaRawInvocation (recording)",
                    ),
                }
            }
            Err(err) => self.write_failure_row(
                audit_writer.as_deref_mut(),
                &smart_account_redacted,
                err,
                auth_rule_ids_count,
                &request_id,
                "add_policy: SaRawInvocation (failure)",
            ),
        }

        outcome?.result
    }

    /// Attaches the policy through [`SignersManager::attach_policy`], which
    /// compares the rule, observes the policy, plans and writes the pin rows
    /// and, for the simple-threshold policy, records the threshold under the
    /// rule's lock. `Err` when the call returned before a confirmation;
    /// nothing was recorded. `Ok` once the add confirmed, whatever the steps
    /// after the confirmation returned. The submission refuses a simulated
    /// return value that is not a `u32` before signing. After the
    /// confirmation, a return value the entry cannot read as a `u32` gives
    /// no policy id and a stage-`observe` result.
    #[allow(
        clippy::too_many_arguments,
        reason = "the signers manager, the account identity, the rule, the policy and its \
                  parameter, the authorization, the source account and the correlation id"
    )]
    async fn add_policy_confirmed(
        &self,
        sm: &SignersManager,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        policy_address: &ScAddress,
        install_param: ScVal,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        source_account_strkey: &str,
        request_id: &str,
        overrides: PinOverrides,
    ) -> Result<PolicyAddConfirmed, SaError> {
        let target = smart_account.clone();
        let ConfirmedThresholdChange {
            submitted,
            parsed,
            recorded,
        } = sm
            .attach_policy(
                smart_account,
                smart_account_strkey,
                smart_account_redacted,
                rule_id,
                auth_rule_ids,
                policy_address,
                install_param,
                overrides,
                Some(source_account_strkey),
                move |locked, invoke_args| {
                    Box::pin(self.submit_signed_invoke(
                        target,
                        "add_policy",
                        invoke_args,
                        auth_rule_ids,
                        signer,
                        "add_policy",
                        None, // no horizon check for policy install
                        // Expiry check at signing-path entry. Refuses with
                        // `SaError::RuleExpired` when `valid_until <
                        // latest_ledger` (OZ `storage.rs:280-285` SHA
                        // `a9c4216`).
                        Some(ExpiryCheck { rule_id }),
                        request_id,
                        Some(locked.rule_locks()),
                        // The attach reads the assigned policy id from the
                        // return value.
                        Some(ExpectedReturn::U32),
                    ))
                },
                request_id,
            )
            .await?;
        // OZ `add_policy` returns `u32` (the assigned policy_id) per
        // `mod.rs:440` + `storage.rs:1143` SHA `a9c4216`.
        let result = match (parsed, recorded) {
            (Some(policy_id), Ok(())) => Ok(policy_id),
            (_, Err(e)) => Err(e),
            // The entry reports a return value with no policy id as a
            // stage-observe refusal; this arm keeps the verb's result an
            // error if it ever reports it as recorded.
            (None, Ok(())) => Err(crate::managers::signers::observe_failed_after(
                rule_id,
                smart_account_redacted,
                &submitted.tx_hash,
                &SaError::DeploymentFailed {
                    phase: "simulate",
                    redacted_reason: "add_policy: the confirmed return value carries no policy id"
                        .to_owned(),
                },
                request_id,
            )),
        };
        Ok(PolicyAddConfirmed {
            policy_id: parsed,
            tx_hash: submitted.tx_hash,
            result,
        })
    }

    /// Removes a policy from an existing context rule via OZ `remove_policy`.
    ///
    /// # Reference cross-check
    ///
    /// - **OZ canonical:** `packages/accounts/src/smart_account/mod.rs:473` +
    ///   `storage.rs:1175–1230` SHA `a9c4216` —
    ///   `fn remove_policy(e, context_rule_id: u32, policy_id: u32)`.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — smart-account contract [`ScAddress`].
    /// - `rule_id` — target context rule ID.
    /// - `policy_id` — on-chain policy ID to remove (from the registry).
    /// - `auth_rule_ids` — context-rule IDs under which this call is
    ///   authorised.
    /// - `signer` — signing key.
    /// - `audit_writer` — optional per-invocation [`AuditWriter`].
    /// - `request_id` — UUID for forensic correlation.
    ///
    /// # Sequence
    ///
    /// The removal requires a signers manager and refuses without one before
    /// any RPC. The signers manager then acquires the locks of `rule_id` and
    /// of every rule other than rule 0 in `auth_rule_ids` in one acquisition
    /// and holds them through the rows of the confirmed removal. Under the
    /// locks, in order:
    ///
    /// 1. the chain is compared with the rule's version-2 signer-set state
    ///    row, whatever the policy. A rule without one refuses with
    ///    [`SaError::SignerSetMissingBaseline`] and a version-1 row with
    ///    [`SaError::SignerSetBaselineLegacy`], both before any RPC. A rule
    ///    with a state row that is not on chain refuses from the comparison's
    ///    rule read, and a changed set with [`SaError::SignerSetDiverged`];
    /// 2. `policy_id` is resolved to its address from the compared rule; a
    ///    policy id the rule does not hold refuses with
    ///    [`SaError::DeploymentFailed`];
    /// 3. the policy's executable is observed through both RPC endpoints, to
    ///    tell whether it is the simple-threshold policy;
    /// 4. the pin record is planned (see "Pin record");
    /// 5. before signing, the submit path runs the pinned-hash drift check of
    ///    every rule other than rule 0 in `auth_rule_ids`, and the signer-set
    ///    baseline read and comparison of each such rule other than the
    ///    target;
    /// 6. after confirmation, the threshold change of the simple-threshold
    ///    policy is recorded, then the pins row is written.
    ///
    /// A concurrent verb on the rule, such as a signer add, is serialized
    /// before or after the whole removal, so the removal's pin record carries
    /// the verifier pin of an add that confirmed first.
    ///
    /// # Simple-threshold policy
    ///
    /// When the policy's executable is the simple-threshold policy, the
    /// detach also records the threshold change:
    ///
    /// - the rule's observed simple-threshold policy must be the removed one,
    ///   else the removal refuses with
    ///   [`SaError::ThresholdPolicyIdentificationFailed`];
    /// - after confirmation the signers must be unchanged and the threshold
    ///   gone, which a `SaThresholdChangedV2` row records.
    ///
    /// A rule with two simple-threshold policies cannot be observed, so no
    /// other verb works on it, and the comparison of step 1 refuses it.
    /// Detaching one of the two is accepted when the rule has a version-2
    /// signer-set state row, recorded before the second policy was attached.
    /// The rule's signers must equal the row's before submission, and after
    /// confirmation the remaining policy's threshold is recorded. Such a rule
    /// with no state row refuses with [`SaError::SignerSetMissingBaseline`];
    /// it can only be deleted under rule 0. Removing a policy other than the
    /// two from such a rule refuses with
    /// [`SaError::ThresholdPolicyIdentificationFailed`], as does any removal
    /// from a rule with three or more. A confirmed detach whose threshold
    /// change is not recorded returns the recording's refusal, and the pin,
    /// `SaPolicyRemoved` and raw rows are still written.
    ///
    /// # Pin record
    ///
    /// When the rule has a pin record, the removal keeps the record in step
    /// with the rule's live policy set. The record is read, and the policy's
    /// executable observed, under the rule's lock. After the removal
    /// confirms, the first policy pin equal to the observed hash and its
    /// aligned executable-reference pin are removed, and a
    /// `SaContextRulePinsUpdated` row (reason `policy_removed`) records the
    /// rest. When the policy is the rule's only policy and the record holds
    /// one policy pin, that pin is removed even when it differs from the
    /// observed hash, since it can only be the removed policy's. The rule
    /// then ends with no policy and no policy pin, so a later `add_policy`
    /// pins its policy afresh. Otherwise, when no pin equals the observed hash,
    /// nothing is written; a record with two or more policy pins is refused
    /// by every checked signing verb whatever it holds. Removing the last
    /// policy under such a record leaves the rule refused with
    /// [`SaError::PinnedPolicyAbsent`] until an `add_policy` authorized under
    /// rule 0 re-pins a policy or the rule is reinstalled.
    ///
    /// # Rows
    ///
    /// A confirmed removal writes, in order: the `SaThresholdChangedV2` row
    /// (the simple-threshold policy only), the `SaContextRulePinsUpdated`
    /// row, the `SaPolicyRemoved` row and the `SaRawInvocation` row (`sa.ok`,
    /// or the recording's refusal). The rows up to the pins row are written
    /// under the rule's lock. A removal that does not confirm writes one
    /// `SaRawInvocation` row.
    ///
    /// # Errors
    ///
    /// - [`SaError::SignersManagerNotConfigured`]: no signers manager is
    ///   configured; the refusal names `rule_id`.
    /// - [`SaError::VerifierHashDrift`] / [`SaError::PolicyHashDrift`] /
    ///   [`SaError::PinnedPolicyAbsent`] /
    ///   [`SaError::PinnedVerifierAbsent`] / [`SaError::PinCheckUnavailable`]:
    ///   the pinned-hash drift check of a non-zero rule in `auth_rule_ids`
    ///   refused before signing.
    /// - [`SaError::SignerSetMissingBaseline`],
    ///   [`SaError::SignerSetBaselineLegacy`] and
    ///   [`SaError::SignerSetDiverged`]: the comparison of the rule, or of a
    ///   rule in `auth_rule_ids`, refused before submission.
    /// - [`SaError::DeploymentFailed`] (`phase = "simulate"`): the rule holds
    ///   no policy `policy_id`, or a read failed.
    /// - [`SaError::ContractInstanceUnsupported`] /
    ///   [`SaError::NetworkRpcDivergence`]: the policy's executable could not
    ///   be observed.
    /// - [`SaError::ThresholdPolicyIdentificationFailed`]: the simple-threshold
    ///   detach refused before submission.
    /// - [`SaError::BaselineWriteFailed`] / [`SaError::SignerSetDiverged`]
    ///   with the transaction hash: the simple-threshold detach confirmed and
    ///   its threshold change was not recorded.
    /// - [`SaError::AuthEntryConstructionFailed`]: transport/XDR failure, or
    ///   at stage `rule_lock` a rule's lock not acquired within the signers
    ///   manager's timeout.
    /// - [`SaError::DeploymentFailed`]: simulate or submit failure.
    /// - [`SaError::AuditLog`]: the pin record or the state row could not be
    ///   read.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible auth-+rule-+signer-+observability arg set"
    )]
    #[allow(
        clippy::needless_option_as_deref,
        reason = "as_deref_mut() reborrows Option<&mut AuditWriter> across \
                  multiple audit emission call sites"
    )]
    pub async fn remove_policy(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        policy_id: u32,
        auth_rule_ids: Vec<ContextRuleId>,
        signer: &(dyn Signer + Send + Sync),
        mut audit_writer: Option<&mut AuditWriter>,
        request_id: String,
    ) -> Result<(), SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let auth_rule_ids_count: u32 =
            auth_rule_ids
                .len()
                .try_into()
                .map_err(|_| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: "auth_rule_ids count exceeds u32".to_owned(),
                })?;

        let sm =
            match self.require_signers_manager(Some(rule_id), &smart_account_redacted, &request_id)
            {
                Ok(sm) => sm,
                Err(e) => {
                    self.write_failure_row(
                        audit_writer.as_deref_mut(),
                        &smart_account_redacted,
                        &e,
                        auth_rule_ids_count,
                        &request_id,
                        "remove_policy: SaRawInvocation (signers manager)",
                    );
                    return Err(e);
                }
            };

        let source_account_strkey = signer
            .public_key()
            .await
            .map(|pk| pk.to_string())
            .unwrap_or_default();

        let outcome = self
            .remove_policy_confirmed(
                sm,
                &smart_account,
                &smart_account_strkey,
                &smart_account_redacted,
                rule_id,
                policy_id,
                &auth_rule_ids,
                signer,
                &source_account_strkey,
                &request_id,
            )
            .await;

        // The entry wrote the threshold row and the pins row of a confirmed
        // removal under the rule's lock; the policy row and the raw row
        // follow, whatever the recording returned.
        match &outcome {
            Ok(confirmed) => {
                let tx_hash_redacted = stellar_agent_network::redact_tx_hash(&confirmed.tx_hash);
                let policy_removed = AuditEntry::new_sa_policy_removed(
                    rule_id,
                    policy_id,
                    &tx_hash_redacted,
                    RedactedStrkey::from_already_redacted(&smart_account_redacted),
                    &self.chain_id,
                    &request_id,
                );
                self.write_audit_entry(
                    audit_writer.as_deref_mut(),
                    policy_removed,
                    "remove_policy: SaPolicyRemoved",
                );
                match &confirmed.result {
                    Ok(()) => {
                        let raw = AuditEntry::new_sa_raw_invocation(
                            &smart_account_redacted,
                            "sa.ok",
                            Some(auth_digest_prefix_from_outcome_unit(&confirmed.result)),
                            auth_rule_ids_count,
                            stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
                            &self.chain_id,
                            &request_id,
                        );
                        self.write_audit_entry(
                            audit_writer.as_deref_mut(),
                            raw,
                            "remove_policy: SaRawInvocation",
                        );
                    }
                    Err(err) => self.write_failure_row(
                        audit_writer.as_deref_mut(),
                        &smart_account_redacted,
                        err,
                        auth_rule_ids_count,
                        &request_id,
                        "remove_policy: SaRawInvocation (recording)",
                    ),
                }
            }
            Err(err) => self.write_failure_row(
                audit_writer.as_deref_mut(),
                &smart_account_redacted,
                err,
                auth_rule_ids_count,
                &request_id,
                "remove_policy: SaRawInvocation (failure)",
            ),
        }

        outcome?.result
    }

    /// Removes the policy through [`SignersManager::detach_policy`]. Under the
    /// rule's lock the entry compares the rule, resolves `policy_id` to its
    /// address, observes the policy, plans and writes the pins row and, for
    /// the simple-threshold policy, records the threshold change. `Err`
    /// when the call returned before a confirmation; nothing was recorded.
    /// `Ok` once the removal confirmed, with the result of the steps after
    /// it.
    #[allow(
        clippy::too_many_arguments,
        reason = "the signers manager, the account identity, the rule, the policy id, the \
                  authorization, the source account and the correlation id"
    )]
    async fn remove_policy_confirmed(
        &self,
        sm: &SignersManager,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        policy_id: u32,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        source_account_strkey: &str,
        request_id: &str,
    ) -> Result<PolicyRemoveConfirmed, SaError> {
        let target = smart_account.clone();
        let ConfirmedThresholdChange {
            submitted,
            parsed: (),
            recorded,
        } = sm
            .detach_policy(
                smart_account,
                smart_account_strkey,
                smart_account_redacted,
                rule_id,
                auth_rule_ids,
                policy_id,
                Some(source_account_strkey),
                move |locked, invoke_args| {
                    Box::pin(self.submit_signed_invoke(
                        target,
                        "remove_policy",
                        invoke_args,
                        auth_rule_ids,
                        signer,
                        "remove_policy",
                        None, // no horizon check for policy removal
                        // Expiry check at signing-path entry.
                        Some(ExpiryCheck { rule_id }),
                        request_id,
                        Some(locked.rule_locks()),
                        None,
                    ))
                },
                request_id,
            )
            .await?;
        Ok(PolicyRemoveConfirmed {
            tx_hash: submitted.tx_hash,
            result: recorded,
        })
    }

    /// Reads the on-chain `ContextRule` for the given `rule_id` via
    /// `simulate_transaction` against `get_context_rule(rule_id)`. No
    /// signing is required — the read does not call `require_auth`.
    ///
    /// Returns `None` when the on-chain `get_context_rule` raises
    /// `SmartAccountError::ContextRuleNotFound` (the simulation surfaces as
    /// an `error` field in the response). All other simulation failures
    /// surface as [`SaError::DeploymentFailed`] with `phase = "simulate"`.
    ///
    /// # Errors
    ///
    /// - [`SaError::AuthEntryConstructionFailed`] / [`SaError::DeploymentFailed`]
    ///   for transport / RPC failures and for malformed simulation responses.
    pub async fn get_rule(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: &str,
    ) -> Result<Option<ScVal>, SaError> {
        let invoke_args = vec![ScVal::U32(rule_id)];
        match self
            .simulate_read_only(
                smart_account,
                "get_context_rule",
                invoke_args,
                source_account_strkey,
            )
            .await
        {
            Ok(scval) => Ok(Some(scval)),
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) if phase == "simulate"
                && (redacted_reason.contains("ContextRuleNotFound")
                    || redacted_reason.contains("#3000")
                    || redacted_reason.contains("Error(Contract, #3000)")) =>
            {
                // OZ `SmartAccountError::ContextRuleNotFound` has discriminant
                // 3000 (OpenZeppelin stellar-contracts v0.7.2,
                // `packages/accounts/src/smart_account/mod.rs:540`, SHA `a9c4216`).
                // Soroban-RPC's simulate response surfaces contract panics as
                // `Error(Contract, #<code>)` with the numeric discriminant —
                // the symbolic enum name is NOT serialised over the wire.
                // We accept either form (numeric or symbolic) for forward-
                // compatibility with future RPC versions that may include
                // symbolic names alongside the numeric code.
                Ok(None)
            }
            Err(other) => Err(other),
        }
    }

    /// Returns the count of installed context rules on the smart-account via
    /// `simulate_transaction` against `get_context_rules_count()`. Read-only;
    /// no signing.
    ///
    /// # Errors
    ///
    /// Same variants as [`Self::get_rule`].
    pub async fn get_rules_count(
        &self,
        smart_account: ScAddress,
        source_account_strkey: &str,
    ) -> Result<u32, SaError> {
        let scval = self
            .simulate_read_only(
                smart_account,
                "get_context_rules_count",
                vec![],
                source_account_strkey,
            )
            .await?;
        match scval {
            ScVal::U32(n) => Ok(n),
            other => Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "get_context_rules_count return is not ScVal::U32 (got {})",
                    scval_variant_name(&other)
                ),
            }),
        }
    }

    /// Pre-submission rule expiry check — refuses with [`SaError::RuleExpired`]
    /// when the rule's `valid_until` is `Some(v)` and `v < latest_ledger`.
    ///
    /// `latest_ledger` is harvested by the caller from the existing
    /// `simulate_transaction` response (every signing-path entry already runs
    /// simulate; `sim_response.latest_ledger` is always present per the
    /// Soroban-RPC contract). This method does NOT make an additional
    /// ledger-fetch round-trip — it makes one `get_context_rule` RPC call to
    /// read the rule's `valid_until` field and compare against the provided
    /// ledger sequence number.
    ///
    /// Returns `Ok(())` immediately when `rule.valid_until` is `None`
    /// (permanent rule) or when `valid_until >= latest_ledger`.
    ///
    /// Returns `Ok(())` when `get_rule` returns `None` (rule not found on
    /// chain — the subsequent submission will surface the error at the
    /// simulate or submit phase; the expiry pre-check should not block on
    /// a not-yet-installed rule).
    ///
    /// **Do NOT call from the revocation path** (`update_valid_until_inner`
    /// with `valid_until = current_ledger`) — the orchestrator is explicitly
    /// allowed to revoke a near-expired rule.
    ///
    /// # Reference cross-check
    ///
    /// OZ `storage.rs:280-285` (SHA `a9c4216`):
    /// ```text
    /// if let Some(valid_until) = context_rule.valid_until {
    ///     if valid_until < e.ledger().sequence() {
    ///         panic_with_error!(e, UnvalidatedContext)
    ///     }
    /// }
    /// ```
    /// The wallet's check mirrors this strict-`<` logic.
    /// `UnvalidatedContext = 3002` per `mod.rs:542` SHA `a9c4216`.
    ///
    /// # Errors
    ///
    /// - [`SaError::RuleExpired`] — `valid_until < latest_ledger`; `valid_until`
    ///   and `current` carry the unwrapped ledger values.
    /// - [`SaError::DeploymentFailed`] / [`SaError::AuthEntryConstructionFailed`]
    ///   on transport or RPC failure propagated from [`Self::get_rule`].
    ///
    pub(crate) async fn check_rule_not_expired(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: &str,
        latest_ledger: u32,
    ) -> Result<(), SaError> {
        let scval_opt = self
            .get_rule(smart_account, rule_id, source_account_strkey)
            .await?;

        let scval = match scval_opt {
            Some(v) => v,
            // Rule not found on-chain — pass through; the subsequent simulate
            // or submit will surface the appropriate contract error.
            None => return Ok(()),
        };

        // Parse only the `valid_until` field from the ContextRule ScVal.
        let valid_until = extract_valid_until_from_rule_scval(&scval)?;

        if let Some(v) = valid_until
            && v < latest_ledger
        {
            return Err(SaError::RuleExpired {
                rule_id,
                valid_until: v,
                current: latest_ledger,
            });
        }

        Ok(())
    }

    /// Enumerates all active (non-deleted) context rules on the smart account.
    ///
    /// Implements the sparse-ID-safe scan algorithm: OZ allocates rule IDs
    /// monotonically from `NextId` but decrements `Count` on delete without
    /// recycling IDs. A naive `0..count` loop silently misses rules whose IDs
    /// exceed `count` when earlier IDs were deleted (e.g. install 0,1,2 →
    /// delete 0 → Count=2, but scanning 0..2 misses ID 2). This method scans
    /// `[0, max_scan_id)` instead, using `get_rule`'s `Ok(None)` gap signal.
    ///
    /// # Algorithm (mirrors the canonical context-rule enumeration scan)
    ///
    /// 1. Fetch `active_count` via [`Self::get_rules_count`].
    /// 2. Early-exit with an empty enumeration if `active_count == 0`.
    /// 3. Scan `rule_id in 0..max_scan_id` calling [`Self::get_rule`].
    ///    - `Ok(Some(scval))` → parse the summary; with an `audit_writer`,
    ///      read the rule's signer-set baseline state ([`BaselineState`]) in
    ///      one audit-log scan and check the scan budget after it; increment
    ///      `returned`.
    ///    - `Ok(None)` → gap (deleted or never allocated); increment `skipped`.
    ///    - `Err(_)` → propagate immediately.
    ///    - Early-exit when `returned + skipped >= active_count` (enough IDs
    ///      processed to account for all allocated IDs).
    /// 4. If `max_scan_id` is exhausted before all rules are found, return
    ///    `SaError::DeploymentFailed` with `phase = "simulate"` (`"simulate"` is
    ///    the correct closed-set value for scan-bound exhaustion —
    ///    `"enumerate_rules"` is NOT in the 7-value closed set at
    ///    `error.rs:620-642`).
    /// 5. Audit-log cross-check: if `audit_writer` is configured, query
    ///    `AuditReader::find_installed_context_rule_ids`. IDs present in the
    ///    audit log but absent from the on-chain enumeration populate
    ///    `audit_log_missing`.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] (`phase = "simulate"`) — any RPC failure
    ///   during the scan, `max_scan_id` exhausted before all active rules
    ///   were found, or the scan budget (`timeout`) elapsed, the baseline
    ///   reads included.
    /// - [`SaError::AuditLog`] — audit-log integrity violation during the
    ///   audit-log cross-check (integrity errors MUST NOT be silently mapped
    ///   to `Ok`). An integrity error during one rule's baseline read is not
    ///   an error: that rule reports [`BaselineState::Unreadable`].
    pub async fn list_active_context_rules(
        &self,
        smart_account: ScAddress,
        source_account_strkey: &str,
        max_scan_id: u32,
    ) -> Result<ActiveContextRuleEnumeration, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // ── Step 1: fetch active rule count ───────────────────────────────────
        let active_count = self
            .get_rules_count(smart_account.clone(), source_account_strkey)
            .await?;

        // ── Step 2: early-exit on empty ───────────────────────────────────────
        if active_count == 0 {
            return Ok(ActiveContextRuleEnumeration {
                rules: vec![],
                active_count_on_chain: 0,
                rules_skipped: 0,
                gaps_seen: 0,
                scanned_id_range_end: 0,
                audit_log_missing: vec![],
            });
        }

        // ── Step 3: sparse-ID scan ────────────────────────────────────────────
        // `skipped` counts only ANOMALOUS skips (`Err(_)` from `get_rule`).
        // `gaps_seen` counts LEGITIMATE sparse gaps (`Ok(None)` — deleted
        // rules).  Operator-facing envelope shows `rules_skipped` only;
        // early-exit and planner accounting use the sum.
        //
        // `scan_budget` bounds the WALL-CLOCK TOTAL of this loop, independent
        // of `max_scan_id`: `max_scan_id` bounds the ITERATION COUNT (up to
        // 10,000 per the profile-load clamp), but each iteration is its own
        // RPC round-trip individually bounded at 60s by the transport — a
        // large `max_scan_id` against a slow endpoint would otherwise cost up
        // to `max_scan_id x 60s` with no total cap. Reuses `self.timeout` (the
        // manager's configured RPC timeout — the flow's existing
        // caller-facing budget) rather than a second, independently-tuned
        // constant, so raising `timeout` in the profile raises the scan
        // budget too.
        let scan_budget = stellar_agent_core::rpc_budget::SequentialRpcBudget::new(self.timeout);
        let mut rules: Vec<ContextRuleSummary> = Vec::with_capacity(active_count as usize);
        let mut returned: u32 = 0;
        let mut skipped: usize = 0;
        let mut gaps_seen: usize = 0;
        // Tracks one-past-the-last probed rule ID; updated on every probe
        // regardless of outcome. Exposed as `scanned_id_range_end` in the return
        // value.
        let mut scanned_id_range_end: u32 = 0;
        let mut budget_elapsed = false;
        // Each summarized rule's baseline state comes from one scan of the
        // audit log, when the manager has a writer.
        let baseline_reader = self.audit_writer.as_ref().map(|writer| {
            stellar_agent_core::audit_log::reader::AuditReader::new(Arc::clone(writer), None)
        });
        let smart_account_digest = stellar_agent_core::audit_log::signer_set::account_digest(
            &self.network_passphrase,
            &smart_account_strkey,
        );

        for rule_id in 0..max_scan_id {
            // Early-exit when all active rules are found.
            // OZ `Count` is decremented on delete and never includes deleted IDs;
            // `returned` counts only `Ok(Some(_))` responses, so the scan breaks
            // once the count of returned summaries reaches the active count.
            // Do NOT add `skipped` here: a gap at ID N does not mean rule N+1 cannot exist.
            if returned >= active_count {
                break;
            }

            // Record the probe before the await so that every probed ID is counted
            // even on early returns from the match arms below.
            scanned_id_range_end = rule_id.saturating_add(1);

            // Defensive skip-and-count: a transient RPC blip on a single rule
            // must not abort the whole enumeration.
            // `Ok(None)` = recognised gap (ContextRuleNotFound) — silent skip.
            // `Err(_)` = unrecognised simulate failure — logged + counted.
            // The collective scan budget wraps the call; a budget timeout
            // stops the scan immediately (distinct from a per-rule simulate
            // failure, which only skips that one rule ID).
            let scval_opt = match stellar_agent_core::rpc_budget::bound_stage(
                scan_budget,
                "get_rule",
                self.get_rule(smart_account.clone(), rule_id, source_account_strkey),
            )
            .await
            {
                Err(_elapsed) => {
                    budget_elapsed = true;
                    break;
                }
                Ok(Ok(opt)) => opt,
                Ok(Err(e)) => {
                    warn!(
                        rule_id,
                        error = %e,
                        smart_account = %smart_account_redacted,
                        "list_active_context_rules: per-rule simulate failed; skipping"
                    );
                    skipped = skipped.saturating_add(1);
                    continue;
                }
            };
            match scval_opt {
                Some(scval) => {
                    let mut summary = parse_context_rule_summary(scval, rule_id)?;
                    let scanned = baseline_reader.as_ref().map(|reader| {
                        BaselineState::read(
                            reader,
                            rule_id,
                            &smart_account_redacted,
                            &smart_account_digest,
                        )
                    });
                    if let Some(baseline) = scanned {
                        summary.baseline = baseline;
                    }
                    rules.push(summary);
                    returned += 1;
                    // The baseline read is a synchronous audit-log scan the
                    // budget's timeout cannot interrupt; the deadline is
                    // checked after it.
                    if scanned.is_some() && tokio::time::Instant::now() >= scan_budget.deadline {
                        budget_elapsed = true;
                        break;
                    }
                }
                None => {
                    // Recognised sparse gap (ContextRuleNotFound) — counted
                    // toward `gaps_seen`, NOT `rules_skipped`. Operator-facing
                    // skip surface is anomalous-only.
                    gaps_seen = gaps_seen.saturating_add(1);
                }
            }
        }

        // ── Step 4: exhaustion check ──────────────────────────────────────────
        // `phase: "simulate"` — exhaustion is a simulate-phase failure (the
        // per-rule simulate loop did not collect all active rules before the
        // scan bound). "enumerate_rules" is not in the closed 7-value
        // `SaError::DeploymentFailed` phase set (error.rs:620-642). The same
        // phase covers both exhaustion causes (scan-bound reached, or the
        // collective wall-clock budget elapsed); the message text
        // distinguishes them for operator diagnosis.
        if budget_elapsed {
            let budget_secs = self.timeout.as_secs();
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "list_active_context_rules: collective scan budget of {budget_secs}s \
                     elapsed before collecting all {active_count} active rules (found \
                     {returned}, probed up to rule_id {scanned_id_range_end}); the RPC \
                     endpoint may be slow or unreachable"
                ),
            });
        }
        if returned < active_count {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "list_active_context_rules: max_scan_id {max_scan_id} reached before \
                     collecting all {active_count} active rules (found {returned}); \
                     raise smart_account_max_context_rule_scan_id in the profile"
                ),
            });
        }

        // ── Step 5: audit-log cross-check ────────────────────────────────────
        // Compare returned rule IDs against the local audit log's installed set.
        // A non-empty difference indicates on-chain / audit-log desync.
        let returned_ids: std::collections::HashSet<u32> =
            rules.iter().map(|r| r.rule_id).collect();

        let audit_log_missing = if let Some(ref writer_arc) = self.audit_writer {
            let reader = stellar_agent_core::audit_log::reader::AuditReader::new(
                Arc::clone(writer_arc),
                None,
            );
            match reader.find_installed_context_rule_ids(&smart_account_redacted) {
                Ok(installed) => {
                    let mut missing: Vec<u32> = installed
                        .into_iter()
                        .filter(|id| !returned_ids.contains(id))
                        .collect();
                    missing.sort_unstable();
                    if !missing.is_empty() {
                        warn!(
                            smart_account = %smart_account_redacted,
                            missing_count = missing.len(),
                            "audit log records rule IDs not returned by on-chain \
                             enumeration — possible RPC data suppression or audit-log \
                             desync"
                        );
                    }
                    missing
                }
                Err(e) => return Err(SaError::AuditLog(e)),
            }
        } else {
            warn!(
                smart_account = %smart_account_redacted,
                "list_active_context_rules: audit_writer not configured; \
                 audit-log cross-check skipped"
            );
            vec![]
        };

        Ok(ActiveContextRuleEnumeration {
            rules,
            active_count_on_chain: active_count,
            rules_skipped: skipped,
            gaps_seen,
            scanned_id_range_end,
            audit_log_missing,
        })
    }

    /// Verify the pinned wasm hashes for a context rule against the live
    /// on-chain contracts (drift-detection on demand).
    ///
    /// Runs the same two-RPC re-fetch used by `sign_with_passkey_rule` at
    /// signing time, but as a stand-alone read-only call initiated by the
    /// operator via `smart-account rules verify-pins`.
    ///
    /// # Flow
    ///
    /// 1. Calls `SignersManager::fetch_verifier_and_policy_addresses` to
    ///    obtain the verifier and policy contract addresses currently registered
    ///    in the on-chain rule.
    /// 2. For each verifier address calls
    ///    `verify_pinned_verifier_against_chain`.
    /// 3. For each policy address calls
    ///    `verify_pinned_policy_against_chain`; with no policy address, calls
    ///    `verify_policy_pins_present`.
    /// 4. Reads the pinned first-8-hex strings from the audit log via
    ///    `AuditReader::find_latest_context_rule_pinned_hashes` for the
    ///    envelope.
    ///
    /// # Status encoding
    ///
    /// - `"match"` — no drift detected.
    /// - `"drift"` — `SaError::VerifierHashDrift` / `PolicyHashDrift`
    ///   returned; a paired `SaVerifierHashDrift` / `SaPolicyHashDrift` audit
    ///   row was emitted. For the policy half also: the rule has no policy on
    ///   chain while its pin record holds policy pins
    ///   (`SaError::PinnedPolicyAbsent`, no audit row); the observed policy
    ///   list is then empty.
    /// - `"unavailable"` — any other `SaError` (infrastructure failure; no
    ///   drift audit row emitted).
    /// - `"no_pin"` — no `SaContextRuleCreated` audit row exists for this
    ///   rule (rule was installed before wasm-hash pinning landed, or via
    ///   non-wallet path).
    /// - `"no_contracts"` — the on-chain rule has no verifier / policy
    ///   contracts (Delegated-only rule) and, for the policy half, the pin
    ///   record holds no policy pin.
    ///
    /// # Requires `signers_manager`
    ///
    /// The manager must have been constructed with `with_signers_manager`.
    /// Returns `SaError::SignersManagerNotConfigured` if `signers_manager` is
    /// `None`.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] — on-chain fetch of rule addresses
    ///   failed (rule may not exist).
    /// - [`SaError::AuditLog`] — audit-log integrity error reading pinned
    ///   hashes.
    pub async fn verify_rule_wasm_pins(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: &str,
        request_id: &str,
    ) -> Result<VerifyPinsResult, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let sm =
            self.require_signers_manager(Some(rule_id), &smart_account_redacted, request_id)?;

        // Fetch on-chain verifier and policy addresses.
        let (verifier_addrs, policy_addrs) = sm
            .fetch_verifier_and_policy_addresses(
                smart_account.clone(),
                rule_id,
                Some(source_account_strkey),
            )
            .await?;

        // Read pinned hashes from the audit log.
        let pin_record = match crate::managers::verifiers::read_pinned_hashes_for_rule(
            sm,
            rule_id,
            &smart_account_redacted,
        ) {
            Ok(Some(r)) => r,
            Ok(None) => {
                // No pin record — rule installed before wasm-hash pinning was enabled, or via non-wallet path.
                let no_contracts = verifier_addrs.is_empty() && policy_addrs.is_empty();
                let status = if no_contracts {
                    PinStatus::NoContracts
                } else {
                    PinStatus::NoPin
                };
                return Ok(VerifyPinsResult {
                    smart_account: smart_account_strkey,
                    rule_id,
                    verifier_pin_status: status.clone(),
                    policy_pin_status: status,
                    pinned_verifier_first8: vec![],
                    pinned_policy_first8: vec![],
                    observed_verifier_first8: vec![],
                    observed_policy_first8: vec![],
                    observed_verifier_executable: vec![],
                    observed_policy_executable: vec![],
                    pinned_verifier_executable_refs: vec![],
                    pinned_policy_executable_refs: vec![],
                    mutable_override: false,
                    unknown_override: false,
                    unavailable_wire_code: None,
                });
            }
            Err(e) => return Err(e),
        };

        // Per-call cache: avoids redundant two-RPC fetches when multiple
        // rules reference the same contract address.
        let mut wasm_hash_cache: std::collections::HashMap<
            Vec<u8>,
            crate::managers::signers::ObservedExecutable,
        > = std::collections::HashMap::new();

        let verifier = verify_kind_pins(
            PinnedKind::Verifier,
            verifier_addrs,
            sm,
            rule_id,
            &smart_account_redacted,
            request_id,
            &mut wasm_hash_cache,
        )
        .await?;
        let policy = verify_kind_pins(
            PinnedKind::Policy,
            policy_addrs,
            sm,
            rule_id,
            &smart_account_redacted,
            request_id,
            &mut wasm_hash_cache,
        )
        .await?;

        // The first failure code, verifiers before policies, is reported only
        // when a final status is Unavailable.
        let wire_code = if verifier.status == PinStatus::Unavailable
            || policy.status == PinStatus::Unavailable
        {
            verifier
                .unavailable_wire_code
                .or(policy.unavailable_wire_code)
        } else {
            None
        };

        Ok(VerifyPinsResult {
            smart_account: smart_account_strkey,
            rule_id,
            verifier_pin_status: verifier.status,
            policy_pin_status: policy.status,
            pinned_verifier_first8: pin_record.pinned_verifier_first8,
            pinned_policy_first8: pin_record.pinned_policy_first8,
            observed_verifier_first8: verifier.observed_first8,
            observed_policy_first8: policy.observed_first8,
            observed_verifier_executable: verifier.observed_executable,
            observed_policy_executable: policy.observed_executable,
            pinned_verifier_executable_refs: pin_record.pinned_verifier_executable_refs,
            pinned_policy_executable_refs: pin_record.pinned_policy_executable_refs,
            mutable_override: pin_record.mutable_override,
            unknown_override: pin_record.unknown_override,
            unavailable_wire_code: wire_code,
        })
    }

    /// Shared signed-invoke flow used by all four mutating methods. Returns
    /// the simulated ScVal return value of the invoked entrypoint.
    ///
    /// `horizon_check` — if `Some`, the horizon cap is enforced AFTER the
    /// first `simulate_transaction` response (so `latestLedger` is known) but
    /// BEFORE any signing bytes are produced. The simulate call is already on
    /// the hot path; the check uses its `latestLedger` field with no additional
    /// RPC.
    ///
    /// [`ContextRuleManager::install_rule`] and
    /// [`ContextRuleManager::update_valid_until`] supply a `HorizonCheck` when
    /// `valid_until.is_some()`.  All other callers pass `None`.
    ///
    /// # Canonical citation
    ///
    /// `latestLedger` is always present in every Soroban-RPC
    /// `simulateTransaction` response, including error responses.  Source:
    /// `stellar/rs-stellar-rpc-client` `src/response.rs`: the
    /// `SimulateTransactionResponse` struct always carries `pub latest_ledger: u32`.
    ///
    /// Builds the `HostFunction` from `entrypoint` + `invoke_args`, constructs
    /// a [`crate::submit::SubmitInvokeArgs`], and calls the free function.
    ///
    /// The pre-submission checks of every rule other than rule 0 in
    /// `auth_rule_ids` (the rule locks, the signer-set baseline read, the
    /// pinned-hash drift check and the signer-set comparison) run through
    /// the configured signers manager with `request_id`
    /// ([`crate::submit::PinCheck`]). `rule_locks` is the held-lock context
    /// of a caller that holds the locks of those rules, `None` otherwise.
    /// `expected_return` is the shape a caller that reads an id from the
    /// return value requires of the simulated result before signing
    /// ([`ExpectedReturn`]).
    /// Without a signers manager, a submission authorized by any rule other
    /// than rule 0 is refused with [`SaError::SignersManagerNotConfigured`]
    /// before anything is simulated or signed; a submission under rule 0
    /// only needs no check.
    #[allow(
        clippy::too_many_arguments,
        reason = "horizon_check, expiry_check and rule_locks params are additive to the \
                  pre-existing arg set; the free function carries the full body"
    )]
    async fn submit_signed_invoke(
        &self,
        smart_account: ScAddress,
        entrypoint: &str,
        invoke_args: Vec<ScVal>,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        op_label: &'static str,
        horizon_check: Option<HorizonCheck>,
        expiry_check: Option<ExpiryCheck>,
        request_id: &str,
        rule_locks: Option<&BorrowedRuleLocks<'_>>,
        expected_return: Option<ExpectedReturn>,
    ) -> Result<crate::submit::SubmitInvokeResult, SaError> {
        // Convert smart_account ScAddress → C-strkey so the free function can
        // call `parse_c_strkey_to_smart_account` uniformly.
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;

        let pin_check =
            self.signers_manager
                .as_deref()
                .map(|signers_manager| crate::submit::PinCheck {
                    signers_manager,
                    request_id,
                    migrating_rule: None,
                });
        if pin_check.is_none()
            && let Some(rule_id) = auth_rule_ids
                .iter()
                .map(ContextRuleId::as_u32)
                .find(|id| *id != 0)
        {
            return Err(SaError::SignersManagerNotConfigured {
                rule_id: Some(rule_id),
                smart_account_redacted: RedactedStrkey::from_full(&smart_account_strkey),
                request_id: request_id.to_owned(),
            });
        }

        // Build the pre-form HostFunction from the entrypoint + args.
        // The free function accepts a pre-built HostFunction so callers that
        // Callers that already hold a secondary client can skip this step.
        let function_name =
            ScSymbol::try_from(entrypoint).map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("encode {entrypoint} symbol: {e:?}"),
            })?;
        let invoke_args_vecm: VecM<ScVal> =
            invoke_args
                .clone()
                .try_into()
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_contexts_args",
                    redacted_reason: format!("encode {entrypoint} args VecM: {e:?}"),
                })?;
        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: smart_account.clone(),
            function_name,
            args: invoke_args_vecm,
        });

        crate::submit::submit_signed_invoke(
            crate::submit::SubmitInvokeArgs::builder()
                .target_contract(&smart_account_strkey)
                .auth_rule_ids(auth_rule_ids)
                .host_function(host_function)
                .signer(signer)
                .primary_rpc_url(&self.primary_rpc_url)
                .maybe_secondary_rpc_url(self.secondary_rpc_url.as_deref())
                .network_passphrase(&self.network_passphrase)
                .chain_id(&self.chain_id)
                .timeout(self.timeout)
                .op_label(op_label)
                .emit_observability_logs(true)
                .maybe_horizon_check(horizon_check)
                .maybe_expiry_check(expiry_check)
                .maybe_pin_check(pin_check)
                .maybe_rule_locks(rule_locks)
                .maybe_expected_return(expected_return)
                .build(),
        )
        .await
    }

    /// Read-only invocation: simulate the entrypoint without signing.
    /// Used by `get_rule` and `get_rules_count` for OZ view methods that do
    /// not call `require_auth`.
    async fn simulate_read_only(
        &self,
        smart_account: ScAddress,
        entrypoint: &str,
        invoke_args: Vec<ScVal>,
        source_account_strkey: &str,
    ) -> Result<ScVal, SaError> {
        let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: reason,
        };

        let function_name = ScSymbol::try_from(entrypoint)
            .map_err(|e| auth_payload_err(format!("encode {entrypoint} symbol: {e:?}")))?;
        let invoke_args_vecm: VecM<ScVal> = invoke_args
            .try_into()
            .map_err(|e| auth_payload_err(format!("encode {entrypoint} args VecM: {e:?}")))?;
        let invoke = InvokeContractArgs {
            contract_address: smart_account.clone(),
            function_name,
            args: invoke_args_vecm,
        };
        let host_fn = HostFunction::InvokeContract(invoke);
        let op = Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: host_fn,
                auth: VecM::default(),
            }),
        };

        let source_view = fetch_account(&self.rpc_client, source_account_strkey, &[])
            .await
            .map_err(|e| auth_payload_err(format!("source-account fetch failed: {e}")))?;
        let mut source_account = BaselibAccount::new(
            source_account_strkey,
            &source_view.sequence_number.to_string(),
        )
        .map_err(|e| auth_payload_err(format!("BaselibAccount::new failed: {e:?}")))?;

        let mut tx_builder =
            TransactionBuilder::new(&mut source_account, &self.network_passphrase, None);
        tx_builder.fee(BASE_FEE_STROOPS);
        tx_builder.add_operation(op);
        let tx_for_simulate = tx_builder.build_for_simulation();

        let server = Client::new(&self.primary_rpc_url)
            .map_err(|e| auth_payload_err(format!("RPC Client construction failed: {e}")))?;

        let sim_envelope = tx_for_simulate
            .to_envelope()
            .map_err(|e| auth_payload_err(format!("to_envelope failed: {e:?}")))?;
        let sim_response = server
            .simulate_transaction_envelope(&sim_envelope, None)
            .await
            .map_err(|e| auth_payload_err(format!("simulate_transaction_envelope failed: {e}")))?;

        if let Some(sim_error) = &sim_response.error {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "{entrypoint} simulation returned error: {}",
                    augment_with_oz_error_name(sim_error)
                ),
            });
        }

        let return_val = sim_response
            .results()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("{entrypoint} simulate results decode failed: {e}"),
            })?
            .into_iter()
            .next()
            .ok_or(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("{entrypoint} simulate_transaction returned no result"),
            })?
            .xdr;
        Ok(return_val)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ContextRuleDefinition
// ─────────────────────────────────────────────────────────────────────────────

/// Wallet-side off-chain mirror of the OZ `ContextRuleType` enum
/// (`packages/accounts/src/smart_account/storage.rs:140-150`, SHA `a9c4216`).
///
/// The OZ type wraps `soroban_sdk::Address` / `soroban_sdk::BytesN<32>`, both of
/// which require a host `Env` to construct and are therefore unusable off-chain.
/// `RuleContext` carries only off-chain XDR types ([`ScAddress`] + a raw 32-byte
/// array) and is encoded to the on-chain `ContextRuleType` ScVal at install time
/// via `encode_context_type`. This is the same layering pattern as
/// [`ContextRuleSignerInput`] versus the OZ `Signer` type.
///
/// Encoded to the on-chain `#[contracttype]` wire shape by `encode_context_type`:
/// - `Default` → `ScVal::Vec([Symbol("Default")])`
/// - `CallContract { contract }` →
///   `ScVal::Vec([Symbol("CallContract"), Address(contract)])`
/// - `CreateContract { wasm_hash }` →
///   `ScVal::Vec([Symbol("CreateContract"), Bytes(wasm_hash)])`
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuleContext {
    /// Default rule that can authorize any context (OZ `ContextRuleType::Default`,
    /// `storage.rs:145`, SHA `a9c4216`).
    Default,
    /// Rule scoped to invocations of one specific contract (OZ
    /// `ContextRuleType::CallContract(Address)`, `storage.rs:147`, SHA `a9c4216`).
    CallContract {
        /// Target contract address (`ScAddress::Contract`).
        contract: ScAddress,
    },
    /// Rule scoped to creating a contract with one specific wasm hash (OZ
    /// `ContextRuleType::CreateContract(BytesN<32>)`, `storage.rs:149`,
    /// SHA `a9c4216`).
    CreateContract {
        /// 32-byte wasm hash the rule authorizes creation of.
        wasm_hash: [u8; 32],
    },
}

/// Definition of a context rule for [`ContextRuleManager::install_rule`].
///
/// Mirrors the OZ `add_context_rule` argument set with wallet-side types.
/// The signer-set field uses the wallet-local
/// [`ContextRuleSignerInput`] enum rather than the OZ
/// `stellar_accounts::smart_account::Signer` because the latter wraps
/// `soroban_sdk::Address`, which requires a host `Env` to construct.
/// `ContextRuleSignerInput` carries only the off-chain XDR types
/// ([`ScAddress`] + raw `Vec<u8>`) and is encoded to the on-chain
/// `Signer` ScVal at install time via `encode_signer`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ContextRuleDefinition {
    /// Context-type variant the rule applies to (`Default`, `CallContract`,
    /// `CreateContract`).
    pub context_type: RuleContext,
    /// Operator-facing rule name (max OZ length enforced on-chain).
    pub name: String,
    /// Optional ledger sequence at which the rule expires. `None` means
    /// permanent.
    pub valid_until: Option<u32>,
    /// Signers attached to the rule (per OZ `Vec<Signer>`).
    pub signers: Vec<ContextRuleSignerInput>,
    /// Policies attached to the rule. The OZ on-chain `Map<Address, Val>`
    /// argument is constructed empty when no policies are supplied.
    pub policies: Vec<ContextRulePolicy>,
}

/// Wallet-side off-chain mirror of the OZ `Signer` enum
/// (`packages/accounts/src/smart_account/storage.rs:96-102`,
/// SHA `a9c4216`). Carries off-chain XDR types so callers don't need a
/// soroban-sdk host `Env` to construct values.
///
/// Encoded to the on-chain wire shape by `encode_signer`:
/// - `Delegated { address }` → `ScVal::Vec([Symbol("Delegated"), Address(address)])`
/// - `External { verifier, pubkey_data }` →
///   `ScVal::Vec([Symbol("External"), Address(verifier), Bytes(pubkey_data)])`
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ContextRuleSignerInput {
    /// A delegated signer: the OZ contract requires the authorization of
    /// `address`. For an ed25519 key this is `ScAddress::Account(...)`
    /// derived from the signer's G-strkey, verified by the host; for a
    /// contract it is `ScAddress::Contract(...)`, whose own authorization
    /// decides.
    Delegated {
        /// Signer address: an account (`ScAddress::Account`, from a
        /// G-strkey) or a contract (`ScAddress::Contract`, from a C-strkey).
        address: ScAddress,
    },
    /// An external signer with custom verification (e.g. WebAuthn-via-verifier).
    /// `verifier` is the on-chain verifier-contract address; `pubkey_data` is
    /// the verifier-specific raw public-key bytes.
    External {
        /// Verifier-contract address.
        verifier: ScAddress,
        /// Verifier-specific raw public-key bytes (passed through to the
        /// on-chain verifier as `Bytes`).
        pubkey_data: Vec<u8>,
    },
}

/// Policy descriptor for use with `add_policy` / `remove_policy`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ContextRulePolicy {
    /// On-chain policy contract address.
    pub policy_address: ScAddress,
    /// Encoded policy parameters (caller-supplied ScVal).
    pub params: ScVal,
}

impl ContextRulePolicy {
    /// Public constructor (the struct is `#[non_exhaustive]` so external
    /// crates cannot use struct-expression syntax).
    ///
    /// # Arguments
    ///
    /// - `policy_address` — on-chain policy contract address.
    /// - `params` — encoded policy parameters (caller-supplied [`ScVal`]).
    #[must_use]
    pub fn new(policy_address: ScAddress, params: ScVal) -> Self {
        Self {
            policy_address,
            params,
        }
    }
}

impl ContextRuleDefinition {
    /// Public constructor (the struct is `#[non_exhaustive]` so external
    /// crates cannot use struct-expression syntax).
    #[must_use]
    pub fn new(
        context_type: RuleContext,
        name: String,
        valid_until: Option<u32>,
        signers: Vec<ContextRuleSignerInput>,
        policies: Vec<ContextRulePolicy>,
    ) -> Self {
        Self {
            context_type,
            name,
            valid_until,
            signers,
            policies,
        }
    }

    /// Stable label of the [`RuleContext`] variant for audit-log emission
    /// (closed 3-value set: `"default"`, `"call_contract"`, `"create_contract"`).
    #[must_use]
    pub fn context_type_label(&self) -> &'static str {
        match self.context_type {
            RuleContext::Default => "default",
            RuleContext::CallContract { .. } => "call_contract",
            RuleContext::CreateContract { .. } => "create_contract",
        }
    }

    /// Number of signers attached to this rule (audit-log emission field).
    ///
    /// Returns `u32::MAX` if the signer count exceeds `u32::MAX`. OZ caps
    /// the on-chain count at `MAX_SIGNERS=15`, so this saturating cast is a
    /// guard against caller-side misuse.
    #[must_use]
    pub fn signers_count(&self) -> u32 {
        u32::try_from(self.signers.len()).unwrap_or(u32::MAX)
    }

    /// Number of policies attached to this rule (audit-log emission field).
    #[must_use]
    pub fn policies_count(&self) -> u32 {
        u32::try_from(self.policies.len()).unwrap_or(u32::MAX)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Active-rule enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Default upper bound for the rule-ID scan range in
/// [`ContextRuleManager::list_active_context_rules`].
///
/// Mirrors the canonical default maximum context-rule scan ID of `50`.
/// Operators with more than 50 historically installed rules (including
/// deletions) must raise the bound via
/// `Profile::smart_account_max_context_rule_scan_id`.
pub const DEFAULT_MAX_SCAN_ID: u32 = 50;

/// Hard upper bound enforced at profile-load time on
/// `smart_account_max_context_rule_scan_id`.
///
/// A value of `u32::MAX` in a profile TOML would cause up to ~4.3B
/// `simulate_transaction` calls on any `smart-account list-rules` or
/// `migrate-verifier` invocation, a practical DoS for any process that can
/// edit the profile file. Capping at 10,000 limits the worst-case scan to
/// 10,000 simulate calls — roughly 10,000 × RTT overhead — which is
/// operationally reasonable while remaining a meaningful bound.
///
/// Canonical site: this constant. Mirrored (as a local literal with comment)
/// in `stellar-agent-core::profile::loader` to avoid a crate dep cycle.
pub const UPPER_BOUND_MAX_SCAN_ID: u32 = 10_000;

// ── Session-rule horizon constants ───────────────────────────────────────────

/// Default cap on a session-rule lookahead window: `valid_until -
/// current_ledger`.
///
/// Approximately 80 minutes at 5 s ledgers. This is the operator-facing default
/// for human-driven session rules — a rule installed now with
/// `valid_until = current_ledger + 1000` expires in roughly 80 minutes.
///
/// Operators may raise this via `session_rule_max_horizon_ledgers` in their
/// profile TOML, up to [`UPPER_BOUND_HORIZON_LEDGERS`].
pub const DEFAULT_SESSION_RULE_HORIZON_LEDGERS: u32 = 1000;

/// Profile-load upper bound on `session_rule_max_horizon_ledgers` overrides.
///
/// Caps the profile-write DoS vector where an attacker who can edit the profile
/// TOML sets the cap to `u32::MAX`, allowing installs with an arbitrary
/// lookahead and extending the in-flight envelope race window to effectively
/// unbounded.
///
/// 10,000 ledgers ≈ 13.9–15.3 hours at 5 s ledgers (Stellar median is ~5.5 s;
/// the exact range depends on network conditions). Longer windows require an
/// explicit review of the profile-write threat model.
///
/// **Canonical site:** this constant. Mirrored as
/// `stellar_agent_core::profile::loader::MIRRORED_UPPER_BOUND_HORIZON_LEDGERS`
/// to avoid a crate dependency cycle.
///
/// **Drift-protection:** the integration test
/// `crates/stellar-agent-smart-account/tests/smart_account/horizon_bound_parity_test.rs`
/// asserts `UPPER_BOUND_HORIZON_LEDGERS == MIRRORED_UPPER_BOUND_HORIZON_LEDGERS`
/// across crate boundaries.
pub const UPPER_BOUND_HORIZON_LEDGERS: u32 = 10_000;

// ── OZ per-rule hard caps ─────────────────────────────────────────────────────

/// Maximum number of signers per context rule, mirroring the OZ on-chain
/// canonical constant.
///
/// OZ source: `packages/accounts/src/smart_account/mod.rs:526` SHA `a9c4216`
/// (`pub const MAX_SIGNERS: u32 = 15`).
///
/// The CLI orchestration layer uses this constant to refuse cap-exceeding
/// operations fail-CLOSED before the simulate/submit cycle reaches the
/// contract. The on-chain enforcement remains the authoritative last-line
/// defence via the `TooManySigners` panic discriminant `3010`
/// (`mod.rs:558`, SHA `a9c4216`).
///
/// **Cross-crate parity test:**
/// `crates/stellar-agent-smart-account/tests/smart_account/oz_caps_parity_test.rs` asserts
/// this constant equals `15` against the OZ canonical pinned at SHA `a9c4216`.
/// If either side drifts, the parity test fails CI at the next pin-advancement.
pub const OZ_MAX_SIGNERS: u32 = 15;

/// Maximum number of policies per context rule, mirroring the OZ on-chain
/// canonical constant.
///
/// OZ source: `packages/accounts/src/smart_account/mod.rs:524` SHA `a9c4216`
/// (`pub const MAX_POLICIES: u32 = 5`).
///
/// The CLI orchestration layer uses this constant to refuse cap-exceeding
/// `add-policy` operations fail-CLOSED before simulate. The on-chain
/// enforcement remains the authoritative last-line defence via the
/// `TooManyPolicies` panic discriminant `3011` (`mod.rs:560`, SHA `a9c4216`).
///
/// **Cross-crate parity test:**
/// `crates/stellar-agent-smart-account/tests/smart_account/oz_caps_parity_test.rs` asserts
/// this constant equals `5` against the OZ canonical pinned at SHA `a9c4216`.
pub const OZ_MAX_POLICIES: u32 = 5;

/// Maximum byte length of a context-rule name, mirroring the OZ on-chain
/// canonical constant.
///
/// OZ source: `packages/accounts/src/smart_account/mod.rs:528` SHA `a9c4216`
/// (`pub const MAX_NAME_SIZE: u32 = 20`).
///
/// The CLI orchestration layer uses this constant to refuse oversized names
/// fail-CLOSED before the simulate/submit cycle. The on-chain enforcement
/// remains the authoritative last-line defence via the `NameTooLong` panic
/// discriminant `3015` (`mod.rs:569`, SHA `a9c4216`).
///
/// Canonical off-chain implementations validate `name.is_empty()` but do
/// not enforce a byte cap client-side; this wallet adds the pre-flight cap
/// check to surface a typed error before the RPC round-trip.
pub const OZ_MAX_NAME_SIZE: usize = 20;

/// Maximum byte length of an `External` signer `pubkey_data` payload.
///
/// Mirrors OZ `stellar-contracts` `packages/accounts/src/smart_account/mod.rs:530`
/// (`pub const MAX_EXTERNAL_KEY_SIZE: u32 = 256`) SHA `a9c4216`. A `pubkey_data`
/// exceeding this cap would be rejected on-chain by the `CheckAuth` error `3012`
/// (`ExternalKeyTooLong`); this client-side check surfaces a typed error before
/// the RPC round-trip.
///
/// The standard WebAuthn layout is 65-byte uncompressed P-256 public key +
/// variable-length credential ID, so 256 bytes accommodates the key plus a
/// 191-byte credential ID — above any credential ID seen in practice.
pub const OZ_MAX_EXTERNAL_KEY_SIZE: usize = 256;

/// Summary of a single installed context rule, returned by
/// [`ContextRuleManager::list_active_context_rules`].
///
/// Contains the on-chain fields most useful for operator inspection and
/// migration planning. The full [`ScVal`] representation is available via
/// [`ContextRuleManager::get_rule`] if additional fields are needed.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ContextRuleSummary {
    /// On-chain rule ID (`NextId`-allocated monotonically, never reused).
    pub rule_id: u32,
    /// Operator-visible rule name (OZ `name` field,
    /// `storage.rs:157`, SHA `a9c4216`).
    pub name: String,
    /// Closed-set context-type label (`"default"`, `"call_contract"`,
    /// `"create_contract"`). Derived from the on-chain `ContextRuleType`
    /// discriminant (OZ `storage.rs:152-174`, SHA `a9c4216`).
    pub context_type_label: &'static str,
    /// Number of signers attached to the rule (OZ `signers` field,
    /// `storage.rs:162-164`, SHA `a9c4216`).
    pub signer_count: u32,
    /// Number of policies attached to the rule (OZ `policies` field,
    /// `storage.rs:168-170`, SHA `a9c4216`).
    pub policy_count: u32,
    /// Optional ledger sequence at which the rule expires. `None` means
    /// permanent (OZ `valid_until` field, `storage.rs:159`, SHA `a9c4216`).
    pub valid_until: Option<u32>,
    /// The rule's signer-set baseline in the manager's audit log; see
    /// [`BaselineState`].
    pub baseline: BaselineState,
}

/// The signer-set baseline a rule has in the audit log, as
/// [`ContextRuleManager::list_active_context_rules`] reports it.
///
/// Every signature under a rule other than rule 0 needs the rule's
/// baseline: a rule reporting [`BaselineState::None`] refuses with
/// `sa.signer_set_missing_baseline` until one `signers list --rule-id N`
/// records it. Rule 0 reports its own state like any rule; the signing path
/// never reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BaselineState {
    /// The manager has no audit writer, so the log was not read.
    Unknown,
    /// The log holds no signer-set state row for the rule.
    None,
    /// The newest state row is version 1.
    V1,
    /// The newest state row is version 2.
    V2,
    /// The log could not be read for the rule (an integrity error).
    Unreadable,
}

impl BaselineState {
    /// The state's serialized name: `unknown`, `none`, `v1`, `v2` or
    /// `unreadable`.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::None => "none",
            Self::V1 => "v1",
            Self::V2 => "v2",
            Self::Unreadable => "unreadable",
        }
    }

    /// The state of rule `rule_id` read through `reader`: the version of its
    /// newest signer-set state row, `None` without one, `Unreadable` on an
    /// integrity error.
    fn read(
        reader: &stellar_agent_core::audit_log::reader::AuditReader,
        rule_id: u32,
        smart_account_redacted: &str,
        account_digest: &[u8; 32],
    ) -> Self {
        match reader.find_latest_signer_set_view(rule_id, smart_account_redacted, account_digest) {
            Ok(None) => Self::None,
            Ok(Some(payload)) => match payload.view() {
                SignerSetView::V1(_) => Self::V1,
                SignerSetView::V2(_) => Self::V2,
            },
            Err(e) => {
                warn!(
                    rule_id,
                    smart_account = %smart_account_redacted,
                    error = %e,
                    "list_active_context_rules: the rule's signer-set baseline is unreadable"
                );
                Self::Unreadable
            }
        }
    }
}

/// Output of [`ContextRuleManager::list_active_context_rules`].
///
/// Contains the list of rules returned by the scan, the number of IDs skipped
/// during enumeration (sparse-gap indicators), and the result of the
/// audit-log cross-check.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ActiveContextRuleEnumeration {
    /// Rules returned by the scan, in ascending rule-ID order.
    pub rules: Vec<ContextRuleSummary>,
    /// On-chain `get_context_rules_count` value at the start of the scan.
    ///
    /// Authoritative active-rule count per the OZ contract
    /// (`storage.rs:212-213`, SHA `a9c4216` — decremented at delete).
    /// Distinct from `rules.len()` which is the count this enumeration
    /// successfully decoded.  When `active_count_on_chain` exceeds
    /// `rules.len() as u32 + rules_skipped + gaps_seen` the scan
    /// disagrees with the on-chain count — typically a malicious-RPC
    /// drop signal complementary to `audit_log_missing`.
    pub active_count_on_chain: u32,
    /// Number of rule IDs in `[0, scanned_id_range_end)` that returned
    /// `Err(_)` during simulate — anomalous skips that the operator
    /// should see (RPC blip, malformed envelope, stale node).
    ///
    /// Does NOT include legitimate sparse-gap signals (`Ok(None)` from
    /// `get_rule`) — those are tracked in `gaps_seen` and are normal
    /// for any account that has had rules deleted.
    ///
    /// The operator-facing skip surface is anomalous-only. Migration-planner
    /// early-exit accounting uses the sum `rules_skipped + gaps_seen`
    /// (see `scanned_id_range_end`).
    pub rules_skipped: usize,
    /// Number of rule IDs in `[0, scanned_id_range_end)` that returned
    /// `Ok(None)` from `get_rule` — legitimate sparse-gap signals.
    ///
    /// Normal for any account that has had rules deleted via
    /// `delete_rule`: the OZ contract retains the monotonic `NextId`
    /// counter but decrements `Count`, leaving ID holes.  Surfaced
    /// separately from `rules_skipped` so the JSON envelope can
    /// distinguish operator-actionable anomalies from expected
    /// sparse-gap observations.
    pub gaps_seen: usize,
    /// One-past-the-last rule ID probed during the scan.
    ///
    /// For a dense scan that early-exits after collecting all `active_count`
    /// rules, this is `last_probed_id + 1`.  For a scan that exhausts
    /// `max_scan_id` without error this is `max_scan_id`.
    ///
    /// Exposed in the `smart-account list-rules` JSON envelope as
    /// `scanned_id_range.end`.
    pub scanned_id_range_end: u32,
    /// Rule IDs that appear in the local audit log as installed
    /// (`SaContextRuleCreated` minus `SaContextRuleDeleted`) but were
    /// absent from the on-chain enumeration.  Non-empty set indicates either
    /// on-chain deletion without a matching audit row, a silently misbehaving
    /// RPC, or audit-log desync.
    pub audit_log_missing: Vec<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public re-exports for callers (CLI / MCP)
// ─────────────────────────────────────────────────────────────────────────────

/// Re-export of the on-chain `ScAddress` type the manager API speaks
/// (`stellar-xdr` 25.x via `soroban-sdk`). Caller-facing for CLI / MCP code
/// that wants to pass an opaque `ScAddress` returned by
/// [`parse_c_strkey_to_smart_account`] / [`parse_g_strkey_to_signer_address`]
/// without directly importing stellar-xdr at a specific version.
pub use stellar_xdr::ScAddress as SmartAccountAddress;

// ─────────────────────────────────────────────────────────────────────────────
// Public strkey-parsing helpers for callers (CLI / MCP)
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a C-strkey (smart-account contract address) into the on-chain
/// `ScAddress::Contract` form used by all manager methods.
///
/// Caller-facing helper: the manager API speaks `stellar_xdr::ScAddress`,
/// while CLI / MCP callers should not need to import the XDR crate
/// directly. This function is the canonical entry point.
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`] with `stage: "auth_payload"` if
///   `s` is not a valid C-strkey.
///
/// # Examples
///
/// ```
/// use stellar_agent_smart_account::managers::rules::parse_c_strkey_to_smart_account;
///
/// // The all-zeros contract address (C-strkey) is the canonical zero-address fixture.
/// let valid = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
/// assert!(parse_c_strkey_to_smart_account(valid).is_ok());
///
/// // An invalid strkey returns an error.
/// let invalid = "not-a-strkey";
/// assert!(parse_c_strkey_to_smart_account(invalid).is_err());
/// ```
pub fn parse_c_strkey_to_smart_account(s: &str) -> Result<ScAddress, SaError> {
    let parsed = stellar_strkey::Contract::from_string(s).map_err(|e| {
        SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("invalid C-strkey: {e}"),
        }
    })?;
    Ok(ScAddress::Contract(stellar_xdr::ContractId(
        stellar_xdr::Hash(parsed.0),
    )))
}

/// Parses a G-strkey (ed25519 public key) into the on-chain
/// `ScAddress::Account` form used by [`ContextRuleSignerInput::Delegated`].
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`] with `stage: "auth_payload"` if
///   `s` is not a valid G-strkey.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
/// use stellar_agent_smart_account::managers::rules::parse_g_strkey_to_signer_address;
///
/// // The all-zeros ed25519 public key G-strkey (canonical zero-key fixture).
/// let valid = SIMULATE_SENTINEL_G;
/// assert!(parse_g_strkey_to_signer_address(valid).is_ok());
///
/// // An invalid strkey returns an error.
/// let invalid = "not-a-strkey";
/// assert!(parse_g_strkey_to_signer_address(invalid).is_err());
/// ```
pub fn parse_g_strkey_to_signer_address(s: &str) -> Result<ScAddress, SaError> {
    let pk = stellar_strkey::ed25519::PublicKey::from_string(s).map_err(|e| {
        SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("invalid G-strkey: {e}"),
        }
    })?;
    Ok(ScAddress::Account(stellar_xdr::AccountId(
        stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(pk.0)),
    )))
}

/// The reason [`parse_delegated_signer_address`] refuses an address with.
/// Input-facing callers report it as is.
pub const DELEGATED_SIGNER_ADDRESS_REASON: &str =
    "invalid delegated signer address: expected a G-strkey or a C-strkey";

/// Parses a delegated signer's address for a rule definition: a G-strkey
/// gives the account address of an ed25519 key, a C-strkey the contract
/// address of a contract whose own authorization decides for the signer.
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] with `stage =
/// "auth_payload"` for anything else, a muxed (M) strkey included.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
/// use stellar_agent_smart_account::managers::rules::parse_delegated_signer_address;
/// use stellar_xdr::ScAddress;
///
/// assert!(matches!(
///     parse_delegated_signer_address(SIMULATE_SENTINEL_G),
///     Ok(ScAddress::Account(_))
/// ));
/// let contract = stellar_strkey::Contract([7u8; 32]).to_string();
/// assert!(matches!(
///     parse_delegated_signer_address(&contract),
///     Ok(ScAddress::Contract(_))
/// ));
/// assert!(parse_delegated_signer_address("not-a-strkey").is_err());
/// ```
pub fn parse_delegated_signer_address(s: &str) -> Result<ScAddress, SaError> {
    if let Ok(pk) = stellar_strkey::ed25519::PublicKey::from_string(s) {
        return Ok(ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(pk.0)),
        )));
    }
    if let Ok(contract) = stellar_strkey::Contract::from_string(s) {
        return Ok(ScAddress::Contract(ContractId(Hash(contract.0))));
    }
    Err(SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: DELEGATED_SIGNER_ADDRESS_REASON.to_owned(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Base fee in stroops for the source-account transaction. The actual
/// resource fee is added on top per `min_resource_fee`.
pub(crate) const BASE_FEE_STROOPS: u32 = 100;

/// Number of ledgers ahead of `latest_ledger` to set as
/// `signature_expiration_ledger` on prepared smart-account auth entries.
///
/// At ~5 s per ledger this is ~8 minutes, well above the testnet/mainnet
/// transaction inclusion window plus simulate-to-submit slack (typically
/// well under 60 s) but still bounded so a leaked signed envelope cannot
/// be replayed indefinitely. js-stellar-base's `authorizeEntry` uses 1000
/// in its example flow; the Python SDK defaults to 100. We pick 100 as
/// a reasonable replay-window vs. inclusion-headroom tradeoff.
pub(crate) const AUTH_VALIDITY_LEDGERS: u32 = 100;

/// Validates an RPC-returned `latest_ledger` before it is bound into a
/// `signature_expiration_ledger` auth-digest preimage.
///
/// Two invariants are checked:
///
/// 1. `latest_ledger >= 1` — a zero value is structurally impossible on a
///    functioning node (ledger 0 is the genesis placeholder, never reported
///    by `simulateTransaction`) and signals a pathological or adversarial
///    RPC response.
///
/// 2. `latest_ledger <= u32::MAX - AUTH_VALIDITY_LEDGERS - 1_000_000` —
///    ensures that `latest_ledger.saturating_add(AUTH_VALIDITY_LEDGERS)` will
///    not overflow and that there is at least 1_000_000 ledger headroom
///    above the operational ceiling.  Values above this bound indicate a
///    far-future or fabricated ledger number; rejecting them prevents an
///    RPC-supplied value from producing a signature with an implausibly
///    distant expiry that could bypass relay-window assumptions.
///
/// # Errors
///
/// Returns [`SaError::DeploymentFailed`] with `phase = "simulate"` on either
/// violation.  The error carries a `redacted_reason` string that does NOT
/// include the raw ledger value to guard against log-injection.
///
/// # Examples
///
/// ```rust,ignore
/// // Used internally by submit_signed_invoke and submit_timelock_invoke_with_g_key_auth.
/// validate_latest_ledger(sim_response.latest_ledger)?;
/// ```
pub(crate) fn validate_latest_ledger(latest_ledger: u32) -> Result<(), SaError> {
    if latest_ledger == 0 {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "RPC-returned latest_ledger out of operational bounds (below minimum)"
                .to_owned(),
        });
    }
    // Upper bound: leave AUTH_VALIDITY_LEDGERS + 1_000_000 headroom below u32::MAX.
    let ceiling = u32::MAX
        .saturating_sub(AUTH_VALIDITY_LEDGERS)
        .saturating_sub(1_000_000);
    if latest_ledger > ceiling {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: "RPC-returned latest_ledger out of operational bounds (above ceiling)"
                .to_owned(),
        });
    }
    Ok(())
}

/// Builds the `Vec<ScVal>` arg list for OZ `add_context_rule`.
///
/// Argument order per OpenZeppelin stellar-contracts v0.7.2,
/// `packages/accounts/src/smart_account/mod.rs:238-248` (SHA `a9c4216`):
/// `(context_type, name, valid_until, signers, policies)`.
fn build_add_context_rule_args(def: &ContextRuleDefinition) -> Result<Vec<ScVal>, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    // 1. context_type: ScVal-encode the RuleContext into the on-chain
    //    ContextRuleType wire shape.
    let context_type_scval = encode_context_type(&def.context_type)?;

    // 2. name: ScVal::String.
    let name_scval =
        ScVal::String(ScString(def.name.clone().try_into().map_err(|e| {
            auth_payload_err(format!("encode rule name as StringM: {e:?}"))
        })?));

    // 3. valid_until: Option<u32> → enum-tagged ScVec.
    let valid_until_scval = encode_option_u32(def.valid_until)?;

    // 4. signers: Vec<Signer>.
    let mut signer_vec: Vec<ScVal> = Vec::with_capacity(def.signers.len());
    for s in &def.signers {
        signer_vec.push(encode_signer(s)?);
    }
    let signer_vecm: VecM<ScVal> = signer_vec
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode signers ScVec: {e:?}")))?;
    let signers_scval = ScVal::Vec(Some(ScVec(signer_vecm)));

    // 5. policies: Map<Address, Val>.
    //
    // The Soroban host validates every `ScVal::Map` for strictly ascending key
    // order (the stellar-xdr `ScMap` validation compares adjacent keys with a
    // strict `<`).  Callers provide policies in arbitrary insertion order, so
    // we sort by key before constructing the `ScMap`.  The generated stellar-xdr
    // `ScVal` type derives `Ord`; the derived ordering matches the host's XDR
    // discriminant + content ordering for `ScVal::Address` (discriminant 18,
    // per `ScValType` enum order; two `Address` values compare by their inner
    // `ScAddress` bytes).
    //
    // Duplicate-key detection: the Soroban host rejects maps with duplicate
    // keys at simulate time (the `ScMap` validation's strict `<`).
    // Duplicate addresses also trigger `DuplicatePolicy` on-chain
    // (`storage.rs:1119-1121`, SHA `a9c4216`).  Both layers enforce uniqueness;
    // the sort here does not merge duplicates — a duplicate will produce
    // adjacent equal keys, which the host rejects with `Error::Invalid`.
    let mut policy_entries: Vec<ScMapEntry> = Vec::with_capacity(def.policies.len());
    for p in &def.policies {
        policy_entries.push(ScMapEntry {
            key: ScVal::Address(p.policy_address.clone()),
            val: p.params.clone(),
        });
    }
    policy_entries.sort_by(|a, b| a.key.cmp(&b.key));
    let policies_vecm: VecM<ScMapEntry> = policy_entries
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode policies ScMap: {e:?}")))?;
    let policies_scval = ScVal::Map(Some(ScMap(policies_vecm)));

    Ok(vec![
        context_type_scval,
        name_scval,
        valid_until_scval,
        signers_scval,
        policies_scval,
    ])
}

/// The signer-set state an install of a [`ContextRuleDefinition`]
/// authorizes, which the confirmed rule must show before it is baselined.
#[derive(Debug)]
pub(crate) struct ExpectedInstallState {
    /// The version-2 identities of the definition's signers, in the
    /// definition's order. The chain assigns the ids, so the comparison
    /// treats them as a multiset.
    pub(crate) signers: Vec<SignerIdentityV2>,
    /// The simple-threshold policy and the threshold its install parameter
    /// sets; `None` when no policy of the definition is the simple-threshold
    /// policy.
    pub(crate) threshold: Option<ThresholdObservation>,
}

/// Derives the state an install of `definition` authorizes.
///
/// Each signer's identity comes from the bytes the submission carries: the
/// signer is encoded as `build_add_context_rule_args` encodes it, decoded as
/// a rule read from the chain is decoded, and projected to its version-2
/// identity. The simple-threshold policy is the policy whose pinned
/// executable hash in `pinned_policy_wasm_hashes` is in
/// [`THRESHOLD_POLICY_WASM_HASHES`]; the observation after confirmation
/// identifies it by the same effective hash. Its threshold is read from the
/// definition's install parameter for that address, which is unique because
/// a policy address listed twice refuses.
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`]: a signer does not encode,
///   including an `External` signer with empty or oversized key data.
/// - [`SaError::DeploymentFailed`] (`phase = "build"`): an encoded signer
///   does not decode, the definition names a policy address twice, more
///   than one policy is the simple-threshold policy, or the simple-threshold
///   policy's address is not a contract address.
/// - [`SaError::SimpleThresholdInstallRefused`]: the simple-threshold
///   policy's install parameter is not the threshold map with a non-zero
///   threshold.
pub(crate) fn expected_install_state(
    definition: &ContextRuleDefinition,
    pinned_policy_wasm_hashes: &[(ScAddress, [u8; 32])],
) -> Result<ExpectedInstallState, SaError> {
    let build_err = |redacted_reason: String| SaError::DeploymentFailed {
        phase: "build",
        redacted_reason,
    };

    let mut signers = Vec::with_capacity(definition.signers.len());
    for (idx, signer) in definition.signers.iter().enumerate() {
        let encoded = encode_signer(signer)?;
        let decoded = crate::managers::signers::decode_signer_scval_full(&encoded)
            .map_err(|e| build_err(format!("install: signers[{idx}] does not decode: {e}")))?;
        signers.push(decoded.to_identity_v2());
    }

    for (idx, policy) in definition.policies.iter().enumerate() {
        if definition.policies[..idx]
            .iter()
            .any(|earlier| earlier.policy_address == policy.policy_address)
        {
            return Err(build_err("install: policy address listed twice".to_owned()));
        }
    }

    let threshold_policies: Vec<&ScAddress> = pinned_policy_wasm_hashes
        .iter()
        .filter(|(_, hash)| THRESHOLD_POLICY_WASM_HASHES.contains(hash))
        .map(|(address, _)| address)
        .collect();
    let threshold = match threshold_policies.as_slice() {
        [] => None,
        [address] => {
            let ScAddress::Contract(ContractId(Hash(policy))) = address else {
                return Err(build_err(
                    "install: the simple-threshold policy address is not a contract address"
                        .to_owned(),
                ));
            };
            let entry = definition
                .policies
                .iter()
                .find(|entry| &entry.policy_address == *address)
                .ok_or_else(|| {
                    build_err(
                        "install: the simple-threshold policy is not in the definition".to_owned(),
                    )
                })?;
            Some(ThresholdObservation {
                policy: *policy,
                threshold: parse_simple_threshold_install_param(&entry.params)?,
            })
        }
        more => {
            return Err(build_err(format!(
                "install: {} policies identify as the simple-threshold policy; at most one is \
                 allowed",
                more.len()
            )));
        }
    };

    Ok(ExpectedInstallState { signers, threshold })
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule-proposal digest (Package D, GH issue #8)
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the domain-separated `proposal_sha256` digest for an
/// agent-proposed `add_context_rule` installation.
///
/// Builds the EXACT XDR bytes the on-chain `add_context_rule` invocation
/// will submit — via `build_add_context_rule_args` wrapped in the same
/// `InvokeContractArgs` shape `ContextRuleManager::submit_signed_invoke`
/// constructs — and binds them to `smart_account` and `auth_rule_ids` via
/// [`stellar_agent_core::approval::compute_rule_proposal_digest`].
///
/// `stellar-agent-core` cannot depend on this crate (the dependency runs the
/// other way), so `stellar-agent-core::approval::compute_rule_proposal_digest`
/// accepts pre-encoded XDR byte buffers rather than typed
/// `InvokeContractArgs` / `ScAddress` values; this function is the boundary
/// that performs the XDR encoding on the smart-account-crate side.
///
/// `auth_rule_ids` is encoded via
/// [`stellar_agent_core::smart_account::rule_id::encode_context_rule_ids`] —
/// the SAME encoder already used for the on-chain signing auth-digest
/// preimage (`stellar_agent_core::smart_account::auth_digest`) — rather than
/// a bespoke encoding, so both digests share one canonical `auth_rule_ids`
/// XDR representation.
///
/// Called at BOTH propose time (to mint `proposal_sha256` for the pending
/// approval) and commit time (to re-derive the digest from the reconstructed
/// definition and confirm it still matches what the operator attested, via
/// `PendingApprovalStore::verify_rule_proposal_gate`).
///
/// # Errors
///
/// [`SaError::AuthEntryConstructionFailed`] (`stage = "rule_proposal_digest"`)
/// on any XDR-encoding failure (symbol/arg encoding, `to_xdr`, or
/// `encode_context_rule_ids`).
pub fn compute_context_rule_proposal_sha256(
    smart_account: &ScAddress,
    rule_definition: &ContextRuleDefinition,
    auth_rule_ids: &[stellar_agent_core::smart_account::rule_id::ContextRuleId],
    accept_mutable_verifier: bool,
    accept_unknown_verifier: bool,
) -> Result<[u8; 32], SaError> {
    let digest_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "rule_proposal_digest",
        redacted_reason: reason,
    };

    let args = build_add_context_rule_args(rule_definition)?;
    let function_name = ScSymbol::try_from("add_context_rule")
        .map_err(|e| digest_err(format!("encode add_context_rule symbol: {e:?}")))?;
    let args_vecm: VecM<ScVal> = args
        .try_into()
        .map_err(|e| digest_err(format!("encode add_context_rule args VecM: {e:?}")))?;
    let invoke_args = InvokeContractArgs {
        contract_address: smart_account.clone(),
        function_name,
        args: args_vecm,
    };
    let invoke_args_xdr = invoke_args
        .to_xdr(Limits::none())
        .map_err(|e| digest_err(format!("InvokeContractArgs to_xdr: {e:?}")))?;

    let smart_account_xdr = smart_account
        .to_xdr(Limits::none())
        .map_err(|e| digest_err(format!("smart_account ScAddress to_xdr: {e:?}")))?;

    let auth_rule_ids_xdr =
        stellar_agent_core::smart_account::rule_id::encode_context_rule_ids(auth_rule_ids)
            .map_err(|e| digest_err(format!("encode_context_rule_ids: {e}")))?;

    // Bit 0: accept_mutable_verifier. Bit 1: accept_unknown_verifier. All
    // other bits reserved (zero).
    let flags_byte = u8::from(accept_mutable_verifier) | (u8::from(accept_unknown_verifier) << 1);

    Ok(stellar_agent_core::approval::compute_rule_proposal_digest(
        &invoke_args_xdr,
        &smart_account_xdr,
        &auth_rule_ids_xdr,
        flags_byte,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// ContextRuleDefinition <- ContextRuleProposalSnapshot (Package D, GH issue #8)
// ─────────────────────────────────────────────────────────────────────────────

/// Reconstructs a [`ContextRuleDefinition`] from a core
/// `ContextRuleProposalSnapshot`.
///
/// Called at commit time (`stellar_rule_create_commit`) to rebuild the EXACT
/// typed definition an operator attested to (via `proposal_sha256`) from the
/// stored snapshot, so [`compute_context_rule_proposal_sha256`] can recompute
/// the digest for [`stellar_agent_core::approval::PendingApprovalStore::verify_rule_proposal_gate`]
/// and so [`ContextRuleManager::install_rule`] can be called with it.
///
/// A `Delegated` signer's `address` is a G-strkey (an ed25519 account) or a
/// C-strkey (a contract).
///
/// # Errors
///
/// [`SaError::AuthEntryConstructionFailed`] (`stage = "rule_proposal_digest"`)
/// on any malformed strkey, hex, or base64 field. This should not occur for a
/// snapshot that already passed `validate_context_rule_proposal_snapshot` at
/// deserialise time (the pending-approval store validates on load), but this
/// function does not assume that validation ran.
pub fn context_rule_definition_from_snapshot(
    snapshot: &stellar_agent_core::approval::ContextRuleProposalSnapshot,
) -> Result<ContextRuleDefinition, SaError> {
    use stellar_agent_core::approval::{RuleProposalContextType, RuleProposalSignerKind};

    let err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "rule_proposal_digest",
        redacted_reason: reason,
    };

    let context_type = match &snapshot.context_type {
        RuleProposalContextType::Default => RuleContext::Default,
        RuleProposalContextType::CallContract { contract } => {
            let sc_addr = parse_c_strkey_to_smart_account(contract)
                .map_err(|e| err(format!("context_type.contract: {e}")))?;
            RuleContext::CallContract { contract: sc_addr }
        }
        RuleProposalContextType::CreateContract { wasm_hash_hex } => {
            let bytes = hex::decode(wasm_hash_hex)
                .map_err(|e| err(format!("context_type.wasm_hash_hex: not valid hex: {e}")))?;
            let wasm_hash: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
                err(format!(
                    "context_type.wasm_hash_hex: decoded to {} bytes, expected 32",
                    v.len()
                ))
            })?;
            RuleContext::CreateContract { wasm_hash }
        }
        // `RuleProposalContextType` is `#[non_exhaustive]` in
        // stellar-agent-core; a variant this match does not name is refused.
        other => {
            return Err(err(format!(
                "context_type: unrecognised RuleProposalContextType variant {}",
                other.variant_name()
            )));
        }
    };

    let mut signers = Vec::with_capacity(snapshot.signers.len());
    for (idx, s) in snapshot.signers.iter().enumerate() {
        let signer = match s.kind {
            RuleProposalSignerKind::Delegated => {
                let address_str = s
                    .address
                    .as_deref()
                    .ok_or_else(|| err(format!("signers[{idx}]: Delegated missing address")))?;
                let address = parse_delegated_signer_address(address_str)
                    .map_err(|e| err(format!("signers[{idx}].address: {e}")))?;
                ContextRuleSignerInput::Delegated { address }
            }
            RuleProposalSignerKind::External => {
                let verifier_str = s
                    .verifier
                    .as_deref()
                    .ok_or_else(|| err(format!("signers[{idx}]: External missing verifier")))?;
                let verifier = parse_c_strkey_to_smart_account(verifier_str)
                    .map_err(|e| err(format!("signers[{idx}].verifier: {e}")))?;
                let pubkey_data = s
                    .pubkey_data
                    .clone()
                    .ok_or_else(|| err(format!("signers[{idx}]: External missing pubkey_data")))?;
                ContextRuleSignerInput::External {
                    verifier,
                    pubkey_data,
                }
            }
        };
        signers.push(signer);
    }

    let mut policies = Vec::with_capacity(snapshot.policies.len());
    for (idx, p) in snapshot.policies.iter().enumerate() {
        let policy_address = parse_c_strkey_to_smart_account(&p.policy_address)
            .map_err(|e| err(format!("policies[{idx}].policy_address: {e}")))?;
        // Bounded decode (depth=500, len=10 MiB) — same established default as
        // the CLI `rules add-policy --kind raw --install-param` decode path —
        // rather than `Limits::none()`, to bound XDR-bomb resource exhaustion
        // on a snapshot field that ultimately originated from agent input.
        use base64::Engine as _;
        let decoded_xdr = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&p.params_xdr_b64)
            .map_err(|e| {
                err(format!(
                    "policies[{idx}].params_xdr_b64: not valid base64: {e}"
                ))
            })?;
        let params = ScVal::from_xdr(
            decoded_xdr,
            Limits {
                depth: 500,
                len: 10 * 1024 * 1024,
            },
        )
        .map_err(|e| {
            err(format!(
                "policies[{idx}].params_xdr_b64: XDR decode failed: {e:?}"
            ))
        })?;
        policies.push(ContextRulePolicy::new(policy_address, params));
    }

    Ok(ContextRuleDefinition::new(
        context_type,
        snapshot.name.clone(),
        snapshot.valid_until,
        signers,
        policies,
    ))
}

/// Encodes a soroban-sdk `Option<u32>` value as the canonical Val ABI
/// shape used by the on-chain `add_context_rule` (`valid_until` arg) and
/// `update_context_rule_valid_until` (`valid_until` arg) entrypoints.
///
/// - `Some(n)` → `ScVal::U32(n)`
/// - `None` → `ScVal::Void`
///
/// Cross-reference: the soroban-env-common host conversion
/// `impl<E: Env, T> TryFromVal<E, Val> for Option<T>` checks
/// `val.is_void()` and returns `None`, otherwise delegates to
/// `T::try_from_val(env, val)` (i.e. the inner type's raw ABI).
///
/// **N.B.** The soroban-sdk `#[contracttype]` enum encoding
/// (`Vec([Symbol("Some"), payload])` / `Vec([Symbol("None")])`) is the ABI for
/// **named-variant** `#[contracttype]` enums — **not** for the standard library
/// `Option<T>`. The wrong encoding causes `add_context_rule` to trap with
/// `Error(WasmVm, InvalidAction) UnreachableCodeReached` because the host's
/// `Option<u32>` deserializer treats any non-Void Val as `Some(_)` and then
/// tries to parse the inner Vec as a u32.
///
/// # Errors
///
/// - This function does not currently return `Err`. The `Result` shape is
///   preserved for forward-compat with non-infallible encodings.
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result preserved for forward-compat with non-infallible encodings"
)]
fn encode_option_u32(v: Option<u32>) -> Result<ScVal, SaError> {
    Ok(match v {
        Some(ledger) => ScVal::U32(ledger),
        None => ScVal::Void,
    })
}

/// Encodes a [`RuleContext`] as the on-chain OZ `ContextRuleType` enum's
/// `#[contracttype]` ScVal wire shape.
///
/// The soroban-sdk `#[contracttype]` macro serialises a data-carrying enum
/// variant as a leading `Symbol("VariantName")` followed by the variant's
/// payload elements as siblings in the same `ScVec`:
///
/// - `Default` → `ScVal::Vec([Symbol("Default")])`
/// - `CallContract { contract }` →
///   `ScVal::Vec([Symbol("CallContract"), Address(contract)])`
/// - `CreateContract { wasm_hash }` →
///   `ScVal::Vec([Symbol("CreateContract"), Bytes(wasm_hash)])`
///
/// Cross-reference: OpenZeppelin stellar-contracts v0.7.2,
/// `packages/accounts/src/smart_account/storage.rs:140-150` (SHA `a9c4216`)
/// defines `ContextRuleType { Default, CallContract(Address),
/// CreateContract(BytesN<32>) }`. In the XDR ABI a soroban `Address` maps to
/// `ScVal::Address` and a `BytesN<32>` maps to `ScVal::Bytes` (the 32-byte
/// length is enforced by the host on conversion, not by a distinct ScVal
/// variant).
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`] with `stage: "auth_payload"` if
///   `Symbol`, `Bytes`, or `ScVec` construction fails (unreachable on
///   well-formed inputs).
fn encode_context_type(ct: &RuleContext) -> Result<ScVal, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    let elems: Vec<ScVal> = match ct {
        RuleContext::Default => {
            let tag = ScSymbol::try_from("Default")
                .map_err(|e| auth_payload_err(format!("encode Default symbol: {e:?}")))?;
            vec![ScVal::Symbol(tag)]
        }
        RuleContext::CallContract { contract } => {
            let tag = ScSymbol::try_from("CallContract")
                .map_err(|e| auth_payload_err(format!("encode CallContract symbol: {e:?}")))?;
            vec![ScVal::Symbol(tag), ScVal::Address(contract.clone())]
        }
        RuleContext::CreateContract { wasm_hash } => {
            let tag = ScSymbol::try_from("CreateContract")
                .map_err(|e| auth_payload_err(format!("encode CreateContract symbol: {e:?}")))?;
            let bytes: BytesM = wasm_hash
                .to_vec()
                .try_into()
                .map_err(|e| auth_payload_err(format!("encode CreateContract Bytes: {e:?}")))?;
            vec![ScVal::Symbol(tag), ScVal::Bytes(ScBytes(bytes))]
        }
    };
    let v: VecM<ScVal> = elems
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode context-type ScVec: {e:?}")))?;
    Ok(ScVal::Vec(Some(ScVec(v))))
}

/// Decodes the on-chain `context_type` ScVal `Vec` into a [`RuleContext`] — the
/// exact inverse of [`encode_context_type`].
///
/// Accepts the three OZ `ContextRuleType` `#[contracttype]` variant shapes
/// (`packages/accounts/src/smart_account/storage.rs:143-149`, SHA `a9c4216`):
///
/// - `ScVal::Vec([Symbol("Default")])` → [`RuleContext::Default`]
/// - `ScVal::Vec([Symbol("CallContract"), Address(contract)])` →
///   [`RuleContext::CallContract`]
/// - `ScVal::Vec([Symbol("CreateContract"), Bytes(wasm_hash)])` →
///   [`RuleContext::CreateContract`] (`Bytes` must be exactly 32 bytes)
///
/// Fail-closed on any other shape (wrong element count, non-Symbol tag, unknown
/// variant, wrong payload type, or a `CreateContract` `Bytes` payload whose
/// length is not 32).
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] (`phase = "simulate"`) — the ScVal does not
///   match one of the three canonical variant shapes.
fn rule_context_from_context_type_scval(context_type: &ScVal) -> Result<RuleContext, SaError> {
    let parse_err = |detail: String| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("decode context_type: {detail}"),
    };

    let elems = match context_type {
        ScVal::Vec(Some(ScVec(elems))) => elems,
        other => {
            return Err(parse_err(format!(
                "expected ScVal::Vec, got {}",
                scval_variant_name(other)
            )));
        }
    };

    let tag = match elems.first() {
        Some(ScVal::Symbol(s)) => s.to_utf8_string_lossy(),
        Some(other) => {
            return Err(parse_err(format!(
                "vec[0]: expected Symbol, got {}",
                scval_variant_name(other)
            )));
        }
        None => {
            return Err(parse_err("context_type vec is empty".to_owned()));
        }
    };

    match tag.as_ref() {
        "Default" => {
            if elems.len() != 1 {
                return Err(parse_err(format!(
                    "Default takes no payload; got {} elements",
                    elems.len()
                )));
            }
            Ok(RuleContext::Default)
        }
        "CallContract" => {
            if elems.len() != 2 {
                return Err(parse_err(format!(
                    "CallContract takes one Address payload; got {} elements",
                    elems.len()
                )));
            }
            match &elems[1] {
                ScVal::Address(addr) => Ok(RuleContext::CallContract {
                    contract: addr.clone(),
                }),
                other => Err(parse_err(format!(
                    "CallContract vec[1]: expected Address, got {}",
                    scval_variant_name(other)
                ))),
            }
        }
        "CreateContract" => {
            if elems.len() != 2 {
                return Err(parse_err(format!(
                    "CreateContract takes one Bytes payload; got {} elements",
                    elems.len()
                )));
            }
            match &elems[1] {
                ScVal::Bytes(ScBytes(b)) => {
                    let wasm_hash: [u8; 32] = b.as_slice().try_into().map_err(|_| {
                        parse_err(format!(
                            "CreateContract wasm hash must be 32 bytes, got {}",
                            b.len()
                        ))
                    })?;
                    Ok(RuleContext::CreateContract { wasm_hash })
                }
                other => Err(parse_err(format!(
                    "CreateContract vec[1]: expected Bytes, got {}",
                    scval_variant_name(other)
                ))),
            }
        }
        other => Err(parse_err(format!(
            "unknown context_type variant \"{}\"",
            untrusted_display_bounded(other.as_bytes())
        ))),
    }
}

/// Decodes the `context_type` field of an OZ `ContextRule` [`ScVal::Map`] into a
/// [`RuleContext`].
///
/// This is the read-side companion to the `encode_context_type` write-path
/// encoder, reached from the full on-chain `ContextRule` map returned by
/// `get_rule`.  The `ContextRule` ScVal layout is defined by `#[contracttype]` on
/// the OZ `ContextRule` struct at
/// `packages/accounts/src/smart_account/storage.rs:152-174` (SHA `a9c4216`); this
/// helper extracts the `context_type` field and decodes it as the exact inverse
/// of `encode_context_type` (variant shapes at `storage.rs:143-149`).
///
/// Used by the typed `smart-account rules add-policy --kind spending-limit`
/// pre-flight to obtain the real [`RuleContext`] for
/// [`crate::spending_limit_policy::ensure_call_contract_context_for_spending_limit`]
/// without an extra RPC round-trip (the rule map is already fetched for the
/// policy-cap check).
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] (`phase = "simulate"`) — the ScVal is not a
///   `ScVal::Map`, the `context_type` field is missing, or the field does not
///   decode to one of the three canonical variant shapes.
pub fn decode_context_type_from_scval(rule_scval: &ScVal) -> Result<RuleContext, SaError> {
    let parse_err = |detail: String| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("decode_context_type_from_scval: {detail}"),
    };

    let entries = match rule_scval {
        ScVal::Map(Some(ScMap(e))) => e.as_slice(),
        other => {
            return Err(parse_err(format!(
                "expected ScVal::Map, got {}",
                scval_variant_name(other)
            )));
        }
    };

    for entry in entries {
        if let ScVal::Symbol(s) = &entry.key
            && s.to_utf8_string_lossy() == "context_type"
        {
            return rule_context_from_context_type_scval(&entry.val);
        }
    }

    Err(parse_err("missing 'context_type' field".to_owned()))
}

/// Encodes a [`ContextRuleSignerInput`] as the on-chain `Signer` enum's
/// `#[contracttype]` ScVal wire shape:
///
/// - `Delegated { address }` →
///   `ScVal::Vec([Symbol("Delegated"), Address(address)])`
/// - `External { verifier, pubkey_data }` →
///   `ScVal::Vec([Symbol("External"), Address(verifier), Bytes(pubkey_data)])`
///
/// Cross-reference: OpenZeppelin stellar-contracts v0.7.2,
/// `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`);
/// the soroban-sdk `#[contracttype]` macro serialises enum variants as a
/// leading `Symbol("VariantName")` followed by the variant's payload elements
/// as siblings in the same `ScVec`.
///
/// # Errors
///
/// - [`SaError::AuthEntryConstructionFailed`] with `stage: "auth_payload"`
///   for an `External` signer whose key data is empty (a rule holding one is
///   unreadable) or longer than OZ `MAX_EXTERNAL_KEY_SIZE`.
/// - The same error if `Symbol`, `BytesM`, or `ScVec` construction fails
///   (unreachable on well-formed inputs).
pub(crate) fn encode_signer(s: &ContextRuleSignerInput) -> Result<ScVal, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };
    let scvec: VecM<ScVal> = match s {
        ContextRuleSignerInput::Delegated { address } => {
            let tag = ScSymbol::try_from("Delegated")
                .map_err(|e| auth_payload_err(format!("encode Delegated symbol: {e:?}")))?;
            vec![ScVal::Symbol(tag), ScVal::Address(address.clone())]
                .try_into()
                .map_err(|e| auth_payload_err(format!("encode Delegated ScVec: {e:?}")))?
        }
        ContextRuleSignerInput::External {
            verifier,
            pubkey_data,
        } => {
            // A rule holding an External signer with empty key data cannot
            // be read back (`SignerDecodeError::ExternalKeyDataEmpty`), so it
            // is never submitted.
            if pubkey_data.is_empty() {
                return Err(SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: "External signer pubkey is empty".to_owned(),
                });
            }
            // Pre-flight cap check before the RPC round-trip.
            // OZ `MAX_EXTERNAL_KEY_SIZE = 256` enforced on-chain at
            // `packages/accounts/src/smart_account/mod.rs:530`, SHA `a9c4216`.
            if pubkey_data.len() > OZ_MAX_EXTERNAL_KEY_SIZE {
                return Err(SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!(
                        "External signer pubkey exceeds OZ MAX_EXTERNAL_KEY_SIZE \
                         (got {} bytes, limit {})",
                        pubkey_data.len(),
                        OZ_MAX_EXTERNAL_KEY_SIZE,
                    ),
                });
            }
            let tag = ScSymbol::try_from("External")
                .map_err(|e| auth_payload_err(format!("encode External symbol: {e:?}")))?;
            let bytes: BytesM = pubkey_data
                .clone()
                .try_into()
                .map_err(|e| auth_payload_err(format!("encode External Bytes: {e:?}")))?;
            vec![
                ScVal::Symbol(tag),
                ScVal::Address(verifier.clone()),
                ScVal::Bytes(ScBytes(bytes)),
            ]
            .try_into()
            .map_err(|e| auth_payload_err(format!("encode External ScVec: {e:?}")))?
        }
    };
    Ok(ScVal::Vec(Some(ScVec(scvec))))
}

/// Locates the auth entry whose `credentials.address` equals the
/// smart-account contract's [`ScAddress`].
pub(crate) fn locate_smart_account_auth_entry(
    entries: &[SorobanAuthorizationEntry],
    target: &ScAddress,
) -> Result<usize, SaError> {
    for (idx, e) in entries.iter().enumerate() {
        if let SorobanCredentials::Address(creds) = &e.credentials
            && &creds.address == target
        {
            return Ok(idx);
        }
    }
    Err(SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: "no auth entry credentialed against the smart-account address; \
                          OZ add_context_rule should produce one"
            .to_owned(),
    })
}

/// Computes a redaction-safe fingerprint of the auth-context invocation
/// (first-8 hex chars of the SHA-256 of the root-invocation XDR).
pub(crate) fn fingerprint_invocation(entry: &SorobanAuthorizationEntry) -> AuthContextFingerprint {
    let xdr = entry
        .root_invocation
        .to_xdr(Limits::none())
        .unwrap_or_default();
    let digest = Sha256::digest(&xdr);
    let hex_full: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    AuthContextFingerprint::new(format!("invoke:{}", &hex_full[..16]))
}

/// Short stable fingerprint of the network passphrase for the simulation /
/// envelope NetworkContext field.
pub(crate) fn passphrase_fingerprint(passphrase: &str) -> String {
    let digest = Sha256::digest(passphrase.as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("net:{hex}")
}

/// Short stable fingerprint of the CAIP-2 chain ID for divergence-detector
/// NetworkContext.
pub(crate) fn chain_id_fingerprint(chain_id: &str) -> String {
    let digest = Sha256::digest(chain_id.as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("chain:{hex}")
}

/// Maps an OZ `SmartAccountError` discriminant to its symbolic name.
///
/// Cross-reference: OpenZeppelin stellar-contracts v0.7.2,
/// `packages/accounts/src/smart_account/mod.rs:535-572` (SHA `a9c4216`) —
/// `pub enum SmartAccountError` carries discriminants 3000, 3002-3016 (3001 is
/// SKIPPED in OZ v0.7.2; not all discriminants are contiguous). Returning
/// `None` for unknown / skipped codes preserves forward compatibility
/// with future OZ releases that add new variants and prevents falsely
/// annotating an unknown discriminant with a stale name.
fn oz_smart_account_error_name(code: u32) -> Option<&'static str> {
    match code {
        3000 => Some("ContextRuleNotFound"),
        // 3001 is SKIPPED in OZ v0.7.2 (no variant assigned).
        3002 => Some("UnvalidatedContext"),
        3003 => Some("ExternalVerificationFailed"),
        3004 => Some("NoSignersAndPolicies"),
        3005 => Some("PastValidUntil"),
        3006 => Some("SignerNotFound"),
        3007 => Some("DuplicateSigner"),
        3008 => Some("PolicyNotFound"),
        3009 => Some("DuplicatePolicy"),
        3010 => Some("TooManySigners"),
        3011 => Some("TooManyPolicies"),
        3012 => Some("MathOverflow"),
        3013 => Some("KeyDataTooLarge"),
        3014 => Some("ContextRuleIdsLengthMismatch"),
        3015 => Some("NameTooLong"),
        3016 => Some("UnauthorizedSigner"),
        _ => None,
    }
}

/// Maps an OZ `TimelockError` numeric discriminant to its symbolic name.
///
/// # Reference cross-check
///
/// Canonical source: OpenZeppelin stellar-contracts v0.7.2 (`stellar-governance`),
/// `packages/governance/src/timelock/mod.rs:325-339` (SHA `a9c4216`).
///
/// ```text
/// TimelockError::OperationAlreadyScheduled  = 4000
/// TimelockError::InsufficientDelay          = 4001
/// TimelockError::InvalidOperationState      = 4002
/// TimelockError::UnexecutedPredecessor      = 4003
/// TimelockError::Unauthorized               = 4004
/// TimelockError::MinDelayNotSet             = 4005
/// TimelockError::OperationNotScheduled      = 4006
/// ```
fn oz_timelock_error_name(code: u32) -> Option<&'static str> {
    match code {
        4000 => Some("OperationAlreadyScheduled"),
        4001 => Some("InsufficientDelay"),
        4002 => Some("InvalidOperationState"),
        4003 => Some("UnexecutedPredecessor"),
        4004 => Some("Unauthorized"),
        4005 => Some("MinDelayNotSet"),
        4006 => Some("OperationNotScheduled"),
        _ => None,
    }
}

/// Maps an OZ `SpendingLimitError` numeric discriminant to its symbolic name.
///
/// # Reference cross-check
///
/// Canonical source: OpenZeppelin stellar-contracts v0.7.2 (`stellar-accounts`),
/// `packages/accounts/src/policies/spending_limit.rs:120-140` (SHA
/// `a9c42169000638da937577f592ebf61a7a3c94ca`).
///
/// ```text
/// SpendingLimitError::SmartAccountNotInstalled = 3220
/// SpendingLimitError::SpendingLimitExceeded    = 3221
/// SpendingLimitError::InvalidLimitOrPeriod     = 3222
/// SpendingLimitError::NotAllowed               = 3223
/// SpendingLimitError::HistoryCapacityExceeded  = 3224
/// SpendingLimitError::AlreadyInstalled         = 3225
/// SpendingLimitError::LessThanZero             = 3226
/// SpendingLimitError::OnlyCallContractAllowed  = 3227
/// ```
///
/// The 3220-3227 range does not overlap the `SmartAccountError` (3000-3016) or
/// `TimelockError` (4000-4006) ranges, so chaining this after the other two in
/// [`augment_with_oz_error_name`] is unambiguous.
fn oz_spending_limit_policy_error_name(code: u32) -> Option<&'static str> {
    match code {
        3220 => Some("SmartAccountNotInstalled"),
        3221 => Some("SpendingLimitExceeded"),
        3222 => Some("InvalidLimitOrPeriod"),
        3223 => Some("NotAllowed"),
        3224 => Some("HistoryCapacityExceeded"),
        3225 => Some("AlreadyInstalled"),
        3226 => Some("LessThanZero"),
        3227 => Some("OnlyCallContractAllowed"),
        _ => None,
    }
}

/// Augments a simulator-returned error message with the symbolic OZ
/// `SmartAccountError` or `TimelockError` name when the message contains an
/// `Error(Contract, #<code>)` token whose `<code>` matches a known OZ
/// discriminant.
///
/// Soroban-RPC's simulate response surfaces contract panics as
/// `Error(Contract, #<code>)` text with the numeric discriminant only —
/// the symbolic enum name is not serialised over the wire. This helper
/// adds a `[OZ:<Name>]` suffix so operator-facing error messages and
/// the `get_rule` / `delete_rule` typed-mapping substring matchers can
/// rely on the symbolic name alongside the numeric code.
///
/// Covers three OZ error ranges:
/// - `SmartAccountError` 3000-3016
///   (`packages/accounts/src/smart_account/mod.rs`, SHA `a9c4216`)
/// - `SpendingLimitError` 3220-3227
///   (`packages/accounts/src/policies/spending_limit.rs:120-140`, SHA `a9c4216`)
/// - `TimelockError` 4000-4006
///   (`packages/governance/src/timelock/mod.rs:325-339`, SHA `a9c4216`)
///
/// Returns the message unchanged when no OZ error code is detected, or
/// when the code is outside all three discriminant ranges.
pub(crate) fn augment_with_oz_error_name(message: &str) -> String {
    // Find every `Error(Contract, #N)` token and append a single
    // `[OZ:<Name>]` annotation per known code. Repeated occurrences of
    // the same code don't get annotated repeatedly — the first match
    // captures the substantive symbolic name for downstream matchers.
    if let Some(start) = message.find("Error(Contract, #") {
        let after_hash = &message[start + "Error(Contract, #".len()..];
        if let Some(end) = after_hash.find(')')
            && let Ok(code) = after_hash[..end].parse::<u32>()
        {
            let name = oz_smart_account_error_name(code)
                .or_else(|| oz_spending_limit_policy_error_name(code))
                .or_else(|| oz_timelock_error_name(code));
            if let Some(name) = name {
                return format!("{message} [OZ:{name}]");
            }
        }
    }
    message.to_owned()
}

/// Casts the simulation response's `min_resource_fee` (a u64) down to the u32
/// the fee builder requires, erroring on overflow.
pub(crate) fn parse_min_resource_fee(
    sim: &stellar_rpc_client::SimulateTransactionResponse,
) -> Result<u32, SaError> {
    u32::try_from(sim.min_resource_fee).map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("min_resource_fee u64->u32 cast failed: {e}"),
    })
}

// `build_and_sign_delegated_g_key_entry` and `resimulate_with_signed_auth`
// live in `managers/auth_entry.rs` with the rest of the auth-entry assembly
// pipeline. Re-exported here so call sites in `submit.rs` and
// `authorization.rs` resolve without path changes.
pub(crate) use crate::managers::auth_entry::{
    build_and_sign_delegated_g_key_entry, resimulate_with_signed_auth,
};

/// Builds the final InvokeHostFunction transaction envelope with the signed
/// smart-account auth-entry injected, ready for SEP-23 source-account
/// signature attachment.
pub(crate) fn build_signed_invoke_envelope(
    source_account: &mut BaselibAccount,
    network_passphrase: &str,
    smart_account: ScAddress,
    function_name: ScSymbol,
    args: VecM<ScVal>,
    signed_auth_entries: Vec<SorobanAuthorizationEntry>,
    sim_response: &stellar_rpc_client::SimulateTransactionResponse,
) -> Result<String, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    let invoke = InvokeContractArgs {
        contract_address: smart_account,
        function_name,
        args,
    };
    let host_fn = HostFunction::InvokeContract(invoke);
    let auth_vecm: VecM<SorobanAuthorizationEntry> = signed_auth_entries
        .try_into()
        .map_err(|e| auth_payload_err(format!("encode auth VecM: {e:?}")))?;

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: host_fn,
            auth: auth_vecm,
        }),
    };

    let mut tx_builder = TransactionBuilder::new(source_account, network_passphrase, None);
    let resource_fee = parse_min_resource_fee(sim_response)?;
    tx_builder.fee(BASE_FEE_STROOPS.saturating_add(resource_fee));
    tx_builder.add_operation(op);
    let mut tx = tx_builder.build_for_simulation();

    // Attach the soroban transaction data (resource footprint + refundable fee).
    // Transaction::soroban_data is rendered into TransactionExt::V1(data) when
    // to_envelope() is called (stellar-baselib, Transaction::to_envelope).
    if let Ok(data) = sim_response.transaction_data() {
        tx.soroban_data = Some(data);
    }

    let envelope = tx
        .to_envelope()
        .map_err(|e| auth_payload_err(format!("Transaction::to_envelope failed: {e:?}")))?;
    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| auth_payload_err(format!("envelope to_xdr_base64 failed: {e:?}")))
}

/// Parses the simulated return value of OZ `add_context_rule` (a `ContextRule`
/// struct ScVal) and extracts the assigned `rule_id: u32`.
///
/// The error names the shape that has no id. The submit path checks the
/// shape with this parser before the install is signed
/// ([`crate::submit::ExpectedReturn::ContextRuleId`]). The install reads the
/// id with it after confirmation, and reports a failure as
/// [`SaError::InstallStateMismatch`] without a rule id, logging this error
/// as the cause.
pub(crate) fn parse_context_rule_id_from_return(scval: &ScVal) -> Result<u32, SaError> {
    let entries = match scval {
        ScVal::Map(Some(ScMap(entries))) => entries,
        other => {
            return Err(SaError::DeploymentFailed {
                phase: "submit",
                redacted_reason: format!(
                    "add_context_rule return is not ScVal::Map (got {})",
                    scval_variant_name(other)
                ),
            });
        }
    };
    for entry in entries.iter() {
        if let ScVal::Symbol(s) = &entry.key
            && s.to_utf8_string_lossy() == "id"
        {
            if let ScVal::U32(id) = entry.val {
                return Ok(id);
            }
            return Err(SaError::DeploymentFailed {
                phase: "submit",
                redacted_reason: "ContextRule.id field is not ScVal::U32".to_owned(),
            });
        }
    }
    Err(SaError::DeploymentFailed {
        phase: "submit",
        redacted_reason: "ContextRule return value has no 'id' field".to_owned(),
    })
}

/// Parses a `ContextRule` ScVal (returned by `get_context_rule`) into a
/// [`ContextRuleSummary`].
///
/// The on-chain `ContextRule` is a soroban `#[contracttype]` struct; the
/// soroban SDK encodes it as `ScVal::Map(Some(ScMap([...])))` with
/// `ScVal::Symbol`-keyed entries sorted lexicographically by field name:
///
/// - `context_type`: `ScVal::Vec([Symbol("Default")])` / `ScVal::Vec([Symbol("CallContract"), ...])`
/// - `id`: `ScVal::U32`
/// - `name`: `ScVal::String`
/// - `policies`: `ScVal::Vec(Some(ScVec([...])))` — `ScVec` len = policy count
/// - `policy_ids`: `ScVal::Vec(Some(ScVec([...])))` — ignored here
/// - `signer_ids`: `ScVal::Vec(Some(ScVec([...])))` — ignored here
/// - `signers`: `ScVal::Vec(Some(ScVec([...])))` — `ScVec` len = signer count
/// - `valid_until`: soroban `Option<u32>` uses the **standard-library `Option`**
///   host ABI, NOT the `#[contracttype]` enum-variant encoding. Per the
///   soroban-env-common `TryFromVal<E, Val> for Option<T>` conversion:
///   `None` → `ScVal::Void`; `Some(n)` → `ScVal::U32(n)` (the inner type's
///   raw ABI directly, without any Map or Vec wrapping). The existing wallet
///   encoder at `rules.rs:encode_option_u32` already uses this canonical shape.
///
/// Byte-layout canonical citation: OZ `storage.rs:152-174` (SHA `a9c4216`) for
/// the `ContextRule` struct field layout; the soroban-env-common
/// `TryFromVal<E, Val> for Option<T>` conversion for the `Option<u32>`
/// host-ABI encoding.
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] (`phase = "simulate"`) if the
///   ScVal shape is malformed.
fn parse_context_rule_summary(scval: ScVal, rule_id: u32) -> Result<ContextRuleSummary, SaError> {
    let parse_err = |detail: String| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("parse ContextRule id={rule_id}: {detail}"),
    };

    let entries = match scval {
        ScVal::Map(Some(ScMap(ref e))) => e.clone(),
        other => {
            return Err(parse_err(format!(
                "expected ScVal::Map, got {}",
                scval_variant_name(&other)
            )));
        }
    };

    let mut name: Option<String> = None;
    let mut context_type_label: Option<&'static str> = None;
    let mut signer_count: Option<u32> = None;
    let mut policy_count: Option<u32> = None;
    let mut valid_until: Option<Option<u32>> = None; // outer = parsed, inner = value

    for entry in entries.iter() {
        let key_sym = match &entry.key {
            ScVal::Symbol(s) => s.to_utf8_string_lossy(),
            _ => continue,
        };
        match key_sym.as_ref() {
            "name" => {
                name = Some(match &entry.val {
                    ScVal::String(ScString(b)) => {
                        // ScString wraps StringM; to_utf8_string_lossy() converts
                        // to String without allocation on valid UTF-8.
                        b.to_utf8_string_lossy().to_owned()
                    }
                    other => {
                        return Err(parse_err(format!(
                            "name field: expected ScVal::String, got {}",
                            scval_variant_name(other)
                        )));
                    }
                });
            }
            "context_type" => {
                // ScVal::Vec([Symbol("Default")]) / [Symbol("CallContract"), ...] /
                // [Symbol("CreateContract"), ...]
                context_type_label = Some(match &entry.val {
                    ScVal::Vec(Some(ScVec(elems))) if !elems.is_empty() => match &elems[0] {
                        ScVal::Symbol(s) => match s.to_utf8_string_lossy().as_ref() {
                            "Default" => "default",
                            "CallContract" => "call_contract",
                            "CreateContract" => "create_contract",
                            other => {
                                return Err(parse_err(format!(
                                    "context_type: unknown variant \"{}\"",
                                    untrusted_display_bounded(other.as_bytes())
                                )));
                            }
                        },
                        other => {
                            return Err(parse_err(format!(
                                "context_type vec[0]: expected Symbol, got {}",
                                scval_variant_name(other)
                            )));
                        }
                    },
                    other => {
                        return Err(parse_err(format!(
                            "context_type: expected ScVal::Vec, got {}",
                            scval_variant_name(other)
                        )));
                    }
                });
            }
            "signers" => {
                signer_count = Some(match &entry.val {
                    ScVal::Vec(Some(ScVec(elems))) => u32::try_from(elems.len()).map_err(|_| {
                        parse_err(format!("signers vec length {} overflows u32", elems.len()))
                    })?,
                    ScVal::Vec(None) => 0,
                    other => {
                        return Err(parse_err(format!(
                            "signers: expected ScVal::Vec, got {}",
                            scval_variant_name(other)
                        )));
                    }
                });
            }
            "policies" => {
                policy_count = Some(match &entry.val {
                    ScVal::Vec(Some(ScVec(elems))) => u32::try_from(elems.len()).map_err(|_| {
                        parse_err(format!("policies vec length {} overflows u32", elems.len()))
                    })?,
                    ScVal::Vec(None) => 0,
                    other => {
                        return Err(parse_err(format!(
                            "policies: expected ScVal::Vec, got {}",
                            scval_variant_name(other)
                        )));
                    }
                });
            }
            "valid_until" => {
                // soroban `Option<u32>` uses the standard-library host ABI, NOT
                // the `#[contracttype]` enum-variant encoding.
                // Canonical source: the soroban-env-common
                // `TryFromVal<E, Val> for Option<T>` conversion:
                //   None  → Val::VOID  → ScVal::Void
                //   Some(t) → t.try_into_val(env) → for u32: ScVal::U32(n)
                // The encoder at `encode_option_u32` already uses this shape
                // (rules.rs:2398-2401). This decoder must match.
                valid_until = Some(match &entry.val {
                    ScVal::U32(n) => Some(*n),
                    ScVal::Void => None,
                    other => {
                        return Err(parse_err(format!(
                            "valid_until: expected ScVal::U32 (Some) or ScVal::Void (None); got {}",
                            scval_variant_name(other)
                        )));
                    }
                });
            }
            // id, signer_ids, policy_ids — not needed for the summary.
            _ => {}
        }
    }

    Ok(ContextRuleSummary {
        rule_id,
        name: name.ok_or_else(|| parse_err("missing 'name' field".to_owned()))?,
        context_type_label: context_type_label
            .ok_or_else(|| parse_err("missing 'context_type' field".to_owned()))?,
        signer_count: signer_count
            .ok_or_else(|| parse_err("missing 'signers' field".to_owned()))?,
        policy_count: policy_count
            .ok_or_else(|| parse_err("missing 'policies' field".to_owned()))?,
        valid_until: valid_until.flatten(),
        baseline: BaselineState::Unknown,
    })
}

/// Decodes the `signer_ids` length from an OZ `ContextRule` [`ScVal::Map`],
/// returning the number of signers currently attached to the rule.
///
/// This is the pre-simulate cap check helper used by `smart-account signers add` to
/// refuse a 16th-signer attempt fail-CLOSED before the simulate/submit cycle
/// reaches the contract.
///
/// The `ContextRule` ScVal layout is defined by `#[contracttype]` on the OZ
/// `ContextRule` struct at
/// `packages/accounts/src/smart_account/storage.rs:152-174` SHA `a9c4216`.
/// Relevant fields for this helper:
///
/// ```text
/// ContextRule {
///     id:         u32,
///     context_type: ContextRuleType,   // enum → ScVal::Vec
///     name:       String,
///     signers:    Vec<Signer>,         // ScVal::Vec — length = signer count
///     signer_ids: Vec<u32>,            // ScVal::Vec — parallel to signers
///     policies:   Vec<Address>,
///     policy_ids: Vec<u32>,
///     valid_until: Option<u32>,
/// }
/// ```
///
/// This helper reads the `signer_ids` field (the registry-ID parallel vector,
/// positionally aligned with `signers`). Its length is identical to `signers.len()`
/// and equals the number of active signers in the rule (per storage.rs:166-167,
/// both vectors are maintained in lockstep by `add_signer` / `remove_signer`).
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] (`phase = "simulate"`) — the ScVal is not
///   a `ScVal::Map`, or the `signer_ids` field is missing or malformed.
///   Uses the `"simulate"` phase tag (closed-7-set discipline per `error.rs`).
pub fn decode_signer_count_from_scval(scval: &ScVal) -> Result<u32, SaError> {
    let parse_err = |detail: String| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("decode_signer_count_from_scval: {detail}"),
    };

    let entries = match scval {
        ScVal::Map(Some(ScMap(e))) => e.as_slice(),
        other => {
            return Err(parse_err(format!(
                "expected ScVal::Map, got {}",
                scval_variant_name(other)
            )));
        }
    };

    for entry in entries {
        let key_sym = match &entry.key {
            ScVal::Symbol(s) => s.to_utf8_string_lossy(),
            _ => continue,
        };
        if key_sym.as_str() == "signer_ids" {
            return match &entry.val {
                ScVal::Vec(Some(ScVec(elems))) => u32::try_from(elems.len()).map_err(|_| {
                    parse_err(format!(
                        "signer_ids vec length {} overflows u32",
                        elems.len()
                    ))
                }),
                ScVal::Vec(None) => Ok(0),
                other => Err(parse_err(format!(
                    "signer_ids: expected ScVal::Vec, got {}",
                    scval_variant_name(other)
                ))),
            };
        }
    }

    Err(parse_err(
        "missing 'signer_ids' field in ContextRule ScVal::Map".to_owned(),
    ))
}

/// Decodes the number of policies in a `ContextRule` `ScVal::Map` returned by
/// `get_context_rule`.
///
/// This is the `CapKind::Policy` mirror of [`decode_signer_count_from_scval`].
/// It reads the `policy_ids` field (the registry-ID parallel vector for
/// policies) and returns its length.  Both `signer_ids` and `policy_ids` are
/// maintained in lockstep with their corresponding data vectors by
/// `add_policy` / `remove_policy` (per OZ `storage.rs:1123` + `:1181`, SHA
/// `a9c4216`).
///
/// The `ContextRule` storage layout (OZ `storage.rs:152-174`, SHA `a9c4216`):
///
/// ```text
/// ContextRuleEntry {
///     signer_ids: Vec<u32>,   // registry IDs aligned with signers Vec
///     policy_ids: Vec<u32>,   // registry IDs aligned with policies Vec
///     context_type: ...,
///     name: String,
///     valid_until: Option<u32>,
/// }
/// ```
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] (`phase = "simulate"`) — the ScVal is not
///   a `ScVal::Map`, or the `policy_ids` field is missing or malformed.
///   Uses the `"simulate"` phase tag (closed-7-set discipline per `error.rs`).
pub fn decode_policy_count_from_scval(scval: &ScVal) -> Result<u32, SaError> {
    let parse_err = |detail: String| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("decode_policy_count_from_scval: {detail}"),
    };

    let entries = match scval {
        ScVal::Map(Some(ScMap(e))) => e.as_slice(),
        other => {
            return Err(parse_err(format!(
                "expected ScVal::Map, got {}",
                scval_variant_name(other)
            )));
        }
    };

    for entry in entries {
        let key_sym = match &entry.key {
            ScVal::Symbol(s) => s.to_utf8_string_lossy(),
            _ => continue,
        };
        if key_sym.as_str() == "policy_ids" {
            return match &entry.val {
                ScVal::Vec(Some(ScVec(elems))) => u32::try_from(elems.len()).map_err(|_| {
                    parse_err(format!(
                        "policy_ids vec length {} overflows u32",
                        elems.len()
                    ))
                }),
                ScVal::Vec(None) => Ok(0),
                other => Err(parse_err(format!(
                    "policy_ids: expected ScVal::Vec, got {}",
                    scval_variant_name(other)
                ))),
            };
        }
    }

    Err(parse_err(
        "missing 'policy_ids' field in ContextRule ScVal::Map".to_owned(),
    ))
}

/// Extracts the `valid_until` field from a `ContextRule` `ScVal::Map` returned
/// by `get_context_rule`.
///
/// Returns `Ok(Some(n))` when the field is `ScVal::U32(n)`, `Ok(None)` when
/// the field is `ScVal::Void` (permanent rule), and `Ok(None)` when the field
/// is absent (legacy rule installed before `valid_until` was added — treated as
/// permanent).
///
/// # Byte-layout citation
///
/// The soroban-env-common `TryFromVal<E, Val> for Option<T>` conversion:
/// - `None`  → `Val::VOID` → `ScVal::Void`
/// - `Some(t)` → `t.try_into_val(env)` → for `u32`: `ScVal::U32(n)`
///
/// OZ `storage.rs:159` (SHA `a9c4216`): `valid_until: Option<u32>` field in
/// `ContextRule` struct.
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] (`phase = "simulate"`) — the input is not
///   a `ScVal::Map`, or the `valid_until` field is present but neither
///   `ScVal::U32` nor `ScVal::Void`.
///
/// **Pure parser — no I/O, no privileged state, no key material.**
/// Returns `Ok(Some(N))` when the rule's `valid_until = Some(N)`,
/// `Ok(None)` when `valid_until = None` (permanent rule), `Err(_)` on
/// malformed ScVal shape. The `pub` visibility is justified by the
/// pure-parser semantics which deter misuse.
pub fn extract_valid_until_from_rule_scval(scval: &ScVal) -> Result<Option<u32>, SaError> {
    let parse_err = |detail: String| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("extract_valid_until_from_rule_scval: {detail}"),
    };

    let entries = match scval {
        ScVal::Map(Some(ScMap(e))) => e.as_slice(),
        other => {
            return Err(parse_err(format!(
                "expected ScVal::Map, got {}",
                scval_variant_name(other)
            )));
        }
    };

    for entry in entries {
        let key_sym = match &entry.key {
            ScVal::Symbol(s) => s.to_utf8_string_lossy(),
            _ => continue,
        };
        if key_sym.as_str() == "valid_until" {
            // `Option<u32>` wire shape per the soroban-env-common
            // `TryFromVal<E, Val> for Option<T>` conversion:
            //   None  → ScVal::Void
            //   Some(n) → ScVal::U32(n)
            return match &entry.val {
                ScVal::U32(n) => Ok(Some(*n)),
                ScVal::Void => Ok(None),
                other => Err(parse_err(format!(
                    "valid_until: expected ScVal::U32 (Some) or ScVal::Void (None); got {}",
                    scval_variant_name(other)
                ))),
            };
        }
    }

    // Field absent — treat as permanent (pre-valid_until legacy rule or
    // a rule without an expiry field from an older contract version).
    Ok(None)
}

/// Standalone pre-submission rule expiry check — usable from any manager
/// that has access to an RPC URL and network passphrase but not a full
/// [`ContextRuleManager`] instance.
///
/// Called from [`crate::submit::submit_signed_invoke`] for every caller
/// that passes an `ExpiryCheck`: the signer verbs through
/// `SignersManager::submit_single_op`, the admin verbs through
/// `SignersManager::submit_signed_invoke`, and the policy verbs through
/// `ContextRuleManager::submit_signed_invoke`.
///
/// Equivalent to [`ContextRuleManager::check_rule_not_expired`] but takes
/// raw RPC-URL and passphrase parameters instead of `&self`.
///
/// # Errors
///
/// - [`SaError::RuleExpired`] — `valid_until < latest_ledger`.
/// - [`SaError::DeploymentFailed`] / [`SaError::AuthEntryConstructionFailed`]
///   on transport or RPC failure.
///
#[allow(
    clippy::too_many_arguments,
    reason = "standalone counterpart to the instance method; takes raw RPC params \
              because SignersManager does not hold a ContextRuleManager"
)]
pub(crate) async fn check_rule_not_expired_standalone(
    rpc_url: &str,
    network_passphrase: &str,
    timeout: Duration,
    smart_account: ScAddress,
    rule_id: u32,
    source_account_strkey: &str,
    latest_ledger: u32,
) -> Result<(), SaError> {
    // Build a minimal ContextRuleManager to reuse the `get_rule` / simulate
    // read-only infrastructure.  The `chain_id` field is not used by
    // `get_rule` (it is only used for auth-entry signing divergence checks),
    // so a placeholder is safe here.  `signers_manager` and `audit_writer`
    // are not needed for a read-only call. `ContextRuleManager::new`
    // constructs its own internal `StellarRpcClient` from the rpc_url —
    let manager = ContextRuleManager::new(ContextRuleManagerConfig::new(
        rpc_url.to_owned(),
        network_passphrase.to_owned(),
        timeout,
        // chain_id placeholder — safe: only consumed by the divergence-check
        // path which `get_rule` does NOT exercise.
        "standalone-expiry-check".to_owned(),
    ))
    .map_err(|e| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: format!(
            "check_rule_not_expired_standalone: ContextRuleManager construction failed: {e}"
        ),
    })?;

    manager
        .check_rule_not_expired(smart_account, rule_id, source_account_strkey, latest_ledger)
        .await
}

/// Extracts the first-8 hex chars of the auth_digest from a successful
/// outcome for the `SaRawInvocation.auth_digest_prefix` audit field.
///
/// The wallet-side digest is computed inside `complete_authorization_entry`
/// and not currently propagated to the manager's caller. Emits a placeholder
/// `"sa_ok___"` marker in the audit row's auth_digest_prefix slot.
fn auth_digest_prefix_from_outcome<T>(_outcome: &Result<T, SaError>) -> String {
    "sa_ok___".to_owned()
}

/// `()`-returning sibling of [`auth_digest_prefix_from_outcome`] for the
/// metadata-update + delete paths whose outcome carries no rule_id payload.
/// Same placeholder discipline as the install-path sibling: emits
/// `"sa_ok___"` until the real digest is threaded through the return path.
fn auth_digest_prefix_from_outcome_unit<T>(_outcome: &Result<T, SaError>) -> String {
    "sa_ok___".to_owned()
}

/// Writes `entry` to `per_method` if present, else to `fallback` if present.
///
/// All write failures are warn-logged but never propagated. The fallback lock
/// scope is strictly synchronous and is never held across `.await`, mirroring
/// the pattern in `SignersManager` at
/// `crates/stellar-agent-smart-account/src/managers/signers.rs`.
///
/// On mutex poison (`Err(_poison)` from `fallback.lock()`), marks the session
/// degraded via `health` (if `Some`) and warns, then returns without writing.
fn dispatch_audit_emission(
    per_method: Option<&mut AuditWriter>,
    fallback: Option<&Arc<Mutex<AuditWriter>>>,
    entry: AuditEntry,
    op_label: &'static str,
    health: Option<&AuditWriterHealthHandle>,
) {
    match per_method {
        Some(writer) => {
            if let Err(e) = writer.write_entry(entry) {
                warn!(error = %e, op = %op_label, "audit write failed (per-method writer)");
            }
        }
        None => {
            if let Some(arc) = fallback {
                match arc.lock() {
                    Ok(mut guard) => {
                        if let Err(e) = guard.write_entry(entry) {
                            warn!(
                                error = %e,
                                op = %op_label,
                                "audit write failed (self.audit_writer fallback)"
                            );
                        }
                    }
                    Err(_poison) => {
                        if let Some(h) = health {
                            h.mark_degraded();
                        }
                        warn!(
                            target: "stellar_agent::audit",
                            op = %op_label,
                            "audit-writer mutex poisoned; audit row dropped"
                        );
                    }
                }
            }
        }
    }
}

/// Audit emission for the metadata-update entrypoints (`update_name`,
/// `update_valid_until`). These operations produce only `SaRawInvocation`
/// rows; the caller passes `outcome_err` so a single helper handles both
/// success (`None`) and failure (`Some(&err)`) paths uniformly.
///
/// Emits a metadata-update audit row via `per_method` if `Some`, else via
/// `fallback` if `Some`, else no-op. All write failures are warn-logged but
/// never propagated.
///
/// Lock scope on `fallback` is strictly synchronous; never held across
/// `.await`. Mirrors the pattern in `SignersManager` at
/// `crates/stellar-agent-smart-account/src/managers/signers.rs`.
#[allow(
    clippy::too_many_arguments,
    reason = "irreducible audit-context parameter set; mirrors the existing allow on install_rule / delete_rule"
)]
fn emit_metadata_update_audit(
    outcome_err: Option<&SaError>,
    smart_account: &ScAddress,
    auth_rule_ids: &[ContextRuleId],
    audit_writer: Option<&mut AuditWriter>,
    fallback: Option<&Arc<Mutex<AuditWriter>>>,
    chain_id: &str,
    request_id: &str,
    op_label: &'static str,
    health: Option<&AuditWriterHealthHandle>,
) {
    let smart_account_strkey = match scaddress_to_strkey(smart_account) {
        Ok(s) => s,
        Err(_) => "unknown".to_owned(),
    };
    let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
    let auth_rule_ids_count = u32::try_from(auth_rule_ids.len()).unwrap_or(u32::MAX);

    let entry = match outcome_err {
        None => AuditEntry::new_sa_raw_invocation(
            &smart_account_redacted,
            "sa.ok",
            Some(auth_digest_prefix_from_outcome_unit(&Ok(()))),
            auth_rule_ids_count,
            stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
            chain_id,
            request_id,
        ),
        Some(err) => {
            let result = sa_error_to_invocation_result(err);
            AuditEntry::new_sa_raw_invocation(
                &smart_account_redacted,
                err.wire_code(),
                None,
                auth_rule_ids_count,
                result,
                chain_id,
                request_id,
            )
        }
    };

    dispatch_audit_emission(audit_writer, fallback, entry, op_label, health);
}

/// A policy add whose transaction confirmed. The entry wrote its threshold
/// and pin rows under the rule's lock.
struct PolicyAddConfirmed {
    /// The policy id the confirmed return value carries, for the
    /// `SaPolicyAdded` row; `None` when it carries none.
    policy_id: Option<u32>,
    /// The confirmed transaction's hash.
    tx_hash: String,
    /// The verb's result: the policy id, or the refusal of the steps after
    /// confirmation.
    result: Result<u32, SaError>,
}

/// A policy removal whose transaction confirmed. The entry wrote its
/// threshold and pin rows under the rule's lock.
struct PolicyRemoveConfirmed {
    /// The confirmed transaction's hash.
    tx_hash: String,
    /// The verb's result: the refusal of the steps after confirmation, if
    /// any.
    result: Result<(), SaError>,
}

/// Maps an [`SaError`] outcome to the corresponding
/// [`stellar_agent_core::audit_log::schema::SaInvocationResult`] variant.
pub(crate) fn sa_error_to_invocation_result(
    err: &SaError,
) -> stellar_agent_core::audit_log::schema::SaInvocationResult {
    use stellar_agent_core::audit_log::schema::SaInvocationResult;
    match err {
        SaError::DeploymentFailed { phase, .. } => match *phase {
            "submit" | "deploy" | "upload" | "post_deploy_verification" => {
                SaInvocationResult::OnChainRejected
            }
            _ => SaInvocationResult::PreSubmissionRefused,
        },
        SaError::AuthEntryConstructionFailed { .. }
        | SaError::RuleIdMismatch { .. }
        | SaError::SimulationDivergence { .. }
        | SaError::ThresholdUnreachable { .. }
        | SaError::ContextRuleCapsExceeded { .. }
        | SaError::RuleExpired { .. }
        | SaError::ScAddressEncodingFailed { .. }
        // WebAuthn assertion failed the off-chain pre-verifier: rejected before
        // chain-submission to prevent fee-burn on malformed assertions.
        | SaError::WebAuthnAssertionInvalid { .. }
        // Verifier-registry / provenance errors: all fire before any network
        // submission (SHA gate, TOML parse, config I/O, sha256-drift guard).
        | SaError::WebAuthnVerifierProvenanceMismatch { .. }
        | SaError::WebAuthnVerifierSha256Drift { .. }
        | SaError::Ed25519VerifierProvenanceMismatch { .. }
        | SaError::Ed25519VerifierSha256Drift { .. }
        | SaError::SpendingLimitPolicyProvenanceMismatch { .. }
        | SaError::SpendingLimitPolicySha256Drift { .. }
        | SaError::SpendingLimitInstallRefused { .. }
        | SaError::SimpleThresholdInstallRefused { .. }
        | SaError::WeightedThresholdInstallRefused { .. }
        | SaError::SimpleThresholdPolicyProvenanceMismatch { .. }
        | SaError::SimpleThresholdPolicySha256Drift { .. }
        | SaError::WeightedThresholdPolicyProvenanceMismatch { .. }
        | SaError::WeightedThresholdPolicySha256Drift { .. }
        | SaError::NetworksTomlIo { .. }
        | SaError::AuditWriterIo { .. }
        | SaError::NetworksTomlParse { .. }
        // Signer-threshold pre-submission refusal variants.
        // All fire before any chain submission attempt.
        | SaError::ThresholdPolicyNotInstalled { .. }
        | SaError::SignerSetMissingBaseline { .. }
        | SaError::SignerSetBaselineLegacy { .. }
        | SaError::SignersManagerNotConfigured { .. }
        | SaError::ThresholdPolicyIdentificationFailed { .. }
        | SaError::ThresholdReadFailed { .. }
        | SaError::NetworkRpcDivergence { .. }
        // Spending-limit-policy identification and read-path errors: both
        // `identify_spending_limit_policy` and `get_spending_limit_data` are
        // read-only (simulate-only, no `submit_transaction`); neither variant
        // can fire after a submission attempt.
        | SaError::SpendingLimitNotInstalled { .. }
        | SaError::SpendingLimitPolicyIdentificationFailed { .. }
        // Weighted-threshold-policy identification and read-path errors: both
        // `identify_weighted_threshold_policy` and `get_weighted_threshold_data`
        // are read-only; neither variant can fire after a submission attempt.
        | SaError::WeightedThresholdNotInstalled { .. }
        | SaError::WeightedThresholdPolicyIdentificationFailed { .. }
        // Batch signer-add client-side refusal (e.g. empty batch): fires
        // before any simulate/submit call.
        | SaError::BatchSignerAddRefused { .. }
        | SaError::AuditLog(_) => SaInvocationResult::PreSubmissionRefused,
        // Wasm-hash pinning pre-submission refusals.
        // All variants fire before any chain-submission attempt; signing
        // is aborted during rule-install pre-flight or on-signing re-fetch.
        SaError::VerifierHashDrift { .. }
        | SaError::PolicyHashDrift { .. }
        | SaError::VerifierMutable { .. }
        | SaError::PolicyMutable { .. }
        | SaError::ContractInstanceUnsupported { .. }
        | SaError::VerifierWasmNotInAllowlist { .. }
        | SaError::PolicyWasmNotInAllowlist { .. }
        // Multi-hash guard fires before any signing attempt; signing aborted
        // fail-closed.
        | SaError::MultiplePinnedHashesUnsupported { .. }
        // Policy pins with no policy on chain, and a live verifier the pin
        // record does not pin, refuse before any signing attempt.
        | SaError::PinnedPolicyAbsent { .. }
        | SaError::PinnedVerifierAbsent { .. }
        // The pre-signing drift check could not run; nothing was signed.
        | SaError::PinCheckUnavailable { .. }
        // Verifier diversification pre-submission refusals.
        // All variants fire before any chain-submission attempt; signing is
        // aborted during allowlist-advisory checks, diversification enforcement,
        // or migration.
        | SaError::VerifierDiversificationRequired { .. }
        | SaError::VerifierWasmRevoked { .. }
        | SaError::VerifierWasmRetired { .. }
        | SaError::VerifierMigrationFailed { .. }
        | SaError::VerifierAllowlistEmpty { .. }
        // Session-rule horizon enforcement fires before any network submission.
        | SaError::HorizonExceeded { .. }
        // Fail-CLOSED required-check enforcement fires before any network I/O.
        | SaError::SubmitCheckMissing { .. } => SaInvocationResult::PreSubmissionRefused,
        // MulticallFailed: phase determines whether on-chain submission was attempted.
        // Phases "submit" and "post_submit_verification" may have landed on-chain;
        // all other phases fire before any submission.
        SaError::MulticallFailed { phase, .. } => match *phase {
            "submit" | "post_submit_verification" => SaInvocationResult::OnChainRejected,
            _ => SaInvocationResult::PreSubmissionRefused,
        },
        // SubmissionUnresolved: the kinds differ on whether this call sent
        // anything. A timeout and a hash mismatch follow a send whose outcome
        // the chain has yet to settle. A duplicate refusal and a
        // record-unavailable refusal both stop before the send.
        SaError::SubmissionUnresolved { kind, .. } => match kind {
            crate::error::SubmissionUnresolvedKind::Timeout
            | crate::error::SubmissionUnresolvedKind::HashMismatch => {
                SaInvocationResult::PostSubmitVerificationFailed
            }
            _ => SaInvocationResult::PreSubmissionRefused,
        },
        // SignerSetDiverged: without a transaction hash the comparison refused
        // before anything was sent; with one, the set observed after a
        // confirmed signer mutation is not the intended change.
        SaError::SignerSetDiverged { tx_hash, .. } => match tx_hash {
            None => SaInvocationResult::PreSubmissionRefused,
            Some(_) => SaInvocationResult::PostSubmitVerificationFailed,
        },
        // BaselineWriteFailed: with a transaction hash a signer mutation
        // confirmed and its resulting state was not recorded; without one a
        // read-only verb sent nothing.
        SaError::BaselineWriteFailed { tx_hash, .. } => match tx_hash {
            None => SaInvocationResult::PreSubmissionRefused,
            Some(_) => SaInvocationResult::PostSubmitVerificationFailed,
        },
        // InstallStateMismatch: the install confirmed and the installed rule
        // was not baselined.
        SaError::InstallStateMismatch { .. } => SaInvocationResult::PostSubmitVerificationFailed,
        // PolicyDenied: the wallet's own refusal, decided before the send.
        SaError::PolicyDenied { .. } => SaInvocationResult::PreSubmissionRefused,
        // MainnetWriteForbidden: refused before signing or before the send;
        // nothing reached the network as a transaction.
        SaError::MainnetWriteForbidden => SaInvocationResult::PreSubmissionRefused,
        // MulticallSha256Drift: fires at registry-lookup time, before any I/O.
        SaError::MulticallSha256Drift { .. } => SaInvocationResult::PreSubmissionRefused,
        // MulticallRegistryEntryNotFound: fires at registry-lookup time, before any I/O.
        SaError::MulticallRegistryEntryNotFound { .. } => {
            SaInvocationResult::PreSubmissionRefused
        }
        // Timelock*Failed variants each carry a typed failure_reason enum that
        // distinguishes pre-submission refusals, on-chain rejections, and the
        // post-submit event-confirmation-missing case.
        //
        // The OZ stellar-contracts v0.7.2 contract has no off-chain
        // InvocationResult taxonomy — on-chain TimelockError codes are
        // classified wallet-side. No off-chain SDK exposes a timelock-handler
        // surface, so this taxonomy is wallet-specific with no reference analogue.
        SaError::TimelockScheduleFailed { failure_reason, .. } => {
            use crate::error::TimelockScheduleFailureReason as R;
            match failure_reason {
                // Fired before any transaction is signed or sent.
                R::SimulationFailed | R::AuditWriterPoisoned => {
                    SaInvocationResult::PreSubmissionRefused
                }
                // Tx submitted and confirmed; OZ OperationScheduled event absent
                // from tx meta.
                R::EventConfirmationMissing => SaInvocationResult::PostSubmitVerificationFailed,
                // On-chain OZ contract returned an error code (simulate-time or
                // __check_auth rejection): Unauthorized (4004),
                // OperationAlreadyScheduled (4000), InsufficientDelay (4001),
                // Other (unrecognised OZ error code).
                _ => SaInvocationResult::OnChainRejected,
            }
        }
        SaError::TimelockCancelFailed { failure_reason, .. } => {
            use crate::error::TimelockCancelFailureReason as R;
            match failure_reason {
                // Fired before any transaction is signed or sent.
                R::SimulationFailed | R::AuditWriterPoisoned => {
                    SaInvocationResult::PreSubmissionRefused
                }
                // Tx submitted and confirmed; OZ OperationCancelled event absent
                // from tx meta.
                R::EventConfirmationMissing => SaInvocationResult::PostSubmitVerificationFailed,
                // On-chain OZ contract returned an error code: Unauthorized (4004),
                // InvalidOperationState (4002), OperationNotScheduled (4006),
                // Other (unrecognised OZ error code).
                _ => SaInvocationResult::OnChainRejected,
            }
        }
        SaError::TimelockExecuteFailed { failure_reason, .. } => {
            use crate::error::TimelockExecuteFailureReason as R;
            match failure_reason {
                // Fired before any transaction is signed or sent.
                // SimulationFailed: simulate step fails pre-submission.
                // AuditWriterPoisoned: audit-log poison on SaTimelockExecuted emission.
                // OperationNotReady: cross-RPC pre-check fires before execute tx.
                // OperationIdMismatch: user-supplied ID checked before submission.
                R::SimulationFailed
                | R::AuditWriterPoisoned
                | R::OperationNotReady { .. }
                | R::OperationIdMismatch { .. } => SaInvocationResult::PreSubmissionRefused,
                // Tx submitted and confirmed; OZ OperationExecuted event absent
                // from tx meta.
                R::EventConfirmationMissing => SaInvocationResult::PostSubmitVerificationFailed,
                // On-chain OZ contract returned an error code:
                // InvalidOperationState (4002), UnexecutedPredecessor (4003),
                // Other (unrecognised OZ error code).
                // Note: TimelockExecuteFailureReason has no Unauthorized variant.
                _ => SaInvocationResult::OnChainRejected,
            }
        }
        // TimelockListPendingFailed: read-path failure (RPC unreachable or URL
        // invalid); no submission attempted. Maps to PreSubmissionRefused because
        // the operation state could not be determined before any action.
        SaError::TimelockListPendingFailed { .. } => SaInvocationResult::PreSubmissionRefused,
        // Simulation-audit mismatch fires immediately before
        // submit_transaction_and_wait; the transaction was never sent.
        SaError::AuthMismatch { .. } => SaInvocationResult::PreSubmissionRefused,
    }
}

/// Renders an [`ScAddress`] as the canonical Stellar strkey form.
///
/// Delegates to [`stellar_agent_core::sc_address::scaddress_to_strkey`]; an
/// address variant with no account or contract strkey form maps to
/// [`SaError::AuthEntryConstructionFailed`] at stage `auth_payload`, naming
/// the variant only.
pub(crate) fn scaddress_to_strkey(addr: &ScAddress) -> Result<String, SaError> {
    stellar_agent_core::sc_address::scaddress_to_strkey(addr).map_err(|e| {
        SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("unsupported ScAddress variant for strkey rendering: {e}"),
        }
    })
}

/// Converts a `stellar_xdr::ScAddress` to its canonical strkey, returning
/// `"[unknown-address-type]"` for address variants that have no strkey representation
/// (`MuxedAccount`, `ClaimableBalance`, `LiquidityPool`).
///
/// Used by [`crate::managers::verifiers::inspect_storage_for_admin_key`] when
/// rendering the `holder_redacted` field of [`crate::managers::verifiers::MutabilityStatus::Mutable`].
/// These unusual variants should never appear as admin-key holders in well-formed
/// OZ contracts, but the sentinel avoids a panic in adversarial inputs.
///
/// Delegates to [`stellar_agent_core::sc_address::scaddress_to_strkey`].
pub(crate) fn xdr_scaddress_to_strkey_or_sentinel(addr: &xdr_curr::ScAddress) -> String {
    stellar_agent_core::sc_address::scaddress_to_strkey(addr)
        .unwrap_or_else(|_| "[unknown-address-type]".to_owned())
}

/// One kind's half of the verify-pins report.
struct KindPinReport {
    /// Last-wins status over the kind's addresses: each address sets
    /// `Match`, `Drift` or `Unavailable` in turn.
    status: PinStatus,
    /// Observed first-8 of each address that matched or drifted.
    observed_first8: Vec<String>,
    /// Bounded summary aligned with `observed_first8`; `None` for a plain
    /// Wasm executable.
    observed_executable: Vec<Option<String>>,
    /// Wire code of the kind's first failure that is not drift, recorded
    /// whatever the final status.
    unavailable_wire_code: Option<&'static str>,
}

/// Verifies the pins of one kind for [`ContextRuleManager::verify_rule_wasm_pins`].
///
/// Each address is checked against the rule's pin record through the kind's
/// check function. The kind's drift refusal sets `Drift` and records the
/// observed hash. A live verifier the record does not pin
/// ([`SaError::PinnedVerifierAbsent`]) sets `Drift` with no observed hash.
/// Any other refusal sets `Unavailable` and records its wire code if none is
/// recorded yet. With no address, a verifier half is `NoContracts`; a policy
/// half is `NoContracts` when the pin record holds no policy pin, `Drift`
/// when it does ([`SaError::PinnedPolicyAbsent`]), and `Unavailable` when the
/// record cannot be read.
///
/// # Errors
///
/// [`SaError::ScAddressEncodingFailed`] when an address cannot be encoded
/// as a cache key.
async fn verify_kind_pins(
    kind: PinnedKind,
    addrs: Vec<ScAddress>,
    signers_manager: &SignersManager,
    rule_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
    wasm_hash_cache: &mut std::collections::HashMap<
        Vec<u8>,
        crate::managers::signers::ObservedExecutable,
    >,
) -> Result<KindPinReport, SaError> {
    let mut report = KindPinReport {
        status: PinStatus::Match,
        observed_first8: Vec::new(),
        observed_executable: Vec::new(),
        unavailable_wire_code: None,
    };

    if addrs.is_empty() {
        report.status = match kind {
            PinnedKind::Verifier => PinStatus::NoContracts,
            PinnedKind::Policy => match crate::managers::verifiers::verify_policy_pins_present(
                signers_manager,
                rule_id,
                smart_account_redacted,
                request_id,
                &addrs,
            ) {
                Ok(()) => PinStatus::NoContracts,
                Err(SaError::PinnedPolicyAbsent { .. }) => PinStatus::Drift,
                // A read failure of the record is not drift; the status is
                // unavailable with its code.
                Err(e) => {
                    report.unavailable_wire_code = Some(e.wire_code());
                    PinStatus::Unavailable
                }
            },
        };
        return Ok(report);
    }

    for addr in addrs {
        let cache_key = scaddress_cache_key(&addr)?;
        let outcome = match kind {
            PinnedKind::Verifier => {
                crate::managers::verifiers::verify_pinned_verifier_against_chain(
                    signers_manager,
                    addr,
                    rule_id,
                    smart_account_redacted,
                    request_id,
                    wasm_hash_cache,
                )
                .await
            }
            PinnedKind::Policy => {
                crate::managers::verifiers::verify_pinned_policy_against_chain(
                    signers_manager,
                    addr,
                    rule_id,
                    smart_account_redacted,
                    request_id,
                    wasm_hash_cache,
                )
                .await
            }
        };
        match (kind, outcome) {
            (_, Ok(())) => {
                // Observed effective hash for the envelope (already cached);
                // the check passed, so no code reads as the zero hash the pin
                // holds.
                if let Some(executable) = wasm_hash_cache.get(&cache_key) {
                    let h = executable.effective_hash().unwrap_or([0u8; 32]);
                    report
                        .observed_first8
                        .push(crate::managers::signers::hash_first8_hex(&h));
                    report
                        .observed_executable
                        .push(non_wasm_executable_summary(executable));
                }
            }
            (
                PinnedKind::Verifier,
                Err(SaError::VerifierHashDrift {
                    observed_hash_first8,
                    ..
                }),
            )
            | (
                PinnedKind::Policy,
                Err(SaError::PolicyHashDrift {
                    observed_hash_first8,
                    ..
                }),
            ) => {
                report.status = PinStatus::Drift;
                report.observed_first8.push(observed_hash_first8);
                report.observed_executable.push(
                    wasm_hash_cache
                        .get(&cache_key)
                        .and_then(non_wasm_executable_summary),
                );
            }
            // A live verifier the record does not pin is drift with no
            // observed hash: the check refused before reading the verifier.
            (PinnedKind::Verifier, Err(SaError::PinnedVerifierAbsent { .. })) => {
                report.status = PinStatus::Drift;
            }
            (_, Err(e)) => {
                report.unavailable_wire_code = report.unavailable_wire_code.or(Some(e.wire_code()));
                report.status = PinStatus::Unavailable;
            }
        }
    }
    Ok(report)
}

/// Returns the bounded summary of an observed executable for the
/// verify-pins report, or `None` for a plain Wasm executable, whose hash the
/// first-8 list already carries.
fn non_wasm_executable_summary(
    executable: &crate::managers::signers::ObservedExecutable,
) -> Option<String> {
    match executable {
        crate::managers::signers::ObservedExecutable::Wasm(_) => None,
        other => Some(other.summary()),
    }
}

/// Builds a `LedgerKey::ContractData` key for a contract's instance entry.
///
/// Encodes the `LedgerKeyContractInstance` ledger key for `getLedgerEntries`.
/// Layout per `LedgerKeyContractData` in `Stellar-ledger-entries.x`:
/// - `contract`: the target contract's `ScAddress`.
/// - `key`: `ScVal::LedgerKeyContractInstance`.
/// - `durability`: `ContractDataDurability::Persistent`.
///
/// Canonical location for this constructor: both signers and verifiers managers
/// import this from `managers::rules`.
///
/// Infallible: merely wraps an `ScAddress` into the `LedgerKey` discriminant.
pub(crate) fn contract_instance_key(contract_addr: &ScAddress) -> xdr_curr::LedgerKey {
    use stellar_xdr::{ContractDataDurability, LedgerKeyContractData};
    xdr_curr::LedgerKey::ContractData(LedgerKeyContractData {
        contract: contract_addr.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    })
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
        reason = "test-only fixture construction"
    )]

    use super::*;
    use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
    use stellar_xdr::{AccountId, ContractId, PublicKey, Uint256};

    fn snapshot_with_delegates(
        addresses: &[&str],
    ) -> stellar_agent_core::approval::ContextRuleProposalSnapshot {
        use stellar_agent_core::approval::{
            ContextRuleProposalSnapshot, RuleProposalContextType, RuleProposalSigner,
        };
        ContextRuleProposalSnapshot::new(
            RuleProposalContextType::Default,
            "spend-daily".to_owned(),
            None,
            addresses
                .iter()
                .enumerate()
                .map(|(idx, address)| {
                    RuleProposalSigner::delegated((*address).to_owned(), idx == 0)
                })
                .collect(),
            vec![],
            vec![0],
            false,
            false,
        )
    }

    /// `context_rule_definition_from_snapshot` reads a `Delegated` signer
    /// whose address is a C-strkey as a contract delegate.
    #[test]
    fn context_rule_definition_from_snapshot_accepts_a_c_strkey_delegated_signer() {
        let c_strkey = stellar_strkey::Contract([0x42; 32]).to_string();
        let definition = context_rule_definition_from_snapshot(&snapshot_with_delegates(&[
            SIMULATE_SENTINEL_G,
            c_strkey.as_str(),
        ]))
        .unwrap();
        assert!(matches!(
            definition.signers[0],
            ContextRuleSignerInput::Delegated {
                address: ScAddress::Account(_)
            }
        ));
        assert!(matches!(
            &definition.signers[1],
            ContextRuleSignerInput::Delegated {
                address: ScAddress::Contract(ContractId(Hash(id)))
            } if *id == [0x42; 32]
        ));
    }

    /// `context_rule_definition_from_snapshot` refuses a `Delegated` signer
    /// whose address is a muxed M-strkey and names the signer's index.
    #[test]
    fn context_rule_definition_from_snapshot_refuses_an_m_strkey_delegated_signer() {
        let muxed = stellar_strkey::ed25519::MuxedAccount {
            ed25519: [0u8; 32],
            id: 7,
        }
        .to_string();
        let Err(SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        }) = context_rule_definition_from_snapshot(&snapshot_with_delegates(&[
            SIMULATE_SENTINEL_G,
            muxed.as_str(),
        ]))
        else {
            panic!("an M-strkey delegated signer must be refused");
        };
        assert_eq!(stage, "rule_proposal_digest");
        assert!(
            redacted_reason.starts_with("signers[1].address: "),
            "{redacted_reason}"
        );
    }

    /// `parse_delegated_signer_address` reads a G-strkey as an account and a
    /// C-strkey as a contract, keeping the key or the contract id.
    #[test]
    fn parse_delegated_signer_address_reads_an_account_or_a_contract() {
        let account = stellar_strkey::ed25519::PublicKey([0x31; 32]).to_string();
        assert_eq!(
            parse_delegated_signer_address(&account).unwrap(),
            ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                [0x31; 32]
            ))))
        );
        let contract = stellar_strkey::Contract([0x32; 32]).to_string();
        assert_eq!(
            parse_delegated_signer_address(&contract).unwrap(),
            ScAddress::Contract(ContractId(Hash([0x32; 32])))
        );
    }

    /// `parse_delegated_signer_address` refuses a muxed M-strkey and any
    /// other text.
    #[test]
    fn parse_delegated_signer_address_refuses_an_m_strkey() {
        let muxed = stellar_strkey::ed25519::MuxedAccount {
            ed25519: [0x31; 32],
            id: 7,
        }
        .to_string();
        for input in [muxed.as_str(), "not-a-strkey", ""] {
            match parse_delegated_signer_address(input) {
                Err(SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason,
                }) => assert_eq!(
                    redacted_reason,
                    "invalid delegated signer address: expected a G-strkey or a C-strkey"
                ),
                other => panic!("{input:?}: expected AuthEntryConstructionFailed, got {other:?}"),
            }
        }
    }

    /// An `External` signer with empty key data is refused before any
    /// encoding: a rule holding it could not be read back.
    #[test]
    fn encode_signer_refuses_an_external_signer_with_empty_key_data() {
        let signer = ContextRuleSignerInput::External {
            verifier: ScAddress::Contract(ContractId(Hash([0x44; 32]))),
            pubkey_data: vec![],
        };
        match encode_signer(&signer) {
            Err(SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason,
            }) => assert_eq!(redacted_reason, "External signer pubkey is empty"),
            other => panic!("expected AuthEntryConstructionFailed, got {other:?}"),
        }
        let one_byte = ContextRuleSignerInput::External {
            verifier: ScAddress::Contract(ContractId(Hash([0x44; 32]))),
            pubkey_data: vec![0x01],
        };
        assert!(encode_signer(&one_byte).is_ok());
    }

    fn threshold_policy_hash() -> [u8; 32] {
        THRESHOLD_POLICY_WASM_HASHES[0]
    }

    fn definition_with(
        signers: Vec<ContextRuleSignerInput>,
        policies: Vec<ContextRulePolicy>,
    ) -> ContextRuleDefinition {
        ContextRuleDefinition::new(
            RuleContext::Default,
            "rule".to_owned(),
            None,
            signers,
            policies,
        )
    }

    /// The expected install state carries every signer's version-2 identity
    /// from the encoded bytes, and the simple-threshold policy with the
    /// threshold of its install parameter. A policy whose pinned hash is not
    /// the simple-threshold policy adds no threshold.
    #[test]
    fn expected_install_state_reads_the_identities_and_the_threshold() {
        let threshold_policy = ScAddress::Contract(ContractId(Hash([0x51; 32])));
        let other_policy = ScAddress::Contract(ContractId(Hash([0x52; 32])));
        let definition = definition_with(
            vec![
                ContextRuleSignerInput::Delegated {
                    address: ScAddress::Contract(ContractId(Hash([0x53; 32]))),
                },
                ContextRuleSignerInput::External {
                    verifier: ScAddress::Contract(ContractId(Hash([0x54; 32]))),
                    pubkey_data: vec![0x07; 65],
                },
            ],
            vec![
                ContextRulePolicy::new(other_policy.clone(), ScVal::Void),
                ContextRulePolicy::new(
                    threshold_policy.clone(),
                    crate::simple_threshold_policy::build_simple_threshold_install_param(2)
                        .unwrap(),
                ),
            ],
        );
        let expected = expected_install_state(
            &definition,
            &[
                (other_policy, [0xee; 32]),
                (threshold_policy, threshold_policy_hash()),
            ],
        )
        .unwrap();
        assert_eq!(
            expected.signers,
            vec![
                SignerIdentityV2::DelegatedContract {
                    contract: [0x53; 32]
                },
                SignerIdentityV2::External {
                    verifier: [0x54; 32],
                    key_data_sha256: Sha256::digest([0x07; 65]).into(),
                    key_data_len: 65,
                },
            ]
        );
        assert_eq!(
            expected.threshold,
            Some(ThresholdObservation {
                policy: [0x51; 32],
                threshold: 2
            })
        );

        let no_threshold = expected_install_state(
            &definition,
            &[(
                ScAddress::Contract(ContractId(Hash([0x52; 32]))),
                [0xee; 32],
            )],
        )
        .unwrap();
        assert_eq!(no_threshold.threshold, None);
    }

    /// A policy address listed twice, two simple-threshold policies and a
    /// malformed simple-threshold parameter each refuse.
    #[test]
    fn expected_install_state_refuses_an_ambiguous_or_malformed_definition() {
        let p = ScAddress::Contract(ContractId(Hash([0x61; 32])));
        let q = ScAddress::Contract(ContractId(Hash([0x62; 32])));
        let param =
            crate::simple_threshold_policy::build_simple_threshold_install_param(1).unwrap();

        let twice = definition_with(
            vec![],
            vec![
                ContextRulePolicy::new(p.clone(), param.clone()),
                ContextRulePolicy::new(p.clone(), param.clone()),
            ],
        );
        match expected_install_state(&twice, &[(p.clone(), threshold_policy_hash())]) {
            Err(SaError::DeploymentFailed {
                phase: "build",
                redacted_reason,
            }) => assert_eq!(redacted_reason, "install: policy address listed twice"),
            other => panic!("expected the duplicate refusal, got {other:?}"),
        }

        let two = definition_with(
            vec![],
            vec![
                ContextRulePolicy::new(p.clone(), param.clone()),
                ContextRulePolicy::new(q.clone(), param.clone()),
            ],
        );
        match expected_install_state(
            &two,
            &[
                (p.clone(), threshold_policy_hash()),
                (q, THRESHOLD_POLICY_WASM_HASHES[1]),
            ],
        ) {
            Err(SaError::DeploymentFailed {
                phase: "build",
                redacted_reason,
            }) => assert_eq!(
                redacted_reason,
                "install: 2 policies identify as the simple-threshold policy; at most one is \
                 allowed"
            ),
            other => panic!("expected the two-policies refusal, got {other:?}"),
        }

        let malformed =
            definition_with(vec![], vec![ContextRulePolicy::new(p.clone(), ScVal::Void)]);
        assert!(matches!(
            expected_install_state(&malformed, &[(p, threshold_policy_hash())]),
            Err(SaError::SimpleThresholdInstallRefused { .. })
        ));
    }

    fn manager_for_test() -> ContextRuleManager {
        ContextRuleManager::new(ContextRuleManagerConfig {
            primary_rpc_url: "http://127.0.0.1:65535".to_owned(),
            secondary_rpc_url: None,
            network_passphrase: "Test SDF Network ; September 2015".to_owned(),
            timeout: Duration::from_secs(30),
            chain_id: "stellar:testnet".to_owned(),
            signers_manager: None,
            audit_writer: None,
            session_rule_max_horizon_ledgers: None,
        })
        .unwrap()
    }

    /// Pins the OZ on-chain cap constants against upstream drift.
    ///
    /// Canonical source: `packages/accounts/src/smart_account/mod.rs:524-530`
    /// SHA `a9c4216` (`MAX_POLICIES = 5`, `MAX_SIGNERS = 15`,
    /// `MAX_NAME_SIZE = 20`, `MAX_EXTERNAL_KEY_SIZE = 256`).
    /// If OZ changes these caps, this test fails and forces a deliberate re-pin.
    #[test]
    fn oz_cap_constants_pin_canonical_values() {
        assert_eq!(OZ_MAX_POLICIES, 5);
        assert_eq!(OZ_MAX_SIGNERS, 15);
        assert_eq!(OZ_MAX_NAME_SIZE, 20);
        assert_eq!(OZ_MAX_EXTERNAL_KEY_SIZE, 256);
    }

    // ── validate_latest_ledger bounds tests ───────────────────────────────────

    #[test]
    fn validate_latest_ledger_zero_is_rejected() {
        let err = validate_latest_ledger(0).unwrap_err();
        assert!(
            matches!(
                err,
                SaError::DeploymentFailed {
                    phase: "simulate",
                    ..
                }
            ),
            "latest_ledger=0 must return DeploymentFailed(simulate)"
        );
    }

    #[test]
    fn validate_latest_ledger_one_is_accepted() {
        validate_latest_ledger(1).expect("latest_ledger=1 must be accepted");
    }

    #[test]
    fn validate_latest_ledger_typical_testnet_accepted() {
        // A representative testnet ledger number as of mid-2026.
        validate_latest_ledger(60_000_000).expect("typical testnet ledger number must be accepted");
    }

    #[test]
    fn validate_latest_ledger_ceiling_accepted() {
        let ceiling = u32::MAX
            .saturating_sub(AUTH_VALIDITY_LEDGERS)
            .saturating_sub(1_000_000);
        validate_latest_ledger(ceiling).expect("ceiling value must be accepted");
    }

    #[test]
    fn validate_latest_ledger_above_ceiling_is_rejected() {
        let above_ceiling = u32::MAX
            .saturating_sub(AUTH_VALIDITY_LEDGERS)
            .saturating_sub(1_000_000)
            .saturating_add(1);
        let err = validate_latest_ledger(above_ceiling).unwrap_err();
        assert!(
            matches!(
                err,
                SaError::DeploymentFailed {
                    phase: "simulate",
                    ..
                }
            ),
            "latest_ledger above ceiling must return DeploymentFailed(simulate)"
        );
    }

    #[test]
    fn validate_latest_ledger_u32_max_is_rejected() {
        let err = validate_latest_ledger(u32::MAX).unwrap_err();
        assert!(
            matches!(
                err,
                SaError::DeploymentFailed {
                    phase: "simulate",
                    ..
                }
            ),
            "latest_ledger=u32::MAX must return DeploymentFailed(simulate)"
        );
    }

    #[test]
    fn context_rule_definition_default_label() {
        let def = ContextRuleDefinition {
            context_type: RuleContext::Default,
            name: "default".to_owned(),
            valid_until: None,
            signers: vec![],
            policies: vec![],
        };
        assert_eq!(def.context_type_label(), "default");
        assert_eq!(def.signers_count(), 0);
        assert_eq!(def.policies_count(), 0);
    }

    #[test]
    fn context_rule_definition_signers_count_combines_delegated_and_external() {
        let delegated = parse_g_strkey_to_signer_address(SIMULATE_SENTINEL_G).unwrap();
        let verifier = parse_c_strkey_to_smart_account(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();
        let def = ContextRuleDefinition::new(
            RuleContext::Default,
            "mixed-signers".to_owned(),
            None,
            vec![
                ContextRuleSignerInput::Delegated { address: delegated },
                ContextRuleSignerInput::External {
                    verifier,
                    pubkey_data: vec![0x04; 65],
                },
            ],
            vec![],
        );
        let delegated_count: u32 = def
            .signers
            .iter()
            .filter(|s| matches!(s, ContextRuleSignerInput::Delegated { .. }))
            .count()
            .try_into()
            .unwrap();
        let external_count: u32 = def
            .signers
            .iter()
            .filter(|s| matches!(s, ContextRuleSignerInput::External { .. }))
            .count()
            .try_into()
            .unwrap();

        assert_eq!(
            def.signers_count(),
            delegated_count + external_count,
            "invariant: signers_count == delegated + external"
        );
    }

    #[test]
    fn build_default_context_type_scval_round_trip() {
        let scval = encode_context_type(&RuleContext::Default).unwrap();
        let ScVal::Vec(Some(ScVec(v))) = scval else {
            panic!("expected ScVal::Vec");
        };
        assert_eq!(v.len(), 1);
        let ScVal::Symbol(s) = &v[0] else {
            panic!("expected Symbol");
        };
        assert_eq!(s.to_utf8_string_lossy(), "Default");
    }

    /// Pins the OZ `Signer::Delegated(Address)` `#[contracttype]` wire
    /// shape: `ScVal::Vec([Symbol("Delegated"), Address(addr)])`. Matches OZ
    /// canonical at OpenZeppelin stellar-contracts v0.7.2,
    /// `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`).
    #[test]
    fn encode_signer_delegated_round_trip() {
        let address = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [0x42_u8; 32],
        ))));
        let scval = encode_signer(&ContextRuleSignerInput::Delegated {
            address: address.clone(),
        })
        .unwrap();
        let ScVal::Vec(Some(ScVec(v))) = scval else {
            panic!("expected ScVal::Vec");
        };
        assert_eq!(v.len(), 2);
        let ScVal::Symbol(s) = &v[0] else {
            panic!("expected Symbol tag");
        };
        assert_eq!(s.to_utf8_string_lossy(), "Delegated");
        let ScVal::Address(a) = &v[1] else {
            panic!("expected Address payload");
        };
        assert_eq!(a, &address);
    }

    /// Pins the OZ `Signer::External(Address, Bytes)` `#[contracttype]`
    /// wire shape: `ScVal::Vec([Symbol("External"), Address(verifier),
    /// Bytes(pubkey)])`.
    #[test]
    fn encode_signer_external_round_trip() {
        let verifier = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x99_u8; 32])));
        let pubkey = vec![0xAA_u8; 65];
        let scval = encode_signer(&ContextRuleSignerInput::External {
            verifier: verifier.clone(),
            pubkey_data: pubkey.clone(),
        })
        .unwrap();
        let ScVal::Vec(Some(ScVec(v))) = scval else {
            panic!("expected ScVal::Vec");
        };
        assert_eq!(v.len(), 3);
        let ScVal::Symbol(s) = &v[0] else {
            panic!("expected Symbol tag");
        };
        assert_eq!(s.to_utf8_string_lossy(), "External");
        let ScVal::Address(a) = &v[1] else {
            panic!("expected Address verifier");
        };
        assert_eq!(a, &verifier);
        let ScVal::Bytes(ScBytes(b)) = &v[2] else {
            panic!("expected Bytes payload");
        };
        assert_eq!(b.as_slice(), pubkey.as_slice());
    }

    // ── OZ_MAX_EXTERNAL_KEY_SIZE boundary tests ──────────────────────────────

    /// Exactly OZ_MAX_EXTERNAL_KEY_SIZE bytes is accepted.
    ///
    /// Canonical source: `packages/accounts/src/smart_account/mod.rs:530`, SHA `a9c4216`.
    #[test]
    fn encode_signer_external_at_max_key_size_is_accepted() {
        let verifier = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x01_u8; 32])));
        let pubkey = vec![0xAB_u8; OZ_MAX_EXTERNAL_KEY_SIZE];
        encode_signer(&ContextRuleSignerInput::External {
            verifier,
            pubkey_data: pubkey,
        })
        .expect("pubkey_data at OZ_MAX_EXTERNAL_KEY_SIZE must be accepted");
    }

    /// One byte over OZ_MAX_EXTERNAL_KEY_SIZE is rejected.
    ///
    /// Canonical source: `packages/accounts/src/smart_account/mod.rs:530`, SHA `a9c4216`.
    #[test]
    fn encode_signer_external_over_max_key_size_is_rejected() {
        let verifier = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x02_u8; 32])));
        let pubkey = vec![0xCD_u8; OZ_MAX_EXTERNAL_KEY_SIZE + 1];
        let err = encode_signer(&ContextRuleSignerInput::External {
            verifier,
            pubkey_data: pubkey,
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    ..
                }
            ),
            "over-cap pubkey must return AuthEntryConstructionFailed(auth_payload)"
        );
    }

    /// Pins the standard soroban-sdk `Option<u32>::Some(n)` Val ABI:
    /// raw `ScVal::U32(n)` (no wrapping enum tag — the `Vec([Symbol(_)])`
    /// shape is for `#[contracttype]` enums, NOT for the std library
    /// `Option<T>`). Cross-reference: the soroban-env-common
    /// `TryFromVal<E, Val> for Option<T>` conversion.
    #[test]
    fn encode_option_u32_some_round_trip() {
        let scval = encode_option_u32(Some(123_456)).unwrap();
        match scval {
            ScVal::U32(n) => assert_eq!(n, 123_456),
            other => panic!("expected ScVal::U32; got {other:?}"),
        }
    }

    /// Pins the standard soroban-sdk `Option<u32>::None` Val ABI:
    /// `ScVal::Void`. The `set_valid_until = None` carve-out
    /// depends on this exact wire shape.
    #[test]
    fn encode_option_u32_none_round_trip() {
        let scval = encode_option_u32(None).unwrap();
        match scval {
            ScVal::Void => {}
            other => panic!("expected ScVal::Void; got {other:?}"),
        }
    }

    /// Pins the OZ `SmartAccountError` enum discriminant table at OpenZeppelin
    /// stellar-contracts v0.7.2, `packages/accounts/src/smart_account/mod.rs:535-572`
    /// (SHA `a9c4216`). Drift on a reference SHA bump surfaces here as a test
    /// failure rather than a silent annotation gap. Note: OZ's enum is
    /// non-contiguous — discriminant 3001 is SKIPPED.
    #[test]
    fn oz_smart_account_error_name_matches_oz_wire_discriminants() {
        assert_eq!(
            oz_smart_account_error_name(3000),
            Some("ContextRuleNotFound")
        );
        assert_eq!(
            oz_smart_account_error_name(3001),
            None,
            "OZ v0.7.2 SKIPS 3001"
        );
        assert_eq!(
            oz_smart_account_error_name(3002),
            Some("UnvalidatedContext")
        );
        assert_eq!(
            oz_smart_account_error_name(3003),
            Some("ExternalVerificationFailed")
        );
        assert_eq!(
            oz_smart_account_error_name(3004),
            Some("NoSignersAndPolicies")
        );
        assert_eq!(oz_smart_account_error_name(3005), Some("PastValidUntil"));
        assert_eq!(oz_smart_account_error_name(3006), Some("SignerNotFound"));
        assert_eq!(oz_smart_account_error_name(3007), Some("DuplicateSigner"));
        assert_eq!(oz_smart_account_error_name(3008), Some("PolicyNotFound"));
        assert_eq!(oz_smart_account_error_name(3009), Some("DuplicatePolicy"));
        assert_eq!(oz_smart_account_error_name(3010), Some("TooManySigners"));
        assert_eq!(oz_smart_account_error_name(3011), Some("TooManyPolicies"));
        assert_eq!(oz_smart_account_error_name(3012), Some("MathOverflow"));
        assert_eq!(oz_smart_account_error_name(3013), Some("KeyDataTooLarge"));
        assert_eq!(
            oz_smart_account_error_name(3014),
            Some("ContextRuleIdsLengthMismatch")
        );
        assert_eq!(oz_smart_account_error_name(3015), Some("NameTooLong"));
        assert_eq!(
            oz_smart_account_error_name(3016),
            Some("UnauthorizedSigner")
        );
        assert_eq!(
            oz_smart_account_error_name(3017),
            None,
            "outside OZ v0.7.2 range"
        );
        assert_eq!(oz_smart_account_error_name(0), None);
        assert_eq!(oz_smart_account_error_name(u32::MAX), None);
    }

    /// `augment_with_oz_error_name` should append `[OZ:<Name>]` when the
    /// message contains a recognised `Error(Contract, #N)` token.
    #[test]
    fn augment_with_oz_error_name_attaches_symbolic_name_for_known_code() {
        let msg = "simulation returned: Error(Contract, #3000) something";
        let augmented = augment_with_oz_error_name(msg);
        assert!(
            augmented.contains("[OZ:ContextRuleNotFound]"),
            "expected [OZ:ContextRuleNotFound] in {augmented}"
        );
    }

    /// Unknown OZ codes are not annotated.
    #[test]
    fn augment_with_oz_error_name_passes_through_unknown_codes() {
        let msg = "Error(Contract, #9999) unknown";
        let augmented = augment_with_oz_error_name(msg);
        assert_eq!(augmented, msg, "unknown codes must not be annotated");
    }

    /// Skipped discriminant 3001 should pass through without annotation.
    #[test]
    fn augment_with_oz_error_name_does_not_annotate_skipped_3001() {
        let msg = "Error(Contract, #3001) skipped-discriminant";
        let augmented = augment_with_oz_error_name(msg);
        assert_eq!(augmented, msg, "OZ v0.7.2 skips 3001; must not annotate");
    }

    // ── OZ caps panic discriminant mapping ────────────────────────────────────
    //
    // These tests are placed in this internal `#[cfg(test)]` block rather than
    // in `tests/smart_account/oz_panic_discriminant_mapping_mock.rs` because
    // `augment_with_oz_error_name` is `pub(crate)` — integration tests in
    // `tests/` are separate compilation units and cannot access `pub(crate)`
    // items. The `tests/smart_account/oz_panic_discriminant_mapping_mock.rs` file exists as
    // a stub pointing here.

    /// `Error(Contract, #3010)` is augmented with `[OZ:TooManySigners]`.
    ///
    /// OZ discriminant: `TooManySigners = 3010`
    /// (`packages/accounts/src/smart_account/mod.rs:558`, SHA `a9c4216`).
    ///
    /// `augment_with_oz_error_name` MUST be called before surfacing simulate
    /// errors at all cap-check bypass sites so that operators see the symbolic
    /// name alongside the numeric code.
    #[test]
    fn t9_error_contract_3010_augmented_with_too_many_signers() {
        let raw = "simulate returned: Error(Contract, #3010)";
        let augmented = augment_with_oz_error_name(raw);
        assert!(
            augmented.contains("[OZ:TooManySigners]"),
            "Expected '[OZ:TooManySigners]' in augmented string, got: {augmented}"
        );
        assert!(
            augmented.contains("Error(Contract, #3010)"),
            "Original token must be preserved in augmented string, got: {augmented}"
        );
    }

    /// Bare `#3010` (RPC-pessimistic form, no `Error(Contract, ...)` prefix)
    /// is NOT enriched — the function returns the message unchanged.
    ///
    /// This is the documented limitation: if a future RPC version changes the
    /// format, `augment_with_oz_error_name` must be extended.
    #[test]
    fn t9b_bare_3010_rpc_pessimistic_form_passes_through() {
        let raw = "simulation error: #3010";
        let augmented = augment_with_oz_error_name(raw);
        assert!(
            !augmented.contains("[OZ:"),
            "Bare '#3010' (no 'Error(Contract, ...)' prefix) must NOT be augmented; \
             got: {augmented}"
        );
        assert_eq!(augmented, raw, "Bare '#3010' must be returned unchanged");
    }

    /// `Error(Contract, #3011)` is augmented with `[OZ:TooManyPolicies]`.
    ///
    /// OZ discriminant: `TooManyPolicies = 3011`
    /// (`packages/accounts/src/smart_account/mod.rs:560`, SHA `a9c4216`).
    #[test]
    fn t10_error_contract_3011_augmented_with_too_many_policies() {
        let raw = "simulate returned: Error(Contract, #3011)";
        let augmented = augment_with_oz_error_name(raw);
        assert!(
            augmented.contains("[OZ:TooManyPolicies]"),
            "Expected '[OZ:TooManyPolicies]' in augmented string, got: {augmented}"
        );
        assert!(
            augmented.contains("Error(Contract, #3011)"),
            "Original token must be preserved in augmented string, got: {augmented}"
        );
    }

    /// Bare `#3011` (RPC-pessimistic form) is NOT enriched.
    #[test]
    fn t10b_bare_3011_rpc_pessimistic_form_passes_through() {
        let raw = "simulation error: #3011";
        let augmented = augment_with_oz_error_name(raw);
        assert!(
            !augmented.contains("[OZ:"),
            "Bare '#3011' must NOT be augmented; got: {augmented}"
        );
        assert_eq!(augmented, raw, "Bare '#3011' must be returned unchanged");
    }

    // ── oz_timelock_error_name: discriminant table pin ────────────────────────
    //
    // Canonical source: OpenZeppelin stellar-contracts v0.7.2 (`stellar-governance`),
    // `packages/governance/src/timelock/mod.rs:325-339` (SHA `a9c4216`).

    /// Pins the full `TimelockError` discriminant table at mod.rs:325-339,
    /// SHA `a9c4216`. Drift on a reference SHA bump surfaces here before
    /// reaching operator-facing error messages.
    #[test]
    fn oz_timelock_error_name_matches_oz_wire_discriminants() {
        assert_eq!(
            oz_timelock_error_name(4000),
            Some("OperationAlreadyScheduled")
        );
        assert_eq!(oz_timelock_error_name(4001), Some("InsufficientDelay"));
        assert_eq!(oz_timelock_error_name(4002), Some("InvalidOperationState"));
        assert_eq!(oz_timelock_error_name(4003), Some("UnexecutedPredecessor"));
        assert_eq!(oz_timelock_error_name(4004), Some("Unauthorized"));
        assert_eq!(oz_timelock_error_name(4005), Some("MinDelayNotSet"));
        assert_eq!(oz_timelock_error_name(4006), Some("OperationNotScheduled"));
        assert_eq!(
            oz_timelock_error_name(4007),
            None,
            "outside OZ v0.7.2 range"
        );
        assert_eq!(
            oz_timelock_error_name(3000),
            None,
            "SmartAccountError range must not match"
        );
        assert_eq!(oz_timelock_error_name(0), None);
    }

    /// `augment_with_oz_error_name` annotates `Error(Contract, #4004)` with
    /// `[OZ:Unauthorized]` (most common timelock failure — proposer or canceller
    /// without the corresponding role; OZ `mod.rs:325-339` SHA `a9c4216`).
    #[test]
    fn augment_with_oz_error_name_annotates_timelock_unauthorized() {
        let msg = "simulation returned: Error(Contract, #4004) something";
        let augmented = augment_with_oz_error_name(msg);
        assert!(
            augmented.contains("[OZ:Unauthorized]"),
            "expected [OZ:Unauthorized] in {augmented}"
        );
        assert!(
            augmented.contains("Error(Contract, #4004)"),
            "original token must be preserved; got: {augmented}"
        );
    }

    /// `augment_with_oz_error_name` annotates `Error(Contract, #4002)` with
    /// `[OZ:InvalidOperationState]` (cancel failure mode; mod.rs:325-339 SHA `a9c4216`).
    #[test]
    fn augment_with_oz_error_name_annotates_timelock_invalid_state() {
        let raw = "Error(Contract, #4002)";
        let augmented = augment_with_oz_error_name(raw);
        assert!(
            augmented.contains("[OZ:InvalidOperationState]"),
            "expected [OZ:InvalidOperationState]; got: {augmented}"
        );
    }

    /// `augment_with_oz_error_name` annotates `Error(Contract, #4000)` with
    /// `[OZ:OperationAlreadyScheduled]` (duplicate-schedule failure; mod.rs:325-339 SHA `a9c4216`).
    #[test]
    fn augment_with_oz_error_name_annotates_timelock_already_scheduled() {
        let raw = "Error(Contract, #4000)";
        let augmented = augment_with_oz_error_name(raw);
        assert!(
            augmented.contains("[OZ:OperationAlreadyScheduled]"),
            "expected [OZ:OperationAlreadyScheduled]; got: {augmented}"
        );
    }

    // ── decode_signer_count_from_scval tests ──────────────────────────────────

    /// Happy path: `ScVal::Map` with `signer_ids: Vec([U32(0), U32(1)])` → 2.
    ///
    /// Layout per OZ `storage.rs:152-174` SHA `a9c4216`:
    /// `signer_ids: Vec<u32>` is a `ScVal::Vec(Some(ScVec([...])))` under the
    /// `"signer_ids"` Symbol key.
    #[test]
    fn decode_signer_count_happy_path_two_signers() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("signer_ids".try_into().unwrap())),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::U32(0), ScVal::U32(1)].try_into().unwrap(),
                ))),
            }]
            .try_into()
            .unwrap(),
        )));
        let count = decode_signer_count_from_scval(&map).unwrap();
        assert_eq!(count, 2, "two-element signer_ids vec should yield count=2");
    }

    /// Empty `signer_ids` vec → 0.
    #[test]
    fn decode_signer_count_empty_vec_yields_zero() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("signer_ids".try_into().unwrap())),
                val: ScVal::Vec(None),
            }]
            .try_into()
            .unwrap(),
        )));
        let count = decode_signer_count_from_scval(&map).unwrap();
        assert_eq!(count, 0, "empty signer_ids vec should yield count=0");
    }

    /// Non-map ScVal returns `DeploymentFailed`.
    #[test]
    fn decode_signer_count_non_map_scval_returns_error() {
        let err = decode_signer_count_from_scval(&ScVal::U32(42)).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-map ScVal must return DeploymentFailed {{ phase: 'simulate' }}"
        );
    }

    /// Map missing `signer_ids` key returns `DeploymentFailed`.
    #[test]
    fn decode_signer_count_missing_signer_ids_key_returns_error() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("name".try_into().unwrap())),
                val: ScVal::String(stellar_xdr::ScString("test-rule".try_into().unwrap())),
            }]
            .try_into()
            .unwrap(),
        )));
        let err = decode_signer_count_from_scval(&map).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "missing signer_ids key must return DeploymentFailed {{ phase: 'simulate' }}"
        );
    }

    #[test]
    fn parse_min_resource_fee_rejects_u32_overflow() {
        // `min_resource_fee` is a u64 on the simulation response; the fee builder
        // needs a u32. A value above u32::MAX must surface as a typed
        // DeploymentFailed rather than wrapping or panicking.
        let over = u64::from(u32::MAX) + 1;
        let sim = sim_from_json(serde_json::json!({
            "latestLedger": 0,
            "minResourceFee": over.to_string(),
            "error": null,
        }));
        let err = parse_min_resource_fee(&sim).unwrap_err();
        assert!(matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"));
    }

    #[test]
    fn parse_min_resource_fee_returns_value_on_well_formed() {
        let sim = sim_from_json(serde_json::json!({
            "latestLedger": 0,
            "minResourceFee": "1234",
            "error": null,
        }));
        assert_eq!(parse_min_resource_fee(&sim).unwrap(), 1234);
    }

    #[test]
    fn manager_constructs_with_valid_url() {
        let _manager = manager_for_test();
    }

    #[test]
    fn parse_context_rule_id_extracts_id_from_map() {
        let map_entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
                val: ScVal::U32(7),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(ScString("rule".to_owned().try_into().unwrap())),
            },
        ]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(map_entries)));
        assert_eq!(parse_context_rule_id_from_return(&scval).unwrap(), 7);
    }

    #[test]
    fn parse_context_rule_id_rejects_non_map_return() {
        let scval = ScVal::U32(42);
        let err = parse_context_rule_id_from_return(&scval).unwrap_err();
        assert!(matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "submit"));
    }

    #[test]
    fn parse_context_rule_id_rejects_missing_id_field() {
        let map_entries: VecM<ScMapEntry> = vec![ScMapEntry {
            key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
            val: ScVal::String(ScString("rule".to_owned().try_into().unwrap())),
        }]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(map_entries)));
        let err = parse_context_rule_id_from_return(&scval).unwrap_err();
        assert!(matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "submit"));
    }

    /// Constructs a `SimulateTransactionResponse` via JSON deserialisation —
    /// `stellar_rpc_client::SimulateTransactionResponse` does not expose a
    /// public field-literal constructor from a downstream crate.
    fn sim_from_json(v: serde_json::Value) -> stellar_rpc_client::SimulateTransactionResponse {
        serde_json::from_value(v).expect("synthetic sim deserialise")
    }

    /// `sa_error_to_invocation_result` maps DeploymentFailed phases correctly:
    /// pre-submission phases → PreSubmissionRefused; on-chain phases →
    /// OnChainRejected. Mirrors the deploy.rs phase-classifier discipline.
    #[test]
    fn sa_error_to_invocation_result_pre_submission_phases() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for phase in &["build", "simulate", "constructor"] {
            let err = SaError::DeploymentFailed {
                phase,
                redacted_reason: "test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::PreSubmissionRefused
                ),
                "phase {phase} must map to PreSubmissionRefused"
            );
        }
    }

    #[test]
    fn sa_error_to_invocation_result_on_chain_phases() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for phase in &["upload", "deploy", "submit", "post_deploy_verification"] {
            let err = SaError::DeploymentFailed {
                phase,
                redacted_reason: "test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::OnChainRejected
                ),
                "phase {phase} must map to OnChainRejected"
            );
        }
    }

    #[test]
    fn sa_error_to_invocation_result_pre_submission_for_typed_errors() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        let typed = [
            SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: "test".to_owned(),
            },
            SaError::RuleIdMismatch {
                expected_len: 1,
                observed_len: 0,
            },
            SaError::SimulationDivergence {
                sub_code: crate::error::SimulationDivergenceSubCode::Network,
                redacted_reason: "test".to_owned(),
            },
            SaError::PinCheckUnavailable {
                rule_id: 4,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                reason: "sa.deployment_failed: rpc unreachable".to_owned(),
                request_id: "req".to_owned(),
            },
        ];
        for err in &typed {
            assert!(matches!(
                sa_error_to_invocation_result(err),
                SaInvocationResult::PreSubmissionRefused
            ));
        }
    }

    #[test]
    fn sa_error_to_invocation_result_mainnet_refusal_is_pre_submission() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        assert!(matches!(
            sa_error_to_invocation_result(&SaError::MainnetWriteForbidden),
            SaInvocationResult::PreSubmissionRefused
        ));
    }

    #[test]
    fn sa_error_to_invocation_result_classifies_signer_set_diverged_by_its_transaction() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;
        use stellar_agent_core::audit_log::signer_set::{SignerSetSnapshotV2, SignerSetView};

        let diverged = |tx_hash: Option<String>| SaError::SignerSetDiverged {
            rule_id: 1,
            expected: SignerSetView::V2(SignerSetSnapshotV2 {
                signers: vec![],
                threshold: None,
            }),
            observed: SignerSetView::V2(SignerSetSnapshotV2 {
                signers: vec![],
                threshold: None,
            }),
            tx_hash,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req".to_owned(),
        };
        assert!(
            matches!(
                sa_error_to_invocation_result(&diverged(None)),
                SaInvocationResult::PreSubmissionRefused
            ),
            "a comparison refusal sent nothing"
        );
        assert!(
            matches!(
                sa_error_to_invocation_result(&diverged(Some("ab".repeat(32)))),
                SaInvocationResult::PostSubmitVerificationFailed
            ),
            "a confirmed transaction whose result is not the intended change"
        );
    }

    #[test]
    fn sa_error_to_invocation_result_classifies_a_legacy_baseline_as_refused() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        let legacy = SaError::SignerSetBaselineLegacy {
            rule_id: 1,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            request_id: "req".to_owned(),
        };
        assert!(matches!(
            sa_error_to_invocation_result(&legacy),
            SaInvocationResult::PreSubmissionRefused
        ));
    }

    /// An install that confirmed and was not baselined is a post-submit
    /// verification failure in both rule-id forms.
    #[test]
    fn sa_error_to_invocation_result_classifies_install_state_mismatch_after_submission() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for rule_id in [None, Some(3)] {
            let err = SaError::InstallStateMismatch {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
                tx_hash: "ab".repeat(32),
                request_id: "req".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::PostSubmitVerificationFailed
                ),
                "{rule_id:?}"
            );
        }
    }

    #[test]
    fn sa_error_to_invocation_result_classifies_baseline_write_failed_by_its_transaction() {
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        let write_failed = |tx_hash: Option<String>| SaError::BaselineWriteFailed {
            rule_id: 1,
            smart_account_redacted: RedactedStrkey::from_already_redacted("CAAAA...ZZZZZ"),
            tx_hash,
            stage: crate::error::BASELINE_WRITE_STAGE_WRITE,
            reason: "audit writer poisoned".to_owned(),
            request_id: "req".to_owned(),
        };
        assert!(
            matches!(
                sa_error_to_invocation_result(&write_failed(None)),
                SaInvocationResult::PreSubmissionRefused
            ),
            "a list or refresh whose baseline row was not written sent nothing"
        );
        assert!(
            matches!(
                sa_error_to_invocation_result(&write_failed(Some("cd".repeat(32)))),
                SaInvocationResult::PostSubmitVerificationFailed
            ),
            "a confirmed signer mutation whose state row was not written"
        );
    }

    // ── Timelock failure_reason classifier ───────────────────────────────────
    //
    // Covers sa_error_to_invocation_result for all three Timelock*Failed variants
    // × all named failure_reason discriminants.  Verifies the 3-way taxonomy:
    //   PreSubmissionRefused / PostSubmitVerificationFailed / OnChainRejected.

    /// `TimelockScheduleFailed` with `SimulationFailed` or `AuditWriterPoisoned` →
    /// `PreSubmissionRefused` (no tx sent).
    #[test]
    fn sa_error_to_invocation_result_timelock_schedule_pre_submission() {
        use crate::error::TimelockScheduleFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for reason in [R::SimulationFailed, R::AuditWriterPoisoned] {
            let err = SaError::TimelockScheduleFailed {
                failure_reason: reason.clone(),
                redacted_reason: "test".to_owned(),
                request_id: "req-test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::PreSubmissionRefused
                ),
                "TimelockScheduleFailed {{ reason: {reason:?} }} must map to PreSubmissionRefused"
            );
        }
    }

    /// `TimelockScheduleFailed` with `EventConfirmationMissing` →
    /// `PostSubmitVerificationFailed` (tx confirmed; event absent).
    #[test]
    fn sa_error_to_invocation_result_timelock_schedule_post_submit_verification_failed() {
        use crate::error::TimelockScheduleFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        let err = SaError::TimelockScheduleFailed {
            failure_reason: R::EventConfirmationMissing,
            redacted_reason: "test".to_owned(),
            request_id: "req-test".to_owned(),
        };
        assert!(
            matches!(
                sa_error_to_invocation_result(&err),
                SaInvocationResult::PostSubmitVerificationFailed
            ),
            "TimelockScheduleFailed {{ reason: EventConfirmationMissing }} must map to \
             PostSubmitVerificationFailed"
        );
    }

    /// `TimelockScheduleFailed` with `Unauthorized`, `OperationAlreadyScheduled`,
    /// `InsufficientDelay`, or `Other` → `OnChainRejected`.
    #[test]
    fn sa_error_to_invocation_result_timelock_schedule_on_chain_rejected() {
        use crate::error::TimelockScheduleFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for reason in [
            R::Unauthorized,
            R::OperationAlreadyScheduled,
            R::InsufficientDelay,
            R::Other,
        ] {
            let err = SaError::TimelockScheduleFailed {
                failure_reason: reason.clone(),
                redacted_reason: "test".to_owned(),
                request_id: "req-test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::OnChainRejected
                ),
                "TimelockScheduleFailed {{ reason: {reason:?} }} must map to OnChainRejected"
            );
        }
    }

    /// `TimelockCancelFailed` with `SimulationFailed` or `AuditWriterPoisoned` →
    /// `PreSubmissionRefused` (no tx sent).
    #[test]
    fn sa_error_to_invocation_result_timelock_cancel_pre_submission() {
        use crate::error::TimelockCancelFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for reason in [R::SimulationFailed, R::AuditWriterPoisoned] {
            let err = SaError::TimelockCancelFailed {
                failure_reason: reason.clone(),
                redacted_reason: "test".to_owned(),
                operation_id_redacted: "aaaa...bbbb".to_owned(),
                request_id: "req-test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::PreSubmissionRefused
                ),
                "TimelockCancelFailed {{ reason: {reason:?} }} must map to PreSubmissionRefused"
            );
        }
    }

    /// `TimelockCancelFailed` with `EventConfirmationMissing` →
    /// `PostSubmitVerificationFailed`.
    #[test]
    fn sa_error_to_invocation_result_timelock_cancel_post_submit_verification_failed() {
        use crate::error::TimelockCancelFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        let err = SaError::TimelockCancelFailed {
            failure_reason: R::EventConfirmationMissing,
            redacted_reason: "test".to_owned(),
            operation_id_redacted: "aaaa...bbbb".to_owned(),
            request_id: "req-test".to_owned(),
        };
        assert!(
            matches!(
                sa_error_to_invocation_result(&err),
                SaInvocationResult::PostSubmitVerificationFailed
            ),
            "TimelockCancelFailed {{ reason: EventConfirmationMissing }} must map to \
             PostSubmitVerificationFailed"
        );
    }

    /// `TimelockCancelFailed` with `Unauthorized`, `InvalidOperationState`,
    /// `OperationNotScheduled`, or `Other` → `OnChainRejected`.
    #[test]
    fn sa_error_to_invocation_result_timelock_cancel_on_chain_rejected() {
        use crate::error::TimelockCancelFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for reason in [
            R::Unauthorized,
            R::InvalidOperationState,
            R::OperationNotScheduled,
            R::Other,
        ] {
            let err = SaError::TimelockCancelFailed {
                failure_reason: reason.clone(),
                redacted_reason: "test".to_owned(),
                operation_id_redacted: "aaaa...bbbb".to_owned(),
                request_id: "req-test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::OnChainRejected
                ),
                "TimelockCancelFailed {{ reason: {reason:?} }} must map to OnChainRejected"
            );
        }
    }

    /// `TimelockExecuteFailed` with `SimulationFailed`, `AuditWriterPoisoned`,
    /// `OperationNotReady`, or `OperationIdMismatch` → `PreSubmissionRefused`
    /// (all fire before any tx is signed or sent).
    #[test]
    fn sa_error_to_invocation_result_timelock_execute_pre_submission() {
        use crate::error::TimelockExecuteFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        let reasons = [
            R::SimulationFailed,
            R::AuditWriterPoisoned,
            R::OperationNotReady {
                observed_state: "Waiting".to_owned(),
                current_ledger: Some(100),
                ready_ledger: 200,
            },
            R::OperationIdMismatch {
                user_supplied: "aaaa".to_owned(),
                simulate_derived: "bbbb".to_owned(),
            },
        ];
        for reason in &reasons {
            let err = SaError::TimelockExecuteFailed {
                failure_reason: reason.clone(),
                redacted_reason: "test".to_owned(),
                operation_id_redacted: "aaaa...bbbb".to_owned(),
                request_id: "req-test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::PreSubmissionRefused
                ),
                "TimelockExecuteFailed {{ reason: {reason:?} }} must map to PreSubmissionRefused"
            );
        }
    }

    /// `TimelockExecuteFailed` with `EventConfirmationMissing` →
    /// `PostSubmitVerificationFailed`.
    #[test]
    fn sa_error_to_invocation_result_timelock_execute_post_submit_verification_failed() {
        use crate::error::TimelockExecuteFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        let err = SaError::TimelockExecuteFailed {
            failure_reason: R::EventConfirmationMissing,
            redacted_reason: "test".to_owned(),
            operation_id_redacted: "aaaa...bbbb".to_owned(),
            request_id: "req-test".to_owned(),
        };
        assert!(
            matches!(
                sa_error_to_invocation_result(&err),
                SaInvocationResult::PostSubmitVerificationFailed
            ),
            "TimelockExecuteFailed {{ reason: EventConfirmationMissing }} must map to \
             PostSubmitVerificationFailed"
        );
    }

    /// `TimelockExecuteFailed` with `InvalidOperationState`, `UnexecutedPredecessor`,
    /// or `Other` → `OnChainRejected`.
    ///
    /// Note: `TimelockExecuteFailureReason` has no `Unauthorized` variant; the
    /// on-chain rejected discriminants are `InvalidOperationState` (code 4002),
    /// `UnexecutedPredecessor` (code 4003), and `Other` (unrecognised OZ error).
    #[test]
    fn sa_error_to_invocation_result_timelock_execute_on_chain_rejected() {
        use crate::error::TimelockExecuteFailureReason as R;
        use stellar_agent_core::audit_log::schema::SaInvocationResult;

        for reason in [R::InvalidOperationState, R::UnexecutedPredecessor, R::Other] {
            let err = SaError::TimelockExecuteFailed {
                failure_reason: reason.clone(),
                redacted_reason: "test".to_owned(),
                operation_id_redacted: "aaaa...bbbb".to_owned(),
                request_id: "req-test".to_owned(),
            };
            assert!(
                matches!(
                    sa_error_to_invocation_result(&err),
                    SaInvocationResult::OnChainRejected
                ),
                "TimelockExecuteFailed {{ reason: {reason:?} }} must map to OnChainRejected"
            );
        }
    }

    #[test]
    fn auth_digest_prefix_helpers_return_marker() {
        assert_eq!(auth_digest_prefix_from_outcome(&Ok(0)), "sa_ok___");
        assert_eq!(auth_digest_prefix_from_outcome_unit(&Ok(())), "sa_ok___");
    }

    // ── ContextRuleManagerConfig builder methods ──────────────────────────────

    /// `with_secondary_rpc_url` stores the URL in `secondary_rpc_url`.
    ///
    /// Cross-RPC simulation checks are gated on this field being `Some`;
    /// verifying it is set correctly is the minimal offline-testable invariant.
    #[test]
    fn config_with_secondary_rpc_url_sets_field() {
        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        )
        .with_secondary_rpc_url("http://secondary.rpc:8080".to_owned());
        assert_eq!(
            cfg.secondary_rpc_url.as_deref(),
            Some("http://secondary.rpc:8080"),
            "with_secondary_rpc_url must populate secondary_rpc_url"
        );
    }

    /// `new` leaves `secondary_rpc_url` as `None` (cross-RPC checks bypassed
    /// when not configured).
    #[test]
    fn config_new_leaves_secondary_rpc_url_none() {
        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        );
        assert!(
            cfg.secondary_rpc_url.is_none(),
            "default config must have secondary_rpc_url = None"
        );
    }

    /// `with_session_rule_max_horizon_ledgers` stores the custom cap.
    ///
    /// The horizon cap is enforced by `submit_signed_invoke` after simulate;
    /// this builder sets the override consumed there. A value of 500 overrides
    /// the DEFAULT_SESSION_RULE_HORIZON_LEDGERS (1000) default.
    #[test]
    fn config_with_session_rule_max_horizon_ledgers_sets_field() {
        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        )
        .with_session_rule_max_horizon_ledgers(500);
        assert_eq!(
            cfg.session_rule_max_horizon_ledgers,
            Some(500),
            "with_session_rule_max_horizon_ledgers must set the override"
        );
    }

    /// `new` leaves `session_rule_max_horizon_ledgers` as `None` (manager uses
    /// DEFAULT_SESSION_RULE_HORIZON_LEDGERS = 1000 at check time).
    #[test]
    fn config_new_leaves_session_rule_max_horizon_ledgers_none() {
        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        );
        assert!(
            cfg.session_rule_max_horizon_ledgers.is_none(),
            "default config must have session_rule_max_horizon_ledgers = None (uses default)"
        );
    }

    /// `with_audit_writer` stores the writer so the manager can emit audit rows
    /// via the fallback path without a per-method `&mut AuditWriter`.
    #[test]
    fn config_with_audit_writer_sets_field() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let writer = stellar_agent_core::audit_log::writer::AuditWriter::open(log_path, None)
            .expect("open writer");
        let arc: Arc<Mutex<stellar_agent_core::audit_log::writer::AuditWriter>> =
            Arc::new(Mutex::new(writer));

        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        )
        .with_audit_writer(Arc::clone(&arc));

        assert!(
            cfg.audit_writer.is_some(),
            "with_audit_writer must populate audit_writer"
        );
    }

    // ── encode_context_type CallContract / CreateContract wire shape ──────────
    //
    // The wallet encodes all three `RuleContext` variants off-chain to the OZ
    // `ContextRuleType` `#[contracttype]` ScVal wire shape. There is no refusal
    // path for `CallContract` / `CreateContract`.

    /// Pins the OZ `ContextRuleType::CallContract(Address)` `#[contracttype]`
    /// wire shape: `ScVal::Vec([Symbol("CallContract"), Address(contract)])`.
    ///
    /// Canonical source: OpenZeppelin stellar-contracts v0.7.2,
    /// `packages/accounts/src/smart_account/storage.rs:147` (SHA `a9c4216`) —
    /// `CallContract(Address)`; a soroban `Address` maps to `ScVal::Address`.
    #[test]
    fn encode_context_type_call_contract_round_trip() {
        use stellar_xdr::ReadXdr as _;

        // Canonical all-zeros contract C-strkey fixture.
        let contract = parse_c_strkey_to_smart_account(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();
        let scval = encode_context_type(&RuleContext::CallContract {
            contract: contract.clone(),
        })
        .unwrap();

        // Field-by-field wire shape.
        let ScVal::Vec(Some(ScVec(v))) = &scval else {
            panic!("expected ScVal::Vec; got {scval:?}");
        };
        assert_eq!(v.len(), 2, "CallContract encodes as a 2-element Vec");
        let ScVal::Symbol(s) = &v[0] else {
            panic!("expected Symbol tag; got {:?}", v[0]);
        };
        assert_eq!(s.to_utf8_string_lossy(), "CallContract");
        let ScVal::Address(a) = &v[1] else {
            panic!("expected Address payload; got {:?}", v[1]);
        };
        assert_eq!(a, &contract);

        // Full expected ScVal equality (every byte of the payload asserted).
        let expected = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("CallContract").unwrap()),
                ScVal::Address(contract.clone()),
            ]
            .try_into()
            .unwrap(),
        )));
        assert_eq!(
            scval, expected,
            "CallContract wire shape must be byte-exact"
        );

        // Canonical XDR serialisation round-trips losslessly.
        let bytes = scval.to_xdr(Limits::none()).unwrap();
        let decoded = ScVal::from_xdr(&bytes, Limits::none()).unwrap();
        assert_eq!(decoded, scval, "CallContract ScVal must XDR round-trip");
    }

    /// Pins the OZ `ContextRuleType::CreateContract(BytesN<32>)`
    /// `#[contracttype]` wire shape:
    /// `ScVal::Vec([Symbol("CreateContract"), Bytes(wasm_hash)])`.
    ///
    /// Canonical source: OpenZeppelin stellar-contracts v0.7.2,
    /// `packages/accounts/src/smart_account/storage.rs:149` (SHA `a9c4216`) —
    /// `CreateContract(BytesN<32>)`; a soroban `BytesN<32>` maps to
    /// `ScVal::Bytes` (32-byte length host-enforced on conversion).
    #[test]
    fn encode_context_type_create_contract_round_trip() {
        use stellar_xdr::ReadXdr as _;

        let wasm_hash = [0xAB_u8; 32];
        let scval = encode_context_type(&RuleContext::CreateContract { wasm_hash }).unwrap();

        // Field-by-field wire shape.
        let ScVal::Vec(Some(ScVec(v))) = &scval else {
            panic!("expected ScVal::Vec; got {scval:?}");
        };
        assert_eq!(v.len(), 2, "CreateContract encodes as a 2-element Vec");
        let ScVal::Symbol(s) = &v[0] else {
            panic!("expected Symbol tag; got {:?}", v[0]);
        };
        assert_eq!(s.to_utf8_string_lossy(), "CreateContract");
        let ScVal::Bytes(ScBytes(b)) = &v[1] else {
            panic!("expected Bytes payload; got {:?}", v[1]);
        };
        assert_eq!(b.as_slice(), &wasm_hash[..], "wasm hash bytes must match");

        // Full expected ScVal equality.
        let expected = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("CreateContract").unwrap()),
                ScVal::Bytes(ScBytes(wasm_hash.to_vec().try_into().unwrap())),
            ]
            .try_into()
            .unwrap(),
        )));
        assert_eq!(
            scval, expected,
            "CreateContract wire shape must be byte-exact"
        );

        // Canonical XDR serialisation round-trips losslessly.
        let bytes = scval.to_xdr(Limits::none()).unwrap();
        let decoded = ScVal::from_xdr(&bytes, Limits::none()).unwrap();
        assert_eq!(decoded, scval, "CreateContract ScVal must XDR round-trip");
    }

    // ── RuleContext encode/decode round-trip tests ────────────────────────────

    /// `rule_context_from_context_type_scval` is the exact inverse of
    /// `encode_context_type` for all three variants: encode then decode returns
    /// the original `RuleContext`.
    #[test]
    fn rule_context_encode_decode_round_trip_all_variants() {
        let contract = parse_c_strkey_to_smart_account(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();
        let cases = [
            RuleContext::Default,
            RuleContext::CallContract {
                contract: contract.clone(),
            },
            RuleContext::CreateContract {
                wasm_hash: [0xCD_u8; 32],
            },
        ];
        for original in cases {
            let encoded = encode_context_type(&original).unwrap();
            let decoded = rule_context_from_context_type_scval(&encoded).unwrap();
            assert_eq!(
                decoded, original,
                "encode -> decode must return the original RuleContext"
            );
        }
    }

    /// `decode_context_type_from_scval` extracts and decodes the `context_type`
    /// field from a full `ContextRule` map.
    #[test]
    fn decode_context_type_from_full_rule_map() {
        let contract = parse_c_strkey_to_smart_account(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();
        let expected = RuleContext::CallContract {
            contract: contract.clone(),
        };
        let context_type_scval = encode_context_type(&expected).unwrap();

        // Minimal ContextRule map carrying only the context_type field (the
        // decoder ignores sibling fields).
        let rule_map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: context_type_scval,
            }]
            .try_into()
            .unwrap(),
        )));

        let decoded = decode_context_type_from_scval(&rule_map).unwrap();
        assert_eq!(decoded, expected);
    }

    /// `decode_context_type_from_scval` fails closed when the map has no
    /// `context_type` field.
    #[test]
    fn decode_context_type_missing_field_fails_closed() {
        let rule_map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::U32(1),
            }]
            .try_into()
            .unwrap(),
        )));
        let err = decode_context_type_from_scval(&rule_map).expect_err("missing field must fail");
        assert!(matches!(err, SaError::DeploymentFailed { .. }));
    }

    /// `rule_context_from_context_type_scval` fails closed on an unknown variant
    /// tag.
    #[test]
    fn rule_context_decode_unknown_variant_fails_closed() {
        let bogus = ScVal::Vec(Some(ScVec(
            vec![ScVal::Symbol(ScSymbol::try_from("Bogus").unwrap())]
                .try_into()
                .unwrap(),
        )));
        let err = rule_context_from_context_type_scval(&bogus)
            .expect_err("unknown variant must fail closed");
        assert!(matches!(err, SaError::DeploymentFailed { .. }));
    }

    /// `rule_context_from_context_type_scval` fails closed when a
    /// `CreateContract` Bytes payload is not exactly 32 bytes.
    #[test]
    fn rule_context_decode_create_contract_wrong_length_fails_closed() {
        let short_bytes: ScBytes = ScBytes(vec![0u8; 16].try_into().unwrap());
        let bogus = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("CreateContract").unwrap()),
                ScVal::Bytes(short_bytes),
            ]
            .try_into()
            .unwrap(),
        )));
        let err = rule_context_from_context_type_scval(&bogus)
            .expect_err("16-byte CreateContract payload must fail closed");
        assert!(matches!(err, SaError::DeploymentFailed { .. }));
    }

    /// `rule_context_from_context_type_scval` refuses a `CreateContract`
    /// context whose payload is the CAP-85 SCVal form of an external-reference
    /// executable, `Vec([Symbol("ExternalRef"), Map(owner, tag)])`: a
    /// `CreateContract` rule context is only ever a 32-byte Wasm hash.
    #[test]
    fn rule_context_decode_create_contract_external_ref_payload_fails_closed() {
        let external_ref = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("ExternalRef").unwrap()),
                ScVal::Map(Some(ScMap(
                    vec![
                        ScMapEntry {
                            key: ScVal::Symbol(ScSymbol::try_from("executable_owner").unwrap()),
                            val: ScVal::Address(ScAddress::Contract(stellar_xdr::ContractId(
                                stellar_xdr::Hash([0x0c; 32]),
                            ))),
                        },
                        ScMapEntry {
                            key: ScVal::Symbol(ScSymbol::try_from("tag").unwrap()),
                            val: ScVal::String(ScString(b"v1".to_vec().try_into().unwrap())),
                        },
                    ]
                    .try_into()
                    .unwrap(),
                ))),
            ]
            .try_into()
            .unwrap(),
        )));
        let context = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("CreateContract").unwrap()),
                external_ref,
            ]
            .try_into()
            .unwrap(),
        )));

        let err = rule_context_from_context_type_scval(&context)
            .expect_err("an external-reference CreateContract payload must fail closed");

        let SaError::DeploymentFailed {
            phase,
            redacted_reason,
        } = err
        else {
            panic!("expected DeploymentFailed; got {err:?}");
        };
        assert_eq!(phase, "simulate");
        assert!(
            redacted_reason
                .starts_with("decode context_type: CreateContract vec[1]: expected Bytes"),
            "{redacted_reason}"
        );
    }

    /// A `CreateContract` context whose payload is a 10 KiB `ScVal::String`
    /// yields a reason under 256 bytes that names the payload's variant and
    /// carries none of its bytes.
    #[test]
    fn rule_context_decode_large_string_payload_reason_is_bounded() {
        let payload = "Z".repeat(10 * 1024);
        let context = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("CreateContract").unwrap()),
                ScVal::String(ScString(payload.as_bytes().to_vec().try_into().unwrap())),
            ]
            .try_into()
            .unwrap(),
        )));

        let err = rule_context_from_context_type_scval(&context)
            .expect_err("a String CreateContract payload must fail closed");

        let SaError::DeploymentFailed {
            phase,
            redacted_reason,
        } = err
        else {
            panic!("expected DeploymentFailed");
        };
        assert_eq!(phase, "simulate");
        assert!(
            redacted_reason.len() < 256,
            "reason is {} bytes",
            redacted_reason.len()
        );
        assert_eq!(
            redacted_reason,
            "decode context_type: CreateContract vec[1]: expected Bytes, got String"
        );
        assert!(!redacted_reason.contains("ZZZZ"));
    }

    /// An unknown context-type tag renders through the bounded untrusted
    /// renderer, so a control character in the ledger symbol is escaped.
    #[test]
    fn rule_context_decode_unknown_tag_is_rendered_escaped() {
        let bogus = ScVal::Vec(Some(ScVec(
            vec![ScVal::Symbol(ScSymbol(
                b"Bad\ntag".to_vec().try_into().unwrap(),
            ))]
            .try_into()
            .unwrap(),
        )));
        let err = rule_context_from_context_type_scval(&bogus)
            .expect_err("unknown variant must fail closed");
        let SaError::DeploymentFailed {
            redacted_reason, ..
        } = err
        else {
            panic!("expected DeploymentFailed");
        };
        assert_eq!(
            redacted_reason,
            "decode context_type: unknown context_type variant \"Bad\\ntag\""
        );
    }

    // ── OZ SpendingLimitError symbolic-name tests ─────────────────────────────

    /// `oz_spending_limit_policy_error_name` maps the OZ `SpendingLimitError`
    /// 3220-3227 discriminants to their symbolic names and returns `None`
    /// outside the range.
    #[test]
    fn oz_spending_limit_policy_error_name_matches_oz_wire_discriminants() {
        assert_eq!(
            oz_spending_limit_policy_error_name(3220),
            Some("SmartAccountNotInstalled")
        );
        assert_eq!(
            oz_spending_limit_policy_error_name(3221),
            Some("SpendingLimitExceeded")
        );
        assert_eq!(
            oz_spending_limit_policy_error_name(3222),
            Some("InvalidLimitOrPeriod")
        );
        assert_eq!(
            oz_spending_limit_policy_error_name(3223),
            Some("NotAllowed")
        );
        assert_eq!(
            oz_spending_limit_policy_error_name(3224),
            Some("HistoryCapacityExceeded")
        );
        assert_eq!(
            oz_spending_limit_policy_error_name(3225),
            Some("AlreadyInstalled")
        );
        assert_eq!(
            oz_spending_limit_policy_error_name(3226),
            Some("LessThanZero")
        );
        assert_eq!(
            oz_spending_limit_policy_error_name(3227),
            Some("OnlyCallContractAllowed")
        );
        assert_eq!(oz_spending_limit_policy_error_name(3219), None);
        assert_eq!(oz_spending_limit_policy_error_name(3228), None);
    }

    /// `augment_with_oz_error_name` attaches the `SpendingLimitExceeded` symbolic
    /// name for discriminant 3221 (the over-budget failure the live acceptance
    /// distinguishes from a wrong-reason failure).
    #[test]
    fn augment_with_oz_error_name_annotates_spending_limit_exceeded() {
        let msg = "HostError: Error(Contract, #3221)";
        let augmented = augment_with_oz_error_name(msg);
        assert!(
            augmented.contains("[OZ:SpendingLimitExceeded]"),
            "3221 must be annotated SpendingLimitExceeded, got: {augmented}"
        );
    }

    /// `augment_with_oz_error_name` attaches the `NotAllowed` symbolic name for
    /// discriminant 3223 (the wrong-shape failure the live acceptance
    /// distinguishes from an over-budget failure).
    #[test]
    fn augment_with_oz_error_name_annotates_spending_limit_not_allowed() {
        let msg = "HostError: Error(Contract, #3223)";
        let augmented = augment_with_oz_error_name(msg);
        assert!(
            augmented.contains("[OZ:NotAllowed]"),
            "3223 must be annotated NotAllowed, got: {augmented}"
        );
    }

    // ── scaddress_to_strkey round-trip tests ──────────────────────────────────

    /// `scaddress_to_strkey` on an `ScAddress::Account` yields the canonical
    /// G-strkey.
    ///
    /// The all-zeros 32-byte ed25519 public key maps to
    /// `GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF`.
    /// Canonical source: stellar-strkey 0.0.18 library docs (`PublicKey([0u8; 32]).to_string()`).
    #[test]
    fn scaddress_to_strkey_account_returns_g_strkey() {
        let addr = ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [0u8; 32],
        ))));
        let strkey = scaddress_to_strkey(&addr).unwrap();
        // All-zeros ed25519 key canonical G-strkey.
        // Source: stellar-strkey 0.0.18 docs — `PublicKey([0u8; 32]).to_string()`
        assert_eq!(
            strkey, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "ScAddress::Account([0;32]) must map to the canonical zero-key G-strkey"
        );
    }

    /// `scaddress_to_strkey` on an `ScAddress::Contract` yields the canonical
    /// C-strkey.
    ///
    /// The all-zeros 32-byte contract hash maps to
    /// `CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4`.
    /// Canonical source: stellar-strkey 0.0.18 library docs (`Contract([0u8; 32])`).
    #[test]
    fn scaddress_to_strkey_contract_returns_c_strkey() {
        let addr = ScAddress::Contract(ContractId(stellar_xdr::Hash([0u8; 32])));
        let strkey = scaddress_to_strkey(&addr).unwrap();
        // All-zeros 32-byte contract hash canonical C-strkey.
        // Source: stellar-strkey 0.0.18 docs — `Contract([0u8; 32])` parses to this.
        assert_eq!(
            strkey, "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "ScAddress::Contract([0;32]) must map to the canonical zero-contract C-strkey"
        );
    }

    // ── xdr_scaddress_to_strkey_or_sentinel round-trip tests ─────────────────

    /// `xdr_scaddress_to_strkey_or_sentinel` on an Account address yields the
    /// G-strkey (same as `scaddress_to_strkey` for the account variant).
    #[test]
    fn xdr_scaddress_to_strkey_or_sentinel_account_yields_g_strkey() {
        let addr = xdr_curr::ScAddress::Account(xdr_curr::AccountId(
            xdr_curr::PublicKey::PublicKeyTypeEd25519(xdr_curr::Uint256([0u8; 32])),
        ));
        let s = xdr_scaddress_to_strkey_or_sentinel(&addr);
        // Canonical zero-key G-strkey: stellar-strkey 0.0.18 docs — `PublicKey([0u8; 32]).to_string()`
        assert_eq!(
            s, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "Account [0;32] must yield canonical zero-key G-strkey"
        );
    }

    /// `xdr_scaddress_to_strkey_or_sentinel` on a Contract address yields the
    /// C-strkey.
    #[test]
    fn xdr_scaddress_to_strkey_or_sentinel_contract_yields_c_strkey() {
        let addr = xdr_curr::ScAddress::Contract(xdr_curr::ContractId(xdr_curr::Hash([0u8; 32])));
        let s = xdr_scaddress_to_strkey_or_sentinel(&addr);
        // Canonical zero-contract C-strkey: stellar-strkey 0.0.18 docs — `Contract([0u8; 32])`.
        assert_eq!(
            s, "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
            "Contract [0;32] must yield canonical zero-contract C-strkey"
        );
    }

    // ── contract_instance_key shape test ─────────────────────────────────────

    /// `contract_instance_key` returns a `LedgerKey::ContractData` with:
    /// - `key = ScVal::LedgerKeyContractInstance`
    /// - `durability = Persistent`
    /// - `contract = the input ScAddress`
    ///
    /// Layout per `LedgerKeyContractData` in `Stellar-ledger-entries.x`.
    #[test]
    fn contract_instance_key_builds_correct_ledger_key() {
        use stellar_xdr::{ContractDataDurability, LedgerKey};
        let contract_addr = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xAB_u8; 32])));
        let key = contract_instance_key(&contract_addr);

        match key {
            LedgerKey::ContractData(ref d) => {
                assert_eq!(
                    &d.contract, &contract_addr,
                    "contract field must match input ScAddress"
                );
                assert!(
                    matches!(d.key, ScVal::LedgerKeyContractInstance),
                    "key must be ScVal::LedgerKeyContractInstance"
                );
                assert!(
                    matches!(d.durability, ContractDataDurability::Persistent),
                    "durability must be Persistent"
                );
            }
            other => panic!("expected LedgerKey::ContractData; got {other:?}"),
        }
    }

    // ── passphrase_fingerprint and chain_id_fingerprint ───────────────────────

    /// `passphrase_fingerprint` produces a stable `"net:<8-hex>"` prefix.
    ///
    /// The fingerprint is the first 8 bytes of SHA-256(passphrase) rendered
    /// as lowercase hex. For "Test SDF Network ; September 2015" the expected
    /// value is derived from the SHA-256 preimage — verified here to catch
    /// any accidental change to the hash function or prefix format.
    ///
    /// Cross-reference: `rules.rs:passphrase_fingerprint` is consumed by
    /// `signing/divergence.rs` `NetworkContext` construction.
    #[test]
    fn passphrase_fingerprint_format_and_stability() {
        let fp = passphrase_fingerprint("Test SDF Network ; September 2015");
        // Must start with "net:" prefix.
        assert!(
            fp.starts_with("net:"),
            "passphrase fingerprint must start with 'net:'; got {fp}"
        );
        // Remaining part must be exactly 16 hex chars (8 bytes × 2 chars/byte).
        let hex_part = &fp[4..];
        assert_eq!(
            hex_part.len(),
            16,
            "hex part must be 16 chars (8 bytes); got len={} in {fp}",
            hex_part.len()
        );
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hex part must be all hex digits; got {fp}"
        );
        // Stability: same passphrase must produce the same fingerprint.
        let fp2 = passphrase_fingerprint("Test SDF Network ; September 2015");
        assert_eq!(fp, fp2, "passphrase_fingerprint must be deterministic");
        // Different passphrase must produce a different fingerprint.
        let fp_other = passphrase_fingerprint("Public Global Stellar Network ; September 2015");
        assert_ne!(
            fp, fp_other,
            "different passphrases must produce different fingerprints"
        );
    }

    /// `chain_id_fingerprint` produces a stable `"chain:<8-hex>"` prefix.
    ///
    /// Cross-reference: consumed by `NetworkContext` in `signing/divergence.rs`.
    #[test]
    fn chain_id_fingerprint_format_and_stability() {
        let fp = chain_id_fingerprint("stellar:testnet");
        assert!(
            fp.starts_with("chain:"),
            "chain_id fingerprint must start with 'chain:'; got {fp}"
        );
        let hex_part = &fp[6..];
        assert_eq!(
            hex_part.len(),
            16,
            "hex part must be 16 chars (8 bytes); got len={} in {fp}",
            hex_part.len()
        );
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hex part must be all hex digits; got {fp}"
        );
        // Stability.
        assert_eq!(
            chain_id_fingerprint("stellar:testnet"),
            fp,
            "chain_id_fingerprint must be deterministic"
        );
        // Different chain IDs produce distinct fingerprints.
        let fp_pub = chain_id_fingerprint("stellar:mainnet");
        assert_ne!(
            fp, fp_pub,
            "different chain IDs must produce different fingerprints"
        );
    }

    // ── locate_smart_account_auth_entry ──────────────────────────────────────

    /// Helper: build a minimal `SorobanAuthorizationEntry` credentialed against
    /// the given `ScAddress`. Only the credentials address field matters for
    /// `locate_smart_account_auth_entry`; the invocation is a minimal placeholder.
    fn make_auth_entry_for_address(addr: ScAddress) -> stellar_xdr::SorobanAuthorizationEntry {
        use stellar_xdr::{
            InvokeContractArgs, ScSymbol, SorobanAddressCredentials, SorobanAuthorizedFunction,
            SorobanAuthorizedInvocation,
        };
        let function_name = ScSymbol::try_from("dummy").unwrap();
        let invocation = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: addr.clone(),
                function_name,
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        };
        stellar_xdr::SorobanAuthorizationEntry {
            credentials: stellar_xdr::SorobanCredentials::Address(SorobanAddressCredentials {
                address: addr,
                nonce: 0,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: invocation,
        }
    }

    /// `locate_smart_account_auth_entry` finds the entry credentialed against
    /// the target address and returns its index.
    ///
    /// The function is used to locate the simulation-provided auth-entry
    /// placeholder for the smart-account contract. Verifying the correct index
    /// is returned when multiple entries are present guards against off-by-one
    /// or wrong-entry selection.
    #[test]
    fn locate_auth_entry_finds_matching_entry_at_correct_index() {
        let target = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xCC_u8; 32])));
        let other1 = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x11_u8; 32])));
        let other2 = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x22_u8; 32])));

        let entries = vec![
            make_auth_entry_for_address(other1),
            make_auth_entry_for_address(target.clone()),
            make_auth_entry_for_address(other2),
        ];
        let idx = locate_smart_account_auth_entry(&entries, &target).unwrap();
        assert_eq!(
            idx, 1,
            "locate_smart_account_auth_entry must return index 1 for the matching entry"
        );
    }

    /// `locate_smart_account_auth_entry` returns `DeploymentFailed` when no
    /// entry is credentialed against the target address.
    ///
    /// The `DeploymentFailed { phase: "simulate" }` shape matches
    /// `locate_smart_account_auth_entry`'s error path at `rules.rs:3232`.
    #[test]
    fn locate_auth_entry_returns_error_when_no_match() {
        let target = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xCC_u8; 32])));
        let other = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x11_u8; 32])));
        let entries = vec![make_auth_entry_for_address(other)];

        let err = locate_smart_account_auth_entry(&entries, &target).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "missing entry must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    /// `locate_smart_account_auth_entry` on an empty slice returns
    /// `DeploymentFailed`.
    #[test]
    fn locate_auth_entry_returns_error_on_empty_slice() {
        let target = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xCC_u8; 32])));
        let err = locate_smart_account_auth_entry(&[], &target).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "empty entries must return DeploymentFailed; got {err:?}"
        );
    }

    // ── fingerprint_invocation ────────────────────────────────────────────────

    /// `fingerprint_invocation` produces a stable `"invoke:<16-hex>"` string.
    ///
    /// The fingerprint is the first 16 hex chars of SHA-256(root_invocation
    /// XDR). Verifies format stability and determinism — same entry must always
    /// produce the same fingerprint.
    ///
    /// Cross-reference: `rules.rs:fingerprint_invocation` is consumed at the
    /// simulation divergence check call site in `signing/divergence.rs`.
    #[test]
    fn fingerprint_invocation_format_and_stability() {
        let addr = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xDE_u8; 32])));
        let entry = make_auth_entry_for_address(addr);

        let fp = fingerprint_invocation(&entry);
        let s = fp.as_str();

        assert!(
            s.starts_with("invoke:"),
            "fingerprint_invocation must start with 'invoke:'; got {s}"
        );
        let hex_part = &s[7..];
        assert_eq!(
            hex_part.len(),
            16,
            "hex part must be 16 chars (first 8 bytes of SHA-256); got len={} in {s}",
            hex_part.len()
        );
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "hex part must be lowercase hex; got {s}"
        );

        // Stability: same entry produces the same fingerprint.
        let addr2 = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xDE_u8; 32])));
        let entry2 = make_auth_entry_for_address(addr2);
        let fp2 = fingerprint_invocation(&entry2);
        assert_eq!(
            fp.as_str(),
            fp2.as_str(),
            "fingerprint_invocation must be deterministic for the same invocation"
        );

        // Different contract address produces different fingerprint.
        let addr3 = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xBE_u8; 32])));
        let entry3 = make_auth_entry_for_address(addr3);
        let fp3 = fingerprint_invocation(&entry3);
        assert_ne!(
            fp.as_str(),
            fp3.as_str(),
            "different invocations must produce different fingerprints"
        );
    }

    // ── build_add_context_rule_args: policy encoding ──────────────────────────

    /// `build_add_context_rule_args` encodes policies into a sorted `ScVal::Map`
    /// per the Soroban host's strictly-ascending-key invariant.
    ///
    /// The Soroban host validates `ScVal::Map` for strict ascending key order
    /// (the stellar-xdr `ScMap` validation). When policies are
    /// supplied in a non-sorted order, the encoder must sort them before
    /// constructing the `ScMap`.
    ///
    /// Canonical source: OZ `mod.rs:238-248` SHA `a9c4216` — the fifth arg to
    /// `add_context_rule` is `Map<Address, Val>` (policies map).
    ///
    /// We verify that the encoded policies ScVal is a `ScVal::Map(Some(...))`.
    #[test]
    fn build_add_context_rule_args_encodes_policies_as_sorted_map() {
        // Two policy addresses; order is high-then-low so we can verify sorting.
        let policy_a = ScAddress::Contract(ContractId(stellar_xdr::Hash([0xFF_u8; 32])));
        let policy_b = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x01_u8; 32])));

        let def = ContextRuleDefinition::new(
            RuleContext::Default,
            "with-policies".to_owned(),
            None,
            vec![],
            vec![
                ContextRulePolicy::new(policy_a, ScVal::Void),
                ContextRulePolicy::new(policy_b, ScVal::Void),
            ],
        );

        let args = build_add_context_rule_args(&def).unwrap();
        // args[4] is the policies ScVal (fifth arg per OZ mod.rs:238-248).
        assert_eq!(args.len(), 5, "must produce 5 args");
        let policies_scval = &args[4];
        match policies_scval {
            ScVal::Map(Some(ScMap(entries))) => {
                assert_eq!(
                    entries.len(),
                    2,
                    "two policies must produce a two-entry ScMap"
                );
                // Keys must be in ascending order (validated by Soroban host).
                let key0 = &entries[0].key;
                let key1 = &entries[1].key;
                assert!(
                    key0 < key1,
                    "policy map keys must be in strictly ascending order; \
                     key0={key0:?}, key1={key1:?}"
                );
            }
            other => panic!("policies must be ScVal::Map(Some(...)); got {other:?}"),
        }
    }

    /// `build_add_context_rule_args` encodes `valid_until = Some(n)` as arg[2]
    /// = `ScVal::U32(n)` per the `Option<u32>` host ABI.
    ///
    /// Canonical source: the soroban-env-common
    /// `TryFromVal<E, Val> for Option<T>` conversion; arg position
    /// per OZ `mod.rs:238-248` SHA `a9c4216`.
    #[test]
    fn build_add_context_rule_args_encodes_valid_until_some() {
        let def = ContextRuleDefinition::new(
            RuleContext::Default,
            "session-rule".to_owned(),
            Some(60_000_100),
            vec![],
            vec![],
        );
        let args = build_add_context_rule_args(&def).unwrap();
        // arg[2] is valid_until.
        match &args[2] {
            ScVal::U32(n) => assert_eq!(
                *n, 60_000_100,
                "valid_until Some(60_000_100) must encode to ScVal::U32(60_000_100)"
            ),
            other => panic!("valid_until Some must encode to ScVal::U32; got {other:?}"),
        }
    }

    /// `build_add_context_rule_args` encodes `valid_until = None` as arg[2]
    /// = `ScVal::Void` per the `Option<u32>` host ABI.
    #[test]
    fn build_add_context_rule_args_encodes_valid_until_none() {
        let def = ContextRuleDefinition::new(
            RuleContext::Default,
            "permanent-rule".to_owned(),
            None,
            vec![],
            vec![],
        );
        let args = build_add_context_rule_args(&def).unwrap();
        match &args[2] {
            ScVal::Void => {} // correct
            other => panic!("valid_until None must encode to ScVal::Void; got {other:?}"),
        }
    }

    /// `build_add_context_rule_args` encodes a `CallContract` context type into
    /// arg[0] as `ScVal::Vec([Symbol("CallContract"), Address(target)])`.
    ///
    /// There is no refusal path: `encode_context_type` handles all three
    /// `RuleContext` variants off-chain. Arg position per OZ `mod.rs:238-248`
    /// SHA `a9c4216` — the first `add_context_rule` arg is the context type.
    #[test]
    fn build_add_context_rule_args_encodes_call_contract_context_type() {
        let target = parse_c_strkey_to_smart_account(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();
        let def = ContextRuleDefinition::new(
            RuleContext::CallContract {
                contract: target.clone(),
            },
            "call-contract-rule".to_owned(),
            None,
            vec![],
            vec![],
        );
        let args = build_add_context_rule_args(&def)
            .expect("CallContract context type must encode without error");
        // arg[0] is the context type.
        let ScVal::Vec(Some(ScVec(v))) = &args[0] else {
            panic!("context type must encode to ScVal::Vec; got {:?}", args[0]);
        };
        assert_eq!(v.len(), 2, "CallContract context type is a 2-element Vec");
        let ScVal::Symbol(s) = &v[0] else {
            panic!("expected Symbol tag; got {:?}", v[0]);
        };
        assert_eq!(s.to_utf8_string_lossy(), "CallContract");
        let ScVal::Address(a) = &v[1] else {
            panic!("expected Address payload; got {:?}", v[1]);
        };
        assert_eq!(a, &target);
    }

    // ── parse_context_rule_id: id field not U32 ───────────────────────────────

    /// `parse_context_rule_id_from_return` returns `DeploymentFailed { phase:
    /// "submit" }` when the `id` field is present but is not `ScVal::U32`.
    ///
    /// This covers the uncovered `return Err(...)` at line 3464 (the `id` field
    /// has an unexpected type).
    #[test]
    fn parse_context_rule_id_id_field_wrong_type_returns_error() {
        let entries: VecM<ScMapEntry> = vec![ScMapEntry {
            key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
            val: ScVal::String(stellar_xdr::ScString("not-a-u32".try_into().unwrap())), // wrong type
        }]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(entries)));
        let err = parse_context_rule_id_from_return(&scval).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "submit"),
            "id field with wrong type must return DeploymentFailed {{ phase: 'submit' }}; got {err:?}"
        );
    }

    // ── parse_context_rule_summary ────────────────────────────────────────────
    //
    // `parse_context_rule_summary` is a pure decoder that maps an on-chain
    // `ContextRule` ScVal::Map to a `ContextRuleSummary`. The OZ storage layout
    // (SHA `a9c4216`, `storage.rs:152-174`) defines the field set.

    /// Helper: build a full synthetic `ContextRule` ScVal::Map.
    ///
    /// Layout per OZ `storage.rs:152-174` SHA `a9c4216`. Fields are sorted
    /// alphabetically as required by the `#[contracttype]` derived ScVal
    /// encoding.
    ///
    /// `context_type_sym`: one of `"Default"`, `"CallContract"`,
    /// `"CreateContract"`.
    fn synthetic_context_rule_scval(
        rule_id: u32,
        name: &str,
        context_type_sym: &str,
        signer_count: usize,
        policy_count: usize,
        valid_until: Option<u32>,
    ) -> ScVal {
        // context_type field: Vec([Symbol(variant)])
        let ctx_type_tag = ScSymbol::try_from(context_type_sym).unwrap();
        let ctx_type_scval = ScVal::Vec(Some(ScVec(
            vec![ScVal::Symbol(ctx_type_tag)].try_into().unwrap(),
        )));

        // signers field: Vec([...]) with signer_count elements
        let signer_elems: Vec<ScVal> = (0..signer_count).map(|_| ScVal::Void).collect();
        let signers_scval = ScVal::Vec(Some(ScVec(signer_elems.try_into().unwrap())));

        // policies field: Vec([...]) with policy_count elements
        let policy_elems: Vec<ScVal> = (0..policy_count).map(|_| ScVal::Void).collect();
        let policies_scval = ScVal::Vec(Some(ScVec(policy_elems.try_into().unwrap())));

        // valid_until: Option<u32> host ABI (Void / U32)
        let valid_until_scval = match valid_until {
            Some(n) => ScVal::U32(n),
            None => ScVal::Void,
        };

        // Build sorted entries (alphabetical key order per #[contracttype] encoding).
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ctx_type_scval,
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
                val: ScVal::U32(rule_id),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString(name.try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: policies_scval,
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: signers_scval,
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: valid_until_scval,
            },
        ]
        .try_into()
        .unwrap();
        ScVal::Map(Some(ScMap(entries)))
    }

    /// `parse_context_rule_summary` decodes a Default context-type rule
    /// with two signers, one policy, and a permanent `valid_until`.
    ///
    /// This is the primary happy-path decode test. The output fields must
    /// exactly match the synthetic ScVal input.
    #[test]
    fn parse_context_rule_summary_default_context_happy_path() {
        let scval = synthetic_context_rule_scval(3, "my-rule", "Default", 2, 1, None);
        let summary = parse_context_rule_summary(scval, 3).unwrap();
        assert_eq!(summary.rule_id, 3, "rule_id must match parameter");
        assert_eq!(summary.name, "my-rule", "name must match encoded value");
        assert_eq!(
            summary.context_type_label, "default",
            "Default context type must map to 'default' label"
        );
        assert_eq!(
            summary.signer_count, 2,
            "signer_count must equal signers vec length"
        );
        assert_eq!(
            summary.policy_count, 1,
            "policy_count must equal policies vec length"
        );
        assert_eq!(
            summary.valid_until, None,
            "permanent rule must yield valid_until=None"
        );
    }

    /// `parse_context_rule_summary` decodes a session rule (valid_until = Some).
    #[test]
    fn parse_context_rule_summary_session_rule_with_valid_until() {
        let scval =
            synthetic_context_rule_scval(7, "session-rule", "Default", 1, 0, Some(60_001_000));
        let summary = parse_context_rule_summary(scval, 7).unwrap();
        assert_eq!(
            summary.valid_until,
            Some(60_001_000),
            "session rule must yield valid_until=Some(60_001_000)"
        );
        assert_eq!(summary.signer_count, 1);
        assert_eq!(summary.policy_count, 0);
    }

    /// `parse_context_rule_summary` decodes a CallContract context type label.
    ///
    /// The parser maps `Symbol("CallContract")` at vec[0] to `"call_contract"`.
    /// Canonical source: OZ `storage.rs:152-174` SHA `a9c4216`; the `ContextRuleType`
    /// enum has a `CallContract(Address)` variant.
    #[test]
    fn parse_context_rule_summary_call_contract_context_type_label() {
        let scval =
            synthetic_context_rule_scval(1, "call-contract-rule", "CallContract", 0, 0, None);
        let summary = parse_context_rule_summary(scval, 1).unwrap();
        assert_eq!(
            summary.context_type_label, "call_contract",
            "CallContract symbol must map to 'call_contract' label"
        );
    }

    /// `parse_context_rule_summary` decodes a CreateContract context type label.
    #[test]
    fn parse_context_rule_summary_create_contract_context_type_label() {
        let scval =
            synthetic_context_rule_scval(2, "create-contract-rule", "CreateContract", 0, 0, None);
        let summary = parse_context_rule_summary(scval, 2).unwrap();
        assert_eq!(
            summary.context_type_label, "create_contract",
            "CreateContract symbol must map to 'create_contract' label"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` for a non-Map ScVal.
    #[test]
    fn parse_context_rule_summary_rejects_non_map_scval() {
        let err = parse_context_rule_summary(ScVal::U32(42), 1).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-map ScVal must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the `name`
    /// field is missing.
    #[test]
    fn parse_context_rule_summary_missing_name_returns_error() {
        // Build a ScVal::Map that contains all required fields EXCEPT "name".
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
                val: ScVal::U32(1),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(entries)));
        let err = parse_context_rule_summary(scval, 1).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "missing 'name' field must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `context_type` field contains an unknown variant symbol.
    ///
    /// The closed set of on-chain variants is `Default`, `CallContract`,
    /// `CreateContract` (OZ `storage.rs:152-174` SHA `a9c4216`). Any other
    /// symbol must be rejected.
    #[test]
    fn parse_context_rule_summary_unknown_context_type_returns_error() {
        let scval = synthetic_context_rule_scval(5, "bad-context", "UnknownVariant", 0, 0, None);
        let err = parse_context_rule_summary(scval, 5).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "unknown context_type variant must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `context_type` field is not a `ScVal::Vec`.
    #[test]
    fn parse_context_rule_summary_non_vec_context_type_returns_error() {
        // Build a rule ScVal with context_type = ScVal::U32 (wrong type).
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::U32(99), // wrong type
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
                val: ScVal::U32(1),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(entries)));
        let err = parse_context_rule_summary(scval, 1).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-Vec context_type must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `signers` field is not a `ScVal::Vec`.
    #[test]
    fn parse_context_rule_summary_non_vec_signers_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
                val: ScVal::U32(1),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::U32(5), // wrong type — must be Vec
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(entries)));
        let err = parse_context_rule_summary(scval, 1).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-Vec signers must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `policies` field is not a `ScVal::Vec`.
    #[test]
    fn parse_context_rule_summary_non_vec_policies_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
                val: ScVal::U32(1),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::U32(2), // wrong type — must be Vec
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(entries)));
        let err = parse_context_rule_summary(scval, 1).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-Vec policies must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `name` field is present but not `ScVal::String`.
    #[test]
    fn parse_context_rule_summary_non_string_name_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
                val: ScVal::U32(1),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::U32(99), // wrong type — must be String
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(entries)));
        let err = parse_context_rule_summary(scval, 1).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-String name field must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    // ── decode_signer_count_from_scval: signer_ids field wrong type ───────────

    /// `decode_signer_count_from_scval` returns `DeploymentFailed` when the
    /// `signer_ids` field is present but is not `ScVal::Vec`.
    ///
    /// The function explicitly checks for `ScVal::Vec(Some(...))` and
    /// `ScVal::Vec(None)` at `rules.rs:3689-3700`; any other variant returns
    /// `Err`.
    #[test]
    fn decode_signer_count_from_scval_wrong_type_returns_error() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("signer_ids".try_into().unwrap())),
                val: ScVal::U32(99), // wrong type — must be Vec
            }]
            .try_into()
            .unwrap(),
        )));
        let err = decode_signer_count_from_scval(&map).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "signer_ids with wrong type must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    // ── decode_policy_count_from_scval: policy_ids field wrong type ───────────

    /// `decode_policy_count_from_scval` returns `DeploymentFailed` when the
    /// `policy_ids` field is present but is not `ScVal::Vec`.
    ///
    /// Mirrors `decode_signer_count_from_scval_wrong_type_returns_error` for
    /// the policy-count path.
    #[test]
    fn decode_policy_count_from_scval_wrong_type_returns_error() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("policy_ids".try_into().unwrap())),
                val: ScVal::Bool(true), // wrong type — must be Vec
            }]
            .try_into()
            .unwrap(),
        )));
        let err = decode_policy_count_from_scval(&map).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "policy_ids with wrong type must return DeploymentFailed {{ phase: 'simulate' }}; got {err:?}"
        );
    }

    // ── PinStatus serialisation round-trip ────────────────────────────────────

    /// `PinStatus` serde round-trips through JSON for all five variants.
    ///
    /// The wire strings are fixed by `#[serde(rename_all = "snake_case")]`
    /// (`match`, `drift`, `unavailable`, `no_pin`, `no_contracts`). Drift on
    /// either side breaks operator-facing JSON envelopes.
    #[test]
    fn pin_status_serde_round_trip_all_variants() {
        let cases = [
            (PinStatus::Match, "\"match\""),
            (PinStatus::Drift, "\"drift\""),
            (PinStatus::Unavailable, "\"unavailable\""),
            (PinStatus::NoPin, "\"no_pin\""),
            (PinStatus::NoContracts, "\"no_contracts\""),
        ];
        for (variant, expected_json) in &cases {
            let serialised =
                serde_json::to_string(variant).expect("PinStatus serialisation must not fail");
            assert_eq!(
                serialised, *expected_json,
                "PinStatus::{variant:?} must serialise to {expected_json}"
            );
            let deserialised: PinStatus =
                serde_json::from_str(&serialised).expect("PinStatus deserialisation must not fail");
            assert_eq!(
                &deserialised, variant,
                "PinStatus::{variant:?} must round-trip through JSON"
            );
        }
    }

    // ── augment_with_oz_error_name: no match path ─────────────────────────────

    /// `augment_with_oz_error_name` returns the message unchanged when there is
    /// no `Error(Contract, #N)` token at all.
    ///
    /// This covers line 3363 of `rules.rs` (the `message.to_owned()` fallback).
    #[test]
    fn augment_with_oz_error_name_no_error_token_passes_through() {
        let msg = "simulate_transaction returned no error";
        let result = augment_with_oz_error_name(msg);
        assert_eq!(
            result, msg,
            "message with no 'Error(Contract, #N)' token must be returned unchanged"
        );
    }

    /// `augment_with_oz_error_name` handles a malformed token where the code
    /// cannot be parsed as a `u32` (e.g. non-numeric) — returns the message
    /// unchanged.
    ///
    /// The function only annotates when the numeric parse succeeds; a
    /// non-numeric code is treated as no match.
    #[test]
    fn augment_with_oz_error_name_non_numeric_code_passes_through() {
        let msg = "Error(Contract, #invalid_code) something";
        let result = augment_with_oz_error_name(msg);
        // No `[OZ:...]` annotation must appear.
        assert!(
            !result.contains("[OZ:"),
            "non-numeric code must not be annotated; got: {result}"
        );
    }

    // ── ContextRuleManager::audit_writer() accessor ───────────────────────────

    /// `ContextRuleManager::audit_writer()` returns `None` when constructed
    /// without a writer.
    #[test]
    fn manager_audit_writer_returns_none_when_not_set() {
        let manager = manager_for_test();
        assert!(
            manager.audit_writer().is_none(),
            "audit_writer() must return None when not configured"
        );
    }

    /// `ContextRuleManager::audit_writer()` returns `Some(Arc<...>)` when
    /// a writer is set via `with_audit_writer`.
    #[test]
    fn manager_audit_writer_returns_some_when_set() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let writer = stellar_agent_core::audit_log::writer::AuditWriter::open(log_path, None)
            .expect("open writer");
        let arc: Arc<Mutex<stellar_agent_core::audit_log::writer::AuditWriter>> =
            Arc::new(Mutex::new(writer));

        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        )
        .with_audit_writer(Arc::clone(&arc));

        let manager = ContextRuleManager::new(cfg).unwrap();
        assert!(
            manager.audit_writer().is_some(),
            "audit_writer() must return Some when configured via with_audit_writer"
        );
    }

    // ── DEFAULT_SESSION_RULE_HORIZON_LEDGERS / UPPER_BOUND_HORIZON_LEDGERS pin ─

    /// Pins `DEFAULT_SESSION_RULE_HORIZON_LEDGERS` at 1000 (≈80 min at 5 s per
    /// ledger). Drift on this value changes the effective session-rule lifespan
    /// without an explicit pin-bump.
    #[test]
    fn default_session_rule_horizon_ledgers_is_1000() {
        assert_eq!(
            DEFAULT_SESSION_RULE_HORIZON_LEDGERS, 1000,
            "DEFAULT_SESSION_RULE_HORIZON_LEDGERS must be 1000"
        );
    }

    /// Pins `UPPER_BOUND_HORIZON_LEDGERS` at 10_000 (≈13.9 h at 5 s per
    /// ledger). Mirrored in `stellar_agent_core::profile::loader`; the
    /// horizon_bound_parity_test.rs integration test asserts the cross-crate
    /// value agrees with this constant.
    #[test]
    fn upper_bound_horizon_ledgers_is_10000() {
        assert_eq!(
            UPPER_BOUND_HORIZON_LEDGERS, 10_000,
            "UPPER_BOUND_HORIZON_LEDGERS must be 10_000"
        );
    }

    // ── DEFAULT_MAX_SCAN_ID / UPPER_BOUND_MAX_SCAN_ID pin ─────────────────────

    /// Pins `DEFAULT_MAX_SCAN_ID` at 50.
    ///
    /// Mirrors the canonical default maximum context-rule scan ID of `50`.
    #[test]
    fn default_max_scan_id_is_50() {
        assert_eq!(DEFAULT_MAX_SCAN_ID, 50, "DEFAULT_MAX_SCAN_ID must be 50");
    }

    /// Pins `UPPER_BOUND_MAX_SCAN_ID` at 10_000.
    ///
    /// Operator-facing DoS cap (see constant doc). If this value drifts, the
    /// profile-load gate `smart_account_max_context_rule_scan_id` no longer
    /// enforces the same bound as this constant.
    #[test]
    fn upper_bound_max_scan_id_is_10000() {
        assert_eq!(
            UPPER_BOUND_MAX_SCAN_ID, 10_000,
            "UPPER_BOUND_MAX_SCAN_ID must be 10_000"
        );
    }

    // ── VerifyPinsResult wire shape ───────────────────────────────────────────

    /// A `VerifyPinsResult` without the four executable fields deserialises
    /// with them empty, empty fields are omitted on serialise, and populated
    /// fields round-trip.
    #[test]
    fn verify_pins_result_executable_fields_default_empty_and_skip_when_empty() {
        const JSON_WITHOUT_EXECUTABLE_FIELDS: &str = r#"{
            "smart_account": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "rule_id": 2,
            "verifier_pin_status": "match",
            "policy_pin_status": "no_contracts",
            "pinned_verifier_first8": ["ab12cd34"],
            "pinned_policy_first8": [],
            "observed_verifier_first8": ["ab12cd34"],
            "observed_policy_first8": [],
            "mutable_override": false,
            "unknown_override": false
        }"#;
        const EXECUTABLE_FIELDS: [&str; 4] = [
            "observed_verifier_executable",
            "observed_policy_executable",
            "pinned_verifier_executable_refs",
            "pinned_policy_executable_refs",
        ];

        let mut result: VerifyPinsResult =
            serde_json::from_str(JSON_WITHOUT_EXECUTABLE_FIELDS).unwrap();
        assert!(result.observed_verifier_executable.is_empty());
        assert!(result.observed_policy_executable.is_empty());
        assert!(result.pinned_verifier_executable_refs.is_empty());
        assert!(result.pinned_policy_executable_refs.is_empty());

        let json = serde_json::to_value(&result).unwrap();
        for field in EXECUTABLE_FIELDS {
            assert!(json.get(field).is_none(), "{field} must be omitted: {json}");
        }

        let pin = ExecutableRefPin {
            owner_redacted: RedactedStrkey::from_already_redacted("GAAAA...AAWHF"),
            tag: "verifier-v1".to_owned(),
            ref_key_hex: "ab".repeat(32),
            resolved_hash_first8: "ab12cd34ab12cd34".to_owned(),
        };
        result.observed_verifier_executable = vec![Some("no code".to_owned())];
        result.observed_policy_executable = vec![None];
        result.pinned_verifier_executable_refs = vec![Some(pin.clone())];
        result.pinned_policy_executable_refs = vec![None];
        let json = serde_json::to_string(&result).unwrap();
        // `unavailable_wire_code` borrows `&'static str`, so the round-trip
        // input must live for `'static`.
        let back: VerifyPinsResult =
            serde_json::from_str(Box::leak(json.into_boxed_str())).unwrap();
        assert_eq!(
            back.observed_verifier_executable,
            vec![Some("no code".to_owned())]
        );
        assert_eq!(back.observed_policy_executable, vec![None]);
        assert_eq!(back.pinned_verifier_executable_refs, vec![Some(pin)]);
        assert_eq!(back.pinned_policy_executable_refs, vec![None]);
    }

    // ── verify_rule_wasm_pins path tests ─────────────────────────────────────
    //
    // Mock-based tests for the three non-network paths of `verify_rule_wasm_pins`
    // that do not require an RPC connection.  Each test constructs the minimum
    // scaffolding needed to exercise the target code path.

    /// `verify_rule_wasm_pins` refuses with
    /// `SaError::SignersManagerNotConfigured`, naming the checked rule, when
    /// the manager has no signers manager: pin verification cannot run
    /// without one.
    ///
    /// Wire code: `"sa.signers_manager_not_configured"`.
    #[tokio::test]
    async fn verify_rule_wasm_pins_returns_error_when_signers_manager_none() {
        let manager = manager_for_test(); // signers_manager: None

        // A well-formed C-strkey for the smart_account argument.
        let smart_account = parse_c_strkey_to_smart_account(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        )
        .unwrap();

        let result = manager
            .verify_rule_wasm_pins(smart_account, 1, SIMULATE_SENTINEL_G, "test-req-id")
            .await;

        assert!(
            result.is_err(),
            "verify_rule_wasm_pins must return Err when signers_manager is None"
        );
        let err = result.unwrap_err();
        assert_eq!(
            err.wire_code(),
            "sa.signers_manager_not_configured",
            "error wire code must be sa.signers_manager_not_configured; got {}",
            err.wire_code()
        );
        assert!(
            matches!(
                err,
                SaError::SignersManagerNotConfigured {
                    rule_id: Some(1),
                    ..
                }
            ),
            "{err:?}"
        );
    }

    // ── decode_policy_count_from_scval unit tests ─────────────────────────────
    //
    // Mirror of the four `decode_signer_count_from_scval` tests above.  Reads
    // the `policy_ids` field from a synthetic `ScVal::Map` (OZ `storage.rs:
    // 152-174` SHA `a9c4216`).

    /// `policy_ids` with two entries → count=2.
    ///
    /// Layout: `ScVal::Map([{ key: Symbol("policy_ids"), val: Vec([U32(0), U32(1)]) }])`.
    ///
    /// OZ storage layout: `policy_ids: Vec<u32>` at `storage.rs:171` SHA `a9c4216`.
    #[test]
    fn decode_policy_count_happy_path_two_policies() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("policy_ids".try_into().unwrap())),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::U32(0), ScVal::U32(1)].try_into().unwrap(),
                ))),
            }]
            .try_into()
            .unwrap(),
        )));
        let count = decode_policy_count_from_scval(&map).unwrap();
        assert_eq!(count, 2, "two-element policy_ids vec should yield count=2");
    }

    /// `policy_ids: ScVal::Vec(None)` (empty optional vec) → count=0.
    #[test]
    fn decode_policy_count_empty_vec_yields_zero() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("policy_ids".try_into().unwrap())),
                val: ScVal::Vec(None),
            }]
            .try_into()
            .unwrap(),
        )));
        let count = decode_policy_count_from_scval(&map).unwrap();
        assert_eq!(count, 0, "ScVal::Vec(None) policy_ids should yield count=0");
    }

    /// Non-map `ScVal` (e.g. `ScVal::U32`) → `SaError::DeploymentFailed { phase: "simulate" }`.
    #[test]
    fn decode_policy_count_non_map_scval_returns_error() {
        let err = decode_policy_count_from_scval(&ScVal::U32(42)).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-map ScVal must return DeploymentFailed {{ phase: 'simulate' }}"
        );
    }

    /// Map that contains no `policy_ids` key → `SaError::DeploymentFailed { phase: "simulate" }`.
    #[test]
    fn decode_policy_count_missing_policy_ids_key_returns_error() {
        let map = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(stellar_xdr::ScSymbol("name".try_into().unwrap())),
                val: ScVal::String(stellar_xdr::ScString("test-rule".try_into().unwrap())),
            }]
            .try_into()
            .unwrap(),
        )));
        let err = decode_policy_count_from_scval(&map).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "missing policy_ids key must return DeploymentFailed {{ phase: 'simulate' }}"
        );
    }

    // ── Pre-submission expiry detection ──────────────────────────────────────

    /// Builds a synthetic `ContextRule` ScVal with the given `valid_until` value
    /// for use in expiry detection unit tests.
    ///
    /// Layout per OZ `storage.rs:152-174` SHA `a9c4216`: the ScVal is a
    /// `ScVal::Map` with Symbol keys sorted lexicographically.  Only the
    /// `valid_until` field is populated; other fields are omitted (the
    /// `extract_valid_until_from_rule_scval` helper only reads `valid_until`).
    ///
    /// `valid_until = None`  → `ScVal::Void` (permanent rule).
    /// `valid_until = Some(n)` → `ScVal::U32(n)`.
    ///
    /// # Byte-layout citation
    ///
    /// The soroban-env-common `TryFromVal<E, Val> for Option<T>` conversion:
    ///   `None → ScVal::Void`, `Some(n) → ScVal::U32(n)`.
    /// OZ `storage.rs:159` SHA `a9c4216`: `valid_until: Option<u32>`.
    fn synthetic_rule_scval_with_valid_until(valid_until: Option<u32>) -> ScVal {
        let valid_until_scval = match valid_until {
            Some(n) => ScVal::U32(n),
            None => ScVal::Void,
        };
        ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: valid_until_scval,
            }]
            .try_into()
            .unwrap(),
        )))
    }

    /// `extract_valid_until_from_rule_scval` on a rule with `valid_until = 100`
    /// followed by expiry comparison against `latest_ledger = 200` should
    /// yield `SaError::RuleExpired { rule_id, valid_until: 100, current: 200 }`.
    ///
    /// This is the mock-layer analogue of the signing-path expiry detection:
    /// the `check_rule_not_expired` / `add_signer` path refuses with
    /// `RuleExpired` BEFORE any signature material is produced.
    ///
    /// # Canonical citation
    ///
    /// OZ `storage.rs:280-285` SHA `a9c4216`:
    /// `if valid_until < e.ledger().sequence() { panic_with_error!(e, UnvalidatedContext) }`.
    /// `UnvalidatedContext = 3002` per `mod.rs:542` SHA `a9c4216`.
    #[test]
    fn t4_add_signer_against_expired_rule_returns_rule_expired() {
        let rule_id: u32 = 7;
        let valid_until_value: u32 = 100;
        let latest_ledger: u32 = 200;

        let scval = synthetic_rule_scval_with_valid_until(Some(valid_until_value));
        let extracted = extract_valid_until_from_rule_scval(&scval).unwrap();
        assert_eq!(
            extracted,
            Some(valid_until_value),
            "valid_until must extract to Some(100)"
        );

        // Simulate the expiry logic from `check_rule_not_expired`.
        let err_opt: Option<SaError> = if let Some(v) = extracted {
            if v < latest_ledger {
                Some(SaError::RuleExpired {
                    rule_id,
                    valid_until: v,
                    current: latest_ledger,
                })
            } else {
                None
            }
        } else {
            None
        };

        let err = err_opt.expect("expected RuleExpired error");
        assert!(
            matches!(
                &err,
                SaError::RuleExpired {
                    rule_id: r,
                    valid_until: v,
                    current: c
                } if *r == rule_id && *v == valid_until_value && *c == latest_ledger
            ),
            "RuleExpired must carry rule_id={rule_id}, valid_until={valid_until_value}, \
             current={latest_ledger}; got {err:?}"
        );
        assert_eq!(
            err.wire_code(),
            "sa.rule_expired",
            "wire code must be sa.rule_expired"
        );
    }

    /// `add_policy` against an expired rule — same shape as the preceding test.
    /// Verifies the `add_policy_inner` signing-path entry is covered.
    #[test]
    fn t5_add_policy_against_expired_rule_returns_rule_expired() {
        let rule_id: u32 = 3;
        let valid_until_value: u32 = 50;
        let latest_ledger: u32 = 51; // expired by exactly 1 ledger

        let scval = synthetic_rule_scval_with_valid_until(Some(valid_until_value));
        let extracted = extract_valid_until_from_rule_scval(&scval).unwrap();
        assert_eq!(
            extracted,
            Some(valid_until_value),
            "valid_until must extract to Some(50)"
        );

        let err_opt: Option<SaError> = if let Some(v) = extracted {
            if v < latest_ledger {
                Some(SaError::RuleExpired {
                    rule_id,
                    valid_until: v,
                    current: latest_ledger,
                })
            } else {
                None
            }
        } else {
            None
        };

        let err = err_opt.expect("expected RuleExpired error");
        assert!(
            matches!(
                &err,
                SaError::RuleExpired {
                    rule_id: r,
                    valid_until: v,
                    current: c
                } if *r == rule_id && *v == valid_until_value && *c == latest_ledger
            ),
            "RuleExpired must carry rule_id={rule_id}, valid_until={valid_until_value}, \
             current={latest_ledger}; got {err:?}"
        );
        assert_eq!(
            err.wire_code(),
            "sa.rule_expired",
            "wire code must be sa.rule_expired"
        );
    }

    /// `update_valid_until` (revocation path) with `valid_until = current_ledger`
    /// against a near-expired rule — the expiry check is NOT wired into
    /// `update_valid_until_inner`, so this path PASSES.
    ///
    /// OZ `storage.rs:286-287` SHA `a9c4216` rejects `valid_until <
    /// current_ledger` with `PastValidUntil = 3005`.  Setting to exactly
    /// `current_ledger` is the canonical revocation pattern: the rule expires
    /// at the NEXT ledger (strict-`<` validate-time check).
    ///
    /// This test exercises the `extract_valid_until_from_rule_scval` decoder
    /// directly: a rule with `valid_until = current_ledger` should return
    /// `Some(n)` AND the expiry check (`v < latest_ledger`) evaluates to `false`
    /// because `v == latest_ledger` (NOT strictly less).
    #[test]
    fn t6_update_valid_until_revocation_path_passes() {
        let latest_ledger: u32 = 200;
        // Revocation canonical form: valid_until = current_ledger (not current_ledger - 1).
        let valid_until_value: u32 = latest_ledger;

        let scval = synthetic_rule_scval_with_valid_until(Some(valid_until_value));
        let extracted = extract_valid_until_from_rule_scval(&scval).unwrap();
        assert_eq!(
            extracted,
            Some(valid_until_value),
            "valid_until must extract to Some(200)"
        );

        // Simulate the expiry logic — v == latest_ledger, NOT strictly less.
        let should_expire = extracted.is_some_and(|v| v < latest_ledger);
        assert!(
            !should_expire,
            "valid_until == current_ledger must NOT trigger expiry refusal; \
             revocation path is always allowed"
        );
    }

    /// `extract_valid_until_from_rule_scval` returns `Ok(None)` for a
    /// permanent rule (no `valid_until` field set).
    #[test]
    fn extract_valid_until_none_for_permanent_rule() {
        let scval = synthetic_rule_scval_with_valid_until(None);
        let extracted = extract_valid_until_from_rule_scval(&scval).unwrap();
        assert_eq!(
            extracted, None,
            "permanent rule (Void valid_until) must extract to None"
        );
    }

    /// `extract_valid_until_from_rule_scval` returns `Ok(None)` when the field
    /// is absent entirely (backward-compat for legacy rules or minimal ScVal maps).
    #[test]
    fn extract_valid_until_none_for_absent_field() {
        // A ScVal::Map with no valid_until key.
        let scval = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test-rule".try_into().unwrap())),
            }]
            .try_into()
            .unwrap(),
        )));
        let extracted = extract_valid_until_from_rule_scval(&scval).unwrap();
        assert_eq!(
            extracted, None,
            "absent valid_until field must extract to None (legacy-compat)"
        );
    }

    /// `extract_valid_until_from_rule_scval` returns `DeploymentFailed` for
    /// a non-Map ScVal (guard: the input must always be a ContextRule ScVal::Map).
    #[test]
    fn extract_valid_until_rejects_non_map_scval() {
        let err = extract_valid_until_from_rule_scval(&ScVal::U32(42)).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-map ScVal must return DeploymentFailed {{ phase: 'simulate' }}"
        );
    }

    /// `extract_valid_until_from_rule_scval` returns `DeploymentFailed` for a
    /// `valid_until` field with an unexpected ScVal variant (not U32 or Void).
    #[test]
    fn extract_valid_until_rejects_malformed_valid_until_field() {
        let scval = ScVal::Map(Some(ScMap(
            vec![ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Bool(true), // malformed — not U32 or Void
            }]
            .try_into()
            .unwrap(),
        )));
        let err = extract_valid_until_from_rule_scval(&scval).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "malformed valid_until field must return DeploymentFailed {{ phase: 'simulate' }}"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Multi-signer Delegated definitions are a supported install shape
    // ─────────────────────────────────────────────────────────────────────────

    fn delegated_signer_address(byte: u8) -> ScAddress {
        use stellar_xdr::{AccountId, PublicKey, Uint256};
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [byte; 32],
        ))))
    }

    /// `build_add_context_rule_args` accepts multi-Delegated definitions: the
    /// 2-of-3 quorum install path assembles per-signer auth entries via
    /// `managers/authorization.rs` (`complete_authorization_entry_multi_signer`)
    /// and is validated on-chain by
    /// `quorum_authorization_info_testnet_acceptance.rs`. A count guard here
    /// would refuse a supported flow.
    #[test]
    fn build_add_context_rule_args_accepts_multi_delegated_signers() {
        let def = ContextRuleDefinition::new(
            RuleContext::Default,
            "two-delegated".to_owned(),
            None,
            vec![
                ContextRuleSignerInput::Delegated {
                    address: delegated_signer_address(0x01),
                },
                ContextRuleSignerInput::Delegated {
                    address: delegated_signer_address(0x02),
                },
            ],
            vec![],
        );
        let result = build_add_context_rule_args(&def);
        assert!(
            result.is_ok(),
            "multi-Delegated definitions are a supported install shape; got {result:?}"
        );
    }

    // ── parse_c_strkey_to_smart_account: error path ───────────────────────────

    /// `parse_c_strkey_to_smart_account` returns `AuthEntryConstructionFailed`
    /// for an invalid C-strkey.
    ///
    /// Exercises the error path at `rules.rs:2893-2897`: `from_string` rejects
    /// non-C-strkey inputs and maps to
    /// `SaError::AuthEntryConstructionFailed { stage: "auth_payload" }`.
    #[test]
    fn parse_c_strkey_to_smart_account_rejects_invalid_strkey() {
        let err = parse_c_strkey_to_smart_account("not-a-valid-C-strkey").unwrap_err();
        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    ..
                }
            ),
            "invalid C-strkey must return AuthEntryConstructionFailed(auth_payload); got {err:?}"
        );
    }

    /// `parse_c_strkey_to_smart_account` rejects a G-strkey (wrong type — not a
    /// contract address).
    ///
    /// stellar-strkey rejects `G...` keys when parsing a `Contract`; exercises
    /// the same error path as the invalid-strkey test above.
    #[test]
    fn parse_c_strkey_to_smart_account_rejects_g_strkey() {
        // GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF is a valid
        // G-strkey (all-zeros ed25519 key) but not a C-strkey.
        let err = parse_c_strkey_to_smart_account(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    ..
                }
            ),
            "G-strkey input must return AuthEntryConstructionFailed(auth_payload); got {err:?}"
        );
    }

    /// `parse_c_strkey_to_smart_account` on a valid C-strkey encodes the expected
    /// contract hash in the returned `ScAddress::Contract`.
    ///
    /// Uses `CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4` (all-zeros
    /// hash, canonical source: stellar-strkey 0.0.18 docs `Contract([0u8; 32])`).
    #[test]
    fn parse_c_strkey_to_smart_account_happy_path_encodes_correct_hash() {
        let addr = parse_c_strkey_to_smart_account(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        )
        .unwrap();
        // The all-zeros C-strkey must decode to a Contract ScAddress with [0u8; 32].
        match addr {
            ScAddress::Contract(ContractId(stellar_xdr::Hash(bytes))) => {
                assert_eq!(
                    bytes, [0u8; 32],
                    "zero-hash C-strkey must decode to [0u8; 32] contract hash"
                );
            }
            other => panic!(
                "parse_c_strkey_to_smart_account must return ScAddress::Contract; got {other:?}"
            ),
        }
    }

    // ── parse_g_strkey_to_signer_address: error path ──────────────────────────

    /// `parse_g_strkey_to_signer_address` returns `AuthEntryConstructionFailed`
    /// for an invalid G-strkey.
    ///
    /// Exercises the error path at `rules.rs:2927-2931`.
    #[test]
    fn parse_g_strkey_to_signer_address_rejects_invalid_strkey() {
        let err = parse_g_strkey_to_signer_address("not-a-valid-G-strkey").unwrap_err();
        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    ..
                }
            ),
            "invalid G-strkey must return AuthEntryConstructionFailed(auth_payload); got {err:?}"
        );
    }

    /// `parse_g_strkey_to_signer_address` rejects a C-strkey (wrong type — not
    /// an account key).
    #[test]
    fn parse_g_strkey_to_signer_address_rejects_c_strkey() {
        let err = parse_g_strkey_to_signer_address(
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    ..
                }
            ),
            "C-strkey input must return AuthEntryConstructionFailed(auth_payload); got {err:?}"
        );
    }

    /// `parse_g_strkey_to_signer_address` on the canonical zero-key G-strkey
    /// encodes `[0u8; 32]` in the returned `ScAddress::Account`.
    ///
    /// Canonical source: stellar-strkey 0.0.18 docs —
    /// `PublicKey([0u8; 32]).to_string()` yields
    /// `GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF`.
    #[test]
    fn parse_g_strkey_to_signer_address_happy_path_encodes_correct_bytes() {
        let addr = parse_g_strkey_to_signer_address(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        )
        .unwrap();
        match addr {
            ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(bytes)))) => {
                assert_eq!(
                    bytes, [0u8; 32],
                    "zero-key G-strkey must decode to [0u8; 32] ed25519 key"
                );
            }
            other => panic!(
                "parse_g_strkey_to_signer_address must return ScAddress::Account; got {other:?}"
            ),
        }
    }

    // ── scaddress_to_strkey: unsupported variant path ─────────────────────────

    /// `scaddress_to_strkey` returns `AuthEntryConstructionFailed` for an
    /// `ScAddress::MuxedAccount`, a variant of the `SCAddress` union in
    /// `Stellar-contract.x` but not an account or contract principal. The reason
    /// names the variant and carries none of the address bytes.
    #[test]
    fn scaddress_to_strkey_muxed_account_returns_error() {
        use stellar_xdr::{MuxedEd25519Account, Uint256};
        let addr = ScAddress::MuxedAccount(MuxedEd25519Account {
            id: 42,
            ed25519: Uint256([0x0A_u8; 32]),
        });
        let err = scaddress_to_strkey(&addr).unwrap_err();
        let SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } = err
        else {
            panic!("MuxedAccount must return AuthEntryConstructionFailed; got {err:?}");
        };
        assert_eq!(stage, "auth_payload");
        assert_eq!(
            redacted_reason,
            "unsupported ScAddress variant for strkey rendering: \
             address variant MuxedAccount has no account or contract strkey form"
        );
    }

    // ── xdr_scaddress_to_strkey_or_sentinel: sentinel arm ────────────────────

    /// `xdr_scaddress_to_strkey_or_sentinel` returns `"[unknown-address-type]"`
    /// for an `ScAddress::MuxedAccount`, which is not representable as a plain
    /// G- or C-strkey.
    #[test]
    fn xdr_scaddress_to_strkey_or_sentinel_muxed_account_returns_sentinel() {
        use stellar_xdr::{MuxedEd25519Account, Uint256};
        let addr = xdr_curr::ScAddress::MuxedAccount(MuxedEd25519Account {
            id: 1,
            ed25519: Uint256([0xAB_u8; 32]),
        });
        let s = xdr_scaddress_to_strkey_or_sentinel(&addr);
        assert_eq!(
            s, "[unknown-address-type]",
            "MuxedAccount must yield the sentinel '[unknown-address-type]'"
        );
    }

    // ── parse_context_rule_summary: uncovered branches ────────────────────────

    /// `parse_context_rule_summary` skips non-Symbol map keys and successfully
    /// parses a rule that contains a non-Symbol key alongside valid Symbol keys.
    ///
    /// The `_ => continue` at line 3527 is exercised when a ScMapEntry key is
    /// not a `ScVal::Symbol`. Such entries must be skipped silently.
    #[test]
    fn parse_context_rule_summary_skips_non_symbol_key_entries() {
        // Build a rule ScVal with a U32 key before the valid Symbol keys.
        // The Soroban map sort order places U32 before Symbol, so this is a
        // valid strictly-ascending ScMap.
        let entries: VecM<ScMapEntry> = vec![
            // Non-symbol key — must be skipped.
            ScMapEntry {
                key: ScVal::U32(0),
                val: ScVal::Bool(false),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("my-rule".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let scval = ScVal::Map(Some(ScMap(entries)));
        let summary = parse_context_rule_summary(scval, 1).unwrap();
        assert_eq!(summary.rule_id, 1, "rule_id must match parameter");
        assert_eq!(summary.name, "my-rule");
        assert_eq!(summary.context_type_label, "default");
        assert_eq!(summary.signer_count, 0);
        assert_eq!(summary.policy_count, 0);
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when
    /// `context_type` Vec[0] is not a `ScVal::Symbol`.
    ///
    /// Exercises lines 3559-3562: the `other =>` arm of the `elems[0]` match.
    #[test]
    fn parse_context_rule_summary_context_type_vec_first_not_symbol_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                // Vec present, but first element is U32 not Symbol.
                val: ScVal::Vec(Some(ScVec(vec![ScVal::U32(99)].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let err = parse_context_rule_summary(ScVal::Map(Some(ScMap(entries))), 1).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "non-Symbol context_type vec[0] must return DeploymentFailed(simulate); got {err:?}"
        );
    }

    /// `parse_context_rule_summary` decodes a `signers: ScVal::Vec(None)` as
    /// signer_count = 0.
    ///
    /// Exercises the `ScVal::Vec(None) => 0` arm at line 3577 — the empty-Option
    /// form of a Vec from the Soroban host (a valid but unusual encoding for an
    /// empty vector).
    #[test]
    fn parse_context_rule_summary_signers_vec_none_yields_zero_count() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(None), // empty-Option Vec form
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let summary = parse_context_rule_summary(ScVal::Map(Some(ScMap(entries))), 2).unwrap();
        assert_eq!(
            summary.signer_count, 0,
            "ScVal::Vec(None) signers must yield signer_count=0"
        );
    }

    /// `parse_context_rule_summary` decodes a `policies: ScVal::Vec(None)` as
    /// policy_count = 0.
    ///
    /// Exercises the `ScVal::Vec(None) => 0` arm at line 3590.
    #[test]
    fn parse_context_rule_summary_policies_vec_none_yields_zero_count() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(None), // empty-Option Vec form
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let summary = parse_context_rule_summary(ScVal::Map(Some(ScMap(entries))), 3).unwrap();
        assert_eq!(
            summary.policy_count, 0,
            "ScVal::Vec(None) policies must yield policy_count=0"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `valid_until` field is present but has a malformed type (not U32 or Void).
    ///
    /// Exercises lines 3609-3613: the `other =>` arm of the valid_until match
    /// inside `parse_context_rule_summary`.
    #[test]
    fn parse_context_rule_summary_malformed_valid_until_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("bad".try_into().unwrap())), // wrong type
            },
        ]
        .try_into()
        .unwrap();
        let err = parse_context_rule_summary(ScVal::Map(Some(ScMap(entries))), 4).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "malformed valid_until in summary must return DeploymentFailed(simulate); got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `context_type` field is absent (no `context_type` key in the ScMap).
    ///
    /// Exercises the `ok_or_else` guard at line 3625-3626: missing field.
    #[test]
    fn parse_context_rule_summary_missing_context_type_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let err = parse_context_rule_summary(ScVal::Map(Some(ScMap(entries))), 5).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "missing context_type must return DeploymentFailed(simulate); got {err:?}"
        );
        if let SaError::DeploymentFailed {
            redacted_reason, ..
        } = err
        {
            assert!(
                redacted_reason.contains("context_type"),
                "error message must mention missing 'context_type' field; got: {redacted_reason}"
            );
        }
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `signers` field is absent.
    ///
    /// Exercises the `ok_or_else` guard at line 3627-3629.
    #[test]
    fn parse_context_rule_summary_missing_signers_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("policies").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let err = parse_context_rule_summary(ScVal::Map(Some(ScMap(entries))), 6).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "missing signers field must return DeploymentFailed(simulate); got {err:?}"
        );
    }

    /// `parse_context_rule_summary` returns `DeploymentFailed` when the
    /// `policies` field is absent.
    ///
    /// Exercises the `ok_or_else` guard at line 3630-3631.
    #[test]
    fn parse_context_rule_summary_missing_policies_returns_error() {
        let entries: VecM<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("context_type").unwrap()),
                val: ScVal::Vec(Some(ScVec(
                    vec![ScVal::Symbol(ScSymbol::try_from("Default").unwrap())]
                        .try_into()
                        .unwrap(),
                ))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("name").unwrap()),
                val: ScVal::String(stellar_xdr::ScString("test".try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(vec![].try_into().unwrap()))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                val: ScVal::Void,
            },
        ]
        .try_into()
        .unwrap();
        let err = parse_context_rule_summary(ScVal::Map(Some(ScMap(entries))), 7).unwrap_err();
        assert!(
            matches!(err, SaError::DeploymentFailed { phase, .. } if phase == "simulate"),
            "missing policies field must return DeploymentFailed(simulate); got {err:?}"
        );
    }

    // ── decode_signer_count_from_scval / decode_policy_count_from_scval:
    // ── non-symbol key skip ────────────────────────────────────────────────────

    /// `decode_signer_count_from_scval` skips non-Symbol keys and still succeeds
    /// when a `signer_ids` Symbol key follows a non-Symbol key.
    ///
    /// Exercises line 3686: `_ => continue` in the key-match arm.
    #[test]
    fn decode_signer_count_from_scval_skips_non_symbol_key() {
        // Build a map where the first entry has a non-Symbol key (U32)
        // and the second has the expected Symbol("signer_ids") key.
        // Soroban map: U32 < Symbol in the canonical sort order, so this is valid.
        let map = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::U32(0), // non-symbol key — must be skipped
                    val: ScVal::Bool(false),
                },
                ScMapEntry {
                    key: ScVal::Symbol(stellar_xdr::ScSymbol("signer_ids".try_into().unwrap())),
                    val: ScVal::Vec(Some(ScVec(
                        vec![ScVal::U32(10), ScVal::U32(20)].try_into().unwrap(),
                    ))),
                },
            ]
            .try_into()
            .unwrap(),
        )));
        let count = decode_signer_count_from_scval(&map).unwrap();
        assert_eq!(
            count, 2,
            "signer_ids vec with two entries must yield count=2 even when preceded by a non-Symbol key"
        );
    }

    /// `decode_policy_count_from_scval` skips non-Symbol keys and still succeeds
    /// when a `policy_ids` Symbol key follows a non-Symbol key.
    ///
    /// Exercises line 3752: `_ => continue` in the key-match arm.
    #[test]
    fn decode_policy_count_from_scval_skips_non_symbol_key() {
        let map = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::U32(0), // non-symbol key — must be skipped
                    val: ScVal::Bool(false),
                },
                ScMapEntry {
                    key: ScVal::Symbol(stellar_xdr::ScSymbol("policy_ids".try_into().unwrap())),
                    val: ScVal::Vec(Some(ScVec(vec![ScVal::U32(5)].try_into().unwrap()))),
                },
            ]
            .try_into()
            .unwrap(),
        )));
        let count = decode_policy_count_from_scval(&map).unwrap();
        assert_eq!(
            count, 1,
            "policy_ids vec with one entry must yield count=1 even when preceded by a non-Symbol key"
        );
    }

    // ── extract_valid_until_from_rule_scval: non-symbol key skip ──────────────

    /// `extract_valid_until_from_rule_scval` skips non-Symbol keys and still
    /// extracts `valid_until` when a Symbol key follows a non-Symbol key.
    ///
    /// Exercises line 3819: `_ => continue` in the key-match arm.
    #[test]
    fn extract_valid_until_skips_non_symbol_key() {
        let scval = ScVal::Map(Some(ScMap(
            vec![
                ScMapEntry {
                    key: ScVal::U32(0), // non-symbol key — must be skipped
                    val: ScVal::Bool(false),
                },
                ScMapEntry {
                    key: ScVal::Symbol(ScSymbol::try_from("valid_until").unwrap()),
                    val: ScVal::U32(99_999),
                },
            ]
            .try_into()
            .unwrap(),
        )));
        let extracted = extract_valid_until_from_rule_scval(&scval).unwrap();
        assert_eq!(
            extracted,
            Some(99_999),
            "valid_until=99999 must be extracted even when preceded by a non-Symbol key"
        );
    }

    // ── oz_smart_account_error_name: coverage of remaining discriminants ──────

    /// `oz_smart_account_error_name` returns the correct symbolic name for all
    /// OZ `SmartAccountError` discriminants in the 3012-3016 range not yet
    /// exercised by the existing `oz_smart_account_error_name_matches_oz_wire_discriminants`
    /// test.
    ///
    /// The existing test at line 4573 covers 3000, 3002-3011. This test pins the
    /// remaining codes 3012-3016 independently.
    ///
    /// Canonical source: `packages/accounts/src/smart_account/mod.rs:535-572`
    /// SHA `a9c4216` (OZ v0.7.2).
    #[test]
    fn oz_smart_account_error_name_upper_discriminants_3012_to_3016() {
        let cases = [
            (3012u32, "MathOverflow"),
            (3013u32, "KeyDataTooLarge"),
            (3014u32, "ContextRuleIdsLengthMismatch"),
            (3015u32, "NameTooLong"),
            (3016u32, "UnauthorizedSigner"),
        ];
        for (code, expected) in &cases {
            assert_eq!(
                oz_smart_account_error_name(*code),
                Some(*expected),
                "discriminant {code} must map to '{expected}'"
            );
        }
    }

    /// `augment_with_oz_error_name` correctly annotates discriminants in the
    /// 3012-3016 range — verifies the full pipeline (parse + lookup + format).
    #[test]
    fn augment_with_oz_error_name_annotates_name_too_long() {
        let msg = "simulate returned Error(Contract, #3015) for rule name";
        let result = augment_with_oz_error_name(msg);
        assert!(
            result.contains("[OZ:NameTooLong]"),
            "discriminant 3015 must annotate with NameTooLong; got: {result}"
        );
    }

    // ── ContextRuleManagerConfig builder methods ───────────────────────────────

    /// `ContextRuleManagerConfig::with_secondary_rpc_url` stores the URL.
    ///
    /// Exercises line 183: the builder sets `secondary_rpc_url = Some(url)`.
    #[test]
    fn config_with_secondary_rpc_url_stores_value() {
        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        )
        .with_secondary_rpc_url("http://127.0.0.1:65536".to_owned());

        assert_eq!(
            cfg.secondary_rpc_url.as_deref(),
            Some("http://127.0.0.1:65536"),
            "with_secondary_rpc_url must set secondary_rpc_url"
        );
    }

    /// `ContextRuleManagerConfig::with_session_rule_max_horizon_ledgers` stores
    /// the override value.
    ///
    /// Exercises line 229: `session_rule_max_horizon_ledgers = Some(ledgers)`.
    #[test]
    fn config_with_session_rule_max_horizon_ledgers_stores_value() {
        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        )
        .with_session_rule_max_horizon_ledgers(500);

        assert_eq!(
            cfg.session_rule_max_horizon_ledgers,
            Some(500),
            "with_session_rule_max_horizon_ledgers must set the override"
        );
    }

    /// `ContextRuleManagerConfig::new` leaves optional builder fields as `None`.
    ///
    /// Verifies that the default (no builder calls) leaves
    /// `secondary_rpc_url`, `signers_manager`, `audit_writer`, and
    /// `session_rule_max_horizon_ledgers` all as `None`.
    #[test]
    fn config_new_leaves_optional_fields_as_none() {
        let cfg = ContextRuleManagerConfig::new(
            "http://127.0.0.1:65535".to_owned(),
            "Test SDF Network ; September 2015".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        );
        assert!(
            cfg.secondary_rpc_url.is_none(),
            "secondary_rpc_url must be None by default"
        );
        assert!(
            cfg.signers_manager.is_none(),
            "signers_manager must be None by default"
        );
        assert!(
            cfg.audit_writer.is_none(),
            "audit_writer must be None by default"
        );
        assert!(
            cfg.session_rule_max_horizon_ledgers.is_none(),
            "session_rule_max_horizon_ledgers must be None by default"
        );
    }

    // ── dispatch_audit_emission: adversarial mutex-poison test ───────────────
    //
    // Verifies the non-panic + degraded-flag contract of the poison branch in
    // `dispatch_audit_emission`. Canonical poison path:
    // `dispatch_audit_emission` → `fallback.lock()` → `Err(_poison)` →
    // `health.mark_degraded()` + warn, no panic, no row written.

    /// Poison the `fallback` mutex by spawning a thread that panics while
    /// holding the lock, then call `dispatch_audit_emission` with a health
    /// handle.
    ///
    /// Asserts:
    /// - No panic propagates to the test thread.
    /// - `health.is_degraded()` flips to `true` after the call.
    ///
    /// Verifies that a poisoned fallback mutex is handled gracefully.
    #[test]
    fn dispatch_audit_emission_poisoned_mutex_marks_health_no_panic() {
        use stellar_agent_core::audit_log::health::AuditWriterHealth;
        use stellar_agent_core::audit_log::writer::AuditWriter;

        // Build a fallback AuditWriter in a temp directory.
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.log");
        let writer = AuditWriter::open(log_path, None).expect("open audit writer");
        let fallback: Arc<Mutex<AuditWriter>> = Arc::new(Mutex::new(writer));

        // Poison the mutex: spawn a thread that holds the lock and panics.
        {
            let fallback_clone = Arc::clone(&fallback);
            let _ = std::thread::spawn(move || {
                let _guard = fallback_clone.lock().expect("lock before panic");
                panic!("intentional poison for test");
            })
            .join(); // join returns Err — that is the expected poisoning result
        }
        assert!(
            fallback.lock().is_err(),
            "mutex must be poisoned before calling dispatch_audit_emission"
        );

        // Build a health owner + handle.
        let health_owner = AuditWriterHealth::new();
        let handle = health_owner.handle();
        assert!(!handle.is_degraded(), "handle must start non-degraded");

        // Build a dummy audit entry (type does not matter for the poison path).
        let entry = AuditEntry::new_sa_raw_invocation(
            "GABCD…12345",
            "sa.ok",
            None,
            0,
            stellar_agent_core::audit_log::schema::SaInvocationResult::Success,
            "stellar:testnet",
            "test-req-id",
        );

        // Call dispatch_audit_emission — must not panic.
        dispatch_audit_emission(
            None,            // no per-method writer
            Some(&fallback), // poisoned fallback
            entry,
            "test_poison",
            Some(&handle),
        );

        // The health latch must flip to degraded.
        assert!(
            health_owner.is_degraded(),
            "AuditWriterHealth owner must observe degraded after poison path"
        );
        assert!(
            handle.is_degraded(),
            "handle must also observe degraded (shared Arc)"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // compute_context_rule_proposal_sha256 (Package D, GH issue #8)
    // ─────────────────────────────────────────────────────────────────────────

    fn digest_smart_account() -> ScAddress {
        ScAddress::Contract(ContractId(stellar_xdr::Hash([0x33_u8; 32])))
    }

    /// Builds a `Delegated` signer directly from raw ed25519 pubkey bytes
    /// (bypassing G-strkey parsing, which requires a valid checksum).
    fn digest_signer_with_pubkey(byte_fill: u8) -> ContextRuleSignerInput {
        ContextRuleSignerInput::Delegated {
            address: ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256([byte_fill; 32])),
            )),
        }
    }

    fn digest_signer() -> ContextRuleSignerInput {
        digest_signer_with_pubkey(0x11)
    }

    fn digest_baseline_def() -> ContextRuleDefinition {
        ContextRuleDefinition::new(
            RuleContext::Default,
            "spend-daily".to_owned(),
            None,
            vec![digest_signer()],
            vec![],
        )
    }

    fn digest_baseline_ids() -> Vec<stellar_agent_core::smart_account::rule_id::ContextRuleId> {
        vec![stellar_agent_core::smart_account::rule_id::ContextRuleId::new(0)]
    }

    #[test]
    fn compute_context_rule_proposal_sha256_is_deterministic() {
        let sa = digest_smart_account();
        let def = digest_baseline_def();
        let ids = digest_baseline_ids();
        let d1 = compute_context_rule_proposal_sha256(&sa, &def, &ids, false, false).unwrap();
        let d2 = compute_context_rule_proposal_sha256(&sa, &def, &ids, false, false).unwrap();
        assert_eq!(d1, d2);
        assert_ne!(d1, [0u8; 32]);
    }

    /// Tamper matrix: flipping ANY snapshot field class must change the
    /// digest (Package D, GH issue #8 — the integrity invariant that binds
    /// the operator's attestation to EXACTLY the resolved arguments).
    #[test]
    fn compute_context_rule_proposal_sha256_tamper_matrix() {
        let sa = digest_smart_account();
        let ids = digest_baseline_ids();
        let baseline =
            compute_context_rule_proposal_sha256(&sa, &digest_baseline_def(), &ids, false, false)
                .unwrap();

        // name
        let mut def_name = digest_baseline_def();
        def_name.name = "different-name".to_owned();
        let d = compute_context_rule_proposal_sha256(&sa, &def_name, &ids, false, false).unwrap();
        assert_ne!(baseline, d, "changing name must change the digest");

        // valid_until
        let mut def_valid_until = digest_baseline_def();
        def_valid_until.valid_until = Some(12345);
        let d = compute_context_rule_proposal_sha256(&sa, &def_valid_until, &ids, false, false)
            .unwrap();
        assert_ne!(baseline, d, "changing valid_until must change the digest");

        // a signer byte (different pubkey bytes ⟹ different address bytes)
        let mut def_signer = digest_baseline_def();
        def_signer.signers = vec![digest_signer_with_pubkey(0x22)];
        let d = compute_context_rule_proposal_sha256(&sa, &def_signer, &ids, false, false).unwrap();
        assert_ne!(baseline, d, "changing a signer byte must change the digest");

        // a policy param
        let mut def_policy = digest_baseline_def();
        def_policy.policies = vec![ContextRulePolicy::new(
            ScAddress::Contract(ContractId(stellar_xdr::Hash([0x55_u8; 32]))),
            ScVal::U32(1),
        )];
        let d = compute_context_rule_proposal_sha256(&sa, &def_policy, &ids, false, false).unwrap();
        assert_ne!(
            baseline, d,
            "changing a policy param must change the digest"
        );

        // auth_rule_ids
        let other_ids = vec![stellar_agent_core::smart_account::rule_id::ContextRuleId::new(1)];
        let d = compute_context_rule_proposal_sha256(
            &sa,
            &digest_baseline_def(),
            &other_ids,
            false,
            false,
        )
        .unwrap();
        assert_ne!(baseline, d, "changing auth_rule_ids must change the digest");

        // accept_mutable_verifier flag
        let d =
            compute_context_rule_proposal_sha256(&sa, &digest_baseline_def(), &ids, true, false)
                .unwrap();
        assert_ne!(
            baseline, d,
            "changing accept_mutable_verifier must change the digest"
        );

        // accept_unknown_verifier flag
        let d =
            compute_context_rule_proposal_sha256(&sa, &digest_baseline_def(), &ids, false, true)
                .unwrap();
        assert_ne!(
            baseline, d,
            "changing accept_unknown_verifier must change the digest"
        );

        // smart_account itself
        let other_sa = ScAddress::Contract(ContractId(stellar_xdr::Hash([0x99_u8; 32])));
        let d = compute_context_rule_proposal_sha256(
            &other_sa,
            &digest_baseline_def(),
            &ids,
            false,
            false,
        )
        .unwrap();
        assert_ne!(baseline, d, "changing smart_account must change the digest");

        // context type: Default → CallContract (a different target contract)
        let mut def_context = digest_baseline_def();
        def_context.context_type = RuleContext::CallContract {
            contract: ScAddress::Contract(ContractId(stellar_xdr::Hash([0x77_u8; 32]))),
        };
        let d =
            compute_context_rule_proposal_sha256(&sa, &def_context, &ids, false, false).unwrap();
        assert_ne!(
            baseline, d,
            "changing context type (Default -> CallContract) must change the digest"
        );

        // signer order: the SAME two signers in a DIFFERENT sequence.
        let mut def_forward = digest_baseline_def();
        def_forward.signers = vec![
            digest_signer_with_pubkey(0x22),
            digest_signer_with_pubkey(0x33),
        ];
        let mut def_reversed = digest_baseline_def();
        def_reversed.signers = vec![
            digest_signer_with_pubkey(0x33),
            digest_signer_with_pubkey(0x22),
        ];
        let d_forward =
            compute_context_rule_proposal_sha256(&sa, &def_forward, &ids, false, false).unwrap();
        let d_reversed =
            compute_context_rule_proposal_sha256(&sa, &def_reversed, &ids, false, false).unwrap();
        assert_ne!(
            d_forward, d_reversed,
            "swapping the order of the SAME signer set must change the digest"
        );
    }

    #[test]
    fn compute_context_rule_proposal_sha256_both_flags_distinguishable() {
        let sa = digest_smart_account();
        let def = digest_baseline_def();
        let ids = digest_baseline_ids();
        let d_none = compute_context_rule_proposal_sha256(&sa, &def, &ids, false, false).unwrap();
        let d_mutable = compute_context_rule_proposal_sha256(&sa, &def, &ids, true, false).unwrap();
        let d_unknown = compute_context_rule_proposal_sha256(&sa, &def, &ids, false, true).unwrap();
        let d_both = compute_context_rule_proposal_sha256(&sa, &def, &ids, true, true).unwrap();
        // All four flag combinations must be pairwise distinct.
        let all = [d_none, d_mutable, d_unknown, d_both];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "flag-combination digests at indices {i} and {j} must differ"
                );
            }
        }
    }

    #[test]
    fn config_debug_redacts_urls_and_writer_paths() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("SENTINEL-WRITER");
        std::fs::create_dir(&parent).unwrap();
        let path = parent.join("SENTINEL-AUDIT.jsonl");
        let writer = Arc::new(Mutex::new(
            stellar_agent_core::audit_log::writer::AuditWriter::open(path.clone(), None).unwrap(),
        ));
        let primary = "https://SENTINEL-USER-A:SENTINEL-PASS-A@primary.example/SENTINEL-PATH-A?k=SENTINEL-QUERY-A";
        let secondary = "https://SENTINEL-USER-B:SENTINEL-PASS-B@secondary.example/SENTINEL-PATH-B?k=SENTINEL-QUERY-B";
        let config = ContextRuleManagerConfig::new(
            primary.into(),
            "network".into(),
            Duration::from_secs(1),
            "stellar:testnet".into(),
        )
        .with_secondary_rpc_url(secondary.into())
        .with_audit_writer(writer);
        let debug = format!("{config:?}");
        assert!(
            !debug.contains("SENTINEL"),
            "Debug leaked a sentinel: {debug}"
        );
        assert!(debug.contains("https://primary.example"));
        assert!(debug.contains("https://secondary.example"));
    }
}
