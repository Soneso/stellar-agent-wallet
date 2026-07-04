//! Signer-set manager — atomic add/remove/set-threshold for OZ context rules.
//!
//! Implements `SignersManager`, the off-chain orchestrator for atomic
//! signer-threshold updates against OpenZeppelin `stellar-accounts` v0.7.1
//! context-rule signer sets.  Every mutating method enforces:
//!
//! 1. **Threshold invariant pre-flight**: refuses operations that would produce
//!    `signer_count' < threshold'` or `threshold' < 1` before submitting.
//! 2. **Two-RPC signer-set consultation**: primary + secondary RPC must agree on
//!    `(signer_count, threshold)` before any divergence check fires.
//! 3. **Audit-log-derived divergence detection**: the expected signer-set view
//!    comes from the most-recent `SaSignerSetBaselined` / `SaSignerAdded` /
//!    `SaSignerRemoved` / `SaThresholdChanged` row, not a separate cache.
//! 4. **Refusal path**: signer mutations that would cross the threshold-vs-count
//!    invariant are refused with [`crate::SaError::ThresholdUnreachable`] carrying
//!    a `safe_ordering_hint` guiding the safe two-command sequence (atomic bundle
//!    dropped; CAP-46 prohibits two `InvokeHostFunctionOp` per Soroban transaction).
//!
//! # Architecture
//!
//! Each public `async` method is a thin outer function that:
//! 1. Acquires the per-rule mutex (non-reentrant; fails on double-lock attempt).
//! 2. Delegates to `*_locked_inner` which does the actual work.
//! 3. Emits the audit-log row (success or failure) inside the write critical
//!    section, sourcing `prev_chain_tip_hash` from `AuditWriter::current_chain_tip()`
//!    inside that section (prev_chain_tip_hash sourced inside the write lock).
//!
//! # Single-caller invariant for `SaSignerSetBaselined`
//!
//! Only `SignersManager::list_signers` (first-observation) and
//! `SignersManager::refresh_signer_baseline` (always) may construct
//! `EventKind::SaSignerSetBaselined`.  A CI gate enforces this single-caller
//! invariant: only these two functions may emit `SaSignerSetBaselined`.
//!
//! # Implements
//!
//! - Atomic signer-threshold update: all signer add/remove and threshold
//!   changes are submitted as a single transaction, preventing partial-update
//!   states.
//! - Signer-threshold policy enforcement: the threshold is validated against
//!   the active signer set to guard against configurations where the threshold
//!   exceeds the number of available signers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::AuditLogIntegrityError;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::health::{AuditWriterHealth, AuditWriterHealthHandle};
use stellar_agent_core::audit_log::signer_set::{
    BaselineReason, ObservedSignerSet, SignerPubkey, compute_signer_set_digest,
    format_digest_first8_last8,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_core::timefmt::now_unix_ms;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::{StellarRpcClient, fetch_account};
use stellar_baselib::account::{Account as BaselibAccount, AccountBehavior};
use stellar_baselib::transaction::TransactionBehavior;
use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
use stellar_rpc_client::Client;
use stellar_xdr::LedgerKey;
use stellar_xdr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Operation,
    OperationBody, PublicKey, ScAddress, ScBytes, ScSymbol, ScVal, ScVec, Uint256, VecM,
};
use tracing::{debug, info, warn};

use crate::SaError;
use crate::managers::rules::{
    BASE_FEE_STROOPS, ExpiryCheck, augment_with_oz_error_name, contract_instance_key,
    scaddress_to_strkey,
};
use crate::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES;
use crate::signers::types::{FrozenChainStateTuple, ThresholdAffectingOp, WasmHashSummary};

/// Context passed to wasm-hash allowlist error constructors.
pub(crate) struct NotInAllowlistContext {
    /// Rule whose referenced contract failed the allowlist check.
    pub(crate) rule_id: u32,
    /// Redacted smart-account C-strkey.
    pub(crate) smart_account_redacted: String,
    /// Observed wasm-hash first eight hex characters, or `"none"`.
    pub(crate) observed_hash_first8: String,
    /// Request correlation ID.
    pub(crate) request_id: String,
}

// ── On-chain constants (OZ stellar-contracts v0.7.1) ────────────

/// Maximum number of signers per context rule, per the OpenZeppelin
/// stellar-accounts v0.7.1 smart-account contract.
const MAX_SIGNERS: u32 = 15;

// ── Per-rule async mutex registry ────────────────────────────────────────────

/// Per-rule async mutex map key: `(audit_log_path, rule_id, smart_account_strkey)`.
type RuleMutexKey = (PathBuf, u32, String);

/// Inner per-rule async mutex shared between concurrent callers.
type RuleMutexInner = Arc<tokio::sync::Mutex<()>>;

/// Per-rule mutex registry map type.
type RuleMutexMap = Mutex<HashMap<RuleMutexKey, RuleMutexInner>>;

/// Process-global per-rule async mutex registry.
///
/// Keyed on `(audit_log_path, rule_id, smart_account_strkey)`.  Provides a
/// non-reentrant mutual exclusion primitive so concurrent `add_signer` /
/// `remove_signer` / `set_threshold` calls against the same rule-ID + smart
/// account are serialised — preventing TOCTOU windows between the divergence
/// check and the transaction submission.
///
/// Six and only six acquire sites are authorised: the three mutating ops
/// (`add_signer`, `remove_signer`, `set_threshold`) AND the three read-side
/// ops that write to the audit log (`list_signers`, `refresh_signer_baseline`,
/// `verify_signer_set_against_chain`).
/// A CI gate enforces this exact-six-site allowlist.
static RULE_MUTEX_REGISTRY: OnceLock<RuleMutexMap> = OnceLock::new();

fn rule_mutex_registry() -> &'static RuleMutexMap {
    RULE_MUTEX_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Acquires or creates the per-rule async mutex for `(audit_log_path, rule_id, smart_account_strkey)`.
///
/// Returns a clone of the `Arc<tokio::sync::Mutex<()>>` so the caller can
/// `.lock().await` it without holding the global registry lock.
///
/// # Panics
///
/// Panics if the global registry `std::sync::Mutex` is poisoned (unrecoverable
/// in a multi-threaded async context; a prior thread panic is the only cause).
#[allow(
    clippy::expect_used,
    reason = "std::sync::Mutex poison is unrecoverable here"
)]
fn rule_mutex_acquire(
    audit_log_path: &std::path::Path,
    rule_id: u32,
    smart_account_strkey: &str,
) -> Arc<tokio::sync::Mutex<()>> {
    let key = (
        audit_log_path.to_path_buf(),
        rule_id,
        smart_account_strkey.to_owned(),
    );
    let registry = rule_mutex_registry();
    let mut map = registry.lock().expect("rule mutex registry poisoned");
    Arc::clone(
        map.entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
    )
}

// ── SignersManagerConfig ──────────────────────────────────────────────────────

/// Configuration for [`SignersManager`].
///
/// Constructed once per CLI / MCP invocation; carries network identity, RPC
/// URLs, audit-log handle, and timeout policy.
///
/// # Two-RPC consultation
///
/// `primary_rpc_url` and `secondary_rpc_url` are used in parallel
/// (`tokio::join!`) for signer-set reads.  If both URLs are equal, a warning
/// is logged at construction time; the consultation degrades to a single RPC
/// with equal responses, which satisfies the "both agree" check trivially.
///
/// # Non-exhaustive
///
/// `#[non_exhaustive]` prevents external crates from using struct-expression
/// syntax; use [`SignersManagerConfig::new`].
///
/// # Implements
///
/// Atomic signer-threshold update: all signer add/remove and threshold changes
/// are submitted as a single transaction, preventing partial-update states.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SignersManagerConfig {
    /// Primary Soroban RPC URL.
    pub primary_rpc_url: String,

    /// Secondary Soroban RPC URL for two-RPC consultation.
    ///
    /// May equal `primary_rpc_url` (degrades to single-RPC; warning is logged).
    pub secondary_rpc_url: String,

    /// Shared audit-log writer handle.
    ///
    /// `Arc<Mutex<AuditWriter>>` so the manager can hold a reference across
    /// the async boundary without blocking the writer for the duration of a
    /// network round-trip.
    pub audit_writer: Arc<Mutex<AuditWriter>>,

    /// Filesystem path of the audit log (used as the mutex registry key).
    pub audit_log_path: PathBuf,

    /// Stellar network passphrase for auth-digest and network-ID computation.
    pub network_passphrase: String,

    /// Profile name used for tracing context (non-sensitive display label).
    pub profile_name: String,

    /// Submission polling timeout.
    pub timeout: Duration,

    /// CAIP-2 chain ID for audit-log entries (e.g. `"stellar:testnet"`).
    pub chain_id: String,
}

impl SignersManagerConfig {
    /// Constructs a new `SignersManagerConfig`.
    ///
    /// Logs a warning if `primary_rpc_url == secondary_rpc_url`, because the
    /// two-RPC consultation degrades to a single RPC in that case.
    ///
    /// # Arguments
    ///
    /// - `primary_rpc_url` — primary Soroban RPC endpoint.
    /// - `secondary_rpc_url` — secondary Soroban RPC endpoint for two-RPC consultation.
    /// - `audit_writer` — shared audit-log writer handle.
    /// - `audit_log_path` — filesystem path of the audit log (mutex-registry key).
    /// - `network_passphrase` — Stellar network passphrase.
    /// - `profile_name` — non-sensitive profile display label.
    /// - `timeout` — submission polling timeout.
    /// - `chain_id` — CAIP-2 chain identifier.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible multi-RPC + audit + network arg set"
    )]
    pub fn new(
        primary_rpc_url: String,
        secondary_rpc_url: String,
        audit_writer: Arc<Mutex<AuditWriter>>,
        audit_log_path: PathBuf,
        network_passphrase: String,
        profile_name: String,
        timeout: Duration,
        chain_id: String,
    ) -> Self {
        if primary_rpc_url == secondary_rpc_url {
            warn!(
                profile = %profile_name,
                "SignersManagerConfig: primary_rpc_url == secondary_rpc_url; \
                 two-RPC consultation degrades to single-RPC (both responses will agree trivially)"
            );
        }
        Self {
            primary_rpc_url,
            secondary_rpc_url,
            audit_writer,
            audit_log_path,
            network_passphrase,
            profile_name,
            timeout,
            chain_id,
        }
    }
}

// ── SignersManager ────────────────────────────────────────────────────────────

/// Off-chain orchestrator for OZ smart-account signer-set lifecycle operations.
///
/// Provides the atomic signer-threshold update surface:
///
/// | Method | Effect | Mutex | Audit row |
/// |--------|--------|-------|-----------|
/// | `list_signers` | Reads on-chain signer set (two-RPC); baselines if no prior row | yes | `SaSignerSetBaselined` (first-obs) |
/// | `refresh_signer_baseline` | Two-RPC fetch; always writes fresh baseline | yes | `SaSignerSetBaselined` |
/// | `add_signer` | Adds a signer; per-rule mutex held | yes | `SaSignerAdded` |
/// | `remove_signer` | Removes a signer; per-rule mutex held | yes | `SaSignerRemoved` |
/// | `set_threshold` | Changes threshold only; per-rule mutex held | yes | `SaThresholdChanged` |
/// | `verify_signer_set_against_chain` | Checks on-chain vs audit-log baseline | yes | `SaSignerSetDiverged` (on mismatch) |
/// | `identify_threshold_policy` | Wasm-hash two-RPC lookup | no | (internal; no audit row) |
/// | `identify_verifier` | Verifier wasm-hash two-RPC lookup | no | (internal; no audit row) |
///
/// # Non-reentrant rule mutex
///
/// All six public `async` methods acquire a per-rule `tokio::sync::Mutex`
/// before any network I/O, preventing TOCTOU races between the divergence
/// check and the transaction submission.
/// A CI gate enforces exactly six authorised acquire sites.
///
/// # Implements
///
/// - Atomic signer-threshold update: all signer add/remove and threshold
///   changes are submitted as a single transaction, preventing partial-update
///   states.
/// - Signer-threshold policy enforcement: the threshold is validated against
///   the active signer set to guard against configurations where the threshold
///   exceeds the number of available signers.
pub struct SignersManager {
    primary_rpc_url: String,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
    network_passphrase: String,
    profile_name: String,
    timeout: Duration,
    chain_id: String,
    primary_rpc_client: StellarRpcClient,
    secondary_rpc_client: StellarRpcClient,
    /// Session-level audit-writer health owner.
    ///
    /// Handles are distributed to free-standing helpers via
    /// [`SignersManager::health_handle`] so they can mark the session degraded
    /// without access to the full manager.
    health: AuditWriterHealth,
}

impl std::fmt::Debug for SignersManager {
    /// Redacted `Debug` impl: RPC URLs and audit-log path are redacted to
    /// non-sensitive labels (no file paths or URLs in debug output at log
    /// level info).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignersManager")
            .field("profile_name", &self.profile_name)
            .field("chain_id", &self.chain_id)
            .field("primary_rpc_url", &"[redacted]")
            .field("secondary_rpc_url", &"[redacted]")
            .field("audit_log_path", &"[redacted]")
            .finish()
    }
}

impl SignersManager {
    /// Constructs a new `SignersManager`.
    ///
    /// # Errors
    ///
    /// Returns [`SaError::AuthEntryConstructionFailed`] (stage `"auth_payload"`)
    /// if either RPC client cannot be constructed (typically a malformed URL).
    pub fn new(config: SignersManagerConfig) -> Result<Self, SaError> {
        let mk_err = |url: &str, e: &dyn std::fmt::Display| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("StellarRpcClient construction failed for {url}: {e}"),
        };
        let primary_rpc_client = StellarRpcClient::new(&config.primary_rpc_url)
            .map_err(|e| mk_err(&config.primary_rpc_url, &e))?;
        let secondary_rpc_client = StellarRpcClient::new(&config.secondary_rpc_url)
            .map_err(|e| mk_err(&config.secondary_rpc_url, &e))?;
        Ok(Self {
            primary_rpc_url: config.primary_rpc_url,
            audit_writer: config.audit_writer,
            audit_log_path: config.audit_log_path,
            network_passphrase: config.network_passphrase,
            profile_name: config.profile_name,
            timeout: config.timeout,
            chain_id: config.chain_id,
            primary_rpc_client,
            secondary_rpc_client,
            health: AuditWriterHealth::new(),
        })
    }

    /// Returns a reference to the primary RPC client.
    ///
    /// `pub(crate)` — used by `managers::verifiers::pin_referenced_contracts`
    /// to forward the manager's two-RPC clients into
    /// `detect_contract_mutability` and `identify_policy_wasm_hash`.
    /// Not part of the public `SignersManager` API surface.
    #[must_use]
    pub(crate) fn primary_rpc_client(&self) -> &StellarRpcClient {
        &self.primary_rpc_client
    }

    /// Returns a reference to the secondary RPC client.
    ///
    /// `pub(crate)` — used by `managers::verifiers::pin_referenced_contracts`
    /// to forward the manager's two-RPC clients into
    /// `detect_contract_mutability` and `identify_policy_wasm_hash`.
    /// Not part of the public `SignersManager` API surface.
    #[must_use]
    pub(crate) fn secondary_rpc_client(&self) -> &StellarRpcClient {
        &self.secondary_rpc_client
    }

    /// Returns a clone of the shared `Arc<Mutex<AuditWriter>>`.
    ///
    /// `pub(crate)` — used by `CredentialsManager::sign_with_passkey_rule`
    /// to obtain the shared audit writer so that both the `PasskeyAssertion`
    /// outer row and the inner `SaSignerSetDiverged` row land through the same
    /// writer instance.  This eliminates the `FileLocked` panic that occurred
    /// when credentials tried to open a second `AuditWriter` against the same
    /// exclusive-lock path.
    #[must_use]
    pub(crate) fn audit_writer(&self) -> Arc<Mutex<AuditWriter>> {
        Arc::clone(&self.audit_writer)
    }

    /// Returns whether any audit row was dropped because the audit-writer mutex
    /// was poisoned during this manager session.
    ///
    /// Delegates to [`AuditWriterHealth::is_degraded`] on the owned health
    /// instance.  The flag is a write-once monotone latch: it transitions from
    /// `false` to `true` on first poison-detection and never resets.
    /// `Ordering::Relaxed` is appropriate because (1) the underlying
    /// `Mutex::lock()` result already carries its own synchronisation; (2) no
    /// other state is published via this flag — it is a pure observability
    /// signal; (3) the swap-and-warn idiom in `mark_audit_writer_degraded` uses
    /// the prior-value return of `swap` to make the warning one-shot independent
    /// of memory ordering.  See [`AuditWriterHealth`] module-level rustdoc for
    /// the full ordering rationale.
    #[must_use]
    pub fn audit_writer_degraded(&self) -> bool {
        self.health.is_degraded()
    }

    /// Marks the audit writer as structurally degraded for the current session.
    ///
    /// Delegates to [`AuditWriterHealth::mark_degraded`]; write-once monotone
    /// latch semantics and warning emission are handled there.  The ordering
    /// rationale is documented in [`AuditWriterHealth`].
    pub(crate) fn mark_audit_writer_degraded(&self) {
        self.health.mark_degraded();
    }

    /// Returns a cheap-clone handle to the shared health state.
    ///
    /// Handles are distributed to free-standing helpers in `rules.rs` and
    /// `verifiers.rs` that do not have access to the full `SignersManager`
    /// but need to mark the session degraded on mutex-poison events.
    ///
    /// Cloning is `O(1)` — only the `Arc` reference count is incremented.
    ///
    /// `pub(crate)` — only `managers::*` helpers consume this.
    #[must_use]
    pub(crate) fn health_handle(&self) -> AuditWriterHealthHandle {
        self.health.handle()
    }

    /// Returns the CAIP-2 chain identifier configured for this manager.
    ///
    /// `pub(crate)` — used by `managers::verifiers::verify_pinned_verifier_against_chain`
    /// and `verify_pinned_policy_against_chain` to populate the
    /// `chain_id` field on drift audit entries.
    #[must_use]
    pub(crate) fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Returns the Stellar network passphrase.
    ///
    /// `pub(crate)` — used by [`crate::managers::migration::MigrationPlanner`] to
    /// pass to `simulate_read_only` for `get_context_rules_count` /
    /// `get_context_rule` read-only simulation calls.
    #[must_use]
    pub(crate) fn network_passphrase_ref(&self) -> String {
        self.network_passphrase.clone()
    }

    /// Returns the configured submission timeout.
    ///
    /// `pub(crate)` — used by [`crate::managers::migration::MigrationPlanner`] to
    /// pass to `simulate_read_only`.
    #[must_use]
    pub(crate) fn timeout_ref(&self) -> Duration {
        self.timeout
    }

    /// Returns the chain ID string.
    ///
    /// `pub(crate)` — used by [`crate::managers::migration`] to pass
    /// the chain ID into `SaVerifierMigrated` audit rows.
    #[must_use]
    pub(crate) fn chain_id_ref(&self) -> &str {
        &self.chain_id
    }

    /// Returns the shared `Arc<Mutex<AuditWriter>>` for migration audit emission.
    ///
    /// `pub(crate)` — used by [`crate::managers::migration`] to emit
    /// `SaVerifierMigrated` audit rows after each signer-step pair submission.
    /// Mirrors the `audit_writer()` accessor used by `CredentialsManager`.
    #[must_use]
    pub(crate) fn audit_writer_arc_migration(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::writer::AuditWriter>> {
        Arc::clone(&self.audit_writer)
    }

    /// Submits a single migration step (remove_signer or add_signer) for a smart account.
    ///
    /// Wraps `submit_signed_invoke` for the migration submit path.
    /// Called by [`crate::managers::migration::MigrationPlan::submit`] for each
    /// `HostFunction` in a `SignerMigrationStep`.
    ///
    /// `entrypoint` MUST be one of `"remove_signer"` or `"add_signer"`.
    ///
    /// # Errors
    ///
    /// - [`SaError::VerifierMigrationFailed`] with `phase: "submit_simulate"` — simulation
    ///   of the migration `HostFunction` failed.
    /// - [`SaError::VerifierMigrationFailed`] with `phase: "submit_send"` — `sendTransaction`
    ///   failed after simulation succeeded.
    /// - [`SaError::AuthEntryConstructionFailed`] — signer public-key fetch or auth-entry
    ///   construction failed.
    ///
    /// # Implements
    ///
    /// Verifier diversification: each migration step submits a single
    /// `HostFunction` (`remove_signer` or `add_signer`) that atomically
    /// replaces one verifier contract in the signer set.
    #[allow(clippy::too_many_arguments, reason = "irreducible migration-step args")]
    pub(crate) async fn submit_migration_step(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        entrypoint: &'static str,
        invoke_args: Vec<ScVal>,
        signer: &(dyn Signer + Send + Sync),
        source_pubkey_strkey: &str,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<crate::submit::SubmitInvokeResult, SaError> {
        use crate::error::MIGRATION_PHASES;

        #[cfg(feature = "test-helpers")]
        if let Some(result) =
            mock_migration_submit_result(rule_id, entrypoint, smart_account_redacted, request_id)
        {
            return result;
        }

        let auth_rule_ids = vec![ContextRuleId::from(rule_id)];

        self.submit_signed_invoke(
            smart_account.clone(),
            &smart_account,
            entrypoint,
            invoke_args,
            &auth_rule_ids,
            signer,
            source_pubkey_strkey,
            entrypoint,
            // Migration steps operate on an existing rule_id but are part of
            // the verifier-diversification path, not the session-key expiry
            // path. The expiry check is not wired here: migration must be
            // allowed even if the rule is near-expired (the operator is
            // replacing the verifier, not adding a new session credential).
            None,
        )
        .await
        .map_err(|e| {
            // Classify the error phase: simulate vs send.
            // `submit_signed_invoke` uses `SaError::DeploymentFailed` internally
            // for both phases.  We re-map to `VerifierMigrationFailed` with the
            // correct phase label so the caller can triage by phase.
            let phase = match &e {
                SaError::DeploymentFailed { phase, .. } if *phase == "simulate" => {
                    MIGRATION_PHASES[3] // "submit_simulate"
                }
                _ => MIGRATION_PHASES[4], // "submit_send"
            };
            SaError::VerifierMigrationFailed {
                phase,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                detail: format!("{entrypoint} migration step failed: {e}"),
                request_id: request_id.to_owned(),
            }
        })
    }

    /// Returns the verifier and policy `ScAddress`es registered in the on-chain
    /// context rule for `(smart_account, rule_id)`.
    ///
    /// Used by `managers::credentials::sign_with_passkey_rule_inner`
    /// to obtain the live contract addresses for drift-detection re-fetch without
    /// requiring the caller to know the verifier addresses up front.
    ///
    /// Performs a single read-only `get_context_rule` simulation against the
    /// primary RPC.  Returns:
    ///
    /// - First element: unique verifier `ScAddress`es from `External` signers.
    /// - Second element: `ScAddress`es from the rule's policies list.
    ///
    /// Duplicate verifier addresses are deduplicated (same verifier, multiple
    /// External signers — common in OZ multisig-webauthn-verifier rules).
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] — simulation or decode error.
    /// - [`SaError::AuthEntryConstructionFailed`] — strkey parse error.
    ///
    /// # Implements
    ///
    /// Verifier-pinning: returns the live on-chain verifier and policy addresses
    /// so callers can detect drift without knowing the addresses up front.
    pub(crate) async fn fetch_verifier_and_policy_addresses(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
    ) -> Result<(Vec<ScAddress>, Vec<ScAddress>), SaError> {
        let rule = self
            .fetch_context_rule_primary(smart_account, rule_id, source_account_strkey)
            .await?;

        // Extract unique verifier addresses from External signers.
        let mut verifier_addrs: Vec<ScAddress> = Vec::new();
        let mut seen_verifiers: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for (_sid, pk) in &rule.signers {
            if let SignerPubkey::External {
                verifier_contract, ..
            } = pk
                && seen_verifiers.insert(verifier_contract.clone())
            {
                let addr =
                    crate::managers::rules::parse_c_strkey_to_smart_account(verifier_contract)
                        .map_err(|e| SaError::AuthEntryConstructionFailed {
                            stage: "strkey_parse",
                            redacted_reason: format!(
                                "External signer verifier_contract is not a valid C-strkey \
                                 (rule_id={rule_id}): {e}"
                            ),
                        })?;
                verifier_addrs.push(addr);
            }
        }

        Ok((verifier_addrs, rule.policies))
    }

    // ── list_signers ──────────────────────────────────────────────────────────

    /// Lists the current signer set for a context rule.
    ///
    /// Fetches the signer set from the primary RPC (view call, no auth), then
    /// emits a `SaSignerSetBaselined` audit row if and only if no prior
    /// baseline / state-change row exists for this `(rule_id, smart_account)`.
    ///
    /// This is the human-path bootstrap: calling `smart-account signers list` for the
    /// first time establishes the audit-log baseline so subsequent signing
    /// attempts can use it.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to query.
    /// - `source_account_strkey` — `Some(G...)` for a real fee-paying account
    ///   or `None` for read-only simulate fallback.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] (phase `"simulate"`) — on-chain view call failed.
    /// - [`SaError::AuditLog`] — audit-log integrity violation on baseline read.
    /// - [`SaError::AuthEntryConstructionFailed`] — RPC or XDR construction failure.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: ensures baseline is written before any
    /// signer mutation can be issued against a rule, so the audit trail always
    /// has a starting point for divergence detection.
    #[allow(
        clippy::expect_used,
        reason = "std::sync::Mutex poison is unrecoverable here"
    )]
    pub async fn list_signers(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<ObservedSignerSet, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // Per-rule mutex acquire — prevents race between read-side baseline
        // write and concurrent mutating ops.
        let mutex = rule_mutex_acquire(&self.audit_log_path, rule_id, &smart_account_strkey);
        let _guard = mutex.lock().await;

        // Identify threshold policy via wasm-hash allowlist (fail-closed).
        // Must precede the two-RPC signer-set fetch so fetch_signer_set_* receive a
        // validated policy address (not an unvalidated policies.first() pick).
        let policy_addr = self
            .identify_threshold_policy(
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                request_id.clone(),
            )
            .await?;

        // Two-RPC consultation — baseline writes must agree across RPCs.
        let (primary_result, secondary_result) = tokio::join!(
            self.fetch_signer_set(
                &self.primary_rpc_client,
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                &policy_addr,
                &request_id,
            ),
            self.fetch_signer_set(
                &self.secondary_rpc_client,
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                &policy_addr,
                &request_id,
            ),
        );
        let primary_observed = primary_result?;
        let secondary_observed = secondary_result?;

        let primary_digest = compute_signer_set_digest(&primary_observed)?;
        let secondary_digest = compute_signer_set_digest(&secondary_observed)?;

        if primary_digest != secondary_digest {
            let primary_first8 = primary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let secondary_first8 = secondary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            return Err(SaError::NetworkRpcDivergence {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                primary_view_digest_first8: primary_first8,
                secondary_view_digest_first8: secondary_first8,
                request_id: request_id.clone(),
            });
        }

        let observed = primary_observed;

        // Check whether a prior baseline exists. If not, emit SaSignerSetBaselined.
        // AuditLogIntegrityError must propagate — never silently reinterpreted as Ok(None).
        let prior = self.read_audit_log_baseline(rule_id, &smart_account_redacted)?;

        if prior.is_none() {
            // First observation: emit SaSignerSetBaselined.
            self.emit_baseline(
                &observed,
                rule_id,
                &smart_account_redacted,
                BaselineReason::first_observation(),
                &request_id,
            );
        }

        info!(
            profile = %self.profile_name,
            rule_id,
            smart_account = %smart_account_redacted,
            signer_count = observed.signer_count,
            threshold = observed.threshold,
            "list_signers: on-chain signer set"
        );

        Ok(observed)
    }

    // ── refresh_signer_baseline ───────────────────────────────────────────────

    /// Fetches the on-chain signer set and unconditionally writes a new
    /// `SaSignerSetBaselined` audit row.
    ///
    /// This is the programmatic baseline-write primitive.  Call this after an
    /// intentional out-of-band signer change to re-anchor the wallet's
    /// divergence-detection view.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to baseline.
    /// - `source_account_strkey` — G-strkey of the fee-paying account.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] (phase `"simulate"`) — view call failed.
    /// - [`SaError::AuthEntryConstructionFailed`] — RPC or XDR construction failure.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: ensures baseline is re-established
    /// after an out-of-band signer change so divergence detection remains
    /// accurate.
    #[allow(
        clippy::expect_used,
        reason = "std::sync::Mutex poison is unrecoverable here"
    )]
    pub async fn refresh_signer_baseline(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<ObservedSignerSet, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // Per-rule mutex acquire.
        let mutex = rule_mutex_acquire(&self.audit_log_path, rule_id, &smart_account_strkey);
        let _guard = mutex.lock().await;

        // Identify threshold policy via wasm-hash allowlist (fail-closed).
        let policy_addr = self
            .identify_threshold_policy(
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                request_id.clone(),
            )
            .await?;

        // Two-RPC consultation — baseline writes must agree across RPCs.
        let (primary_result, secondary_result) = tokio::join!(
            self.fetch_signer_set(
                &self.primary_rpc_client,
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                &policy_addr,
                &request_id,
            ),
            self.fetch_signer_set(
                &self.secondary_rpc_client,
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                &policy_addr,
                &request_id,
            ),
        );
        let primary_observed = primary_result?;
        let secondary_observed = secondary_result?;

        let primary_digest = compute_signer_set_digest(&primary_observed)?;
        let secondary_digest = compute_signer_set_digest(&secondary_observed)?;

        if primary_digest != secondary_digest {
            let primary_first8 = primary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let secondary_first8 = secondary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            return Err(SaError::NetworkRpcDivergence {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                primary_view_digest_first8: primary_first8,
                secondary_view_digest_first8: secondary_first8,
                request_id: request_id.clone(),
            });
        }

        let observed = primary_observed;

        // Always emit SaSignerSetBaselined on explicit refresh.
        self.emit_baseline(
            &observed,
            rule_id,
            &smart_account_redacted,
            BaselineReason::explicit_refresh(),
            &request_id,
        );

        info!(
            profile = %self.profile_name,
            rule_id,
            smart_account = %smart_account_redacted,
            signer_count = observed.signer_count,
            threshold = observed.threshold,
            "refresh_signer_baseline: baseline written"
        );

        Ok(observed)
    }

    // ── verify_signer_set_against_chain ───────────────────────────────────────

    /// Checks the on-chain signer set against the audit-log baseline.
    ///
    /// Executes in three ordered steps:
    ///
    /// 1. **Audit-log read** — loads the most-recent signer-set state row.
    ///    Returns [`SaError::SignerSetMissingBaseline`] if no baseline exists
    ///    (before any RPC call), or [`SaError::AuditLog`] on integrity failure.
    /// 2. **Two-RPC consultation** — fetches `(signer_count, threshold)` from
    ///    primary + secondary RPC in parallel.  Returns
    ///    [`SaError::NetworkRpcDivergence`] if they disagree.
    /// 3. **Audit-vs-chain comparison** — compares the audit-log-derived
    ///    expected view against the agreed on-chain state.  Returns
    ///    [`SaError::SignerSetDiverged`] (and emits `SaSignerSetDiverged` audit
    ///    row) if they disagree.
    ///
    /// On success, returns a move-only [`FrozenChainStateTuple`].
    ///
    /// **TOCTOU semantics.** The `FrozenChainStateTuple` is a data-only
    /// tamper-evidence anchor — it captures the audit-log expectation hash at
    /// the moment of the divergence check.  It does NOT retain the per-rule
    /// mutex beyond this call's scope.  The cross-call TOCTOU window is closed
    /// by two independent mechanisms:
    ///
    /// 1. **Per-rule mutex at the next acquire site** — any concurrent
    ///    `add_signer` / `remove_signer` / `set_threshold` call on the same
    ///    `(rule_id, smart_account)` pair serialises behind the same mutex
    ///    registry and cannot interleave between the divergence check and the
    ///    subsequent signing call.
    /// 2. **Re-simulate at submit time** — `submit_signed_invoke`
    ///    re-simulates the transaction before submitting; if the on-chain state
    ///    has changed since the divergence check, the re-simulation diverges
    ///    and the submission is refused.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to verify.
    /// - `source_account_strkey` — `Some(G...)` for a real fee-paying account,
    ///   or `None` when no fee-payer is available (e.g. read-only divergence
    ///   checks called from `sign_with_passkey_rule_inner`).  When `None`, the
    ///   underlying `simulate_read_only` calls use [`SIMULATE_SENTINEL_G`] with
    ///   sequence number `"0"`.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::SignerSetMissingBaseline`] — no baseline row in audit log.
    /// - [`SaError::AuditLog`] — audit-log integrity violation.
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree.
    /// - [`SaError::SignerSetDiverged`] — on-chain state differs from baseline.
    /// - [`SaError::DeploymentFailed`] / [`SaError::AuthEntryConstructionFailed`]
    ///   — RPC errors during signer-set fetch.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: divergence detection is a precondition
    /// for any signer-set mutation, ensuring every change is anchored against
    /// a verified on-chain state.
    pub async fn verify_signer_set_against_chain(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<FrozenChainStateTuple, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // Per-rule mutex acquire — prevents TOCTOU between audit-log read and
        // on-chain comparison when a concurrent mutating op is in flight.
        let mutex = rule_mutex_acquire(&self.audit_log_path, rule_id, &smart_account_strkey);
        let _guard = mutex.lock().await;

        // Step 1: audit-log read (before any RPC call).
        let baseline = self.read_audit_log_baseline(rule_id, &smart_account_redacted)?;

        let state_payload = baseline.ok_or_else(|| SaError::SignerSetMissingBaseline {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted(
                smart_account_redacted.clone(),
            ),
            request_id: request_id.clone(),
        })?;

        let expected = state_payload.state().clone();
        let row_hash = *state_payload.row_hash();

        // Step 2a: identify threshold policy (fail-closed).
        let policy_addr = self
            .identify_threshold_policy(
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                request_id.clone(),
            )
            .await?;

        // Step 2b: two-RPC consultation in parallel.
        let (primary_result, secondary_result) = tokio::join!(
            self.fetch_signer_set(
                &self.primary_rpc_client,
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                &policy_addr,
                &request_id,
            ),
            self.fetch_signer_set(
                &self.secondary_rpc_client,
                smart_account.clone(),
                rule_id,
                source_account_strkey,
                &policy_addr,
                &request_id,
            ),
        );

        let primary_observed = primary_result?;
        let secondary_observed = secondary_result?;

        // Compute digests for both RPC views and check agreement.
        let primary_digest = compute_signer_set_digest(&primary_observed)?;
        let secondary_digest = compute_signer_set_digest(&secondary_observed)?;

        if primary_digest != secondary_digest {
            let primary_first8 = primary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let secondary_first8 = secondary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            return Err(SaError::NetworkRpcDivergence {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                primary_view_digest_first8: primary_first8,
                secondary_view_digest_first8: secondary_first8,
                request_id: request_id.clone(),
            });
        }

        // Both RPCs agreed; use the primary observation as the authoritative view.
        let observed = primary_observed;

        // Step 3: audit-log expected vs on-chain comparison.
        let expected_digest = compute_signer_set_digest(&expected)?;
        let observed_digest = compute_signer_set_digest(&observed)?;

        if expected_digest != observed_digest {
            // Divergence detected — emit SaSignerSetDiverged audit row.
            self.emit_signer_set_diverged(
                rule_id,
                &smart_account_redacted,
                &expected,
                &observed,
                &request_id,
            );

            return Err(SaError::SignerSetDiverged {
                rule_id,
                expected,
                observed,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                request_id: request_id.clone(),
            });
        }

        // Use the ledger sequence from the primary simulation (not available
        // from the view-call result directly; use timestamp instead).
        let now_ms = i64::try_from(now_unix_ms().unwrap_or(0)).unwrap_or(i64::MAX);
        let simulation_ledger = (0u32, now_ms);

        debug!(
            profile = %self.profile_name,
            rule_id,
            smart_account = %smart_account_redacted,
            signer_count = observed.signer_count,
            threshold = observed.threshold,
            "verify_signer_set_against_chain: on-chain matches baseline"
        );

        Ok(FrozenChainStateTuple::new(
            observed,
            simulation_ledger,
            row_hash,
            rule_id,
        ))
    }

    // ── add_signer ────────────────────────────────────────────────────────────

    /// Adds a signer to a context rule.
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Checks `signer_count' <= MAX_SIGNERS`.
    /// 2. Validates the threshold invariant; refuses with
    ///    [`SaError::ThresholdUnreachable`] if the add would create an
    ///    unreachable threshold state.
    /// 3. Constructs and submits a single `InvokeHostFunctionOp` transaction.
    /// 4. Emits `SaSignerAdded` audit row.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to update.
    /// - `new_signer` — the signer to add (encoded as an OZ `Signer` ScVal).
    /// - `new_signer_pubkey` — pubkey envelope for the audit-log row.
    /// - `signer` — the ed25519 signer for auth-entry signing + fee envelope.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::ContextRuleCapsExceeded`] — signer count would exceed `MAX_SIGNERS`.
    /// - [`SaError::ThresholdUnreachable`] — threshold invariant violated.
    /// - [`SaError::SignerSetMissingBaseline`] — no audit-log baseline.
    /// - [`SaError::AuditLog`] — audit-log integrity violation.
    /// - [`SaError::NetworkRpcDivergence`] — two-RPC disagreement.
    /// - [`SaError::SignerSetDiverged`] — on-chain state diverged from baseline.
    /// - [`SaError::DeploymentFailed`] — submission or on-chain rejection.
    /// - [`SaError::AuthEntryConstructionFailed`] — XDR or RPC construction failure.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: the signer is added in a single
    /// `InvokeHostFunctionOp` transaction; the threshold invariant is checked
    /// before submission to prevent unreachable configurations.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible signer + auth + audit arg set"
    )]
    pub async fn add_signer(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        new_signer: ScVal,
        new_signer_pubkey: SignerPubkey,
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
    ) -> Result<u32, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // Per-rule mutex acquire (non-reentrant; authorised acquire site).
        let mutex = rule_mutex_acquire(&self.audit_log_path, rule_id, &smart_account_strkey);
        let _guard = mutex.lock().await;

        let outcome = self
            .add_signer_locked_inner(
                smart_account.clone(),
                rule_id,
                &smart_account_redacted,
                new_signer,
                new_signer_pubkey.clone(),
                signer,
                &request_id,
            )
            .await;

        match &outcome {
            Ok((signer_id, resulting)) => {
                let pubkeys_first8 = pubkeys_first8(&resulting.signer_pubkeys);
                match self.audit_writer.lock() {
                    Ok(mut writer) => {
                        let entry = AuditEntry::new_sa_signer_added(
                            rule_id,
                            *signer_id,
                            resulting,
                            pubkeys_first8,
                            RedactedStrkey::from_already_redacted(smart_account_redacted.clone()),
                            self.chain_id.as_str(),
                            request_id.clone(),
                        );
                        if let Err(e) = writer.write_entry(entry) {
                            warn!(error = %e, "add_signer: SaSignerAdded audit write failed");
                        }
                    }
                    Err(_poison) => {
                        self.mark_audit_writer_degraded();
                        warn!(
                            target: "stellar_agent::audit",
                            rule_id,
                            signer_id = *signer_id,
                            resulting_signer_count = resulting.signer_count,
                            resulting_threshold = resulting.threshold,
                            resulting_signer_ids = ?resulting.signer_ids,
                            resulting_signer_pubkeys_first8 = ?pubkeys_first8,
                            smart_account_redacted = %smart_account_redacted,
                            chain_id = %self.chain_id,
                            request_id = %request_id,
                            "audit-writer mutex poisoned; SaSignerAdded row dropped"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    rule_id,
                    smart_account = %smart_account_redacted,
                    "add_signer: operation failed"
                );
            }
        }

        outcome.map(|(signer_id, _)| signer_id)
    }

    // ── remove_signer ─────────────────────────────────────────────────────────

    /// Removes a signer from a context rule.
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Validates `threshold' >= 1 && signer_count' >= threshold'`.
    ///    Returns [`SaError::ThresholdUnreachable`] with a `safe_ordering_hint`
    ///    if the invariant would be violated.  To lower the threshold first, run
    ///    `smart-account signers set-threshold` and then retry the removal.
    /// 2. Constructs and submits a single `InvokeHostFunctionOp` transaction.
    /// 3. Emits `SaSignerRemoved` audit row.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to update.
    /// - `signer_id` — the on-chain signer ID to remove.
    /// - `signer` — the ed25519 signer for auth-entry signing + fee envelope.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Errors
    ///
    /// See [`Self::add_signer`] for the error taxonomy; same variants apply.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: the signer is removed in a single
    /// `InvokeHostFunctionOp` transaction; the threshold invariant is checked
    /// before submission to prevent unreachable configurations.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible signer + auth + audit arg set"
    )]
    pub async fn remove_signer(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        signer_id: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
    ) -> Result<(), SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // Per-rule mutex acquire.
        let mutex = rule_mutex_acquire(&self.audit_log_path, rule_id, &smart_account_strkey);
        let _guard = mutex.lock().await;

        let outcome = self
            .remove_signer_locked_inner(
                smart_account.clone(),
                rule_id,
                &smart_account_redacted,
                signer_id,
                signer,
                &request_id,
            )
            .await;

        match &outcome {
            Ok(resulting) => {
                let pubkeys_first8 = pubkeys_first8(&resulting.signer_pubkeys);
                match self.audit_writer.lock() {
                    Ok(mut writer) => {
                        let entry = AuditEntry::new_sa_signer_removed(
                            rule_id,
                            signer_id,
                            resulting,
                            pubkeys_first8,
                            RedactedStrkey::from_already_redacted(smart_account_redacted.clone()),
                            self.chain_id.as_str(),
                            request_id.clone(),
                        );
                        if let Err(e) = writer.write_entry(entry) {
                            warn!(error = %e, "remove_signer: SaSignerRemoved audit write failed");
                        }
                    }
                    Err(_poison) => {
                        self.mark_audit_writer_degraded();
                        warn!(
                            target: "stellar_agent::audit",
                            rule_id,
                            signer_id,
                            resulting_signer_count = resulting.signer_count,
                            resulting_threshold = resulting.threshold,
                            resulting_signer_ids = ?resulting.signer_ids,
                            resulting_signer_pubkeys_first8 = ?pubkeys_first8,
                            smart_account_redacted = %smart_account_redacted,
                            chain_id = %self.chain_id,
                            request_id = %request_id,
                            "audit-writer mutex poisoned; SaSignerRemoved row dropped"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    rule_id,
                    smart_account = %smart_account_redacted,
                    "remove_signer: operation failed"
                );
            }
        }

        outcome.map(|_| ())
    }

    // ── set_threshold ─────────────────────────────────────────────────────────

    /// Changes the threshold of a context rule (without a signer-count change).
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Reads the current signer count from the audit-log baseline.
    /// 2. Validates `1 <= new_threshold <= signer_count`.
    /// 3. Identifies the threshold-policy address via wasm-hash lookup.
    /// 4. Constructs and submits a single `InvokeHostFunctionOp` targeting
    ///    the threshold-policy `set_threshold` entrypoint.
    /// 5. Emits `SaThresholdChanged` audit row.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to update.
    /// - `new_threshold` — the desired new threshold.
    /// - `signer` — the ed25519 signer.
    /// - `request_id` — caller-supplied UUID.
    ///
    /// # Errors
    ///
    /// - [`SaError::ThresholdUnreachable`] — new threshold would violate invariants.
    /// - [`SaError::SignerSetMissingBaseline`] — no audit-log baseline.
    /// - [`SaError::ThresholdPolicyNotInstalled`] — empty `policies` list.
    /// - [`SaError::ThresholdPolicyIdentificationFailed`] — wasm-hash mismatch.
    /// - [`SaError::NetworkRpcDivergence`] — two-RPC disagreement on policy hash.
    /// - [`SaError::DeploymentFailed`] — submission or on-chain rejection.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: the threshold change is submitted as a
    /// single `InvokeHostFunctionOp` targeting the threshold-policy contract,
    /// validated against the current signer count before submission.
    pub async fn set_threshold(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        new_threshold: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
    ) -> Result<(), SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // Per-rule mutex acquire.
        let mutex = rule_mutex_acquire(&self.audit_log_path, rule_id, &smart_account_strkey);
        let _guard = mutex.lock().await;

        let outcome = self
            .set_threshold_locked_inner(
                smart_account.clone(),
                rule_id,
                &smart_account_redacted,
                new_threshold,
                signer,
                &request_id,
            )
            .await;

        match &outcome {
            Ok((old_threshold, resulting)) => {
                let pubkeys_first8 = pubkeys_first8(&resulting.signer_pubkeys);
                match self.audit_writer.lock() {
                    Ok(mut writer) => {
                        let entry = AuditEntry::new_sa_threshold_changed(
                            rule_id,
                            *old_threshold,
                            new_threshold,
                            resulting,
                            pubkeys_first8,
                            RedactedStrkey::from_already_redacted(smart_account_redacted.clone()),
                            self.chain_id.as_str(),
                            request_id.clone(),
                        );
                        if let Err(e) = writer.write_entry(entry) {
                            warn!(
                                error = %e,
                                "set_threshold: SaThresholdChanged audit write failed"
                            );
                        }
                    }
                    Err(_poison) => {
                        self.mark_audit_writer_degraded();
                        warn!(
                            target: "stellar_agent::audit",
                            rule_id,
                            old_threshold = *old_threshold,
                            new_threshold,
                            resulting_threshold = resulting.threshold,
                            resulting_signer_count = resulting.signer_count,
                            resulting_signer_ids = ?resulting.signer_ids,
                            resulting_signer_pubkeys_first8 = ?pubkeys_first8,
                            smart_account_redacted = %smart_account_redacted,
                            chain_id = %self.chain_id,
                            request_id = %request_id,
                            "audit-writer mutex poisoned; SaThresholdChanged row dropped"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    rule_id,
                    smart_account = %smart_account_redacted,
                    "set_threshold: operation failed"
                );
            }
        }

        outcome.map(|_| ())
    }

    // ── identify_threshold_policy ─────────────────────────────────────────────

    /// Identifies the threshold-policy contract for a context rule.
    ///
    /// Fetches the wasm-hash of each `Address` in the rule's `policies` list
    /// via batched `getLedgerEntries` on BOTH RPCs in parallel (two-RPC
    /// consultation).  Single-match against `THRESHOLD_POLICY_WASM_HASHES` is
    /// required; zero or multi-match returns a typed error (fail-closed).
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule whose policies are examined.
    /// - `source_account_strkey` — G-strkey of the fee-paying account.
    /// - `request_id` — caller-supplied UUID for error reporting.
    ///
    /// # Errors
    ///
    /// - [`SaError::ThresholdPolicyNotInstalled`] — `policies` list is empty.
    /// - [`SaError::NetworkRpcDivergence`] — primary + secondary disagree on wasm-hash.
    /// - [`SaError::ThresholdPolicyIdentificationFailed`] — zero or multi-match.
    /// - [`SaError::DeploymentFailed`] — RPC `getLedgerEntries` failure.
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the infallible `expect` on a SHA-256 slice
    /// and on the `Option<ScAddress>` guarded by `match_count == 1` are
    /// provably safe. See inline comments.
    ///
    /// # Implements
    ///
    /// Threshold-policy identification: locates the single installed threshold
    /// policy by matching its wasm-hash against the allowlist, ensuring the
    /// correct contract is targeted for threshold mutations.
    #[allow(
        clippy::expect_used,
        reason = "infallible: sha256 is 32 bytes; match_count == 1"
    )]
    pub async fn identify_threshold_policy(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<ScAddress, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // Fetch the on-chain context rule to get the policies list.
        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, source_account_strkey)
            .await?;

        // Policy list empty check (fail-closed).
        if context_rule.policies.is_empty() {
            return Err(SaError::ThresholdPolicyNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                request_id,
            });
        }

        // Build LedgerKey::ContractData(ContractInstance) keys for each policy address.
        // `contract_instance_key` is infallible: no silent skip.
        let policy_keys: Vec<LedgerKey> = context_rule
            .policies
            .iter()
            .map(contract_instance_key)
            .collect();

        if policy_keys.is_empty() {
            return Err(SaError::ThresholdPolicyIdentificationFailed {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                observed_wasm_hashes_summary: WasmHashSummary {
                    count: 0,
                    first_first8: None,
                },
                request_id,
            });
        }

        // Two-RPC parallel wasm-hash fetch.
        let (primary_hashes_result, secondary_hashes_result) = tokio::join!(
            fetch_contract_wasm_hashes(&self.primary_rpc_client, &policy_keys),
            fetch_contract_wasm_hashes(&self.secondary_rpc_client, &policy_keys),
        );

        // Returns Vec<Option<[u8; 32]>> aligned with policy_keys.
        let primary_hashes = primary_hashes_result.map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("primary RPC policy wasm-hash fetch failed: {e}"),
        })?;
        let secondary_hashes = secondary_hashes_result.map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("secondary RPC policy wasm-hash fetch failed: {e}"),
        })?;

        // Two-RPC agreement check.
        if primary_hashes.len() != secondary_hashes.len() || primary_hashes != secondary_hashes {
            let primary_digest: [u8; 32] = Sha256::digest(
                primary_hashes
                    .iter()
                    .flat_map(|h| h.iter().flat_map(|b| b.iter()).copied())
                    .collect::<Vec<u8>>(),
            )
            .into();
            let secondary_digest: [u8; 32] = Sha256::digest(
                secondary_hashes
                    .iter()
                    .flat_map(|h| h.iter().flat_map(|b| b.iter()).copied())
                    .collect::<Vec<u8>>(),
            )
            .into();
            let primary_first8 = primary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            let secondary_first8 = secondary_digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            return Err(SaError::NetworkRpcDivergence {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                primary_view_digest_first8: primary_first8,
                secondary_view_digest_first8: secondary_first8,
                request_id,
            });
        }

        // Allowlist match: single-match required, fail-closed.
        // Zip aligned with policy addresses: position i in primary_hashes corresponds
        // to position i in context_rule.policies.
        let mut matched_policy_addr: Option<ScAddress> = None;
        let mut match_count = 0usize;
        let first_first8: Option<[u8; 8]> = primary_hashes
            .iter()
            .find_map(|opt_h| opt_h.as_ref())
            .map(|h| <[u8; 8]>::try_from(&h[..8]).expect("sha256 is 32 bytes"));

        for (opt_hash, policy_addr) in primary_hashes.iter().zip(context_rule.policies.iter()) {
            let Some(hash) = opt_hash else { continue };
            debug!(
                policy_wasm_hash_first8 = %hash[..8].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "identify_threshold_policy: observed policy wasm hash"
            );
            if THRESHOLD_POLICY_WASM_HASHES
                .iter()
                .any(|allowed| allowed == hash)
            {
                match_count += 1;
                matched_policy_addr = Some(policy_addr.clone());
            }
        }

        if match_count != 1 {
            let count = u32::try_from(primary_hashes.len()).unwrap_or(u32::MAX);
            return Err(SaError::ThresholdPolicyIdentificationFailed {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                observed_wasm_hashes_summary: WasmHashSummary {
                    count,
                    first_first8,
                },
                request_id,
            });
        }

        Ok(matched_policy_addr.expect("match_count == 1 guarantees Some"))
    }

    // ── identify_verifier ─────────────────────────────────────────────────────

    /// Identifies a deployed verifier contract by its wasm hash.
    ///
    /// Fetches the wasm-hash of `verifier_addr` via two-RPC parallel
    /// `getLedgerEntries` (`LedgerKey::ContractData { key:
    /// LedgerKeyContractInstance }`) and matches against
    /// [`crate::VERIFIER_ALLOWLIST`].  Exactly one match is required; zero
    /// matches return [`SaError::VerifierWasmNotInAllowlist`] (fail-closed).
    ///
    /// Returns the matched wasm hash on success.  The hash is the data needed
    /// for pinning at rule-install time.
    ///
    /// For drift-detection at signing time where allowlist enforcement is not
    /// desired (comparison is against the pinned value), use
    /// `fetch_observed_wasm_hash` instead.
    ///
    /// Mirrors [`SignersManager::identify_threshold_policy`] but accepts a
    /// direct verifier address instead of fetching a context rule (verifiers
    /// are looked up by address; policies are looked up via the rule's
    /// `policies` list).
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`], used for
    ///   forensic fields in error variants (`smart_account_redacted`).
    /// - `verifier_addr` — the deployed verifier contract's [`ScAddress`].
    /// - `rule_id` — the context rule this verifier is associated with (used for
    ///   error forensics only; no on-chain read against this rule).
    /// - `source_account_strkey` — G-strkey of the fee-paying account (passed
    ///   through but not used for forensic ID).
    /// - `request_id` — caller-supplied UUID for error correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::VerifierWasmNotInAllowlist`] — zero allowlist matches
    ///   (fail-closed; allowlist is the authoritative gate).
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree
    ///   on the contract's wasm hash before the allowlist check runs.
    /// - [`SaError::DeploymentFailed`] (phase `"simulate"`) — `getLedgerEntries`
    ///   RPC failure on primary or secondary.
    ///
    /// # Implements
    ///
    /// Verifier pinning: matches the live on-chain wasm hash against the
    /// allowlist before any rule-install operation, ensuring only approved
    /// verifier contracts can be referenced.
    pub async fn identify_verifier(
        &self,
        smart_account: ScAddress,
        verifier_addr: ScAddress,
        rule_id: u32,
        source_account_strkey: &str,
        request_id: String,
    ) -> Result<[u8; 32], SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
        // source_account_strkey is accepted for API symmetry with identify_threshold_policy
        // but not used directly — smart_account_redacted populates forensic fields.
        let _ = source_account_strkey;

        // Fetch the observed wasm hash via two-RPC consultation. Allowlist
        // enforcement is done below against VERIFIER_ALLOWLIST[i].wasm_hash,
        // not at the fetch layer.
        let observed_hash = fetch_observed_wasm_hash(
            &self.primary_rpc_client,
            &self.secondary_rpc_client,
            &verifier_addr,
            rule_id,
            &smart_account_redacted,
            &request_id,
        )
        .await?;

        let Some(hash) = observed_hash else {
            return Err(SaError::VerifierWasmNotInAllowlist {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                observed_hash_first8: "none".to_owned(),
                request_id,
            });
        };

        let observed_hash_first8 = hash[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        debug!(
            wasm_hash_first8 = %observed_hash_first8,
            "identify_verifier: observed verifier wasm hash"
        );

        // Allowlist check against VERIFIER_ALLOWLIST.
        if !crate::VERIFIER_ALLOWLIST
            .iter()
            .any(|entry| entry.wasm_hash == hash)
        {
            return Err(SaError::VerifierWasmNotInAllowlist {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                observed_hash_first8,
                request_id,
            });
        }

        Ok(hash)
    }

    /// Identifies a deployed contract by two-RPC wasm-hash lookup and allowlist match.
    ///
    /// The helper centralises the common verifier/policy shape: fetch a single
    /// contract instance's wasm hash from primary and secondary RPCs, fail on
    /// RPC disagreement, then require the observed hash to appear in `allowlist`.
    ///
    /// # Errors
    ///
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree.
    /// - [`SaError::DeploymentFailed`] — RPC fetch failed.
    /// - The caller-provided `not_in_allowlist_err` when the contract is absent
    ///   or its hash is not in `allowlist`.
    pub(crate) async fn identify_contract_wasm_hash(
        &self,
        contract_addr: &ScAddress,
        allowlist: &'static [[u8; 32]],
        rule_id: u32,
        smart_account_redacted: &str,
        request_id: &str,
        not_in_allowlist_err: impl FnOnce(NotInAllowlistContext) -> SaError,
    ) -> Result<[u8; 32], SaError> {
        let observed_hash = fetch_observed_wasm_hash(
            &self.primary_rpc_client,
            &self.secondary_rpc_client,
            contract_addr,
            rule_id,
            smart_account_redacted,
            request_id,
        )
        .await?;

        let Some(hash) = observed_hash else {
            return Err(not_in_allowlist_err(NotInAllowlistContext {
                rule_id,
                smart_account_redacted: smart_account_redacted.to_owned(),
                observed_hash_first8: "none".to_owned(),
                request_id: request_id.to_owned(),
            }));
        };

        let contract_redacted = scaddress_to_strkey(contract_addr)
            .map(|s| redact_strkey_first5_last5(&s))
            .unwrap_or_else(|_| "unknown".to_owned());
        let observed_hash_first8 = hash[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        debug!(
            contract = %contract_redacted,
            wasm_hash_first8 = %observed_hash_first8,
            "identify_contract_wasm_hash: observed contract wasm hash"
        );

        if !allowlist.iter().any(|allowed| allowed == &hash) {
            return Err(not_in_allowlist_err(NotInAllowlistContext {
                rule_id,
                smart_account_redacted: smart_account_redacted.to_owned(),
                observed_hash_first8,
                request_id: request_id.to_owned(),
            }));
        }

        Ok(hash)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Reads the audit-log baseline for `(rule_id, smart_account_redacted)`.
    ///
    /// `AuditLogIntegrityError` MUST propagate — never silently reinterpreted as
    /// `Ok(None)`.  This function is a thin wrapper that enforces this contract
    /// via the return type.
    fn read_audit_log_baseline(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
    ) -> Result<
        Option<stellar_agent_core::audit_log::signer_set::SignerSetStatePayload>,
        AuditLogIntegrityError,
    > {
        let reader = stellar_agent_core::audit_log::reader::AuditReader::new(
            Arc::clone(&self.audit_writer),
            None,
        );
        reader.find_latest_signer_set_state(rule_id, smart_account_redacted)
    }

    /// Emits a `SaSignerSetBaselined` audit row.
    ///
    /// Called exclusively from `list_signers` (first-observation) and
    /// `refresh_signer_baseline` (always).  A CI gate enforces this
    /// single-caller invariant.
    ///
    /// `prev_chain_tip_hash` is sourced from `AuditWriter::current_chain_tip()`
    /// inside the write critical section, ensuring the tip hash captured is
    /// consistent with the write being committed.
    ///
    fn emit_baseline(
        &self,
        observed: &ObservedSignerSet,
        rule_id: u32,
        smart_account_redacted: &str,
        baseline_reason: BaselineReason,
        request_id: &str,
    ) {
        let pubkeys_first8 = pubkeys_first8(&observed.signer_pubkeys);
        let now_ms = now_unix_ms().unwrap_or(0);

        match self.audit_writer.lock() {
            Ok(mut writer) => {
                // prev_chain_tip_hash MUST be sourced inside the write critical
                // section so it is consistent with the write being committed.
                let prev_chain_tip_hash = writer.current_chain_tip();

                let entry = AuditEntry::new_sa_signer_set_baselined(
                    rule_id,
                    observed,
                    pubkeys_first8,
                    now_ms,
                    baseline_reason,
                    prev_chain_tip_hash,
                    RedactedStrkey::from_already_redacted(smart_account_redacted),
                    self.chain_id.as_str(),
                    request_id,
                );

                if let Err(e) = writer.write_entry(entry) {
                    warn!(error = %e, rule_id, "emit_baseline: SaSignerSetBaselined audit write failed");
                }
            }
            Err(_poison) => {
                self.mark_audit_writer_degraded();
                warn!(
                    target: "stellar_agent::audit",
                    rule_id,
                    observed_signer_count = observed.signer_count,
                    observed_threshold = observed.threshold,
                    observed_signer_ids = ?observed.signer_ids,
                    observed_signer_pubkeys_first8 = ?pubkeys_first8,
                    observed_at_unix_ms = now_ms,
                    baseline_reason = ?baseline_reason,
                    prev_chain_tip_hash = "[unavailable-poisoned]",
                    smart_account_redacted = %smart_account_redacted,
                    chain_id = %self.chain_id,
                    request_id = %request_id,
                    "audit-writer mutex poisoned; SaSignerSetBaselined row dropped"
                );
            }
        }
    }

    /// Emits a `SaSignerSetDiverged` audit row.
    ///
    fn emit_signer_set_diverged(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        expected: &ObservedSignerSet,
        observed: &ObservedSignerSet,
        request_id: &str,
    ) {
        let expected_digest = compute_signer_set_digest(expected)
            .map(|d| format_digest_first8_last8(&d))
            .unwrap_or_else(|_| "compute_error".to_owned());
        let observed_digest = compute_signer_set_digest(observed)
            .map(|d| format_digest_first8_last8(&d))
            .unwrap_or_else(|_| "compute_error".to_owned());

        match self.audit_writer.lock() {
            Ok(mut writer) => {
                let entry = AuditEntry::new_sa_signer_set_diverged(
                    rule_id,
                    RedactedStrkey::from_already_redacted(smart_account_redacted),
                    expected.signer_count,
                    observed.signer_count,
                    expected.threshold,
                    observed.threshold,
                    expected_digest.as_str(),
                    observed_digest.as_str(),
                    self.chain_id.as_str(),
                    request_id,
                );
                if let Err(e) = writer.write_entry(entry) {
                    warn!(error = %e, rule_id, "emit_signer_set_diverged: SaSignerSetDiverged audit write failed");
                }
            }
            Err(_poison) => {
                self.mark_audit_writer_degraded();
                warn!(
                    target: "stellar_agent::audit",
                    rule_id,
                    smart_account_redacted = %smart_account_redacted,
                    expected_signer_count = expected.signer_count,
                    observed_signer_count = observed.signer_count,
                    expected_threshold = expected.threshold,
                    observed_threshold = observed.threshold,
                    expected_signer_set_digest = %expected_digest,
                    observed_signer_set_digest = %observed_digest,
                    chain_id = %self.chain_id,
                    request_id = %request_id,
                    "audit-writer mutex poisoned; SaSignerSetDiverged row dropped"
                );
            }
        }
    }

    /// Fetches the on-chain `ContextRule` via the primary RPC (simulate read-only).
    async fn fetch_context_rule_primary(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
    ) -> Result<OnChainContextRule, SaError> {
        self.fetch_context_rule(
            &self.primary_rpc_client,
            smart_account,
            rule_id,
            source_account_strkey,
        )
        .await
    }

    async fn fetch_context_rule(
        &self,
        rpc_client: &StellarRpcClient,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
    ) -> Result<OnChainContextRule, SaError> {
        let rule_id_val = ScVal::U32(rule_id);
        let scval = simulate_read_only(
            rpc_client.url(),
            smart_account,
            "get_context_rule",
            vec![rule_id_val],
            source_account_strkey,
            &self.network_passphrase,
            self.timeout,
        )
        .await?;
        decode_context_rule_scval(scval)
    }

    /// Fetches the real threshold for `(rule_id, smart_account)` from the threshold
    /// policy contract through the supplied RPC client.
    ///
    /// Calls `policy.get_threshold(rule_id, smart_account)` via read-only simulation.
    ///
    /// The threshold policy exposes
    /// `get_threshold(e, context_rule_id: u32, smart_account: Address) -> u32`
    /// per the OpenZeppelin stellar-accounts v0.7.1 contract.
    async fn fetch_threshold(
        &self,
        rpc_client: &StellarRpcClient,
        policy_addr: &ScAddress,
        smart_account: &ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
    ) -> Result<u32, SaError> {
        let get_threshold_args = vec![ScVal::U32(rule_id), ScVal::Address(smart_account.clone())];
        let result = simulate_read_only(
            rpc_client.url(),
            policy_addr.clone(),
            "get_threshold",
            get_threshold_args,
            source_account_strkey,
            &self.network_passphrase,
            self.timeout,
        )
        .await?;
        match result {
            ScVal::U32(t) => Ok(t),
            other => Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "get_threshold ({}): expected ScVal::U32, got {other:?}",
                    self.rpc_source_kind(rpc_client)
                ),
            }),
        }
    }

    /// Fetches the on-chain signer set for a rule via the supplied RPC client.
    ///
    /// `policy_addr` MUST be the result of a prior `identify_threshold_policy` call —
    /// it is the wasm-hash-allowlist-matched threshold-policy contract address.
    /// Callers are responsible for calling `identify_threshold_policy` first and
    /// passing the result here (fail-closed: no silent `signers.len()` proxy).
    ///
    /// Calls `get_context_rule` to obtain the signer list, then calls
    /// `get_threshold(rule_id, smart_account)` on `policy_addr` to populate
    /// `ObservedSignerSet.threshold` from actual on-chain storage.
    ///
    /// Returns `SaError::ThresholdReadFailed` if the `get_threshold` call fails
    /// or returns an unexpected `ScVal` type.
    async fn fetch_signer_set(
        &self,
        rpc_client: &StellarRpcClient,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        policy_addr: &ScAddress,
        request_id: &str,
    ) -> Result<ObservedSignerSet, SaError> {
        let smart_account_redacted = scaddress_to_strkey(&smart_account)
            .map(|s| redact_strkey_first5_last5(&s))
            .unwrap_or_else(|_| "<redact-err>".to_owned());

        let source_kind = self.rpc_source_kind(rpc_client);
        let mut rule = self
            .fetch_context_rule(
                rpc_client,
                smart_account.clone(),
                rule_id,
                source_account_strkey,
            )
            .await?;

        rule.threshold = self
            .fetch_threshold(
                rpc_client,
                policy_addr,
                &smart_account,
                rule_id,
                source_account_strkey,
            )
            .await
            .map_err(|e| {
                debug!(
                    rule_id,
                    error = %e,
                    source_kind,
                    "fetch_signer_set: get_threshold failed (fail-closed)"
                );
                SaError::ThresholdReadFailed {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted.clone(),
                    ),
                    source_kind,
                    request_id: request_id.to_owned(),
                }
            })?;

        Ok(rule.into_observed_signer_set())
    }

    fn rpc_source_kind(&self, rpc_client: &StellarRpcClient) -> &'static str {
        if std::ptr::eq(rpc_client, &self.primary_rpc_client) {
            "primary"
        } else if std::ptr::eq(rpc_client, &self.secondary_rpc_client) {
            "secondary"
        } else {
            "rpc"
        }
    }

    /// Core logic for `add_signer` (called inside the per-rule mutex).
    ///
    /// Returns `(assigned_signer_id, resulting_ObservedSignerSet)`.
    #[allow(clippy::too_many_arguments, reason = "irreducible inner arg set")]
    async fn add_signer_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        new_signer: ScVal,
        new_signer_pubkey: SignerPubkey,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(u32, ObservedSignerSet), SaError> {
        let source_pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!("signer public_key fetch failed: {e}"),
                })?;
        let source_pubkey_strkey = stellar_strkey::ed25519::PublicKey(source_pubkey.0).to_string();

        // Read baseline signer set for pre-flight invariant check.
        let baseline = self
            .read_audit_log_baseline(rule_id, smart_account_redacted)?
            .ok_or_else(|| SaError::SignerSetMissingBaseline {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id: request_id.to_owned(),
            })?;

        let current_signer_count = baseline.state().signer_count;
        let current_threshold = baseline.state().threshold;
        let post_op_signer_count = current_signer_count.saturating_add(1);

        // Cap check (MAX_SIGNERS = 15 per OZ `mod.rs:526`).
        if post_op_signer_count > MAX_SIGNERS {
            return Err(SaError::ContextRuleCapsExceeded {
                kind: "signers",
                cur: current_signer_count,
                max: MAX_SIGNERS,
            });
        }

        // Threshold invariant check: adding a signer is always safe (count goes
        // up) unless the threshold is somehow > signer_count already (which
        // would be a corrupted on-chain state).  Check for the degenerate case.
        compute_post_op_invariant(
            rule_id,
            post_op_signer_count,
            current_threshold,
            current_threshold, // effective threshold unchanged
            ThresholdAffectingOp::AddSigner {
                signer_type: signer_pubkey_type_label(&new_signer_pubkey).to_owned(),
                signer_id: None,
            },
            smart_account_redacted,
            request_id,
        )?;

        // Identify threshold policy (fail-closed).
        // Must be called before the op submission so that the result-fetch
        // receives a validated policy address.
        let policy_addr = self
            .identify_threshold_policy(
                smart_account.clone(),
                rule_id,
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;

        // Single-op: add_signer.
        // `add_signer` calls `e.current_contract_address().require_auth()`;
        // auth entry is credentialed for the smart account (= contract).
        let auth_rule_ids = vec![ContextRuleId::from(rule_id)];
        let add_signer_args = vec![ScVal::U32(rule_id), new_signer.clone()];

        let return_val = self
            .submit_single_op(
                smart_account.clone(),
                &smart_account,
                rule_id,
                "add_signer",
                add_signer_args,
                &auth_rule_ids,
                signer,
                &source_pubkey_strkey,
                // Expiry check at signing-path entry.
                // Refuses with `SaError::RuleExpired` when `valid_until <
                // latest_ledger`.
                Some(ExpiryCheck { rule_id }),
            )
            .await?;

        let assigned_id = extract_u32_return(&return_val, "add_signer")?;
        let resulting = self
            .fetch_signer_set(
                &self.primary_rpc_client,
                smart_account,
                rule_id,
                Some(&source_pubkey_strkey),
                &policy_addr,
                request_id,
            )
            .await?;

        Ok((assigned_id, resulting))
    }

    /// Core logic for `remove_signer` (called inside the per-rule mutex).
    #[allow(clippy::too_many_arguments, reason = "irreducible inner arg set")]
    async fn remove_signer_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        signer_id: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<ObservedSignerSet, SaError> {
        let source_pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!("signer public_key fetch failed: {e}"),
                })?;
        let source_pubkey_strkey = stellar_strkey::ed25519::PublicKey(source_pubkey.0).to_string();

        // Read baseline.
        let baseline = self
            .read_audit_log_baseline(rule_id, smart_account_redacted)?
            .ok_or_else(|| SaError::SignerSetMissingBaseline {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id: request_id.to_owned(),
            })?;

        let current_signer_count = baseline.state().signer_count;
        let current_threshold = baseline.state().threshold;
        let post_op_signer_count = current_signer_count.saturating_sub(1);

        // Threshold invariant check.  current_threshold is unchanged (no bundle);
        // if post_op_signer_count < current_threshold, the op would brick the rule.
        compute_post_op_invariant(
            rule_id,
            post_op_signer_count,
            current_threshold,
            current_threshold, // effective threshold unchanged
            ThresholdAffectingOp::RemoveSigner { signer_id },
            smart_account_redacted,
            request_id,
        )?;

        // Identify threshold policy (fail-closed).
        let policy_addr = self
            .identify_threshold_policy(
                smart_account.clone(),
                rule_id,
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;

        // Single-op: remove_signer.
        // `remove_signer` calls `e.current_contract_address().require_auth()`.
        let auth_rule_ids = vec![ContextRuleId::from(rule_id)];
        let remove_signer_args = vec![ScVal::U32(rule_id), ScVal::U32(signer_id)];

        self.submit_single_op(
            smart_account.clone(),
            &smart_account,
            rule_id,
            "remove_signer",
            remove_signer_args,
            &auth_rule_ids,
            signer,
            &source_pubkey_strkey,
            // Expiry check at signing-path entry.
            Some(ExpiryCheck { rule_id }),
        )
        .await?;

        let resulting = self
            .fetch_signer_set(
                &self.primary_rpc_client,
                smart_account,
                rule_id,
                Some(&source_pubkey_strkey),
                &policy_addr,
                request_id,
            )
            .await?;
        Ok(resulting)
    }

    /// Core logic for `set_threshold` (called inside the per-rule mutex).
    async fn set_threshold_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        new_threshold: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(u32, ObservedSignerSet), SaError> {
        let source_pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!("signer public_key fetch failed: {e}"),
                })?;
        let source_pubkey_strkey = stellar_strkey::ed25519::PublicKey(source_pubkey.0).to_string();

        // Read baseline for old_threshold.
        let baseline = self
            .read_audit_log_baseline(rule_id, smart_account_redacted)?
            .ok_or_else(|| SaError::SignerSetMissingBaseline {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id: request_id.to_owned(),
            })?;

        let current_signer_count = baseline.state().signer_count;
        let old_threshold = baseline.state().threshold;

        // Threshold invariant: 1 <= new_threshold <= signer_count.
        compute_post_op_invariant(
            rule_id,
            current_signer_count,
            old_threshold,
            new_threshold,
            ThresholdAffectingOp::SetThreshold { new: new_threshold },
            smart_account_redacted,
            request_id,
        )?;

        // Identify threshold policy.
        let policy_addr = self
            .identify_threshold_policy(
                smart_account.clone(),
                rule_id,
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;

        // Fetch context rule for set_threshold args.
        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, Some(&source_pubkey_strkey))
            .await?;

        // Route `set_threshold` through the smart account's `execute()` entrypoint
        // to avoid Soroban re-entry.  Direct call: `set_threshold(policy)` →
        // `smart_account.__check_auth` → `policy.enforce` →
        // `smart_account.require_auth()` → re-entry (forbidden).
        // Via execute: `execute(smart_account, policy, "set_threshold", ...)` →
        // top-level `execute` auth satisfies the inner `require_auth` — no re-entry.
        //
        // The OpenZeppelin smart-account contract exposes
        // `execute(target, target_fn, target_args)`, and the threshold policy
        // exposes `set_threshold(threshold, context_rule, smart_account)`.
        let set_threshold_sym = ScSymbol::try_from("set_threshold").map_err(|e| {
            SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("encode set_threshold symbol: {e:?}"),
            }
        })?;
        let context_rule_scval = context_rule.as_scval()?;
        // `target_args` = [threshold: u32, context_rule: ContextRule, smart_account: Address]
        // (Env is implicit in Soroban contractimpl; not encoded in the Vec<Val>).
        let target_args_vec: VecM<ScVal> = vec![
            ScVal::U32(new_threshold),
            context_rule_scval,
            ScVal::Address(smart_account.clone()),
        ]
        .try_into()
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_contexts_args",
            redacted_reason: format!("encode set_threshold target_args VecM: {e:?}"),
        })?;
        // Clone policy_addr before move into ScVal (needed for result-fetch below).
        let policy_addr_for_result_fetch = policy_addr.clone();
        let execute_args = vec![
            ScVal::Address(policy_addr),
            ScVal::Symbol(set_threshold_sym),
            ScVal::Vec(Some(ScVec(target_args_vec))),
        ];

        // Both contract and auth_address are the smart account; `execute()` calls
        // `e.current_contract_address().require_auth()`.
        let policy_auth_rule_ids = vec![ContextRuleId::from(rule_id)];
        self.submit_single_op(
            smart_account.clone(),
            &smart_account,
            rule_id,
            "execute",
            execute_args,
            &policy_auth_rule_ids,
            signer,
            &source_pubkey_strkey,
            // Expiry check at signing-path entry.
            Some(ExpiryCheck { rule_id }),
        )
        .await?;

        let resulting = self
            .fetch_signer_set(
                &self.primary_rpc_client,
                smart_account,
                rule_id,
                Some(&source_pubkey_strkey),
                &policy_addr_for_result_fetch,
                request_id,
            )
            .await?;
        Ok((old_threshold, resulting))
    }

    /// Submits a single `InvokeHostFunction` op transaction.
    ///
    /// Uses the six-stage flow (build → simulate → build_auth →
    /// sign_auth → delegated_entry → resimulate → envelope-sign → submit).
    ///
    /// `auth_address` — the `ScAddress` the simulation records a
    /// `SorobanCredentials::Address` auth entry for.  For all current callers,
    /// `contract == auth_address` (smart account): `add_signer`, `remove_signer`,
    /// and `execute` all call `e.current_contract_address().require_auth()`.
    /// The `set_threshold` path is always routed through `execute()` to avoid
    /// Soroban re-entry (see `set_threshold_locked_inner` execute-path inline).
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible six-stage flow args + additive expiry_check param"
    )]
    async fn submit_single_op(
        &self,
        contract: ScAddress,
        auth_address: &ScAddress,
        _rule_id: u32,
        entrypoint: &'static str,
        invoke_args: Vec<ScVal>,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        source_pubkey_strkey: &str,
        expiry_check: Option<ExpiryCheck>,
    ) -> Result<ScVal, SaError> {
        self.submit_signed_invoke(
            contract,
            auth_address,
            entrypoint,
            invoke_args,
            auth_rule_ids,
            signer,
            source_pubkey_strkey,
            entrypoint,
            expiry_check,
        )
        .await
        .map(|result| result.return_val)
    }

    /// Thin delegating wrapper that forwards to
    /// [`crate::submit::submit_signed_invoke`].
    ///
    /// `auth_address` — the `ScAddress` the simulation records a
    /// `SorobanCredentials::Address` auth entry for. In all current call sites,
    /// `contract == auth_address` (smart account) because all invoked entrypoints
    /// (`add_signer`, `remove_signer`, `execute`) call
    /// `e.current_contract_address().require_auth()`. The parameter is retained
    /// for correctness should a future entrypoint require a different credential.
    ///
    /// The caller-supplied `_source_pubkey_strkey` is no longer forwarded —
    /// the free function derives the pubkey inline from the signer. The
    /// parameter is kept on this wrapper signature to avoid a breaking change
    /// to the six call sites in this file; the leading `_` discards the value
    /// at the binding site without a `let _ =` drop statement.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update — delegated to free function.
    /// Session-key expiry check — `expiry_check` passed through.
    #[allow(
        clippy::too_many_arguments,
        reason = "expiry_check and _source_pubkey_strkey are additive to the pre-existing \
                  arg set; the free function carries the full body"
    )]
    async fn submit_signed_invoke(
        &self,
        contract: ScAddress,
        auth_address: &ScAddress,
        entrypoint: &'static str,
        invoke_args: Vec<ScVal>,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        _source_pubkey_strkey: &str,
        op_label: &'static str,
        expiry_check: Option<ExpiryCheck>,
    ) -> Result<crate::submit::SubmitInvokeResult, SaError> {
        // Convert ScAddress → C-strkey for the free function.
        let contract_strkey = scaddress_to_strkey(&contract)?;
        let auth_address_strkey = scaddress_to_strkey(auth_address)?;

        // Build the pre-form HostFunction from the entrypoint + args.
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
            contract_address: contract.clone(),
            function_name,
            args: invoke_args_vecm,
        });

        crate::submit::submit_signed_invoke(
            crate::submit::SubmitInvokeArgs::builder()
                .target_contract(&contract_strkey)
                // auth_address differs from target_contract when the entrypoint's
                // require_auth credential is a different address; pass it
                // explicitly so the auth-entry locator finds the right entry.
                .auth_address(auth_address_strkey.as_str())
                .auth_rule_ids(auth_rule_ids)
                .host_function(host_function)
                .signer(signer)
                .primary_rpc_url(&self.primary_rpc_url)
                .network_passphrase(&self.network_passphrase)
                .chain_id(&self.chain_id)
                .timeout(self.timeout)
                .op_label(op_label)
                .maybe_expiry_check(expiry_check)
                .build(),
        )
        .await
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

/// Pre-flight threshold + count invariant check.
///
/// Returns `Ok(())` when both:
/// - `1 <= effective_threshold`
/// - `effective_threshold <= post_op_signer_count`
///
/// Otherwise returns [`SaError::ThresholdUnreachable`] with a
/// `safe_ordering_hint` describing the two-command sequence the operator
/// should run to proceed safely. CAP-46 prohibits two `InvokeHostFunctionOp`
/// per Soroban tx, so signer and threshold changes cannot be bundled.
///
/// # Arguments
///
/// - `rule_id` — context rule identifier (for error context).
/// - `post_op_signer_count` — signer count AFTER the proposed operation.
/// - `current_threshold` — current threshold (before the operation).
/// - `effective_threshold` — threshold that would apply post-op.
/// - `requested_op` — the operation that triggered the check.
/// - `smart_account_redacted` — redacted smart-account address (for error context).
/// - `request_id` — correlation ID (for error context).
fn compute_post_op_invariant(
    rule_id: u32,
    post_op_signer_count: u32,
    current_threshold: u32,
    effective_threshold: u32,
    requested_op: ThresholdAffectingOp,
    smart_account_redacted: &str,
    request_id: &str,
) -> Result<(), SaError> {
    let invariant_ok = effective_threshold >= 1 && effective_threshold <= post_op_signer_count;

    if !invariant_ok {
        let safe_threshold = post_op_signer_count.max(1);
        let hint = match &requested_op {
            ThresholdAffectingOp::RemoveSigner { signer_id } => {
                format!(
                    "run 'smart-account signers set-threshold --rule-id {rule_id} \
                     --threshold {safe_threshold}' first, \
                     then retry 'smart-account signers remove --rule-id {rule_id} \
                     --signer {signer_id}'"
                )
            }
            ThresholdAffectingOp::AddSigner { .. } => {
                format!(
                    "add the signer first ('smart-account signers add --rule-id {rule_id} ...'), \
                     then adjust the threshold with \
                     'smart-account signers set-threshold --rule-id {rule_id} \
                     --threshold {safe_threshold}'"
                )
            }
            ThresholdAffectingOp::SetThreshold { new } => {
                format!(
                    "threshold {new} exceeds post-op signer count {post_op_signer_count}; \
                     use a value between 1 and {post_op_signer_count}"
                )
            }
        };
        return Err(SaError::ThresholdUnreachable {
            rule_id,
            current_signer_count: post_op_signer_count, // show post-op count
            current_threshold,
            requested_op,
            safe_ordering_hint: hint,
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            request_id: request_id.to_owned(),
        });
    }

    Ok(())
}

/// Fetches the wasm hash of each `ContractInstance` from a ledger-entries response.
///
/// Generic over any contract address slice — used for both policy contracts
/// (via `identify_threshold_policy`) and verifier contracts (via
/// `identify_verifier`).
///
/// Returns `Vec<Option<[u8; 32]>>` **aligned with `keys`**:
/// `Some(hash)` when the key resolved to a WASM contract instance, `None`
/// when the key was absent from the ledger or resolved to a non-WASM entry.
/// The caller may zip this result with the original contract address slice using
/// index position — no positional drift can occur because the lengths match.
///
/// The `LedgerEntryResult.xdr` field from `stellar-rpc-client` (rs-stellar-rpc-client)
/// contains `LedgerEntryData` XDR — NOT a full `LedgerEntry` wrapper.
/// `LedgerEntryResult` carries the data portion directly (confirmed from the
/// `stellar-rpc-client` source: `LedgerEntryResult.xdr` is decoded as
/// `LedgerEntryData`).
/// Using `LedgerEntry::from_xdr_base64` would fail with "xdr value invalid"
/// because the wire bytes do not contain the outer `LedgerEntry` discriminant
/// and the `last_modified_ledger_seq` / `ext` fields that wrap `LedgerEntryData`.
///
/// The `LedgerEntryResult.key` field contains base64-encoded `LedgerKey` XDR.
/// We decode it to match each response entry back to its request position, since
/// the RPC server MAY reorder entries relative to the request.
///
/// Mirrors the decode path of `deployment::deploy::verify_post_deploy_wasm_hash`
/// (`crates/stellar-agent-smart-account/src/deployment/deploy.rs:492-563`) —
/// the established known-working reference for the
/// `getLedgerEntries` + `ContractData` + `ContractInstance::executable` walk.
///
/// # Visibility
///
/// `pub(crate)` — exposed to `managers::verifiers::identify_policy_wasm_hash`
/// for `pin_referenced_contracts`.
pub(crate) async fn fetch_contract_wasm_hashes(
    client: &StellarRpcClient,
    keys: &[LedgerKey],
) -> Result<Vec<Option<[u8; 32]>>, String> {
    use stellar_xdr::{ContractExecutable, LedgerEntryData, LedgerKey as XdrLedgerKey, ReadXdr};

    if keys.is_empty() {
        return Ok(vec![]);
    }

    let response = client
        .get_ledger_entries(keys)
        .await
        .map_err(|e| format!("get_ledger_entries failed: {e}"))?;

    let raw_entries = response.entries.unwrap_or_default();

    // Build a position-keyed map: key_index → wasm_hash.
    // `LedgerEntryResult.key` is base64-encoded `LedgerKey` XDR.
    // `LedgerEntryResult.xdr` is base64-encoded `LedgerEntryData` XDR.
    // Both fields confirmed from the `stellar-rpc-client` (rs-stellar-rpc-client)
    // `LedgerEntryResult` struct.
    let mut hash_by_key_pos: std::collections::HashMap<usize, [u8; 32]> =
        std::collections::HashMap::new();

    for entry_result in &raw_entries {
        // Decode the response key to match it against our request keys by position.
        let response_key = match XdrLedgerKey::from_xdr_base64(
            &entry_result.key,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.key.len()),
        ) {
            Ok(k) => k,
            Err(_) => continue, // skip malformed key — safe, only loses one entry
        };

        // Find the position in our request key slice that matches this response key.
        let Some(pos) = keys.iter().position(|k| k == &response_key) else {
            continue; // response contains an entry not in our request — skip
        };

        // Decode the entry data.
        // `LedgerEntryResult.xdr` contains `LedgerEntryData` XDR (not a full LedgerEntry).
        // Confirmed from `stellar-rpc-client` (rs-stellar-rpc-client): `LedgerEntryResult.xdr`
        // holds `LedgerEntryData`, decoded via `LedgerEntryData::from_xdr_base64`.
        let entry_data = match LedgerEntryData::from_xdr_base64(
            &entry_result.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.xdr.len()),
        ) {
            Ok(d) => d,
            Err(_) => continue, // skip malformed entry — safe
        };

        if let LedgerEntryData::ContractData(cd) = &entry_data
            && let ScVal::ContractInstance(instance) = &cd.val
            && let ContractExecutable::Wasm(Hash(bytes)) = &instance.executable
        {
            hash_by_key_pos.insert(pos, *bytes);
        }
    }

    // Build the aligned result vector: Some(hash) for resolved keys, None for missing.
    Ok((0..keys.len())
        .map(|i| hash_by_key_pos.get(&i).copied())
        .collect())
}

#[cfg(feature = "test-helpers")]
fn mock_migration_submit_result(
    _rule_id: u32,
    entrypoint: &'static str,
    smart_account_redacted: &str,
    request_id: &str,
) -> Option<Result<crate::submit::SubmitInvokeResult, SaError>> {
    use std::collections::hash_map::Entry;
    use std::sync::{Mutex, OnceLock};

    static CALLS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

    if request_id.starts_with("mock-submit-send-failure") {
        return Some(Err(SaError::VerifierMigrationFailed {
            phase: crate::error::MIGRATION_PHASES[4],
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            detail: format!("{entrypoint} migration step failed: mock sendTransaction failure"),
            request_id: request_id.to_owned(),
        }));
    }

    if !request_id.starts_with("mock-partial-submit-send-failure") {
        return None;
    }

    let call_index = {
        let calls = CALLS.get_or_init(|| Mutex::new(HashMap::new()));
        let Ok(mut calls) = calls.lock() else {
            return Some(Err(SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: "test-helper migration submit call map poisoned".to_owned(),
            }));
        };
        match calls.entry(request_id.to_owned()) {
            Entry::Occupied(mut entry) => {
                let current = *entry.get();
                entry.insert(current.saturating_add(1));
                current
            }
            Entry::Vacant(entry) => {
                entry.insert(1);
                0
            }
        }
    };

    if call_index == 2 {
        return Some(Err(SaError::VerifierMigrationFailed {
            phase: crate::error::MIGRATION_PHASES[4],
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            detail: format!(
                "{entrypoint} migration step failed: mock second-step sendTransaction failure"
            ),
            request_id: request_id.to_owned(),
        }));
    }

    let fill = u8::try_from(call_index + 1).unwrap_or(0xff);
    let tx_hash = format!("{fill:064x}");
    Some(Ok(crate::submit::SubmitInvokeResult {
        return_val: ScVal::Void,
        tx_hash,
        ledger: 1000 + u32::try_from(call_index).unwrap_or(0),
    }))
}

/// Fetches the wasm hash of a single deployed contract via two-RPC consultation,
/// WITHOUT allowlist enforcement.
///
/// This is the lower-level primitive underlying [`SignersManager::identify_verifier`].
/// It delegates the two-RPC fetch and divergence check to
/// [`stellar_agent_network::fetch_contract_wasm_hash`], then maps the
/// [`stellar_agent_network::WasmHashFetch`] tri-state to `Option<[u8; 32]>`:
/// `Wasm(h)` → `Some(h)`, `Sac` and `Absent` → `None`.
///
/// The `None` mapping is deliberate and per-caller:
/// - `identify_verifier` (install-time) — treats `None` as not-in-allowlist.
/// - `pin_referenced_contracts` `accept_unknown_verifier` branch (install-time
///   override) — calls `.unwrap_or([0u8; 32])` to store a zero sentinel for
///   absent-entry edge cases; drift detection later compares live hash vs this pin.
/// - `verify_pinned_verifier_against_chain` (signing-time drift detection) —
///   calls `.unwrap_or([0u8; 32])` so a zero-pinned entry (from the absent-entry
///   path above) compares equal to a zero observed value, passing cleanly.
///
/// # Returns
///
/// - `Ok(Some(hash))` — two-RPC agreement reached; contract is present and is a
///   WASM instance.
/// - `Ok(None)` — two-RPC agreement reached; contract is absent from the ledger
///   or is a Stellar Asset Contract (SAC); callers apply their per-caller absent
///   semantics (see above).
///
/// # Errors
///
/// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC responses differ.
/// - [`SaError::DeploymentFailed`] (phase `"simulate"`) — `getLedgerEntries` RPC
///   failure on primary or secondary.
///
/// # Implements
///
/// Verifier pinning: fetches the live on-chain wasm hash without allowlist
/// enforcement, for use in drift detection (signing-time) and the
/// `accept_unknown_verifier` install-time override path.
pub(crate) async fn fetch_observed_wasm_hash(
    primary: &StellarRpcClient,
    secondary: &StellarRpcClient,
    contract_addr: &ScAddress,
    rule_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
) -> Result<Option<[u8; 32]>, SaError> {
    use stellar_agent_network::{
        FetchContractWasmHashError, WasmHashFetch, fetch_contract_wasm_hash,
    };

    // Convert ScAddress to strkey so the shared primitive can parse it.
    // scaddress_to_strkey only fails for exotic non-Contract / non-Account variants;
    // all callers of fetch_observed_wasm_hash pass contract addresses (C-strkeys).
    let strkey = scaddress_to_strkey(contract_addr)?;

    match fetch_contract_wasm_hash(primary, Some(secondary), &strkey).await {
        Ok(WasmHashFetch::Wasm(hash)) => Ok(Some(hash)),
        // SAC and Absent both map to None — per-caller absent handling
        // (unwrap_or([0u8;32]) or not-in-allowlist error) is applied at each call site.
        Ok(WasmHashFetch::Sac | WasmHashFetch::Absent) => Ok(None),
        // Forward-compatibility arm: WasmHashFetch is #[non_exhaustive]; future
        // variants (e.g. a new contract-executable type) map to None so callers
        // treat them as "no plain WASM hash" — the fail-closed default (None
        // drives drift detection against any real pin at the signing-time call
        // sites).  If the primitive ever grows a hash-BEARING variant, this arm
        // must be revisited so the hash is not silently discarded.
        Ok(_) => Ok(None),
        Err(FetchContractWasmHashError::Divergent(div)) => Err(SaError::NetworkRpcDivergence {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            primary_view_digest_first8: div.primary_first8,
            secondary_view_digest_first8: div.secondary_first8,
            request_id: request_id.to_owned(),
        }),
        Err(FetchContractWasmHashError::Unavailable { source, .. }) => {
            Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("RPC wasm-hash fetch failed: {source}"),
            })
        }
        // Belt-and-braces guard, not a live path: `scaddress_to_strkey` above
        // already produced a valid C-strkey, so the primitive's own address
        // parse cannot realistically reject it.  Kept for #[non_exhaustive]
        // safety; maps to the same variant scaddress_to_strkey itself returns.
        Err(FetchContractWasmHashError::InvalidAddress { reason, .. }) => {
            Err(SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("contract address is not a valid strkey: {reason}"),
            })
        }
        // Forward-compatibility arm: FetchContractWasmHashError is #[non_exhaustive].
        Err(e) => Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("RPC wasm-hash fetch failed (unrecognised error kind): {e}"),
        }),
    }
}

/// Extracts a `u32` from a `ScVal::U32` return value.
fn extract_u32_return(val: &ScVal, context: &str) -> Result<u32, SaError> {
    match val {
        ScVal::U32(n) => Ok(*n),
        other => Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("{context}: expected ScVal::U32 return, got {other:?}"),
        }),
    }
}

/// Returns the info-level redacted first-8-hex summary for a signer pubkey.
fn pubkey_first8(pk: &SignerPubkey) -> String {
    use stellar_agent_core::audit_log::signer_set::signer_pubkey_canonical_body;
    signer_pubkey_canonical_body(pk)
        .map(|body| {
            body[..body.len().min(8)]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .unwrap_or_else(|_| "encode_error".to_owned())
}

/// Returns the info-level first-8-hex summaries for a pubkey slice.
fn pubkeys_first8(pks: &[SignerPubkey]) -> Vec<String> {
    pks.iter().map(pubkey_first8).collect()
}

/// Builds an OZ `Signer::Delegated(Address)` ScVal from a delegated signer
/// G-strkey.
///
/// OZ `Signer` contracttype byte-layout (stellar-accounts v0.7.1):
/// `Delegated(Address)` is encoded as
/// `ScVal::Vec([ScVal::Symbol("Delegated"), ScVal::Address(account)])`.
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] for invalid G-strkeys and
/// if the fixed symbol/vector cannot be encoded.
pub fn build_delegated_signer_scval(g_strkey: &str) -> Result<ScVal, SaError> {
    let signer_addr = crate::managers::rules::parse_g_strkey_to_signer_address(g_strkey)?;
    let tag =
        ScSymbol::try_from("Delegated").map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("encode Delegated symbol: {e:?}"),
        })?;
    let scvec: VecM<ScVal> = vec![ScVal::Symbol(tag), ScVal::Address(signer_addr)]
        .try_into()
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_payload",
            redacted_reason: format!("encode Delegated ScVec: {e:?}"),
        })?;
    Ok(ScVal::Vec(Some(ScVec(scvec))))
}

/// Builds an OZ `Signer::External(Address, Bytes)` ScVal from a verifier
/// C-strkey and raw `key_data` bytes.
///
/// OZ `Signer` contracttype byte-layout (stellar-accounts v0.7.1):
/// `External(Address, Bytes)` is encoded as
/// `ScVal::Vec([ScVal::Symbol("External"), ScVal::Address(verifier), ScVal::Bytes(key_data)])`.
///
/// For WebAuthn signers, `key_data` is `pubkey_65_bytes || credential_id_bytes`
/// per the OpenZeppelin WebAuthn verifier (`canonicalize_key` strips the
/// credential-ID suffix at verify time; the full concatenation is stored
/// on-chain).
///
/// # Errors
///
/// Returns [`SaError::AuthEntryConstructionFailed`] when XDR encoding fails
/// or the verifier C-strkey cannot be decoded to a contract address.
pub fn build_external_signer_scval(
    verifier_sc_addr: ScAddress,
    key_data: &[u8],
) -> Result<ScVal, SaError> {
    let tag = ScSymbol::try_from("External").map_err(|e| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: format!("encode External symbol: {e:?}"),
    })?;
    let key_bytes: stellar_xdr::BytesM =
        key_data
            .to_vec()
            .try_into()
            .map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("key_data BytesM encode failed: {e:?}"),
            })?;
    let scvec: VecM<ScVal> = vec![
        ScVal::Symbol(tag),
        ScVal::Address(verifier_sc_addr),
        ScVal::Bytes(ScBytes(key_bytes)),
    ]
    .try_into()
    .map_err(|e| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: format!("encode External ScVec: {e:?}"),
    })?;
    Ok(ScVal::Vec(Some(ScVec(scvec))))
}

/// Returns a stable type-discriminant label for a `SignerPubkey` (for error messages).
fn signer_pubkey_type_label(pk: &SignerPubkey) -> &'static str {
    match pk {
        SignerPubkey::Ed25519 { .. } => "ed25519",
        SignerPubkey::External { .. } => "external",
        SignerPubkey::WebAuthn { .. } => "webauthn",
        // `SignerPubkey` is `#[non_exhaustive]`; forward-compatibility arm.
        &_ => "unknown",
    }
}

/// Standalone read-only simulate helper (no auth, no signing).
///
/// When `source_account_strkey` is `None`, uses [`SIMULATE_SENTINEL_G`] with
/// sequence number `"0"` and skips the `fetch_account` RPC call.
///
/// `pub(crate)` — used by `managers::migration::MigrationPlanner` for
/// `get_context_rules_count` and `get_context_rule` read-only calls.
/// Not part of the public `SignersManager` API surface.
pub(crate) async fn simulate_read_only(
    rpc_url: &str,
    smart_account: ScAddress,
    entrypoint: &str,
    invoke_args: Vec<ScVal>,
    source_account_strkey: Option<&str>,
    network_passphrase: &str,
    timeout: Duration,
) -> Result<ScVal, SaError> {
    let auth_payload_err = |reason: String| SaError::AuthEntryConstructionFailed {
        stage: "auth_payload",
        redacted_reason: reason,
    };

    let function_name = ScSymbol::try_from(entrypoint)
        .map_err(|e| auth_payload_err(format!("encode {entrypoint} symbol: {e:?}")))?;
    let invoke_args_vecm: VecM<ScVal> =
        invoke_args
            .try_into()
            .map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_contexts_args",
                redacted_reason: format!("encode {entrypoint} args VecM: {e:?}"),
            })?;

    let invoke = InvokeContractArgs {
        contract_address: smart_account.clone(),
        function_name: function_name.clone(),
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

    let rpc_client = StellarRpcClient::new(rpc_url)
        .map_err(|e| auth_payload_err(format!("StellarRpcClient construction failed: {e}")))?;

    let (effective_source, sequence) = if let Some(source_account_strkey) = source_account_strkey {
        let source_view = tokio::time::timeout(
            timeout,
            fetch_account(&rpc_client, source_account_strkey, &[]),
        )
        .await
        .map_err(|_| auth_payload_err("source-account fetch timed out".to_owned()))?
        .map_err(|e| auth_payload_err(format!("source-account fetch failed: {e}")))?;
        (
            source_account_strkey,
            source_view.sequence_number.to_string(),
        )
    } else {
        (SIMULATE_SENTINEL_G, "0".to_owned())
    };

    let mut source_account = BaselibAccount::new(effective_source, &sequence)
        .map_err(|e| auth_payload_err(format!("BaselibAccount::new failed: {e:?}")))?;

    let mut tx_builder = TransactionBuilder::new(&mut source_account, network_passphrase, None);
    tx_builder.fee(BASE_FEE_STROOPS);
    tx_builder.add_operation(op);
    let tx_for_simulate = tx_builder.build_for_simulation();

    let server = Client::new(rpc_url)
        .map_err(|e| auth_payload_err(format!("RPC Client construction failed: {e}")))?;

    let sim_envelope = tx_for_simulate
        .to_envelope()
        .map_err(|e| auth_payload_err(format!("to_envelope failed: {e:?}")))?;
    let sim = tokio::time::timeout(
        timeout,
        server.simulate_transaction_envelope(&sim_envelope, None),
    )
    .await
    .map_err(|_| auth_payload_err("simulate_transaction_envelope timed out".to_owned()))?
    .map_err(|e| auth_payload_err(format!("simulate_transaction_envelope failed: {e}")))?;

    if let Some(err) = &sim.error {
        return Err(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!(
                "{entrypoint} simulation error: {}",
                augment_with_oz_error_name(err)
            ),
        });
    }

    let return_val = sim
        .results()
        .map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("{entrypoint}: simulate results decode failed: {e}"),
        })?
        .into_iter()
        .next()
        .ok_or(SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("{entrypoint}: simulate returned no result entry"),
        })?
        .xdr;

    Ok(return_val)
}

// ── OnChainContextRule ────────────────────────────────────────────────────────

/// Decoded on-chain context rule (off-chain mirror of the OZ `ContextRule` struct).
///
/// Produced by decoding the `ScVal` returned from `get_context_rule`.
/// The `raw_scval` field preserves the verbatim simulation return value so it
/// can be round-tripped back to the chain as the `context_rule` argument for
/// `set_threshold` without re-encoding risk.
///
/// # Round-trip strategy
///
/// `set_threshold(e, threshold, context_rule, smart_account)` reads:
///   - `context_rule.id` — storage key for the threshold
///   - `context_rule.signers.len()` — upper bound for threshold validation
///     (enforced by the threshold policy contract)
///
/// Rather than hand-rolling the 8-field `#[contracttype]` ScVal encoding off-chain
/// (which risks field-order or variant drift), we store the exact `ScVal::Map`
/// returned by the `get_context_rule` simulation and pass it through verbatim.
/// The simulation uses the OZ soroban-sdk contracttype derive — the SAME encoder
/// the host runs on-chain — guaranteeing byte-identity.
struct OnChainContextRule {
    #[allow(
        dead_code,
        reason = "kept for struct completeness; not accessed after decode"
    )]
    pub id: u32,
    pub signers: Vec<(u32, SignerPubkey)>, // (signer_id, pubkey)
    pub threshold: u32,
    pub policies: Vec<ScAddress>,
    /// Verbatim `ScVal::Map` from `get_context_rule` simulation — passed through
    /// as the `context_rule` argument to `set_threshold`.
    ///
    /// Stores the full on-chain `#[contracttype]` ScVal encoding so the wallet
    /// never re-encodes the 8-field struct off-chain.
    pub raw_scval: ScVal,
}

impl OnChainContextRule {
    fn into_observed_signer_set(self) -> ObservedSignerSet {
        let signer_count = u32::try_from(self.signers.len()).unwrap_or(u32::MAX);
        let signer_ids = self.signers.iter().map(|(id, _)| *id).collect();
        let signer_pubkeys = self.signers.into_iter().map(|(_, pk)| pk).collect();
        ObservedSignerSet {
            signer_count,
            threshold: self.threshold,
            signer_ids,
            signer_pubkeys,
        }
    }

    /// Returns the verbatim `ScVal::Map` encoding of the ContextRule for use as
    /// the `context_rule` argument to `set_threshold`.
    ///
    /// The stored ScVal is the exact value returned by the `get_context_rule`
    /// simulation — produced by the OZ soroban-sdk `#[contracttype]` derive on-chain.
    /// Passing it back verbatim ensures byte-identity with the host decoder.
    ///
    /// # Byte-layout
    ///
    /// The OZ stellar-accounts v0.7.1 `ContextRule` is an 8-field
    /// `#[contracttype]` struct. The `#[contracttype]` derive
    /// (soroban-sdk-macros `derive_type_struct`) produces `ScVal::Map(ScMap([sorted entries]))`.
    /// Field ordering by `ScVal::Symbol` lexicographic key:
    /// `context_type`, `id`, `name`, `policies`, `policy_ids`, `signer_ids`, `signers`, `valid_until`.
    fn as_scval(&self) -> Result<ScVal, SaError> {
        Ok(self.raw_scval.clone())
    }
}

/// Decodes a `ScVal` returned by `get_context_rule` into an [`OnChainContextRule`].
///
/// The `get_context_rule` entrypoint returns a `ContextRule` contracttype.
/// In Soroban simulation, contracttype structs are returned as `ScVal::Map`
/// with sorted keys. We decode the relevant fields: `id`, `signers`,
/// `signer_ids`, and `policies`.
///
/// # Threshold placeholder
///
/// `ContextRule` does not carry a `threshold` field directly; the threshold is
/// stored in the threshold-policy contract's own storage keyed by
/// `(context_rule_id, smart_account)`.  This function stores a **placeholder**
/// value of `signers.len()` in `OnChainContextRule.threshold`.  All callers
/// that care about the real threshold MUST call `fetch_threshold` with an
/// explicit RPC client on the first policy address and overwrite `threshold`
/// before returning the value to the user.
///
/// # Errors
///
/// Returns [`SaError::DeploymentFailed`] (phase `"simulate"`) if the `ScVal`
/// cannot be decoded as a `ContextRule`.
fn decode_context_rule_scval(val: ScVal) -> Result<OnChainContextRule, SaError> {
    // The simulation returns a ScVal::Map for a contracttype struct.
    // We extract id, signers, signer_ids, policies.
    // We also preserve the raw ScVal for round-trip use in set_threshold args.
    let map = match &val {
        ScVal::Map(Some(m)) => m.clone(),
        other => {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("get_context_rule: expected ScVal::Map, got {other:?}"),
            });
        }
    };
    // Preserve the verbatim ScVal — used as the `context_rule` arg in set_threshold.
    // This round-trips the on-chain #[contracttype] encoding without re-encoding risk.
    let raw_scval = val;

    let mut id: Option<u32> = None;
    let mut signer_ids: Vec<u32> = vec![];
    let mut signers_scvals: Vec<ScVal> = vec![];
    let mut policies: Vec<ScAddress> = vec![];

    for entry in map.iter() {
        let key_str = match &entry.key {
            ScVal::Symbol(s) => s.as_slice().to_vec(),
            _ => continue,
        };
        let key = std::str::from_utf8(&key_str).unwrap_or("");
        match key {
            "id" => {
                if let ScVal::U32(n) = &entry.val {
                    id = Some(*n);
                }
            }
            "signer_ids" => {
                if let ScVal::Vec(Some(v)) = &entry.val {
                    for item in v.iter() {
                        if let ScVal::U32(n) = item {
                            signer_ids.push(*n);
                        }
                    }
                }
            }
            "signers" => {
                if let ScVal::Vec(Some(v)) = &entry.val {
                    for item in v.iter() {
                        signers_scvals.push(item.clone());
                    }
                }
            }
            "policy_ids" | "policies" => {
                if let ScVal::Vec(Some(v)) = &entry.val {
                    for item in v.iter() {
                        if let ScVal::Address(addr) = item {
                            policies.push(addr.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let rule_id = id.ok_or_else(|| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: "get_context_rule: missing 'id' field in ContextRule map".to_owned(),
    })?;

    // Decode signers from signer ScVals. The OZ `Signer` contracttype is:
    //   Delegated(Address) → ScVal::Vec([Symbol("Delegated"), Address])
    //   External(Address, Bytes) → ScVal::Vec([Symbol("External"), Address, Bytes])
    // We match signer_ids by index position (parallel slice).
    let signers: Vec<(u32, SignerPubkey)> = signer_ids
        .iter()
        .zip(signers_scvals.iter())
        .filter_map(|(sid, sv)| decode_signer_scval(sv).map(|pk| (*sid, pk)))
        .collect();

    // Threshold placeholder: callers that need the real threshold MUST override
    // this value by calling `fetch_threshold` with an explicit RPC client on
    // the first policy address. `signers.len()` is NOT the threshold; the
    // threshold is stored in the policy contract's own storage keyed by
    // `(context_rule_id, smart_account)`. `fetch_signer_set` replaces this
    // value with the real on-chain threshold before returning.
    let threshold = u32::try_from(signers.len()).unwrap_or(1).max(1);

    Ok(OnChainContextRule {
        id: rule_id,
        signers,
        threshold,
        policies,
        raw_scval,
    })
}

/// Full-fidelity decoded representation of an OZ on-chain `Signer` variant.
///
/// Produced by [`decode_signer_scval_full`] from a `Signer` `#[contracttype]`
/// ScVal.  Carries all fields without truncation so callers can either project
/// to [`SignerPubkey`] (truncating `key_data` to 16 bytes for audit-log
/// display) or assert byte-exact equality against the original key blob.
///
/// Decoded from the OZ stellar-accounts v0.7.1 `Signer` contracttype.
///
/// This type is always compiled.  It is accessible outside the crate only via
/// the `#[cfg(any(test, feature = "test-helpers"))]`-gated re-export in
/// `src/lib.rs`.  Production callers within this crate reach it through
/// `decode_signer_scval`, which projects the result to [`SignerPubkey`].
#[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
pub enum DecodedOnChainSigner {
    /// `Signer::Delegated(Address)` — a G-strkey ed25519 keypair.
    ///
    /// The `Address` payload is always `ScAddress::Account(...)` wrapping an
    /// ed25519 public key.
    ///
    /// Note: in the OZ contracttype, the `Address` is the **signer** account
    /// address (a G-strkey public key), not a verifier contract address.
    Delegated {
        /// The 32-byte ed25519 public key extracted from the Account address.
        pubkey: [u8; 32],
        /// The verbatim `ScAddress` for callers that need the typed value
        /// (e.g. for ScMap key construction or equality assertions).
        signer_address: ScAddress,
    },
    /// `Signer::External(Address, Bytes)` — a custom verifier contract with an
    /// opaque public-key blob.
    ///
    /// The `Address` payload is always `ScAddress::Contract(...)`.
    External {
        /// Verifier contract C-strkey (e.g. `"CABC..."` prefix).
        verifier_strkey: String,
        /// Full public-key byte blob.  NOT truncated — production callers
        /// derive `key_data_first16: [u8; 16]` at the call site; test callers
        /// use the full blob for byte-exact equality assertions.
        key_data: Vec<u8>,
    },
}

/// Full-fidelity decode of an OZ `Signer` ScVal — the single decode site for
/// all OZ `Signer` variant routing and field extraction.
///
/// Both production callers (which project to [`SignerPubkey`] via
/// `decode_signer_scval`) and test-helper callers (which need the full
/// `key_data` for byte-exact equality assertions) route through this function.
/// A future OZ change to the `Signer` enum encoding requires updating only
/// this function — production and test paths pick up the change automatically.
///
/// The OZ stellar-accounts v0.7.1 `Signer` contracttype encodes as:
/// - `Delegated(Address)` → `ScVal::Vec([Symbol("Delegated"), Address(pubkey_addr)])`
/// - `External(Address, Bytes)` → `ScVal::Vec([Symbol("External"), Address(verifier), Bytes(key_data)])`
///
/// Returns `None` for any unknown variant or malformed ScVal so callers can
/// silently skip unknown future OZ signer variants without panicking.
///
/// This function is always compiled.  It is accessible outside the crate only
/// via the `#[cfg(any(test, feature = "test-helpers"))]`-gated re-export in
/// `src/lib.rs`.  Production use within this crate goes through `decode_signer_scval`.
///
/// # Returns
///
/// `Some(DecodedOnChainSigner)` on successful decode of a recognised OZ
/// `Signer` variant; `None` on malformed `ScVal` or an unknown variant tag
/// (callers that panic on `None` are integration tests; production callers
/// silently skip unknown variants for forward-compat).
#[cfg_attr(not(any(test, feature = "test-helpers")), allow(dead_code))]
pub fn decode_signer_scval_full(val: &ScVal) -> Option<DecodedOnChainSigner> {
    let vec = match val {
        ScVal::Vec(Some(v)) => v,
        _ => return None,
    };
    let items: Vec<&ScVal> = vec.iter().collect();
    if items.len() < 2 {
        return None;
    }

    let tag = match items[0] {
        ScVal::Symbol(s) => std::str::from_utf8(s.as_slice()).unwrap_or("").to_owned(),
        _ => return None,
    };

    match tag.as_str() {
        "Delegated" => {
            // Delegated(Address) — the address is a G-strkey ed25519 account.
            // OZ `Signer::Delegated(Address)`.
            match items[1] {
                ScVal::Address(addr @ ScAddress::Account(acc)) => {
                    let pubkey = match &acc.0 {
                        PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => *bytes,
                    };
                    Some(DecodedOnChainSigner::Delegated {
                        pubkey,
                        signer_address: addr.clone(),
                    })
                }
                _ => None,
            }
        }
        "External" => {
            if items.len() < 3 {
                return None;
            }
            // OZ `Signer::External(Address, Bytes)`.
            let verifier_addr = match items[1] {
                ScVal::Address(addr) => addr,
                _ => return None,
            };
            // Encode verifier as C-strkey.
            let verifier_strkey = match verifier_addr {
                ScAddress::Contract(ContractId(Hash(bytes))) => {
                    format!("{}", stellar_strkey::Contract(*bytes))
                }
                _ => return None,
            };
            let key_data = match items[2] {
                ScVal::Bytes(ScBytes(bytes)) => bytes.as_slice().to_vec(),
                _ => return None,
            };
            Some(DecodedOnChainSigner::External {
                verifier_strkey,
                key_data,
            })
        }
        _ => None,
    }
}

/// Decodes an OZ `Signer` ScVal into a [`SignerPubkey`].
///
/// Projects the full-fidelity [`DecodedOnChainSigner`] returned by
/// [`decode_signer_scval_full`] to the production-facing [`SignerPubkey`],
/// truncating `key_data` to 16 bytes for audit-log display efficiency.
/// Test-helper consumers that need the full `key_data` call
/// [`decode_signer_scval_full`] directly (enabled via `features = ["test-helpers"]`).
///
/// The OZ `Signer` contracttype encodes as:
/// - `Delegated(Address)` → `ScVal::Vec([Symbol("Delegated"), Address(pubkey_addr)])`
/// - `External(Address, Bytes)` → `ScVal::Vec([Symbol("External"), Address(verifier), Bytes(key_data)])`
fn decode_signer_scval(val: &ScVal) -> Option<SignerPubkey> {
    match decode_signer_scval_full(val)? {
        DecodedOnChainSigner::Delegated { pubkey, .. } => Some(SignerPubkey::Ed25519 { pubkey }),
        DecodedOnChainSigner::External {
            verifier_strkey,
            key_data,
            ..
        } => {
            let key_data_first16: [u8; 16] = {
                let mut arr = [0u8; 16];
                let len = key_data.len().min(16);
                arr[..len].copy_from_slice(&key_data[..len]);
                arr
            };
            Some(SignerPubkey::External {
                verifier_contract: verifier_strkey,
                key_data_first16,
            })
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used,
        reason = "test-only"
    )]

    use std::sync::{Arc, Mutex};

    use serial_test::serial;
    use stellar_agent_core::audit_log::signer_set::SignerPubkey;
    use stellar_agent_core::audit_log::writer::AuditWriter;
    use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
    use stellar_agent_test_support::CaptureWriter;

    use super::*;

    // ── compute_post_op_invariant ─────────────────────────────────────────────

    #[test]
    fn post_op_invariant_allows_valid_remove() {
        // 3-of-3, removing one signer WITH atomic threshold decrement → 2-of-2.
        let result = compute_post_op_invariant(
            1,
            2, // post_op_signer_count
            3, // current_threshold
            2, // effective_threshold
            ThresholdAffectingOp::RemoveSigner { signer_id: 2 },
            "CDABC...12345",
            "req-1",
        );
        assert!(
            result.is_ok(),
            "2-of-2 after remove should be valid: {result:?}"
        );
    }

    #[test]
    fn post_op_invariant_refuses_threshold_brick() {
        // 3-of-3, removing one signer WITHOUT threshold decrement → count=2 < threshold=3.
        let result = compute_post_op_invariant(
            1,
            2, // post_op_signer_count
            3, // current_threshold
            3, // effective_threshold (unchanged, would brick)
            ThresholdAffectingOp::RemoveSigner { signer_id: 2 },
            "CDABC...12345",
            "req-1",
        );
        assert!(
            matches!(result, Err(SaError::ThresholdUnreachable { .. })),
            "threshold brick must return ThresholdUnreachable: {result:?}"
        );
    }

    #[test]
    fn post_op_invariant_refuses_zero_threshold() {
        let result = compute_post_op_invariant(
            1,
            1,
            1,
            0, // threshold = 0 is invalid
            ThresholdAffectingOp::SetThreshold { new: 0 },
            "CDABC...12345",
            "req-1",
        );
        assert!(
            matches!(result, Err(SaError::ThresholdUnreachable { .. })),
            "threshold=0 must return ThresholdUnreachable: {result:?}"
        );
    }

    #[test]
    fn post_op_invariant_allows_threshold_equal_to_signer_count() {
        // threshold == signer_count is valid (N-of-N).
        let result = compute_post_op_invariant(
            1,
            3,
            3,
            3,
            ThresholdAffectingOp::SetThreshold { new: 3 },
            "CDABC...12345",
            "req-1",
        );
        assert!(result.is_ok(), "N-of-N should be valid: {result:?}");
    }

    #[test]
    #[serial]
    fn emit_baseline_marks_degraded_and_warns_when_audit_writer_poisoned() {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None)
                .expect("AuditWriter::open must succeed"),
        ));

        let poison_result = std::panic::catch_unwind({
            let audit_writer = Arc::clone(&audit_writer);
            move || {
                let _guard = audit_writer.lock().expect("initial lock must succeed");
                panic!("poison audit writer");
            }
        });
        assert!(poison_result.is_err(), "poison setup must panic");
        assert!(
            audit_writer.lock().is_err(),
            "audit writer must be poisoned"
        );

        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:1".to_owned(),
            Arc::clone(&audit_writer),
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(1),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager construction must succeed");
        assert!(
            !manager.audit_writer_degraded(),
            "manager starts with non-degraded audit writer state"
        );

        let observed = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0x11; 32] }],
        };
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            manager.emit_baseline(
                &observed,
                7,
                "CDABC...12345",
                BaselineReason::FirstObservation,
                "req-poison",
            );
        });

        let logs = capture.captured_str();
        assert!(
            logs.contains("audit-writer mutex poisoned; SaSignerSetBaselined row dropped"),
            "missing poison warning: {logs}"
        );
        assert!(
            logs.contains("audit-log structurally degraded during this session"),
            "missing degraded-session warning: {logs}"
        );
        assert!(logs.contains("rule_id=7"), "missing rule_id: {logs}");
        assert!(
            logs.contains("request_id=req-poison"),
            "missing request_id: {logs}"
        );
        assert!(
            manager.audit_writer_degraded(),
            "poisoned audit-writer branch must mark manager degraded"
        );
    }

    // ── shared helper for poison-path tests ───────────────────────────────────

    /// Constructs a `SignersManager` backed by a pre-poisoned `AuditWriter`
    /// mutex and returns both.
    ///
    /// The returned `tempdir` must stay alive for the duration of the test.
    /// Pattern mirrors `emit_baseline_marks_degraded_and_warns_when_audit_writer_poisoned`.
    fn make_manager_with_poisoned_writer() -> (SignersManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None)
                .expect("AuditWriter::open must succeed"),
        ));

        let _ = std::panic::catch_unwind({
            let audit_writer = Arc::clone(&audit_writer);
            move || {
                let _guard = audit_writer.lock().expect("initial lock must succeed");
                panic!("poison audit writer");
            }
        });
        assert!(
            audit_writer.lock().is_err(),
            "audit writer must be poisoned after setup"
        );

        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:1".to_owned(),
            Arc::clone(&audit_writer),
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(1),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager construction must succeed");

        assert!(
            !manager.audit_writer_degraded(),
            "manager must start non-degraded"
        );

        (manager, dir)
    }

    /// `emit_signer_set_diverged` marks the session-level degraded flag and
    /// emits the expected structured warning when the `AuditWriter` mutex is
    /// poisoned (the `SaSignerSetDiverged` mark site).
    ///
    /// This test exercises the `signers.rs` mark site at
    /// `emit_signer_set_diverged` (the `Err(_poison)` arm).
    #[test]
    #[serial]
    fn emit_signer_set_diverged_marks_degraded_and_warns_when_audit_writer_poisoned() {
        let (manager, _dir) = make_manager_with_poisoned_writer();

        let signer_set = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0x22; 32] }],
        };

        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            manager.emit_signer_set_diverged(
                3,
                "CDABC...12345",
                &signer_set,
                &signer_set,
                "req-diverge-poison",
            );
        });

        let logs = capture.captured_str();
        assert!(
            logs.contains("audit-writer mutex poisoned; SaSignerSetDiverged row dropped"),
            "missing poison warning: {logs}"
        );
        assert!(
            logs.contains("audit-log structurally degraded during this session"),
            "missing degraded-session warning: {logs}"
        );
        assert!(logs.contains("rule_id=3"), "missing rule_id: {logs}");
        assert!(
            logs.contains("request_id=req-diverge-poison"),
            "missing request_id: {logs}"
        );
        assert!(
            manager.audit_writer_degraded(),
            "poisoned emit_signer_set_diverged branch must mark manager degraded"
        );
    }

    // ── AuditWriterHealth tests ───────────────────────────────────────────────

    /// `mark_audit_writer_degraded` delegates to the health field and propagates
    /// via `health_handle()`.
    ///
    /// Verifies that after the `Arc<AtomicBool>` → `AuditWriterHealth` migration:
    /// 1. A freshly constructed manager reports `audit_writer_degraded() == false`.
    /// 2. Calling `mark_audit_writer_degraded()` transitions to `true`.
    /// 3. A handle obtained via `health_handle()` reflects the same flag.
    /// 4. Calling `mark_audit_writer_degraded()` again is idempotent.
    #[test]
    fn mark_audit_writer_degraded_delegates_to_health_and_reflects_in_handle() {
        let (manager, _dir) = make_manager_with_poisoned_writer();

        // Before any mark: handle and manager agree on non-degraded.
        let handle = manager.health_handle();
        assert!(
            !manager.audit_writer_degraded(),
            "pre-mark: manager must be non-degraded"
        );
        assert!(
            !handle.is_degraded(),
            "pre-mark: health_handle must be non-degraded"
        );

        // Mark degraded once.
        manager.mark_audit_writer_degraded();

        assert!(
            manager.audit_writer_degraded(),
            "post-mark: manager must be degraded"
        );
        assert!(
            handle.is_degraded(),
            "post-mark: health_handle must reflect degraded state"
        );

        // Idempotent: second call must not panic or change state.
        manager.mark_audit_writer_degraded();
        assert!(
            manager.audit_writer_degraded(),
            "idempotent: still degraded"
        );
    }

    /// A health handle obtained before the first `mark_audit_writer_degraded`
    /// call correctly reflects the flag change made through `mark_audit_writer_degraded`.
    ///
    /// This verifies the Arc-sharing semantics of the `AuditWriterHealth` +
    /// `AuditWriterHealthHandle` pair: a handle obtained before any mark call
    /// correctly observes the flag change made through the owner.
    #[test]
    fn health_handle_reflects_mark_from_manager() {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None)
                .expect("AuditWriter::open must succeed"),
        ));
        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:1".to_owned(),
            Arc::clone(&audit_writer),
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(1),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager construction must succeed");

        let h1 = manager.health_handle();
        let h2 = h1.clone();

        assert!(!h1.is_degraded(), "initial: h1 non-degraded");
        assert!(!h2.is_degraded(), "initial: h2 non-degraded");
        assert!(
            !manager.audit_writer_degraded(),
            "initial: manager non-degraded"
        );

        // Mark through the manager method.
        manager.mark_audit_writer_degraded();

        // Both handles and the manager must observe the change.
        assert!(manager.audit_writer_degraded(), "manager sees degraded");
        assert!(h1.is_degraded(), "h1 sees degraded");
        assert!(h2.is_degraded(), "h2 sees degraded");
    }

    /// A handle obtained from `health_handle()` can mark degraded and the manager
    /// observes the change.
    #[test]
    fn health_handle_mark_reflects_in_manager() {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None)
                .expect("AuditWriter::open must succeed"),
        ));
        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:1".to_owned(),
            Arc::clone(&audit_writer),
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(1),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager construction must succeed");

        let handle = manager.health_handle();
        assert!(
            !manager.audit_writer_degraded(),
            "initial: manager non-degraded"
        );

        // Mark through the handle.
        handle.mark_degraded();

        // Manager observes the change.
        assert!(
            manager.audit_writer_degraded(),
            "manager must observe mark from health_handle"
        );
    }

    #[test]
    fn post_op_invariant_allows_add_signer_raising_count() {
        // 2-of-3, adding a 4th signer → 2-of-4 (threshold unchanged).
        let result = compute_post_op_invariant(
            1,
            4, // post_op_signer_count
            2, // current_threshold
            2, // effective_threshold (unchanged)
            ThresholdAffectingOp::AddSigner {
                signer_type: "ed25519".to_owned(),
                signer_id: None,
            },
            "CDABC...12345",
            "req-1",
        );
        assert!(
            result.is_ok(),
            "2-of-4 after add should be valid: {result:?}"
        );
    }

    // ── decode_signer_scval ───────────────────────────────────────────────────

    #[test]
    fn decode_signer_scval_delegated_ed25519() {
        // Build a ScVal::Vec([Symbol("Delegated"), Address(Account(pubkey))]).
        use stellar_xdr::{AccountId, ScAddress, ScSymbol, ScVec, Uint256};
        let pubkey = [0x42u8; 32];
        let addr = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pubkey)),
        )));
        let sym = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));

        let pk = decode_signer_scval(&vec_val);
        assert!(pk.is_some(), "should decode Delegated signer");
        assert_eq!(pk.unwrap(), SignerPubkey::Ed25519 { pubkey });
    }

    #[test]
    fn build_delegated_signer_scval_matches_known_xdr_fixture() {
        use stellar_xdr::{Limits, WriteXdr};

        let val = build_delegated_signer_scval(SIMULATE_SENTINEL_G).unwrap();
        let xdr = val.to_xdr(Limits::none()).unwrap();
        let expected = hex::decode(
            "0000001000000001000000020000000f0000000944656c6567617465640000000000001200000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        assert_eq!(xdr, expected);
        assert_eq!(
            decode_signer_scval(&val),
            Some(SignerPubkey::Ed25519 { pubkey: [0; 32] })
        );
    }

    #[test]
    fn decode_signer_scval_unknown_tag_returns_none() {
        use stellar_xdr::{AccountId, ScAddress, ScSymbol, ScVec, Uint256};
        let sym = ScVal::Symbol(ScSymbol::try_from("UnknownTag").unwrap());
        let addr = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])),
        )));
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));
        assert!(
            decode_signer_scval(&vec_val).is_none(),
            "unknown tag must return None"
        );
    }

    // ── pubkeys_first8 ────────────────────────────────────────────────────────

    #[test]
    fn pubkeys_first8_returns_one_per_pubkey() {
        let pks = vec![
            SignerPubkey::Ed25519 {
                pubkey: [0xabu8; 32],
            },
            SignerPubkey::WebAuthn {
                credential_id_first16: [0xccu8; 16],
            },
        ];
        let first8 = pubkeys_first8(&pks);
        assert_eq!(first8.len(), 2, "must produce one entry per pubkey");
        // Each is a non-empty hex string.
        for s in &first8 {
            assert!(!s.is_empty(), "first8 entry must not be empty");
        }
    }

    // ── rule_mutex_acquire ────────────────────────────────────────────────────

    #[test]
    fn rule_mutex_acquire_same_key_returns_same_arc() {
        let path = std::path::PathBuf::from("/tmp/test-audit.jsonl");
        let arc1 = rule_mutex_acquire(&path, 1, "CDABC...12345");
        let arc2 = rule_mutex_acquire(&path, 1, "CDABC...12345");
        // Same Arc for same key.
        assert!(
            Arc::ptr_eq(&arc1, &arc2),
            "same key must return the same Arc"
        );
    }

    #[test]
    fn rule_mutex_acquire_different_rule_id_returns_different_arc() {
        let path = std::path::PathBuf::from("/tmp/test-audit-2.jsonl");
        let arc1 = rule_mutex_acquire(&path, 10, "CDABC...12345");
        let arc2 = rule_mutex_acquire(&path, 11, "CDABC...12345");
        assert!(
            !Arc::ptr_eq(&arc1, &arc2),
            "different rule_id must return different Arc"
        );
    }

    // ── fetch_contract_wasm_hashes ──────────────────────────────────────────────

    /// `fetch_contract_wasm_hashes` must return a Vec aligned with the input
    /// `keys` slice by position, not by the order entries happen to arrive
    /// in the `getLedgerEntries` response.
    ///
    /// Test strategy: build two distinct `LedgerKey`s (A, B), issue a mock
    /// response where entry B arrives BEFORE entry A (reversed order), and
    /// assert the returned `Vec<Option<[u8; 32]>>` is `[Some(hash_A), Some(hash_B)]`
    /// (position-aligned with the input), not `[Some(hash_B), Some(hash_A)]`.
    ///
    /// Implements the position-alignment contract: each result index maps to the same
    /// input key index regardless of response ordering from the RPC server.
    #[tokio::test]
    async fn fetch_contract_wasm_hashes_aligns_responses_by_key() {
        use stellar_agent_test_support::echo_id_responder::EchoIdResponder;
        use stellar_xdr::{
            ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId,
            ExtensionPoint, Hash, LedgerEntryData, LedgerKey, LedgerKeyContractData, Limits,
            ScAddress, ScContractInstance, ScVal, WriteXdr,
        };
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        // Build two deterministic contract-instance LedgerKey XDR values.
        // Key A: contract address with all-0x11 hash bytes.
        // Key B: contract address with all-0x22 hash bytes.
        //
        // stellar-xdr 27: ScAddress::Contract takes ContractId(Hash(...))
        // (ContractId is a newtype over Hash introduced in Protocol-22).
        let addr_a = ScAddress::Contract(ContractId(Hash([0x11u8; 32])));
        let addr_b = ScAddress::Contract(ContractId(Hash([0x22u8; 32])));

        let make_ledger_key = |addr: ScAddress| {
            LedgerKey::ContractData(LedgerKeyContractData {
                contract: addr,
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
            })
        };

        let key_a = make_ledger_key(addr_a);
        let key_b = make_ledger_key(addr_b);

        // Encode keys to base64 XDR (the format used by `getLedgerEntries`).
        let key_a_b64 = key_a
            .to_xdr_base64(Limits::none())
            .expect("key_a must encode");
        let key_b_b64 = key_b
            .to_xdr_base64(Limits::none())
            .expect("key_b must encode");

        // Build wasm hashes: hash_a = [0xaa; 32], hash_b = [0xbb; 32].
        let hash_a = [0xaau8; 32];
        let hash_b = [0xbbu8; 32];

        // Build LedgerEntryData::ContractData(ContractInstance{Wasm(hash)}) XDR.
        // stellar-xdr 27: ScVal::ContractInstance takes ScContractInstance directly
        // (not Box<ScContractInstance>).
        let make_contract_instance_xdr = |wasm_hash: [u8; 32]| -> String {
            let instance = ScContractInstance {
                executable: ContractExecutable::Wasm(Hash(wasm_hash)),
                storage: None,
            };
            let data = LedgerEntryData::ContractData(ContractDataEntry {
                ext: ExtensionPoint::V0,
                contract: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                key: ScVal::LedgerKeyContractInstance,
                durability: ContractDataDurability::Persistent,
                val: ScVal::ContractInstance(instance),
            });
            data.to_xdr_base64(Limits::none()).expect("must encode")
        };

        let entry_a_xdr = make_contract_instance_xdr(hash_a);
        let entry_b_xdr = make_contract_instance_xdr(hash_b);

        // Mock server: returns entries for B FIRST, then A (reversed from request order).
        // This tests that the alignment logic uses key matching, not response order.
        // EchoIdResponder copies the JSON-RPC request `id` into the response so
        // jsonrpsee-http-client accepts the reply (it validates id parity).
        let mock_server = MockServer::start().await;
        let result_payload = serde_json::json!({
            "entries": [
                {
                    "key": key_b_b64,
                    "xdr": entry_b_xdr,
                    "lastModifiedLedgerSeq": 100
                },
                {
                    "key": key_a_b64,
                    "xdr": entry_a_xdr,
                    "lastModifiedLedgerSeq": 100
                }
            ],
            "latestLedger": 1000
        });
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result_payload))
            .mount(&mock_server)
            .await;

        let client = stellar_agent_network::StellarRpcClient::new(&mock_server.uri())
            .expect("client must init with mock server URI");

        // Request in order [A, B]; response arrives in order [B, A].
        let keys = vec![key_a.clone(), key_b.clone()];
        let result = fetch_contract_wasm_hashes(&client, &keys)
            .await
            .expect("fetch must succeed against mock");

        assert_eq!(result.len(), 2, "result length must equal key count");
        // Position 0 → key_a → hash_a, even though the response had B first.
        assert_eq!(
            result[0],
            Some(hash_a),
            "position 0 must align with key_a hash (alignment regression)"
        );
        // Position 1 → key_b → hash_b.
        assert_eq!(
            result[1],
            Some(hash_b),
            "position 1 must align with key_b hash (alignment regression)"
        );
    }

    // ── Property test: compute_post_op_invariant ─────────────────────────────
    //
    // For random (signer_count, threshold) pairs in 1..=15, assert that
    // compute_post_op_invariant produces Ok iff
    // 1 <= threshold' <= signer_count' && signer_count' <= MAX_SIGNERS (15).

    proptest::proptest! {
        /// Property: `compute_post_op_invariant` returns `Ok` exactly when the
        /// post-op `(signer_count, threshold)` satisfies the invariant
        /// `1 <= threshold <= signer_count <= MAX_SIGNERS`.
        #[test]
        fn prop_post_op_invariant_remove_signer(
            signer_count in 1u32..=MAX_SIGNERS,
            threshold in 1u32..=MAX_SIGNERS,
        ) {
            // Bound threshold to be ≤ signer_count (valid pre-state).
            let threshold = threshold.min(signer_count);
            // Post-op signer count after a remove: signer_count - 1.
            let post_op_count = signer_count.saturating_sub(1);
            let result = compute_post_op_invariant(
                1, // rule_id
                post_op_count,
                threshold,
                threshold, // effective_threshold unchanged (no atomic decrement)
                ThresholdAffectingOp::RemoveSigner { signer_id: 0 },
                "CDABC...12345",
                "prop-req",
            );
            // Remove is valid iff post_op_count >= 1 AND threshold <= post_op_count.
            let should_succeed = post_op_count >= 1 && threshold <= post_op_count;
            proptest::prop_assert_eq!(
                result.is_ok(),
                should_succeed,
                "remove signer_count={} threshold={} post_op={}: expected ok={}, got {:?}",
                signer_count, threshold, post_op_count, should_succeed, result
            );
        }

        /// Property: `compute_post_op_invariant` for `SetThreshold` returns `Ok`
        /// exactly when `1 <= new_threshold <= signer_count && signer_count <= MAX_SIGNERS`.
        #[test]
        fn prop_post_op_invariant_set_threshold(
            signer_count in 1u32..=MAX_SIGNERS,
            threshold in 1u32..=MAX_SIGNERS,
            new_threshold in 0u32..=16u32,
        ) {
            let threshold = threshold.min(signer_count);
            let result = compute_post_op_invariant(
                1,
                signer_count,
                threshold,
                new_threshold,
                ThresholdAffectingOp::SetThreshold { new: new_threshold },
                "CDABC...12345",
                "prop-req",
            );
            // SetThreshold is valid iff 1 <= new_threshold <= signer_count.
            let should_succeed = new_threshold >= 1 && new_threshold <= signer_count;
            proptest::prop_assert_eq!(
                result.is_ok(),
                should_succeed,
                "set_threshold signer_count={} threshold={} new_threshold={}: expected ok={}, got {:?}",
                signer_count, threshold, new_threshold, should_succeed, result
            );
        }
    }

    // ── Cross-impl WASM-hash parity gate ─────────────────────────────────────

    /// Asserts that `fetch_contract_wasm_hash` (the shared network primitive, also
    /// used by `fetch_observed_wasm_hash`) and
    /// `fetch_contract_wasm_hashes` (the multi-key batch primitive used by
    /// `identify_threshold_policy`) extract an IDENTICAL 32-byte WASM hash from
    /// the SAME shared fixture bytes.
    ///
    /// Both parsers decode the same `LedgerEntryData` XDR blob produced by
    /// `stellar_agent_test_support::xdr_fixtures::contract_instance_ledger_entries_json`
    /// and must agree on the extracted 32-byte hash.
    ///
    /// # Coverage
    ///
    /// - **Match** case: a shared `[0xde; 32]` WASM hash that both parsers
    ///   accept and agree on (this function).
    /// - **Non-Wasm / SAC** case: a `ContractExecutable::StellarAsset` instance
    ///   (verified at `stellar-xdr-27/src/curr/generated.rs:11616-11618`);
    ///   the network primitive returns `WasmHashFetch::Sac` and the multi-key
    ///   primitive returns `None` — both agree "not a plain WASM hash"
    ///   (`wasm_hash_parse_parity_network_vs_smart_account_sac`).
    ///
    /// The remaining nominal variants — `Divergent` (two-RPC disagreement) and
    /// `Unavailable` (fetch error) — are covered at the shared network-primitive
    /// level by `wasm_hash.rs` unit tests; `fetch_observed_wasm_hash` maps those
    /// errors to `SaError::NetworkRpcDivergence` / `SaError::DeploymentFailed`.
    ///
    /// If this test fails after a parser change in either crate, the unification
    /// in `fetch_observed_wasm_hash` must be revisited before sealing.
    #[tokio::test]
    async fn wasm_hash_parse_parity_network_vs_smart_account() {
        use stellar_agent_network::WasmHashFetch;
        use stellar_agent_network::fetch_contract_wasm_hash;
        use stellar_agent_test_support::echo_id_responder::EchoIdResponder;
        use stellar_agent_test_support::xdr_fixtures::contract_instance_ledger_entries_json;
        use stellar_xdr::{
            ContractDataDurability, ContractId, Hash, LedgerKey, LedgerKeyContractData, ScAddress,
            ScVal,
        };
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        // Shared test contract and WASM hash — same values used in network
        // crate wasm_hash.rs tests so any cross-test drift is immediately visible.
        const TEST_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let shared_hash = [0xdeu8; 32];

        // Build the shared JSON-RPC fixture using the test-support helper.
        // This produces the same XDR bytes that both parsers must agree on.
        let fixture_json = contract_instance_ledger_entries_json(TEST_CONTRACT, shared_hash);
        let fixture_result: serde_json::Value =
            serde_json::from_str(&fixture_json).expect("fixture is valid JSON");
        let result_payload = fixture_result["result"].clone();

        // Build the LedgerKey for the smart-account parser — mirrors
        // `contract_instance_key` in rules.rs and `contract_instance_ledger_key`
        // in network/wasm_hash.rs.
        let contract = stellar_strkey::Contract::from_string(TEST_CONTRACT)
            .expect("TEST_CONTRACT is a valid C-strkey");
        let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_addr,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });

        // ── Path A: network primitive ────────────────────────────────────────
        // `fetch_contract_wasm_hash` — single-RPC, no secondary.
        let server_a = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result_payload.clone()))
            .mount(&server_a)
            .await;
        let client_a =
            stellar_agent_network::StellarRpcClient::new(&server_a.uri()).expect("client_a");

        let network_result = fetch_contract_wasm_hash(&client_a, None, TEST_CONTRACT)
            .await
            .expect("network primitive must succeed on valid fixture");

        let network_hash = match network_result {
            WasmHashFetch::Wasm(h) => h,
            other => panic!("network primitive returned unexpected variant: {other:?}"),
        };

        // ── Path B: smart-account primitive ─────────────────────────────────
        // `fetch_contract_wasm_hashes` — same fixture, same XDR bytes.
        let server_b = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result_payload))
            .mount(&server_b)
            .await;
        let client_b =
            stellar_agent_network::StellarRpcClient::new(&server_b.uri()).expect("client_b");

        let sa_results = fetch_contract_wasm_hashes(&client_b, &[ledger_key])
            .await
            .expect("smart-account primitive must succeed on valid fixture");

        let sa_hash =
            sa_results.into_iter().next().flatten().expect(
                "smart-account primitive must return Some(hash) for a WASM contract fixture",
            );

        // ── Parity assertion ─────────────────────────────────────────────────
        // Both parsers MUST extract the same 32-byte WASM hash from the same
        // fixture XDR bytes.  A divergence here means the two codepaths have
        // drifted in their `LedgerEntryData` parsing logic.
        assert_eq!(
            network_hash,
            sa_hash,
            "WASM-hash parse DRIFT between network primitive and smart-account \
             primitive on shared fixture bytes: network={:?} sa={:?}",
            &network_hash[..8],
            &sa_hash[..8],
        );

        // Both extracted values must also equal the fixture's known hash.
        assert_eq!(
            network_hash, shared_hash,
            "network primitive extracted unexpected hash from fixture"
        );
        assert_eq!(
            sa_hash, shared_hash,
            "smart-account primitive extracted unexpected hash from fixture"
        );
    }

    /// Asserts that both `fetch_contract_wasm_hash` (network primitive) and
    /// `fetch_contract_wasm_hashes` (smart-account primitive) correctly handle
    /// a `ContractExecutable::StellarAsset` instance — the most drift-prone
    /// parse divergence, since one parser could treat a SAC differently from
    /// the other.
    ///
    /// The fixture is a `getLedgerEntries` response whose `executable` field is
    /// `ContractExecutable::StellarAsset` (verified at
    /// `stellar-xdr-27/src/curr/generated.rs:11616-11618`).  Both parsers
    /// must agree it is NOT a plain WASM hash:
    ///
    /// - **Network primitive** (`fetch_contract_wasm_hash`) → `WasmHashFetch::Sac`
    /// - **Smart-account primitive** (`fetch_contract_wasm_hashes`) → `None` for
    ///   that entry (the Wasm-only match arm in `signers.rs:2713-2718` does not
    ///   fire for `StellarAsset`; the entry is absent from `hash_by_key_pos`;
    ///   the aligned-result vector yields `None`).
    ///
    /// This is the "non-Wasm / SAC" case in the `# Coverage` block of
    /// `wasm_hash_parse_parity_network_vs_smart_account`.  It is a sibling test
    /// rather than an additional arm of the parent so that failure isolation
    /// is precise.
    #[tokio::test]
    async fn wasm_hash_parse_parity_network_vs_smart_account_sac() {
        use stellar_agent_network::WasmHashFetch;
        use stellar_agent_network::fetch_contract_wasm_hash;
        use stellar_agent_test_support::echo_id_responder::EchoIdResponder;
        use stellar_agent_test_support::xdr_fixtures::sac_instance_ledger_entries_json;
        use stellar_xdr::{
            ContractDataDurability, ContractId, Hash, LedgerKey, LedgerKeyContractData, ScAddress,
            ScVal,
        };
        use wiremock::{
            Mock, MockServer,
            matchers::{method, path},
        };

        const TEST_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

        // Build the SAC fixture: a contract instance whose executable is
        // ContractExecutable::StellarAsset (not Wasm).
        // Verified at stellar-xdr-27/src/curr/generated.rs:11616-11618:
        //   pub enum ContractExecutable { Wasm(Hash), StellarAsset }
        let fixture_json = sac_instance_ledger_entries_json(TEST_CONTRACT);
        let fixture_result: serde_json::Value =
            serde_json::from_str(&fixture_json).expect("fixture is valid JSON");
        let result_payload = fixture_result["result"].clone();

        // Build the LedgerKey so the smart-account parser can match by position.
        let contract = stellar_strkey::Contract::from_string(TEST_CONTRACT)
            .expect("TEST_CONTRACT is a valid C-strkey");
        let sc_addr = ScAddress::Contract(ContractId(Hash(contract.0)));
        let ledger_key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: sc_addr,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });

        // ── Path A: network primitive ────────────────────────────────────────
        // Expected: WasmHashFetch::Sac — the explicit SAC tri-state variant.
        let server_a = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result_payload.clone()))
            .mount(&server_a)
            .await;
        let client_a =
            stellar_agent_network::StellarRpcClient::new(&server_a.uri()).expect("client_a");

        let network_result = fetch_contract_wasm_hash(&client_a, None, TEST_CONTRACT)
            .await
            .expect("network primitive must succeed on SAC fixture");

        assert!(
            matches!(network_result, WasmHashFetch::Sac),
            "network primitive must return WasmHashFetch::Sac for a SAC fixture; \
             got {network_result:?}"
        );

        // ── Path B: smart-account primitive ─────────────────────────────────
        // Expected: None — the Wasm-only match arm does not fire for StellarAsset;
        // the entry is absent from hash_by_key_pos; aligned result is None.
        // signers.rs:2713-2718:
        //   if let LedgerEntryData::ContractData(cd) = &entry_data
        //      && let ScVal::ContractInstance(instance) = &cd.val
        //      && let ContractExecutable::Wasm(Hash(bytes)) = &instance.executable
        //   { hash_by_key_pos.insert(pos, *bytes); }
        let server_b = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(result_payload))
            .mount(&server_b)
            .await;
        let client_b =
            stellar_agent_network::StellarRpcClient::new(&server_b.uri()).expect("client_b");

        let sa_results = fetch_contract_wasm_hashes(&client_b, &[ledger_key])
            .await
            .expect("smart-account primitive must succeed on SAC fixture");

        let sa_entry = sa_results
            .into_iter()
            .next()
            .expect("smart-account primitive must return one entry for one key");

        assert!(
            sa_entry.is_none(),
            "smart-account primitive must return None for a SAC fixture \
             (Wasm-only match arm does not fire); got {sa_entry:?}"
        );

        // ── Agreement assertion ──────────────────────────────────────────────
        // Both parsers agree: this is NOT a plain WASM hash.
        // Network → Sac (explicit); smart-account → None (Wasm arm skipped).
        // Neither returns a 32-byte hash, confirming no false-positive extraction.
    }

    // ── extract_u32_return ────────────────────────────────────────────────────

    /// `extract_u32_return` must return `Ok(n)` for `ScVal::U32(n)`.
    #[test]
    fn extract_u32_return_ok_for_u32_scval() {
        let val = ScVal::U32(42);
        let result = extract_u32_return(&val, "add_signer");
        assert_eq!(result.unwrap(), 42, "ScVal::U32(42) must extract to 42");
    }

    /// `extract_u32_return` must return `Err(SaError::DeploymentFailed)` for any
    /// non-U32 ScVal.  The error message must mention the `context` argument so
    /// operators can triage which call site produced the error.
    #[test]
    fn extract_u32_return_err_for_non_u32_scval() {
        let val = ScVal::Void;
        let result = extract_u32_return(&val, "add_signer");
        match result {
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) => {
                assert_eq!(phase, "simulate", "phase must be 'simulate'");
                assert!(
                    redacted_reason.contains("add_signer"),
                    "reason must contain context: {redacted_reason}"
                );
            }
            other => panic!("expected DeploymentFailed, got: {other:?}"),
        }
    }

    /// `extract_u32_return` error path: `ScVal::Bool` (another non-U32 variant)
    /// also returns `DeploymentFailed`.
    #[test]
    fn extract_u32_return_err_for_bool_scval() {
        let val = ScVal::Bool(true);
        let result = extract_u32_return(&val, "remove_signer");
        assert!(
            matches!(result, Err(SaError::DeploymentFailed { .. })),
            "ScVal::Bool must trigger DeploymentFailed"
        );
    }

    // ── build_external_signer_scval ───────────────────────────────────────────

    /// `build_external_signer_scval` must produce a `ScVal::Vec` with three
    /// elements: `Symbol("External")`, `Address(verifier)`, `Bytes(key_data)`.
    ///
    /// The expected XDR structure is per the OZ `Signer` contracttype:
    /// `External(Address, Bytes)` → `ScVal::Vec([Symbol("External"), Address(verifier), Bytes(key_data)])`.
    /// We verify this by decoding the produced ScVal with `decode_signer_scval_full`
    /// and asserting byte-exact equality on the extracted `key_data`.
    #[test]
    fn build_external_signer_scval_round_trips_via_decode() {
        use stellar_xdr::{ContractId, Hash, ScAddress};

        // A known verifier C-strkey (all-0x77 contract bytes).
        let verifier_sc_addr = ScAddress::Contract(ContractId(Hash([0x77u8; 32])));
        // key_data: 65-byte fake WebAuthn public key concatenated with 16-byte credential ID.
        let key_data: Vec<u8> = (0u8..81).collect();

        let val = build_external_signer_scval(verifier_sc_addr, &key_data)
            .expect("build_external_signer_scval must succeed for valid inputs");

        // The produced ScVal must decode via decode_signer_scval_full to External.
        let decoded = decode_signer_scval_full(&val)
            .expect("decode_signer_scval_full must return Some for a well-formed External ScVal");

        match decoded {
            DecodedOnChainSigner::External {
                verifier_strkey,
                key_data: decoded_key,
            } => {
                // The verifier strkey must be the canonical encoding of the all-0x77 hash.
                // Use format!("{}", ...) to obtain a std::string::String (stellar_strkey
                // Display produces a heapless::String via to_string(), which does not
                // impl PartialEq<std::string::String> directly).
                let expected_strkey = format!("{}", stellar_strkey::Contract([0x77u8; 32]));
                assert_eq!(
                    verifier_strkey, expected_strkey,
                    "verifier_strkey must match canonical C-strkey encoding"
                );
                // The key_data must be byte-exact (not truncated at this level).
                assert_eq!(decoded_key, key_data, "decoded key_data must be byte-exact");
            }
            DecodedOnChainSigner::Delegated { .. } => {
                panic!("expected External variant, got Delegated")
            }
        }
    }

    /// `build_external_signer_scval` with empty `key_data` must succeed.
    /// The OZ contract does not forbid zero-length key_data at encoding time.
    #[test]
    fn build_external_signer_scval_empty_key_data_succeeds() {
        use stellar_xdr::{ContractId, Hash, ScAddress};

        let verifier_sc_addr = ScAddress::Contract(ContractId(Hash([0x33u8; 32])));
        let result = build_external_signer_scval(verifier_sc_addr, &[]);
        assert!(
            result.is_ok(),
            "build_external_signer_scval with empty key_data must succeed"
        );
        // Verify the decoded form has an empty key blob.
        let decoded = decode_signer_scval_full(&result.unwrap()).unwrap();
        if let DecodedOnChainSigner::External { key_data, .. } = decoded {
            assert!(key_data.is_empty(), "decoded key_data must be empty");
        } else {
            panic!("expected External variant");
        }
    }

    // ── decode_signer_scval_full ──────────────────────────────────────────────

    /// `decode_signer_scval_full` must return `None` for a non-Vec ScVal.
    #[test]
    fn decode_signer_scval_full_returns_none_for_non_vec() {
        assert!(
            decode_signer_scval_full(&ScVal::Void).is_none(),
            "ScVal::Void must return None"
        );
        assert!(
            decode_signer_scval_full(&ScVal::U32(1)).is_none(),
            "ScVal::U32 must return None"
        );
    }

    /// `decode_signer_scval_full` must return `None` for a Vec with fewer than
    /// 2 elements (minimum required: tag + at least one payload field).
    #[test]
    fn decode_signer_scval_full_returns_none_for_short_vec() {
        use stellar_xdr::{ScSymbol, ScVec};

        // Empty vec.
        let empty = ScVal::Vec(Some(ScVec(VecM::try_from(vec![]).unwrap())));
        assert!(
            decode_signer_scval_full(&empty).is_none(),
            "empty Vec must return None"
        );

        // Vec with exactly 1 element (symbol only, no payload).
        let sym = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let one_elem = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym]).unwrap())));
        assert!(
            decode_signer_scval_full(&one_elem).is_none(),
            "1-element Vec must return None"
        );
    }

    /// `decode_signer_scval_full` must return `None` when the first element is
    /// not a Symbol (unknown tag type).
    #[test]
    fn decode_signer_scval_full_returns_none_when_first_elem_not_symbol() {
        use stellar_xdr::ScVec;

        let elem0 = ScVal::U32(42); // not a Symbol
        let elem1 = ScVal::U32(0);
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![elem0, elem1]).unwrap())));
        assert!(
            decode_signer_scval_full(&vec_val).is_none(),
            "non-Symbol first element must return None"
        );
    }

    /// `decode_signer_scval_full` must return `None` for the `External` variant
    /// when fewer than 3 elements are present (missing `Bytes` payload).
    #[test]
    fn decode_signer_scval_full_external_returns_none_for_two_elem_vec() {
        use stellar_xdr::{AccountId, ScAddress, ScSymbol, ScVec, Uint256};

        let sym = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        // Provide Address but omit Bytes — 2-element External vec.
        let addr = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])),
        )));
        let two_elem = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));
        assert!(
            decode_signer_scval_full(&two_elem).is_none(),
            "2-element External vec must return None (missing Bytes)"
        );
    }

    /// `decode_signer_scval_full` must return `None` for `Delegated` when the
    /// second element is not a `ScAddress::Account` (e.g. a Contract address).
    #[test]
    fn decode_signer_scval_full_delegated_non_account_address_returns_none() {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScSymbol, ScVec};

        let sym = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        // Contract address (not Account) — invalid for Delegated.
        let addr = ScVal::Address(ScAddress::Contract(ContractId(Hash([0x11u8; 32]))));
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));
        assert!(
            decode_signer_scval_full(&vec_val).is_none(),
            "Delegated with Contract address must return None"
        );
    }

    /// `decode_signer_scval_full` for `External` must return `None` when the
    /// third element is not `ScVal::Bytes`.
    #[test]
    fn decode_signer_scval_full_external_non_bytes_payload_returns_none() {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScSymbol, ScVec};

        let sym = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let addr = ScVal::Address(ScAddress::Contract(ContractId(Hash([0x22u8; 32]))));
        let not_bytes = ScVal::U32(99); // wrong type for key_data slot
        let vec_val = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![sym, addr, not_bytes]).unwrap(),
        )));
        assert!(
            decode_signer_scval_full(&vec_val).is_none(),
            "External with non-Bytes third element must return None"
        );
    }

    /// `decode_signer_scval_full` for `External` must return `None` when the
    /// second element is not an `ScVal::Address` (e.g. a U32).
    #[test]
    fn decode_signer_scval_full_external_non_address_second_elem_returns_none() {
        use stellar_xdr::{ScBytes, ScSymbol, ScVec};

        let sym = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let not_addr = ScVal::U32(7); // wrong type for verifier slot
        let bytes = ScVal::Bytes(ScBytes(vec![0x01, 0x02].try_into().unwrap()));
        let vec_val = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![sym, not_addr, bytes]).unwrap(),
        )));
        assert!(
            decode_signer_scval_full(&vec_val).is_none(),
            "External with non-Address second element must return None"
        );
    }

    // ── decode_context_rule_scval ─────────────────────────────────────────────

    /// `decode_context_rule_scval` must return `Err(DeploymentFailed)` for a
    /// non-Map ScVal.  The contract guarantees that `get_context_rule` only ever
    /// returns a `ScVal::Map`; any other value is a parse error.
    #[test]
    fn decode_context_rule_scval_non_map_returns_err() {
        let result = decode_context_rule_scval(ScVal::Void);
        match result {
            Err(SaError::DeploymentFailed { phase, .. }) => {
                assert_eq!(phase, "simulate");
            }
            Ok(_) => panic!("expected Err(DeploymentFailed), got Ok"),
            Err(e) => panic!("expected DeploymentFailed, got different error: {e}"),
        }
    }

    /// `decode_context_rule_scval` must return `Err` when the 'id' field is
    /// absent from the map.  This verifies the `ok_or_else` guard that prevents
    /// a malformed on-chain return value from silently producing a rule with id=0.
    #[test]
    fn decode_context_rule_scval_missing_id_field_returns_err() {
        use stellar_xdr::{ScMap, ScMapEntry, ScSymbol, ScVec};

        // Build a map WITHOUT an "id" key, but with a "signers" and "signer_ids" key.
        let signers_key = ScVal::Symbol(ScSymbol::try_from("signers").unwrap());
        let signers_val = ScVal::Vec(Some(ScVec(VecM::default())));
        let signer_ids_key = ScVal::Symbol(ScSymbol::try_from("signer_ids").unwrap());
        let signer_ids_val = ScVal::Vec(Some(ScVec(VecM::default())));

        let map_entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: signer_ids_key,
                val: signer_ids_val,
            },
            ScMapEntry {
                key: signers_key,
                val: signers_val,
            },
        ];
        let sc_map = ScMap(map_entries.try_into().unwrap());
        let val = ScVal::Map(Some(sc_map));

        let result = decode_context_rule_scval(val);
        match result {
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) => {
                assert_eq!(phase, "simulate");
                assert!(
                    redacted_reason.contains("missing 'id'"),
                    "error must mention missing 'id': {redacted_reason}"
                );
            }
            Ok(_) => panic!("expected Err(DeploymentFailed) for missing id, got Ok"),
            Err(e) => panic!("expected DeploymentFailed for missing id, got: {e}"),
        }
    }

    /// `decode_context_rule_scval` must correctly parse the `policy_ids` key
    /// as well as the `policies` key (both map to `policies` in the decoded result).
    ///
    /// The OZ `ContextRule` struct uses `policy_ids` in some contract versions
    /// and `policies` in others; both must be accepted.
    #[test]
    fn decode_context_rule_scval_accepts_policy_ids_key() {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVec};

        // Build a policy address to include.
        let policy_addr = ScAddress::Contract(ContractId(Hash([0x55u8; 32])));

        let id_key = ScVal::Symbol(ScSymbol::try_from("id").unwrap());
        let id_val = ScVal::U32(3);
        let policy_ids_key = ScVal::Symbol(ScSymbol::try_from("policy_ids").unwrap());
        let policy_ids_val = ScVal::Vec(Some(ScVec(
            vec![ScVal::Address(policy_addr.clone())]
                .try_into()
                .unwrap(),
        )));
        let signers_key = ScVal::Symbol(ScSymbol::try_from("signers").unwrap());
        let signers_val = ScVal::Vec(Some(ScVec(VecM::default())));
        let signer_ids_key = ScVal::Symbol(ScSymbol::try_from("signer_ids").unwrap());
        let signer_ids_val = ScVal::Vec(Some(ScVec(VecM::default())));

        let map_entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: id_key,
                val: id_val,
            },
            ScMapEntry {
                key: policy_ids_key,
                val: policy_ids_val,
            },
            ScMapEntry {
                key: signer_ids_key,
                val: signer_ids_val,
            },
            ScMapEntry {
                key: signers_key,
                val: signers_val,
            },
        ];
        let sc_map = ScMap(map_entries.try_into().unwrap());
        let val = ScVal::Map(Some(sc_map));

        let rule = decode_context_rule_scval(val).expect("must succeed with policy_ids key");
        assert_eq!(rule.id, 3, "rule.id must be 3");
        assert_eq!(rule.policies.len(), 1, "policies must have one entry");
        assert_eq!(rule.policies[0], policy_addr, "policy address must match");
    }

    /// `decode_context_rule_scval` must silently skip unknown signer ScVals
    /// (via `decode_signer_scval` returning `None`) and only include decodable signers
    /// in the resulting `signers` vec.
    ///
    /// OZ forward-compat: a future signer variant unknown to this client must not
    /// cause a parse failure — it is silently dropped.
    #[test]
    fn decode_context_rule_scval_skips_unknown_signer_scval() {
        use stellar_xdr::{AccountId, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVec, Uint256};

        let pubkey = [0xaau8; 32];
        let delegated_sym = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let delegated_addr = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pubkey)),
        )));
        let valid_signer = ScVal::Vec(Some(ScVec(
            vec![delegated_sym, delegated_addr].try_into().unwrap(),
        )));

        // An unknown signer: ScVal::Void (decode_signer_scval returns None).
        let unknown_signer = ScVal::Void;

        let id_key = ScVal::Symbol(ScSymbol::try_from("id").unwrap());
        let id_val = ScVal::U32(7);
        let signer_ids_key = ScVal::Symbol(ScSymbol::try_from("signer_ids").unwrap());
        // Two signer_ids: [0, 1] — one for the valid signer, one for the unknown.
        let signer_ids_val = ScVal::Vec(Some(ScVec(
            vec![ScVal::U32(0), ScVal::U32(1)].try_into().unwrap(),
        )));
        let signers_key = ScVal::Symbol(ScSymbol::try_from("signers").unwrap());
        // signers vec: [valid_signer, unknown_signer]
        let signers_val = ScVal::Vec(Some(ScVec(
            vec![valid_signer, unknown_signer].try_into().unwrap(),
        )));

        let map_entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: id_key,
                val: id_val,
            },
            ScMapEntry {
                key: signer_ids_key,
                val: signer_ids_val,
            },
            ScMapEntry {
                key: signers_key,
                val: signers_val,
            },
        ];
        let sc_map = ScMap(map_entries.try_into().unwrap());
        let val = ScVal::Map(Some(sc_map));

        let rule = decode_context_rule_scval(val).expect("must succeed even with unknown signer");
        // Only the valid signer (index 0) must appear in the decoded signers list.
        // The unknown signer (index 1) is silently skipped by filter_map.
        assert_eq!(
            rule.signers.len(),
            1,
            "only valid signers must appear; unknown signer must be silently skipped"
        );
        assert_eq!(rule.signers[0].0, 0u32, "signer_id must be 0");
        assert_eq!(
            rule.signers[0].1,
            SignerPubkey::Ed25519 { pubkey },
            "signer pubkey must be the delegated key"
        );
    }

    // ── signer_pubkey_type_label ──────────────────────────────────────────────

    /// `signer_pubkey_type_label` must return distinct discriminant strings for
    /// each `SignerPubkey` variant used in production.
    ///
    /// The labels are embedded in `ThresholdUnreachable::requested_op::AddSigner::signer_type`
    /// error messages visible to operators; they must be stable.
    #[test]
    fn signer_pubkey_type_label_returns_correct_labels() {
        let ed25519 = SignerPubkey::Ed25519 { pubkey: [0u8; 32] };
        assert_eq!(signer_pubkey_type_label(&ed25519), "ed25519");

        let external = SignerPubkey::External {
            verifier_contract: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM"
                .to_owned(),
            key_data_first16: [0u8; 16],
        };
        assert_eq!(signer_pubkey_type_label(&external), "external");

        let webauthn = SignerPubkey::WebAuthn {
            credential_id_first16: [0u8; 16],
        };
        assert_eq!(signer_pubkey_type_label(&webauthn), "webauthn");
    }

    // ── SignersManagerConfig::new ─────────────────────────────────────────────

    /// `SignersManagerConfig::new` with identical primary/secondary URLs must
    /// succeed (not error); the function only emits a warning in that case.
    /// `SignersManager::new` built from this config must also succeed.
    #[test]
    fn signers_manager_config_same_url_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
        ));

        let config = SignersManagerConfig::new(
            "http://127.0.0.1:8000".to_owned(),
            "http://127.0.0.1:8000".to_owned(), // same as primary
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(10),
            "stellar:testnet".to_owned(),
        );
        // Config fields must reflect what was passed in.
        assert_eq!(config.primary_rpc_url, "http://127.0.0.1:8000");
        assert_eq!(config.secondary_rpc_url, "http://127.0.0.1:8000");
        assert_eq!(
            config.network_passphrase,
            "Test SDF Network ; September 2015"
        );
        assert_eq!(config.chain_id, "stellar:testnet");
        assert_eq!(config.profile_name, "test-profile");

        // Building a manager from this config must succeed.
        let manager = SignersManager::new(config).expect("manager construction must succeed");
        // Verify the chain_id accessor.
        assert_eq!(manager.chain_id(), "stellar:testnet");
    }

    // ── SignersManager::new error branch ──────────────────────────────────────

    /// `SignersManager::new` must return `Err(SaError::AuthEntryConstructionFailed)`
    /// when the primary RPC URL is not a valid HTTP/HTTPS URI.
    ///
    /// The error stage must be `"auth_payload"` and the reason must describe the
    /// failed URL construction.
    #[test]
    fn signers_manager_new_returns_err_for_invalid_primary_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
        ));

        let config = SignersManagerConfig::new(
            "not a valid url %%%".to_owned(), // invalid primary URL
            "http://127.0.0.1:8000".to_owned(),
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(10),
            "stellar:testnet".to_owned(),
        );
        let result = SignersManager::new(config);
        match result {
            Err(SaError::AuthEntryConstructionFailed { stage, .. }) => {
                assert_eq!(stage, "auth_payload", "error stage must be 'auth_payload'");
            }
            other => panic!("expected AuthEntryConstructionFailed, got: {other:?}"),
        }
    }

    // ── SignersManager::Debug ─────────────────────────────────────────────────

    /// `SignersManager`'s `Debug` impl must redact URLs and path, containing
    /// only the non-sensitive `profile_name` and `chain_id` fields.
    #[test]
    fn signers_manager_debug_impl_redacts_urls_and_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
        ));
        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:2".to_owned(),
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "my-profile".to_owned(),
            Duration::from_secs(1),
            "stellar:mainnet".to_owned(),
        ))
        .expect("manager must construct");

        let debug_str = format!("{manager:?}");
        // Must contain profile_name and chain_id.
        assert!(
            debug_str.contains("my-profile"),
            "debug must contain profile_name: {debug_str}"
        );
        assert!(
            debug_str.contains("stellar:mainnet"),
            "debug must contain chain_id: {debug_str}"
        );
        // Must NOT contain actual URLs or filesystem paths.
        assert!(
            !debug_str.contains("127.0.0.1"),
            "debug must not expose actual URL: {debug_str}"
        );
        assert!(
            debug_str.contains("[redacted]"),
            "debug must use [redacted] sentinel: {debug_str}"
        );
    }

    // ── rpc_source_kind ───────────────────────────────────────────────────────

    /// `rpc_source_kind` must return `"primary"` for the primary client,
    /// `"secondary"` for the secondary client, and `"rpc"` for any other client.
    #[test]
    fn rpc_source_kind_returns_correct_labels() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
        ));
        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:2".to_owned(),
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(1),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager must construct");

        // Primary client.
        assert_eq!(
            manager.rpc_source_kind(manager.primary_rpc_client()),
            "primary"
        );
        // Secondary client.
        assert_eq!(
            manager.rpc_source_kind(manager.secondary_rpc_client()),
            "secondary"
        );
        // An unrelated third client — must return "rpc".
        let third_client = stellar_agent_network::StellarRpcClient::new("http://127.0.0.1:3")
            .expect("third client must construct");
        assert_eq!(manager.rpc_source_kind(&third_client), "rpc");
    }

    // ── pubkey_first8 ─────────────────────────────────────────────────────────

    /// `pubkey_first8` must return a non-empty hex string for a `WebAuthn`
    /// pubkey.  The WebAuthn canonical body is `0x03 ‖ credential_id_first16`
    /// (17 bytes); the first 8 bytes rendered as hex must be 16 hex characters.
    #[test]
    fn pubkey_first8_webauthn_produces_16_hex_chars() {
        let pk = SignerPubkey::WebAuthn {
            credential_id_first16: [0xddu8; 16],
        };
        let result = pubkey_first8(&pk);
        // The tag byte is 0x03 and the first 7 bytes of credential_id are 0xdd.
        // Expected first 8 hex chars: "03dddddddddddddd".
        assert_eq!(
            result, "03dddddddddddddd",
            "WebAuthn pubkey_first8 must be tag+7_bytes: got {result}"
        );
    }

    /// `pubkey_first8` for an `Ed25519` key must be exactly the first 8 bytes
    /// rendered as hex (16 hex characters), preceded by the 0x01 type tag.
    ///
    /// The canonical body for `Ed25519` is `0x01 ‖ pubkey[32]` (33 bytes);
    /// the first 8 bytes rendered as hex: `"01" + first_7_pubkey_bytes`.
    #[test]
    fn pubkey_first8_ed25519_produces_correct_prefix() {
        let pk = SignerPubkey::Ed25519 {
            pubkey: [0xabu8; 32],
        };
        let result = pubkey_first8(&pk);
        // Tag=0x01, then 7 bytes of 0xab.
        assert_eq!(
            result, "01ababababababab",
            "Ed25519 pubkey_first8 must be tag+7_pubkey_bytes: got {result}"
        );
    }

    // ── fetch_contract_wasm_hashes: empty keys path ───────────────────────────

    /// `fetch_contract_wasm_hashes` with an empty key slice must return
    /// `Ok(vec![])` without making any RPC call.
    ///
    /// The early-return guard `if keys.is_empty()` exists to avoid issuing a
    /// `getLedgerEntries([])` request (which some RPC servers reject).
    #[tokio::test]
    async fn fetch_contract_wasm_hashes_returns_empty_vec_for_empty_keys() {
        // A client pointing at an unreachable address. The test must NOT make any
        // network call, so the address being unreachable is safe.
        let client = stellar_agent_network::StellarRpcClient::new("http://127.0.0.1:1")
            .expect("client construction must succeed");

        let result = fetch_contract_wasm_hashes(&client, &[])
            .await
            .expect("empty keys must return Ok without making any RPC call");

        assert!(
            result.is_empty(),
            "result for empty keys must be an empty Vec"
        );
    }

    // ── compute_post_op_invariant: AddSigner hint text ────────────────────────

    /// When `compute_post_op_invariant` refuses an `AddSigner` operation because
    /// the effective threshold (already set at signer_count) would exceed
    /// post-op signer count (this is the degenerate "corrupted on-chain state"
    /// case), the `safe_ordering_hint` must describe the correct two-step sequence
    /// for adding and then adjusting threshold.
    ///
    /// This tests the `ThresholdAffectingOp::AddSigner { .. }` hint branch in
    /// `compute_post_op_invariant`, verifying the two-step hint is correct.
    #[test]
    fn post_op_invariant_add_signer_hint_contains_add_then_threshold() {
        // Simulate a degenerate state: signer_count=1, threshold=2 (corrupted).
        // Post-op after add: signer_count=2, threshold stays at 2 (effective=2).
        // 2 <= 2 is ok. Let's construct a FAILING case:
        // threshold=3, signer_count=1, post-op=2, effective=3. 3 > 2 → fail.
        let result = compute_post_op_invariant(
            5, // rule_id
            2, // post_op_signer_count
            3, // current_threshold
            3, // effective_threshold — unchanged, violates 3 <= 2
            ThresholdAffectingOp::AddSigner {
                signer_type: "ed25519".to_owned(),
                signer_id: None,
            },
            "CDABC...12345",
            "req-add-hint",
        );
        match result {
            Err(SaError::ThresholdUnreachable {
                rule_id,
                safe_ordering_hint,
                ..
            }) => {
                assert_eq!(rule_id, 5, "rule_id must be 5");
                // The hint must tell the operator to add the signer first,
                // then adjust the threshold.
                assert!(
                    safe_ordering_hint.contains("add"),
                    "hint must mention 'add': {safe_ordering_hint}"
                );
                assert!(
                    safe_ordering_hint.contains("set-threshold"),
                    "hint must mention 'set-threshold': {safe_ordering_hint}"
                );
                assert!(
                    safe_ordering_hint.contains("--rule-id 5"),
                    "hint must include rule_id=5: {safe_ordering_hint}"
                );
            }
            other => panic!("expected ThresholdUnreachable, got: {other:?}"),
        }
    }

    /// The `SetThreshold` hint text must mention the proposed new threshold and
    /// the post-op signer count so the operator knows the valid range.
    #[test]
    fn post_op_invariant_set_threshold_hint_contains_counts() {
        // signer_count=2, new_threshold=5 — clearly exceeds count.
        let result = compute_post_op_invariant(
            9, // rule_id
            2, // post_op_signer_count
            2, // current_threshold
            5, // effective_threshold (new_threshold) — 5 > 2 → fail
            ThresholdAffectingOp::SetThreshold { new: 5 },
            "CDABC...12345",
            "req-threshold-hint",
        );
        match result {
            Err(SaError::ThresholdUnreachable {
                safe_ordering_hint, ..
            }) => {
                assert!(
                    safe_ordering_hint.contains('5'),
                    "hint must contain the bad threshold value: {safe_ordering_hint}"
                );
                assert!(
                    safe_ordering_hint.contains('2'),
                    "hint must contain the signer count: {safe_ordering_hint}"
                );
            }
            other => panic!("expected ThresholdUnreachable, got: {other:?}"),
        }
    }

    // ── accessor methods ──────────────────────────────────────────────────────

    /// `network_passphrase_ref` and `timeout_ref` must return the configured values.
    #[test]
    fn signers_manager_accessor_methods_return_configured_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None).expect("AuditWriter::open"),
        ));
        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:2".to_owned(),
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(30),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager must construct");

        assert_eq!(
            manager.network_passphrase_ref(),
            "Test SDF Network ; September 2015",
            "network_passphrase_ref must return the configured passphrase"
        );
        assert_eq!(
            manager.timeout_ref(),
            Duration::from_secs(30),
            "timeout_ref must return the configured timeout"
        );
        assert_eq!(
            manager.chain_id_ref(),
            "stellar:testnet",
            "chain_id_ref must return the configured chain ID"
        );
        // audit_writer_arc_migration must return the same Arc (pointer equality).
        let w1 = manager.audit_writer();
        let w2 = manager.audit_writer_arc_migration();
        assert!(
            Arc::ptr_eq(&w1, &w2),
            "audit_writer and audit_writer_arc_migration must return the same Arc"
        );
    }

    // ── XDR depth-bomb regression ─────────────────────────────────────────────

    /// Verifies that [`stellar_agent_xdr_limits::untrusted_decode_limits`] rejects
    /// a deeply-nested `ScVal` (depth-bomb) and accepts one within the ceiling.
    ///
    /// This regression-locks the security property relied on by every decode site
    /// in this crate that calls `untrusted_decode_limits`.
    ///
    /// # Depth accounting
    ///
    /// The `stellar-xdr` decoder tracks the number of **simultaneously active**
    /// `with_limited_depth` frames (the current call-stack depth), not a
    /// cumulative count.  Frames that have already returned do not count.
    ///
    /// At the deepest point of decoding N levels of `ScVal::Vec(Some([inner]))`,
    /// the still-open frames are:
    ///
    /// - N `ScVal::read_xdr` frames (one per nesting level)
    /// - N `Option::<ScVec>::read_xdr` frames
    /// - N `ScVec::read_xdr` frames
    /// - N `VecM::<ScVal>::read_xdr` frames
    /// - 1 innermost `ScVal::read_xdr` (Void)
    /// - 1 `ScValType::read_xdr` (Void discriminant)
    /// - 1 `i32::read_xdr` (Void discriminant value)
    ///
    /// Total simultaneous frames: **4·N + 3**.
    ///
    /// Note: the `ScValType` and `i32` frames that decode the outer Vec
    /// discriminants are **not** active at this point — they returned before
    /// the inner reads began.
    ///
    /// With `depth = 500` (the [`stellar_agent_xdr_limits::XDR_DECODE_MAX_DEPTH`]
    /// constant):
    ///
    /// - N = 125 → `4·125 + 3 = 503 > 500` → rejected
    /// - N = 124 → `4·124 + 3 = 499 ≤ 500` → accepted
    ///
    /// # Why XDR bytes are built directly
    ///
    /// The `stellar-xdr` encoder is also recursive (`WriteXdr` uses
    /// `with_limited_depth` closures at every type boundary).  Constructing and
    /// then recursively encoding a 125-level tree overflows the native call stack
    /// in debug builds.  Instead the test manufactures raw XDR bytes directly
    /// (the format is three big-endian u32 words per nesting level plus an
    /// innermost Void discriminant word) and base64-encodes them, bypassing all
    /// Rust recursion.  The bytes are identical to what the encoder would produce.
    #[test]
    fn untrusted_decode_limits_rejects_depth_bomb() {
        use stellar_xdr::ReadXdr;

        // Each level of `ScVal::Vec(Some([inner]))` encodes as three 4-byte
        // big-endian words:
        //   [0,0,0,16]  SCV_VEC discriminant (i32 = 16)
        //   [0,0,0, 1]  Option<ScVec> present tag (u32 = 1)
        //   [0,0,0, 1]  VecM<ScVal> length (u32 = 1)
        // Innermost ScVal::Void:
        //   [0,0,0, 1]  SCV_VOID discriminant (i32 = 1)
        const LEVEL: [u8; 12] = [0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1];
        const VOID: [u8; 4] = [0, 0, 0, 1];

        let make_xdr_b64 = |levels: usize| -> String {
            let mut raw: Vec<u8> = Vec::with_capacity(levels * 12 + 4);
            for _ in 0..levels {
                raw.extend_from_slice(&LEVEL);
            }
            raw.extend_from_slice(&VOID);
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&raw)
        };

        // ── Part 1: N=125 → simultaneous depth 4·125+3 = 503 — must REJECT ──
        let b64_bomb = make_xdr_b64(125);
        assert!(
            stellar_xdr::ScVal::from_xdr_base64(
                &b64_bomb,
                stellar_agent_xdr_limits::untrusted_decode_limits(b64_bomb.len())
            )
            .is_err(),
            "untrusted_decode_limits must reject N=125 nesting levels (simultaneous depth 503 > 500)"
        );

        // ── Part 2: N=124 → simultaneous depth 4·124+3 = 499 — must ACCEPT ──
        let b64_safe = make_xdr_b64(124);
        assert!(
            stellar_xdr::ScVal::from_xdr_base64(
                &b64_safe,
                stellar_agent_xdr_limits::untrusted_decode_limits(b64_safe.len())
            )
            .is_ok(),
            "untrusted_decode_limits must accept N=124 nesting levels (simultaneous depth 499 ≤ 500)"
        );
    }
}
