//! Signer-set manager — atomic add/remove/set-threshold for OZ context rules.
//!
//! Implements `SignersManager`, the off-chain orchestrator for atomic
//! signer-threshold updates against OpenZeppelin `stellar-accounts` v0.7.2
//! context-rule signer sets.  Every mutating method enforces:
//!
//! 1. **Threshold invariant pre-flight**: refuses operations that would produce
//!    `signer_count' < threshold'` or `threshold' < 1` before submitting, when
//!    the rule has a simple-threshold policy.
//! 2. **Two-RPC signer-set observation**: the primary and secondary RPC
//!    endpoints each read the rule, its policies' executables and its
//!    simple-threshold value, and must agree on all of them.
//! 3. **Audit-log-derived divergence detection**: the expected signer-set view
//!    comes from the newest signer-set state row of either snapshot version,
//!    not a separate cache, and is compared with the chain in that row's
//!    version before every signer mutation.
//! 4. **Refusal path**: signer mutations that would cross the threshold-vs-count
//!    invariant are refused with [`crate::SaError::ThresholdUnreachable`] carrying
//!    a `safe_ordering_hint` guiding the safe two-command sequence (atomic bundle
//!    dropped; CAP-46 prohibits two `InvokeHostFunctionOp` per Soroban transaction).
//! 5. **Recorded confirmed state**: after a signer mutation confirms, both
//!    endpoints are read again at or past the confirmation ledger, the
//!    resulting set must be exactly the intended change, and it is recorded as
//!    a version-2 state row; a failure to observe or record it is returned as
//!    [`crate::SaError::BaselineWriteFailed`] with the transaction hash. A rule
//!    the wallet installs is baselined the same way from its confirmed state,
//!    and an attach or detach of the simple-threshold policy records the
//!    threshold change.
//!
//! # Architecture
//!
//! Each public `async` method is a thin outer function that:
//! 1. Acquires its rule locks through one `acquire_rule_locks` call, bounded
//!    by the manager's timeout: the target rule, and for a verb that signs
//!    under other rules, those rules too. A lock not acquired in time
//!    refuses at stage `rule_lock`.
//! 2. Delegates to `*_locked_inner` which compares, submits, observes and
//!    validates. The submission receives the held locks and the verb's own
//!    comparison as a `BorrowedRuleLocks` context; the submit path compares
//!    every other rule the submission is signed under and acquires no lock.
//! 3. Writes the audit-log state row inside the write critical section
//!    (`write_state_row`). A signer add also writes its pin rows once its
//!    transaction confirms: after the state row, or before a refusal that
//!    follows the confirmation.
//!
//! The policy verbs of `ContextRuleManager` submit through `attach_policy`
//! and `detach_policy`, which follow the same shape. They lock the rule and
//! its auth rules, then, under the locks, compare the rule, plan the pin
//! record, submit, record the threshold change of the simple-threshold
//! policy and write the pin rows. The migration pair
//! (`migrate_signer_pair`) holds the rule's lock across its removal and its
//! add, and writes both state rows and the pin repoint under it. The signer
//! verbs, the policy verbs, `refresh_signer_baseline` and the migration pair
//! therefore write each pin row under the lock of the rule it pins, held
//! since the record read it was planned from.
//!
//! # Single-caller invariant for the signer-set baseline
//!
//! Only `SignersManager::list_signers` (first observation),
//! `SignersManager::refresh_signer_baseline` (explicit re-anchor) and
//! `SignersManager::baseline_confirmed_install` (a rule the wallet installed)
//! may write a baseline, a `EventKind::SaSignerSetBaselinedV2` row. The CI
//! gate `.github/scripts/check-no-direct-sasignersetbaselined-emit.sh`
//! enforces this over the production code of every crate:
//!
//! 1. `AuditEntry::new_sa_signer_set_baselined_v2` is called exactly once,
//!    inside `SignersManager::emit_baseline`, and the version-1 constructor
//!    `AuditEntry::new_sa_signer_set_baselined` is not called;
//! 2. `emit_baseline` is called exactly three times, once from each of
//!    `list_signers`, `refresh_signer_baseline` and
//!    `baseline_confirmed_install`;
//! 3. no code outside `stellar-agent-core`'s `audit_log/entry.rs` constructs
//!    `SaSignerSetBaselined` or `SaSignerSetBaselinedV2`, with any path prefix
//!    (pattern matches are allowed);
//! 4. each `BaselineReason` constructor and variant is used only in its own
//!    function: `first_observation` and `FirstObservation` in
//!    `list_signers`, `explicit_refresh` and `ExplicitRefresh` in
//!    `refresh_signer_baseline`, `confirmed_install` and `ConfirmedInstall` in
//!    `baseline_confirmed_install` (pattern matches are allowed);
//! 5. no `use` statement outside `entry.rs` and `schema.rs` imports through
//!    `EventKind::` or renames `EventKind`.
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

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::AuditLogIntegrityError;
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::health::{AuditWriterHealth, AuditWriterHealthHandle};
use stellar_agent_core::audit_log::reader::PinnedHashesRecord;
use stellar_agent_core::audit_log::schema::{ContractKind, PinsUpdateReason};
use stellar_agent_core::audit_log::signer_set::{
    BaselineReason, ObservedSignerSet, SignerEntryV2, SignerIdentityV2, SignerPubkey,
    SignerSetSnapshotV2, SignerSetView, SignerSetViewPayload, ThresholdObservation, account_digest,
    compute_signer_set_digest, compute_signer_set_digest_v2,
};
use stellar_agent_core::audit_log::writer::{AuditWriter, WriterError};
use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_core::observability::{
    RedactedStrkey, redact_strkey_first5_last5, untrusted_display_bounded,
};
use stellar_agent_core::scval::scval_variant_name;
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
    ContractId, Hash, HostFunction, Int128Parts, InvokeContractArgs, InvokeHostFunctionOp,
    Operation, OperationBody, PublicKey, ScAddress, ScBytes, ScMap, ScSymbol, ScVal, ScVec,
    Uint256, VecM,
};
use tracing::{debug, info, warn};

use crate::SaError;
use crate::error::{
    AdminOrOwnerKey, BASELINE_WRITE_STAGE_OBSERVE, BASELINE_WRITE_STAGE_WRITE,
    baseline_observe_reason, baseline_write_reason,
};
use crate::managers::auth_entry::{PreSubmitBudget, bound_pre_submit_stage};
use crate::managers::migration::PendingAddStep;
use crate::managers::rules::{
    BASE_FEE_STROOPS, ExpectedInstallState, ExpiryCheck, augment_with_oz_error_name,
    contract_instance_key, scaddress_to_strkey,
};
use crate::managers::verifiers::{PinnedKind, PlannedPinUpdate};
use crate::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES;
use crate::signers::types::{
    FrozenChainStateTuple, PolicyIdentifiedKind, ThresholdAffectingOp, WasmHashSummary,
};
use crate::simple_threshold_policy::parse_simple_threshold_install_param;
use crate::submit::ExpectedReturn;
use crate::weighted_threshold_policy::WEIGHTED_THRESHOLD_POLICY_WASM_HASHES;

/// Weighted-threshold policy's on-chain view state: the current threshold
/// and per-signer weight map.
///
/// The `signer_weights` map is decoded generically as `(key ScVal, weight)`
/// pairs — byte-equality against a target signer's canonical key (built via
/// [`build_delegated_signer_scval`] / [`build_external_signer_scval`]),
/// never a semantic `Signer` decode.
pub struct WeightedThresholdView {
    /// Current on-chain threshold.
    pub threshold: u32,
    /// Per-signer weight map, decoded generically as `(key ScVal, weight)`
    /// pairs. Look up a specific signer's weight via [`Self::weight_of`]
    /// using a canonical key built via [`build_delegated_signer_scval`] /
    /// [`build_external_signer_scval`] — never decode the key semantically.
    pub signer_weights: Vec<(ScVal, u32)>,
}

impl WeightedThresholdView {
    /// Returns the checked sum of all signer weights.
    ///
    /// # Errors
    ///
    /// Returns [`SaError::WeightedThresholdInstallRefused`] if the sum
    /// overflows `u32` (mirrors OZ `MathOverflow`, code 3212).
    pub fn total_weight(&self) -> Result<u32, SaError> {
        let mut total: u32 = 0;
        for (_, weight) in &self.signer_weights {
            total = total.checked_add(*weight).ok_or_else(|| {
                SaError::WeightedThresholdInstallRefused {
                    reason: "sum of on-chain signer weights overflows u32".to_owned(),
                }
            })?;
        }
        Ok(total)
    }

    /// Returns the weight for the signer whose canonical key ScVal equals
    /// `key`, or `0` if absent (matching OZ "no weight configured
    /// contributes zero" semantics, `weighted_threshold.rs:257-264`, SHA
    /// `a9c4216`).
    pub fn weight_of(&self, key: &ScVal) -> u32 {
        self.signer_weights
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, w)| *w)
            .unwrap_or(0)
    }
}

/// Returns a redacted, kind-labelled identity string for a weighted-threshold
/// signer, for audit-log display (never the raw G-strkey or key material).
fn redact_weighted_signer_identity(
    input: &crate::weighted_threshold_policy::WeightedThresholdSignerInput,
) -> String {
    match input {
        crate::weighted_threshold_policy::WeightedThresholdSignerInput::Delegated { g_strkey } => {
            format!("delegated:{}", redact_strkey_first5_last5(g_strkey))
        }
        crate::weighted_threshold_policy::WeightedThresholdSignerInput::External {
            verifier,
            ..
        } => {
            let verifier_display = scaddress_to_strkey(verifier)
                .map(|s| redact_strkey_first5_last5(&s))
                .unwrap_or_else(|_| "unknown".to_owned());
            format!("external:{verifier_display}")
        }
    }
}

// ── On-chain constants (OZ stellar-contracts v0.7.2) ────────────

/// Maximum number of signers per context rule, per the OpenZeppelin
/// stellar-accounts v0.7.2 smart-account contract.
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
/// Keyed on `(audit_log_path, rule_id, smart_account_strkey)`. It provides a
/// non-reentrant mutual exclusion primitive, so this manager's calls against
/// one rule of one smart account run one at a time. One call's comparison
/// with the rule's state row, its submission and its row write never
/// interleave with another call's.
///
/// Every holder takes its locks through
/// [`SignersManager::acquire_rule_locks`] (or its single-rule form
/// [`SignersManager::acquire_rule_lock`]): one call, one set of rules,
/// acquired in ascending rule-id order under a deadline. Nothing that runs
/// under a held guard acquires a lock again. Two holders whose sets overlap
/// therefore acquire their common rules in the same order and cannot
/// deadlock, and a waiter that does not get a lock before its deadline
/// refuses at stage `rule_lock`.
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

/// A held lock on one rule of one smart account, from
/// [`SignersManager::acquire_rule_locks`] or
/// [`SignersManager::acquire_rule_lock`].
///
/// The guard carries the lock's full key: the audit-log path, the rule id
/// and the account strkey. A function that takes a `&RuleLockGuard` reads
/// the rule and the account from it, so the guard is the proof that the
/// caller holds the lock of the rule it works on. Dropping the guard
/// releases the lock.
pub(crate) struct RuleLockGuard {
    key: RuleMutexKey,
    /// The owned guard of the rule's mutex, held for its drop.
    _held: tokio::sync::OwnedMutexGuard<()>,
}

impl RuleLockGuard {
    /// The locked rule.
    pub(crate) fn rule_id(&self) -> u32 {
        self.key.1
    }

    /// The smart account whose rule is locked, as its C-strkey.
    pub(crate) fn smart_account_strkey(&self) -> &str {
        &self.key.2
    }

    /// The smart account whose rule is locked, redacted first-5-last-5.
    pub(crate) fn smart_account_redacted(&self) -> String {
        redact_strkey_first5_last5(&self.key.2)
    }

    /// The audit log of the manager that took the lock.
    pub(crate) fn audit_log_path(&self) -> &std::path::Path {
        &self.key.0
    }
}

/// The guard in `guards` for rule `rule_id` of the smart account
/// `smart_account_strkey`, if any.
pub(crate) fn find_rule_guard<'g>(
    guards: &'g [RuleLockGuard],
    smart_account_strkey: &str,
    rule_id: u32,
) -> Option<&'g RuleLockGuard> {
    guards.iter().find(|guard| {
        guard.rule_id() == rule_id && guard.smart_account_strkey() == smart_account_strkey
    })
}

/// The refusal of a rule whose lock the caller does not hold: the one error
/// of stage `rule_lock_missing`.
pub(crate) fn rule_lock_missing(rule_id: u32) -> SaError {
    SaError::AuthEntryConstructionFailed {
        stage: "rule_lock_missing",
        redacted_reason: format!(
            "rule {rule_id}: the submission names an auth rule the caller holds no lock for"
        ),
    }
}

/// The guard of rule `rule_id` in a holder's own acquisition.
///
/// # Errors
///
/// [`rule_lock_missing`] when `guards` holds no lock for the rule.
fn held_guard<'g>(
    guards: &'g [RuleLockGuard],
    smart_account_strkey: &str,
    rule_id: u32,
) -> Result<&'g RuleLockGuard, SaError> {
    find_rule_guard(guards, smart_account_strkey, rule_id).ok_or_else(|| rule_lock_missing(rule_id))
}

/// The rules a holder locks: its target and the distinct non-zero rules
/// its submission is signed under. Rule 0 among the latter is not compared
/// and needs no lock.
fn holder_lock_set(
    target_rule_id: u32,
    auth_rule_ids: &[ContextRuleId],
) -> impl Iterator<Item = u32> + '_ {
    std::iter::once(target_rule_id).chain(
        auth_rule_ids
            .iter()
            .map(ContextRuleId::as_u32)
            .filter(|rule_id| *rule_id != 0),
    )
}

/// Logs the wait of one rule-lock acquisition on the `sa_submit_timing`
/// debug span.
fn log_rule_lock_wait(started: std::time::Instant) {
    debug!(
        target: "sa_submit_timing",
        stage = "rule_lock",
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "sa_submit_timing: pre-submit stage elapsed"
    );
}

/// The locks a holder took through one [`SignersManager::acquire_rule_locks`]
/// call, with the comparisons it ran under them, lent to
/// [`crate::submit::submit_signed_invoke`].
///
/// The context is built only in this module, from the guards of one
/// acquisition and the [`ComparedState`]s of the holder's own comparisons;
/// a `ComparedState` exists only as the result of a comparison. The free
/// function acquires no lock when it is handed a context: it refuses a
/// submission naming a rule the context holds no guard for, on the
/// submission's account and in the log of the manager that checks it, and it
/// reads and compares every named rule the context did not compare.
pub(crate) struct BorrowedRuleLocks<'a> {
    guards: &'a [RuleLockGuard],
    compared: &'a [ComparedState],
}

/// Builds the held-lock context of `guards` and `compared`.
fn borrowed<'a>(
    guards: &'a [RuleLockGuard],
    compared: &'a [ComparedState],
) -> BorrowedRuleLocks<'a> {
    BorrowedRuleLocks { guards, compared }
}

impl<'a> BorrowedRuleLocks<'a> {
    /// The held guard for rule `rule_id` of the smart account
    /// `smart_account_strkey`, if the context holds one. A guard for another
    /// account never matches.
    pub(crate) fn guard_for(
        &self,
        smart_account_strkey: &str,
        rule_id: u32,
    ) -> Option<&'a RuleLockGuard> {
        find_rule_guard(self.guards, smart_account_strkey, rule_id)
    }

    /// The holder's comparison of rule `rule_id`, if it ran one.
    pub(crate) fn compared_for(&self, rule_id: u32) -> Option<&'a ComparedState> {
        self.compared
            .iter()
            .find(|compared| compared.rule_id() == rule_id)
    }
}

/// The held-lock context a policy entry hands the submission it runs under
/// its locks.
///
/// `'l` is the life of the context, which the entry owns; `'env` is the life
/// of the borrows the submission captures. The type records that `'env`
/// outlives `'l`, so a submission closure that borrows its caller's data can
/// return a future tied to the context.
pub(crate) struct LockedSubmission<'l, 'env> {
    rule_locks: &'l BorrowedRuleLocks<'l>,
    _env: std::marker::PhantomData<&'l &'env ()>,
}

impl<'l> LockedSubmission<'l, '_> {
    /// Hands `rule_locks` to a submission.
    fn new(rule_locks: &'l BorrowedRuleLocks<'l>) -> Self {
        Self {
            rule_locks,
            _env: std::marker::PhantomData,
        }
    }

    /// The held-lock context to pass to the submission.
    pub(crate) fn rule_locks(&self) -> &'l BorrowedRuleLocks<'l> {
        self.rule_locks
    }
}

/// The submission a policy entry runs under its locks.
pub(crate) type LockedSubmitFuture<'l> = std::pin::Pin<
    Box<dyn Future<Output = Result<crate::submit::SubmitInvokeResult, SaError>> + Send + 'l>,
>;

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
#[derive(Clone)]
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

impl std::fmt::Debug for SignersManagerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            primary_rpc_url,
            secondary_rpc_url,
            audit_writer: _,
            audit_log_path: _,
            network_passphrase,
            profile_name,
            timeout,
            chain_id,
        } = self;
        f.debug_struct("SignersManagerConfig")
            .field(
                "primary_rpc_url",
                &stellar_agent_core::redact::redact_url_authority(primary_rpc_url),
            )
            .field(
                "secondary_rpc_url",
                &stellar_agent_core::redact::redact_url_authority(secondary_rpc_url),
            )
            .field("audit_writer", &"[redacted]")
            .field("audit_log_path", &"[redacted]")
            .field("network_passphrase", network_passphrase)
            .field("profile_name", profile_name)
            .field("timeout", timeout)
            .field("chain_id", chain_id)
            .finish()
    }
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
/// | `list_signers` | Observes the signer set (two-RPC); baselines if no prior row, otherwise compares | yes | `SaSignerSetBaselinedV2` (first observation) |
/// | `refresh_signer_baseline` | Observes and compares; writes a fresh baseline (a changed set needs `accept_divergence`) and pins the live verifier of a pin record that pins none | yes | `SaSignerSetDiverged` (changed set), `SaSignerSetBaselinedV2`, override rows and `SaContextRulePinsUpdated` (verifier pinned) |
/// | `add_signer` | Compares, adds a signer, validates the confirmed set | yes | `SaSignerAddedV2` |
/// | `batch_add_signers` | Compares, adds signers, validates the confirmed set | yes | `SaSignerAddedV2` per signer |
/// | `remove_signer` | Compares, removes a signer, validates the confirmed set | yes | `SaSignerRemovedV2` |
/// | `set_threshold` | Compares, changes the threshold, validates the confirmed set | yes | `SaThresholdChangedV2` |
/// | `migrate_signer_pair` (through `MigrationPlan::submit`) | Compares, removes an `External` signer, validates the confirmed set, repoints the pin record, compares again, adds the key data on the destination verifier, validates the confirmed set | yes | `SaSignerRemovedV2`, `SaContextRulePinsUpdated` (pinned rule), `SaSignerAddedV2`, `SaVerifierMigrated` |
/// | `verify_signer_set_against_chain` | Compares the chain with the audit-log baseline | yes | `SaSignerSetDiverged` (on mismatch) |
/// | `identify_verifier` | Verifier wasm-hash two-RPC lookup | no | (internal; no audit row) |
///
/// # Non-reentrant rule mutex
///
/// Every method that reads or writes a rule's signer-set state, and every
/// verb that signs under a rule, acquires the per-rule `tokio::sync::Mutex`
/// of each rule it compares before any network I/O, and holds it until its
/// rows are written. A comparison and the submission it guards therefore
/// never interleave with another call on the same rule. The lock wait is
/// bounded by the manager's timeout; a lock not acquired in time refuses
/// with [`SaError::AuthEntryConstructionFailed`] at stage `rule_lock`.
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
            redacted_reason: format!(
                "StellarRpcClient construction failed for {}: {e}",
                stellar_agent_core::redact::redact_url_authority(url)
            ),
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

    /// Returns the audit log this manager writes and keys its rule locks by.
    #[must_use]
    pub(crate) fn audit_log_path(&self) -> &std::path::Path {
        &self.audit_log_path
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
    /// `pub(crate)`: used by [`crate::managers::migration::MigrationPlanner`]
    /// to configure the rule manager it lists the account's rules through.
    #[must_use]
    pub(crate) fn chain_id_ref(&self) -> &str {
        &self.chain_id
    }

    /// Returns the shared `Arc<Mutex<AuditWriter>>` for the migration
    /// planner.
    ///
    /// `pub(crate)`: used by [`crate::managers::migration::MigrationPlanner`]
    /// to give the rule manager it lists the account's rules through this
    /// manager's audit writer. Mirrors the `audit_writer()` accessor used by
    /// `CredentialsManager`.
    #[must_use]
    pub(crate) fn audit_writer_arc_migration(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<stellar_agent_core::audit_log::writer::AuditWriter>> {
        Arc::clone(&self.audit_writer)
    }

    // ── migrate_signer_pair ───────────────────────────────────────────────────

    /// Migrates the `External` signer `signer_id` of rule `rule_id` to the
    /// destination verifier `to_verifier_addr` as two checked signer
    /// mutations, a removal and an add of the same key data, under the
    /// rule's lock.
    ///
    /// Called by [`crate::managers::migration::MigrationPlan::submit`] once
    /// per pair. `remove_args` and `add_args` are the invoke arguments of the
    /// pair's two host functions; `from_hash_first8` and `to_hash_first8`
    /// name the source and destination verifier hashes.
    ///
    /// # Order
    ///
    /// One acquisition of the rule's lock is held through both submissions
    /// and both confirmations, and released when the entry returns. Under
    /// it:
    ///
    /// 1. The removal compares the rule with its newest state row, which
    ///    must be version 2.
    /// 2. The plan is checked before anything is sent. The compared set
    ///    holds signer `signer_id` with an `External` identity, `add_args`
    ///    add the same key data on the destination verifier, and
    ///    `remove_args` remove signer `signer_id` of rule `rule_id`.
    /// 3. The removal's preconditions of [`Self::remove_signer`] apply: a
    ///    rule with policies and no simple-threshold policy, and a rule whose
    ///    threshold the removal would make unreachable, are refused. The
    ///    pair signs under the rule with the source key alone, so that key
    ///    must be a Delegated signer of the rule.
    /// 4. The removal is submitted, the confirmed rule is observed through
    ///    both endpoints and must be the compared set without the signer,
    ///    and `SaSignerRemovedV2` records it.
    /// 5. The rule's pin record is repointed to the destination verifier.
    /// 6. The add compares the rule with the removal's state row.
    /// 7. The add is submitted; its simulated return value must be a `u32`
    ///    before it is signed. The confirmed rule must hold the removed
    ///    identity on the destination verifier under the id the simulation
    ///    returned, every other signer and the threshold unchanged.
    ///    `SaSignerAddedV2` records it.
    /// 8. `SaVerifierMigrated` records the completed pair.
    ///
    /// A completed pair writes `[SaSignerRemovedV2, SaContextRulePinsUpdated,
    /// SaSignerAddedV2, SaVerifierMigrated]`; the pins row is written only
    /// for a rule with a pin record that does not already name the
    /// destination alone. The pins row and `SaVerifierMigrated` are logged
    /// and skipped when the audit log refuses them; the two state rows are
    /// required.
    ///
    /// # Pin record
    ///
    /// The repoint replaces the record's verifier pins by `to_hash_first8`
    /// with no executable-reference pin, the policy pins and override flags
    /// unchanged. The migration preflight identified the destination,
    /// required it in the allowlist and refused a mutable one, which
    /// includes every external reference. It runs as soon as the removal
    /// was sent and before the add, so a pair that stops after the send
    /// leaves a record that already names the destination. A rule without a
    /// pin record stays unpinned, and a record that already names the
    /// destination alone is not rewritten.
    ///
    /// # Pending add
    ///
    /// A failure after the removal was sent returns the add that completes
    /// the pair as [`PendingAddStep`] data. That is the case when the
    /// removal confirmed and a later step before the add's confirmation
    /// failed, and when the removal's outcome is unknown
    /// ([`SaError::SubmissionUnresolved`], `remove_confirmed: false`). An
    /// add whose outcome is unknown sets `add_tx_hash`. Once the add
    /// confirmed, a failure to validate or record its state returns no
    /// pending add: the add is on chain, and
    /// `signers refresh --accept-divergence` records the chain state. A
    /// failure before the removal was sent returns no pending add and
    /// leaves the rule unchanged.
    ///
    /// # Budgets
    ///
    /// The lock wait runs under the manager's timeout from the call. Each
    /// submission runs its pre-flight under its own pre-submit budget, and
    /// each confirmation's observation under the manager's timeout from
    /// that confirmation.
    ///
    /// # Errors
    ///
    /// Raised by the entry and returned unchanged:
    ///
    /// - [`SaError::SignerSetMissingBaseline`] /
    ///   [`SaError::SignerSetBaselineLegacy`]: the rule has no state row, or
    ///   a version-1 one, before any RPC.
    /// - [`SaError::SignerSetDiverged`]: the chain differs from the newest
    ///   state row before a step is submitted (no transaction hash), or a
    ///   confirmed step left another state than the intended one (with its
    ///   hash).
    /// - [`SaError::ThresholdPolicyIdentificationFailed`] /
    ///   [`SaError::ThresholdUnreachable`]: the removal's preconditions.
    /// - [`SaError::BaselineWriteFailed`]: a confirmed step's state was not
    ///   observed (stage `observe`) or not recorded (stage `write`).
    /// - [`SaError::AuditLog`] / [`SaError::NetworkRpcDivergence`]: a
    ///   comparison met an audit-log integrity error or endpoints that
    ///   disagree.
    /// - [`SaError::VerifierMigrationFailed`] at phase `plan_build`: the
    ///   plan check of step 2.
    /// - [`SaError::AuthEntryConstructionFailed`] at stage `rule_lock`: the
    ///   lock was not acquired within its budget.
    /// - The errors of [`Self::submit_migration_step`] for either step.
    #[allow(
        clippy::too_many_arguments,
        reason = "the rule and the signer, the destination and both hash labels, both steps' \
                  arguments, the signer and its source account, and the correlation id"
    )]
    pub(crate) async fn migrate_signer_pair(
        &self,
        smart_account: &ScAddress,
        rule_id: u32,
        signer_id: u32,
        to_verifier_addr: &ScAddress,
        from_hash_first8: &str,
        to_hash_first8: &str,
        remove_args: Vec<ScVal>,
        add_args: Vec<ScVal>,
        signer: &(dyn Signer + Send + Sync),
        source_pubkey_strkey: &str,
        request_id: &str,
    ) -> Result<MigratedPair, PairFailure> {
        let without_pending_add = |error: SaError| PairFailure {
            error,
            pending_add: None,
        };
        let smart_account_strkey =
            scaddress_to_strkey(smart_account).map_err(without_pending_add)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // The migrating rule is the only rule each step signs under.
        let guards = self
            .acquire_rule_locks(&smart_account_strkey, [rule_id], self.lock_budget())
            .await
            .map_err(without_pending_add)?;
        let guard =
            held_guard(&guards, &smart_account_strkey, rule_id).map_err(without_pending_add)?;

        // The removal's comparison.
        let compared = [self
            .verify_signer_set_locked(
                guard,
                V1Handling::RefuseLegacy,
                Some(source_pubkey_strkey),
                request_id,
            )
            .await
            .map_err(without_pending_add)?];
        let before = compared[0].snapshot();

        let (intended, key_data) = check_migration_pair_plan(
            before,
            rule_id,
            signer_id,
            to_verifier_addr,
            &remove_args,
            &add_args,
        )
        .map_err(|detail| {
            without_pending_add(SaError::VerifierMigrationFailed {
                phase: crate::error::MIGRATION_PHASES[2], // "plan_build"
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.as_str(),
                ),
                detail,
                request_id: request_id.to_owned(),
            })
        })?;
        check_remove_preconditions(&compared[0], signer_id, &smart_account_redacted, request_id)
            .map_err(without_pending_add)?;

        let pending = |remove_tx_hash: &str, remove_confirmed: bool| {
            PendingAddStep::new(
                rule_id,
                signer_id,
                to_verifier_addr.clone(),
                key_data.clone(),
                remove_tx_hash.to_owned(),
                remove_confirmed,
            )
        };

        // The removal.
        let removal = self
            .submit_migration_step(
                smart_account.clone(),
                rule_id,
                "remove_signer",
                remove_args,
                signer,
                source_pubkey_strkey,
                &smart_account_redacted,
                request_id,
                &borrowed(&guards, &compared),
                None,
            )
            .await;
        let removed = match removal {
            Ok(removed) => removed,
            Err(error) => {
                let pending_add = match &error {
                    // The removal was sent and may land: the record names the
                    // destination before the pair stops.
                    SaError::SubmissionUnresolved {
                        tx_hash: Some(tx_hash),
                        ..
                    } => {
                        self.repoint_migrated_pins(
                            rule_id,
                            &smart_account_redacted,
                            to_hash_first8,
                            request_id,
                        );
                        Some(pending(tx_hash, false))
                    }
                    _ => None,
                };
                return Err(PairFailure { error, pending_add });
            }
        };
        let pending_add = pending(&removed.tx_hash, true);
        let stopped = |error: SaError| PairFailure {
            error,
            pending_add: Some(pending_add.clone()),
        };

        let recorded = self
            .record_confirmed_remove(
                smart_account,
                &smart_account_strkey,
                &smart_account_redacted,
                rule_id,
                signer_id,
                source_pubkey_strkey,
                before,
                &removed,
                request_id,
            )
            .await;
        // The removal is on chain: the record names the destination whatever
        // its recording returned.
        self.repoint_migrated_pins(rule_id, &smart_account_redacted, to_hash_first8, request_id);
        recorded.map_err(stopped)?;

        // The add's comparison, against the removal's state row.
        let compared_add = [self
            .verify_signer_set_locked(
                guard,
                V1Handling::RefuseLegacy,
                Some(source_pubkey_strkey),
                request_id,
            )
            .await
            .map_err(stopped)?];

        let added = self
            .submit_migration_step(
                smart_account.clone(),
                rule_id,
                "add_signer",
                add_args,
                signer,
                source_pubkey_strkey,
                &smart_account_redacted,
                request_id,
                &borrowed(&guards, &compared_add),
                Some(ExpectedReturn::U32),
            )
            .await
            .map_err(|error| {
                let add_tx_hash = match &error {
                    SaError::SubmissionUnresolved { tx_hash, .. } => tx_hash.clone(),
                    _ => None,
                };
                PairFailure {
                    error,
                    pending_add: Some(pending_add.clone().with_add_tx_hash(add_tx_hash)),
                }
            })?;

        // The add confirmed: a failure from here on returns no pending add,
        // since the add is on chain and the refresh records the chain state.
        let (new_signer_id, mutation) = self
            .validate_confirmed_add(
                smart_account,
                rule_id,
                &smart_account_redacted,
                source_pubkey_strkey,
                compared_add[0].snapshot(),
                intended,
                added,
                request_id,
            )
            .await
            .map_err(without_pending_add)?;
        let account = account_digest(&self.network_passphrase, &smart_account_strkey);
        self.write_confirmed_state_row(
            rule_id,
            &smart_account_redacted,
            &mutation.tx_hash,
            request_id,
            |_| {
                AuditEntry::new_sa_signer_added_v2(
                    rule_id,
                    new_signer_id,
                    &mutation.resulting,
                    account,
                    RedactedStrkey::from_already_redacted(smart_account_redacted.as_str()),
                    self.chain_id.as_str(),
                    request_id,
                )
            },
        )
        // The add confirmed; its state row was not written.
        .map_err(without_pending_add)?;

        self.write_verifier_migrated_row(
            rule_id,
            &smart_account_redacted,
            from_hash_first8,
            to_hash_first8,
            &mutation.tx_hash,
            request_id,
        );

        Ok(MigratedPair {
            remove_tx_hash: removed.tx_hash,
            add_tx_hash: mutation.tx_hash,
            new_signer_id,
        })
    }

    /// Observes the rule after the confirmed removal of a migration pair,
    /// requires the compared set `before` without signer `signer_id`, and
    /// writes the `SaSignerRemovedV2` row.
    ///
    /// # Errors
    ///
    /// - [`SaError::BaselineWriteFailed`] at stage `observe` or `write`, with
    ///   the removal's hash.
    /// - [`SaError::SignerSetDiverged`] with the removal's hash: the
    ///   confirmed state is not the intended removal.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the rule and the signer, the source account, the \
                  compared set, the confirmed removal and the correlation id"
    )]
    async fn record_confirmed_remove(
        &self,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        signer_id: u32,
        source_pubkey_strkey: &str,
        before: &SignerSetSnapshotV2,
        removed: &crate::submit::SubmitInvokeResult,
        request_id: &str,
    ) -> Result<(), SaError> {
        let observation = self
            .observe_confirmed(
                smart_account,
                rule_id,
                Some(source_pubkey_strkey),
                removed,
                smart_account_redacted,
                request_id,
            )
            .await?;
        let resulting = self.require_intended_state(
            rule_id,
            smart_account_redacted,
            without_signer(before, signer_id),
            observation,
            &removed.tx_hash,
            request_id,
        )?;
        let account = account_digest(&self.network_passphrase, smart_account_strkey);
        self.write_confirmed_state_row(
            rule_id,
            smart_account_redacted,
            &removed.tx_hash,
            request_id,
            |_| {
                AuditEntry::new_sa_signer_removed_v2(
                    rule_id,
                    signer_id,
                    &resulting,
                    account,
                    RedactedStrkey::from_already_redacted(smart_account_redacted),
                    self.chain_id.as_str(),
                    request_id,
                )
            },
        )
    }

    /// Repoints the pin record of rule `rule_id` to the destination verifier
    /// of a migration pair; see "Pin record" on
    /// [`Self::migrate_signer_pair`].
    ///
    /// Every caller holds the rule's lock. The pair's removal was sent, so a
    /// record that cannot be read or written is logged and the rule keeps
    /// its previous record, which the drift check compares against the live
    /// verifier set.
    fn repoint_migrated_pins(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        to_hash_first8: &str,
        request_id: &str,
    ) {
        match crate::managers::verifiers::read_pinned_hashes_for_rule(
            self,
            rule_id,
            smart_account_redacted,
        ) {
            Ok(Some(record)) => {
                if record.pinned_verifier_first8 == [to_hash_first8]
                    && record.pinned_verifier_executable_refs.is_empty()
                {
                    debug!(
                        rule_id,
                        request_id,
                        "migrate_signer_pair: the pin record already names the destination; \
                         no pin update is written"
                    );
                    return;
                }
                let mut update = PlannedPinUpdate::unchanged(record);
                update.record.pinned_verifier_first8 = vec![to_hash_first8.to_owned()];
                update.record.pinned_verifier_executable_refs = Vec::new();
                self.write_pin_rows(
                    rule_id,
                    smart_account_redacted,
                    Some(update),
                    PinsUpdateReason::VerifierMigrated,
                    request_id,
                );
            }
            Ok(None) => debug!(
                rule_id,
                request_id,
                "migrate_signer_pair: the rule has no pin record; no pin update is written"
            ),
            Err(e) => warn!(
                rule_id,
                error = %e,
                request_id,
                "migrate_signer_pair: the pin record is unreadable after the removal was sent; \
                 SaContextRulePinsUpdated row not written"
            ),
        }
    }

    /// Writes the `SaVerifierMigrated` row of a completed migration pair,
    /// carrying the redacted hash of its add transaction.
    ///
    /// The pair's state rows carry its integrity, so a row the audit log
    /// refuses is logged, and a poisoned writer marks the session degraded.
    fn write_verifier_migrated_row(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        from_hash_first8: &str,
        to_hash_first8: &str,
        add_tx_hash: &str,
        request_id: &str,
    ) {
        let add_tx_hash_redacted = stellar_agent_network::redact_tx_hash(add_tx_hash);
        let written = self.write_state_row(|_| {
            AuditEntry::new_sa_verifier_migrated(
                rule_id,
                RedactedStrkey::from_already_redacted(smart_account_redacted),
                from_hash_first8,
                to_hash_first8,
                &add_tx_hash_redacted,
                self.chain_id.as_str(),
                request_id,
            )
        });
        if let Err(e) = written {
            warn!(
                target: "stellar_agent::audit",
                rule_id,
                smart_account_redacted = %smart_account_redacted,
                error = %e,
                request_id = %request_id,
                "SaVerifierMigrated row not written; the pair's state rows record it"
            );
        }
    }

    /// Submits one step of a migration pair (`remove_signer` or
    /// `add_signer`) under the held lock of rule `rule_id`.
    ///
    /// Called by [`Self::migrate_signer_pair`] for each step, with the
    /// pair's guards and the comparison it ran for that step as
    /// `rule_locks`. `entrypoint` MUST be one of `"remove_signer"` or
    /// `"add_signer"`.
    ///
    /// The step signs under `rule_id` alone, with the pinned-hash drift
    /// check marking `rule_id` as the migrating rule: the rule's policies
    /// are checked against its pin record, its verifiers are not. The
    /// migration preflight already identified, allowlisted and probed the
    /// destination verifier, and the remove step signs while the source
    /// verifier, which may be the drifted contract the migration moves away
    /// from, is still live. The submit path skips the rule's signer-set
    /// baseline read and comparison because `rule_locks` carries the pair's
    /// own comparison of the rule; it acquires no lock. `expected_return` is
    /// checked against the simulated result before signing.
    ///
    /// # Errors
    ///
    /// Returned as themselves:
    ///
    /// - [`SaError::PolicyHashDrift`]: a policy of the rule differs from the
    ///   rule's pin record.
    /// - [`SaError::PinnedPolicyAbsent`]: the rule's pin record holds policy
    ///   pins while the rule has no policy on chain.
    /// - [`SaError::PinCheckUnavailable`]: the drift check could not run,
    ///   including an audit-log integrity error or an endpoint divergence it
    ///   met.
    /// - [`SaError::AuthEntryConstructionFailed`] at every stage, including
    ///   `rule_lock_missing` and `migrating_rule_mismatch`.
    /// - [`SaError::SubmissionUnresolved`]: the transaction was sent and its
    ///   outcome is unknown; it keeps its transaction and envelope hashes.
    ///
    /// Folded into [`SaError::VerifierMigrationFailed`], whose `detail`
    /// carries the folded error's Display:
    ///
    /// - phase `submit_simulate`: the simulation failed, or its return value
    ///   is not the `expected_return` shape;
    /// - phase `submit_send`: every other failure of the step, including a
    ///   transaction refused on send or failed on chain.
    ///
    /// # Implements
    ///
    /// Verifier diversification: each migration step submits a single
    /// `HostFunction` (`remove_signer` or `add_signer`) under the rule's
    /// lock.
    #[allow(clippy::too_many_arguments, reason = "irreducible migration-step args")]
    async fn submit_migration_step(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        entrypoint: &'static str,
        invoke_args: Vec<ScVal>,
        signer: &(dyn Signer + Send + Sync),
        source_pubkey_strkey: &str,
        smart_account_redacted: &str,
        request_id: &str,
        rule_locks: &BorrowedRuleLocks<'_>,
        expected_return: Option<ExpectedReturn>,
    ) -> Result<crate::submit::SubmitInvokeResult, SaError> {
        use crate::error::MIGRATION_PHASES;

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
            request_id,
            // The verifier check of the migrating rule is skipped; its policy
            // check runs. See `PinCheck::migrating_rule`.
            Some(crate::submit::MigratingRule::new(rule_id)),
            Some(rule_locks),
            expected_return,
        )
        .await
        .map_err(|e| {
            // The drift check's findings, every argument and lock stage, and
            // an unknown submission outcome keep their own identity. The
            // operator's next step is to inspect the contract, the audit log
            // or the transaction hash, not the migration. The step signs under
            // the migrating rule alone, whose verifier check is skipped, so no
            // verifier finding reaches it.
            if matches!(
                e,
                SaError::PolicyHashDrift { .. }
                    | SaError::PinnedPolicyAbsent { .. }
                    | SaError::PinCheckUnavailable { .. }
                    | SaError::AuthEntryConstructionFailed { .. }
                    | SaError::SubmissionUnresolved { .. }
            ) {
                return e;
            }
            // `submit_signed_invoke` reports both phases as
            // `SaError::DeploymentFailed`; the migration names the phase.
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
    /// - [`SaError::AuthEntryConstructionFailed`]: RPC or XDR construction
    ///   failure.
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

        let verifier_addrs = external_verifiers(rule.signers.iter().map(|(_, signer)| signer));
        Ok((verifier_addrs, rule.policies))
    }

    // ── Rule locks ────────────────────────────────────────────────────────────

    /// Acquires the locks of `rule_ids` on the smart account
    /// `smart_account_strkey`, sorted ascending and deduplicated, one at a
    /// time in that order, each wait bounded by `budget.deadline`.
    ///
    /// Rule 0 is locked like any other rule when it is named. The submit
    /// path names only the rules it compares, which never include rule 0.
    /// The total wait is logged on the `sa_submit_timing` debug span as stage
    /// `rule_lock`.
    ///
    /// # Errors
    ///
    /// [`SaError::AuthEntryConstructionFailed`] at stage `rule_lock` when a
    /// lock is not acquired before the deadline; the locks already taken are
    /// released.
    pub(crate) async fn acquire_rule_locks(
        &self,
        smart_account_strkey: &str,
        rule_ids: impl IntoIterator<Item = u32>,
        budget: PreSubmitBudget,
    ) -> Result<Vec<RuleLockGuard>, SaError> {
        let mut rule_ids: Vec<u32> = rule_ids.into_iter().collect();
        rule_ids.sort_unstable();
        rule_ids.dedup();
        let started = std::time::Instant::now();
        let mut guards = Vec::with_capacity(rule_ids.len());
        let mut outcome = Ok(());
        for rule_id in rule_ids {
            match self
                .lock_rule_before(smart_account_strkey, rule_id, budget.deadline)
                .await
            {
                Ok(guard) => guards.push(guard),
                Err(refusal) => {
                    outcome = Err(refusal);
                    break;
                }
            }
        }
        log_rule_lock_wait(started);
        outcome.map(|()| guards)
    }

    /// Acquires the lock of rule `rule_id` on the smart account
    /// `smart_account_strkey`, the single-rule form of
    /// [`Self::acquire_rule_locks`].
    ///
    /// # Errors
    ///
    /// [`SaError::AuthEntryConstructionFailed`] at stage `rule_lock` when the
    /// lock is not acquired before `budget.deadline`.
    pub(crate) async fn acquire_rule_lock(
        &self,
        smart_account_strkey: &str,
        rule_id: u32,
        budget: PreSubmitBudget,
    ) -> Result<RuleLockGuard, SaError> {
        let started = std::time::Instant::now();
        let outcome = self
            .lock_rule_before(smart_account_strkey, rule_id, budget.deadline)
            .await;
        log_rule_lock_wait(started);
        outcome
    }

    /// Waits for the lock of one rule until `deadline`.
    async fn lock_rule_before(
        &self,
        smart_account_strkey: &str,
        rule_id: u32,
        deadline: tokio::time::Instant,
    ) -> Result<RuleLockGuard, SaError> {
        let mutex = rule_mutex_acquire(&self.audit_log_path, rule_id, smart_account_strkey);
        let held = tokio::time::timeout_at(deadline, mutex.lock_owned())
            .await
            .map_err(|_elapsed| SaError::AuthEntryConstructionFailed {
                stage: "rule_lock",
                redacted_reason: format!(
                    "rule {rule_id}: the rule lock was not acquired within its budget"
                ),
            })?;
        Ok(RuleLockGuard {
            key: (
                self.audit_log_path.clone(),
                rule_id,
                smart_account_strkey.to_owned(),
            ),
            _held: held,
        })
    }

    /// The budget a holder's lock wait runs under: the manager's timeout from
    /// now.
    fn lock_budget(&self) -> PreSubmitBudget {
        PreSubmitBudget {
            deadline: tokio::time::Instant::now() + self.timeout,
            total: self.timeout,
        }
    }

    // ── list_signers ──────────────────────────────────────────────────────────

    /// Lists the current signer set of a context rule and compares it with
    /// the rule's audit-log state.
    ///
    /// Reads the rule's newest signer-set state row, then observes the signer
    /// set in version 2 through both RPC endpoints (the signers, the policy
    /// list, each policy's executable and the simple-threshold value; see
    /// [`ListOutcome`]). With no prior row it writes a `SaSignerSetBaselinedV2`
    /// row (`first_observation`) and reports [`PreviousBaseline::None`]. With a
    /// prior row it writes nothing and reports how the chain compares with
    /// that row in the row's version: [`PreviousBaseline::Matched`],
    /// [`PreviousBaseline::Diverged`] or [`PreviousBaseline::NotComparable`].
    ///
    /// A rule without a simple-threshold policy is observed with no threshold
    /// and can be baselined.
    ///
    /// This is the human-path bootstrap: calling `smart-account signers list`
    /// for the first time establishes the audit-log baseline so subsequent
    /// signing attempts can use it.
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
    /// - [`SaError::AuditLog`]: audit-log integrity violation on the state
    ///   read.
    /// - [`SaError::NetworkRpcDivergence`]: the two endpoints disagree on the
    ///   rule, a policy's executable or the threshold.
    /// - [`SaError::ThresholdPolicyIdentificationFailed`]: more than one
    ///   attached policy is a simple-threshold policy.
    /// - [`SaError::ThresholdReadFailed`]: the threshold read failed.
    /// - [`SaError::ContractInstanceUnsupported`]: a policy's instance is
    ///   malformed or an external reference with no live tag entry.
    /// - [`SaError::DeploymentFailed`] (phase `"simulate"`): a read failed or
    ///   the rule holds a signer the wallet cannot decode.
    /// - [`SaError::BaselineWriteFailed`] (stage `write`): the first
    ///   observation's baseline row was not written.
    /// - [`SaError::AuthEntryConstructionFailed`]: RPC or XDR construction
    ///   failure, or the rule's lock was not acquired within the manager's
    ///   timeout (stage `rule_lock`).
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: ensures baseline is written before any
    /// signer mutation can be issued against a rule, so the audit trail always
    /// has a starting point for divergence detection.
    pub async fn list_signers(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<ListOutcome, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // The rule's lock serializes the first-observation baseline write with
        // every other comparison and mutation of the rule.
        let _guard = self
            .acquire_rule_lock(&smart_account_strkey, rule_id, self.lock_budget())
            .await?;

        // The state row is read before the observation: an audit-log integrity
        // failure refuses without any RPC.
        let prior =
            self.read_signer_set_view(rule_id, &smart_account_strkey, &smart_account_redacted)?;

        let observation = self
            .observe_signer_set_v2(
                &smart_account,
                rule_id,
                source_account_strkey,
                None,
                &request_id,
            )
            .await?;

        let Some(prior) = prior else {
            self.emit_baseline(
                &observation,
                rule_id,
                &smart_account_strkey,
                &smart_account_redacted,
                BaselineReason::first_observation(),
                None,
                &request_id,
            )?;
            info!(
                profile = %self.profile_name,
                rule_id,
                smart_account = %smart_account_redacted,
                signer_count = observation.snapshot.signer_count(),
                threshold = ?observation.snapshot.threshold.as_ref().map(|t| t.threshold),
                "list_signers: first observation baselined"
            );
            return Ok(ListOutcome {
                view: SignerSetView::V2(observation.snapshot),
                baseline: PreviousBaseline::None,
            });
        };

        let baseline = match classify_against(prior.view(), &observation)? {
            Classified::Matched { .. } => PreviousBaseline::Matched,
            Classified::Diverged { .. } => PreviousBaseline::Diverged,
            Classified::NotComparable { cause } => {
                debug!(
                    rule_id,
                    cause = cause.wire_code(),
                    "list_signers: the version-1 baseline has no comparable projection"
                );
                PreviousBaseline::NotComparable
            }
        };

        info!(
            profile = %self.profile_name,
            rule_id,
            smart_account = %smart_account_redacted,
            signer_count = observation.snapshot.signer_count(),
            threshold = ?observation.snapshot.threshold.as_ref().map(|t| t.threshold),
            baseline = ?baseline,
            "list_signers: on-chain signer set"
        );

        Ok(ListOutcome {
            view: SignerSetView::V2(observation.snapshot),
            baseline,
        })
    }

    // ── refresh_signer_baseline ───────────────────────────────────────────────

    /// Observes the on-chain signer set, compares it with the rule's
    /// audit-log state and records it as a new `SaSignerSetBaselinedV2` row.
    ///
    /// The signer set is observed once in version 2 through both RPC
    /// endpoints, under the rule's lock. With a prior state row it is
    /// compared in that row's version, a version-1 row through the version-1
    /// projection of the same reads (see [`RefreshOutcome`]):
    ///
    /// - no prior row, or a matching one: the baseline is written;
    /// - a changed set ([`PreviousBaseline::Diverged`]): a
    ///   `SaSignerSetDiverged` row records the two states, then the baseline
    ///   is written only with [`RefreshOptions::accept_divergence`];
    ///   otherwise the call refuses with [`SaError::SignerSetDiverged`];
    /// - a version-1 row with no comparable projection
    ///   ([`PreviousBaseline::NotComparable`]: a signer delegated to a
    ///   contract address, or no simple-threshold policy): nothing is
    ///   written. The call refuses with [`SaError::SignerSetDiverged`]
    ///   carrying the version-1 row and the version-2 observation, unless
    ///   [`RefreshOptions::accept_divergence`] is set, which writes the
    ///   baseline.
    ///
    /// # Verifier reconciliation
    ///
    /// When the rule has a pin record that pins no verifier and the
    /// observation holds `External` signers, the signing-time drift check
    /// refuses the rule with [`SaError::PinnedVerifierAbsent`]. Before the
    /// baseline is written, the refresh then identifies and probes each
    /// distinct live verifier as `rules create` probes one. A mutable
    /// verifier needs [`RefreshOptions::with_accept_mutable_verifier`], and
    /// one whose hash is outside the verifier allowlist needs
    /// [`RefreshOptions::with_accept_unknown_verifier`]. An unpinnable
    /// instance refuses regardless. A refusal returns before the baseline or
    /// any pin row is written.
    ///
    /// Two verifier addresses whose pins are equal, in hash and executable
    /// reference, share one pin. Live verifiers whose pins differ refuse with
    /// [`SaError::MultiplePinnedHashesUnsupported`] before the baseline or
    /// any pin row is written, since a rule is pinned to one verifier. After
    /// the baseline row, the refresh writes the applied overrides' rows and a
    /// `SaContextRulePinsUpdated` row (reason `baseline_refreshed`) that
    /// adds the verifier pin to the record. A record that already pins a
    /// verifier is left as it is while the rule holds `External` signers,
    /// whatever the live verifier runs: a pinned verifier that changed is the
    /// drift check's finding. A rule without a pin record, such as one
    /// installed outside the wallet, gets no record.
    ///
    /// When the observation holds no `External` signer and the record pins
    /// exactly one verifier, the refresh drops that pin. A verifier pin on a
    /// rule without `External` signers protects nothing, and the refresh is
    /// the operator's explicit reconciliation of the record with the chain.
    /// After the baseline row, a `SaContextRulePinsUpdated` row (reason
    /// `baseline_refreshed`) records the record without a verifier pin, the
    /// policy pins and override flags unchanged. A signer added on a verifier
    /// later pins that verifier.
    ///
    /// Call this after an intentional out-of-band signer change, once on a
    /// rule whose baseline is version 1, or on a rule refused with
    /// [`SaError::PinnedVerifierAbsent`], to re-anchor the wallet's view of
    /// the rule.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to baseline.
    /// - `source_account_strkey` — G-strkey of the fee-paying account.
    /// - `options`: whether a differing state is recorded, and the verifier
    ///   overrides of the reconciliation.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::SignerSetDiverged`] (no transaction hash): the chain
    ///   differs from the prior row, or a version-1 row cannot be compared,
    ///   and `accept_divergence` is not set.
    /// - [`SaError::VerifierMutable`], [`SaError::VerifierWasmNotInAllowlist`]
    ///   and [`SaError::ContractInstanceUnsupported`]: a live verifier the
    ///   reconciliation probed was refused; the Display names the override
    ///   it needs.
    /// - [`SaError::MultiplePinnedHashesUnsupported`] (kind `verifier`): the
    ///   live verifiers' pins differ in hash or executable reference.
    /// - [`SaError::BaselineWriteFailed`] (stage `write`): the baseline row
    ///   was not written.
    /// - [`SaError::AuditLog`]: audit-log integrity violation.
    /// - The observation errors of [`Self::list_signers`].
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: ensures baseline is re-established
    /// after an out-of-band signer change so divergence detection remains
    /// accurate.
    pub async fn refresh_signer_baseline(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        options: RefreshOptions,
        request_id: String,
    ) -> Result<RefreshOutcome, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
        let accept_divergence = options.accept_divergence();

        let _guard = self
            .acquire_rule_lock(&smart_account_strkey, rule_id, self.lock_budget())
            .await?;

        let prior =
            self.read_signer_set_view(rule_id, &smart_account_strkey, &smart_account_redacted)?;

        let observation = self
            .observe_signer_set_v2(
                &smart_account,
                rule_id,
                source_account_strkey,
                None,
                &request_id,
            )
            .await?;

        let previous_baseline = match prior {
            None => PreviousBaseline::None,
            Some(prior) => {
                let expected = prior.view().clone();
                match classify_against(&expected, &observation)? {
                    Classified::Matched { .. } => PreviousBaseline::Matched,
                    Classified::Diverged { observed } => {
                        // The log records what the refresh met, whether or
                        // not it accepts it.
                        self.emit_signer_set_diverged(
                            rule_id,
                            &smart_account_redacted,
                            &expected,
                            &observed,
                            &request_id,
                        );
                        if !accept_divergence {
                            return Err(SaError::SignerSetDiverged {
                                rule_id,
                                expected,
                                observed,
                                tx_hash: None,
                                smart_account_redacted: RedactedStrkey::from_already_redacted(
                                    smart_account_redacted,
                                ),
                                request_id,
                            });
                        }
                        PreviousBaseline::Diverged
                    }
                    Classified::NotComparable { cause } => {
                        warn!(
                            rule_id,
                            smart_account = %smart_account_redacted,
                            cause = cause.wire_code(),
                            accept_divergence,
                            "refresh_signer_baseline: the version-1 baseline cannot be compared \
                             with the chain"
                        );
                        if !accept_divergence {
                            return Err(SaError::SignerSetDiverged {
                                rule_id,
                                expected,
                                observed: SignerSetView::V2(observation.snapshot),
                                tx_hash: None,
                                smart_account_redacted: RedactedStrkey::from_already_redacted(
                                    smart_account_redacted,
                                ),
                                request_id,
                            });
                        }
                        PreviousBaseline::NotComparable
                    }
                }
            }
        };

        let pin_update = self
            .plan_refresh_pin_update(
                rule_id,
                &smart_account_redacted,
                &observation.snapshot,
                PinOverrides {
                    accept_mutable_verifier: options.accept_mutable_verifier(),
                    accept_unknown_verifier: options.accept_unknown_verifier(),
                },
                &request_id,
            )
            .await?;
        let (pin_update, verifier_pinned, verifier_pin_dropped) = match pin_update {
            RefreshPinPlan::Unchanged => (None, false, false),
            RefreshPinPlan::PinLiveVerifier(update) => (Some(update), true, false),
            RefreshPinPlan::DropDeadPin(update) => (Some(update), false, true),
        };

        self.emit_baseline(
            &observation,
            rule_id,
            &smart_account_strkey,
            &smart_account_redacted,
            BaselineReason::explicit_refresh(),
            None,
            &request_id,
        )?;
        self.write_pin_rows(
            rule_id,
            &smart_account_redacted,
            pin_update,
            PinsUpdateReason::BaselineRefreshed,
            &request_id,
        );

        info!(
            profile = %self.profile_name,
            rule_id,
            smart_account = %smart_account_redacted,
            signer_count = observation.snapshot.signer_count(),
            threshold = ?observation.snapshot.threshold.as_ref().map(|t| t.threshold),
            previous_baseline = ?previous_baseline,
            verifier_pinned,
            verifier_pin_dropped,
            "refresh_signer_baseline: baseline written"
        );

        Ok(RefreshOutcome {
            view: SignerSetView::V2(observation.snapshot),
            previous_baseline,
            verifier_pinned,
        })
    }

    /// Plans the verifier reconciliation of a refresh of rule `rule_id`; see
    /// "Verifier reconciliation" on [`Self::refresh_signer_baseline`].
    ///
    /// `observed` is the rule's signer set the refresh observed under the
    /// rule's lock. A rule without a pin record is left unchanged.
    ///
    /// - With no live `External` signer, a record that pins exactly one
    ///   verifier drops that pin ([`RefreshPinPlan::DropDeadPin`]). A
    ///   verifier pin on a rule without `External` signers protects nothing,
    ///   and the refresh is the operator's explicit reconciliation of the
    ///   record with the chain. Any other record is left unchanged.
    /// - With live `External` signers, a record that already pins a verifier
    ///   is left unchanged: a pinned verifier that changed is the drift
    ///   check's finding. A record that pins none gains the one pin every
    ///   live verifier's probe produced, equal in hash and executable
    ///   reference, with the overrides applied while probing them pending
    ///   ([`RefreshPinPlan::PinLiveVerifier`]).
    ///
    /// # Errors
    ///
    /// - [`SaError::AuditLog`]: the pin record could not be read.
    /// - The refusals of `pin_added_contract` for a live verifier.
    /// - [`SaError::MultiplePinnedHashesUnsupported`] (kind `verifier`, count
    ///   2): two live verifiers' pins differ in hash or executable reference.
    async fn plan_refresh_pin_update(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        observed: &SignerSetSnapshotV2,
        overrides: PinOverrides,
        request_id: &str,
    ) -> Result<RefreshPinPlan, SaError> {
        let mut live_verifiers: Vec<ScAddress> = Vec::new();
        for entry in &observed.signers {
            if let SignerIdentityV2::External { verifier, .. } = &entry.identity {
                let address = ScAddress::Contract(ContractId(Hash(*verifier)));
                if !live_verifiers.contains(&address) {
                    live_verifiers.push(address);
                }
            }
        }
        let Some(record) = crate::managers::verifiers::read_pinned_hashes_for_rule(
            self,
            rule_id,
            smart_account_redacted,
        )?
        else {
            debug!(
                rule_id,
                "signers refresh: the rule has no pin record; no verifier is pinned"
            );
            return Ok(RefreshPinPlan::Unchanged);
        };
        if live_verifiers.is_empty() {
            if record.pinned_verifier_first8.len() != 1 {
                return Ok(RefreshPinPlan::Unchanged);
            }
            let mut update = PlannedPinUpdate::unchanged(record);
            update.record.pinned_verifier_first8 = Vec::new();
            update.record.pinned_verifier_executable_refs = Vec::new();
            return Ok(RefreshPinPlan::DropDeadPin(update));
        }
        if !record.pinned_verifier_first8.is_empty() {
            return Ok(RefreshPinPlan::Unchanged);
        }

        let mut update = PlannedPinUpdate::unchanged(record);
        for verifier in &live_verifiers {
            let pin = crate::managers::verifiers::pin_added_contract(
                self,
                verifier,
                PinnedKind::Verifier,
                rule_id,
                smart_account_redacted,
                overrides.accept_mutable_verifier,
                overrides.accept_unknown_verifier,
                request_id,
            )
            .await?;
            if update.record.pinned_verifier_first8.is_empty() {
                update.append_pin(PinnedKind::Verifier, pin);
            } else if update.record.pinned_verifier_first8.first() == Some(&pin.hash_first8)
                && update.record.verifier_executable_ref(0) == pin.executable_ref.as_ref()
            {
                // Another address whose pin equals the recorded one, in hash
                // and executable reference. The signing check compares it
                // with that pin and accepts it, so it adds no pin, and the
                // overrides applied to it are recorded.
                update.fold_overrides(
                    pin.mutable_override,
                    pin.unknown_override,
                    pin.pending_overrides,
                );
            } else {
                return Err(SaError::MultiplePinnedHashesUnsupported {
                    kind: "verifier",
                    rule_id,
                    count: 2,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    request_id: request_id.to_owned(),
                });
            }
        }
        Ok(RefreshPinPlan::PinLiveVerifier(update))
    }

    // ── verify_signer_set_against_chain ───────────────────────────────────────

    /// Checks the on-chain signer set against the audit-log baseline.
    ///
    /// Acquires the rule's lock, bounded by the manager's timeout, then
    /// compares (see `verify_signer_set_locked`):
    ///
    /// 1. **Audit-log read**: loads the newest signer-set state row of either
    ///    snapshot version. Returns [`SaError::SignerSetMissingBaseline`] if no
    ///    baseline exists (before any RPC call), or [`SaError::AuditLog`] on
    ///    integrity failure.
    /// 2. **Two-RPC observation**: observes the signer set in version 2
    ///    through the primary and secondary endpoints. Returns
    ///    [`SaError::NetworkRpcDivergence`] if they disagree.
    /// 3. **Audit-vs-chain comparison**: compares the row with the
    ///    observation in the row's version: a version-2 row with the full
    ///    snapshot, a version-1 row with the observation's version-1
    ///    projection, whose 16-byte `External` key-data prefix is all a
    ///    version-1 row records. Returns [`SaError::SignerSetDiverged`] (and
    ///    writes a `SaSignerSetDiverged` audit row) if they disagree.
    ///
    /// On success, returns a move-only [`FrozenChainStateTuple`] carrying the
    /// observed view in the row's version, the smallest `latestLedger` the
    /// observation's reads reported and the matched row's hash.
    ///
    /// The submit path runs the same three steps for every non-zero rule a submission
    /// is signed under, under the rule's lock, through
    /// [`crate::submit::submit_signed_invoke`]; this entry is the standalone
    /// form of that check. The `FrozenChainStateTuple` is a data-only record
    /// of the comparison and does not retain the rule's lock: a later call on
    /// the same rule compares again under its own lock.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to verify.
    /// - `source_account_strkey` — `Some(G...)` for a real fee-paying account,
    ///   or `None` when no fee-payer is available. When `None`, the
    ///   underlying simulations use [`SIMULATE_SENTINEL_G`] with sequence
    ///   number `"0"`.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::SignerSetMissingBaseline`] — no baseline row in audit log.
    /// - [`SaError::AuditLog`] — audit-log integrity violation.
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree.
    /// - [`SaError::SignerSetDiverged`] — on-chain state differs from baseline.
    /// - [`SaError::ThresholdPolicyNotInstalled`] /
    ///   [`SaError::ThresholdPolicyIdentificationFailed`]: a version-1
    ///   baseline needs a threshold and the rule observes none.
    /// - [`SaError::DeploymentFailed`]: a read failed, or a version-1
    ///   baseline meets a signer it has no representation for.
    /// - [`SaError::AuthEntryConstructionFailed`]: RPC or XDR construction
    ///   failure, or the rule's lock was not acquired within the manager's
    ///   timeout (stage `rule_lock`).
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: the comparison anchors a signature
    /// under the rule against the recorded signer set, and the same check
    /// guards every submission signed under a rule other than rule 0.
    pub async fn verify_signer_set_against_chain(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<FrozenChainStateTuple, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let guard = self
            .acquire_rule_lock(&smart_account_strkey, rule_id, self.lock_budget())
            .await?;
        let compared = self
            .verify_signer_set_locked(
                &guard,
                V1Handling::Compare,
                source_account_strkey,
                &request_id,
            )
            .await?;
        drop(guard);

        let now_ms = i64::try_from(now_unix_ms().unwrap_or(0)).unwrap_or(i64::MAX);

        debug!(
            profile = %self.profile_name,
            rule_id,
            smart_account = %smart_account_redacted,
            observed = %compared.view(),
            ledger = compared.ledger(),
            "verify_signer_set_against_chain: on-chain matches baseline"
        );

        Ok(FrozenChainStateTuple::new(
            compared.view().clone(),
            (compared.ledger(), now_ms),
            *compared.row_hash(),
            rule_id,
        ))
    }

    // ── add_signer ────────────────────────────────────────────────────────────

    /// Adds a signer to a context rule.
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Compares the chain with the rule's version-2 audit-log state through
    ///    both RPC endpoints; a version-1 state refuses before any RPC with
    ///    [`SaError::SignerSetBaselineLegacy`], a changed set refuses with
    ///    [`SaError::SignerSetDiverged`] and submits nothing.
    /// 2. Checks `signer_count' <= MAX_SIGNERS` and, when the rule has a
    ///    simple-threshold policy, the threshold invariant; refuses with
    ///    [`SaError::ThresholdUnreachable`] if the add would create an
    ///    unreachable threshold state.
    /// 3. Constructs and submits a single `InvokeHostFunctionOp` transaction.
    /// 4. After it confirms, observes the rule through both endpoints at or
    ///    past the confirmation ledger and requires exactly the intended
    ///    change. The new signer must hold a new id equal to the id the
    ///    simulation returned; every other signer and the threshold must be
    ///    unchanged.
    /// 5. Writes a `SaSignerAddedV2` audit row carrying the resulting set,
    ///    then the override rows and the `SaContextRulePinsUpdated` row
    ///    described under "Pin record".
    ///
    /// # Pin record
    ///
    /// A rule's pin record is its newest `SaContextRuleCreated` or
    /// `SaContextRulePinsUpdated` row. When the new signer is `External` (a
    /// passkey signer included) and the rule has a pin record, the add keeps
    /// the record in step with the rule's live verifier set. The
    /// signing-time drift check then does not refuse the rule the wallet
    /// itself changed:
    ///
    /// - before submission, each new verifier address not already live on
    ///   the rule is identified and probed with the checks rule install
    ///   applies: an allowlist miss refuses unless `accept_unknown_verifier`
    ///   is set, and a mutable contract refuses unless
    ///   `accept_mutable_verifier` is set;
    /// - once the add confirms, each applied override writes its override
    ///   row carrying the rule id; a refused add writes none;
    /// - then a `SaContextRulePinsUpdated` row (reason `signer_added`)
    ///   records the verifier pins, one per distinct pin in hash and
    ///   executable reference. A signer on a verifier already live, or on a
    ///   new verifier whose pin equals a recorded one, leaves the list
    ///   unchanged. A signer on a new verifier with another pin appends it.
    ///
    /// The pin rows are written exactly once after the add confirms. They
    /// follow the `SaSignerAddedV2` row when the change is recorded. When the
    /// confirmed state is not observed or not the intended change, they are
    /// written before the refusal returns. When the state row is not written,
    /// they are attempted, and the audit log usually refuses them as well.
    /// The confirmed add put the new verifier on the rule in every case, and
    /// a pin only restricts which executable may run under it.
    ///
    /// A record with more than one verifier pin is refused by every checked
    /// signing verb with `sa.pin_check_unavailable`
    /// (`sa.multiple_pinned_hashes_unsupported`), the outcome for a rule
    /// installed with two verifiers. A rule without a pin record stays
    /// unpinned: nothing is observed and no row is written.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule to update.
    /// - `new_signer`: the signer to add (encoded as an OZ `Signer` ScVal);
    ///   its identity for the comparison, the audit row and pin planning is
    ///   decoded from this value.
    /// - `signer` — the ed25519 signer for auth-entry signing + fee envelope.
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    /// - `accept_mutable_verifier` / `accept_unknown_verifier`: the overrides
    ///   `rules create` takes, applied to a new verifier pinned under
    ///   "Pin record".
    ///
    /// # Errors
    ///
    /// - [`SaError::VerifierWasmNotInAllowlist`] / [`SaError::VerifierMutable`] /
    ///   [`SaError::ContractInstanceUnsupported`]: a new verifier of a pinned
    ///   rule was refused under "Pin record".
    /// - [`SaError::VerifierHashDrift`] / [`SaError::PolicyHashDrift`] /
    ///   [`SaError::PinnedPolicyAbsent`] / [`SaError::PinCheckUnavailable`]:
    ///   the pinned-hash drift check of the rule refused before signing.
    /// - [`SaError::ContextRuleCapsExceeded`] — signer count would exceed `MAX_SIGNERS`.
    /// - [`SaError::ThresholdUnreachable`] — threshold invariant violated.
    /// - [`SaError::SignerSetMissingBaseline`] — no audit-log baseline.
    /// - [`SaError::SignerSetBaselineLegacy`]: the baseline is version 1.
    /// - [`SaError::AuditLog`] — audit-log integrity violation.
    /// - [`SaError::NetworkRpcDivergence`]: two-RPC disagreement before
    ///   submission.
    /// - [`SaError::SignerSetDiverged`]: the chain differs from the baseline
    ///   before submission (no transaction hash), or the confirmed set is not
    ///   the intended change (with the transaction hash).
    /// - [`SaError::BaselineWriteFailed`]: the transaction confirmed and its
    ///   resulting state was not observed (stage `observe`) or not recorded
    ///   (stage `write`).
    /// - [`SaError::DeploymentFailed`] — submission or on-chain rejection.
    /// - [`SaError::AuthEntryConstructionFailed`]: XDR or RPC construction
    ///   failure, or `new_signer` is not a signer the wallet can decode.
    ///
    /// # Implements
    ///
    /// Atomic signer-threshold update: the signer is added in a single
    /// `InvokeHostFunctionOp` transaction; the threshold invariant is checked
    /// before submission to prevent unreachable configurations.
    #[allow(
        clippy::too_many_arguments,
        reason = "signer + auth + audit arg set plus the two pin overrides rule install takes"
    )]
    pub async fn add_signer(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        new_signer: ScVal,
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
        accept_mutable_verifier: bool,
        accept_unknown_verifier: bool,
    ) -> Result<u32, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // The target is the only rule the add signs under.
        let guards = self
            .acquire_rule_locks(&smart_account_strkey, [rule_id], self.lock_budget())
            .await?;

        let outcome = self
            .add_signer_locked_inner(
                smart_account,
                rule_id,
                &guards,
                &smart_account_strkey,
                &smart_account_redacted,
                new_signer,
                signer,
                &request_id,
                PinOverrides {
                    accept_mutable_verifier,
                    accept_unknown_verifier,
                },
            )
            .await;
        let confirmed = outcome
            .inspect_err(|err| warn_failed("add_signer", rule_id, &smart_account_redacted, err))?;

        let [signer_id] = self.record_confirmed_add(
            "add_signer",
            rule_id,
            &smart_account_strkey,
            &smart_account_redacted,
            confirmed,
            &request_id,
        )?;
        Ok(signer_id)
    }

    // ── remove_signer ─────────────────────────────────────────────────────────

    /// Removes a signer from a context rule.
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Compares the chain with the rule's version-2 audit-log state, as
    ///    [`Self::add_signer`] does.
    /// 2. When the rule has a simple-threshold policy, validates
    ///    `threshold' >= 1 && signer_count' >= threshold'`; returns
    ///    [`SaError::ThresholdUnreachable`] with a `safe_ordering_hint` if the
    ///    invariant would be violated. To lower the threshold first, run
    ///    `smart-account signers set-threshold` and then retry the removal.
    ///    A rule with no policy has no threshold to check. A rule whose
    ///    policies include no simple-threshold policy refuses with
    ///    [`SaError::ThresholdPolicyIdentificationFailed`]: another policy
    ///    decides which signers suffice, and a removal could make its
    ///    threshold unreachable.
    /// 3. Constructs and submits a single `InvokeHostFunctionOp` transaction.
    /// 4. After it confirms, requires exactly the intended change (the signer
    ///    absent, every other signer and the threshold unchanged) through both
    ///    endpoints at or past the confirmation ledger.
    /// 5. Writes a `SaSignerRemovedV2` audit row carrying the resulting set.
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
    /// See [`Self::add_signer`] for the error taxonomy; the same variants
    /// apply, plus [`SaError::ThresholdPolicyIdentificationFailed`] for a rule
    /// whose policies include no simple-threshold policy.
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

        // The target is the only rule the removal signs under.
        let guards = self
            .acquire_rule_locks(&smart_account_strkey, [rule_id], self.lock_budget())
            .await?;

        let outcome = self
            .remove_signer_locked_inner(
                smart_account,
                rule_id,
                &guards,
                &smart_account_strkey,
                &smart_account_redacted,
                signer_id,
                signer,
                &request_id,
            )
            .await;
        let confirmed = outcome.inspect_err(|err| {
            warn_failed("remove_signer", rule_id, &smart_account_redacted, err)
        })?;

        let account = account_digest(&self.network_passphrase, &smart_account_strkey);
        self.write_confirmed_state_row(
            rule_id,
            &smart_account_redacted,
            &confirmed.tx_hash,
            &request_id,
            |_| {
                AuditEntry::new_sa_signer_removed_v2(
                    rule_id,
                    signer_id,
                    &confirmed.resulting,
                    account,
                    RedactedStrkey::from_already_redacted(smart_account_redacted.as_str()),
                    self.chain_id.as_str(),
                    request_id.as_str(),
                )
            },
        )
    }

    // ── set_threshold ─────────────────────────────────────────────────────────

    /// Changes the threshold of a context rule (without a signer-count change).
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Compares the chain with the rule's version-2 audit-log state, as
    ///    [`Self::add_signer`] does. The comparison's observation supplies the
    ///    signer count, the simple-threshold policy, the current threshold
    ///    and the rule value passed to the policy.
    /// 2. Refuses a rule with no simple-threshold policy with
    ///    [`SaError::ThresholdPolicyNotInstalled`].
    /// 3. Validates `1 <= new_threshold <= signer_count`.
    /// 4. Constructs and submits a single `InvokeHostFunctionOp` targeting
    ///    the threshold-policy `set_threshold` entrypoint.
    /// 5. After it confirms, requires exactly the intended change (the new
    ///    threshold on the same policy, the signers unchanged) through both
    ///    endpoints at or past the confirmation ledger.
    /// 6. Writes a `SaThresholdChangedV2` audit row carrying the previous
    ///    threshold observation and the resulting set.
    ///
    /// # Arguments
    ///
    /// - `smart_account`: the smart-account contract's [`ScAddress`].
    /// - `rule_id`: the context rule to update.
    /// - `new_threshold`: the desired new threshold.
    /// - `signer`: the ed25519 signer.
    /// - `request_id`: caller-supplied UUID.
    ///
    /// # Errors
    ///
    /// - [`SaError::ThresholdUnreachable`]: new threshold would violate invariants.
    /// - [`SaError::ThresholdPolicyNotInstalled`]: the rule has no
    ///   simple-threshold policy.
    /// - The comparison, submission and recording errors of
    ///   [`Self::add_signer`].
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

        // The target is the only rule the change signs under.
        let guards = self
            .acquire_rule_locks(&smart_account_strkey, [rule_id], self.lock_budget())
            .await?;

        let outcome = self
            .set_threshold_locked_inner(
                smart_account,
                rule_id,
                &guards,
                &smart_account_strkey,
                &smart_account_redacted,
                new_threshold,
                signer,
                &request_id,
            )
            .await;
        let (previous, confirmed) = outcome.inspect_err(|err| {
            warn_failed("set_threshold", rule_id, &smart_account_redacted, err)
        })?;

        let account = account_digest(&self.network_passphrase, &smart_account_strkey);
        self.write_confirmed_state_row(
            rule_id,
            &smart_account_redacted,
            &confirmed.tx_hash,
            &request_id,
            |_| {
                AuditEntry::new_sa_threshold_changed_v2(
                    rule_id,
                    Some(previous),
                    &confirmed.resulting,
                    account,
                    RedactedStrkey::from_already_redacted(smart_account_redacted.as_str()),
                    self.chain_id.as_str(),
                    request_id.as_str(),
                )
            },
        )
    }

    // ── Rule install and the policy entries ───────────────────────────────────

    /// Records the signer-set baseline of a rule the wallet installed, from
    /// the confirmed chain state.
    ///
    /// Acquires the rule's lock, then observes the rule through both
    /// endpoints at or past the confirmation ledger of `submitted` and
    /// requires the observation to be the authorized definition:
    ///
    /// - the observed signers' version-2 identities equal `expected.signers`
    ///   as a multiset: the counts are equal and each expected identity is
    ///   matched by exactly one observed signer;
    /// - the observed threshold equals `expected.threshold`: none when the
    ///   definition attaches no simple-threshold policy, otherwise the same
    ///   policy with the same value.
    ///
    /// The validated observation is written as a `SaSignerSetBaselinedV2`
    /// row with reason `confirmed_install`.
    ///
    /// # Errors
    ///
    /// - [`SaError::BaselineWriteFailed`] with the transaction hash: the
    ///   rule's lock was not acquired within the manager's timeout or the
    ///   confirmed rule was not observed (stage `observe`), or the row was
    ///   not written (stage `write`).
    /// - [`SaError::InstallStateMismatch`] with the rule id and the
    ///   transaction hash: the observed rule is not the definition. No row is
    ///   written.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the new rule, its expected state, the confirmed \
                  transaction, the source account and the correlation id"
    )]
    pub(crate) async fn baseline_confirmed_install(
        &self,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        expected: &ExpectedInstallState,
        submitted: &crate::submit::SubmitInvokeResult,
        source_account_strkey: &str,
        request_id: &str,
    ) -> Result<(), SaError> {
        // The install confirmed: a lock not acquired in time leaves the rule
        // unobserved, which is a stage-`observe` failure carrying the hash.
        let _guard = self
            .acquire_rule_lock(smart_account_strkey, rule_id, self.lock_budget())
            .await
            .map_err(|cause| {
                observe_failed_after(
                    rule_id,
                    smart_account_redacted,
                    &submitted.tx_hash,
                    &cause,
                    request_id,
                )
            })?;

        let observation = self
            .observe_confirmed(
                smart_account,
                rule_id,
                Some(source_account_strkey),
                submitted,
                smart_account_redacted,
                request_id,
            )
            .await?;
        if !is_installed_state(&observation.snapshot, expected) {
            warn!(
                rule_id,
                smart_account = %smart_account_redacted,
                tx_hash = %submitted.tx_hash,
                observed_signer_count = observation.snapshot.signer_count(),
                expected_signer_count = expected.signers.len(),
                "baseline_confirmed_install: the confirmed rule is not the authorized definition"
            );
            return Err(SaError::InstallStateMismatch {
                rule_id: Some(rule_id),
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                tx_hash: submitted.tx_hash.clone(),
                request_id: request_id.to_owned(),
            });
        }
        self.emit_baseline(
            &observation,
            rule_id,
            smart_account_strkey,
            smart_account_redacted,
            BaselineReason::confirmed_install(),
            Some(&submitted.tx_hash),
            request_id,
        )
    }

    /// Attaches `policy` to rule `rule_id` through `submit`, and writes the
    /// rows the confirmed attach records under the locks.
    ///
    /// Acquires, in one acquisition, the locks of the rule and of the
    /// distinct non-zero rules in `auth_rule_ids`, the rules the attach is
    /// signed under, then, every step under the locks:
    ///
    /// 1. Compares the chain with the rule's version-2 state row, as
    ///    [`Self::add_signer`] does. A missing row refuses with
    ///    [`SaError::SignerSetMissingBaseline`] and a version-1 row with
    ///    [`SaError::SignerSetBaselineLegacy`], both before any RPC; a changed
    ///    set refuses with [`SaError::SignerSetDiverged`].
    /// 2. Observes the policy's executable through both endpoints to tell
    ///    whether it is the simple-threshold policy. For that policy,
    ///    `install_param` must be the `{ threshold: u32 }` map with a non-zero
    ///    threshold ([`SaError::SimpleThresholdInstallRefused`]). A rule that
    ///    already has a simple-threshold policy refuses with
    ///    [`SaError::ThresholdPolicyIdentificationFailed`]: the only change an
    ///    attach records is from no threshold to one.
    /// 3. Plans the pin record the attach writes when the rule has one, from
    ///    the record read here and the live policies of the comparison; a
    ///    policy not already live is probed as `rules create` probes one.
    /// 4. Runs `submit` with the held locks, the comparison of step 1 and the
    ///    invocation arguments built here. It signs and submits the
    ///    `add_policy` invocation, and the submit path compares every auth
    ///    rule other than the target under the held locks.
    /// 5. Reads the assigned policy id from the confirmed return value. For
    ///    the simple-threshold policy it observes the rule after confirmation,
    ///    requires the signers unchanged and the threshold the parameter's,
    ///    and writes the `SaThresholdChangedV2` row.
    /// 6. Writes the planned override rows and the `SaContextRulePinsUpdated`
    ///    row, whatever step 5 returned, since the policy is on chain.
    ///
    /// A concurrent verb on the rule is therefore serialized before or after
    /// the whole attach. The rows written here precede the policy and raw
    /// invocation rows the caller writes after this entry returns.
    ///
    /// The held-lock context lends the target compared and any non-zero auth
    /// rule uncompared; the submit path reads and compares the latter under
    /// the lent guard. An attach authorized under rule 0 alone locks the
    /// target only.
    ///
    /// `budget`, the manager's timeout from the start of the call, bounds the
    /// lock wait, the policy's observation and the plan. The comparison's
    /// reads carry the manager's per-read timeout, and the submission carries
    /// the caller's own pre-submit budget.
    ///
    /// # Returns
    ///
    /// `Err` when the entry returned before a confirmation; nothing was
    /// recorded. `Ok` once the transaction confirmed. Then `parsed` is the
    /// policy id, `None` only when the return value is not a `u32`.
    /// `recorded` is the outcome of the threshold recording of step 5,
    /// `Ok(())` for any other policy, or the stage-`observe` refusal of a
    /// return value that is not a `u32`.
    ///
    /// # Errors
    ///
    /// - The comparison errors of [`Self::add_signer`].
    /// - The observation errors of the policy
    ///   ([`SaError::ContractInstanceUnsupported`],
    ///   [`SaError::NetworkRpcDivergence`], [`SaError::DeploymentFailed`]).
    /// - [`SaError::SimpleThresholdInstallRefused`] and
    ///   [`SaError::ThresholdPolicyIdentificationFailed`].
    /// - The pin refusals of a probed policy
    ///   ([`SaError::PolicyWasmNotInAllowlist`], [`SaError::PolicyMutable`]),
    ///   and [`SaError::AuditLog`] when the pin record cannot be read.
    /// - [`SaError::AuthEntryConstructionFailed`] when the budget elapses.
    /// - The errors of `submit`.
    /// - After confirmation, `recorded` carries
    ///   [`SaError::BaselineWriteFailed`] (stage `observe` or `write`) or
    ///   [`SaError::SignerSetDiverged`] with the transaction hash.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the rule and its auth rules, the policy and its \
                  parameter, the pin overrides, the source account, the submission and the \
                  correlation id"
    )]
    pub(crate) async fn attach_policy<'env>(
        &self,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        auth_rule_ids: &[ContextRuleId],
        policy: &ScAddress,
        install_param: ScVal,
        overrides: PinOverrides,
        source_account_strkey: Option<&str>,
        submit: impl for<'l> FnOnce(LockedSubmission<'l, 'env>, Vec<ScVal>) -> LockedSubmitFuture<'l>,
        request_id: &str,
    ) -> Result<ConfirmedThresholdChange<Option<u32>>, SaError> {
        let budget = self.lock_budget();
        let guards = self
            .acquire_rule_locks(
                smart_account_strkey,
                holder_lock_set(rule_id, auth_rule_ids),
                budget,
            )
            .await?;

        let compared = [self
            .verify_signer_set_locked(
                held_guard(&guards, smart_account_strkey, rule_id)?,
                V1Handling::RefuseLegacy,
                source_account_strkey,
                request_id,
            )
            .await?];

        let observation = self
            .observe_policy_path(policy, rule_id, smart_account_redacted, request_id, budget)
            .await?;
        let expected_threshold = if observation.allowlisted {
            let threshold = parse_simple_threshold_install_param(&install_param)?;
            if compared[0].snapshot().threshold.is_some() {
                return Err(SaError::ThresholdPolicyIdentificationFailed {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    observed_wasm_hashes_summary: compared[0].policy_hashes().clone(),
                    request_id: request_id.to_owned(),
                });
            }
            Some(threshold)
        } else {
            None
        };

        let pin_update = bound_pre_submit_stage(
            budget,
            "pin_plan",
            "auth_payload",
            self.plan_policy_add_pin_update(
                rule_id,
                smart_account_redacted,
                compared[0].policies(),
                policy,
                overrides,
                request_id,
            ),
        )
        .await??;

        let invoke_args = vec![
            ScVal::U32(rule_id),
            ScVal::Address(policy.clone()),
            install_param,
        ];
        let rule_locks = borrowed(&guards, &compared);
        let submitted = submit(LockedSubmission::new(&rule_locks), invoke_args).await?;
        let (parsed, recorded) = match extract_u32_return(&submitted.return_val, "add_policy") {
            Err(cause) => (
                None,
                Err(observe_failed_after(
                    rule_id,
                    smart_account_redacted,
                    &submitted.tx_hash,
                    &cause,
                    request_id,
                )),
            ),
            Ok(policy_id) => {
                let recorded = match expected_threshold {
                    Some(threshold) => {
                        let intended = SignerSetSnapshotV2 {
                            signers: compared[0].snapshot().signers.clone(),
                            threshold: Some(ThresholdObservation {
                                policy: contract_address_bytes(policy),
                                threshold,
                            }),
                        };
                        self.record_threshold_change(
                            smart_account,
                            smart_account_strkey,
                            smart_account_redacted,
                            rule_id,
                            source_account_strkey,
                            &submitted,
                            intended,
                            None,
                            request_id,
                        )
                        .await
                    }
                    None => Ok(()),
                };
                (Some(policy_id), recorded)
            }
        };
        self.write_pin_rows(
            rule_id,
            smart_account_redacted,
            pin_update,
            PinsUpdateReason::PolicyAdded,
            request_id,
        );
        Ok(ConfirmedThresholdChange {
            submitted,
            parsed,
            recorded,
        })
    }

    /// Removes the policy with on-chain id `policy_id` from rule `rule_id`
    /// through `submit`, and writes the rows the confirmed removal records
    /// under the locks.
    ///
    /// Acquires the locks of the rule and of the distinct non-zero rules in
    /// `auth_rule_ids`, as [`Self::attach_policy`] does, then, every step
    /// under the locks:
    ///
    /// 1. Compares the chain with the rule's version-2 state row. A rule with
    ///    no state row refuses with [`SaError::SignerSetMissingBaseline`]
    ///    before any RPC; a rule with a state row that is not on chain
    ///    refuses from the comparison's rule read.
    /// 2. Resolves `policy_id` to its address from the comparison's rule
    ///    value; an id the rule does not hold refuses with
    ///    [`SaError::DeploymentFailed`] (phase `simulate`).
    /// 3. Observes the policy's executable through both endpoints. When it
    ///    is the simple-threshold policy, it must be the rule's observed
    ///    threshold policy, else the call refuses with
    ///    [`SaError::ThresholdPolicyIdentificationFailed`].
    /// 4. Plans the pin record the removal writes when the rule has one: the
    ///    first policy pin equal to the observed hash is dropped. The single
    ///    pin of the rule's only policy is dropped whatever the hash, since it
    ///    can only be that policy's.
    /// 5. Runs `submit` with the held locks, the comparison and the
    ///    invocation arguments built here.
    /// 6. For the simple-threshold policy, observes the rule after
    ///    confirmation, requires the signers unchanged and the threshold
    ///    gone, and writes the `SaThresholdChangedV2` row with the observed
    ///    threshold as the previous one.
    /// 7. Writes the `SaContextRulePinsUpdated` row of the plan, whatever
    ///    step 6 returned.
    ///
    /// A rule with two simple-threshold policies cannot be observed, so the
    /// comparison of step 1 refuses it with
    /// [`SaError::ThresholdPolicyIdentificationFailed`]. The removal of one
    /// of the two is then accepted, under the same locks, when the rule has
    /// a version-2 state row. The rule is read through both endpoints, and
    /// its signers must equal the state row's before submission. A changed
    /// set writes the `SaSignerSetDiverged` row and refuses with
    /// [`SaError::SignerSetDiverged`] without a transaction hash. The
    /// removed policy's hash comes from that read's identification of the
    /// two policies. After confirmation the signers must equal the state
    /// row's and the threshold must be the other policy's. The row records
    /// no previous threshold, since none was observable, and the other
    /// policy's threshold as the resulting one. The pin rows follow as in
    /// step 7. The held-lock context of this case carries no comparison. The
    /// submit path therefore compares the rule again when it is among
    /// `auth_rule_ids`, and that comparison refuses the two-policy rule: the
    /// repair is authorized through another rule, such as rule 0. Any other
    /// identification failure, a third matching policy or the removal of a
    /// policy other than the two included, refuses unchanged.
    ///
    /// The rows written here precede the policy and raw invocation rows the
    /// caller writes after this entry returns, and a concurrent verb on the
    /// rule is serialized before or after the whole removal. The held-lock
    /// context and `budget` are as on [`Self::attach_policy`]; the plan's
    /// only read is the synchronous pin-record scan.
    ///
    /// # Returns
    ///
    /// `Err` when the entry returned before a confirmation; nothing was
    /// recorded. `Ok` once the transaction confirmed, with `recorded` the
    /// outcome of the threshold recording, `Ok(())` for any other policy.
    ///
    /// # Errors
    ///
    /// - The comparison errors of [`Self::add_signer`].
    /// - [`SaError::DeploymentFailed`] for a policy id the rule does not
    ///   hold, and the observation errors of the policy.
    /// - [`SaError::ThresholdPolicyIdentificationFailed`], and
    ///   [`SaError::SignerSetDiverged`] without a transaction hash.
    /// - [`SaError::AuditLog`] when the pin record cannot be read, and
    ///   [`SaError::AuthEntryConstructionFailed`] when the budget elapses.
    /// - The rule read errors and the errors of `submit`.
    /// - After confirmation, `recorded` carries
    ///   [`SaError::BaselineWriteFailed`] (stage `observe` or `write`) or
    ///   [`SaError::SignerSetDiverged`] with the transaction hash.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the rule and its auth rules, the policy id, the source \
                  account, the submission and the correlation id"
    )]
    pub(crate) async fn detach_policy<'env>(
        &self,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        auth_rule_ids: &[ContextRuleId],
        policy_id: u32,
        source_account_strkey: Option<&str>,
        submit: impl for<'l> FnOnce(LockedSubmission<'l, 'env>, Vec<ScVal>) -> LockedSubmitFuture<'l>,
        request_id: &str,
    ) -> Result<ConfirmedThresholdChange<()>, SaError> {
        let budget = self.lock_budget();
        let guards = self
            .acquire_rule_locks(
                smart_account_strkey,
                holder_lock_set(rule_id, auth_rule_ids),
                budget,
            )
            .await?;

        let compared = match self
            .verify_signer_set_locked(
                held_guard(&guards, smart_account_strkey, rule_id)?,
                V1Handling::RefuseLegacy,
                source_account_strkey,
                request_id,
            )
            .await
        {
            Ok(compared) => [compared],
            Err(identification @ SaError::ThresholdPolicyIdentificationFailed { .. }) => {
                return self
                    .detach_one_of_two_threshold_policies(
                        smart_account,
                        smart_account_strkey,
                        smart_account_redacted,
                        rule_id,
                        &guards,
                        policy_id,
                        source_account_strkey,
                        submit,
                        identification,
                        budget,
                        request_id,
                    )
                    .await;
            }
            Err(other) => return Err(other),
        };

        let RulePolicy {
            address: policy,
            rule_policy_count,
        } = rule_policy_for_id(compared[0].primary_rule(), policy_id)
            .ok_or_else(|| policy_not_attached(rule_id, policy_id))?;
        let observation = self
            .observe_policy_path(&policy, rule_id, smart_account_redacted, request_id, budget)
            .await?;
        let before = compared[0].snapshot();
        if observation.allowlisted
            && !before
                .threshold
                .as_ref()
                .is_some_and(|threshold| threshold.policy == contract_address_bytes(&policy))
        {
            return Err(SaError::ThresholdPolicyIdentificationFailed {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                observed_wasm_hashes_summary: compared[0].policy_hashes().clone(),
                request_id: request_id.to_owned(),
            });
        }

        // The plan's only read is a synchronous scan: the wrapper records the
        // `pin_plan` stage's timing, and the plan checks the budget itself.
        let pin_record = bound_pre_submit_stage(budget, "pin_plan", "auth_payload", async {
            self.plan_policy_remove_pin_update(
                rule_id,
                smart_account_redacted,
                policy_id,
                &observation.effective_hash,
                rule_policy_count,
                budget,
            )
        })
        .await??;

        let invoke_args = vec![ScVal::U32(rule_id), ScVal::U32(policy_id)];
        let rule_locks = borrowed(&guards, &compared);
        let submitted = submit(LockedSubmission::new(&rule_locks), invoke_args).await?;
        let recorded = if observation.allowlisted {
            let intended = SignerSetSnapshotV2 {
                signers: before.signers.clone(),
                threshold: None,
            };
            self.record_threshold_change(
                smart_account,
                smart_account_strkey,
                smart_account_redacted,
                rule_id,
                source_account_strkey,
                &submitted,
                intended,
                before.threshold.clone(),
                request_id,
            )
            .await
        } else {
            Ok(())
        };
        self.write_pin_rows(
            rule_id,
            smart_account_redacted,
            pin_record.map(PlannedPinUpdate::unchanged),
            PinsUpdateReason::PolicyRemoved,
            request_id,
        );
        Ok(ConfirmedThresholdChange {
            submitted,
            parsed: (),
            recorded,
        })
    }

    /// The removal of one of two simple-threshold policies of
    /// [`Self::detach_policy`]. The caller holds `guards`, the locks of the
    /// rule and its auth rules, and nothing here acquires a lock. The
    /// caller's comparison refused with `identification`, which is returned
    /// unchanged unless exactly two attached policies match and one of them
    /// is the policy with id `policy_id`.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the rule and its held locks, the policy id, the source \
                  account, the submission, the comparison's refusal, the budget and the \
                  correlation id"
    )]
    async fn detach_one_of_two_threshold_policies<'env>(
        &self,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        guards: &[RuleLockGuard],
        policy_id: u32,
        source_account_strkey: Option<&str>,
        submit: impl for<'l> FnOnce(LockedSubmission<'l, 'env>, Vec<ScVal>) -> LockedSubmitFuture<'l>,
        identification: SaError,
        budget: PreSubmitBudget,
        request_id: &str,
    ) -> Result<ConfirmedThresholdChange<()>, SaError> {
        // The comparison read the state row before any RPC and refused a
        // missing or version-1 row, so the row is version 2.
        let baseline = match self
            .read_signer_set_view(rule_id, smart_account_strkey, smart_account_redacted)?
            .map(|payload| payload.view().clone())
        {
            Some(SignerSetView::V2(snapshot)) => snapshot,
            _ => {
                return Err(SaError::DeploymentFailed {
                    phase: "simulate",
                    redacted_reason: format!(
                        "remove_policy: rule {rule_id} has no version-2 state row"
                    ),
                });
            }
        };

        let (primary, secondary) = tokio::join!(
            self.read_rule(
                &self.primary_rpc_client,
                smart_account,
                rule_id,
                source_account_strkey,
                None,
            ),
            self.read_rule(
                &self.secondary_rpc_client,
                smart_account,
                rule_id,
                source_account_strkey,
                None,
            ),
        );
        let (primary, secondary) = (primary?, secondary?);
        Self::require_same_rule(
            &primary.rule,
            &secondary.rule,
            rule_id,
            smart_account_redacted,
            request_id,
        )?;
        let RulePolicy {
            address: policy,
            rule_policy_count,
        } = rule_policy_for_id(&primary.rule.raw_scval, policy_id)
            .ok_or_else(|| policy_not_attached(rule_id, policy_id))?;
        let (matches, _summary) = self
            .allowlisted_threshold_policies(
                &primary.rule.policies,
                rule_id,
                smart_account_redacted,
                request_id,
            )
            .await?;
        let (removed_hash, remaining) = match matches.as_slice() {
            [first, second] if first.address == policy => {
                (first.executable_hash, second.contract_id)
            }
            [first, second] if second.address == policy => {
                (second.executable_hash, first.contract_id)
            }
            _ => return Err(identification),
        };

        let observed = snapshot_of_rule(&primary.rule, None)?;
        if observed.signers != baseline.signers {
            let expected = SignerSetView::V2(baseline);
            let observed = SignerSetView::V2(observed);
            self.emit_signer_set_diverged(
                rule_id,
                smart_account_redacted,
                &expected,
                &observed,
                request_id,
            );
            return Err(SaError::SignerSetDiverged {
                rule_id,
                expected,
                observed,
                tx_hash: None,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id: request_id.to_owned(),
            });
        }

        // The plan's only read is a synchronous scan: the wrapper records the
        // `pin_plan` stage's timing, and the plan checks the budget itself.
        let pin_record = bound_pre_submit_stage(budget, "pin_plan", "auth_payload", async {
            self.plan_policy_remove_pin_update(
                rule_id,
                smart_account_redacted,
                policy_id,
                &removed_hash,
                rule_policy_count,
                budget,
            )
        })
        .await??;

        let invoke_args = vec![ScVal::U32(rule_id), ScVal::U32(policy_id)];
        let rule_locks = borrowed(guards, &[]);
        let submitted = submit(LockedSubmission::new(&rule_locks), invoke_args).await?;
        let recorded = self
            .record_one_of_two_detached(
                smart_account,
                smart_account_strkey,
                smart_account_redacted,
                rule_id,
                source_account_strkey,
                &submitted,
                baseline,
                remaining,
                request_id,
            )
            .await;
        self.write_pin_rows(
            rule_id,
            smart_account_redacted,
            pin_record.map(PlannedPinUpdate::unchanged),
            PinsUpdateReason::PolicyRemoved,
            request_id,
        );
        Ok(ConfirmedThresholdChange {
            submitted,
            parsed: (),
            recorded,
        })
    }

    /// Observes the executable of `policy`, a policy of rule `rule_id`,
    /// through both endpoints under `budget`, to tell whether it is the
    /// simple-threshold policy.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::observe_contract`], and
    /// [`SaError::AuthEntryConstructionFailed`] (stage `auth_payload`) when
    /// `budget` elapses.
    async fn observe_policy_path(
        &self,
        policy: &ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        request_id: &str,
        budget: PreSubmitBudget,
    ) -> Result<ContractObservation, SaError> {
        bound_pre_submit_stage(
            budget,
            "policy_path",
            "auth_payload",
            self.observe_contract(
                policy,
                ContractKind::Policy,
                |hash| THRESHOLD_POLICY_WASM_HASHES.contains(hash),
                Some(rule_id),
                smart_account_redacted,
                request_id,
            ),
        )
        .await?
    }

    /// Computes the pin record a policy add writes for rule `rule_id` once
    /// the add confirms.
    ///
    /// `live_policies` are the rule's policies as the comparison under the
    /// rule's lock observed them. Returns `None` without a pin record.
    /// Otherwise the returned record is the current one, with a pin appended
    /// for `policy` when the policy is not already live on the rule, probed
    /// here, before submission, with the overrides applied to it pending.
    /// When the rule has no live policy, the record's policy pins are
    /// replaced by that pin, so the record pins exactly the policy set the
    /// add produces.
    ///
    /// # Errors
    ///
    /// - [`SaError::AuditLog`]: the pin record could not be read.
    /// - The refusals of `pin_added_contract` for the policy.
    async fn plan_policy_add_pin_update(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        live_policies: &[ScAddress],
        policy: &ScAddress,
        overrides: PinOverrides,
        request_id: &str,
    ) -> Result<Option<PlannedPinUpdate>, SaError> {
        let Some(record) = crate::managers::verifiers::read_pinned_hashes_for_rule(
            self,
            rule_id,
            smart_account_redacted,
        )?
        else {
            debug!(
                rule_id,
                "add_policy: the rule has no pin record; no pin update is written"
            );
            return Ok(None);
        };
        let mut update = PlannedPinUpdate::unchanged(record);
        if live_policies.contains(policy) {
            return Ok(Some(update));
        }
        let pin = crate::managers::verifiers::pin_added_contract(
            self,
            policy,
            PinnedKind::Policy,
            rule_id,
            smart_account_redacted,
            overrides.accept_mutable_verifier,
            overrides.accept_unknown_verifier,
            request_id,
        )
        .await?;
        if live_policies.is_empty() {
            // With no live policy, the record's policy pins describe no
            // policy of the rule; the row pins exactly the policy set the
            // add produces. The override flags stay, since they record
            // overrides applied to the rule's contracts.
            update.record.pinned_policy_first8.clear();
            update.record.pinned_policy_executable_refs.clear();
        }
        update.append_pin(PinnedKind::Policy, pin);
        Ok(Some(update))
    }

    /// Computes the pin record a policy removal writes for rule `rule_id`
    /// once the removal confirms.
    ///
    /// `removed_hash` is the removed policy's effective hash as observed
    /// under the rule's lock, and `rule_policy_count` the number of policies
    /// the rule held there. Returns `None` without a pin record, or when no
    /// policy pin is the removed policy's. A pin is the removed policy's when
    /// it equals `removed_hash`. When the policy is the rule's only policy
    /// and the record holds one policy pin, that pin is the removed policy's
    /// whatever the hash: it can only be that policy's. The rule then ends
    /// with no policy and no policy pin, the state of a rule installed
    /// without a policy.
    ///
    /// The record is read by a synchronous audit-log scan, which no timeout
    /// can stop, so `budget` is checked once the scan returns.
    ///
    /// # Errors
    ///
    /// - [`SaError::AuditLog`] when the pin record cannot be read.
    /// - [`SaError::AuthEntryConstructionFailed`] (stage `auth_payload`, the
    ///   reason naming `pin_plan`) when `budget` elapsed during the scan.
    fn plan_policy_remove_pin_update(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        policy_id: u32,
        removed_hash: &[u8; 32],
        rule_policy_count: usize,
        budget: PreSubmitBudget,
    ) -> Result<Option<PinnedHashesRecord>, SaError> {
        let record = crate::managers::verifiers::read_pinned_hashes_for_rule(
            self,
            rule_id,
            smart_account_redacted,
        )?;
        budget.check_at("pin_plan", "auth_payload")?;
        let Some(mut record) = record else {
            debug!(
                rule_id,
                "remove_policy: the rule has no pin record; no pin update is written"
            );
            return Ok(None);
        };
        let removed_first8 = hash_first8_hex(removed_hash);
        let position = match record
            .pinned_policy_first8
            .iter()
            .position(|pinned| *pinned == removed_first8)
        {
            Some(position) => position,
            None if rule_policy_count == 1 && record.pinned_policy_first8.len() == 1 => 0,
            None => {
                debug!(
                    rule_id,
                    policy_id,
                    removed_first8 = %removed_first8,
                    "remove_policy: no policy pin is the removed policy's; no pin update is written"
                );
                return Ok(None);
            }
        };
        record.pinned_policy_first8.remove(position);
        if position < record.pinned_policy_executable_refs.len() {
            record.pinned_policy_executable_refs.remove(position);
        }
        Ok(Some(record))
    }

    /// Observes the rule after a confirmed attach or detach of the
    /// simple-threshold policy, requires `intended`, and writes the
    /// `SaThresholdChangedV2` row with `previous` as the threshold before the
    /// change.
    ///
    /// # Errors
    ///
    /// [`SaError::BaselineWriteFailed`] with the transaction hash at stage
    /// `observe` or `write`, and [`SaError::SignerSetDiverged`] with it when
    /// the confirmed state is not `intended`.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the rule, the source account, the confirmed \
                  transaction, the intended state, the previous threshold and the correlation id"
    )]
    async fn record_threshold_change(
        &self,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        submitted: &crate::submit::SubmitInvokeResult,
        intended: SignerSetSnapshotV2,
        previous: Option<ThresholdObservation>,
        request_id: &str,
    ) -> Result<(), SaError> {
        let observation = self
            .observe_confirmed(
                smart_account,
                rule_id,
                source_account_strkey,
                submitted,
                smart_account_redacted,
                request_id,
            )
            .await?;
        let resulting = self.require_intended_state(
            rule_id,
            smart_account_redacted,
            intended,
            observation,
            &submitted.tx_hash,
            request_id,
        )?;
        self.write_threshold_changed(
            smart_account_strkey,
            smart_account_redacted,
            rule_id,
            previous,
            &resulting,
            &submitted.tx_hash,
            request_id,
        )
    }

    /// Observes the rule after a confirmed detach of one of two
    /// simple-threshold policies and requires the signers of `baseline` and
    /// the threshold of the `remaining` policy. It then writes the
    /// `SaThresholdChangedV2` row with no previous threshold.
    ///
    /// # Errors
    ///
    /// [`SaError::BaselineWriteFailed`] with the transaction hash at stage
    /// `observe` or `write`, and [`SaError::SignerSetDiverged`] with it,
    /// comparing `baseline` with the observation, when the confirmed state is
    /// not that.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the rule, the source account, the confirmed \
                  transaction, the state row, the remaining policy and the correlation id"
    )]
    async fn record_one_of_two_detached(
        &self,
        smart_account: &ScAddress,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        submitted: &crate::submit::SubmitInvokeResult,
        baseline: SignerSetSnapshotV2,
        remaining: [u8; 32],
        request_id: &str,
    ) -> Result<(), SaError> {
        let observation = self
            .observe_confirmed(
                smart_account,
                rule_id,
                source_account_strkey,
                submitted,
                smart_account_redacted,
                request_id,
            )
            .await?;
        let remains = observation
            .snapshot
            .threshold
            .as_ref()
            .is_some_and(|threshold| threshold.policy == remaining);
        if observation.snapshot.signers != baseline.signers || !remains {
            return Err(self.unintended_state(
                rule_id,
                smart_account_redacted,
                baseline,
                observation.snapshot,
                &submitted.tx_hash,
                request_id,
            ));
        }
        self.write_threshold_changed(
            smart_account_strkey,
            smart_account_redacted,
            rule_id,
            None,
            &observation.snapshot,
            &submitted.tx_hash,
            request_id,
        )
    }

    /// Writes the `SaThresholdChangedV2` row of a confirmed attach or detach
    /// of the simple-threshold policy.
    ///
    /// # Errors
    ///
    /// [`SaError::BaselineWriteFailed`] at stage `write` with the transaction
    /// hash when the row is not written.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account identity, the rule, both threshold sides, the confirmed \
                  transaction and the correlation id"
    )]
    fn write_threshold_changed(
        &self,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        rule_id: u32,
        previous: Option<ThresholdObservation>,
        resulting: &SignerSetSnapshotV2,
        tx_hash: &str,
        request_id: &str,
    ) -> Result<(), SaError> {
        let account = account_digest(&self.network_passphrase, smart_account_strkey);
        self.write_confirmed_state_row(rule_id, smart_account_redacted, tx_hash, request_id, |_| {
            AuditEntry::new_sa_threshold_changed_v2(
                rule_id,
                previous,
                resulting,
                account,
                RedactedStrkey::from_already_redacted(smart_account_redacted),
                self.chain_id.as_str(),
                request_id,
            )
        })
    }

    // ── set_spending_limit ─────────────────────────────────────────────────────

    /// Retunes the spending limit of an installed spending-limit policy
    /// (without resetting rolling spend history).
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Refuses `new_limit <= 0` client-side (OZ `set_spending_limit` panics
    ///    `InvalidLimitOrPeriod`, code 3222, for a non-positive value).
    /// 2. Identifies the spending-limit-policy address via wasm-hash lookup.
    /// 3. Reads the current on-chain data (`old_limit` for the audit row;
    ///    this also fails closed early with
    ///    [`SaError::SpendingLimitNotInstalled`] if the policy's storage was
    ///    never initialised, before any submission).
    /// 4. Constructs and submits a single `InvokeHostFunctionOp` routed
    ///    through the smart account's `execute()` entrypoint (avoids Soroban
    ///    re-entry — see the inline rationale in
    ///    `set_threshold_locked_inner`).
    /// 5. Emits `SaSpendingLimitRetuned` audit row.
    ///
    /// `period_ledgers` is immutable post-install: OZ `set_spending_limit`
    /// mutates only the limit (`spending_limit.rs:314-339`, SHA `a9c4216`).
    /// Retuning the period requires remove-policy + add-policy, which resets
    /// rolling spend history (`install` initialises an empty history,
    /// `spending_limit.rs:367-425`). This method does not attempt to change
    /// the period.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule whose spending-limit policy is retuned
    ///   (the ARGUMENT rule: it keys the policy's storage mutation, but does
    ///   NOT authorize the call).
    /// - `auth_rule_ids` — the rule(s) AUTHORIZING the retune. Must be
    ///   admin-capable (typically the genesis Default rule): the auth context
    ///   is `execute` on the smart account, which a CallContract-scoped rule
    ///   refuses with `UnvalidatedContext` (3002) — so the target rule can
    ///   never authorize its own retune. The client-side expiry pre-flight
    ///   covers only the FIRST entry; expiry of any additional auth rule is
    ///   still enforced on-chain, just without the early local refusal.
    /// - `new_limit` — the desired new spending limit, in stroops.
    /// - `signer` — the ed25519 signer (must satisfy the auth rule).
    /// - `request_id` — caller-supplied UUID.
    ///
    /// # Errors
    ///
    /// - [`SaError::SpendingLimitInstallRefused`] — `new_limit <= 0`, or
    ///   `auth_rule_ids` empty.
    /// - [`SaError::SpendingLimitNotInstalled`] — no accessible spending-limit
    ///   policy for this rule (client-side identification, or on-chain 3220).
    /// - [`SaError::SpendingLimitPolicyIdentificationFailed`] — ambiguous
    ///   multi-match.
    /// - [`SaError::NetworkRpcDivergence`] — two-RPC disagreement on policy
    ///   hash.
    /// - [`SaError::DeploymentFailed`] — submission or on-chain rejection.
    ///
    /// # Implements
    ///
    /// Policy observability: the write side of the spending-limit budget
    /// surface — retuning the limit without tearing down rolling spend
    /// history (GH issue #7).
    pub async fn set_spending_limit(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        auth_rule_ids: &[ContextRuleId],
        new_limit: i128,
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
    ) -> Result<(), SaError> {
        // The AUTHORIZING rule must be admin-capable (typically the genesis
        // Default rule): the retune's auth context is `execute` on the smart
        // account itself, and the CallContract-scoped rule being retuned can
        // never validate that context — on-chain `get_validated_context_by_id`
        // refuses it with `UnvalidatedContext` (3002, OZ storage.rs:272-324,
        // SHA `a9c4216`). This is why `auth_rule_ids` is caller-supplied
        // rather than derived from `rule_id` (the `set_threshold` convention
        // of auth == target only works because threshold policies sit on
        // Default-scoped rules).
        if auth_rule_ids.is_empty() {
            return Err(SaError::SpendingLimitInstallRefused {
                reason: "set-spending-limit refused: auth_rule_ids must not be empty; supply \
                         an admin-capable rule (the CallContract rule being retuned cannot \
                         authorize a smart-account admin call)"
                    .to_owned(),
            });
        }
        if new_limit <= 0 {
            return Err(SaError::SpendingLimitInstallRefused {
                reason: format!(
                    "set-spending-limit refused: --limit must be positive; got {new_limit} \
                     (OZ set_spending_limit rejects non-positive values with \
                     InvalidLimitOrPeriod)"
                ),
            });
        }

        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // The target and the admin rules the call signs under; the submit
        // path compares the admin rules under these locks.
        let guards = self
            .acquire_rule_locks(
                &smart_account_strkey,
                holder_lock_set(rule_id, auth_rule_ids),
                self.lock_budget(),
            )
            .await?;

        let outcome = self
            .set_spending_limit_locked_inner(
                smart_account.clone(),
                rule_id,
                auth_rule_ids,
                &guards,
                new_limit,
                signer,
                &request_id,
            )
            .await;

        match &outcome {
            Ok((old_limit, period_ledgers, policy_addr, tx_hash)) => {
                let policy_addr_redacted = scaddress_to_strkey(policy_addr)
                    .map(|s| redact_strkey_first5_last5(&s))
                    .unwrap_or_else(|_| "unknown".to_owned());
                let tx_hash_redacted = stellar_agent_network::redact_tx_hash(tx_hash);
                match self.audit_writer.lock() {
                    Ok(mut writer) => {
                        let entry = AuditEntry::new_sa_spending_limit_retuned(
                            rule_id,
                            *old_limit,
                            new_limit,
                            *period_ledgers,
                            RedactedStrkey::from_already_redacted(policy_addr_redacted.clone()),
                            tx_hash_redacted.clone(),
                            RedactedStrkey::from_already_redacted(smart_account_redacted.clone()),
                            self.chain_id.as_str(),
                            request_id.clone(),
                        );
                        if let Err(e) = writer.write_entry(entry) {
                            warn!(
                                error = %e,
                                "set_spending_limit: SaSpendingLimitRetuned audit write failed"
                            );
                        }
                    }
                    Err(_poison) => {
                        self.mark_audit_writer_degraded();
                        warn!(
                            target: "stellar_agent::audit",
                            rule_id,
                            old_limit = *old_limit,
                            new_limit,
                            period_ledgers = *period_ledgers,
                            policy_address_redacted = %policy_addr_redacted,
                            transaction_hash_redacted = %tx_hash_redacted,
                            smart_account_redacted = %smart_account_redacted,
                            chain_id = %self.chain_id,
                            request_id = %request_id,
                            "audit-writer mutex poisoned; SaSpendingLimitRetuned row dropped"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    rule_id,
                    smart_account = %smart_account_redacted,
                    "set_spending_limit: operation failed"
                );
            }
        }

        outcome.map(|_| ())
    }

    /// Core logic for `set_spending_limit` (called inside the per-rule mutex).
    ///
    /// Returns `(old_limit, period_ledgers, policy_addr, tx_hash)` on success.
    #[allow(
        clippy::too_many_arguments,
        reason = "the account, the target rule, its auth rules and their held locks, the new \
                  value, the signer and the correlation id"
    )]
    async fn set_spending_limit_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        auth_rule_ids: &[ContextRuleId],
        guards: &[RuleLockGuard],
        new_limit: i128,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(i128, u32, ScAddress, String), SaError> {
        let source_pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!("signer public_key fetch failed: {e}"),
                })?;
        let source_pubkey_strkey = stellar_strkey::ed25519::PublicKey(source_pubkey.0).to_string();

        // Identify the spending-limit policy (fail-closed).
        let policy_addr = self
            .identify_spending_limit_policy(
                smart_account.clone(),
                rule_id,
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;

        // Pre-read the current data: `old_limit` for the audit row, and an
        // early fail-closed check on the on-chain 3220 case before any
        // submission is attempted.
        let (current_data, _as_of_ledger) = self
            .get_spending_limit_data(
                policy_addr.clone(),
                rule_id,
                smart_account.clone(),
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;
        let old_limit = current_data.spending_limit;
        let period_ledgers = current_data.period_ledgers;

        // Fetch context rule for the set_spending_limit args.
        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, Some(&source_pubkey_strkey))
            .await?;

        // Route `set_spending_limit` through the smart account's `execute()`
        // entrypoint to avoid Soroban re-entry — the same rationale as
        // `set_threshold_locked_inner`: a direct call would re-enter
        // `smart_account.require_auth()` via the policy's own
        // `require_auth` call.
        let set_spending_limit_sym = ScSymbol::try_from("set_spending_limit").map_err(|e| {
            SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("encode set_spending_limit symbol: {e:?}"),
            }
        })?;
        let context_rule_scval = context_rule.as_scval()?;
        #[allow(
            clippy::cast_possible_truncation,
            reason = "canonical i128 -> Int128Parts split: hi = high 64 bits, lo = low 64 bits"
        )]
        let new_limit_parts = Int128Parts {
            hi: (new_limit >> 64) as i64,
            lo: new_limit as u64,
        };
        // `target_args` = [spending_limit: i128, context_rule: ContextRule,
        // smart_account: Address], per the example contract signature
        // `set_spending_limit(e, spending_limit, context_rule, smart_account)`
        // (examples/multisig-smart-account/spending-limit-policy/src/contract.rs:79-86,
        // SHA `a9c4216`).
        let target_args_vec: VecM<ScVal> = vec![
            ScVal::I128(new_limit_parts),
            context_rule_scval,
            ScVal::Address(smart_account.clone()),
        ]
        .try_into()
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_contexts_args",
            redacted_reason: format!("encode set_spending_limit target_args VecM: {e:?}"),
        })?;
        let execute_args = vec![
            ScVal::Address(policy_addr.clone()),
            ScVal::Symbol(set_spending_limit_sym),
            ScVal::Vec(Some(ScVec(target_args_vec))),
        ];

        // Both contract and auth_address are the smart account; `execute()`
        // calls `e.current_contract_address().require_auth()`. That auth
        // context (`execute` on the smart account) is validated against
        // `auth_rule_ids` — the caller-supplied ADMIN rule — never against
        // `rule_id`: the CallContract-scoped rule being retuned refuses this
        // context with `UnvalidatedContext` (3002). The target rule enters
        // the call only through the `context_rule` ARGUMENT, which is what
        // keys the policy's storage mutation
        // (`AccountContext(smart_account, context_rule.id)`,
        // spending_limit.rs:328, SHA `a9c4216`).
        let expiry_rule_id = auth_rule_ids
            .first()
            .map(ContextRuleId::as_u32)
            .unwrap_or(rule_id);
        let submit_result = self
            .submit_signed_invoke(
                smart_account.clone(),
                &smart_account,
                "execute",
                execute_args,
                auth_rule_ids,
                signer,
                &source_pubkey_strkey,
                "execute",
                // Expiry check on the AUTHORIZING rule at signing-path entry
                // (the on-chain expiry refusal applies to the auth rule).
                Some(ExpiryCheck {
                    rule_id: expiry_rule_id,
                }),
                request_id,
                None,
                Some(&borrowed(guards, &[])),
                None,
            )
            .await?;

        Ok((
            old_limit,
            period_ledgers,
            policy_addr,
            submit_result.tx_hash,
        ))
    }

    // ── identify_spending_limit_policy ────────────────────────────────────────

    /// Identifies the spending-limit-policy contract for a context rule.
    ///
    /// Fetches the wasm-hash of each `Address` in the rule's `policies` list
    /// via batched `getLedgerEntries` on BOTH RPCs in parallel (two-RPC
    /// consultation), then matches against the spending-limit-policy
    /// wasm-hash allowlist. Exactly one match is required (fail closed).
    ///
    /// Unlike the two-entry simple-threshold allowlist (current deploy hash
    /// plus one grandfathered legacy version), the spending-limit
    /// allowlist has exactly one entry — decoded at call time from
    /// [`crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256`],
    /// the same hex string the deploy-time
    /// `deployment::deploy::verify_post_deploy_wasm_hash` check
    /// already verifies equals `SHA256(SPENDING_LIMIT_POLICY_WASM)` and
    /// byte-matches the on-chain `ContractExecutable::Wasm(Hash)` value: both
    /// this allowlist and `THRESHOLD_POLICY_WASM_HASHES` compare against the
    /// identical on-chain domain (raw SHA-256 of the deployed WASM), so the
    /// constant is reusable here without re-deriving it.
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
    /// - [`SaError::SpendingLimitNotInstalled`] — the rule's `policies` list
    ///   is empty, or none of the attached policies' wasm-hash matches the
    ///   allowlist entry.
    /// - [`SaError::SpendingLimitPolicyIdentificationFailed`] — more than one
    ///   attached policy matches the allowlist entry (ambiguous).
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC
    ///   disagree on wasm-hash.
    /// - [`SaError::DeploymentFailed`] — RPC `getLedgerEntries` failure, or
    ///   the pinned `SPENDING_LIMIT_POLICY_WASM_SHA256` constant is not
    ///   valid 64-char hex (unreachable in practice; guarded by
    ///   `spending_limit_policy::tests::spending_limit_policy_wasm_sha256_matches_provenance`).
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the infallible `expect` on the
    /// `Option<ScAddress>` guarded by `match_count == 1` is provably safe.
    /// See inline comment.
    ///
    /// # Implements
    ///
    /// Spending-limit-policy identification: locates the single installed
    /// spending-limit policy by matching its wasm-hash against the allowlist,
    /// ensuring `get_spending_limit_data` / `set_spending_limit` target the
    /// correct contract.
    #[allow(
        clippy::expect_used,
        reason = "infallible: match_count == 1 guarantees Some"
    )]
    pub async fn identify_spending_limit_policy(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<ScAddress, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let allowed_hash = stellar_agent_core::hex::decode_hex32(
            crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256,
        )
        .map_err(|_| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: "SPENDING_LIMIT_POLICY_WASM_SHA256 const is not valid 64-char hex"
                .to_owned(),
        })?;

        // Fetch the on-chain context rule to get the policies list.
        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, source_account_strkey)
            .await?;

        // Empty policies list: nothing to check (fail-closed, same reported
        // outcome as a zero-match against a non-empty list).
        if context_rule.policies.is_empty() {
            return Err(SaError::SpendingLimitNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id,
            });
        }

        // Build LedgerKey::ContractData(ContractInstance) keys for each policy address.
        let policy_keys: Vec<LedgerKey> = context_rule
            .policies
            .iter()
            .map(contract_instance_key)
            .collect();

        if policy_keys.is_empty() {
            return Err(SaError::SpendingLimitNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id,
            });
        }

        // Two-RPC parallel wasm-hash fetch.
        let (primary_hashes_result, secondary_hashes_result) = tokio::join!(
            fetch_contract_wasm_hashes(&self.primary_rpc_client, &policy_keys),
            fetch_contract_wasm_hashes(&self.secondary_rpc_client, &policy_keys),
        );

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
                rule_id: Some(rule_id),
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                primary_view_digest_first8: primary_first8,
                secondary_view_digest_first8: secondary_first8,
                request_id,
            });
        }

        // Single-entry allowlist match: exactly-one-match required, fail-closed.
        let mut matched_policy_addr: Option<ScAddress> = None;
        let mut match_count = 0usize;
        let first_first8: Option<[u8; 8]> = primary_hashes
            .iter()
            .find_map(|opt_h| opt_h.as_ref())
            .map(|h| <[u8; 8]>::try_from(&h[..8]).expect("sha256 is 32 bytes"));

        for (opt_hash, policy_addr) in primary_hashes.iter().zip(context_rule.policies.iter()) {
            let Some(hash) = opt_hash else { continue };
            debug!(
                policy_wasm_hash_first8 = %hash_first8_hex(hash),
                "identify_spending_limit_policy: observed policy wasm hash"
            );
            if hash == &allowed_hash {
                match_count += 1;
                matched_policy_addr = Some(policy_addr.clone());
            }
        }

        match match_count {
            1 => Ok(matched_policy_addr.expect("match_count == 1 guarantees Some")),
            0 => Err(SaError::SpendingLimitNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id,
            }),
            _ => {
                let count = u32::try_from(primary_hashes.len()).unwrap_or(u32::MAX);
                Err(SaError::SpendingLimitPolicyIdentificationFailed {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    observed_wasm_hashes_summary: WasmHashSummary {
                        count,
                        first_first8,
                    },
                    request_id,
                })
            }
        }
    }

    // ── get_spending_limit_data ────────────────────────────────────────────────

    /// Reads the on-chain `SpendingLimitData` for `(rule_id, smart_account)`
    /// from the spending-limit-policy contract.
    ///
    /// `policy` MUST be the result of a prior
    /// [`SignersManager::identify_spending_limit_policy`] call — callers are
    /// responsible for identifying the policy first and passing the result
    /// here (fail-closed: no unvalidated address is read).
    ///
    /// Calls `get_spending_limit_data(context_rule_id: u32, smart_account:
    /// Address) -> SpendingLimitData` via the primary-RPC read-only simulate
    /// path (`simulate_read_only_with_ledger`), decodes the return value, and
    /// returns it alongside the ledger sequence the simulation observed
    /// (the "as of" ledger for [`crate::managers::spending_limit_data::compute_spending_window`]).
    ///
    /// # Errors
    ///
    /// - [`SaError::SpendingLimitNotInstalled`] — the on-chain call panics
    ///   `SpendingLimitError::SmartAccountNotInstalled` (code 3220,
    ///   `packages/accounts/src/policies/spending_limit.rs:124-127`, SHA
    ///   `a9c4216`), meaning `install` was never called for this
    ///   `(smart_account, rule_id)` pair on the policy contract. This is
    ///   defense in depth: `identify_spending_limit_policy` can succeed
    ///   against a raw-attached policy address whose storage was never
    ///   initialised.
    /// - [`SaError::DeploymentFailed`] — any other simulation failure, or a
    ///   malformed / unexpected-shape return value.
    /// - [`SaError::AuthEntryConstructionFailed`] — strkey or XDR
    ///   construction failure.
    ///
    /// # Implements
    ///
    /// Policy observability: the read side of the spending-limit budget
    /// surface (limit, period, spend history, remaining budget).
    pub async fn get_spending_limit_data(
        &self,
        policy: ScAddress,
        rule_id: u32,
        smart_account: ScAddress,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<(crate::managers::spending_limit_data::SpendingLimitData, u32), SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let invoke_args = vec![ScVal::U32(rule_id), ScVal::Address(smart_account)];

        let sim_result = simulate_read_only_with_ledger(
            self.primary_rpc_client.url(),
            policy,
            "get_spending_limit_data",
            invoke_args,
            source_account_strkey,
            &self.network_passphrase,
            self.timeout,
        )
        .await;

        // Mirrors the `ContextRuleNotFound` decode pattern
        // (`managers::rules::get_rule`) — the on-chain panic is surfaced as a
        // simulation `error` string containing `Error(Contract, #3220)`
        // (optionally augmented with the symbolic `[OZ:SmartAccountNotInstalled]`
        // name by `augment_with_oz_error_name`). Unlike `get_rule`, absence of
        // the policy here is an operator mistake, not a benign gap, so this
        // maps to a typed error rather than `Ok(None)`.
        let (scval, as_of_ledger) = match sim_result {
            Ok(v) => v,
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) if phase == "simulate"
                && (redacted_reason.contains("SmartAccountNotInstalled")
                    // Exact bracketed form only: a bare "#3220" substring
                    // would prefix-over-match hypothetical codes 3220x.
                    || redacted_reason.contains("Error(Contract, #3220)")) =>
            {
                return Err(SaError::SpendingLimitNotInstalled {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    request_id,
                });
            }
            Err(other) => return Err(other),
        };

        let data = crate::managers::spending_limit_data::decode_spending_limit_data(&scval)?;
        Ok((data, as_of_ledger))
    }

    // ── identify_weighted_threshold_policy ────────────────────────────────────

    /// Identifies the weighted-threshold-policy contract for a context rule.
    ///
    /// Mirrors [`SignersManager::identify_spending_limit_policy`]: fetches the
    /// wasm-hash of each `Address` in the rule's `policies` list via batched
    /// `getLedgerEntries` on BOTH RPCs in parallel (two-RPC consultation),
    /// then matches against [`WEIGHTED_THRESHOLD_POLICY_WASM_HASHES`] (a
    /// single-entry allowlist, separate from [`THRESHOLD_POLICY_WASM_HASHES`]
    /// — the two policy kinds cannot cross-identify). Exactly one match is
    /// required (fail-closed).
    ///
    /// # Errors
    ///
    /// - [`SaError::WeightedThresholdNotInstalled`] — the rule's `policies`
    ///   list is empty, or none of the attached policies' wasm-hash matches
    ///   the allowlist.
    /// - [`SaError::WeightedThresholdPolicyIdentificationFailed`] — more than
    ///   one attached policy matches the allowlist (ambiguous).
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC
    ///   disagree on wasm-hash.
    /// - [`SaError::DeploymentFailed`] — RPC `getLedgerEntries` failure.
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the infallible `expect` on a SHA-256
    /// slice and on the `Option<ScAddress>` guarded by `match_count == 1`
    /// are provably safe. See inline comments.
    #[allow(
        clippy::expect_used,
        reason = "infallible: match_count == 1 guarantees Some"
    )]
    pub async fn identify_weighted_threshold_policy(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<ScAddress, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, source_account_strkey)
            .await?;

        if context_rule.policies.is_empty() {
            return Err(SaError::WeightedThresholdNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id,
            });
        }

        let policy_keys: Vec<LedgerKey> = context_rule
            .policies
            .iter()
            .map(contract_instance_key)
            .collect();

        if policy_keys.is_empty() {
            return Err(SaError::WeightedThresholdNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id,
            });
        }

        let (primary_hashes_result, secondary_hashes_result) = tokio::join!(
            fetch_contract_wasm_hashes(&self.primary_rpc_client, &policy_keys),
            fetch_contract_wasm_hashes(&self.secondary_rpc_client, &policy_keys),
        );

        let primary_hashes = primary_hashes_result.map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("primary RPC policy wasm-hash fetch failed: {e}"),
        })?;
        let secondary_hashes = secondary_hashes_result.map_err(|e| SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("secondary RPC policy wasm-hash fetch failed: {e}"),
        })?;

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
                rule_id: Some(rule_id),
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                primary_view_digest_first8: primary_first8,
                secondary_view_digest_first8: secondary_first8,
                request_id,
            });
        }

        let mut matched_policy_addr: Option<ScAddress> = None;
        let mut match_count = 0usize;
        let first_first8: Option<[u8; 8]> = primary_hashes
            .iter()
            .find_map(|opt_h| opt_h.as_ref())
            .map(|h| <[u8; 8]>::try_from(&h[..8]).expect("sha256 is 32 bytes"));

        for (opt_hash, policy_addr) in primary_hashes.iter().zip(context_rule.policies.iter()) {
            let Some(hash) = opt_hash else { continue };
            debug!(
                policy_wasm_hash_first8 = %hash_first8_hex(hash),
                "identify_weighted_threshold_policy: observed policy wasm hash"
            );
            if WEIGHTED_THRESHOLD_POLICY_WASM_HASHES
                .iter()
                .any(|allowed| allowed == hash)
            {
                match_count += 1;
                matched_policy_addr = Some(policy_addr.clone());
            }
        }

        match match_count {
            1 => Ok(matched_policy_addr.expect("match_count == 1 guarantees Some")),
            0 => Err(SaError::WeightedThresholdNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id,
            }),
            _ => {
                let count = u32::try_from(primary_hashes.len()).unwrap_or(u32::MAX);
                Err(SaError::WeightedThresholdPolicyIdentificationFailed {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    observed_wasm_hashes_summary: WasmHashSummary {
                        count,
                        first_first8,
                    },
                    request_id,
                })
            }
        }
    }

    // ── get_weighted_threshold_data ────────────────────────────────────────────

    /// Reads the current on-chain `threshold` and `signer_weights` map for an
    /// installed weighted-threshold policy — the public read side of the
    /// weighted-threshold surface, mirroring [`Self::get_spending_limit_data`].
    ///
    /// `policy` MUST be the result of a prior
    /// [`SignersManager::identify_weighted_threshold_policy`] call — callers
    /// are responsible for identifying the policy first and passing the
    /// result here (fail-closed: no unvalidated address is read).
    ///
    /// Fetches the rule's [`crate::managers::rules::ContextRuleDefinition`]
    /// (`get_signer_weights` takes the full context-rule value, not just its
    /// ID — OZ `weighted_threshold.rs` exported view), then reads the
    /// on-chain `threshold` and `signer_weights` map.
    ///
    /// # Errors
    ///
    /// - [`SaError::WeightedThresholdNotInstalled`] — `install` was never
    ///   called for this `(smart_account, rule_id)` pair on the policy
    ///   contract.
    /// - [`SaError::DeploymentFailed`] — simulation or decode failure.
    ///
    /// # Implements
    ///
    /// Weighted-threshold policy observability: reading back the threshold
    /// and per-signer weight map a mutator (`set_weighted_threshold`,
    /// `set_signer_weight`) or the initial `install` produced.
    pub async fn get_weighted_threshold_data(
        &self,
        policy: ScAddress,
        rule_id: u32,
        smart_account: ScAddress,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<WeightedThresholdView, SaError> {
        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, source_account_strkey)
            .await?;
        let context_rule_scval = context_rule.as_scval()?;
        self.get_weighted_threshold_view(
            policy,
            rule_id,
            smart_account,
            context_rule_scval,
            source_account_strkey,
            request_id,
        )
        .await
    }

    // ── get_weighted_threshold_view ───────────────────────────────────────────

    /// Reads the current on-chain `threshold` and `signer_weights` map for an
    /// installed weighted-threshold policy.
    ///
    /// Calls the policy contract's exported `get_threshold(context_rule_id,
    /// smart_account)` and `get_signer_weights(context_rule, smart_account)`
    /// views (`examples/multisig-smart-account/weighted-threshold-policy/src/contract.rs:46,50`,
    /// SHA `a9c4216`). The signer-weights map is decoded generically as
    /// `(key ScVal, weight)` pairs — byte-equality against a target signer's
    /// canonical key (built via [`build_delegated_signer_scval`] /
    /// [`build_external_signer_scval`]), never a semantic `Signer` decode.
    ///
    /// Called both by [`Self::get_weighted_threshold_data`] (the public read
    /// path) and internally by the mutators' mandatory pre-flight read.
    ///
    /// # Errors
    ///
    /// - [`SaError::WeightedThresholdNotInstalled`] — the policy's
    ///   `get_threshold` view panics `WeightedThresholdError::SmartAccountNotInstalled`
    ///   (code 3210, `weighted_threshold.rs:180-196`, SHA `a9c4216`), meaning
    ///   `install` was never called for this `(smart_account, rule_id)` pair.
    /// - [`SaError::DeploymentFailed`] — simulation or decode failure.
    async fn get_weighted_threshold_view(
        &self,
        policy: ScAddress,
        rule_id: u32,
        smart_account: ScAddress,
        context_rule_scval: ScVal,
        source_account_strkey: Option<&str>,
        request_id: String,
    ) -> Result<WeightedThresholdView, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let threshold_args = vec![ScVal::U32(rule_id), ScVal::Address(smart_account.clone())];
        let threshold_sim = simulate_read_only_with_ledger(
            self.primary_rpc_client.url(),
            policy.clone(),
            "get_threshold",
            threshold_args,
            source_account_strkey,
            &self.network_passphrase,
            self.timeout,
        )
        .await;

        let (threshold_scval, _as_of_ledger) = match threshold_sim {
            Ok(v) => v,
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) if phase == "simulate"
                && (redacted_reason.contains("SmartAccountNotInstalled")
                    || redacted_reason.contains("Error(Contract, #3210)")) =>
            {
                return Err(SaError::WeightedThresholdNotInstalled {
                    rule_id,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    request_id,
                });
            }
            Err(other) => return Err(other),
        };

        let threshold = extract_u32_return(&threshold_scval, "get_threshold")?;

        let weights_args = vec![context_rule_scval, ScVal::Address(smart_account)];
        let (weights_scval, _as_of_ledger) = simulate_read_only_with_ledger(
            self.primary_rpc_client.url(),
            policy,
            "get_signer_weights",
            weights_args,
            source_account_strkey,
            &self.network_passphrase,
            self.timeout,
        )
        .await?;

        let signer_weights = match weights_scval {
            ScVal::Map(Some(ScMap(entries))) => {
                let mut out = Vec::with_capacity(entries.len());
                for entry in entries.iter() {
                    let weight = extract_u32_return(&entry.val, "get_signer_weights entry")?;
                    out.push((entry.key.clone(), weight));
                }
                out
            }
            other => {
                return Err(SaError::DeploymentFailed {
                    phase: "simulate",
                    redacted_reason: format!(
                        "get_signer_weights: expected ScVal::Map return, got {}",
                        scval_variant_name(&other)
                    ),
                });
            }
        };

        Ok(WeightedThresholdView {
            threshold,
            signer_weights,
        })
    }

    // ── set_weighted_threshold ─────────────────────────────────────────────────

    /// Changes the `threshold` of an installed weighted-threshold policy.
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Identifies the weighted-threshold-policy address.
    /// 2. Pre-reads the current `threshold` and `signer_weights` (MANDATORY
    ///    pre-flight — the vendored example contract exports both views).
    /// 3. Refuses client-side if `new_threshold == 0` or `new_threshold`
    ///    exceeds the checked sum of current signer weights (mirrors OZ
    ///    `InvalidThreshold`, code 3211, `weighted_threshold.rs:352-383`, SHA
    ///    `a9c4216` — defense in depth, not a substitute for the on-chain check).
    /// 4. Submits `set_threshold(threshold, context_rule, smart_account)`
    ///    routed through the smart account's `execute()` entrypoint (avoids
    ///    Soroban re-entry; same rationale as `set_threshold_locked_inner`).
    /// 5. Emits `SaWeightedThresholdChanged` audit row with the pre-read old
    ///    threshold.
    ///
    /// `compute_post_op_invariant` does NOT apply here: weighted-threshold
    /// reachability is a weight-sum invariant, not a signer-count invariant.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule whose weighted-threshold policy is
    ///   changed (the ARGUMENT rule; keys the policy's storage mutation).
    /// - `new_threshold` — the desired new threshold.
    /// - `auth_rule_ids` — the rule(s) AUTHORIZING the change. Defaults to
    ///   `[rule_id]` at the CLI layer (a weighted policy commonly sits on a
    ///   Default-scoped rule that self-authorizes); pass an explicit
    ///   admin-capable rule when the target rule is scoped (a CallContract- or
    ///   CreateContract-scoped rule cannot validate the `execute` auth context
    ///   and refuses with `UnvalidatedContext`, 3002).
    /// - `signer` — the ed25519 signer.
    /// - `request_id` — caller-supplied UUID.
    ///
    /// # Errors
    ///
    /// - [`SaError::WeightedThresholdInstallRefused`] — `new_threshold == 0`
    ///   or exceeds the current weight sum, or `auth_rule_ids` is empty.
    /// - [`SaError::WeightedThresholdNotInstalled`] /
    ///   [`SaError::WeightedThresholdPolicyIdentificationFailed`] —
    ///   identification failure.
    /// - [`SaError::NetworkRpcDivergence`] — two-RPC disagreement.
    /// - [`SaError::DeploymentFailed`] — submission or on-chain rejection.
    pub async fn set_weighted_threshold(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        new_threshold: u32,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
    ) -> Result<(), SaError> {
        if auth_rule_ids.is_empty() {
            return Err(SaError::WeightedThresholdInstallRefused {
                reason: "set-weighted-threshold refused: auth_rule_ids must not be empty"
                    .to_owned(),
            });
        }

        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // The target and the admin rules the call signs under; the submit
        // path compares the admin rules under these locks.
        let guards = self
            .acquire_rule_locks(
                &smart_account_strkey,
                holder_lock_set(rule_id, auth_rule_ids),
                self.lock_budget(),
            )
            .await?;

        let outcome = self
            .set_weighted_threshold_locked_inner(
                smart_account.clone(),
                rule_id,
                auth_rule_ids,
                &guards,
                new_threshold,
                signer,
                &request_id,
            )
            .await;

        match &outcome {
            Ok((old_threshold, policy_addr, tx_hash)) => {
                let policy_addr_redacted = scaddress_to_strkey(policy_addr)
                    .map(|s| redact_strkey_first5_last5(&s))
                    .unwrap_or_else(|_| "unknown".to_owned());
                let tx_hash_redacted = stellar_agent_network::redact_tx_hash(tx_hash);
                match self.audit_writer.lock() {
                    Ok(mut writer) => {
                        let entry = AuditEntry::new_sa_weighted_threshold_changed(
                            rule_id,
                            *old_threshold,
                            new_threshold,
                            RedactedStrkey::from_already_redacted(policy_addr_redacted.clone()),
                            tx_hash_redacted.clone(),
                            RedactedStrkey::from_already_redacted(smart_account_redacted.clone()),
                            self.chain_id.as_str(),
                            request_id.clone(),
                        );
                        if let Err(e) = writer.write_entry(entry) {
                            warn!(
                                error = %e,
                                "set_weighted_threshold: SaWeightedThresholdChanged audit write failed"
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
                            policy_address_redacted = %policy_addr_redacted,
                            transaction_hash_redacted = %tx_hash_redacted,
                            smart_account_redacted = %smart_account_redacted,
                            chain_id = %self.chain_id,
                            request_id = %request_id,
                            "audit-writer mutex poisoned; SaWeightedThresholdChanged row dropped"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    rule_id,
                    smart_account = %smart_account_redacted,
                    "set_weighted_threshold: operation failed"
                );
            }
        }

        outcome.map(|_| ())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the account, the target rule, its auth rules and their held locks, the new \
                  value, the signer and the correlation id"
    )]
    async fn set_weighted_threshold_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        auth_rule_ids: &[ContextRuleId],
        guards: &[RuleLockGuard],
        new_threshold: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(u32, ScAddress, String), SaError> {
        let source_pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!("signer public_key fetch failed: {e}"),
                })?;
        let source_pubkey_strkey = stellar_strkey::ed25519::PublicKey(source_pubkey.0).to_string();

        let policy_addr = self
            .identify_weighted_threshold_policy(
                smart_account.clone(),
                rule_id,
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;

        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, Some(&source_pubkey_strkey))
            .await?;
        let context_rule_scval = context_rule.as_scval()?;

        let view = self
            .get_weighted_threshold_view(
                policy_addr.clone(),
                rule_id,
                smart_account.clone(),
                context_rule_scval.clone(),
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;
        let old_threshold = view.threshold;
        let total_weight = view.total_weight()?;

        if new_threshold == 0 {
            return Err(SaError::WeightedThresholdInstallRefused {
                reason: "--threshold must be non-zero (OZ set_threshold rejects threshold == 0 \
                         with InvalidThreshold)"
                    .to_owned(),
            });
        }
        if new_threshold > total_weight {
            return Err(SaError::WeightedThresholdInstallRefused {
                reason: format!(
                    "--threshold ({new_threshold}) must not exceed the sum of current signer \
                     weights ({total_weight}); OZ set_threshold rejects this with \
                     InvalidThreshold"
                ),
            });
        }

        let set_threshold_sym = ScSymbol::try_from("set_threshold").map_err(|e| {
            SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("encode set_threshold symbol: {e:?}"),
            }
        })?;
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
        let execute_args = vec![
            ScVal::Address(policy_addr.clone()),
            ScVal::Symbol(set_threshold_sym),
            ScVal::Vec(Some(ScVec(target_args_vec))),
        ];

        let expiry_rule_id = auth_rule_ids
            .first()
            .map(ContextRuleId::as_u32)
            .unwrap_or(rule_id);
        let submit_result = self
            .submit_signed_invoke(
                smart_account.clone(),
                &smart_account,
                "execute",
                execute_args,
                auth_rule_ids,
                signer,
                &source_pubkey_strkey,
                "execute",
                Some(ExpiryCheck {
                    rule_id: expiry_rule_id,
                }),
                request_id,
                None,
                Some(&borrowed(guards, &[])),
                None,
            )
            .await?;

        Ok((old_threshold, policy_addr, submit_result.tx_hash))
    }

    // ── set_signer_weight ──────────────────────────────────────────────────────

    /// Changes one signer's `weight` in an installed weighted-threshold policy.
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Identifies the weighted-threshold-policy address.
    /// 2. Pre-reads the current `threshold` and `signer_weights` (MANDATORY
    ///    pre-flight). The target signer's OLD weight is looked up by
    ///    canonical-key byte-equality — `0` if the signer is absent from the
    ///    map (matching OZ "no weight configured contributes zero" semantics).
    /// 3. Refuses client-side if the adjusted weight sum (current sum minus
    ///    the old weight plus the new weight) would fall below the current
    ///    threshold (mirrors OZ `InvalidThreshold`, code 3211,
    ///    `weighted_threshold.rs:413-447`, SHA `a9c4216` — defense in depth).
    /// 4. Submits `set_signer_weight(signer, weight, context_rule,
    ///    smart_account)` routed through `execute()`.
    /// 5. Emits `SaSignerWeightChanged` audit row with the pre-read old weight.
    ///
    /// `compute_post_op_invariant` does NOT apply (weight-sum semantics).
    ///
    /// # Arguments
    ///
    /// See [`Self::set_weighted_threshold`] for the shared argument shapes;
    /// `target_signer` identifies the signer whose weight changes, and
    /// `new_weight` is the desired weight.
    ///
    /// # Errors
    ///
    /// See [`Self::set_weighted_threshold`] for the error taxonomy.
    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible signer + auth + audit arg set"
    )]
    pub async fn set_signer_weight(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        target_signer: crate::weighted_threshold_policy::WeightedThresholdSignerInput,
        new_weight: u32,
        auth_rule_ids: &[ContextRuleId],
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
    ) -> Result<(), SaError> {
        if auth_rule_ids.is_empty() {
            return Err(SaError::WeightedThresholdInstallRefused {
                reason: "set-signer-weight refused: auth_rule_ids must not be empty".to_owned(),
            });
        }

        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
        let signer_identity_redacted = redact_weighted_signer_identity(&target_signer);

        // The target and the admin rules the call signs under; the submit
        // path compares the admin rules under these locks.
        let guards = self
            .acquire_rule_locks(
                &smart_account_strkey,
                holder_lock_set(rule_id, auth_rule_ids),
                self.lock_budget(),
            )
            .await?;

        let outcome = self
            .set_signer_weight_locked_inner(
                smart_account.clone(),
                rule_id,
                auth_rule_ids,
                &guards,
                target_signer,
                new_weight,
                signer,
                &request_id,
            )
            .await;

        match &outcome {
            Ok((old_weight, policy_addr, tx_hash)) => {
                let policy_addr_redacted = scaddress_to_strkey(policy_addr)
                    .map(|s| redact_strkey_first5_last5(&s))
                    .unwrap_or_else(|_| "unknown".to_owned());
                let tx_hash_redacted = stellar_agent_network::redact_tx_hash(tx_hash);
                match self.audit_writer.lock() {
                    Ok(mut writer) => {
                        let entry = AuditEntry::new_sa_signer_weight_changed(
                            rule_id,
                            signer_identity_redacted.clone(),
                            *old_weight,
                            new_weight,
                            RedactedStrkey::from_already_redacted(policy_addr_redacted.clone()),
                            tx_hash_redacted.clone(),
                            RedactedStrkey::from_already_redacted(smart_account_redacted.clone()),
                            self.chain_id.as_str(),
                            request_id.clone(),
                        );
                        if let Err(e) = writer.write_entry(entry) {
                            warn!(
                                error = %e,
                                "set_signer_weight: SaSignerWeightChanged audit write failed"
                            );
                        }
                    }
                    Err(_poison) => {
                        self.mark_audit_writer_degraded();
                        warn!(
                            target: "stellar_agent::audit",
                            rule_id,
                            signer_identity_redacted = %signer_identity_redacted,
                            old_weight = *old_weight,
                            new_weight,
                            policy_address_redacted = %policy_addr_redacted,
                            transaction_hash_redacted = %tx_hash_redacted,
                            smart_account_redacted = %smart_account_redacted,
                            chain_id = %self.chain_id,
                            request_id = %request_id,
                            "audit-writer mutex poisoned; SaSignerWeightChanged row dropped"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    error = %err,
                    rule_id,
                    smart_account = %smart_account_redacted,
                    "set_signer_weight: operation failed"
                );
            }
        }

        outcome.map(|_| ())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "irreducible signer + auth + audit arg set"
    )]
    async fn set_signer_weight_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        auth_rule_ids: &[ContextRuleId],
        guards: &[RuleLockGuard],
        target_signer: crate::weighted_threshold_policy::WeightedThresholdSignerInput,
        new_weight: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(u32, ScAddress, String), SaError> {
        let source_pubkey =
            signer
                .public_key()
                .await
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_payload",
                    redacted_reason: format!("signer public_key fetch failed: {e}"),
                })?;
        let source_pubkey_strkey = stellar_strkey::ed25519::PublicKey(source_pubkey.0).to_string();

        let policy_addr = self
            .identify_weighted_threshold_policy(
                smart_account.clone(),
                rule_id,
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;

        let context_rule = self
            .fetch_context_rule_primary(smart_account.clone(), rule_id, Some(&source_pubkey_strkey))
            .await?;
        let context_rule_scval = context_rule.as_scval()?;

        let view = self
            .get_weighted_threshold_view(
                policy_addr.clone(),
                rule_id,
                smart_account.clone(),
                context_rule_scval.clone(),
                Some(&source_pubkey_strkey),
                request_id.to_owned(),
            )
            .await?;

        let target_signer_scval = match &target_signer {
            crate::weighted_threshold_policy::WeightedThresholdSignerInput::Delegated {
                g_strkey,
            } => build_delegated_signer_scval(g_strkey)?,
            crate::weighted_threshold_policy::WeightedThresholdSignerInput::External {
                verifier,
                key_data,
            } => build_external_signer_scval(verifier.clone(), key_data)?,
        };

        let old_weight = view.weight_of(&target_signer_scval);
        let current_threshold = view.threshold;
        let current_total = view.total_weight()?;

        let adjusted_total = current_total
            .checked_sub(old_weight)
            .and_then(|t| t.checked_add(new_weight))
            .ok_or_else(|| SaError::WeightedThresholdInstallRefused {
                reason: "adjusted signer-weight sum overflows/underflows u32".to_owned(),
            })?;

        if current_threshold > adjusted_total {
            return Err(SaError::WeightedThresholdInstallRefused {
                reason: format!(
                    "--weight ({new_weight}) would drop the adjusted signer-weight sum \
                     ({adjusted_total}) below the current threshold ({current_threshold}); \
                     OZ set_signer_weight rejects this with InvalidThreshold"
                ),
            });
        }

        let set_signer_weight_sym = ScSymbol::try_from("set_signer_weight").map_err(|e| {
            SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("encode set_signer_weight symbol: {e:?}"),
            }
        })?;
        let target_args_vec: VecM<ScVal> = vec![
            target_signer_scval,
            ScVal::U32(new_weight),
            context_rule_scval,
            ScVal::Address(smart_account.clone()),
        ]
        .try_into()
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_contexts_args",
            redacted_reason: format!("encode set_signer_weight target_args VecM: {e:?}"),
        })?;
        let execute_args = vec![
            ScVal::Address(policy_addr.clone()),
            ScVal::Symbol(set_signer_weight_sym),
            ScVal::Vec(Some(ScVec(target_args_vec))),
        ];

        let expiry_rule_id = auth_rule_ids
            .first()
            .map(ContextRuleId::as_u32)
            .unwrap_or(rule_id);
        let submit_result = self
            .submit_signed_invoke(
                smart_account.clone(),
                &smart_account,
                "execute",
                execute_args,
                auth_rule_ids,
                signer,
                &source_pubkey_strkey,
                "execute",
                Some(ExpiryCheck {
                    rule_id: expiry_rule_id,
                }),
                request_id,
                None,
                Some(&borrowed(guards, &[])),
                None,
            )
            .await?;

        Ok((old_weight, policy_addr, submit_result.tx_hash))
    }

    // ── batch_add_signers ──────────────────────────────────────────────────────

    /// Adds multiple signers to a context rule in ONE transaction via OZ
    /// `batch_add_signer(context_rule_id, Vec<Signer>)`
    /// (`examples/multisig-smart-account/account/src/contract.rs:43`,
    /// `packages/accounts/src/smart_account/storage.rs:1053`, SHA `a9c4216`
    /// — on-chain dup-check across existing + new signers, one
    /// `SignerAdded` event per signer).
    ///
    /// Acquires the per-rule mutex, then:
    ///
    /// 1. Compares the chain with the rule's version-2 audit-log state, as
    ///    [`Self::add_signer`] does.
    /// 2. Refuses client-side if `existing_signer_count + batch.len() >
    ///    MAX_SIGNERS` (OZ `MAX_SIGNERS = 15`,
    ///    `packages/accounts/src/smart_account/mod.rs:526`, SHA `a9c4216`;
    ///    enforced on-chain via a raw panic, `storage.rs:1072` → `:379`).
    /// 3. Submits `batch_add_signer(rule_id, signers)` as a single
    ///    `InvokeHostFunctionOp`.
    /// 4. After it confirms, requires exactly the intended change through both
    ///    endpoints at or past the confirmation ledger: each new signer
    ///    present under a new id, every other signer and the threshold
    ///    unchanged.
    /// 5. Writes one `SaSignerAddedV2` row per signer, each carrying the
    ///    resulting set, then the override rows and the
    ///    `SaContextRulePinsUpdated` row described under "Pin record".
    ///
    /// Returns the id the chain assigned to each new signer, in input order.
    /// A rule without a simple-threshold policy accepts a batch; adding
    /// signers cannot make a threshold unreachable.
    ///
    /// The single-signer `add_signer` verb and its arg contract are
    /// unchanged; this is an additive verb for the batch case.
    ///
    /// # Pin record
    ///
    /// The batch keeps a pinned rule's pin record in step as
    /// [`Self::add_signer`] does (see "Pin record" there), for every distinct
    /// new verifier address among the batch's `External` signers. Once the
    /// batch confirms it writes the override rows of every new verifier,
    /// then one `SaContextRulePinsUpdated` row, at the points
    /// [`Self::add_signer`] writes them. A refusal of any new verifier
    /// refuses the batch and writes no override row.
    ///
    /// # Errors
    ///
    /// - [`SaError::BatchSignerAddRefused`] — the batch is empty (nothing to
    ///   add), refused before acquiring the per-rule mutex, or one of its
    ///   signers is not a signer the wallet can decode.
    /// - [`SaError::ContextRuleCapsExceeded`] — the batch would exceed
    ///   `MAX_SIGNERS`.
    /// - The comparison, submission and recording errors of
    ///   [`Self::add_signer`].
    /// - [`SaError::VerifierWasmNotInAllowlist`] / [`SaError::VerifierMutable`] /
    ///   [`SaError::ContractInstanceUnsupported`]: a new verifier of a pinned
    ///   rule was refused under "Pin record".
    /// - [`SaError::VerifierHashDrift`] / [`SaError::PolicyHashDrift`] /
    ///   [`SaError::PinnedPolicyAbsent`] / [`SaError::PinCheckUnavailable`]:
    ///   the pinned-hash drift check of the rule refused before signing.
    #[allow(
        clippy::too_many_arguments,
        reason = "signer + auth + audit arg set plus the two pin overrides rule install takes"
    )]
    pub async fn batch_add_signers(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        new_signers: Vec<ScVal>,
        signer: &(dyn Signer + Send + Sync),
        request_id: String,
        accept_mutable_verifier: bool,
        accept_unknown_verifier: bool,
    ) -> Result<Vec<u32>, SaError> {
        if new_signers.is_empty() {
            return Err(SaError::BatchSignerAddRefused {
                reason: "batch is empty: at least one signer is required".to_owned(),
            });
        }

        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        // The target is the only rule the batch signs under.
        let guards = self
            .acquire_rule_locks(&smart_account_strkey, [rule_id], self.lock_budget())
            .await?;

        let outcome = self
            .batch_add_signers_locked_inner(
                smart_account,
                rule_id,
                &guards,
                &smart_account_strkey,
                &smart_account_redacted,
                new_signers,
                signer,
                &request_id,
                PinOverrides {
                    accept_mutable_verifier,
                    accept_unknown_verifier,
                },
            )
            .await;
        let confirmed = outcome.inspect_err(|err| {
            warn_failed("batch_add_signers", rule_id, &smart_account_redacted, err);
        })?;

        self.record_confirmed_add(
            "batch_add_signers",
            rule_id,
            &smart_account_strkey,
            &smart_account_redacted,
            confirmed,
            &request_id,
        )
    }

    /// Core logic for `batch_add_signers` (called inside the per-rule
    /// mutex).
    ///
    /// Returns an error when the batch is refused or fails before it
    /// confirms. Once it confirms, returns the outcome of the steps after
    /// confirmation ([`Self::validate_confirmed_batch`]) with the pin update
    /// planned before submission.
    #[allow(clippy::too_many_arguments, reason = "irreducible inner arg set")]
    async fn batch_add_signers_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        guards: &[RuleLockGuard],
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        new_signers: Vec<ScVal>,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
        overrides: PinOverrides,
    ) -> Result<ConfirmedSignerAdd<Vec<u32>>, SaError> {
        let source_pubkey_strkey = signer_source_strkey(signer).await?;

        let added = new_signers
            .iter()
            .enumerate()
            .map(|(index, scval)| {
                decode_signer_scval_full(scval).map_err(|e| SaError::BatchSignerAddRefused {
                    reason: format!("signer at index {index} is not a recognised Signer: {e}"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let identities: Vec<SignerIdentityV2> = added
            .iter()
            .map(DecodedOnChainSigner::to_identity_v2)
            .collect();

        let compared = [self
            .verify_signer_set_locked(
                held_guard(guards, smart_account_strkey, rule_id)?,
                V1Handling::RefuseLegacy,
                Some(&source_pubkey_strkey),
                request_id,
            )
            .await?];
        let before = compared[0].snapshot();

        let current_signer_count = before.signer_count();
        let batch_len = u32::try_from(new_signers.len()).unwrap_or(u32::MAX);
        let post_op_signer_count = current_signer_count.saturating_add(batch_len);

        // Mandatory pre-check (OZ MAX_SIGNERS = 15, mod.rs:526): the batch is
        // refused client-side BEFORE any submission if it would exceed the
        // cap — the on-chain enforcement is a raw panic (storage.rs:1072 ->
        // :379), so this check names the cap explicitly for the operator.
        if post_op_signer_count > MAX_SIGNERS {
            return Err(SaError::ContextRuleCapsExceeded {
                kind: "signers",
                cur: current_signer_count,
                max: MAX_SIGNERS,
            });
        }

        let signers_vec: VecM<ScVal> =
            new_signers
                .try_into()
                .map_err(|e| SaError::AuthEntryConstructionFailed {
                    stage: "auth_contexts_args",
                    redacted_reason: format!("encode batch_add_signer signers VecM: {e:?}"),
                })?;
        let batch_add_signer_args = vec![ScVal::U32(rule_id), ScVal::Vec(Some(ScVec(signers_vec)))];

        let pin_update = self
            .plan_signer_add_pin_update(
                rule_id,
                smart_account_redacted,
                before,
                &external_verifiers(added.iter()),
                overrides,
                request_id,
            )
            .await?;

        let auth_rule_ids = vec![ContextRuleId::from(rule_id)];
        let submitted = self
            .submit_single_op(
                smart_account.clone(),
                &smart_account,
                rule_id,
                "batch_add_signer",
                batch_add_signer_args,
                &auth_rule_ids,
                signer,
                &source_pubkey_strkey,
                Some(ExpiryCheck { rule_id }),
                request_id,
                &borrowed(guards, &compared),
                None,
            )
            .await?;

        let outcome = self
            .validate_confirmed_batch(
                &smart_account,
                rule_id,
                smart_account_redacted,
                &source_pubkey_strkey,
                before,
                identities,
                submitted,
                request_id,
            )
            .await;
        Ok(ConfirmedSignerAdd {
            outcome,
            pin_update,
        })
    }

    /// Observes the rule after a confirmed `batch_add_signer` and requires
    /// exactly the intended change: `before` with each of `identities` added,
    /// every other signer and the threshold unchanged. Returns the id the
    /// chain assigned to each added identity, in input order.
    ///
    /// # Errors
    ///
    /// - [`SaError::BaselineWriteFailed`] at stage `observe`: the confirmed
    ///   state was not observed.
    /// - [`SaError::SignerSetDiverged`] with the transaction hash: the
    ///   confirmed state is not the intended change.
    #[allow(
        clippy::too_many_arguments,
        reason = "rule identity, the pre-submission state, the added identities and the \
                  confirmed transaction"
    )]
    async fn validate_confirmed_batch(
        &self,
        smart_account: &ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        source_pubkey_strkey: &str,
        before: &SignerSetSnapshotV2,
        identities: Vec<SignerIdentityV2>,
        submitted: crate::submit::SubmitInvokeResult,
        request_id: &str,
    ) -> Result<(Vec<u32>, ConfirmedMutation), SaError> {
        let observation = self
            .observe_confirmed(
                smart_account,
                rule_id,
                Some(source_pubkey_strkey),
                &submitted,
                smart_account_redacted,
                request_id,
            )
            .await?;

        // The chain assigns the ids; each added identity takes the id it
        // holds in the observed set, so the returned ids follow the input
        // order whatever order the chain assigned them in.
        let added_ids = assign_added_ids(before, &observation.snapshot, &identities);
        let intended = with_added_signers(before, added_ids.iter().copied().zip(identities));
        let resulting = self.require_intended_state(
            rule_id,
            smart_account_redacted,
            intended,
            observation,
            &submitted.tx_hash,
            request_id,
        )?;

        Ok((
            added_ids,
            ConfirmedMutation {
                resulting,
                tx_hash: submitted.tx_hash,
            },
        ))
    }

    // ── classify_rule_policies ─────────────────────────────────────────────────

    /// Classifies every policy attached to a context rule by its own on-chain
    /// wasm-hash, for read-only observability (`stellar_rules_get`).
    ///
    /// Unlike [`Self::identify_spending_limit_policy`] and the signer-set
    /// observation's threshold-policy identification (which fail closed
    /// when the rule's policies do not resolve to the allowlisted contracts
    /// they require), this is a per-address,
    /// best-effort classification for display purposes: each attached policy
    /// is independently checked against both allowlists, and an unrecognised
    /// or unobservable hash degrades to [`PolicyIdentifiedKind::Unknown`]
    /// rather than failing the whole read.
    ///
    /// Uses a single-RPC (primary only) wasm-hash fetch — this is a read-only
    /// display aid, not a security gate, so the two-RPC divergence check used
    /// by the identify_* functions is not warranted here.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `rule_id` — the context rule whose policies are classified.
    /// - `source_account_strkey` — G-strkey of the fee-paying account.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] — the `get_context_rule` simulation or
    ///   the `getLedgerEntries` wasm-hash fetch failed. Per-policy hash
    ///   absence/mismatch does NOT error; it classifies as `Unknown`.
    ///
    /// # Implements
    ///
    /// Policy observability: `stellar_rules_get`'s `policies: [{ address,
    /// identified_kind }]` field (GH issue #7).
    pub async fn classify_rule_policies(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
    ) -> Result<Vec<(ScAddress, PolicyIdentifiedKind)>, SaError> {
        let context_rule = self
            .fetch_context_rule_primary(smart_account, rule_id, source_account_strkey)
            .await?;

        if context_rule.policies.is_empty() {
            return Ok(vec![]);
        }

        let policy_keys: Vec<LedgerKey> = context_rule
            .policies
            .iter()
            .map(contract_instance_key)
            .collect();

        let primary_hashes = fetch_contract_wasm_hashes(&self.primary_rpc_client, &policy_keys)
            .await
            .map_err(|e| SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("policy classification wasm-hash fetch failed: {e}"),
            })?;

        let spending_limit_hash = stellar_agent_core::hex::decode_hex32(
            crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256,
        )
        .map_err(|_| SaError::DeploymentFailed {
            phase: "build",
            redacted_reason: "SPENDING_LIMIT_POLICY_WASM_SHA256 const is not valid 64-char hex"
                .to_owned(),
        })?;

        let mut out = Vec::with_capacity(context_rule.policies.len());
        for (addr, hash_opt) in context_rule.policies.iter().zip(primary_hashes.iter()) {
            let kind = match hash_opt {
                Some(hash) if THRESHOLD_POLICY_WASM_HASHES.iter().any(|h| h == hash) => {
                    PolicyIdentifiedKind::Threshold
                }
                Some(hash) if *hash == spending_limit_hash => PolicyIdentifiedKind::SpendingLimit,
                _ => PolicyIdentifiedKind::Unknown,
            };
            out.push((addr.clone(), kind));
        }

        Ok(out)
    }

    // ── fetch_current_ledger ───────────────────────────────────────────────────

    /// Fetches the current ledger sequence via a cheap read-only simulation
    /// against the smart account's `get_context_rules_count` entrypoint
    /// (always available; no arguments).
    ///
    /// Used by callers that need a shared "as of" ledger stamp for a batch of
    /// otherwise ledger-oblivious reads (`ContextRuleManager::list_active_context_rules`,
    /// `ContextRuleManager::get_rule`), e.g. the `stellar_rules_list` /
    /// `stellar_rules_get` MCP tools' `as_of_ledger` / `expires_in_ledgers` fields.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] — the simulation failed.
    /// - [`SaError::AuthEntryConstructionFailed`] — RPC or XDR construction failure.
    pub async fn fetch_current_ledger(
        &self,
        smart_account: ScAddress,
        source_account_strkey: Option<&str>,
    ) -> Result<u32, SaError> {
        let (_scval, ledger) = simulate_read_only_with_ledger(
            self.primary_rpc_client.url(),
            smart_account,
            "get_context_rules_count",
            vec![],
            source_account_strkey,
            &self.network_passphrase,
            self.timeout,
        )
        .await?;
        Ok(ledger)
    }

    // ── identify_verifier ─────────────────────────────────────────────────────

    /// Identifies a deployed verifier contract by its effective wasm hash.
    ///
    /// Observes `verifier_addr` via `SignersManager::observe_contract` and
    /// matches the effective hash against [`crate::VERIFIER_ALLOWLIST`]. An
    /// external reference identifies as the allowlisted code its tag
    /// resolves to at this ledger; the owner can repoint it later, so the
    /// install path pins the reference itself and treats it as mutable.
    /// Zero matches return [`SaError::VerifierWasmNotInAllowlist`]
    /// (fail-closed).
    ///
    /// Returns the matched effective hash on success.
    ///
    /// For drift-detection at signing time where allowlist enforcement is not
    /// desired (comparison is against the pinned value), use
    /// `fetch_observed_executable` instead.
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
    /// - [`SaError::VerifierWasmNotInAllowlist`]: no code, or an effective
    ///   hash outside the allowlist (fail-closed; allowlist is the
    ///   authoritative gate).
    /// - [`SaError::ContractInstanceUnsupported`] — the verifier's executable
    ///   is an external reference with no live tag entry (reason
    ///   `ExternalRefUnresolved`) or an endpoint returned a malformed entry
    ///   (reason `UndecodableInstance`); no flag overrides it.
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree
    ///   on the contract's executable before the allowlist check runs.
    /// - [`SaError::DeploymentFailed`] (phase `"simulate"`) — `getLedgerEntries`
    ///   RPC failure on primary or secondary.
    ///
    /// # Implements
    ///
    /// Verifier pinning: matches the live on-chain effective hash against the
    /// allowlist before any rule-install operation, ensuring only approved
    /// verifier code can be referenced.
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
        // source_account_strkey is accepted for API symmetry with the other
        // identify_* helpers but not used directly; smart_account_redacted
        // populates forensic fields.
        let _ = source_account_strkey;

        let observation = self
            .observe_contract(
                &verifier_addr,
                ContractKind::Verifier,
                verifier_hash_allowlisted,
                Some(rule_id),
                &smart_account_redacted,
                &request_id,
            )
            .await?;

        if !observation.allowlisted {
            return Err(SaError::VerifierWasmNotInAllowlist {
                rule_id: Some(rule_id),
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                observed_hash_first8: observation.observed_hash_first8(),
                request_id,
            });
        }

        Ok(observation.effective_hash)
    }

    /// Observes a deployed verifier or policy contract and decides whether
    /// its effective hash is allowlisted.
    ///
    /// Fetches the executable via [`fetch_observed_executable`] (two-RPC,
    /// with an external reference resolved at each endpoint). An external
    /// reference with no live tag entry is refused before any allowlist
    /// decision, because it names no code the wallet can pin. Otherwise the
    /// returned [`ContractObservation`] carries the executable, its effective
    /// hash (zero for no code) and whether `is_allowlisted` accepts that
    /// hash; no code is never allowlisted.
    ///
    /// `contract_kind` names the role of `contract_addr` in a refusal.
    /// `rule_id` is `None` before install, when the rule has no on-chain id
    /// yet; see [`fetch_observed_executable`] for how each refusal carries it.
    ///
    /// # Errors
    ///
    /// - [`SaError::ContractInstanceUnsupported`]: an external reference
    ///   with no live tag entry (reason `ExternalRefUnresolved`), or a
    ///   malformed entry (reason `UndecodableInstance`); no flag overrides it.
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree.
    /// - [`SaError::DeploymentFailed`] — RPC fetch failed.
    pub(crate) async fn observe_contract(
        &self,
        contract_addr: &ScAddress,
        contract_kind: ContractKind,
        is_allowlisted: impl Fn(&[u8; 32]) -> bool,
        rule_id: Option<u32>,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<ContractObservation, SaError> {
        let observed = fetch_observed_executable(
            &self.primary_rpc_client,
            &self.secondary_rpc_client,
            contract_addr,
            contract_kind,
            rule_id,
            smart_account_redacted,
            request_id,
        )
        .await?;

        let contract_redacted = scaddress_to_strkey(contract_addr)
            .map(|s| redact_strkey_first5_last5(&s))
            .unwrap_or_else(|_| "unknown".to_owned());

        if let ObservedExecutable::ExternalRef(external) = &observed
            && external.resolved.is_none()
        {
            warn!(
                contract_redacted = %contract_redacted,
                contract_kind = %contract_kind,
                owner_redacted = %external.owner_redacted(),
                tag = %external.tag_display(),
                rule_id,
                "observe_contract: external reference has no live tag entry; refusing"
            );
            return Err(SaError::ContractInstanceUnsupported {
                rule_id,
                contract_kind,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                contract_address_redacted: RedactedStrkey::from_already_redacted(contract_redacted),
                reason: AdminOrOwnerKey::ExternalRefUnresolved,
                request_id: request_id.to_owned(),
            });
        }

        let effective = observed.effective_hash();
        let observation = ContractObservation {
            allowlisted: effective.is_some_and(|hash| is_allowlisted(&hash)),
            effective_hash: effective.unwrap_or([0u8; 32]),
            observed,
        };

        debug!(
            contract = %contract_redacted,
            contract_kind = %contract_kind,
            executable = %observation.observed.summary(),
            wasm_hash_first8 = %observation.observed_hash_first8(),
            allowlisted = observation.allowlisted,
            "observe_contract: observed contract executable"
        );

        Ok(observation)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Reads the newest signer-set state row of rule `rule_id` of the smart
    /// account `smart_account_strkey`, of either snapshot version.
    ///
    /// The reader matches a version-1 state row on `smart_account_redacted`
    /// and a version-2 state row on the account digest of this manager's
    /// network passphrase and `smart_account_strkey`. Each caller branches on
    /// the returned view's version.
    ///
    /// `AuditLogIntegrityError` MUST propagate; it is never reinterpreted as
    /// `Ok(None)`.
    fn read_signer_set_view(
        &self,
        rule_id: u32,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
    ) -> Result<Option<SignerSetViewPayload>, AuditLogIntegrityError> {
        let reader = stellar_agent_core::audit_log::reader::AuditReader::new(
            Arc::clone(&self.audit_writer),
            None,
        );
        let digest = account_digest(&self.network_passphrase, smart_account_strkey);
        reader.find_latest_signer_set_view(rule_id, smart_account_redacted, &digest)
    }

    /// Reads the newest signer-set state row of the rule `guard` locks, of
    /// either snapshot version. No RPC.
    ///
    /// The rule, the account and its redaction come from the guard, which
    /// proves the caller holds the rule's lock; this function acquires none.
    /// The read is a synchronous audit-log scan; a caller under a deadline
    /// checks it after the read.
    ///
    /// # Errors
    ///
    /// - [`SaError::SignerSetMissingBaseline`]: the rule has no state row.
    /// - [`SaError::SignerSetBaselineLegacy`]: the newest row is version 1
    ///   and `on_v1` is [`V1Handling::RefuseLegacy`].
    /// - [`SaError::AuditLog`]: audit-log integrity violation.
    pub(crate) async fn read_baseline_locked(
        &self,
        guard: &RuleLockGuard,
        on_v1: V1Handling,
        request_id: &str,
    ) -> Result<BaselineRead, SaError> {
        let rule_id = guard.rule_id();
        let smart_account_redacted = guard.smart_account_redacted();
        let payload = self
            .read_signer_set_view(
                rule_id,
                guard.smart_account_strkey(),
                &smart_account_redacted,
            )?
            .ok_or_else(|| SaError::SignerSetMissingBaseline {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.as_str(),
                ),
                request_id: request_id.to_owned(),
            })?;
        if on_v1 == V1Handling::RefuseLegacy && matches!(payload.view(), SignerSetView::V1(_)) {
            return Err(SaError::SignerSetBaselineLegacy {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id: request_id.to_owned(),
            });
        }
        Ok(BaselineRead { payload, rule_id })
    }

    /// Compares the chain with `baseline`, the state row of the rule `guard`
    /// locks.
    ///
    /// Observes the signer set in version 2 through both endpoints and
    /// classifies it against the row in the row's version
    /// ([`classify_against`]). A changed set writes the `SaSignerSetDiverged`
    /// row and refuses with [`SaError::SignerSetDiverged`] without a
    /// transaction hash; a version-1 row without a comparable projection
    /// refuses with the projection's error. A [`ComparedState`] is produced
    /// only here.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] (phase `simulate`): `baseline` was read
    ///   for another rule than the one `guard` locks.
    /// - [`SaError::SignerSetDiverged`]: the chain differs from the row.
    /// - The observation errors of [`Self::list_signers`] and the version-1
    ///   projection errors of [`Self::verify_signer_set_against_chain`].
    pub(crate) async fn compare_locked(
        &self,
        guard: &RuleLockGuard,
        baseline: BaselineRead,
        source_account_strkey: Option<&str>,
        request_id: &str,
    ) -> Result<ComparedState, SaError> {
        let rule_id = guard.rule_id();
        if baseline.rule_id != rule_id {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "signer-set comparison: the state row of rule {} was presented for rule \
                     {rule_id}",
                    baseline.rule_id
                ),
            });
        }
        let smart_account_redacted = guard.smart_account_redacted();
        let smart_account =
            crate::managers::rules::parse_c_strkey_to_smart_account(guard.smart_account_strkey())?;
        let expected = baseline.payload.view().clone();
        let row_hash = *baseline.payload.row_hash();

        let observation = self
            .observe_signer_set_v2(
                &smart_account,
                rule_id,
                source_account_strkey,
                None,
                request_id,
            )
            .await?;

        match classify_against(&expected, &observation)? {
            Classified::Matched { observed } => Ok(ComparedState {
                view: observed,
                row_hash,
                observation,
            }),
            Classified::Diverged { observed } => {
                self.emit_signer_set_diverged(
                    rule_id,
                    &smart_account_redacted,
                    &expected,
                    &observed,
                    request_id,
                );
                Err(SaError::SignerSetDiverged {
                    rule_id,
                    expected,
                    observed,
                    tx_hash: None,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    request_id: request_id.to_owned(),
                })
            }
            Classified::NotComparable { cause } => Err(cause),
        }
    }

    /// Reads the state row of the rule `guard` locks and compares the chain
    /// with it: [`Self::read_baseline_locked`], then
    /// [`Self::compare_locked`].
    ///
    /// # Errors
    ///
    /// The errors of the two steps.
    pub(crate) async fn verify_signer_set_locked(
        &self,
        guard: &RuleLockGuard,
        on_v1: V1Handling,
        source_account_strkey: Option<&str>,
        request_id: &str,
    ) -> Result<ComparedState, SaError> {
        let baseline = self.read_baseline_locked(guard, on_v1, request_id).await?;
        self.compare_locked(guard, baseline, source_account_strkey, request_id)
            .await
    }

    /// Observes rule `rule_id`'s signer set in version 2 through both RPC
    /// endpoints.
    ///
    /// Per endpoint, in order: the rule read (`get_context_rule`), then, once
    /// both endpoints agree on the rule, one executable read per distinct
    /// attached policy (two-endpoint, see
    /// `identify_simple_threshold_policy`), then the `get_threshold` read of
    /// the simple-threshold policy when there is one. The two endpoints must
    /// agree on the rule (id, signers as version-2 identities, policy list)
    /// and on the threshold; a difference refuses with
    /// [`SaError::NetworkRpcDivergence`]. A threshold read failure refuses
    /// with [`SaError::ThresholdReadFailed`]. The snapshot is built in
    /// ascending id order and validated; a malformed set is a chain fact and
    /// refuses with [`SaError::DeploymentFailed`] (phase `simulate`) naming
    /// the broken rule.
    ///
    /// `catch_up` is `Some` for the observation after a confirmed
    /// transaction. A read reporting a `latestLedger` below its floor comes
    /// from an endpoint that is behind: a behind rule read is repeated after
    /// a pause, and a behind threshold read repeats that endpoint's whole
    /// observation, rule and threshold. Reads repeat until they reach the
    /// floor or the budget ends, which refuses with
    /// [`SaError::DeploymentFailed`]. The observation's ledger is the
    /// smallest `latestLedger` across the reads it keeps.
    async fn observe_signer_set_v2(
        &self,
        smart_account: &ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        catch_up: Option<CatchUp<'_>>,
        request_id: &str,
    ) -> Result<ObservationV2, SaError> {
        let smart_account_redacted =
            redact_strkey_first5_last5(&scaddress_to_strkey(smart_account)?);

        let (primary, secondary) = tokio::join!(
            self.read_rule(
                &self.primary_rpc_client,
                smart_account,
                rule_id,
                source_account_strkey,
                catch_up,
            ),
            self.read_rule(
                &self.secondary_rpc_client,
                smart_account,
                rule_id,
                source_account_strkey,
                catch_up,
            ),
        );
        let (primary, secondary) = (primary?, secondary?);
        Self::require_same_rule(
            &primary.rule,
            &secondary.rule,
            rule_id,
            &smart_account_redacted,
            request_id,
        )?;

        let policies = primary.rule.policies.clone();
        let (threshold_policy, policy_hashes) = self
            .identify_simple_threshold_policy(
                &policies,
                rule_id,
                &smart_account_redacted,
                request_id,
            )
            .await?;
        let threshold_policy_address = threshold_policy.as_ref().map(|(address, _)| address);

        let (primary, secondary) = tokio::join!(
            self.complete_endpoint(
                &self.primary_rpc_client,
                smart_account,
                rule_id,
                source_account_strkey,
                primary,
                threshold_policy_address,
                catch_up,
                &smart_account_redacted,
                request_id,
            ),
            self.complete_endpoint(
                &self.secondary_rpc_client,
                smart_account,
                rule_id,
                source_account_strkey,
                secondary,
                threshold_policy_address,
                catch_up,
                &smart_account_redacted,
                request_id,
            ),
        );
        let (primary, secondary) = (primary?, secondary?);

        // A repeated endpoint observation replaced that endpoint's rule read,
        // so the endpoints are compared again, and the rule's policy list must
        // still be the one the threshold policy was identified from.
        Self::require_same_rule(
            &primary.rule,
            &secondary.rule,
            rule_id,
            &smart_account_redacted,
            request_id,
        )?;
        if primary.rule.policies != policies {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: "get_context_rule: the rule's policy list changed during the \
                                  signer-set observation"
                    .to_owned(),
            });
        }
        if let (Some(primary_threshold), Some(secondary_threshold)) =
            (primary.threshold, secondary.threshold)
            && primary_threshold != secondary_threshold
        {
            return Err(Self::signer_set_rpc_divergence(
                rule_id,
                &smart_account_redacted,
                &ScVal::U32(primary_threshold),
                &ScVal::U32(secondary_threshold),
                request_id,
            ));
        }
        let threshold = threshold_policy
            .zip(primary.threshold)
            .map(|((_, policy), threshold)| ThresholdObservation { policy, threshold });
        let snapshot = snapshot_of_rule(&primary.rule, threshold)?;

        let v1_signers = primary
            .rule
            .signers
            .iter()
            .enumerate()
            .map(|(index, (id, signer))| {
                signer
                    .to_signer_pubkey_v1()
                    .map(|pubkey| (*id, pubkey))
                    .map_err(|e| (index, *id, e))
            })
            .collect();

        Ok(ObservationV2 {
            rule_id,
            smart_account_redacted,
            request_id: request_id.to_owned(),
            snapshot,
            policies,
            policy_hashes,
            ledger: primary.ledger.min(secondary.ledger),
            primary_rule: primary.rule.raw_scval,
            v1_signers,
        })
    }

    /// Reads rule `rule_id` from one endpoint with the read's `latestLedger`.
    ///
    /// With `catch_up`, a read reporting a ledger below the floor is repeated
    /// after [`CONFIRMATION_CATCH_UP_PAUSE`] until it reaches the floor or the
    /// budget ends, whether its simulation succeeded or failed: an endpoint
    /// behind the confirmation does not hold a rule the confirmed transaction
    /// created yet.
    async fn read_rule(
        &self,
        rpc_client: &StellarRpcClient,
        smart_account: &ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        catch_up: Option<CatchUp<'_>>,
    ) -> Result<EndpointRead, SaError> {
        loop {
            let (outcome, ledger) = simulate_read_only_at_ledger(
                rpc_client.url(),
                smart_account.clone(),
                "get_context_rule",
                vec![ScVal::U32(rule_id)],
                source_account_strkey,
                &self.network_passphrase,
                self.timeout,
            )
            .await?;
            if let Some(catch_up) = catch_up
                && ledger < catch_up.floor
            {
                self.catch_up_pause(rpc_client, "get_context_rule", ledger, catch_up)
                    .await?;
                continue;
            }
            return Ok(EndpointRead {
                rule: decode_context_rule_scval(outcome?)?,
                ledger,
                threshold: None,
            });
        }
    }

    /// Completes one endpoint's observation with the `get_threshold` read of
    /// `threshold_policy`; returns `read` unchanged when the rule has no
    /// simple-threshold policy.
    ///
    /// With `catch_up`, a threshold read reporting a ledger below the floor
    /// repeats the endpoint's whole observation, the rule read and the
    /// threshold read, after [`CONFIRMATION_CATCH_UP_PAUSE`], whether the
    /// read succeeded or failed: an endpoint behind the confirmation does not
    /// hold a threshold the confirmed transaction set yet.
    #[allow(
        clippy::too_many_arguments,
        reason = "endpoint, rule identity, the endpoint's rule read, the policy, the \
                  catch-up floor and correlation fields"
    )]
    async fn complete_endpoint(
        &self,
        rpc_client: &StellarRpcClient,
        smart_account: &ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        mut read: EndpointRead,
        threshold_policy: Option<&ScAddress>,
        catch_up: Option<CatchUp<'_>>,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<EndpointRead, SaError> {
        let Some(policy) = threshold_policy else {
            return Ok(read);
        };
        loop {
            let (outcome, ledger) = self
                .read_threshold(
                    rpc_client,
                    policy,
                    smart_account,
                    rule_id,
                    source_account_strkey,
                    smart_account_redacted,
                    request_id,
                )
                .await?;
            if let Some(catch_up) = catch_up
                && ledger < catch_up.floor
            {
                self.catch_up_pause(rpc_client, "get_threshold", ledger, catch_up)
                    .await?;
                read = self
                    .read_rule(
                        rpc_client,
                        smart_account,
                        rule_id,
                        source_account_strkey,
                        Some(catch_up),
                    )
                    .await?;
                continue;
            }
            read.threshold = Some(outcome?);
            read.ledger = read.ledger.min(ledger);
            return Ok(read);
        }
    }

    /// Reads `get_threshold(rule_id, smart_account)` of the simple-threshold
    /// policy `policy` from one endpoint, with the read's `latestLedger`.
    ///
    /// The threshold policy exposes
    /// `get_threshold(e, context_rule_id: u32, smart_account: Address) -> u32`
    /// per the OpenZeppelin stellar-accounts v0.7.2 contract. A failed
    /// simulation or a return that is not a `u32` is the inner
    /// [`SaError::ThresholdReadFailed`] naming the endpoint, beside the
    /// ledger the response reported. The caller can then tell a read behind
    /// the confirmation from a failure. No threshold is inferred from the
    /// signer count.
    ///
    /// # Errors
    ///
    /// [`SaError::ThresholdReadFailed`] when no response arrived, such as a
    /// transport failure.
    #[allow(
        clippy::too_many_arguments,
        reason = "endpoint, policy, rule identity and correlation fields"
    )]
    async fn read_threshold(
        &self,
        rpc_client: &StellarRpcClient,
        policy: &ScAddress,
        smart_account: &ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<(Result<u32, SaError>, u32), SaError> {
        let source_kind = self.rpc_source_kind(rpc_client);
        let read = simulate_read_only_at_ledger(
            rpc_client.url(),
            policy.clone(),
            "get_threshold",
            vec![ScVal::U32(rule_id), ScVal::Address(smart_account.clone())],
            source_account_strkey,
            &self.network_passphrase,
            self.timeout,
        )
        .await;
        let refused = |detail: String| {
            debug!(
                rule_id,
                source_kind,
                detail = %detail,
                "get_threshold failed (fail closed)"
            );
            SaError::ThresholdReadFailed {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                source_kind,
                request_id: request_id.to_owned(),
            }
        };
        match read {
            Ok((Ok(ScVal::U32(threshold)), ledger)) => Ok((Ok(threshold), ledger)),
            Ok((Ok(other), ledger)) => Ok((
                Err(refused(format!(
                    "expected ScVal::U32, got {}",
                    scval_variant_name(&other)
                ))),
                ledger,
            )),
            Ok((Err(e), ledger)) => Ok((Err(refused(e.to_string())), ledger)),
            Err(e) => Err(refused(e.to_string())),
        }
    }

    /// Waits [`CONFIRMATION_CATCH_UP_PAUSE`] before an endpoint behind the
    /// confirmation ledger is read again. The read is first recorded as
    /// `catch_up`'s last behind read.
    ///
    /// # Errors
    ///
    /// [`SaError::DeploymentFailed`] (phase `simulate`) naming the read, the
    /// endpoint and both ledgers when the pause would end past `catch_up`'s
    /// deadline.
    async fn catch_up_pause(
        &self,
        rpc_client: &StellarRpcClient,
        read: &'static str,
        latest_ledger: u32,
        catch_up: CatchUp<'_>,
    ) -> Result<(), SaError> {
        let source_kind = self.rpc_source_kind(rpc_client);
        let behind = BehindRead {
            read,
            source_kind,
            latest_ledger,
            floor: catch_up.floor,
        };
        if let Ok(mut last_behind) = catch_up.last_behind.lock() {
            *last_behind = Some(behind);
        }
        if tokio::time::Instant::now() + CONFIRMATION_CATCH_UP_PAUSE > catch_up.deadline {
            return Err(behind.refusal(&format!(
                "the confirmation_recording budget of {} ms leaves no time for another read",
                self.timeout.as_millis()
            )));
        }
        debug!(
            read,
            source_kind,
            latest_ledger,
            floor = catch_up.floor,
            "endpoint behind the confirmation ledger; reading again after a pause"
        );
        tokio::time::sleep(CONFIRMATION_CATCH_UP_PAUSE).await;
        Ok(())
    }

    /// Identifies the rule's simple-threshold policy among `policies`.
    ///
    /// Returns the one match of [`Self::allowlisted_threshold_policies`] with
    /// its contract id, or `None` when no policy matches, together with the
    /// summary a refusal carries.
    ///
    /// # Errors
    ///
    /// - [`SaError::ThresholdPolicyIdentificationFailed`]: more than one
    ///   policy matches.
    /// - The errors of [`Self::allowlisted_threshold_policies`].
    async fn identify_simple_threshold_policy(
        &self,
        policies: &[ScAddress],
        rule_id: u32,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<(Option<(ScAddress, [u8; 32])>, WasmHashSummary), SaError> {
        let (matches, summary) = self
            .allowlisted_threshold_policies(policies, rule_id, smart_account_redacted, request_id)
            .await?;
        if matches.len() > 1 {
            return Err(SaError::ThresholdPolicyIdentificationFailed {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                observed_wasm_hashes_summary: summary,
                request_id: request_id.to_owned(),
            });
        }
        let identified = matches
            .into_iter()
            .next()
            .map(|matched| (matched.address, matched.contract_id));
        Ok((identified, summary))
    }

    /// Lists the policies among `policies` that identify as the
    /// simple-threshold policy, each with its contract id and its observed
    /// executable hash.
    ///
    /// Observes each distinct policy's executable through both endpoints
    /// ([`Self::observe_contract`], which refuses a divergence, a malformed
    /// instance or an external reference with no live tag entry). A policy
    /// matches when its effective hash is in [`THRESHOLD_POLICY_WASM_HASHES`];
    /// a policy with no code (an absent instance or a Stellar asset) is
    /// readable and never matches. The matches keep the order of `policies`
    /// and each distinct address appears once. The summary is the one a
    /// refusal carries: the number of attached policies and the first 8 bytes
    /// of the first observed effective hash.
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`] (phase `simulate`): a matching policy
    ///   address is not a contract address.
    /// - The errors of [`Self::observe_contract`].
    async fn allowlisted_threshold_policies(
        &self,
        policies: &[ScAddress],
        rule_id: u32,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<(Vec<ThresholdPolicyMatch>, WasmHashSummary), SaError> {
        let mut distinct: Vec<&ScAddress> = Vec::with_capacity(policies.len());
        for policy in policies {
            if !distinct.contains(&policy) {
                distinct.push(policy);
            }
        }

        let mut first_first8: Option<[u8; 8]> = None;
        let mut matches: Vec<ThresholdPolicyMatch> = Vec::new();
        for policy in distinct {
            let observation = self
                .observe_contract(
                    policy,
                    ContractKind::Policy,
                    |hash| THRESHOLD_POLICY_WASM_HASHES.contains(hash),
                    Some(rule_id),
                    smart_account_redacted,
                    request_id,
                )
                .await?;
            if first_first8.is_none()
                && let Some(hash) = observation.observed.effective_hash()
            {
                let mut first8 = [0u8; 8];
                first8.copy_from_slice(&hash[..8]);
                first_first8 = Some(first8);
            }
            if observation.allowlisted {
                let ScAddress::Contract(ContractId(Hash(policy_id))) = policy else {
                    return Err(SaError::DeploymentFailed {
                        phase: "simulate",
                        redacted_reason: "get_context_rule: the simple-threshold policy address \
                                          is not a contract address"
                            .to_owned(),
                    });
                };
                matches.push(ThresholdPolicyMatch {
                    address: policy.clone(),
                    contract_id: *policy_id,
                    executable_hash: observation.effective_hash,
                });
            }
        }

        let summary = WasmHashSummary {
            count: u32::try_from(policies.len()).unwrap_or(u32::MAX),
            first_first8,
        };
        Ok((matches, summary))
    }

    /// Refuses with [`SaError::NetworkRpcDivergence`] unless the two
    /// endpoints' rules agree on the id, the signers as version-2 identities
    /// and the policy list.
    fn require_same_rule(
        primary: &OnChainContextRule,
        secondary: &OnChainContextRule,
        rule_id: u32,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<(), SaError> {
        if primary.id == secondary.id
            && primary.identities() == secondary.identities()
            && primary.policies == secondary.policies
        {
            return Ok(());
        }
        Err(Self::signer_set_rpc_divergence(
            rule_id,
            smart_account_redacted,
            &primary.raw_scval,
            &secondary.raw_scval,
            request_id,
        ))
    }

    /// Builds the [`SaError::NetworkRpcDivergence`] of a signer-set
    /// observation whose endpoints disagree on the rule or the threshold.
    ///
    /// Each view digest is the first 8 bytes, as hex, of the SHA-256 of that
    /// endpoint's returned value's XDR: the `get_context_rule` value for a
    /// rule disagreement, the `get_threshold` value for a threshold
    /// disagreement.
    fn signer_set_rpc_divergence(
        rule_id: u32,
        smart_account_redacted: &str,
        primary: &ScVal,
        secondary: &ScVal,
        request_id: &str,
    ) -> SaError {
        SaError::NetworkRpcDivergence {
            rule_id: Some(rule_id),
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            primary_view_digest_first8: scval_digest_first8(primary),
            secondary_view_digest_first8: scval_digest_first8(secondary),
            request_id: request_id.to_owned(),
        }
    }

    /// Observes the rule after a signer mutation confirmed, under the
    /// `confirmation_recording` budget: the manager's timeout, measured from
    /// the confirmation.
    ///
    /// Every read must reach the confirmation ledger; see
    /// `observe_signer_set_v2`. Every failure, including the budget ending,
    /// returns [`SaError::BaselineWriteFailed`] at stage `observe` with the
    /// transaction hash. A budget that ends while a read is outstanding names
    /// the last read found behind the confirmation ledger, with its endpoint
    /// and ledger ([`BehindRead`]).
    async fn observe_confirmed(
        &self,
        smart_account: &ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
        submitted: &crate::submit::SubmitInvokeResult,
        smart_account_redacted: &str,
        request_id: &str,
    ) -> Result<ObservationV2, SaError> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let last_behind = std::sync::Mutex::new(None);
        let catch_up = CatchUp {
            floor: submitted.ledger,
            deadline,
            last_behind: &last_behind,
        };
        let observed = tokio::time::timeout_at(
            deadline,
            self.observe_signer_set_v2(
                smart_account,
                rule_id,
                source_account_strkey,
                Some(catch_up),
                request_id,
            ),
        )
        .await;
        let cause = match observed {
            Ok(Ok(observation)) => return Ok(observation),
            Ok(Err(cause)) => cause,
            Err(_elapsed) => {
                let budget_ms = self.timeout.as_millis();
                match last_behind.lock().ok().and_then(|last| *last) {
                    Some(behind) => behind.refusal(&format!(
                        "the confirmation_recording budget of {budget_ms} ms ended"
                    )),
                    None => SaError::DeploymentFailed {
                        phase: "simulate",
                        redacted_reason: format!(
                            "the confirmation_recording budget of {budget_ms} ms ended before \
                             the signer-set observation completed"
                        ),
                    },
                }
            }
        };
        Err(observe_failed_after(
            rule_id,
            smart_account_redacted,
            &submitted.tx_hash,
            &cause,
            request_id,
        ))
    }

    /// Requires the state observed after a confirmed signer mutation to be
    /// `intended`, compared by their version-2 digests, and returns the
    /// observed snapshot.
    ///
    /// Otherwise refuses through [`Self::unintended_state`]. An intended
    /// state that is not a valid snapshot never matches.
    fn require_intended_state(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        intended: SignerSetSnapshotV2,
        observation: ObservationV2,
        tx_hash: &str,
        request_id: &str,
    ) -> Result<SignerSetSnapshotV2, SaError> {
        let intended_digest = compute_signer_set_digest_v2(&intended).ok();
        let observed_digest = compute_signer_set_digest_v2(&observation.snapshot).ok();
        if intended_digest.is_some() && intended_digest == observed_digest {
            return Ok(observation.snapshot);
        }
        Err(self.unintended_state(
            rule_id,
            smart_account_redacted,
            intended,
            observation.snapshot,
            tx_hash,
            request_id,
        ))
    }

    /// Writes the `SaSignerSetDiverged` row of a confirmed signer mutation
    /// whose observed state is not the intended one, and returns the
    /// [`SaError::SignerSetDiverged`] carrying the transaction hash.
    fn unintended_state(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        intended: SignerSetSnapshotV2,
        observed: SignerSetSnapshotV2,
        tx_hash: &str,
        request_id: &str,
    ) -> SaError {
        let expected = SignerSetView::V2(intended);
        let observed = SignerSetView::V2(observed);
        self.emit_signer_set_diverged(
            rule_id,
            smart_account_redacted,
            &expected,
            &observed,
            request_id,
        );
        SaError::SignerSetDiverged {
            rule_id,
            expected,
            observed,
            tx_hash: Some(tx_hash.to_owned()),
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            request_id: request_id.to_owned(),
        }
    }

    /// Writes a `SaSignerSetBaselinedV2` row recording `observation` as the
    /// rule's baseline.
    ///
    /// Called only from `list_signers` (first observation),
    /// `refresh_signer_baseline` (explicit re-anchor) and
    /// `baseline_confirmed_install` (a confirmed install); a CI gate enforces
    /// these three callers and that this function is the only builder of the
    /// row. The row carries the observation's ledger and the account digest
    /// of this manager's network and `smart_account_strkey`.
    /// `prev_chain_tip_hash` is read from `AuditWriter::current_chain_tip()`
    /// inside the write critical section, so it names the row's predecessor.
    /// `tx_hash` is the confirmed install's transaction, which a refused
    /// write carries; the other two callers submit nothing and pass `None`.
    ///
    /// # Errors
    ///
    /// [`SaError::BaselineWriteFailed`] at stage `write`, carrying `tx_hash`,
    /// when the row is not written.
    #[allow(
        clippy::too_many_arguments,
        reason = "the observation, the account identity, the reason, the confirmed transaction \
                  and the correlation id"
    )]
    fn emit_baseline(
        &self,
        observation: &ObservationV2,
        rule_id: u32,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        baseline_reason: BaselineReason,
        tx_hash: Option<&str>,
        request_id: &str,
    ) -> Result<(), SaError> {
        let account = account_digest(&self.network_passphrase, smart_account_strkey);
        let now_ms = now_unix_ms().unwrap_or(0);
        self.write_state_row(|writer| {
            AuditEntry::new_sa_signer_set_baselined_v2(
                rule_id,
                &observation.snapshot,
                observation.ledger,
                now_ms,
                baseline_reason,
                writer.current_chain_tip(),
                account,
                RedactedStrkey::from_already_redacted(smart_account_redacted),
                self.chain_id.as_str(),
                request_id,
            )
        })
        .map_err(|e| {
            warn!(
                target: "stellar_agent::audit",
                rule_id,
                smart_account_redacted = %smart_account_redacted,
                tx_hash = tx_hash.unwrap_or("none"),
                error = %e,
                request_id = %request_id,
                "SaSignerSetBaselinedV2 row not written"
            );
            SaError::BaselineWriteFailed {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                tx_hash: tx_hash.map(ToOwned::to_owned),
                stage: BASELINE_WRITE_STAGE_WRITE,
                reason: baseline_write_reason(&e.to_string()),
                request_id: request_id.to_owned(),
            }
        })
    }

    /// Writes a `SaSignerSetDiverged` row comparing `expected` with
    /// `observed`, two views of one snapshot version.
    ///
    /// A row that is not written is a warning: the refusal that follows
    /// carries the same two views.
    fn emit_signer_set_diverged(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        expected: &SignerSetView,
        observed: &SignerSetView,
        request_id: &str,
    ) {
        let written = self.write_state_row(|_| {
            AuditEntry::new_sa_signer_set_diverged(
                rule_id,
                RedactedStrkey::from_already_redacted(smart_account_redacted),
                expected,
                observed,
                self.chain_id.as_str(),
                request_id,
            )
        });
        if let Err(e) = written {
            warn!(
                target: "stellar_agent::audit",
                rule_id,
                smart_account_redacted = %smart_account_redacted,
                expected = %expected,
                observed = %observed,
                chain_id = %self.chain_id,
                request_id = %request_id,
                error = %e,
                "SaSignerSetDiverged row not written"
            );
        }
    }

    /// Writes one audit row built by `build` inside the writer's critical
    /// section.
    ///
    /// `build` receives the locked writer, so a row that anchors the chain
    /// tip reads it inside the same critical section as the write. A
    /// poisoned writer lock marks the manager's audit writer degraded and
    /// returns [`BaselineWriteError::Poisoned`]; a failed write returns
    /// [`BaselineWriteError::Write`]. Nothing is written in either case.
    fn write_state_row(
        &self,
        build: impl FnOnce(&AuditWriter) -> AuditEntry,
    ) -> Result<(), BaselineWriteError> {
        let Ok(mut writer) = self.audit_writer.lock() else {
            self.mark_audit_writer_degraded();
            return Err(BaselineWriteError::Poisoned);
        };
        let entry = build(&writer);
        writer.write_entry(entry).map_err(BaselineWriteError::Write)
    }

    /// Writes the state row recording a confirmed signer mutation.
    ///
    /// # Errors
    ///
    /// [`SaError::BaselineWriteFailed`] at stage `write` with the transaction
    /// hash when the row is not written.
    fn write_confirmed_state_row(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        tx_hash: &str,
        request_id: &str,
        build: impl FnOnce(&AuditWriter) -> AuditEntry,
    ) -> Result<(), SaError> {
        self.write_state_row(build).map_err(|e| {
            warn!(
                target: "stellar_agent::audit",
                rule_id,
                smart_account_redacted = %smart_account_redacted,
                tx_hash,
                error = %e,
                request_id = %request_id,
                "signer-set state row of a confirmed transaction not written"
            );
            SaError::BaselineWriteFailed {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                tx_hash: Some(tx_hash.to_owned()),
                stage: BASELINE_WRITE_STAGE_WRITE,
                reason: baseline_write_reason(&e.to_string()),
                request_id: request_id.to_owned(),
            }
        })
    }

    /// Records a confirmed signer add, then writes its pin rows.
    ///
    /// A validated outcome writes one `SaSignerAddedV2` row per added id, in
    /// order, each carrying the resulting set. The planned pin rows are then
    /// written exactly once whatever the outcome, because the confirmed add
    /// put its verifiers on the rule:
    ///
    /// - on success they follow the state rows;
    /// - when the confirmed state is not observed or not the intended
    ///   change, they are written before the refusal returns;
    /// - when a state row is not written, they are attempted, and the audit
    ///   log usually refuses them as well.
    ///
    /// Returns the added ids, or the refusal of the outcome or of a state
    /// row write.
    fn record_confirmed_add<Ids: AsRef<[u32]>>(
        &self,
        verb: &str,
        rule_id: u32,
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        confirmed: ConfirmedSignerAdd<Ids>,
        request_id: &str,
    ) -> Result<Ids, SaError> {
        let account = account_digest(&self.network_passphrase, smart_account_strkey);
        let recorded = confirmed
            .outcome
            .inspect_err(|err| warn_failed(verb, rule_id, smart_account_redacted, err))
            .and_then(|(added_ids, mutation)| {
                for signer_id in added_ids.as_ref() {
                    self.write_confirmed_state_row(
                        rule_id,
                        smart_account_redacted,
                        &mutation.tx_hash,
                        request_id,
                        |_| {
                            AuditEntry::new_sa_signer_added_v2(
                                rule_id,
                                *signer_id,
                                &mutation.resulting,
                                account,
                                RedactedStrkey::from_already_redacted(smart_account_redacted),
                                self.chain_id.as_str(),
                                request_id,
                            )
                        },
                    )?;
                }
                Ok(added_ids)
            });
        self.write_pin_rows(
            rule_id,
            smart_account_redacted,
            confirmed.pin_update,
            PinsUpdateReason::SignerAdded,
            request_id,
        );
        recorded
    }

    /// Writes the pin rows a wallet mutation of rule `rule_id` planned: the
    /// pending override rows, then the `SaContextRulePinsUpdated` row with
    /// `reason`. Writes nothing when the mutation planned no pin update.
    ///
    /// Every caller holds the rule's lock, from the read of the record it
    /// planned from through this write, so no other wallet verb on the rule
    /// writes a pin row in between.
    fn write_pin_rows(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        pin_update: Option<PlannedPinUpdate>,
        reason: PinsUpdateReason,
        request_id: &str,
    ) {
        let Some(update) = pin_update else {
            return;
        };
        crate::managers::verifiers::write_pending_override_rows(
            self,
            smart_account_redacted,
            rule_id,
            request_id,
            &update.pending_overrides,
        );
        crate::managers::verifiers::write_pins_updated_row(
            self,
            smart_account_redacted,
            rule_id,
            reason,
            &update.record,
            request_id,
        );
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

    /// Reads a context rule's signers directly from the on-chain
    /// `ContextRule` through the primary RPC, as version-2 entries in the
    /// rule's order: each signer id with its full identity.
    ///
    /// Policy-independent: no policy is identified and no threshold is read,
    /// so this works on a rule with no policy at all (for example right after
    /// `deploy_smart_account`) or with a weighted-threshold policy. A signer
    /// delegated to a contract address reads as
    /// [`SignerIdentityV2::DelegatedContract`].
    ///
    /// # Errors
    ///
    /// - [`SaError::DeploymentFailed`]: simulation or decode failure (the
    ///   rule does not exist, the `ContextRule` ScVal is malformed, or a
    ///   signer does not decode).
    pub async fn get_rule_signers(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        source_account_strkey: Option<&str>,
    ) -> Result<Vec<SignerEntryV2>, SaError> {
        let rule = self
            .fetch_context_rule_primary(smart_account, rule_id, source_account_strkey)
            .await?;
        Ok(rule
            .signers
            .iter()
            .map(|(id, signer)| SignerEntryV2 {
                id: *id,
                identity: signer.to_identity_v2(),
            })
            .collect())
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
    /// Returns an error when the add is refused or fails before it confirms.
    /// Once it confirms, returns the outcome of the steps after confirmation
    /// ([`Self::validate_confirmed_add`]) with the pin update planned before
    /// submission.
    #[allow(clippy::too_many_arguments, reason = "irreducible inner arg set")]
    async fn add_signer_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        guards: &[RuleLockGuard],
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        new_signer: ScVal,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
        overrides: PinOverrides,
    ) -> Result<ConfirmedSignerAdd<[u32; 1]>, SaError> {
        let source_pubkey_strkey = signer_source_strkey(signer).await?;

        let added = decode_signer_scval_full(&new_signer).map_err(|e| {
            SaError::AuthEntryConstructionFailed {
                stage: "auth_contexts_args",
                redacted_reason: format!(
                    "add_signer: the new signer is not a recognised Signer: {e}"
                ),
            }
        })?;
        let identity = added.to_identity_v2();

        let compared = [self
            .verify_signer_set_locked(
                held_guard(guards, smart_account_strkey, rule_id)?,
                V1Handling::RefuseLegacy,
                Some(&source_pubkey_strkey),
                request_id,
            )
            .await?];
        let before = compared[0].snapshot();

        let current_signer_count = before.signer_count();
        let post_op_signer_count = current_signer_count.saturating_add(1);

        // Cap check (MAX_SIGNERS = 15 per OZ `mod.rs:526`).
        if post_op_signer_count > MAX_SIGNERS {
            return Err(SaError::ContextRuleCapsExceeded {
                kind: "signers",
                cur: current_signer_count,
                max: MAX_SIGNERS,
            });
        }

        // Adding a signer raises the count, so the invariant only fails for
        // a threshold already above the count (a corrupted on-chain state). A
        // rule without a simple-threshold policy has no threshold to check.
        if let Some(threshold) = &before.threshold {
            compute_post_op_invariant(
                rule_id,
                post_op_signer_count,
                threshold.threshold,
                threshold.threshold,
                ThresholdAffectingOp::AddSigner {
                    signer_type: identity_kind_label(&identity).to_owned(),
                    signer_id: None,
                },
                smart_account_redacted,
                request_id,
            )?;
        }

        let pin_update = self
            .plan_signer_add_pin_update(
                rule_id,
                smart_account_redacted,
                before,
                &external_verifiers(std::iter::once(&added)),
                overrides,
                request_id,
            )
            .await?;

        // Single-op: add_signer.
        // `add_signer` calls `e.current_contract_address().require_auth()`;
        // auth entry is credentialed for the smart account (= contract).
        let auth_rule_ids = vec![ContextRuleId::from(rule_id)];
        let add_signer_args = vec![ScVal::U32(rule_id), new_signer];

        let submitted = self
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
                request_id,
                &borrowed(guards, &compared),
                // The add reads the assigned signer id from the return value.
                Some(ExpectedReturn::U32),
            )
            .await?;

        let outcome = self
            .validate_confirmed_add(
                &smart_account,
                rule_id,
                smart_account_redacted,
                &source_pubkey_strkey,
                before,
                identity,
                submitted,
                request_id,
            )
            .await
            .map(|(signer_id, mutation)| ([signer_id], mutation));
        Ok(ConfirmedSignerAdd {
            outcome,
            pin_update,
        })
    }

    /// Observes the rule after a confirmed `add_signer` and requires exactly
    /// the intended change: `before` with `identity` added under the id the
    /// simulation returned, every other signer and the threshold unchanged.
    ///
    /// # Errors
    ///
    /// - [`SaError::BaselineWriteFailed`] at stage `observe`: the simulated
    ///   id or the confirmed state was not observed.
    /// - [`SaError::SignerSetDiverged`] with the transaction hash: the
    ///   confirmed state is not the intended change, or the chain assigned
    ///   the new signer another id.
    #[allow(
        clippy::too_many_arguments,
        reason = "rule identity, the pre-submission state, the added identity and the \
                  confirmed transaction"
    )]
    async fn validate_confirmed_add(
        &self,
        smart_account: &ScAddress,
        rule_id: u32,
        smart_account_redacted: &str,
        source_pubkey_strkey: &str,
        before: &SignerSetSnapshotV2,
        identity: SignerIdentityV2,
        submitted: crate::submit::SubmitInvokeResult,
        request_id: &str,
    ) -> Result<(u32, ConfirmedMutation), SaError> {
        let simulated_id =
            extract_u32_return(&submitted.return_val, "add_signer").map_err(|e| {
                observe_failed_after(
                    rule_id,
                    smart_account_redacted,
                    &submitted.tx_hash,
                    &e,
                    request_id,
                )
            })?;
        let observation = self
            .observe_confirmed(
                smart_account,
                rule_id,
                Some(source_pubkey_strkey),
                &submitted,
                smart_account_redacted,
                request_id,
            )
            .await?;

        // The observed set is authoritative: the new signer takes the id it
        // holds on chain, and every other signer and the threshold must be
        // unchanged.
        let observed_id = new_entry_id(before, &observation.snapshot, &identity, &[]);
        let intended = with_added_signers(
            before,
            [(observed_id.unwrap_or(simulated_id), identity.clone())],
        );
        let resulting = self.require_intended_state(
            rule_id,
            smart_account_redacted,
            intended,
            observation,
            &submitted.tx_hash,
            request_id,
        )?;

        // The id the simulation returned, which the caller reports, must be
        // the id the chain assigned.
        if observed_id != Some(simulated_id) {
            return Err(self.unintended_state(
                rule_id,
                smart_account_redacted,
                with_added_signers(before, [(simulated_id, identity)]),
                resulting,
                &submitted.tx_hash,
                request_id,
            ));
        }

        Ok((
            simulated_id,
            ConfirmedMutation {
                resulting,
                tx_hash: submitted.tx_hash,
            },
        ))
    }

    /// Computes the pin record a signer add writes for rule `rule_id` once
    /// the add confirms; see "Pin record" on [`Self::add_signer`].
    ///
    /// `new_verifiers` holds the distinct verifier addresses of the added
    /// `External` signers, decoded from the signers being added. `live` is
    /// the rule's signer set as the pre-submission comparison observed it
    /// through both endpoints. Returns `None` when `new_verifiers` is empty
    /// or the rule has no pin record. Otherwise each new verifier address
    /// that no `External` signer of `live` uses is identified and probed
    /// here, before submission, with the overrides applied to it pending. A
    /// probed pin equal to a recorded verifier pin, in hash and executable
    /// reference, adds no pin. The signing check compares the verifier with
    /// that pin and accepts it, and only the overrides applied to it are
    /// recorded. Every other probed pin is appended to the record. A refusal
    /// of any new verifier refuses the add, and no override row is written
    /// for it.
    ///
    /// # Errors
    ///
    /// - [`SaError::AuditLog`]: the pin record could not be read.
    /// - The refusals of `pin_added_contract` for a new verifier.
    async fn plan_signer_add_pin_update(
        &self,
        rule_id: u32,
        smart_account_redacted: &str,
        live: &SignerSetSnapshotV2,
        new_verifiers: &[ScAddress],
        overrides: PinOverrides,
        request_id: &str,
    ) -> Result<Option<PlannedPinUpdate>, SaError> {
        if new_verifiers.is_empty() {
            return Ok(None);
        }
        let Some(record) = crate::managers::verifiers::read_pinned_hashes_for_rule(
            self,
            rule_id,
            smart_account_redacted,
        )?
        else {
            debug!(
                rule_id,
                "signer add: the rule has no pin record; no pin update is written"
            );
            return Ok(None);
        };

        let live_verifiers: Vec<[u8; 32]> = live
            .signers
            .iter()
            .filter_map(|entry| match &entry.identity {
                SignerIdentityV2::External { verifier, .. } => Some(*verifier),
                _ => None,
            })
            .collect();

        let mut update = PlannedPinUpdate::unchanged(record);
        for verifier in new_verifiers {
            // A decoded `External` verifier is always a contract address.
            if live_verifiers.contains(&contract_address_bytes(verifier)) {
                continue;
            }
            let pin = crate::managers::verifiers::pin_added_contract(
                self,
                verifier,
                PinnedKind::Verifier,
                rule_id,
                smart_account_redacted,
                overrides.accept_mutable_verifier,
                overrides.accept_unknown_verifier,
                request_id,
            )
            .await?;
            let recorded = update.record.pinned_verifier_first8.iter().enumerate().any(
                |(position, first8)| {
                    *first8 == pin.hash_first8
                        && update.record.verifier_executable_ref(position)
                            == pin.executable_ref.as_ref()
                },
            );
            if recorded {
                update.fold_overrides(
                    pin.mutable_override,
                    pin.unknown_override,
                    pin.pending_overrides,
                );
            } else {
                update.append_pin(PinnedKind::Verifier, pin);
            }
        }
        Ok(Some(update))
    }

    /// Core logic for `remove_signer` (called inside the per-rule mutex).
    #[allow(clippy::too_many_arguments, reason = "irreducible inner arg set")]
    async fn remove_signer_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        guards: &[RuleLockGuard],
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        signer_id: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<ConfirmedMutation, SaError> {
        let source_pubkey_strkey = signer_source_strkey(signer).await?;

        let compared = [self
            .verify_signer_set_locked(
                held_guard(guards, smart_account_strkey, rule_id)?,
                V1Handling::RefuseLegacy,
                Some(&source_pubkey_strkey),
                request_id,
            )
            .await?];
        check_remove_preconditions(&compared[0], signer_id, smart_account_redacted, request_id)?;
        let before = compared[0].snapshot();

        // Single-op: remove_signer.
        // `remove_signer` calls `e.current_contract_address().require_auth()`.
        let auth_rule_ids = vec![ContextRuleId::from(rule_id)];
        let remove_signer_args = vec![ScVal::U32(rule_id), ScVal::U32(signer_id)];

        let submitted = self
            .submit_single_op(
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
                request_id,
                &borrowed(guards, &compared),
                None,
            )
            .await?;

        let observation = self
            .observe_confirmed(
                &smart_account,
                rule_id,
                Some(&source_pubkey_strkey),
                &submitted,
                smart_account_redacted,
                request_id,
            )
            .await?;
        let intended = without_signer(before, signer_id);
        let resulting = self.require_intended_state(
            rule_id,
            smart_account_redacted,
            intended,
            observation,
            &submitted.tx_hash,
            request_id,
        )?;

        Ok(ConfirmedMutation {
            resulting,
            tx_hash: submitted.tx_hash,
        })
    }

    /// Core logic for `set_threshold` (called inside the per-rule mutex).
    ///
    /// Returns the threshold observation before the change and the confirmed,
    /// validated mutation.
    #[allow(clippy::too_many_arguments, reason = "irreducible inner arg set")]
    async fn set_threshold_locked_inner(
        &self,
        smart_account: ScAddress,
        rule_id: u32,
        guards: &[RuleLockGuard],
        smart_account_strkey: &str,
        smart_account_redacted: &str,
        new_threshold: u32,
        signer: &(dyn Signer + Send + Sync),
        request_id: &str,
    ) -> Result<(ThresholdObservation, ConfirmedMutation), SaError> {
        let source_pubkey_strkey = signer_source_strkey(signer).await?;

        let compared = [self
            .verify_signer_set_locked(
                held_guard(guards, smart_account_strkey, rule_id)?,
                V1Handling::RefuseLegacy,
                Some(&source_pubkey_strkey),
                request_id,
            )
            .await?];
        let before = compared[0].snapshot();

        let Some(previous) = before.threshold.clone() else {
            return Err(SaError::ThresholdPolicyNotInstalled {
                rule_id,
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                request_id: request_id.to_owned(),
            });
        };

        // Threshold invariant: 1 <= new_threshold <= signer_count.
        compute_post_op_invariant(
            rule_id,
            before.signer_count(),
            previous.threshold,
            new_threshold,
            ThresholdAffectingOp::SetThreshold { new: new_threshold },
            smart_account_redacted,
            request_id,
        )?;

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
        // `target_args` = [threshold: u32, context_rule: ContextRule, smart_account: Address]
        // (Env is implicit in Soroban contractimpl; not encoded in the Vec<Val>).
        // The context rule is the verbatim value of the primary read the
        // comparison covered, so the policy receives the rule the wallet
        // checked.
        let target_args_vec: VecM<ScVal> = vec![
            ScVal::U32(new_threshold),
            compared[0].primary_rule().clone(),
            ScVal::Address(smart_account.clone()),
        ]
        .try_into()
        .map_err(|e| SaError::AuthEntryConstructionFailed {
            stage: "auth_contexts_args",
            redacted_reason: format!("encode set_threshold target_args VecM: {e:?}"),
        })?;
        let execute_args = vec![
            ScVal::Address(ScAddress::Contract(ContractId(Hash(previous.policy)))),
            ScVal::Symbol(set_threshold_sym),
            ScVal::Vec(Some(ScVec(target_args_vec))),
        ];

        // Both contract and auth_address are the smart account; `execute()` calls
        // `e.current_contract_address().require_auth()`.
        let policy_auth_rule_ids = vec![ContextRuleId::from(rule_id)];
        let submitted = self
            .submit_single_op(
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
                request_id,
                &borrowed(guards, &compared),
                None,
            )
            .await?;

        let observation = self
            .observe_confirmed(
                &smart_account,
                rule_id,
                Some(&source_pubkey_strkey),
                &submitted,
                smart_account_redacted,
                request_id,
            )
            .await?;
        let intended = SignerSetSnapshotV2 {
            signers: before.signers.clone(),
            threshold: Some(ThresholdObservation {
                policy: previous.policy,
                threshold: new_threshold,
            }),
        };
        let resulting = self.require_intended_state(
            rule_id,
            smart_account_redacted,
            intended,
            observation,
            &submitted.tx_hash,
            request_id,
        )?;

        Ok((
            previous,
            ConfirmedMutation {
                resulting,
                tx_hash: submitted.tx_hash,
            },
        ))
    }

    /// Submits a single `InvokeHostFunction` op transaction and returns the
    /// confirmed result: the simulated return value, the transaction hash
    /// and the confirmation ledger.
    ///
    /// `rule_locks` is the verb's held-lock context: the target's guard and
    /// the verb's comparison of it, so the submit path compares nothing
    /// again for the target and acquires no lock.
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
        request_id: &str,
        rule_locks: &BorrowedRuleLocks<'_>,
        expected_return: Option<ExpectedReturn>,
    ) -> Result<crate::submit::SubmitInvokeResult, SaError> {
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
            request_id,
            None,
            Some(rule_locks),
            expected_return,
        )
        .await
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
    /// Every call runs the pinned-hash drift check through this manager
    /// ([`crate::submit::PinCheck`]) with `request_id`; `migrating_rule`
    /// names the rule whose verifier check is skipped, and only
    /// [`Self::submit_migration_step`] sets it. `rule_locks` is the caller's
    /// held-lock context, `None` when the caller holds no lock and the
    /// submit path acquires the locks of the rules it checks.
    /// `expected_return` is the shape a caller that reads an id from the
    /// return value requires of the simulated result before signing
    /// ([`ExpectedReturn`]).
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
        request_id: &str,
        migrating_rule: Option<crate::submit::MigratingRule>,
        rule_locks: Option<&BorrowedRuleLocks<'_>>,
        expected_return: Option<ExpectedReturn>,
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
                .pin_check(crate::submit::PinCheck {
                    signers_manager: self,
                    request_id,
                    migrating_rule,
                })
                .maybe_rule_locks(rule_locks)
                .maybe_expected_return(expected_return)
                .build(),
        )
        .await
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

/// The overrides `rules create` takes, applied to a verifier or policy a
/// wallet mutation pins for an existing rule.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PinOverrides {
    /// Admit a mutable contract, recording a mutable-contract override.
    pub(crate) accept_mutable_verifier: bool,
    /// Admit a contract whose hash is outside the allowlist, recording an
    /// unknown-contract override.
    pub(crate) accept_unknown_verifier: bool,
}

/// A policy of an on-chain `ContextRule`, with the number of policies the
/// rule holds.
struct RulePolicy {
    /// The policy's address.
    address: ScAddress,
    /// The number of policies the rule holds.
    rule_policy_count: usize,
}

/// Returns the policy with on-chain id `policy_id` in a `ContextRule`
/// value: the `policies` entry at the position `policy_id` holds in the
/// aligned `policy_ids` list, and the length of `policies`. `None` when the
/// value is not a rule map or holds no such id.
fn rule_policy_for_id(rule: &ScVal, policy_id: u32) -> Option<RulePolicy> {
    let ScVal::Map(Some(map)) = rule else {
        return None;
    };
    let field = |name: &[u8]| {
        map.iter().find_map(|entry| match (&entry.key, &entry.val) {
            (ScVal::Symbol(symbol), ScVal::Vec(Some(values))) if symbol.as_slice() == name => {
                Some(values)
            }
            _ => None,
        })
    };
    let position = field(b"policy_ids")?
        .iter()
        .position(|id| *id == ScVal::U32(policy_id))?;
    let policies = field(b"policies")?;
    match policies.get(position)? {
        ScVal::Address(address) => Some(RulePolicy {
            address: address.clone(),
            rule_policy_count: policies.len(),
        }),
        _ => None,
    }
}

/// The refusal of a policy removal naming a policy id the rule does not
/// hold.
fn policy_not_attached(rule_id: u32, policy_id: u32) -> SaError {
    SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!(
            "remove_policy: policy {policy_id} is not attached to rule {rule_id}"
        ),
    }
}

/// An attached policy that identifies as the simple-threshold policy.
struct ThresholdPolicyMatch {
    /// The policy's address.
    address: ScAddress,
    /// The policy's contract id.
    contract_id: [u8; 32],
    /// The policy's effective executable hash, as both endpoints observed it.
    executable_hash: [u8; 32],
}

// ── Signer-set observation and comparison ─────────────────────────────────────

/// The pause before an endpoint behind the confirmation ledger is read again.
const CONFIRMATION_CATCH_UP_PAUSE: Duration = Duration::from_secs(1);

/// The ledger floor of an observation after a confirmed transaction, and the
/// end of its `confirmation_recording` budget.
#[derive(Clone, Copy, Debug)]
struct CatchUp<'a> {
    /// The confirmation ledger every read must reach.
    floor: u32,
    /// When the budget ends.
    deadline: tokio::time::Instant,
    /// The last read found behind `floor`, which the refusal at the end of
    /// the budget names.
    last_behind: &'a std::sync::Mutex<Option<BehindRead>>,
}

/// A read that reported a `latestLedger` below the confirmation ledger.
///
/// `Display` renders it as history: `{read} ({endpoint}) was last seen at
/// latestLedger {N}, below the confirmation ledger {F}`. The endpoint may
/// have caught up since.
#[derive(Clone, Copy, Debug)]
struct BehindRead {
    /// The simulated function.
    read: &'static str,
    /// The endpoint, `primary` or `secondary`.
    source_kind: &'static str,
    /// The `latestLedger` the read reported.
    latest_ledger: u32,
    /// The confirmation ledger the read had to reach.
    floor: u32,
}

impl BehindRead {
    /// The refusal of an observation stopped by its budget with this read the
    /// last one behind; `budget` states how the budget stopped it. The read
    /// comes first so the reason cap never removes it.
    fn refusal(self, budget: &str) -> SaError {
        SaError::DeploymentFailed {
            phase: "simulate",
            redacted_reason: format!("{self}; {budget}"),
        }
    }
}

impl std::fmt::Display for BehindRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) was last seen at latestLedger {}, below the confirmation ledger {}",
            self.read, self.source_kind, self.latest_ledger, self.floor
        )
    }
}

/// One endpoint's reads of a rule.
struct EndpointRead {
    /// The decoded rule, with its verbatim value.
    rule: OnChainContextRule,
    /// The smallest `latestLedger` the endpoint's reads reported.
    ledger: u32,
    /// The simple-threshold value, when the rule has a simple-threshold
    /// policy.
    threshold: Option<u32>,
}

/// A rule's signer set observed in version 2 through both RPC endpoints,
/// with the reads a version-1 comparison and the signer verbs need.
struct ObservationV2 {
    /// The observed rule's id, as requested.
    rule_id: u32,
    /// The smart account, redacted first-5-last-5.
    smart_account_redacted: String,
    /// The correlation id of the call that observed.
    request_id: String,
    /// The validated snapshot, signers in ascending id order.
    snapshot: SignerSetSnapshotV2,
    /// The rule's attached policies, in the rule's order.
    policies: Vec<ScAddress>,
    /// The number of attached policies and the first 8 bytes of the first
    /// observed effective hash, for a threshold-policy refusal.
    policy_hashes: WasmHashSummary,
    /// The smallest `latestLedger` across the reads the observation kept.
    ledger: u32,
    /// The primary's verbatim `get_context_rule` value.
    primary_rule: ScVal,
    /// The version-1 projection of the primary's signers in the rule's
    /// order, or the index, id and reason of the first signer without one.
    v1_signers: Result<Vec<(u32, SignerPubkey)>, (usize, u32, SignerDecodeError)>,
}

/// How a comparison treats a version-1 state row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum V1Handling {
    /// Compare through the observation's version-1 projection.
    Compare,
    /// Refuse with [`SaError::SignerSetBaselineLegacy`] before any RPC.
    RefuseLegacy,
}

/// A rule's newest signer-set state row, read under the rule's lock by
/// [`SignersManager::read_baseline_locked`] for one comparison.
pub(crate) struct BaselineRead {
    payload: SignerSetViewPayload,
    rule_id: u32,
}

/// The result of a comparison that matched: the observed view in the row's
/// version, the matched row's hash and the observation. Produced only by
/// [`SignersManager::compare_locked`].
pub(crate) struct ComparedState {
    view: SignerSetView,
    row_hash: [u8; 32],
    observation: ObservationV2,
}

impl ComparedState {
    /// The compared rule.
    pub(crate) fn rule_id(&self) -> u32 {
        self.observation.rule_id
    }

    /// The observation in the matched row's version.
    pub(crate) fn view(&self) -> &SignerSetView {
        &self.view
    }

    /// The hash of the matched state row.
    pub(crate) fn row_hash(&self) -> &[u8; 32] {
        &self.row_hash
    }

    /// The version-2 snapshot the observation built.
    pub(crate) fn snapshot(&self) -> &SignerSetSnapshotV2 {
        &self.observation.snapshot
    }

    /// The rule's attached policies, in the rule's order.
    pub(crate) fn policies(&self) -> &[ScAddress] {
        &self.observation.policies
    }

    /// The policy count and first observed executable hash, for a
    /// threshold-policy refusal.
    pub(crate) fn policy_hashes(&self) -> &WasmHashSummary {
        &self.observation.policy_hashes
    }

    /// The smallest `latestLedger` across the reads the observation kept.
    pub(crate) fn ledger(&self) -> u32 {
        self.observation.ledger
    }

    /// The primary endpoint's verbatim `get_context_rule` value.
    pub(crate) fn primary_rule(&self) -> &ScVal {
        &self.observation.primary_rule
    }
}

/// How an observation compares with a state row, in the row's version.
enum Classified {
    /// The observation matches the row.
    Matched {
        /// The observation in the row's version.
        observed: SignerSetView,
    },
    /// The observation differs from the row.
    Diverged {
        /// The observation in the row's version.
        observed: SignerSetView,
    },
    /// The row is version 1 and the observation has no version-1
    /// projection.
    NotComparable {
        /// Why the projection failed.
        cause: SaError,
    },
}

/// A signer mutation that confirmed and whose resulting state was observed
/// and validated.
struct ConfirmedMutation {
    /// The validated resulting snapshot.
    resulting: SignerSetSnapshotV2,
    /// The confirmed transaction's hash.
    tx_hash: String,
}

/// The verifier reconciliation a refresh plans for a rule's pin record.
enum RefreshPinPlan {
    /// The record stays as it is, or the rule has none.
    Unchanged,
    /// The record pinned no verifier while `External` signers are live: the
    /// update pins the live verifier.
    PinLiveVerifier(PlannedPinUpdate),
    /// The record pins one verifier while no `External` signer is live: the
    /// update drops the pin.
    DropDeadPin(PlannedPinUpdate),
}

/// A migration pair that completed: both transactions confirmed and both
/// state rows were written.
pub(crate) struct MigratedPair {
    /// The confirmed removal's transaction hash.
    pub(crate) remove_tx_hash: String,
    /// The confirmed add's transaction hash.
    pub(crate) add_tx_hash: String,
    /// The id the chain assigned to the restored signer.
    pub(crate) new_signer_id: u32,
}

/// A migration pair that stopped: the refusal or failure, and the add that
/// completes the pair once its removal was sent.
pub(crate) struct PairFailure {
    /// The error the pair stopped on, as the step raised it.
    pub(crate) error: SaError,
    /// The add that completes the pair; `None` when the removal was not
    /// sent or the add confirmed. See "Pending add" on
    /// [`SignersManager::migrate_signer_pair`].
    pub(crate) pending_add: Option<PendingAddStep>,
}

/// A signer add whose transaction confirmed: the outcome of the steps after
/// confirmation, and the pin update planned before submission.
///
/// The confirmed add put its verifiers on the rule whatever `outcome` is, so
/// `SignersManager::record_confirmed_add` writes `pin_update` in either case.
struct ConfirmedSignerAdd<Ids> {
    /// The ids the chain assigned and the validated mutation, or the
    /// refusal of an observation or validation after confirmation.
    outcome: Result<(Ids, ConfirmedMutation), SaError>,
    /// The pin rows to write for the confirmed add.
    pin_update: Option<PlannedPinUpdate>,
}

/// A policy attach or removal whose transaction confirmed.
///
/// A confirmed policy change is a fact on chain, so what the entry read from
/// the confirmed return value sits beside the recording outcome. The entry
/// has written its pin rows, and the caller writes its policy row from
/// `parsed` whatever `recorded` holds.
pub(crate) struct ConfirmedThresholdChange<T> {
    /// The confirmed submission.
    pub(crate) submitted: crate::submit::SubmitInvokeResult,
    /// What the entry read from `submitted.return_val`: the attach's policy
    /// id, `None` only when the return value is not a `u32`; nothing for a
    /// detach.
    pub(crate) parsed: T,
    /// The outcome of the observation, the validation and the threshold row
    /// after confirmation; `Ok(())` for a policy other than the
    /// simple-threshold policy.
    pub(crate) recorded: Result<(), SaError>,
}

/// Why an audit row was not written.
#[derive(Debug, thiserror::Error)]
enum BaselineWriteError {
    /// The audit-log writer lock is poisoned.
    #[error("the audit-log writer lock is poisoned")]
    Poisoned,
    /// The audit-log writer refused the row.
    #[error("audit-log write failed: {0}")]
    Write(WriterError),
}

/// How the observed signer set compared with the rule's audit-log state row
/// that existed before the call.
///
/// A version-1 row is compared through the version-1 projection of the
/// observation, which keeps the first 16 bytes of an `External` signer's key
/// data; a version-2 row with the full snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PreviousBaseline {
    /// No state row existed.
    None,
    /// The row's state matches the chain.
    Matched,
    /// The row's state differs from the chain.
    Diverged,
    /// The row is version 1 and the chain state has no version-1 projection:
    /// the rule holds a signer delegated to a contract address, or has no
    /// simple-threshold policy.
    NotComparable,
}

/// The result of [`SignersManager::list_signers`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListOutcome {
    /// The observed signer set, always version 2.
    pub view: SignerSetView,
    /// How the observation compared with the prior state row; `None` when
    /// this call wrote the first baseline.
    pub baseline: PreviousBaseline,
}

/// The result of [`SignersManager::refresh_signer_baseline`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshOutcome {
    /// The observed signer set the new baseline records, always version 2.
    pub view: SignerSetView,
    /// How the observation compared with the state row the refresh
    /// replaced.
    pub previous_baseline: PreviousBaseline,
    /// Whether the refresh pinned the live verifier of a pin record that
    /// pinned no verifier while the rule held `External` signers. A rule is
    /// pinned to one verifier, so the refresh adds at most one pin.
    pub verifier_pinned: bool,
}

/// The options of [`SignersManager::refresh_signer_baseline`].
///
/// `accept_divergence` records a chain state that differs from, or cannot be
/// compared with, the rule's state row. The two verifier overrides apply when
/// the refresh pins the live verifier of a rule whose pin record pins none.
/// The verifier is identified and probed as `rules create` probes one. A
/// mutable verifier, or one whose hash is outside the allowlist, is pinned
/// only with its override, which then records an override row.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RefreshOptions {
    accept_divergence: bool,
    accept_mutable_verifier: bool,
    accept_unknown_verifier: bool,
}

impl RefreshOptions {
    /// Options with `accept_divergence` and neither verifier override.
    #[must_use]
    pub fn new(accept_divergence: bool) -> Self {
        Self {
            accept_divergence,
            ..Self::default()
        }
    }

    /// These options with the mutable-verifier override set to `accept`.
    #[must_use]
    pub fn with_accept_mutable_verifier(self, accept: bool) -> Self {
        Self {
            accept_mutable_verifier: accept,
            ..self
        }
    }

    /// These options with the unknown-verifier override set to `accept`.
    #[must_use]
    pub fn with_accept_unknown_verifier(self, accept: bool) -> Self {
        Self {
            accept_unknown_verifier: accept,
            ..self
        }
    }

    /// Whether a chain state that differs from, or cannot be compared with,
    /// the rule's state row is recorded.
    #[must_use]
    pub fn accept_divergence(&self) -> bool {
        self.accept_divergence
    }

    /// Whether a mutable live verifier is pinned.
    #[must_use]
    pub fn accept_mutable_verifier(&self) -> bool {
        self.accept_mutable_verifier
    }

    /// Whether a live verifier whose hash is outside the allowlist is
    /// pinned.
    #[must_use]
    pub fn accept_unknown_verifier(&self) -> bool {
        self.accept_unknown_verifier
    }
}

/// Projects an observation to the version-1 view a version-1 row compares
/// with: the signers truncated as version 1 records them, in the rule's
/// order, and the simple-threshold value.
///
/// # Errors
///
/// - [`SaError::DeploymentFailed`] (phase `simulate`) naming the index and id
///   of the first signer without a version-1 form (a signer delegated to a
///   contract address).
/// - [`SaError::ThresholdPolicyNotInstalled`]: no threshold and no attached
///   policy.
/// - [`SaError::ThresholdPolicyIdentificationFailed`]: no threshold, with
///   attached policies none of which is a simple-threshold policy.
fn project_v1(obs: &ObservationV2) -> Result<ObservedSignerSet, SaError> {
    let signers = match &obs.v1_signers {
        Ok(signers) => signers,
        Err((index, id, reason)) => {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: unrecognised_signer_reason(*index, *id, reason),
            });
        }
    };
    let Some(threshold) = &obs.snapshot.threshold else {
        let smart_account_redacted =
            RedactedStrkey::from_already_redacted(obs.smart_account_redacted.as_str());
        return Err(if obs.policies.is_empty() {
            SaError::ThresholdPolicyNotInstalled {
                rule_id: obs.rule_id,
                smart_account_redacted,
                request_id: obs.request_id.clone(),
            }
        } else {
            SaError::ThresholdPolicyIdentificationFailed {
                rule_id: obs.rule_id,
                smart_account_redacted,
                observed_wasm_hashes_summary: obs.policy_hashes.clone(),
                request_id: obs.request_id.clone(),
            }
        });
    };
    Ok(ObservedSignerSet {
        signer_count: u32::try_from(signers.len()).unwrap_or(u32::MAX),
        threshold: threshold.threshold,
        signer_ids: signers.iter().map(|(id, _)| *id).collect(),
        signer_pubkeys: signers.iter().map(|(_, pubkey)| pubkey.clone()).collect(),
    })
}

/// Classifies `obs` against the state row `view` in the row's version; the
/// one comparison body behind `SignersManager::compare_locked` (the submit
/// path, the passkey path, the signer verbs and the public entry),
/// `list_signers` and `refresh_signer_baseline`.
///
/// A version-2 row compares its snapshot's digest with the observation's.
/// A version-1 row compares with the observation's version-1 projection
/// ([`project_v1`]); a projection that fails is
/// [`Classified::NotComparable`] with the projection's error.
///
/// # Errors
///
/// [`SaError::AuditLog`] when the row's own digest cannot be computed.
fn classify_against(view: &SignerSetView, obs: &ObservationV2) -> Result<Classified, SaError> {
    let (expected_digest, observed_digest, observed) = match view {
        SignerSetView::V1(expected) => {
            let observed = match project_v1(obs) {
                Ok(observed) => observed,
                Err(cause) => return Ok(Classified::NotComparable { cause }),
            };
            (
                compute_signer_set_digest(expected)?,
                compute_signer_set_digest(&observed)?,
                SignerSetView::V1(observed),
            )
        }
        SignerSetView::V2(expected) => (
            compute_signer_set_digest_v2(expected)?,
            compute_signer_set_digest_v2(&obs.snapshot)?,
            SignerSetView::V2(obs.snapshot.clone()),
        ),
    };
    if expected_digest != observed_digest {
        return Ok(Classified::Diverged { observed });
    }
    Ok(Classified::Matched { observed })
}

/// The reason a rule read refuses a signer at `index` (id `id`) the wallet
/// cannot represent.
fn unrecognised_signer_reason(index: usize, id: u32, reason: &SignerDecodeError) -> String {
    format!(
        "get_context_rule: signer at index {index} (id {id}) is not a recognised Signer: {reason}"
    )
}

/// The first 8 bytes, as hex, of the SHA-256 of `value`'s XDR encoding, or
/// `encode_error` when the value does not encode.
fn scval_digest_first8(value: &ScVal) -> String {
    use stellar_xdr::{Limits, WriteXdr};
    value.to_xdr(Limits::none()).map_or_else(
        |_| "encode_error".to_owned(),
        |bytes| hex::encode(&Sha256::digest(bytes)[..8]),
    )
}

/// Whether `snapshot` is the state an install authorized: its signers'
/// identities equal `expected.signers` as a multiset, and its threshold
/// equals `expected.threshold` in both the policy and the value.
///
/// `SignerIdentityV2` has no order, so each observed identity removes one
/// equal expected identity from a working copy; equal counts and no
/// unmatched observation make the two multisets equal.
fn is_installed_state(snapshot: &SignerSetSnapshotV2, expected: &ExpectedInstallState) -> bool {
    if snapshot.threshold != expected.threshold || snapshot.signers.len() != expected.signers.len()
    {
        return false;
    }
    let mut unmatched: Vec<&SignerIdentityV2> = expected.signers.iter().collect();
    snapshot.signers.iter().all(|entry| {
        match unmatched
            .iter()
            .position(|identity| **identity == entry.identity)
        {
            Some(position) => {
                unmatched.swap_remove(position);
                true
            }
            None => false,
        }
    })
}

/// The version-2 snapshot of `rule`'s signers with `threshold`: one entry
/// per signer with its version-2 identity, in ascending id order, validated.
///
/// # Errors
///
/// [`SaError::DeploymentFailed`] (phase `simulate`) naming the malformed set,
/// a chain fact such as a duplicate signer id.
fn snapshot_of_rule(
    rule: &OnChainContextRule,
    threshold: Option<ThresholdObservation>,
) -> Result<SignerSetSnapshotV2, SaError> {
    let mut signers: Vec<SignerEntryV2> = rule
        .signers
        .iter()
        .map(|(id, signer)| SignerEntryV2 {
            id: *id,
            identity: signer.to_identity_v2(),
        })
        .collect();
    signers.sort_by_key(|entry| entry.id);
    let snapshot = SignerSetSnapshotV2 { signers, threshold };
    snapshot.validate().map_err(|e| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason: format!("get_context_rule: the observed signer set is malformed: {e}"),
    })?;
    Ok(snapshot)
}

/// The [`SaError::BaselineWriteFailed`] at stage `observe` of a confirmed
/// transaction whose resulting state could not be observed because of
/// `cause`.
pub(crate) fn observe_failed_after(
    rule_id: u32,
    smart_account_redacted: &str,
    tx_hash: &str,
    cause: &SaError,
    request_id: &str,
) -> SaError {
    warn!(
        rule_id,
        smart_account_redacted = %smart_account_redacted,
        tx_hash,
        cause = cause.wire_code(),
        "the confirmed signer-set state could not be observed"
    );
    SaError::BaselineWriteFailed {
        rule_id,
        smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
        tx_hash: Some(tx_hash.to_owned()),
        stage: BASELINE_WRITE_STAGE_OBSERVE,
        reason: baseline_observe_reason(cause),
        request_id: request_id.to_owned(),
    }
}

/// `before` with `added` signers inserted, in ascending id order, and the
/// threshold unchanged.
fn with_added_signers(
    before: &SignerSetSnapshotV2,
    added: impl IntoIterator<Item = (u32, SignerIdentityV2)>,
) -> SignerSetSnapshotV2 {
    let mut signers = before.signers.clone();
    signers.extend(
        added
            .into_iter()
            .map(|(id, identity)| SignerEntryV2 { id, identity }),
    );
    signers.sort_by_key(|entry| entry.id);
    SignerSetSnapshotV2 {
        signers,
        threshold: before.threshold.clone(),
    }
}

/// `before` without the signer `signer_id`, the threshold unchanged.
fn without_signer(before: &SignerSetSnapshotV2, signer_id: u32) -> SignerSetSnapshotV2 {
    SignerSetSnapshotV2 {
        signers: before
            .signers
            .iter()
            .filter(|entry| entry.id != signer_id)
            .cloned()
            .collect(),
        threshold: before.threshold.clone(),
    }
}

/// The lowest id of an entry of `observed` that holds `identity`, whose id
/// `before` does not hold and that `taken` does not list; `None` when there
/// is none.
fn new_entry_id(
    before: &SignerSetSnapshotV2,
    observed: &SignerSetSnapshotV2,
    identity: &SignerIdentityV2,
    taken: &[u32],
) -> Option<u32> {
    observed
        .signers
        .iter()
        .filter(|entry| {
            &entry.identity == identity
                && !taken.contains(&entry.id)
                && !before
                    .signers
                    .iter()
                    .any(|existing| existing.id == entry.id)
        })
        .map(|entry| entry.id)
        .min()
}

/// The ids of the `added` identities, in input order.
///
/// Each identity takes the id of a new entry of `observed` that holds it
/// ([`new_entry_id`]). An identity without one takes an id above every id of
/// `before` and `observed`, so the intended state built from these ids
/// differs from the observed one.
fn assign_added_ids(
    before: &SignerSetSnapshotV2,
    observed: &SignerSetSnapshotV2,
    added: &[SignerIdentityV2],
) -> Vec<u32> {
    let mut next_unobserved = before
        .signers
        .iter()
        .chain(&observed.signers)
        .map(|entry| entry.id)
        .max()
        .map_or(0, |id| id.saturating_add(1));
    let mut ids: Vec<u32> = Vec::with_capacity(added.len());
    for identity in added {
        let id = new_entry_id(before, observed, identity, &ids).unwrap_or_else(|| {
            let id = next_unobserved;
            next_unobserved = next_unobserved.saturating_add(1);
            id
        });
        ids.push(id);
    }
    ids
}

/// The distinct verifier addresses of the `External` signers among
/// `signers`, in first-seen order.
fn external_verifiers<'a>(
    signers: impl IntoIterator<Item = &'a DecodedOnChainSigner>,
) -> Vec<ScAddress> {
    let mut verifiers: Vec<ScAddress> = Vec::new();
    for signer in signers {
        if let DecodedOnChainSigner::External {
            verifier_address, ..
        } = signer
            && !verifiers.contains(verifier_address)
        {
            verifiers.push(verifier_address.clone());
        }
    }
    verifiers
}

/// The kind label a threshold refusal names for a signer being added. The
/// CLI's `signer_kinds` envelope uses its own labels (`delegated_ed25519`).
fn identity_kind_label(identity: &SignerIdentityV2) -> &'static str {
    match identity {
        SignerIdentityV2::Ed25519 { .. } => "ed25519",
        SignerIdentityV2::External { .. } => "external",
        SignerIdentityV2::DelegatedContract { .. } => "delegated_contract",
        // `SignerIdentityV2` is `#[non_exhaustive]`.
        _ => "unknown",
    }
}

/// The G-strkey of `signer`'s public key, the source account of a signer
/// verb's transaction.
async fn signer_source_strkey(signer: &(dyn Signer + Send + Sync)) -> Result<String, SaError> {
    let source_pubkey =
        signer
            .public_key()
            .await
            .map_err(|e| SaError::AuthEntryConstructionFailed {
                stage: "auth_payload",
                redacted_reason: format!("signer public_key fetch failed: {e}"),
            })?;
    Ok(format!(
        "{}",
        stellar_strkey::ed25519::PublicKey(source_pubkey.0)
    ))
}

/// Logs a signer verb's refusal or failure.
fn warn_failed(verb: &str, rule_id: u32, smart_account_redacted: &str, err: &SaError) {
    warn!(
        error = %err,
        verb,
        rule_id,
        smart_account = %smart_account_redacted,
        "signer verb failed"
    );
}

/// Checks the plan of a migration pair against `before`, the compared set
/// of rule `rule_id`, before anything is sent. Returns the identity the add
/// restores and the key data it carries.
///
/// The removed signer `signer_id` must be on the rule with an `External`
/// identity. `add_args` must be `[U32(rule_id), signer]`, where `signer`
/// decodes to that identity's key data on `to_verifier_addr`. `remove_args`
/// must be `[U32(rule_id), U32(signer_id)]`.
///
/// # Errors
///
/// The detail of the `plan_build` refusal naming the first mismatch.
fn check_migration_pair_plan(
    before: &SignerSetSnapshotV2,
    rule_id: u32,
    signer_id: u32,
    to_verifier_addr: &ScAddress,
    remove_args: &[ScVal],
    add_args: &[ScVal],
) -> Result<(SignerIdentityV2, Vec<u8>), String> {
    let removed = before
        .signers
        .iter()
        .find(|entry| entry.id == signer_id)
        .ok_or_else(|| format!("migrate_verifier: signer {signer_id} is not on rule {rule_id}"))?;
    let SignerIdentityV2::External {
        key_data_sha256,
        key_data_len,
        ..
    } = &removed.identity
    else {
        return Err(format!(
            "migrate_verifier: the removed signer {signer_id} is not an External signer"
        ));
    };
    let intended = SignerIdentityV2::External {
        verifier: contract_address_bytes(to_verifier_addr),
        key_data_sha256: *key_data_sha256,
        key_data_len: *key_data_len,
    };
    let not_restored = || {
        format!(
            "migrate_verifier: the add step of signer {signer_id} does not restore the removed \
             identity on the destination verifier"
        )
    };
    let [ScVal::U32(add_rule_id), signer] = add_args else {
        return Err(not_restored());
    };
    let Ok(decoded) = decode_signer_scval_full(signer) else {
        return Err(not_restored());
    };
    let restores = *add_rule_id == rule_id && decoded.to_identity_v2() == intended;
    let DecodedOnChainSigner::External { key_data, .. } = decoded else {
        return Err(not_restored());
    };
    if !restores {
        return Err(not_restored());
    }
    if remove_args != [ScVal::U32(rule_id), ScVal::U32(signer_id)] {
        return Err("migrate_verifier: the remove step's arguments are not the pair's".to_owned());
    }
    Ok((intended, key_data))
}

/// Checks the preconditions of removing signer `signer_id` from the rule
/// `compared` holds, before anything is sent. One body decides them for
/// [`SignersManager::remove_signer`] and the remove step of
/// [`SignersManager::migrate_signer_pair`].
///
/// # Errors
///
/// - [`SaError::ThresholdPolicyIdentificationFailed`]: the rule has
///   policies and none is the simple-threshold policy. Another policy then
///   decides which signers suffice (OZ `weighted_threshold.rs:16-22`); a
///   removal can make its threshold unreachable, and the wallet cannot
///   check it.
/// - [`SaError::ThresholdUnreachable`]: the rule's simple threshold would
///   exceed its signer count after the removal. The threshold is unchanged
///   (no bundle), so the removal would leave the rule unable to sign.
fn check_remove_preconditions(
    compared: &ComparedState,
    signer_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
) -> Result<(), SaError> {
    let rule_id = compared.rule_id();
    let before = compared.snapshot();
    if before.threshold.is_none() && !compared.policies().is_empty() {
        return Err(SaError::ThresholdPolicyIdentificationFailed {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            observed_wasm_hashes_summary: compared.policy_hashes().clone(),
            request_id: request_id.to_owned(),
        });
    }
    if let Some(threshold) = &before.threshold {
        compute_post_op_invariant(
            rule_id,
            before.signer_count().saturating_sub(1),
            threshold.threshold,
            threshold.threshold,
            ThresholdAffectingOp::RemoveSigner { signer_id },
            smart_account_redacted,
            request_id,
        )?;
    }
    Ok(())
}

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

/// Fetches the effective Wasm hash of each `ContractInstance` from one
/// endpoint.
///
/// Generic over any contract address slice; its consumers are the on-chain
/// policy identification helpers `identify_spending_limit_policy`,
/// `identify_weighted_threshold_policy` and `classify_rule_policies`. The two
/// identify helpers compare aligned results from both endpoints. The
/// display-only `classify_rule_policies` uses the primary endpoint.
///
/// Returns `Vec<Option<[u8; 32]>>` **aligned with `keys`**:
/// - `Some(hash)` when the key resolved to a Wasm contract instance, or to a
///   CAP-85 external-reference instance whose owner's tag entry holds a
///   32-byte hash.
/// - `None` when the key was absent from the ledger, resolved to a
///   non-Wasm, non-reference executable or an undecodable entry, or resolved
///   to an external reference whose tag entry is not live, does not decode or
///   does not hold a 32-byte hash.
///
/// The caller may zip this result with the original contract address slice
/// using index position; no positional drift can occur because the lengths
/// match.
///
/// External references are resolved with one more `getLedgerEntries` on the
/// same endpoint for every distinct tag key found, matched by key. The
/// resolved hash identifies the code the reference runs at this ledger; it is
/// owner-mutable, so the result is a snapshot for the caller's allowlist
/// decision and is never stored as a pin.
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
/// # Errors
///
/// Returns a non-sensitive description when either `getLedgerEntries` request
/// fails.
pub(crate) async fn fetch_contract_wasm_hashes(
    client: &StellarRpcClient,
    keys: &[LedgerKey],
) -> Result<Vec<Option<[u8; 32]>>, String> {
    use stellar_xdr::ContractExecutable;

    if keys.is_empty() {
        return Ok(vec![]);
    }

    // Instance data per request position. A malformed key or entry is
    // skipped and leaves its position `None`.
    let instances = fetch_entries_by_key(client, keys).await?;

    let mut hashes: Vec<Option<[u8; 32]>> = vec![None; keys.len()];
    // Request position -> index into `tag_keys` for external references.
    let mut tag_key_index: Vec<Option<usize>> = vec![None; keys.len()];
    let mut tag_keys: Vec<LedgerKey> = Vec::new();

    for (pos, entry_data) in instances.into_iter().enumerate() {
        let Some(stellar_xdr::LedgerEntryData::ContractData(cd)) = entry_data else {
            continue;
        };
        let ScVal::ContractInstance(instance) = &cd.val else {
            continue;
        };
        match &instance.executable {
            ContractExecutable::Wasm(Hash(bytes)) => hashes[pos] = Some(*bytes),
            ContractExecutable::ExternalRef(external) => {
                let tag_key = stellar_agent_network::executable_tag_ledger_key(
                    &external.executable_owner,
                    &external.tag,
                );
                let index = match tag_keys.iter().position(|k| k == &tag_key) {
                    Some(index) => index,
                    None => {
                        tag_keys.push(tag_key);
                        tag_keys.len() - 1
                    }
                };
                tag_key_index[pos] = Some(index);
            }
            ContractExecutable::StellarAsset => {}
        }
    }

    if tag_keys.is_empty() {
        return Ok(hashes);
    }

    // Resolve every tag key at the same endpoint. No live tag entry, an
    // undecodable entry, or a value that is not a 32-byte hash leaves the
    // referencing positions `None`.
    let resolved: Vec<Option<[u8; 32]>> = fetch_entries_by_key(client, &tag_keys)
        .await?
        .into_iter()
        .map(|entry_data| match entry_data {
            Some(stellar_xdr::LedgerEntryData::ContractData(tag_entry)) => match &tag_entry.val {
                ScVal::Bytes(bytes) => <[u8; 32]>::try_from(bytes.0.as_vec().as_slice()).ok(),
                _ => None,
            },
            _ => None,
        })
        .collect();

    for (pos, index) in tag_key_index.into_iter().enumerate() {
        if let Some(index) = index {
            hashes[pos] = resolved.get(index).copied().flatten();
        }
    }

    Ok(hashes)
}

/// Requests `keys` from one endpoint and returns the decoded
/// `LedgerEntryData` of the entry whose own key equals each requested key,
/// aligned with `keys`.
///
/// Both the entry key and the entry data come from an untrusted RPC response
/// and are decoded under the depth- and length-bounded untrusted-decode
/// limits. A returned entry whose data does not decode is skipped, so its
/// position reads `None` like a missing entry. A returned entry whose key
/// does not decode or was not requested reads as `None`, which never matches
/// an allowlist, so identification fails closed.
async fn fetch_entries_by_key(
    client: &StellarRpcClient,
    keys: &[LedgerKey],
) -> Result<Vec<Option<stellar_xdr::LedgerEntryData>>, String> {
    use stellar_xdr::{LedgerEntryData, ReadXdr};

    let response = client
        .get_ledger_entries(keys)
        .await
        .map_err(|e| format!("get_ledger_entries failed: {e}"))?;

    let mut by_pos: Vec<Option<LedgerEntryData>> = vec![None; keys.len()];
    for entry_result in response.entries.unwrap_or_default() {
        let Ok(response_key) = LedgerKey::from_xdr_base64(
            &entry_result.key,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.key.len()),
        ) else {
            continue;
        };
        let Some(pos) = keys.iter().position(|k| k == &response_key) else {
            continue;
        };
        let Ok(entry_data) = LedgerEntryData::from_xdr_base64(
            &entry_result.xdr,
            stellar_agent_xdr_limits::untrusted_decode_limits(entry_result.xdr.len()),
        ) else {
            continue;
        };
        by_pos[pos] = Some(entry_data);
    }
    Ok(by_pos)
}

/// The executable a verifier or policy contract instance runs, as agreed by
/// the primary and secondary endpoints.
///
/// `NoCode` covers an absent instance and a Stellar Asset Contract, neither of
/// which has a Wasm hash. An external reference carries the owner, the tag
/// and the hash the owner's tag entry held when it was read (`None` when no
/// tag entry was live).
///
/// The `Debug` form renders an external reference's owner and tag through
/// their bounded renderings.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObservedExecutable {
    /// Ordinary Wasm executable with its 32-byte hash.
    Wasm([u8; 32]),
    /// No instance, or a Stellar Asset Contract: no Wasm hash.
    NoCode,
    /// CAP-85 external reference: the owner decides which Wasm runs.
    ExternalRef(stellar_agent_network::ExternalRefExecutable),
}

impl ObservedExecutable {
    /// Returns the hash of the code the instance runs: the Wasm hash, the
    /// hash an external reference resolved to, or `None` for no code and for
    /// an external reference with no live tag entry.
    #[must_use]
    pub fn effective_hash(&self) -> Option<[u8; 32]> {
        match self {
            Self::Wasm(hash) => Some(*hash),
            Self::NoCode => None,
            Self::ExternalRef(external) => external.resolved,
        }
    }

    /// Returns a bounded summary for drift rows and errors: `wasm`,
    /// `no code`, or `external reference owner <redacted> tag "<bounded>"
    /// resolved <first-8 hex or unset>`.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Wasm(_) => "wasm".to_owned(),
            Self::NoCode => "no code".to_owned(),
            Self::ExternalRef(external) => format!(
                "external reference owner {} tag \"{}\" resolved {}",
                external.owner_redacted(),
                external.tag_display(),
                external
                    .resolved
                    .map_or_else(|| "unset".to_owned(), |hash| hash_first8_hex(&hash)),
            ),
        }
    }
}

/// Returns `true` when `hash` is the Wasm hash of a
/// [`crate::VERIFIER_ALLOWLIST`] entry.
pub(crate) fn verifier_hash_allowlisted(hash: &[u8; 32]) -> bool {
    crate::VERIFIER_ALLOWLIST
        .iter()
        .any(|entry| &entry.wasm_hash == hash)
}

/// Returns `true` when `hash` is a policy Wasm the wallet vendors, the set a
/// policy pin accepts without the unknown-hash override: the simple-threshold
/// hashes ([`THRESHOLD_POLICY_WASM_HASHES`]), the weighted-threshold hashes
/// ([`WEIGHTED_THRESHOLD_POLICY_WASM_HASHES`]) and the spending-limit hash
/// ([`crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256`]).
pub(crate) fn policy_hash_allowlisted(hash: &[u8; 32]) -> bool {
    THRESHOLD_POLICY_WASM_HASHES
        .iter()
        .chain(WEIGHTED_THRESHOLD_POLICY_WASM_HASHES)
        .any(|allowed| allowed == hash)
        || hex::encode(hash) == crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256
}

/// The first-8 projection of a hash the audit rows, pins and errors carry.
pub(crate) use stellar_agent_core::hex::wasm_hash_first8_hex as hash_first8_hex;

/// Identification result of one verifier or policy contract: the observed
/// executable, its effective hash, and whether that hash is allowlisted.
#[derive(Clone, Debug)]
pub(crate) struct ContractObservation {
    /// The executable both endpoints agreed on.
    pub(crate) observed: ObservedExecutable,
    /// The effective hash, or the zero hash for no code.
    pub(crate) effective_hash: [u8; 32],
    /// `true` when the instance has code and its effective hash is in the
    /// caller's allowlist.
    pub(crate) allowlisted: bool,
}

impl ContractObservation {
    /// First-8 hex of the effective hash, or `"none"` for no code; the form
    /// the allowlist-miss errors and override rows carry.
    pub(crate) fn observed_hash_first8(&self) -> String {
        match self.observed {
            ObservedExecutable::NoCode => "none".to_owned(),
            _ => hash_first8_hex(&self.effective_hash),
        }
    }
}

/// Fetches the executable of a single deployed contract via two-RPC
/// consultation, WITHOUT allowlist enforcement.
///
/// This is the lower-level primitive underlying
/// [`SignersManager::observe_contract`], the signing-time drift check and the
/// migration planner. It delegates the two-RPC fetch and divergence check to
/// [`stellar_agent_network::fetch_contract_wasm_hash`], which resolves an
/// external reference's tag entry at each endpoint, then maps the
/// [`stellar_agent_network::WasmHashFetch`] outcome: `Wasm(h)` to
/// [`ObservedExecutable::Wasm`], `Sac` and `Absent` to
/// [`ObservedExecutable::NoCode`], and `ExternalRef` to
/// [`ObservedExecutable::ExternalRef`], resolved or not. Each caller applies
/// its own policy to the observation.
///
/// `contract_kind` names the role of `contract_addr` in a refusal.
/// `rule_id` is `None` before install, when the rule has no on-chain id yet:
/// a `ContractInstanceUnsupported` or `NetworkRpcDivergence` refusal raised
/// before a rule exists carries no rule id.
///
/// # Errors
///
/// - [`SaError::ContractInstanceUnsupported`]: an endpoint returned a
///   malformed instance or tag entry (reason `UndecodableInstance`), or an
///   outcome this crate does not know (reason `NonWasmExecutable`). No flag
///   overrides either refusal.
/// - [`SaError::NetworkRpcDivergence`]: primary and secondary RPC responses
///   differ, including on an external reference's owner, tag or resolved hash.
/// - [`SaError::DeploymentFailed`] (phase `"simulate"`) — `getLedgerEntries` RPC
///   failure on primary or secondary.
///
/// # Implements
///
/// Verifier pinning: fetches the live on-chain executable without allowlist
/// enforcement, for install-time identification, signing-time drift
/// detection and migration planning.
pub(crate) async fn fetch_observed_executable(
    primary: &StellarRpcClient,
    secondary: &StellarRpcClient,
    contract_addr: &ScAddress,
    contract_kind: ContractKind,
    rule_id: Option<u32>,
    smart_account_redacted: &str,
    request_id: &str,
) -> Result<ObservedExecutable, SaError> {
    use stellar_agent_network::{
        FetchContractWasmHashError, WasmHashFetch, fetch_contract_wasm_hash,
    };

    // Convert ScAddress to strkey so the shared primitive can parse it.
    // scaddress_to_strkey only fails for exotic non-Contract / non-Account
    // variants; every caller passes a contract address (C-strkey).
    let strkey = scaddress_to_strkey(contract_addr)?;
    let unsupported = |reason: AdminOrOwnerKey| SaError::ContractInstanceUnsupported {
        rule_id,
        contract_kind,
        smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
        contract_address_redacted: RedactedStrkey::from_full(&strkey),
        reason,
        request_id: request_id.to_owned(),
    };

    match fetch_contract_wasm_hash(primary, Some(secondary), &strkey).await {
        Ok(WasmHashFetch::Wasm(hash)) => Ok(ObservedExecutable::Wasm(hash)),
        Ok(WasmHashFetch::Sac | WasmHashFetch::Absent) => Ok(ObservedExecutable::NoCode),
        Ok(WasmHashFetch::ExternalRef(external)) => Ok(ObservedExecutable::ExternalRef(external)),
        // WasmHashFetch is #[non_exhaustive]: an outcome this crate does not
        // know is not a Wasm executable and carries no hash the wallet can
        // pin, so it is refused and never read as absent.
        Ok(_) => Err(unsupported(AdminOrOwnerKey::NonWasmExecutable)),
        Err(FetchContractWasmHashError::Malformed { reason, .. }) => {
            warn!(
                contract_redacted = %redact_strkey_first5_last5(&strkey),
                contract_kind = %contract_kind,
                reason = %reason,
                rule_id,
                "fetch_observed_executable: malformed ledger entry; refusing"
            );
            Err(unsupported(AdminOrOwnerKey::UndecodableInstance))
        }
        Err(FetchContractWasmHashError::Divergent(div)) => Err(SaError::NetworkRpcDivergence {
            rule_id,
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            primary_view_digest_first8: div.primary_summary,
            secondary_view_digest_first8: div.secondary_summary,
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
        // parse cannot realistically reject it.  Maps to the same variant
        // scaddress_to_strkey itself returns.
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
            redacted_reason: format!(
                "{context}: expected ScVal::U32 return, got {}",
                scval_variant_name(other)
            ),
        }),
    }
}

/// Builds an OZ `Signer::Delegated(Address)` ScVal from a delegated signer
/// G-strkey.
///
/// OZ `Signer` contracttype byte-layout (stellar-accounts v0.7.2):
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
/// OZ `Signer` contracttype byte-layout (stellar-accounts v0.7.2):
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

/// Standalone read-only simulate helper (no auth, no signing).
///
/// Thin wrapper over [`simulate_read_only_with_ledger`] that discards the
/// simulation's `latestLedger`; see that function's rustdoc for the full
/// argument and behavior contract.
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
    simulate_read_only_with_ledger(
        rpc_url,
        smart_account,
        entrypoint,
        invoke_args,
        source_account_strkey,
        network_passphrase,
        timeout,
    )
    .await
    .map(|(return_val, _latest_ledger)| return_val)
}

/// Standalone read-only simulate helper (no auth, no signing) that also
/// returns the simulation's `latestLedger`.
///
/// When `source_account_strkey` is `None`, uses [`SIMULATE_SENTINEL_G`] with
/// sequence number `"0"` and skips the `fetch_account` RPC call.
///
/// The returned `u32` is the ledger sequence the RPC node observed while
/// simulating (`SimulateTransactionResponse::latest_ledger`) — the "as of"
/// ledger for any budget or expiry computation derived from the return
/// value. [`simulate_read_only`] is a thin wrapper that discards it for
/// callers that only need the decoded `ScVal`.
///
/// `pub(crate)` — used by `SignersManager::get_spending_limit_data`, which
/// needs the as-of ledger for `compute_spending_window`.
pub(crate) async fn simulate_read_only_with_ledger(
    rpc_url: &str,
    smart_account: ScAddress,
    entrypoint: &str,
    invoke_args: Vec<ScVal>,
    source_account_strkey: Option<&str>,
    network_passphrase: &str,
    timeout: Duration,
) -> Result<(ScVal, u32), SaError> {
    let (outcome, latest_ledger) = simulate_read_only_at_ledger(
        rpc_url,
        smart_account,
        entrypoint,
        invoke_args,
        source_account_strkey,
        network_passphrase,
        timeout,
    )
    .await?;
    outcome.map(|return_val| (return_val, latest_ledger))
}

/// Read-only simulate helper (no auth, no signing) that returns the
/// simulation's outcome beside the `latestLedger` its response reported.
///
/// Every `simulateTransaction` response carries `latestLedger`, a failed
/// simulation's included, so a caller can tell an endpoint behind a ledger
/// it needs from a failure. The inner result is the decoded return value or
/// the simulation's refusal, with the ledger either way.
///
/// # Errors
///
/// The outer error is a failure before any response: an argument that does
/// not encode, the source-account fetch, the transport or a timeout. It
/// carries no ledger.
async fn simulate_read_only_at_ledger(
    rpc_url: &str,
    smart_account: ScAddress,
    entrypoint: &str,
    invoke_args: Vec<ScVal>,
    source_account_strkey: Option<&str>,
    network_passphrase: &str,
    timeout: Duration,
) -> Result<(Result<ScVal, SaError>, u32), SaError> {
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

    let latest_ledger = sim.latest_ledger;
    if let Some(err) = &sim.error {
        return Ok((
            Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "{entrypoint} simulation error: {}",
                    augment_with_oz_error_name(err)
                ),
            }),
            latest_ledger,
        ));
    }

    let return_val =
        sim.results()
            .map_err(|e| SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!("{entrypoint}: simulate results decode failed: {e}"),
            })
            .and_then(|results| {
                results.into_iter().next().map(|result| result.xdr).ok_or(
                    SaError::DeploymentFailed {
                        phase: "simulate",
                        redacted_reason: format!("{entrypoint}: simulate returned no result entry"),
                    },
                )
            });

    Ok((return_val, latest_ledger))
}

// ── OnChainContextRule ────────────────────────────────────────────────────────

/// Decoded on-chain context rule (off-chain mirror of the OZ `ContextRule` struct).
///
/// Produced by decoding the `ScVal` returned from `get_context_rule`. Every
/// signer is kept in full ([`DecodedOnChainSigner`]); the version-2 identity
/// and the version-1 projection are derived from it. The `raw_scval` field
/// preserves the verbatim simulation return value so it can be round-tripped
/// back to the chain as the `context_rule` argument for `set_threshold`
/// without re-encoding risk.
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
    /// The rule id the contract returned.
    id: u32,
    /// `(signer_id, signer)` pairs in the rule's order.
    signers: Vec<(u32, DecodedOnChainSigner)>,
    /// The attached policies in the rule's order.
    policies: Vec<ScAddress>,
    /// Verbatim `ScVal::Map` from `get_context_rule` simulation — passed through
    /// as the `context_rule` argument to `set_threshold`.
    ///
    /// Stores the full on-chain `#[contracttype]` ScVal encoding so the wallet
    /// never re-encodes the 8-field struct off-chain.
    raw_scval: ScVal,
}

impl OnChainContextRule {
    /// The signers as `(signer_id, version-2 identity)` pairs, in the rule's
    /// order.
    fn identities(&self) -> Vec<(u32, SignerIdentityV2)> {
        self.signers
            .iter()
            .map(|(id, signer)| (*id, signer.to_identity_v2()))
            .collect()
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
    /// The OZ stellar-accounts v0.7.2 `ContextRule` is an 8-field
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
/// `signer_ids`, and `policies`. `ContextRule` carries no threshold: a
/// simple-threshold policy stores it keyed by `(context_rule_id,
/// smart_account)`, and the signer-set observation reads it there.
///
/// # Complete signer set
///
/// An observed signer set describes every signer the rule holds. The map
/// must carry both `signer_ids` and `signers` as `Vec`s; the two lists are
/// parallel, so they must have the same length, every id must be a `u32` and
/// every signer must decode through [`decode_signer_scval_full`]. A signer the
/// wallet cannot represent (an unknown `Signer` variant, a malformed
/// encoding, a `Delegated` address that is neither an account nor a
/// contract, or an `External` signer with empty key data) refuses the
/// observation, so every read of the rule's signer set fails closed: the
/// baseline comparison, `signers list` and `signers refresh`, the signer verbs
/// and their post-submit reads, policy identification for threshold,
/// spending-limit and weighted-threshold policies, the executable pin check on
/// every rule-authorized signing verb, the passkey path and the policy
/// classification of the MCP `stellar_rules_get` tool. Every signer of the
/// rule can authorize its transactions, so the baseline, the threshold
/// arithmetic and the operator's view each need all of them.
/// Such a rule is removed with `smart-account rules delete`, authorized by a
/// rule the wallet can read; the delete reads only its authorizing rules.
///
/// # Errors
///
/// Returns [`SaError::DeploymentFailed`] (phase `"simulate"`) if the `ScVal`
/// cannot be decoded as a `ContextRule`: not a map, no `id`, a missing or
/// non-`Vec` `signer_ids` or `signers` field, a `signer_ids` item that is not
/// a `u32`, `signer_ids` and `signers` of different lengths, or a signer that
/// does not decode. The reason names the offending field or index and never
/// renders the value.
fn decode_context_rule_scval(val: ScVal) -> Result<OnChainContextRule, SaError> {
    // The simulation returns a ScVal::Map for a contracttype struct.
    // We extract id, signers, signer_ids, policies.
    // We also preserve the raw ScVal for round-trip use in set_threshold args.
    let map = match &val {
        ScVal::Map(Some(m)) => m.clone(),
        other => {
            return Err(SaError::DeploymentFailed {
                phase: "simulate",
                redacted_reason: format!(
                    "get_context_rule: expected ScVal::Map, got {}",
                    scval_variant_name(other)
                ),
            });
        }
    };
    // Preserve the verbatim ScVal — used as the `context_rule` arg in set_threshold.
    // This round-trips the on-chain #[contracttype] encoding without re-encoding risk.
    let raw_scval = val;

    let refuse = |redacted_reason: String| SaError::DeploymentFailed {
        phase: "simulate",
        redacted_reason,
    };

    let mut id: Option<u32> = None;
    let mut signer_ids: Option<Vec<u32>> = None;
    let mut signers_scvals: Option<Vec<ScVal>> = None;
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
                let items = context_rule_list_items(&entry.val, "signer_ids")
                    .map_err(|e| refuse(format!("get_context_rule: {e}")))?;
                let mut ids = Vec::with_capacity(items.len());
                for (i, item) in items.into_iter().enumerate() {
                    let ScVal::U32(n) = item else {
                        return Err(refuse(format!(
                            "get_context_rule: signer_ids[{i}] is not a u32: {}",
                            scval_variant_name(item)
                        )));
                    };
                    ids.push(*n);
                }
                signer_ids = Some(ids);
            }
            "signers" => {
                let items = context_rule_list_items(&entry.val, "signers")
                    .map_err(|e| refuse(format!("get_context_rule: {e}")))?;
                signers_scvals = Some(items.into_iter().cloned().collect());
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
    let signer_ids = signer_ids.ok_or_else(|| {
        refuse("get_context_rule: missing 'signer_ids' field in ContextRule map".to_owned())
    })?;
    let signers_scvals = signers_scvals.ok_or_else(|| {
        refuse("get_context_rule: missing 'signers' field in ContextRule map".to_owned())
    })?;

    // `signer_ids[i]` is the id of `signers[i]` (OZ keeps the two lists
    // parallel), so a length mismatch leaves a signer without an id or an id
    // without a signer.
    if signer_ids.len() != signers_scvals.len() {
        return Err(refuse(format!(
            "get_context_rule: signer_ids has {} entries and signers has {}",
            signer_ids.len(),
            signers_scvals.len()
        )));
    }

    let signers: Vec<(u32, DecodedOnChainSigner)> = signer_ids
        .iter()
        .zip(signers_scvals.iter())
        .enumerate()
        .map(|(i, (sid, sv))| {
            decode_signer_scval_full(sv)
                .map(|signer| (*sid, signer))
                .map_err(|e| refuse(unrecognised_signer_reason(i, *sid, &e)))
        })
        .collect::<Result<_, _>>()?;

    Ok(OnChainContextRule {
        id: rule_id,
        signers,
        policies,
        raw_scval,
    })
}

/// Returns the items of a `ContextRule` list field (`signer_ids`, `signers`).
///
/// An absent `Vec` body (`ScVal::Vec(None)`) is an empty list.
///
/// # Errors
///
/// Returns `"{field} is not a Vec: {variant}"` when the value is not an
/// `ScVal::Vec`; the caller prefixes its own context.
pub(crate) fn context_rule_list_items<'a>(
    val: &'a ScVal,
    field: &str,
) -> Result<Vec<&'a ScVal>, String> {
    match val {
        ScVal::Vec(list) => Ok(list.iter().flat_map(|l| l.iter()).collect()),
        other => Err(format!(
            "{field} is not a Vec: {}",
            scval_variant_name(other)
        )),
    }
}

/// Full-fidelity decoded representation of an OZ on-chain `Signer` variant.
///
/// Produced by [`decode_signer_scval_full`] from a `Signer` `#[contracttype]`
/// ScVal. Carries all fields without truncation. [`Self::to_identity_v2`]
/// derives the full version-2 identity every signer has;
/// [`Self::to_signer_pubkey_v1`] derives the truncated version-1 form, which
/// a signer delegated to a contract address does not have.
///
/// Decoded from the OZ stellar-accounts v0.7.2 `Signer` contracttype.
///
/// Production callers within this crate reach it through the rule decoder,
/// which keeps every signer of a rule, and through the verifier-migration
/// planner, which keeps the full `key_data` to rebuild the signer.
///
/// The enum is `#[non_exhaustive]`: a match outside this crate needs a
/// wildcard arm.
#[non_exhaustive]
pub enum DecodedOnChainSigner {
    /// `Signer::Delegated(Address)` with an account (G) address: an ed25519
    /// keypair.
    ///
    /// Note: in the OZ contracttype, the `Address` is the **signer** account
    /// address (a G-strkey public key), not a verifier contract address.
    Delegated {
        /// The 32-byte ed25519 public key extracted from the Account address.
        pubkey: [u8; 32],
        /// The verbatim `ScAddress` (always `ScAddress::Account`) for callers
        /// that need the typed value (for example for ScMap key construction or
        /// equality assertions).
        signer_address: ScAddress,
    },
    /// `Signer::Delegated(Address)` with a contract (C) address: the
    /// contract's own authorization decides for this signer.
    DelegatedContract {
        /// The 32-byte contract id extracted from the Contract address.
        contract: [u8; 32],
        /// The verbatim `ScAddress` (always `ScAddress::Contract`).
        signer_address: ScAddress,
    },
    /// `Signer::External(Address, Bytes)`: a custom verifier contract with an
    /// opaque public-key blob, a passkey signer included.
    ///
    /// The `Address` payload is always `ScAddress::Contract(...)`: the
    /// variant is `#[non_exhaustive]`, so only [`decode_signer_scval_full`]
    /// constructs it, and it refuses any other verifier address.
    #[non_exhaustive]
    External {
        /// Verifier contract C-strkey (e.g. `"CABC..."` prefix).
        verifier_strkey: String,
        /// The verbatim verifier `ScAddress` (always `ScAddress::Contract`),
        /// for callers that rebuild the signer ScVal.
        verifier_address: ScAddress,
        /// Full public-key byte blob, never empty. NOT truncated: the
        /// version-2 identity hashes it whole, and test callers use it for
        /// byte-exact equality assertions.
        key_data: Vec<u8>,
    },
}

impl DecodedOnChainSigner {
    /// The signer's full version-2 identity.
    ///
    /// `Delegated` maps to [`SignerIdentityV2::Ed25519`],
    /// `DelegatedContract` to [`SignerIdentityV2::DelegatedContract`], and
    /// `External` to [`SignerIdentityV2::External`] with the SHA-256 and the
    /// length of the whole key data.
    #[must_use]
    pub fn to_identity_v2(&self) -> SignerIdentityV2 {
        match self {
            Self::Delegated { pubkey, .. } => SignerIdentityV2::Ed25519 { pubkey: *pubkey },
            Self::DelegatedContract { contract, .. } => SignerIdentityV2::DelegatedContract {
                contract: *contract,
            },
            Self::External {
                verifier_address,
                key_data,
                ..
            } => SignerIdentityV2::External {
                verifier: contract_address_bytes(verifier_address),
                key_data_sha256: Sha256::digest(key_data).into(),
                key_data_len: u32::try_from(key_data.len()).unwrap_or(u32::MAX),
            },
        }
    }

    /// The signer's version-1 form, as version-1 state rows record it:
    /// `Delegated` as [`SignerPubkey::Ed25519`], `External` as
    /// [`SignerPubkey::External`] keeping the first 16 bytes of the key data
    /// (zero-padded when shorter).
    ///
    /// # Errors
    ///
    /// [`SignerDecodeError::DelegatedAddressNotAnAccount`] for a
    /// `DelegatedContract` signer, which version 1 cannot represent.
    pub fn to_signer_pubkey_v1(&self) -> Result<SignerPubkey, SignerDecodeError> {
        match self {
            Self::Delegated { pubkey, .. } => Ok(SignerPubkey::Ed25519 { pubkey: *pubkey }),
            Self::DelegatedContract { .. } => Err(SignerDecodeError::DelegatedAddressNotAnAccount),
            Self::External {
                verifier_strkey,
                key_data,
                ..
            } => {
                let mut key_data_first16 = [0u8; 16];
                let len = key_data.len().min(16);
                key_data_first16[..len].copy_from_slice(&key_data[..len]);
                Ok(SignerPubkey::External {
                    verifier_contract: verifier_strkey.clone(),
                    key_data_first16,
                })
            }
        }
    }
}

/// The 32-byte id of a contract address: an `External` signer's verifier,
/// or a policy a threshold observation names.
///
/// Only [`decode_signer_scval_full`] constructs an `External` signer, and
/// only with a contract address, so the zero id of the other arm is never
/// produced for a decoded signer.
fn contract_address_bytes(address: &ScAddress) -> [u8; 32] {
    match address {
        ScAddress::Contract(ContractId(Hash(bytes))) => *bytes,
        _ => [0u8; 32],
    }
}

/// Reason an OZ `Signer` ScVal does not decode to a [`DecodedOnChainSigner`],
/// or has no version-1 form.
///
/// One variant per refusal. The `Display` text names the offending shape
/// (an `ScVal` variant name, an item count or the tag bounded to
/// [`stellar_agent_core::observability::UNTRUSTED_DISPLAY_MAX_BYTES`] bytes)
/// and never renders an address, a key blob or an unbounded value, so it is
/// safe inside a redacted error reason.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerDecodeError {
    /// The signer is not an `ScVal::Vec`.
    #[error("expected ScVal::Vec, got {variant}")]
    NotAVec {
        /// Variant name of the value, from `scval_variant_name`.
        variant: &'static str,
    },
    /// The `Vec` has fewer than two items (a tag and a payload).
    #[error("expected at least 2 items, got {count}")]
    TooFewItems {
        /// Number of items in the `Vec`.
        count: usize,
    },
    /// The first item, the variant tag, is not an `ScVal::Symbol`.
    #[error("tag is not a Symbol: {variant}")]
    TagNotASymbol {
        /// Variant name of the tag item, from `scval_variant_name`.
        variant: &'static str,
    },
    /// The tag names neither `Delegated` nor `External`.
    #[error("unknown signer tag \"{tag}\"")]
    UnknownTag {
        /// The tag bytes rendered through `untrusted_display_bounded`.
        tag: String,
    },
    /// A `Delegated` signer's address is not an account (G) address.
    ///
    /// Raised by [`decode_signer_scval_full`] for an address that is neither
    /// an account nor a contract, and by
    /// [`DecodedOnChainSigner::to_signer_pubkey_v1`] for a contract address,
    /// which the version-1 form cannot represent.
    #[error("Delegated signer address is not an account address")]
    DelegatedAddressNotAnAccount,
    /// An `External` signer has fewer than three items (tag, verifier, key data).
    #[error("External signer expected 3 items, got {count}")]
    ExternalTooFewItems {
        /// Number of items in the `Vec`.
        count: usize,
    },
    /// An `External` signer's verifier item is not an `ScVal::Address`.
    #[error("External verifier is not an Address: {variant}")]
    ExternalVerifierNotAnAddress {
        /// Variant name of the verifier item, from `scval_variant_name`.
        variant: &'static str,
    },
    /// An `External` signer's verifier address is not a contract (C) address.
    #[error("External verifier address is not a contract address")]
    ExternalVerifierNotAContract,
    /// An `External` signer's key data item is not an `ScVal::Bytes`.
    #[error("External key data is not Bytes: {variant}")]
    ExternalKeyDataNotBytes {
        /// Variant name of the key data item, from `scval_variant_name`.
        variant: &'static str,
    },
    /// An `External` signer's key data is empty; no verifier can check a
    /// signature against no key.
    #[error("External signer key data is empty")]
    ExternalKeyDataEmpty,
}

/// Full-fidelity decode of an OZ `Signer` ScVal — the single decode site for
/// all OZ `Signer` variant routing and field extraction.
///
/// Production callers (the rule decoder and the verifier-migration planner)
/// and test-helper callers (which need the full `key_data` for byte-exact
/// equality assertions) route through this function, so a change to the OZ
/// `Signer` encoding is made here once.
///
/// The OZ stellar-accounts v0.7.2 `Signer` contracttype encodes as:
/// - `Delegated(Address)` → `ScVal::Vec([Symbol("Delegated"), Address(signer)])`,
///   where the address is an account or a contract
/// - `External(Address, Bytes)` → `ScVal::Vec([Symbol("External"), Address(verifier), Bytes(key_data)])`
///
/// A signer the wallet cannot represent refuses the observation: every rule
/// read requires the whole signer set, so a caller propagates the error and
/// never drops the signer.
///
/// # Errors
///
/// Returns the [`SignerDecodeError`] variant naming the first malformed part:
/// a value that is not a `Vec`, a `Vec` shorter than its variant requires, a
/// tag that is not a `Symbol` or names an unknown variant, a `Delegated`
/// address that is neither an account nor a contract, or an `External`
/// verifier that is not a contract address or key data that is not `Bytes`
/// or is empty.
pub fn decode_signer_scval_full(val: &ScVal) -> Result<DecodedOnChainSigner, SignerDecodeError> {
    let ScVal::Vec(vec) = val else {
        return Err(SignerDecodeError::NotAVec {
            variant: scval_variant_name(val),
        });
    };
    // An absent `Vec` body (`ScVal::Vec(None)`) holds zero items.
    let items: Vec<&ScVal> = vec.iter().flat_map(|v| v.iter()).collect();
    if items.len() < 2 {
        return Err(SignerDecodeError::TooFewItems { count: items.len() });
    }

    let ScVal::Symbol(tag) = items[0] else {
        return Err(SignerDecodeError::TagNotASymbol {
            variant: scval_variant_name(items[0]),
        });
    };

    match tag.as_slice() {
        b"Delegated" => {
            // OZ `Signer::Delegated(Address)`: an account (G) or a contract
            // (C) address.
            match items[1] {
                ScVal::Address(addr @ ScAddress::Account(acc)) => {
                    let pubkey = match &acc.0 {
                        PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => *bytes,
                    };
                    Ok(DecodedOnChainSigner::Delegated {
                        pubkey,
                        signer_address: addr.clone(),
                    })
                }
                ScVal::Address(addr @ ScAddress::Contract(ContractId(Hash(contract)))) => {
                    Ok(DecodedOnChainSigner::DelegatedContract {
                        contract: *contract,
                        signer_address: addr.clone(),
                    })
                }
                _ => Err(SignerDecodeError::DelegatedAddressNotAnAccount),
            }
        }
        b"External" => {
            if items.len() < 3 {
                return Err(SignerDecodeError::ExternalTooFewItems { count: items.len() });
            }
            // OZ `Signer::External(Address, Bytes)`.
            let ScVal::Address(verifier_address) = items[1] else {
                return Err(SignerDecodeError::ExternalVerifierNotAnAddress {
                    variant: scval_variant_name(items[1]),
                });
            };
            let ScAddress::Contract(ContractId(Hash(bytes))) = verifier_address else {
                return Err(SignerDecodeError::ExternalVerifierNotAContract);
            };
            let verifier_strkey = format!("{}", stellar_strkey::Contract(*bytes));
            let ScVal::Bytes(ScBytes(key_data)) = items[2] else {
                return Err(SignerDecodeError::ExternalKeyDataNotBytes {
                    variant: scval_variant_name(items[2]),
                });
            };
            if key_data.is_empty() {
                return Err(SignerDecodeError::ExternalKeyDataEmpty);
            }
            Ok(DecodedOnChainSigner::External {
                verifier_strkey,
                verifier_address: verifier_address.clone(),
                key_data: key_data.as_slice().to_vec(),
            })
        }
        other => Err(SignerDecodeError::UnknownTag {
            tag: untrusted_display_bounded(other),
        }),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
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

    use super::*;

    /// A policy pin accepts every policy Wasm the wallet vendors without the
    /// unknown-hash override, and nothing else.
    #[test]
    fn policy_hash_allowlisted_accepts_the_vendored_policy_wasms_only() {
        let spending_limit: [u8; 32] =
            hex::decode(crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256)
                .expect("hex")
                .try_into()
                .expect("32 bytes");
        for hash in THRESHOLD_POLICY_WASM_HASHES
            .iter()
            .chain(WEIGHTED_THRESHOLD_POLICY_WASM_HASHES)
            .chain(std::iter::once(&spending_limit))
        {
            assert!(policy_hash_allowlisted(hash), "{}", hash_first8_hex(hash));
        }
        assert!(!policy_hash_allowlisted(&[0xdd; 32]));
        assert!(!policy_hash_allowlisted(
            &crate::VERIFIER_ALLOWLIST[0].wasm_hash
        ));
    }

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

        let observation = test_observation(SignerSetSnapshotV2 {
            signers: vec![SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0x11; 32] },
            }],
            threshold: None,
        });
        let mut outcome = None;
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            outcome = Some(manager.emit_baseline(
                &observation,
                7,
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
                "CDABC...12345",
                BaselineReason::FirstObservation,
                None,
                "req-poison",
            ));
        });
        match outcome.expect("emit_baseline ran") {
            Err(SaError::BaselineWriteFailed {
                rule_id: 7,
                tx_hash: None,
                stage,
                ..
            }) => assert_eq!(stage, BASELINE_WRITE_STAGE_WRITE),
            other => panic!("a poisoned writer must fail the baseline write: {other:?}"),
        }
        assert!(
            logs.contains("SaSignerSetBaselinedV2 row not written"),
            "missing poison warning: {logs}"
        );
        // The session-degraded warning TEXT is pinned next to its emitter
        // (core audit_log::health tests); its callsite is shared with other
        // tests in this binary, and tracing's process-global interest cache
        // makes cross-test capture of shared callsites nondeterministic
        // under the parallel harness. This test asserts the state transition
        // via `audit_writer_degraded()` below instead.
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

    /// An observation of `snapshot` with no policies, for tests that write
    /// rows from an observation.
    fn test_observation(snapshot: SignerSetSnapshotV2) -> ObservationV2 {
        ObservationV2 {
            rule_id: 7,
            smart_account_redacted: "CDABC...12345".to_owned(),
            request_id: "req-test".to_owned(),
            snapshot,
            policies: vec![],
            policy_hashes: WasmHashSummary {
                count: 0,
                first_first8: None,
            },
            ledger: 1000,
            primary_rule: ScVal::Void,
            v1_signers: Ok(vec![]),
        }
    }

    fn ed25519_entry(id: u32, byte: u8) -> SignerEntryV2 {
        SignerEntryV2 {
            id,
            identity: SignerIdentityV2::Ed25519 { pubkey: [byte; 32] },
        }
    }

    /// An observation of two Ed25519 signers (ids 0 and 1) whose version-1
    /// projection is available, with `threshold` and `policies`.
    fn two_signer_observation(
        threshold: Option<ThresholdObservation>,
        policies: Vec<ScAddress>,
    ) -> ObservationV2 {
        let mut observation = test_observation(SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(0, 0x10), ed25519_entry(1, 0x11)],
            threshold,
        });
        observation.v1_signers = Ok(vec![
            (0, SignerPubkey::Ed25519 { pubkey: [0x10; 32] }),
            (1, SignerPubkey::Ed25519 { pubkey: [0x11; 32] }),
        ]);
        observation.policy_hashes = WasmHashSummary {
            count: u32::try_from(policies.len()).unwrap(),
            first_first8: (!policies.is_empty()).then_some([0xab; 8]),
        };
        observation.policies = policies;
        observation
    }

    fn v1_state(threshold: u32, second: u8) -> ObservedSignerSet {
        ObservedSignerSet {
            signer_count: 2,
            threshold,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::Ed25519 { pubkey: [0x10; 32] },
                SignerPubkey::Ed25519 {
                    pubkey: [second; 32],
                },
            ],
        }
    }

    fn policy_address(byte: u8) -> ScAddress {
        ScAddress::Contract(ContractId(Hash([byte; 32])))
    }

    /// A version-1 row compares through the projection: a matching state is
    /// `Matched` with the version-1 view, one changed field is `Diverged`.
    #[test]
    fn classify_against_compares_a_version_1_row_through_the_projection() {
        let observation = two_signer_observation(
            Some(ThresholdObservation {
                policy: [0x66; 32],
                threshold: 2,
            }),
            vec![policy_address(0x66)],
        );
        match classify_against(&SignerSetView::V1(v1_state(2, 0x11)), &observation).unwrap() {
            Classified::Matched { observed } => {
                assert_eq!(observed, SignerSetView::V1(v1_state(2, 0x11)));
            }
            _ => panic!("an equal version-1 state must match"),
        }
        assert!(matches!(
            classify_against(&SignerSetView::V1(v1_state(1, 0x11)), &observation).unwrap(),
            Classified::Diverged { .. }
        ));
        assert!(matches!(
            classify_against(&SignerSetView::V1(v1_state(2, 0x12)), &observation).unwrap(),
            Classified::Diverged { .. }
        ));
    }

    /// A version-1 row meets an observation without a threshold: not
    /// comparable, and the cause names the rule's policy state: no policy,
    /// or policies without a simple-threshold policy.
    #[test]
    fn classify_against_a_version_1_row_without_a_threshold_is_not_comparable() {
        let policyless = two_signer_observation(None, vec![]);
        match classify_against(&SignerSetView::V1(v1_state(2, 0x11)), &policyless).unwrap() {
            Classified::NotComparable { cause } => {
                assert_eq!(cause.wire_code(), "sa.threshold_policy_not_installed");
            }
            _ => panic!("a policyless rule has no version-1 projection"),
        }
        let weighted_only = two_signer_observation(None, vec![policy_address(0x77)]);
        match classify_against(&SignerSetView::V1(v1_state(2, 0x11)), &weighted_only).unwrap() {
            Classified::NotComparable { cause } => {
                assert_eq!(
                    cause.wire_code(),
                    "sa.threshold_policy_identification_failed"
                );
            }
            _ => panic!("a rule without a simple-threshold policy has no projection"),
        }
    }

    /// A version-2 row compares the full snapshot, the threshold's policy
    /// included.
    #[test]
    fn classify_against_compares_a_version_2_row_with_the_full_snapshot() {
        let threshold = |policy: u8| {
            Some(ThresholdObservation {
                policy: [policy; 32],
                threshold: 2,
            })
        };
        let observation = two_signer_observation(threshold(0x66), vec![policy_address(0x66)]);
        let row = |policy: u8| {
            SignerSetView::V2(SignerSetSnapshotV2 {
                signers: vec![ed25519_entry(0, 0x10), ed25519_entry(1, 0x11)],
                threshold: threshold(policy),
            })
        };
        assert!(matches!(
            classify_against(&row(0x66), &observation).unwrap(),
            Classified::Matched {
                observed: SignerSetView::V2(_)
            }
        ));
        assert!(matches!(
            classify_against(&row(0x67), &observation).unwrap(),
            Classified::Diverged { .. }
        ));
    }

    /// Each added identity takes the id it holds on chain, in input order,
    /// whatever order the chain assigned the ids in; an identity the chain
    /// does not hold takes an id no observed entry has.
    #[test]
    fn assign_added_ids_follows_the_input_order() {
        let before = SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(0, 0x10)],
            threshold: None,
        };
        let observed = SignerSetSnapshotV2 {
            signers: vec![
                ed25519_entry(0, 0x10),
                ed25519_entry(7, 0x22),
                ed25519_entry(8, 0x21),
            ],
            threshold: None,
        };
        let added = [
            SignerIdentityV2::Ed25519 { pubkey: [0x21; 32] },
            SignerIdentityV2::Ed25519 { pubkey: [0x22; 32] },
        ];
        assert_eq!(assign_added_ids(&before, &observed, &added), vec![8, 7]);

        let missing = [SignerIdentityV2::Ed25519 { pubkey: [0x23; 32] }];
        assert_eq!(assign_added_ids(&before, &observed, &missing), vec![9]);
    }

    /// An entry whose id the prior set already held is not a new entry, even
    /// when it holds the added identity.
    #[test]
    fn new_entry_id_ignores_an_id_the_prior_set_held() {
        let before = SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(0, 0x10)],
            threshold: None,
        };
        let replaced = SignerSetSnapshotV2 {
            signers: vec![ed25519_entry(0, 0x22)],
            threshold: None,
        };
        assert_eq!(
            new_entry_id(
                &before,
                &replaced,
                &SignerIdentityV2::Ed25519 { pubkey: [0x22; 32] },
                &[]
            ),
            None
        );
    }

    /// A budget refusal renders the behind read as history, and the capped
    /// `sa.baseline_write_failed` reason keeps that read whole at the largest
    /// ledgers, the budget clause after it.
    #[test]
    fn a_budget_refusal_keeps_the_behind_read_within_the_reason_cap() {
        let behind = BehindRead {
            read: "get_context_rule",
            source_kind: "secondary",
            latest_ledger: u32::MAX - 1,
            floor: u32::MAX,
        };
        assert_eq!(
            behind.to_string(),
            "get_context_rule (secondary) was last seen at latestLedger 4294967294, below \
             the confirmation ledger 4294967295"
        );
        let reason = baseline_observe_reason(&behind.refusal(
            "the confirmation_recording budget of 600000 ms leaves no time for another read",
        ));
        // The premise: the full reason exceeds the cap, so the cap cuts it.
        assert_eq!(
            reason.len(),
            crate::error::BASELINE_WRITE_REASON_MAX_BYTES,
            "{reason}"
        );
        assert!(reason.ends_with("..."), "{reason}");
        assert!(
            reason.starts_with("sa.deployment_failed: ") && reason.contains(&behind.to_string()),
            "{reason}"
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

        let signer_set = SignerSetView::V2(SignerSetSnapshotV2 {
            signers: vec![SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0x22; 32] },
            }],
            threshold: None,
        });

        let logs = stellar_agent_test_support::with_captured_logs(|| {
            manager.emit_signer_set_diverged(
                3,
                "CDABC...12345",
                &signer_set,
                &signer_set,
                "req-diverge-poison",
            );
        });
        assert!(
            logs.contains("SaSignerSetDiverged row not written"),
            "missing poison warning: {logs}"
        );
        // Session-degraded warning text: pinned in core audit_log::health
        // (see the sibling baseline test's comment); the state transition is
        // asserted via `audit_writer_degraded()` below.
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

    // ── the version-1 projection ─────────────────────────────────────────────

    /// Decodes `val` and projects it to its version-1 form.
    fn decode_v1(val: &ScVal) -> Result<SignerPubkey, SignerDecodeError> {
        decode_signer_scval_full(val).and_then(|signer| signer.to_signer_pubkey_v1())
    }

    #[test]
    fn to_signer_pubkey_v1_projects_a_delegated_ed25519_signer() {
        // Build a ScVal::Vec([Symbol("Delegated"), Address(Account(pubkey))]).
        use stellar_xdr::{AccountId, ScAddress, ScSymbol, ScVec, Uint256};
        let pubkey = [0x42u8; 32];
        let addr = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pubkey)),
        )));
        let sym = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));

        assert_eq!(
            decode_v1(&vec_val),
            Ok(SignerPubkey::Ed25519 { pubkey }),
            "should decode Delegated signer"
        );
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
            decode_v1(&val),
            Ok(SignerPubkey::Ed25519 { pubkey: [0; 32] })
        );
    }

    #[test]
    fn to_signer_pubkey_v1_keeps_the_first_16_key_data_bytes_of_an_external_signer() {
        let verifier = ScAddress::Contract(ContractId(Hash([0x31; 32])));
        let long = build_external_signer_scval(verifier.clone(), &[0x7e; 40]).unwrap();
        assert_eq!(
            decode_v1(&long),
            Ok(SignerPubkey::External {
                verifier_contract: format!("{}", stellar_strkey::Contract([0x31; 32])),
                key_data_first16: [0x7e; 16],
            })
        );
        let short = build_external_signer_scval(verifier, &[0x5a; 3]).unwrap();
        let mut padded = [0u8; 16];
        padded[..3].copy_from_slice(&[0x5a; 3]);
        assert_eq!(
            decode_v1(&short),
            Ok(SignerPubkey::External {
                verifier_contract: format!("{}", stellar_strkey::Contract([0x31; 32])),
                key_data_first16: padded,
            })
        );
    }

    #[test]
    fn to_signer_pubkey_v1_refuses_a_delegated_contract_signer() {
        use stellar_xdr::{ScSymbol, ScVec};
        let val = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![
                ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap()),
                ScVal::Address(ScAddress::Contract(ContractId(Hash([0x11; 32])))),
            ])
            .unwrap(),
        )));
        assert_eq!(
            decode_v1(&val),
            Err(SignerDecodeError::DelegatedAddressNotAnAccount)
        );
    }

    #[test]
    fn to_identity_v2_keeps_every_signer_in_full() {
        use stellar_xdr::{AccountId, ScSymbol, ScVec};
        let delegated = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![
                ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap()),
                ScVal::Address(ScAddress::Account(AccountId(
                    PublicKey::PublicKeyTypeEd25519(Uint256([0x42; 32])),
                ))),
            ])
            .unwrap(),
        )));
        let contract = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![
                ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap()),
                ScVal::Address(ScAddress::Contract(ContractId(Hash([0x11; 32])))),
            ])
            .unwrap(),
        )));
        let key_data = [0x7e; 40];
        let external = build_external_signer_scval(
            ScAddress::Contract(ContractId(Hash([0x31; 32]))),
            &key_data,
        )
        .unwrap();

        let identity = |val: &ScVal| decode_signer_scval_full(val).unwrap().to_identity_v2();
        assert_eq!(
            identity(&delegated),
            SignerIdentityV2::Ed25519 { pubkey: [0x42; 32] }
        );
        assert_eq!(
            identity(&contract),
            SignerIdentityV2::DelegatedContract {
                contract: [0x11; 32]
            }
        );
        assert_eq!(
            identity(&external),
            SignerIdentityV2::External {
                verifier: [0x31; 32],
                key_data_sha256: Sha256::digest(key_data).into(),
                key_data_len: 40,
            }
        );
    }

    #[test]
    fn decode_signer_scval_full_refuses_an_unknown_tag() {
        use stellar_xdr::{AccountId, ScAddress, ScSymbol, ScVec, Uint256};
        let sym = ScVal::Symbol(ScSymbol::try_from("UnknownTag").unwrap());
        let addr = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])),
        )));
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));
        assert!(matches!(
            decode_signer_scval_full(&vec_val),
            Err(SignerDecodeError::UnknownTag { tag }) if tag == "UnknownTag"
        ));
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

    // ── Held-lock contexts in the submit path ─────────────────────────────────

    /// The smart account the held-lock context tests submit for.
    const LOCK_TEST_ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    /// A second smart account, whose guards the account check refuses.
    fn other_lock_test_account() -> String {
        stellar_strkey::Contract([0x77; 32])
            .to_string()
            .as_str()
            .to_owned()
    }

    /// A URL the submit path never dials: every refusal below lands before
    /// network I/O.
    const LOCK_TEST_RPC: &str = "http://rule-locks-must-not-be-dialed.invalid";

    /// A signers manager over a fresh audit log, with the directory that
    /// holds the log.
    fn lock_test_manager() -> (Arc<SignersManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(
            AuditWriter::open(log_path.clone(), None).unwrap(),
        ));
        let manager = crate::test_helpers::signers_manager_for_tests(
            LOCK_TEST_RPC,
            LOCK_TEST_RPC,
            writer,
            log_path,
            std::time::Duration::from_secs(5),
        );
        (manager, dir)
    }

    /// Submits `noop` on [`LOCK_TEST_ACCOUNT`] under `rule_ids`, with the
    /// drift check through `manager` when `checked`, and `rule_locks`.
    async fn submit_with_rule_locks(
        manager: &SignersManager,
        rule_ids: &[u32],
        checked: bool,
        rule_locks: &BorrowedRuleLocks<'_>,
    ) -> Result<crate::submit::SubmitInvokeResult, SaError> {
        let signer = stellar_agent_network::SoftwareSigningKey::new_from_bytes([0x51; 32]);
        let rule_ids: Vec<ContextRuleId> =
            rule_ids.iter().copied().map(ContextRuleId::new).collect();
        let host_function = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: crate::managers::rules::parse_c_strkey_to_smart_account(
                LOCK_TEST_ACCOUNT,
            )
            .unwrap(),
            function_name: ScSymbol::try_from("noop").unwrap(),
            args: VecM::default(),
        });
        crate::submit::submit_signed_invoke(
            crate::submit::SubmitInvokeArgs::builder()
                .target_contract(LOCK_TEST_ACCOUNT)
                .auth_rule_ids(&rule_ids)
                .host_function(host_function)
                .signer(&signer)
                .primary_rpc_url(LOCK_TEST_RPC)
                .network_passphrase(stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE)
                .chain_id("stellar:testnet")
                .timeout(std::time::Duration::from_secs(5))
                .op_label("rule_locks_unit")
                .maybe_pin_check(checked.then_some(crate::submit::PinCheck {
                    signers_manager: manager,
                    request_id: "req-rule-locks",
                    migrating_rule: None,
                }))
                .rule_locks(rule_locks)
                .build(),
        )
        .await
    }

    fn lock_test_budget() -> PreSubmitBudget {
        PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(5),
            total: std::time::Duration::from_secs(5),
        }
    }

    /// A held-lock context that holds no guard for a rule the submission
    /// names refuses at stage `rule_lock_missing` naming that rule, before
    /// any network I/O; the submit path acquires nothing in its place.
    #[tokio::test]
    async fn a_held_lock_context_without_a_named_rule_refuses_rule_lock_missing() {
        let (manager, _dir) = lock_test_manager();
        let guards = manager
            .acquire_rule_locks(LOCK_TEST_ACCOUNT, [1], lock_test_budget())
            .await
            .unwrap();
        let rule_locks = borrowed(&guards, &[]);

        let err = submit_with_rule_locks(&manager, &[1, 2], true, &rule_locks)
            .await
            .unwrap_err();
        match &err {
            SaError::AuthEntryConstructionFailed {
                stage,
                redacted_reason,
            } => {
                assert_eq!(*stage, "rule_lock_missing");
                assert_eq!(
                    redacted_reason,
                    "rule 2: the submission names an auth rule the caller holds no lock for"
                );
            }
            other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
        }
    }

    /// A guard for another account never stands in for the submission's
    /// account: the context's guard of rule 1 on a second account refuses
    /// rule 1 at stage `rule_lock_missing`.
    #[tokio::test]
    async fn a_held_lock_context_for_another_account_refuses_rule_lock_missing() {
        let (manager, _dir) = lock_test_manager();
        let guards = manager
            .acquire_rule_locks(&other_lock_test_account(), [1], lock_test_budget())
            .await
            .unwrap();
        let rule_locks = borrowed(&guards, &[]);

        let err = submit_with_rule_locks(&manager, &[1], true, &rule_locks)
            .await
            .unwrap_err();
        match &err {
            SaError::AuthEntryConstructionFailed {
                stage,
                redacted_reason,
            } => {
                assert_eq!(*stage, "rule_lock_missing");
                assert!(redacted_reason.starts_with("rule 1: "), "{redacted_reason}");
            }
            other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
        }
    }

    /// A guard taken through a manager over another audit log never stands
    /// in for the checking manager's lock: a context acquired through one
    /// manager and submitted with another's drift check refuses rule 1 at
    /// stage `rule_lock_missing`.
    #[tokio::test]
    async fn a_held_lock_context_from_another_log_refuses_rule_lock_missing() {
        let (lending, _lending_dir) = lock_test_manager();
        let (checking, _checking_dir) = lock_test_manager();
        let guards = lending
            .acquire_rule_locks(LOCK_TEST_ACCOUNT, [1], lock_test_budget())
            .await
            .unwrap();
        let rule_locks = borrowed(&guards, &[]);

        let err = submit_with_rule_locks(&checking, &[1], true, &rule_locks)
            .await
            .unwrap_err();
        match &err {
            SaError::AuthEntryConstructionFailed {
                stage,
                redacted_reason,
            } => {
                assert_eq!(*stage, "rule_lock_missing");
                assert!(redacted_reason.starts_with("rule 1: "), "{redacted_reason}");
            }
            other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
        }
    }

    /// A held-lock context without a drift check refuses at stage
    /// `rule_locks_without_pin_check`, whatever the auth rules are.
    #[tokio::test]
    async fn a_held_lock_context_without_a_pin_check_refuses() {
        let (manager, _dir) = lock_test_manager();
        let guards = manager
            .acquire_rule_locks(LOCK_TEST_ACCOUNT, [1, 2], lock_test_budget())
            .await
            .unwrap();
        let rule_locks = borrowed(&guards, &[]);

        for rule_ids in [&[1, 2][..], &[0][..]] {
            let err = submit_with_rule_locks(&manager, rule_ids, false, &rule_locks)
                .await
                .unwrap_err();
            match &err {
                SaError::AuthEntryConstructionFailed { stage, .. } => {
                    assert_eq!(*stage, "rule_locks_without_pin_check", "{rule_ids:?}");
                }
                other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
            }
        }
    }

    /// One acquisition locks its rules sorted and deduplicated, and a second
    /// acquisition of an overlapping set waits for the first and refuses at
    /// stage `rule_lock` when its budget ends, releasing what it took.
    #[tokio::test]
    async fn rule_lock_acquisition_is_sorted_and_bounded() {
        let (manager, _dir) = lock_test_manager();
        let held = manager
            .acquire_rule_locks(LOCK_TEST_ACCOUNT, [3, 1, 3], lock_test_budget())
            .await
            .unwrap();
        assert_eq!(
            held.iter().map(RuleLockGuard::rule_id).collect::<Vec<_>>(),
            vec![1, 3]
        );

        let short = PreSubmitBudget {
            deadline: tokio::time::Instant::now() + std::time::Duration::from_millis(50),
            total: std::time::Duration::from_millis(50),
        };
        let err = manager
            .acquire_rule_locks(LOCK_TEST_ACCOUNT, [2, 3], short)
            .await
            .err()
            .expect("rule 3 is held");
        match &err {
            SaError::AuthEntryConstructionFailed {
                stage,
                redacted_reason,
            } => {
                assert_eq!(*stage, "rule_lock");
                assert_eq!(
                    redacted_reason,
                    "rule 3: the rule lock was not acquired within its budget"
                );
            }
            other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
        }
        // The refused acquisition released rule 2, which it had taken.
        let rule_two = manager
            .acquire_rule_lock(LOCK_TEST_ACCOUNT, 2, short)
            .await
            .expect("rule 2 was released");
        drop(rule_two);

        drop(held);
        manager
            .acquire_rule_locks(LOCK_TEST_ACCOUNT, [2, 3], lock_test_budget())
            .await
            .expect("the locks are free once the holder drops them");
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
        // ScAddress::Contract takes ContractId(Hash(...)); `ContractId` is a
        // newtype over `Hash` in `Stellar-contract.x`.
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
        // ScVal::ContractInstance takes ScContractInstance directly
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
    /// used by `fetch_observed_executable`) and
    /// `fetch_contract_wasm_hashes` (the multi-key batch primitive used by
    /// `identify_spending_limit_policy`) extract an IDENTICAL 32-byte WASM hash from
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
    ///   (`ContractExecutable::StellarAsset` in `Stellar-contract.x`);
    ///   the network primitive returns `WasmHashFetch::Sac` and the multi-key
    ///   primitive returns `None` — both agree "not a plain WASM hash"
    ///   (`wasm_hash_parse_parity_network_vs_smart_account_sac`).
    ///
    /// The remaining nominal variants — `Divergent` (two-RPC disagreement) and
    /// `Unavailable` (fetch error) — are covered at the shared network-primitive
    /// level by `wasm_hash.rs` unit tests; `fetch_observed_executable` maps those
    /// errors to `SaError::NetworkRpcDivergence` / `SaError::DeploymentFailed`.
    ///
    /// If this test fails after a parser change in either crate, the unification
    /// in `fetch_observed_executable` must be revisited before sealing.
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
    /// `ContractExecutable::StellarAsset` (the `ContractExecutable` union in
    /// `Stellar-contract.x`).  Both parsers
    /// must agree it is NOT a plain WASM hash:
    ///
    /// - **Network primitive** (`fetch_contract_wasm_hash`) → `WasmHashFetch::Sac`
    /// - **Smart-account primitive** (`fetch_contract_wasm_hashes`) → `None` for
    ///   that entry (a `StellarAsset` executable has no Wasm hash and no tag
    ///   entry to resolve, so the aligned-result vector yields `None`).
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
        // `ContractExecutable::StellarAsset` is the Stellar Asset Contract arm
        // of the `ContractExecutable` union in `Stellar-contract.x`.
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
        // Expected: WasmHashFetch::Sac — the explicit SAC variant.
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
        // Expected: None; a StellarAsset executable has no Wasm hash and no
        // tag entry to resolve, so its aligned position stays None.
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
             (no Wasm hash, no tag entry); got {sa_entry:?}"
        );

        // ── Agreement assertion ──────────────────────────────────────────────
        // Both parsers agree: this is NOT a plain WASM hash.
        // Network → Sac (explicit); smart-account → None (no hash).
        // Neither returns a 32-byte hash, confirming no false-positive extraction.
    }

    // ── fetch_observed_executable, observe_contract and the batch fetch ──

    const EXTERNAL_REF_CONTRACT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    const EXTERNAL_REF_OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    fn external_ref_responder(
        resolved: [u8; 32],
    ) -> stellar_agent_test_support::KeyedLedgerEntriesResponder {
        use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};

        KeyedLedgerEntriesResponder::new()
            .with_entry(xdr_fixtures::ledger_entry_from_response_json(
                &xdr_fixtures::external_ref_instance_ledger_entries_json(
                    EXTERNAL_REF_CONTRACT,
                    EXTERNAL_REF_OWNER,
                    b"verifier",
                ),
            ))
            .with_entry(xdr_fixtures::ledger_entry_from_response_json(
                &xdr_fixtures::executable_tag_ledger_entries_json(
                    EXTERNAL_REF_OWNER,
                    b"verifier",
                    resolved,
                ),
            ))
    }

    fn external_ref_contract_scaddress() -> ScAddress {
        ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(
            stellar_strkey::Contract::from_string(EXTERNAL_REF_CONTRACT)
                .expect("contract")
                .0,
        )))
    }

    fn external_ref_instance_key() -> LedgerKey {
        LedgerKey::ContractData(stellar_xdr::LedgerKeyContractData {
            contract: external_ref_contract_scaddress(),
            key: ScVal::LedgerKeyContractInstance,
            durability: stellar_xdr::ContractDataDurability::Persistent,
        })
    }

    fn manager_for(uri: &str) -> (SignersManager, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None)
                .expect("AuditWriter::open must succeed"),
        ));
        let manager = SignersManager::new(SignersManagerConfig::new(
            uri.to_owned(),
            uri.to_owned(),
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(5),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager construction must succeed");
        (manager, dir)
    }

    /// An external-reference contract is observed, not refused: the fetch
    /// reports the owner, the tag and the resolved hash for either contract
    /// kind, and the effective hash is the resolved hash.
    #[tokio::test]
    async fn fetch_observed_executable_reports_external_ref_for_each_kind() {
        let allowlisted = crate::VERIFIER_ALLOWLIST[0].wasm_hash;
        for kind in [ContractKind::Verifier, ContractKind::Policy] {
            let server1 = external_ref_responder(allowlisted).serve().await;
            let primary = StellarRpcClient::new(&server1.uri()).expect("client");
            let server2 = external_ref_responder(allowlisted).serve().await;
            let secondary = StellarRpcClient::new(&server2.uri()).expect("client");

            let observed = fetch_observed_executable(
                &primary,
                &secondary,
                &external_ref_contract_scaddress(),
                kind,
                Some(7),
                "CSMART...ACCNT",
                "req-1",
            )
            .await
            .unwrap_or_else(|e| panic!("{kind}: external reference must be observed: {e}"));

            let ObservedExecutable::ExternalRef(external) = &observed else {
                panic!("{kind}: expected ExternalRef, got {observed:?}");
            };
            assert_eq!(external.owner_redacted(), "GAAAA...AAWHF");
            assert_eq!(external.tag_display(), "verifier");
            assert_eq!(external.resolved, Some(allowlisted));
            assert_eq!(observed.effective_hash(), Some(allowlisted));
            assert_eq!(
                observed.summary(),
                format!(
                    "external reference owner GAAAA...AAWHF tag \"verifier\" resolved {}",
                    hash_first8_hex(&allowlisted)
                )
            );
        }
    }

    /// A malformed instance entry is refused with reason `UndecodableInstance`,
    /// never read as absent.
    #[tokio::test]
    async fn fetch_observed_executable_refuses_malformed_entry_as_undecodable_instance() {
        use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};

        let mut instance = xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::contract_instance_ledger_entries_json(EXTERNAL_REF_CONTRACT, [1; 32]),
        );
        instance["xdr"] = serde_json::Value::String("AAAA////".to_owned());
        let responder = KeyedLedgerEntriesResponder::new().with_entry(instance);
        let server1 = responder.clone().serve().await;
        let primary = StellarRpcClient::new(&server1.uri()).expect("client");
        let server2 = responder.serve().await;
        let secondary = StellarRpcClient::new(&server2.uri()).expect("client");

        let result = fetch_observed_executable(
            &primary,
            &secondary,
            &external_ref_contract_scaddress(),
            ContractKind::Verifier,
            Some(7),
            "CSMART...ACCNT",
            "req-1",
        )
        .await;

        assert!(
            matches!(
                result,
                Err(SaError::ContractInstanceUnsupported {
                    reason: AdminOrOwnerKey::UndecodableInstance,
                    contract_kind: ContractKind::Verifier,
                    ..
                })
            ),
            "expected ContractInstanceUnsupported(UndecodableInstance); got {result:?}"
        );
    }

    /// `ObservedExecutable` renders the bounded summary for each kind and
    /// reports no effective hash for no code or an unresolved reference.
    #[test]
    fn observed_executable_summary_and_effective_hash() {
        let wasm = ObservedExecutable::Wasm([7u8; 32]);
        assert_eq!(wasm.summary(), "wasm");
        assert_eq!(wasm.effective_hash(), Some([7u8; 32]));
        assert_eq!(ObservedExecutable::NoCode.summary(), "no code");
        assert_eq!(ObservedExecutable::NoCode.effective_hash(), None);
        let unresolved =
            ObservedExecutable::ExternalRef(stellar_agent_network::ExternalRefExecutable {
                owner: ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash([0u8; 32]))),
                tag: stellar_xdr::ScString("v\u{202e}1".as_bytes().to_vec().try_into().unwrap()),
                resolved: None,
            });
        assert_eq!(unresolved.effective_hash(), None);
        assert_eq!(
            unresolved.summary(),
            "external reference owner CAAAA...ABSC4 tag \"v\\u{202e}1\" resolved unset"
        );
    }

    /// `observe_contract` identifies an external reference by the hash its tag
    /// resolves to: an allowlisted resolved hash is allowlisted, and the
    /// observation keeps the reference.
    #[tokio::test]
    async fn observe_contract_accepts_allowlisted_resolved_hash() {
        let allowlisted = crate::VERIFIER_ALLOWLIST[0].wasm_hash;
        let server = external_ref_responder(allowlisted).serve().await;
        let (manager, _dir) = manager_for(&server.uri());

        let observation = manager
            .observe_contract(
                &external_ref_contract_scaddress(),
                ContractKind::Verifier,
                verifier_hash_allowlisted,
                Some(7),
                "CSMART...ACCNT",
                "req-1",
            )
            .await
            .expect("resolved reference is observed");

        assert!(observation.allowlisted);
        assert_eq!(observation.effective_hash, allowlisted);
        assert_eq!(
            observation.observed_hash_first8(),
            hash_first8_hex(&allowlisted)
        );
        assert!(matches!(
            observation.observed,
            ObservedExecutable::ExternalRef(ref external) if external.resolved == Some(allowlisted)
        ));
    }

    /// A resolved hash outside the allowlist is reported as
    /// `allowlisted: false` with the resolved hash, so the caller's
    /// unknown-hash override applies.
    #[tokio::test]
    async fn observe_contract_reports_non_allowlisted_resolved_hash() {
        let unknown = [0xd1u8; 32];
        let server = external_ref_responder(unknown).serve().await;
        let (manager, _dir) = manager_for(&server.uri());

        let observation = manager
            .observe_contract(
                &external_ref_contract_scaddress(),
                ContractKind::Policy,
                policy_hash_allowlisted,
                Some(7),
                "CSMART...ACCNT",
                "req-1",
            )
            .await
            .expect("resolved reference is observed");

        assert!(!observation.allowlisted);
        assert_eq!(observation.effective_hash, unknown);
        assert_eq!(observation.observed_hash_first8(), "d1d1d1d1d1d1d1d1");
    }

    /// An external reference with no live tag entry is refused with
    /// `ContractInstanceUnsupported { reason: ExternalRefUnresolved }` before
    /// any allowlist decision, for either contract kind.
    #[tokio::test]
    async fn observe_contract_refuses_unresolved_external_ref() {
        use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};

        let server = KeyedLedgerEntriesResponder::new()
            .with_entry(xdr_fixtures::ledger_entry_from_response_json(
                &xdr_fixtures::external_ref_instance_ledger_entries_json(
                    EXTERNAL_REF_CONTRACT,
                    EXTERNAL_REF_OWNER,
                    b"verifier",
                ),
            ))
            .serve()
            .await;
        let (manager, _dir) = manager_for(&server.uri());

        for kind in [ContractKind::Verifier, ContractKind::Policy] {
            let result = manager
                .observe_contract(
                    &external_ref_contract_scaddress(),
                    kind,
                    |_| true,
                    Some(7),
                    "CSMART...ACCNT",
                    "req-1",
                )
                .await;
            let Err(SaError::ContractInstanceUnsupported {
                rule_id,
                contract_kind,
                contract_address_redacted,
                reason,
                request_id,
                ..
            }) = result
            else {
                panic!("{kind}: expected ContractInstanceUnsupported; got {result:?}");
            };
            assert_eq!(reason, AdminOrOwnerKey::ExternalRefUnresolved);
            assert_eq!(contract_kind, kind);
            assert_eq!(rule_id, Some(7));
            assert_eq!(request_id, "req-1");
            assert_eq!(contract_address_redacted.as_str(), "CAAAA...AD2KM");
        }
    }

    /// The batch fetch resolves an external reference through the owner's tag
    /// entry and returns the resolved hash in the reference's position,
    /// beside a Wasm instance and an absent contract.
    #[tokio::test]
    async fn fetch_contract_wasm_hashes_resolves_external_ref_in_position() {
        use stellar_agent_test_support::xdr_fixtures;

        const WASM_CONTRACT: &str = "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526";
        const ABSENT_CONTRACT: &str = "CABAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAFNSZ";
        let resolved = [0x5au8; 32];
        let wasm_hash = [0x6bu8; 32];
        let server = external_ref_responder(resolved)
            .with_entry(xdr_fixtures::ledger_entry_from_response_json(
                &xdr_fixtures::contract_instance_ledger_entries_json(WASM_CONTRACT, wasm_hash),
            ))
            .serve()
            .await;
        let client = StellarRpcClient::new(&server.uri()).expect("client");
        let key_for = |strkey: &str| {
            LedgerKey::ContractData(stellar_xdr::LedgerKeyContractData {
                contract: ScAddress::Contract(stellar_xdr::ContractId(stellar_xdr::Hash(
                    stellar_strkey::Contract::from_string(strkey)
                        .expect("contract")
                        .0,
                ))),
                key: ScVal::LedgerKeyContractInstance,
                durability: stellar_xdr::ContractDataDurability::Persistent,
            })
        };
        let results = fetch_contract_wasm_hashes(
            &client,
            &[
                key_for(WASM_CONTRACT),
                key_for(ABSENT_CONTRACT),
                external_ref_instance_key(),
            ],
        )
        .await
        .expect("batch fetch succeeds");

        assert_eq!(results, vec![Some(wasm_hash), None, Some(resolved)]);
    }

    /// The batch fetch yields `None` for an external reference whose tag entry
    /// is not live, does not decode, or does not hold a 32-byte hash.
    #[tokio::test]
    async fn fetch_contract_wasm_hashes_yields_none_for_unresolved_or_malformed_tag_entry() {
        use stellar_agent_test_support::{KeyedLedgerEntriesResponder, xdr_fixtures};

        let instance = xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::external_ref_instance_ledger_entries_json(
                EXTERNAL_REF_CONTRACT,
                EXTERNAL_REF_OWNER,
                b"verifier",
            ),
        );
        let short_value = xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::executable_tag_ledger_entries_json_with_value(
                EXTERNAL_REF_OWNER,
                b"verifier",
                ScVal::Bytes(ScBytes(vec![1u8; 31].try_into().unwrap())),
            ),
        );
        let mut undecodable = xdr_fixtures::ledger_entry_from_response_json(
            &xdr_fixtures::executable_tag_ledger_entries_json(
                EXTERNAL_REF_OWNER,
                b"verifier",
                [1u8; 32],
            ),
        );
        undecodable["xdr"] = serde_json::Value::String("AAAA////".to_owned());

        for (case, responder) in [
            (
                "no live tag entry",
                KeyedLedgerEntriesResponder::new().with_entry(instance.clone()),
            ),
            (
                "31-byte tag value",
                KeyedLedgerEntriesResponder::new()
                    .with_entry(instance.clone())
                    .with_entry(short_value),
            ),
            (
                "undecodable tag entry",
                KeyedLedgerEntriesResponder::new()
                    .with_entry(instance)
                    .with_entry(undecodable),
            ),
        ] {
            let server = responder.serve().await;
            let client = StellarRpcClient::new(&server.uri()).expect("client");
            let results = fetch_contract_wasm_hashes(&client, &[external_ref_instance_key()])
                .await
                .unwrap_or_else(|e| panic!("{case}: batch fetch succeeds: {e}"));
            assert_eq!(results, vec![None], "{case}");
        }
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

    /// A 10 KiB `ScVal::String` payload: an untrusted ledger value far larger
    /// than any error reason may be.
    pub(crate) fn large_string_scval() -> ScVal {
        let payload = "Z".repeat(10 * 1024);
        ScVal::String(stellar_xdr::ScString(
            payload
                .into_bytes()
                .try_into()
                .expect("10 KiB fits an ScString"),
        ))
    }

    /// Asserts a `DeploymentFailed` reason at phase `simulate` is bounded,
    /// equals `expected` and carries no byte of the `large_string_scval`
    /// payload.
    fn assert_bounded_string_reason(err: SaError, expected: &str) {
        let SaError::DeploymentFailed {
            phase,
            redacted_reason,
        } = err
        else {
            panic!("expected DeploymentFailed, got {err:?}");
        };
        assert_eq!(phase, "simulate");
        assert!(
            redacted_reason.len() < 256,
            "reason is {} bytes",
            redacted_reason.len()
        );
        assert_eq!(redacted_reason, expected);
        assert!(!redacted_reason.contains("ZZZZ"));
    }

    /// `extract_u32_return` names the variant of an unexpected return value
    /// and never renders the value, so a large payload yields a short reason.
    #[test]
    fn extract_u32_return_large_string_payload_reason_is_bounded() {
        let err = extract_u32_return(&large_string_scval(), "add_signer")
            .expect_err("a String return must fail closed");
        assert_bounded_string_reason(err, "add_signer: expected ScVal::U32 return, got String");
    }

    /// `decode_context_rule_scval` names the variant of an unexpected rule
    /// value and never renders the value, so a large payload yields a short
    /// reason.
    #[test]
    fn decode_context_rule_scval_large_string_payload_reason_is_bounded() {
        let Err(err) = decode_context_rule_scval(large_string_scval()) else {
            panic!("a String rule value must fail closed");
        };
        assert_bounded_string_reason(err, "get_context_rule: expected ScVal::Map, got String");
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
        let Ok(decoded) = decode_signer_scval_full(&val) else {
            panic!("decode_signer_scval_full must decode a well-formed External ScVal");
        };

        match decoded {
            DecodedOnChainSigner::External {
                verifier_strkey,
                verifier_address,
                key_data: decoded_key,
            } => {
                assert_eq!(
                    verifier_address,
                    ScAddress::Contract(ContractId(Hash([0x77u8; 32]))),
                    "verifier_address must be the verbatim verifier ScAddress"
                );
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
            DecodedOnChainSigner::Delegated { .. }
            | DecodedOnChainSigner::DelegatedContract { .. } => {
                panic!("expected External variant, got a delegated signer")
            }
        }
    }

    /// `build_external_signer_scval` encodes empty `key_data` (the OZ contract
    /// does not forbid it at encoding time), and the decoder refuses such a
    /// signer, naming the empty key data: no verifier checks a signature
    /// against no key, and a version-2 identity is never empty.
    #[test]
    fn build_external_signer_scval_empty_key_data_encodes_and_the_decoder_refuses_it() {
        use stellar_xdr::{ContractId, Hash, ScAddress};

        let verifier_sc_addr = ScAddress::Contract(ContractId(Hash([0x33u8; 32])));
        let encoded = build_external_signer_scval(verifier_sc_addr, &[])
            .expect("build_external_signer_scval with empty key_data must succeed");
        assert!(matches!(
            decode_signer_scval_full(&encoded),
            Err(SignerDecodeError::ExternalKeyDataEmpty)
        ));
    }

    /// A rule holding an `External` signer with empty key data refuses the
    /// whole rule with the per-index reason.
    #[test]
    fn decode_context_rule_scval_refuses_an_external_signer_with_empty_key_data() {
        let empty =
            build_external_signer_scval(ScAddress::Contract(ContractId(Hash([0x33u8; 32]))), &[])
                .unwrap();
        let val = rule_with_signer_lists(
            vec![ScVal::U32(0), ScVal::U32(5)],
            vec![delegated_signer(0xaa), empty],
        );
        assert_eq!(
            refused_rule_reason(val),
            "get_context_rule: signer at index 1 (id 5) is not a recognised Signer: \
             External signer key data is empty"
        );
    }

    // ── decode_signer_scval_full ──────────────────────────────────────────────

    /// `decode_signer_scval_full` refuses a value that is not a `ScVal::Vec`,
    /// naming its variant.
    #[test]
    fn decode_signer_scval_full_refuses_a_non_vec() {
        assert_eq!(
            decode_signer_scval_full(&ScVal::Void).err(),
            Some(SignerDecodeError::NotAVec { variant: "Void" })
        );
        assert_eq!(
            decode_signer_scval_full(&ScVal::U32(1)).err(),
            Some(SignerDecodeError::NotAVec { variant: "U32" })
        );
    }

    /// `decode_signer_scval_full` refuses a Vec with fewer than 2 elements
    /// (minimum required: tag + at least one payload field); an absent Vec
    /// body counts as zero elements.
    #[test]
    fn decode_signer_scval_full_refuses_a_short_vec() {
        use stellar_xdr::{ScSymbol, ScVec};

        assert_eq!(
            decode_signer_scval_full(&ScVal::Vec(None)).err(),
            Some(SignerDecodeError::TooFewItems { count: 0 })
        );

        let empty = ScVal::Vec(Some(ScVec(VecM::try_from(vec![]).unwrap())));
        assert_eq!(
            decode_signer_scval_full(&empty).err(),
            Some(SignerDecodeError::TooFewItems { count: 0 })
        );

        // Vec with exactly 1 element (symbol only, no payload).
        let sym = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let one_elem = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym]).unwrap())));
        assert_eq!(
            decode_signer_scval_full(&one_elem).err(),
            Some(SignerDecodeError::TooFewItems { count: 1 })
        );
    }

    /// `decode_signer_scval_full` refuses a Vec whose first element, the
    /// variant tag, is not a Symbol.
    #[test]
    fn decode_signer_scval_full_refuses_a_non_symbol_tag() {
        use stellar_xdr::ScVec;

        let elem0 = ScVal::U32(42); // not a Symbol
        let elem1 = ScVal::U32(0);
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![elem0, elem1]).unwrap())));
        assert_eq!(
            decode_signer_scval_full(&vec_val).err(),
            Some(SignerDecodeError::TagNotASymbol { variant: "U32" })
        );
    }

    /// `decode_signer_scval_full` refuses the `External` variant when fewer
    /// than 3 elements are present (missing `Bytes` payload).
    #[test]
    fn decode_signer_scval_full_refuses_a_two_item_external() {
        use stellar_xdr::{AccountId, ScAddress, ScSymbol, ScVec, Uint256};

        let sym = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        // Provide Address but omit Bytes — 2-element External vec.
        let addr = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([0u8; 32])),
        )));
        let two_elem = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));
        assert_eq!(
            decode_signer_scval_full(&two_elem).err(),
            Some(SignerDecodeError::ExternalTooFewItems { count: 2 })
        );
    }

    /// `decode_signer_scval_full` decodes a `Delegated` signer whose address
    /// is a contract as `DelegatedContract`, keeping the contract id and the
    /// verbatim address.
    #[test]
    fn decode_signer_scval_full_accepts_a_delegated_contract_address() {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScSymbol, ScVec};

        let sym = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let address = ScAddress::Contract(ContractId(Hash([0x11u8; 32])));
        let addr = ScVal::Address(address.clone());
        let vec_val = ScVal::Vec(Some(ScVec(VecM::try_from(vec![sym, addr]).unwrap())));
        match decode_signer_scval_full(&vec_val) {
            Ok(DecodedOnChainSigner::DelegatedContract {
                contract,
                signer_address,
            }) => {
                assert_eq!(contract, [0x11u8; 32]);
                assert_eq!(signer_address, address);
            }
            Ok(_) => panic!("a contract delegate must decode as DelegatedContract"),
            Err(e) => panic!("a contract delegate must decode: {e}"),
        }
    }

    /// `decode_signer_scval_full` refuses an `External` signer whose third
    /// element is not `ScVal::Bytes`.
    #[test]
    fn decode_signer_scval_full_refuses_external_non_bytes_key_data() {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScSymbol, ScVec};

        let sym = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let addr = ScVal::Address(ScAddress::Contract(ContractId(Hash([0x22u8; 32]))));
        let not_bytes = ScVal::U32(99); // wrong type for key_data slot
        let vec_val = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![sym, addr, not_bytes]).unwrap(),
        )));
        assert_eq!(
            decode_signer_scval_full(&vec_val).err(),
            Some(SignerDecodeError::ExternalKeyDataNotBytes { variant: "U32" })
        );
    }

    /// `decode_signer_scval_full` refuses an `External` signer whose second
    /// element is not an `ScVal::Address`.
    #[test]
    fn decode_signer_scval_full_refuses_external_non_address_verifier() {
        use stellar_xdr::{ScBytes, ScSymbol, ScVec};

        let sym = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let not_addr = ScVal::U32(7); // wrong type for verifier slot
        let bytes = ScVal::Bytes(ScBytes(vec![0x01, 0x02].try_into().unwrap()));
        let vec_val = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![sym, not_addr, bytes]).unwrap(),
        )));
        assert_eq!(
            decode_signer_scval_full(&vec_val).err(),
            Some(SignerDecodeError::ExternalVerifierNotAnAddress { variant: "U32" })
        );
    }

    /// `decode_signer_scval_full` refuses an `External` signer whose verifier
    /// address is an account, not a contract.
    #[test]
    fn decode_signer_scval_full_refuses_external_account_verifier() {
        use stellar_xdr::{AccountId, ScAddress, ScBytes, ScSymbol, ScVec, Uint256};

        let sym = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let account = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([0x33u8; 32])),
        )));
        let bytes = ScVal::Bytes(ScBytes(vec![0x01, 0x02].try_into().unwrap()));
        let vec_val = ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![sym, account, bytes]).unwrap(),
        )));
        assert_eq!(
            decode_signer_scval_full(&vec_val).err(),
            Some(SignerDecodeError::ExternalVerifierNotAContract)
        );
    }

    /// Every `SignerDecodeError` renders a fixed text around its bounded field.
    #[test]
    fn signer_decode_error_display_names_the_shape() {
        let cases = [
            (
                SignerDecodeError::NotAVec { variant: "Map" },
                "expected ScVal::Vec, got Map",
            ),
            (
                SignerDecodeError::TooFewItems { count: 1 },
                "expected at least 2 items, got 1",
            ),
            (
                SignerDecodeError::TagNotASymbol { variant: "U32" },
                "tag is not a Symbol: U32",
            ),
            (
                SignerDecodeError::UnknownTag {
                    tag: "Future".to_owned(),
                },
                "unknown signer tag \"Future\"",
            ),
            (
                SignerDecodeError::DelegatedAddressNotAnAccount,
                "Delegated signer address is not an account address",
            ),
            (
                SignerDecodeError::ExternalTooFewItems { count: 2 },
                "External signer expected 3 items, got 2",
            ),
            (
                SignerDecodeError::ExternalVerifierNotAnAddress { variant: "U32" },
                "External verifier is not an Address: U32",
            ),
            (
                SignerDecodeError::ExternalVerifierNotAContract,
                "External verifier address is not a contract address",
            ),
            (
                SignerDecodeError::ExternalKeyDataNotBytes { variant: "Void" },
                "External key data is not Bytes: Void",
            ),
            (
                SignerDecodeError::ExternalKeyDataEmpty,
                "External signer key data is empty",
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(err.to_string(), expected);
        }
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

    /// Builds a `ContextRule` map with id `7` and the given parallel lists.
    fn rule_with_signer_lists(signer_ids: Vec<ScVal>, signers: Vec<ScVal>) -> ScVal {
        use stellar_xdr::ScVec;
        rule_with_entries(vec![
            (
                "signer_ids",
                ScVal::Vec(Some(ScVec(signer_ids.try_into().unwrap()))),
            ),
            (
                "signers",
                ScVal::Vec(Some(ScVec(signers.try_into().unwrap()))),
            ),
        ])
    }

    /// A `Delegated` signer for the ed25519 key `[byte; 32]`.
    fn delegated_signer(byte: u8) -> ScVal {
        use stellar_xdr::{AccountId, ScAddress, ScSymbol, ScVec, Uint256};
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap()),
                ScVal::Address(ScAddress::Account(AccountId(
                    PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
                ))),
            ]
            .try_into()
            .unwrap(),
        )))
    }

    /// A two-item signer whose tag is `tag`.
    fn tagged_signer(tag: ScSymbol) -> ScVal {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScVec};
        ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(tag),
                ScVal::Address(ScAddress::Contract(ContractId(Hash([0x44u8; 32])))),
            ]
            .try_into()
            .unwrap(),
        )))
    }

    /// Returns the `DeploymentFailed` reason of a refused rule decode.
    fn refused_rule_reason(val: ScVal) -> String {
        match decode_context_rule_scval(val) {
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) => {
                assert_eq!(phase, "simulate");
                redacted_reason
            }
            Err(other) => panic!("expected DeploymentFailed, got {other:?}"),
            Ok(rule) => panic!(
                "expected a refusal, got a rule with {} signers",
                rule.signers.len()
            ),
        }
    }

    /// A signer with an unknown `Signer` tag refuses the whole rule: the
    /// observed set must hold every signer of the rule, and the reason names
    /// the signer's index, its id and the tag.
    #[test]
    fn decode_context_rule_scval_refuses_an_unknown_signer() {
        let val = rule_with_signer_lists(
            vec![ScVal::U32(0), ScVal::U32(1)],
            vec![
                delegated_signer(0xaa),
                tagged_signer(ScSymbol::try_from("Future").unwrap()),
            ],
        );
        assert_eq!(
            refused_rule_reason(val),
            "get_context_rule: signer at index 1 (id 1) is not a recognised Signer: \
             unknown signer tag \"Future\""
        );
    }

    /// `signer_ids` and `signers` of different lengths refuse the rule; equal
    /// lists decode every signer with its id.
    #[test]
    fn decode_context_rule_scval_refuses_unequal_signer_lists() {
        let rule = decode_context_rule_scval(rule_with_signer_lists(
            vec![ScVal::U32(4), ScVal::U32(9)],
            vec![delegated_signer(0xaa), delegated_signer(0xbb)],
        ))
        .expect("equal lists of decodable signers must decode");
        assert_eq!(
            rule.identities(),
            vec![
                (4, SignerIdentityV2::Ed25519 { pubkey: [0xaa; 32] }),
                (9, SignerIdentityV2::Ed25519 { pubkey: [0xbb; 32] }),
            ]
        );

        let more_ids = rule_with_signer_lists(
            vec![ScVal::U32(0), ScVal::U32(1), ScVal::U32(2)],
            vec![delegated_signer(0xaa), delegated_signer(0xbb)],
        );
        assert_eq!(
            refused_rule_reason(more_ids),
            "get_context_rule: signer_ids has 3 entries and signers has 2"
        );

        let more_signers = rule_with_signer_lists(
            vec![ScVal::U32(0)],
            vec![delegated_signer(0xaa), delegated_signer(0xbb)],
        );
        assert_eq!(
            refused_rule_reason(more_signers),
            "get_context_rule: signer_ids has 1 entries and signers has 2"
        );
    }

    /// A `signer_ids` item that is not a `u32` refuses the rule, naming its
    /// index and variant.
    #[test]
    fn decode_context_rule_scval_refuses_a_non_u32_signer_id() {
        let val = rule_with_signer_lists(
            vec![ScVal::U32(0), ScVal::I32(1)],
            vec![delegated_signer(0xaa), delegated_signer(0xbb)],
        );
        assert_eq!(
            refused_rule_reason(val),
            "get_context_rule: signer_ids[1] is not a u32: I32"
        );
    }

    /// Builds a `ContextRule` map with id `7` and the given extra entries.
    fn rule_with_entries(entries: Vec<(&str, ScVal)>) -> ScVal {
        use stellar_xdr::{ScMap, ScMapEntry};
        let mut map_entries = vec![ScMapEntry {
            key: ScVal::Symbol(ScSymbol::try_from("id").unwrap()),
            val: ScVal::U32(7),
        }];
        for (key, val) in entries {
            map_entries.push(ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from(key).unwrap()),
                val,
            });
        }
        ScVal::Map(Some(ScMap(map_entries.try_into().unwrap())))
    }

    /// A map without a `signer_ids` or a `signers` key refuses the rule: an
    /// absent list is not an empty one.
    #[test]
    fn decode_context_rule_scval_refuses_a_missing_signer_list() {
        let empty = || ScVal::Vec(Some(stellar_xdr::ScVec(VecM::default())));
        assert_eq!(
            refused_rule_reason(rule_with_entries(vec![("signers", empty())])),
            "get_context_rule: missing 'signer_ids' field in ContextRule map"
        );
        assert_eq!(
            refused_rule_reason(rule_with_entries(vec![("signer_ids", empty())])),
            "get_context_rule: missing 'signers' field in ContextRule map"
        );
    }

    /// A `signer_ids` or `signers` value that is not a `Vec` refuses the rule,
    /// naming its variant; `Vec(None)` is an empty list.
    #[test]
    fn decode_context_rule_scval_refuses_a_non_vec_signer_list() {
        assert_eq!(
            refused_rule_reason(rule_with_entries(vec![
                ("signer_ids", ScVal::U32(1)),
                ("signers", ScVal::Vec(None)),
            ])),
            "get_context_rule: signer_ids is not a Vec: U32"
        );
        assert_eq!(
            refused_rule_reason(rule_with_entries(vec![
                ("signer_ids", ScVal::Vec(None)),
                ("signers", large_string_scval()),
            ])),
            "get_context_rule: signers is not a Vec: String"
        );
        let rule = decode_context_rule_scval(rule_with_entries(vec![
            ("signer_ids", ScVal::Vec(None)),
            ("signers", ScVal::Vec(None)),
        ]))
        .expect("absent Vec bodies are empty lists");
        assert!(rule.signers.is_empty());
    }

    /// A `Delegated` signer whose address is a contract decodes in version 2,
    /// and its version-1 projection, which a version-1 comparison needs,
    /// refuses with the per-index reason.
    #[test]
    fn decode_context_rule_scval_reads_a_delegated_contract_address_in_version_2_only() {
        use stellar_xdr::{ContractId, Hash, ScAddress, ScVec};

        let delegated_contract = ScVal::Vec(Some(ScVec(
            vec![
                ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap()),
                ScVal::Address(ScAddress::Contract(ContractId(Hash([0x55u8; 32])))),
            ]
            .try_into()
            .unwrap(),
        )));
        let val = rule_with_signer_lists(
            vec![ScVal::U32(3), ScVal::U32(8)],
            vec![delegated_signer(0xaa), delegated_contract],
        );
        let rule = decode_context_rule_scval(val).expect("a contract delegate decodes");
        assert_eq!(
            rule.identities(),
            vec![
                (3, SignerIdentityV2::Ed25519 { pubkey: [0xaa; 32] }),
                (
                    8,
                    SignerIdentityV2::DelegatedContract {
                        contract: [0x55; 32]
                    }
                ),
            ]
        );

        let mut observation = test_observation(SignerSetSnapshotV2 {
            signers: rule
                .identities()
                .into_iter()
                .map(|(id, identity)| SignerEntryV2 { id, identity })
                .collect(),
            threshold: Some(ThresholdObservation {
                policy: [0x66; 32],
                threshold: 1,
            }),
        });
        observation.v1_signers = rule
            .signers
            .iter()
            .enumerate()
            .map(|(index, (id, signer))| {
                signer
                    .to_signer_pubkey_v1()
                    .map(|pubkey| (*id, pubkey))
                    .map_err(|e| (index, *id, e))
            })
            .collect();
        match project_v1(&observation) {
            Err(SaError::DeploymentFailed {
                phase,
                redacted_reason,
            }) => {
                assert_eq!(phase, "simulate");
                assert_eq!(
                    redacted_reason,
                    "get_context_rule: signer at index 1 (id 8) is not a recognised Signer: \
                     Delegated signer address is not an account address"
                );
            }
            other => panic!("the version-1 projection must refuse: {other:?}"),
        }
    }

    /// An unknown tag renders through `untrusted_display_bounded`: a 32-byte
    /// tag of control characters yields a bounded, escaped reason.
    #[test]
    fn decode_context_rule_scval_large_unknown_tag_reason_is_bounded() {
        let tag = ScSymbol::try_from(vec![0x1bu8; 32]).expect("32 bytes fit an ScSymbol");
        let val = rule_with_signer_lists(vec![ScVal::U32(0)], vec![tagged_signer(tag)]);
        let Err(err) = decode_context_rule_scval(val) else {
            panic!("an unknown tag must fail closed");
        };
        let expected = format!(
            "get_context_rule: signer at index 0 (id 0) is not a recognised Signer: \
             unknown signer tag \"{}...\"",
            r"\u{1b}".repeat(10)
        );
        assert_bounded_string_reason(err, &expected);
    }

    /// A signer that is a large non-`Vec` value is named by its variant and
    /// never rendered.
    #[test]
    fn decode_context_rule_scval_large_non_vec_signer_reason_is_bounded() {
        let val = rule_with_signer_lists(vec![ScVal::U32(0)], vec![large_string_scval()]);
        let Err(err) = decode_context_rule_scval(val) else {
            panic!("a String signer must fail closed");
        };
        assert_bounded_string_reason(
            err,
            "get_context_rule: signer at index 0 (id 0) is not a recognised Signer: \
             expected ScVal::Vec, got String",
        );
    }

    // ── identity_kind_label ───────────────────────────────────────────────────

    /// `identity_kind_label` returns a distinct label for each version-2
    /// identity kind; a passkey signer is an `External` identity.
    ///
    /// The labels are embedded in `ThresholdUnreachable::requested_op::AddSigner::signer_type`
    /// error messages visible to operators; they must be stable.
    #[test]
    fn identity_kind_label_returns_correct_labels() {
        assert_eq!(
            identity_kind_label(&SignerIdentityV2::Ed25519 { pubkey: [0u8; 32] }),
            "ed25519"
        );
        assert_eq!(
            identity_kind_label(&SignerIdentityV2::External {
                verifier: [0u8; 32],
                key_data_sha256: [0u8; 32],
                key_data_len: 97,
            }),
            "external"
        );
        assert_eq!(
            identity_kind_label(&SignerIdentityV2::DelegatedContract {
                contract: [0u8; 32]
            }),
            "delegated_contract"
        );
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

    // ── WeightedThresholdView ──────────────────────────────────────────────────

    fn weighted_signer_key(byte_fill: u8) -> ScVal {
        let g_strkey = stellar_strkey::ed25519::PublicKey([byte_fill; 32])
            .to_string()
            .as_str()
            .to_owned();
        build_delegated_signer_scval(&g_strkey).expect("build delegated key")
    }

    #[test]
    fn weighted_threshold_view_total_weight_sums_all_entries() {
        let view = WeightedThresholdView {
            threshold: 3,
            signer_weights: vec![(weighted_signer_key(1), 2), (weighted_signer_key(2), 5)],
        };
        assert_eq!(view.total_weight().unwrap(), 7);
    }

    #[test]
    fn weighted_threshold_view_total_weight_refuses_overflow() {
        let view = WeightedThresholdView {
            threshold: 1,
            signer_weights: vec![
                (weighted_signer_key(1), u32::MAX),
                (weighted_signer_key(2), 1),
            ],
        };
        assert!(matches!(
            view.total_weight(),
            Err(SaError::WeightedThresholdInstallRefused { .. })
        ));
    }

    #[test]
    fn weighted_threshold_view_weight_of_returns_zero_for_absent_signer() {
        let present = weighted_signer_key(1);
        let absent = weighted_signer_key(2);
        let view = WeightedThresholdView {
            threshold: 1,
            signer_weights: vec![(present.clone(), 5)],
        };
        assert_eq!(view.weight_of(&present), 5);
        assert_eq!(
            view.weight_of(&absent),
            0,
            "a signer absent from the map contributes zero weight"
        );
    }

    // ── redact_weighted_signer_identity ────────────────────────────────────────

    #[test]
    fn redact_weighted_signer_identity_delegated_is_kind_labelled_and_redacted() {
        let g_strkey = stellar_strkey::ed25519::PublicKey([7u8; 32])
            .to_string()
            .as_str()
            .to_owned();
        let input = crate::weighted_threshold_policy::WeightedThresholdSignerInput::Delegated {
            g_strkey: g_strkey.clone(),
        };
        let redacted = redact_weighted_signer_identity(&input);
        assert!(redacted.starts_with("delegated:"));
        assert!(
            !redacted.contains(&g_strkey),
            "redacted identity must not contain the full G-strkey"
        );
    }

    #[test]
    fn redact_weighted_signer_identity_external_is_kind_labelled() {
        let verifier = ScAddress::Contract(ContractId(Hash([9u8; 32])));
        let input = crate::weighted_threshold_policy::WeightedThresholdSignerInput::External {
            verifier,
            key_data: vec![0xAAu8; 32],
        };
        let redacted = redact_weighted_signer_identity(&input);
        assert!(redacted.starts_with("external:"));
    }

    // ── batch_add_signers: empty-batch refusal ────────────────────────────────

    /// Minimal `Signer` stub for the empty-batch test, which must refuse
    /// before ever calling into the signer or the network.
    struct UnreachableSigner;

    #[async_trait::async_trait]
    impl stellar_agent_network::signing::Signer for UnreachableSigner {
        async fn sign_tx_payload(
            &self,
            _: &[u8; 32],
        ) -> Result<[u8; 64], stellar_agent_core::error::WalletError> {
            unimplemented!("stub — must not be called by the empty-batch refusal test")
        }
        async fn sign_auth_digest(
            &self,
            _: &[u8; 32],
        ) -> Result<[u8; 64], stellar_agent_core::error::WalletError> {
            unimplemented!("stub — must not be called by the empty-batch refusal test")
        }
        async fn sign_soroban_address_auth_payload(
            &self,
            _: &[u8; 32],
        ) -> Result<[u8; 64], stellar_agent_core::error::WalletError> {
            unimplemented!("stub — must not be called by the empty-batch refusal test")
        }
        async fn sign_webauthn_assertion(
            &self,
            _: &[u8; 32],
            _: &[u8],
        ) -> Result<
            stellar_agent_network::signing::WebAuthnAssertion,
            stellar_agent_core::error::WalletError,
        > {
            unimplemented!("stub — must not be called by the empty-batch refusal test")
        }
        async fn public_key(
            &self,
        ) -> Result<stellar_strkey::ed25519::PublicKey, stellar_agent_core::error::WalletError>
        {
            unimplemented!("stub — must not be called by the empty-batch refusal test")
        }
    }

    /// `batch_add_signers` with an empty `new_signers` vec must refuse with
    /// `SaError::BatchSignerAddRefused` before acquiring the per-rule mutex,
    /// touching the audit log, or making any network call — the guard lives
    /// in the public manager function itself, not only at the CLI layer.
    #[tokio::test]
    async fn batch_add_signers_refuses_empty_batch_before_any_io() {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let audit_log_path = dir.path().join("audit.jsonl");
        let audit_writer = Arc::new(Mutex::new(
            AuditWriter::open(audit_log_path.clone(), None)
                .expect("AuditWriter::open must succeed"),
        ));

        // Deliberately unreachable RPC endpoints and a nonexistent audit-log
        // baseline: if the guard did not fire before any I/O, this test
        // would fail on the network call or the missing baseline instead of
        // asserting the refusal reason.
        let manager = SignersManager::new(SignersManagerConfig::new(
            "http://127.0.0.1:1".to_owned(),
            "http://127.0.0.1:1".to_owned(),
            audit_writer,
            audit_log_path,
            "Test SDF Network ; September 2015".to_owned(),
            "test-profile".to_owned(),
            Duration::from_secs(1),
            "stellar:testnet".to_owned(),
        ))
        .expect("manager construction must succeed");

        let smart_account = ScAddress::Contract(ContractId(Hash([1u8; 32])));
        let result = manager
            .batch_add_signers(
                smart_account,
                7,
                Vec::new(),
                &UnreachableSigner,
                "req-empty-batch".to_owned(),
                false,
                false,
            )
            .await;

        match result {
            Err(SaError::BatchSignerAddRefused { reason }) => {
                assert!(
                    reason.contains("empty"),
                    "refusal reason must name the empty batch: {reason}"
                );
            }
            other => panic!("expected SaError::BatchSignerAddRefused, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod config_redaction_tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]
    use super::*;
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
        let config = SignersManagerConfig::new(
            primary.into(),
            secondary.into(),
            writer,
            path,
            "network".into(),
            "profile".into(),
            Duration::from_secs(1),
            "stellar:testnet".into(),
        );
        let debug = format!("{config:?}");
        assert!(
            !debug.contains("SENTINEL"),
            "Debug leaked a sentinel: {debug}"
        );
        assert!(debug.contains("https://primary.example"));
        assert!(debug.contains("https://secondary.example"));
    }
    #[test]
    fn construction_error_redacts_credentialed_url() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));
        let config = SignersManagerConfig::new(
            "ftp://SENTINEL-USER:SENTINEL-PASS@rpc.example/SENTINEL-PATH?k=SENTINEL-QUERY".into(),
            "https://secondary.example".into(),
            writer,
            path,
            "network".into(),
            "profile".into(),
            Duration::from_secs(1),
            "stellar:testnet".into(),
        );
        let error = SignersManager::new(config).unwrap_err().to_string();
        assert!(
            !error.contains("SENTINEL"),
            "construction error leaked: {error}"
        );
    }
}
