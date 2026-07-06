//! Migration planner for verifier diversification.
//!
//! # Architecture
//!
//! OZ `stellar-contracts` v0.7.2 has no dedicated "replace verifier" entrypoint.
//! A verifier migration for an `External(old_verifier_addr, key_data)` signer
//! is a two-step pair at the OZ level:
//!
//! 1. `remove_signer(rule_id, signer_id)` — removes the `External` signer with
//!    the old verifier address.
//!    OZ reference: `packages/accounts/src/smart_account/mod.rs:405-408`
//!    (SHA `a9c4216`).
//!
//! 2. `add_signer(rule_id, Signer::External(new_verifier_addr, key_data))` — adds a
//!    new `External` signer with the new verifier address, preserving the same
//!    key data (public key bytes).
//!    OZ reference: `packages/accounts/src/smart_account/mod.rs:374-377`
//!    (SHA `a9c4216`).
//!
//! Each step is one `InvokeHostFunctionOp` per Soroban transaction (CAP-46
//! invariant: exactly one `InvokeHostFunctionOp` per Soroban tx, confirmed at
//! `packages/accounts/src/smart_account/mod.rs:511-513` SHA `a9c4216`).
//! A rule with `k` affected external signers requires `2k` transactions.
//!
//! The read-only planner builds a [`MigrationPlan`] for `--dry-run` inspection.
//! [`MigrationPlan::submit`] executes the on-chain submission path.
//!
//! # Pre-flight gates (fail-CLOSED)
//!
//! 1. The destination verifier's **wasm hash** (queried from chain) MUST appear
//!    in [`VERIFIER_ALLOWLIST`] (else `VerifierMigrationFailed { phase: "preflight_destination_unknown" }`).
//! 2. Destination audit status MUST be [`VerifierAuditStatus::Audited`],
//!    [`VerifierAuditStatus::Provisional`], or [`VerifierAuditStatus::Unaudited`].
//!    `Revoked` → `SaError::VerifierWasmRevoked`; `Retired` → `SaError::VerifierWasmRetired`.
//! 3. Destination contract MUST be immutable (no admin/owner key in instance storage)
//!    (else `VerifierMigrationFailed { phase: "preflight_destination_mutable" }`).
//!
//! # Inter-transaction failure mode
//!
//! A migration with `N` affected rules each with `M` External signers produces
//! `2 × N × M` separate Soroban transactions (`N × M` remove + `N × M` add pairs).
//! Between the `remove_signer` and `add_signer` of a pair, the rule's signer set
//! is temporarily degraded. If `add_signer` fails after `remove_signer` succeeds,
//! the rule is left without that signer's authorisation weight. If the rule's
//! threshold equalled its pre-migration signer count, the rule may be bricked —
//! the same `ThresholdUnreachable` condition.
//!
//! Re-running `migrate-verifier` after a partial failure re-plans from the current
//! on-chain state — already-migrated signers no longer match `from_hash`.
//! The dry-run envelope surfaces this hazard as a `warnings` field so the
//! operator can assess it before authorising execution. See [`MigrationPlan::warnings`].
//!
//! # Entrypoint names (OZ stellar-contracts v0.7.2 SHA `a9c4216`)
//!
//! | Step | OZ entrypoint | File:line |
//! |------|--------------|-----------|
//! | Remove old External signer | `remove_signer(context_rule_id, signer_id)` | `mod.rs:405-408` |
//! | Add new External signer | `add_signer(context_rule_id, signer)` | `mod.rs:374-377` |
//!
//! There is no `update_verifier`, `replace_signer`, or `set_context_rule` entrypoint in OZ v0.7.2.
//! Migration is implemented as a remove+add pair per affected External signer per context rule.
//!
//! # Reference cross-check
//!
//! - OZ `packages/accounts/src/smart_account/mod.rs:374-408` (SHA `a9c4216`) —
//!   `add_signer` / `remove_signer` entrypoints.
//! - OZ `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`) —
//!   `Signer::External(Address, Bytes)` contracttype shape.
//! - OZ `packages/accounts/src/smart_account/mod.rs:511-513` (SHA `a9c4216`) —
//!   `ExecutionEntryPoint::execute` single-target call; CAP-46 single-op invariant.
//!
//! # Why remove+add pairs (not a single atomic replace)
//!
//! There is no atomic "replace verifier" primitive in OZ v0.7.2. A single-tx
//! bundle is not possible for two independent reasons:
//!
//! 1. **CAP-46 invariant** — Stellar restricts every Soroban transaction to
//!    exactly one `InvokeHostFunctionOp` (confirmed at OZ
//!    `packages/accounts/src/smart_account/mod.rs:511-513` SHA `a9c4216`). A
//!    single transaction cannot bundle a `remove_signer` + `add_signer` pair.
//!
//! 2. **OZ v0.7.2 surface absence** — OZ `stellar-contracts` v0.7.2 has no
//!    `update_verifier`, `replace_signer`, or `set_context_rule` entrypoint.
//!    Migration is necessarily a remove+add pair per affected External signer.
//!
//! For `N` rules each with `M` affected External signers, migration requires
//! `2 × N × M` sequential transactions. Audit cadence is one `SaVerifierMigrated`
//! row per signer-step pair, emitted only after the post-remove `add_signer`
//! transaction succeeds. The emitted tx-hash field is the first-8-last-8
//! redaction of the confirmed add-signing transaction hash.

use stellar_xdr::{
    HostFunction, InvokeContractArgs, ScAddress, ScBytes, ScSymbol, ScVal, ScVec, VecM,
};
use tracing::{debug, info, warn};

use crate::SaError;
use crate::error::MIGRATION_PHASES;
use crate::managers::rules::{ContextRuleManager, ContextRuleManagerConfig, scaddress_to_strkey};
use crate::managers::signers::fetch_observed_wasm_hash;
use crate::managers::signers::{SignersManager, simulate_read_only};
use crate::managers::verifiers::{MutabilityStatus, detect_contract_mutability};
use crate::verifier_allowlist::{VERIFIER_ALLOWLIST, VerifierAuditStatus};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_network::Signer;

// ── Types ─────────────────────────────────────────────────────────────────────

/// One per-signer migration step within a rule migration.
///
/// OZ `stellar-contracts` v0.7.2 has no atomic "replace verifier" primitive:
/// migration is a `remove_signer` + `add_signer` pair per affected External signer.
/// This struct captures both HostFunctions so they can be submitted sequentially.
///
/// # CAP-46 invariant
///
/// Each `HostFunction` is one `InvokeHostFunctionOp`, one transaction. A rule
/// with `k` affected External signers requires `2k` sequential transactions.
///
/// # OZ entrypoints
///
/// - `remove_host_function`: `remove_signer(context_rule_id, signer_id)` at
///   `packages/accounts/src/smart_account/mod.rs:405-408` (SHA `a9c4216`).
/// - `add_host_function`: `add_signer(context_rule_id, signer)` at
///   `packages/accounts/src/smart_account/mod.rs:374-377` (SHA `a9c4216`).
///
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct SignerMigrationStep {
    /// On-chain signer ID to remove (from `get_context_rule` simulation).
    pub signer_id: u32,
    /// First-8 hex chars of the old verifier wasm hash (for audit + display).
    pub current_hash_first8: String,
    /// Pre-formed `HostFunction::InvokeContract` for the `remove_signer` call.
    ///
    /// Invokes `remove_signer(rule_id, signer_id)` on the smart-account contract.
    /// OZ: `packages/accounts/src/smart_account/mod.rs:405-408` (SHA `a9c4216`).
    pub remove_host_function: HostFunction,
    /// Pre-formed `HostFunction::InvokeContract` for the `add_signer` call.
    ///
    /// Invokes `add_signer(rule_id, Signer::External(new_verifier_addr, key_data))`
    /// on the smart-account contract. OZ:
    /// `packages/accounts/src/smart_account/mod.rs:374-377` (SHA `a9c4216`).
    pub add_host_function: HostFunction,
}

/// Per-rule migration entry within a [`MigrationPlan`].
///
/// One `RuleMigration` per affected context rule. Each affected `External` signer
/// on the rule whose verifier wasm hash matches `from_hash` contributes one
/// [`SignerMigrationStep`] (remove + add pair).
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct RuleMigration {
    /// Context-rule identifier.
    pub rule_id: u32,
    /// First-8 hex chars of the current verifier wasm hash observed on this rule.
    pub current_hash_first8: String,
    /// One entry per External signer on this rule whose verifier wasm matches `from_hash`.
    ///
    /// Each step is a remove + add pair submitted sequentially via
    /// [`MigrationPlan::submit`] (one transaction per HostFunction per CAP-46).
    pub signer_steps: Vec<SignerMigrationStep>,
}

impl RuleMigration {
    /// Number of transactions required to migrate this rule.
    ///
    /// `2 * signer_steps.len()` — one `remove_signer` tx + one `add_signer` tx per step.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.signer_steps.len().saturating_mul(2)
    }
}

/// Plan for migrating all rules on a smart account whose External signers reference
/// a verifier with `from_hash` to a new verifier at `to_verifier_addr` with `to_hash`.
///
/// Built by [`MigrationPlanner::build`] (read-only; no signing, no submission).
/// Consumed by [`MigrationPlan::submit`] for on-chain submission.
///
/// # Total transaction count
///
/// Use [`Self::total_transaction_count`] before confirming a mainnet migration.
///
/// # Warnings
///
/// [`Self::warnings`] is non-empty whenever `total_transaction_count > 2`.  The
/// inter-transaction failure hazard (see module `# Inter-transaction failure mode`)
/// is surfaced here so operators can assess it before authorising execution.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct MigrationPlan {
    /// Target smart-account contract address.
    pub smart_account: ScAddress,
    /// WASM hash of the source verifier (32 bytes).
    pub from_hash: [u8; 32],
    /// WASM hash of the destination verifier (32 bytes), queried from chain.
    pub to_hash: [u8; 32],
    /// Destination verifier contract address (the new verifier to substitute in).
    pub to_verifier_addr: ScAddress,
    /// Per-rule migration entries, sorted by `rule_id` ascending.
    pub affected_rules: Vec<RuleMigration>,
    /// Allowlist audit status of the destination verifier.
    ///
    /// Guaranteed to be [`VerifierAuditStatus::Audited`],
    /// [`VerifierAuditStatus::Provisional`], or [`VerifierAuditStatus::Unaudited`]
    /// — preflight refuses `Revoked` / `Retired`.
    pub destination_audit_status: VerifierAuditStatus,
    /// Per-request correlation identifier (UUIDv4).
    pub request_id: String,
    /// Human-readable operator advisories.
    ///
    /// Non-empty when `total_transaction_count > 2`.  Contains the inter-transaction
    /// failure-mode advisory: between paired `remove_signer` / `add_signer` transactions
    /// a rule's signer set is degraded.  If `add_signer` fails after `remove_signer`
    /// succeeds, the rule may lose its authorisation signer.  Per-rule idempotency is
    /// provided by re-running `MigrationPlanner::build` after a partial failure —
    /// already-migrated signers no longer match `from_hash`.
    pub warnings: Vec<String>,
    /// Number of context rules that were fetched but could not be decoded during the
    /// `plan_build` phase (e.g., malformed `get_context_rule` simulation result).
    ///
    /// `0` on a clean run.  Non-zero means at least one rule was silently skipped.
    /// Operators should investigate skipped rules and re-run after resolving the
    /// underlying decode error before executing a migration submit.
    pub rules_skipped_count: usize,
    /// Rule IDs present in the local audit log as installed but absent from the
    /// on-chain enumeration returned by `list_active_context_rules`.
    ///
    /// A non-empty vector indicates an audit-log / on-chain desync — either the
    /// rule was deleted on-chain without a matching audit-log row, or the RPC
    /// silently suppressed a live rule from the enumeration (possible malicious-RPC drop).
    ///
    /// Empty when no `audit_writer` is configured or when all audit-log entries
    /// match the on-chain state.
    pub audit_log_missing: Vec<u32>,
}

impl MigrationPlan {
    /// First-8 hex chars of `from_hash` for envelope display.
    ///
    /// Returns 16 lower-hex characters (8 bytes × 2 chars/byte).
    #[must_use]
    pub fn from_hash_first8(&self) -> String {
        self.from_hash[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// First-8 hex chars of `to_hash` for envelope display.
    ///
    /// Returns 16 lower-hex characters (8 bytes × 2 chars/byte).
    #[must_use]
    pub fn to_hash_first8(&self) -> String {
        self.to_hash[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Total number of on-chain transactions required to execute this plan.
    ///
    /// Sum of `rule.transaction_count()` across all `affected_rules`.
    /// Each affected External signer contributes 2 transactions (remove + add).
    #[must_use]
    pub fn total_transaction_count(&self) -> usize {
        self.affected_rules
            .iter()
            .map(|r| r.transaction_count())
            .sum()
    }
}

// ── Internal data for rule-signer extraction ──────────────────────────────────

/// Full External signer data extracted from an on-chain `get_context_rule` result.
///
/// `SignerPubkey::External` in the audit-log layer only stores the first 16 bytes
/// of `key_data` (for display). The migration planner needs the FULL bytes to
/// reconstruct the `add_signer` ScVal correctly.
struct ExternalSignerData {
    /// On-chain signer ID (from `signer_ids` field of `ContextRule`).
    signer_id: u32,
    /// Verifier contract address.
    verifier_addr: ScAddress,
    /// Full key bytes from the on-chain `Signer::External(Address, Bytes)`.
    ///
    /// Byte-layout citation: `Signer::External(Address, Bytes)` at
    /// `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`).
    key_data_full: Vec<u8>,
}

// ── Submit result types ────────────────────────────────────────────────────────

/// Outcome of a single `SignerMigrationStep` (remove + add pair) during
/// [`MigrationPlan::submit`].
///
/// `remove_tx_hash` and `add_tx_hash` are confirmed 64-character transaction
/// hashes returned by the shared submit primitive. Audit rows redact these
/// hashes separately before emission.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct SignerStepSubmitOutcome {
    /// Context-rule identifier for this step.
    pub rule_id: u32,
    /// On-chain signer ID that was migrated.
    pub signer_id: u32,
    /// Full 64-character hex of the `remove_signer` transaction hash.
    pub remove_tx_hash: String,
    /// Full 64-character hex of the `add_signer` transaction hash.
    pub add_tx_hash: String,
}

/// Result returned by [`MigrationPlan::submit`].
///
/// On a complete success, `failed_step_index` is `None` and
/// `successful_steps.len() == plan.total_transaction_count() / 2`
/// (one entry per signer-step pair, not per individual transaction).
///
/// On partial failure at step index K, `failed_step_index == Some(K)`,
/// `successful_steps.len() == K`, and `failed_step_error` carries the
/// wrapped `SaError`.  The plan is idempotent at planning time: re-running
/// `MigrationPlanner::build` + `submit` will re-detect only the remaining
/// affected signers (the already-migrated ones are no longer matching
/// `from_hash`).
#[non_exhaustive]
#[derive(Debug)]
pub struct MigrationSubmitResult {
    /// Steps that completed successfully (remove + add pair each).
    pub successful_steps: Vec<SignerStepSubmitOutcome>,
    /// Zero-based index of the first step that failed, if any.
    ///
    /// `None` on complete success.
    pub failed_step_index: Option<usize>,
    /// The [`SaError`] from the failed step, if any.
    ///
    /// `None` on complete success.
    pub failed_step_error: Option<SaError>,
    /// Remove transaction hash for the failed step when `remove_signer` succeeded
    /// and the subsequent `add_signer` failed.
    ///
    /// `None` when failure happened before or during remove, or on complete success.
    pub failed_step_remove_tx_hash: Option<String>,
    /// Total number of steps attempted (successful + failed).
    pub total_steps_attempted: usize,
}

impl MigrationPlan {
    /// Submits all transactions in this plan sequentially.
    ///
    /// For each [`RuleMigration`] in `affected_rules`, for each [`SignerMigrationStep`]
    /// in `signer_steps`:
    ///
    /// 1. Simulate + sign + submit the `remove_signer` [`HostFunction`].
    /// 2. Simulate + sign + submit the `add_signer` [`HostFunction`].
    /// 3. Emit one `SaVerifierMigrated` audit row per signer step.
    ///
    /// Returns a [`MigrationSubmitResult`] describing the outcome.  On partial
    /// failure, `failed_step_index` and `failed_step_error` are set so the
    /// operator can triage.
    ///
    /// # Partial-failure semantics
    ///
    /// If submission of step K fails, the method stops immediately and returns
    /// `MigrationSubmitResult { successful_steps: steps_0..K-1, failed_step_index: Some(K), ... }`.
    /// Steps K+1 onwards are NOT attempted.  The operator can re-run
    /// `MigrationPlanner::build` to produce a new plan reflecting the remaining
    /// affected signers (already-migrated signers no longer match `from_hash`).
    ///
    /// # Audit emission
    ///
    /// Each successful signer-step pair emits one `SaVerifierMigrated` audit row.
    /// Rows are emitted only after both `remove_signer` and `add_signer` succeed.
    ///
    /// # Arguments
    ///
    /// - `signer` — the source-account signer (G-key) authorising the transactions.
    /// - `signers_manager` — provides the RPC client, network passphrase, timeout,
    ///   and audit writer.  Must be the same manager used to build the plan.
    /// - `request_id` — per-request UUID for audit-row correlation.
    ///
    /// # Errors
    ///
    /// - [`SaError::VerifierMigrationFailed`] with `phase: "submit_simulate"` —
    ///   on simulation failure of any step.
    /// - [`SaError::VerifierMigrationFailed`] with `phase: "submit_send"` —
    ///   on `sendTransaction` failure of any step.
    /// - [`SaError::AuthEntryConstructionFailed`] — signer public-key fetch failed.
    ///
    pub async fn submit(
        &self,
        signer: &(dyn Signer + Send + Sync),
        signers_manager: &SignersManager,
        request_id: &str,
    ) -> MigrationSubmitResult {
        let smart_account_strkey = match scaddress_to_strkey(&self.smart_account) {
            Ok(s) => s,
            Err(e) => {
                // `C_UNKNOWN` is the canonical shape-compliant sentinel for an
                // unredactable contract address. It is preserved as-is via
                // `from_already_redacted`; if the sentinel format changes,
                // re-run it through `redact_strkey_first5_last5` here.
                let redacted = "C_UNKNOWN".to_owned();
                return MigrationSubmitResult {
                    successful_steps: vec![],
                    failed_step_index: Some(0),
                    failed_step_error: Some(SaError::VerifierMigrationFailed {
                        // Strkey encoding failure is local (pre-simulate), but
                        // routes to submit_simulate so migration submit has one
                        // unified pre-send failure class.
                        phase: MIGRATION_PHASES[3], // "submit_simulate"
                        smart_account_redacted: RedactedStrkey::from_already_redacted(redacted),
                        detail: format!("smart_account strkey encoding failed: {e}"),
                        request_id: request_id.to_owned(),
                    }),
                    failed_step_remove_tx_hash: None,
                    total_steps_attempted: 0,
                };
            }
        };
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);

        let from_hash_first8 = self.from_hash_first8();
        let to_hash_first8 = self.to_hash_first8();

        // Resolve the source pubkey once — reused across all steps.
        let source_pubkey = match signer.public_key().await {
            Ok(pk) => pk,
            Err(e) => {
                return MigrationSubmitResult {
                    successful_steps: vec![],
                    failed_step_index: Some(0),
                    failed_step_error: Some(SaError::AuthEntryConstructionFailed {
                        stage: "auth_payload",
                        redacted_reason: format!("signer public_key fetch failed: {e}"),
                    }),
                    failed_step_remove_tx_hash: None,
                    total_steps_attempted: 0,
                };
            }
        };
        let source_pubkey_strkey = stellar_strkey::ed25519::PublicKey(source_pubkey.0).to_string();

        let chain_id = signers_manager.chain_id_ref().to_owned();

        let mut successful_steps: Vec<SignerStepSubmitOutcome> = Vec::new();
        let mut global_step_index: usize = 0;

        for rule in &self.affected_rules {
            for step in &rule.signer_steps {
                info!(
                    smart_account = %smart_account_redacted,
                    rule_id = rule.rule_id,
                    signer_id = step.signer_id,
                    from_hash_first8 = %from_hash_first8,
                    to_hash_first8 = %to_hash_first8,
                    step_index = global_step_index,
                    request_id,
                    "MigrationPlan::submit: submitting remove_signer step"
                );

                // Extract invoke_args from the pre-formed remove HostFunction.
                let (remove_function_name, remove_args) =
                    match extract_invoke_args(&step.remove_host_function) {
                        Ok(pair) => pair,
                        Err(detail) => {
                            return MigrationSubmitResult {
                                successful_steps,
                                failed_step_index: Some(global_step_index),
                                failed_step_error: Some(SaError::VerifierMigrationFailed {
                                    phase: MIGRATION_PHASES[3], // "submit_simulate"
                                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                                        smart_account_redacted.clone(),
                                    ),
                                    detail: format!("remove HostFunction decode failed: {detail}"),
                                    request_id: request_id.to_owned(),
                                }),
                                failed_step_remove_tx_hash: None,
                                total_steps_attempted: global_step_index + 1,
                            };
                        }
                    };

                // Step 1: submit remove_signer.
                let remove_result = signers_manager
                    .submit_migration_step(
                        self.smart_account.clone(),
                        rule.rule_id,
                        remove_function_name,
                        remove_args,
                        signer,
                        &source_pubkey_strkey,
                        &smart_account_redacted,
                        request_id,
                    )
                    .await;

                let remove_tx_hash = match remove_result {
                    Ok(result) => result.tx_hash,
                    Err(e) => {
                        return MigrationSubmitResult {
                            successful_steps,
                            failed_step_index: Some(global_step_index),
                            failed_step_error: Some(e),
                            failed_step_remove_tx_hash: None,
                            total_steps_attempted: global_step_index + 1,
                        };
                    }
                };

                info!(
                    smart_account = %smart_account_redacted,
                    rule_id = rule.rule_id,
                    signer_id = step.signer_id,
                    remove_tx_hash = %stellar_agent_network::redact_tx_hash(&remove_tx_hash),
                    step_index = global_step_index,
                    request_id,
                    "MigrationPlan::submit: remove_signer confirmed; submitting add_signer step"
                );

                // Extract invoke_args from the pre-formed add HostFunction.
                let (add_function_name, add_args) =
                    match extract_invoke_args(&step.add_host_function) {
                        Ok(pair) => pair,
                        Err(detail) => {
                            return MigrationSubmitResult {
                                successful_steps,
                                failed_step_index: Some(global_step_index),
                                failed_step_error: Some(SaError::VerifierMigrationFailed {
                                    phase: MIGRATION_PHASES[3], // "submit_simulate"
                                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                                        smart_account_redacted.clone(),
                                    ),
                                    detail: format!("add HostFunction decode failed: {detail}"),
                                    request_id: request_id.to_owned(),
                                }),
                                failed_step_remove_tx_hash: Some(remove_tx_hash.clone()),
                                total_steps_attempted: global_step_index + 1,
                            };
                        }
                    };

                // Step 2: submit add_signer.
                let add_result = signers_manager
                    .submit_migration_step(
                        self.smart_account.clone(),
                        rule.rule_id,
                        add_function_name,
                        add_args,
                        signer,
                        &source_pubkey_strkey,
                        &smart_account_redacted,
                        request_id,
                    )
                    .await;

                let add_tx_hash = match add_result {
                    Ok(result) => result.tx_hash,
                    Err(e) => {
                        return MigrationSubmitResult {
                            successful_steps,
                            failed_step_index: Some(global_step_index),
                            failed_step_error: Some(e),
                            failed_step_remove_tx_hash: Some(remove_tx_hash.clone()),
                            total_steps_attempted: global_step_index + 1,
                        };
                    }
                };

                info!(
                    smart_account = %smart_account_redacted,
                    rule_id = rule.rule_id,
                    signer_id = step.signer_id,
                    add_tx_hash = %stellar_agent_network::redact_tx_hash(&add_tx_hash),
                    step_index = global_step_index,
                    from_hash_first8 = %from_hash_first8,
                    to_hash_first8 = %to_hash_first8,
                    request_id,
                    "MigrationPlan::submit: add_signer confirmed; emitting SaVerifierMigrated audit row"
                );

                // Step 3: emit SaVerifierMigrated audit row.
                // tx_hash_redacted uses the add_signer tx as the representative
                // hash (the add_signer completes the migration pair).
                let add_tx_hash_redacted = stellar_agent_network::redact_tx_hash(&add_tx_hash);
                let audit_entry = AuditEntry::new_sa_verifier_migrated(
                    rule.rule_id,
                    RedactedStrkey::from_already_redacted(smart_account_redacted.clone()),
                    &from_hash_first8,
                    &to_hash_first8,
                    &add_tx_hash_redacted,
                    chain_id.as_str(),
                    request_id,
                );

                let writer_arc = signers_manager.audit_writer_arc_migration();
                match writer_arc.lock() {
                    Ok(mut writer) => {
                        if let Err(e) = writer.write_entry(audit_entry) {
                            warn!(
                                smart_account = %smart_account_redacted,
                                rule_id = rule.rule_id,
                                signer_id = step.signer_id,
                                error = %e,
                                request_id,
                                "MigrationPlan::submit: SaVerifierMigrated audit write failed \
                                 (non-fatal; migration pair already succeeded on-chain)"
                            );
                        }
                    }
                    // Poisoned mutex: a previous thread panicked while holding
                    // the lock.  The audit row is silently dropped without this
                    // branch; warn explicitly so the gap is visible in structured
                    // logs.  Non-fatal: the on-chain migration state is already
                    // committed and correct.  (Sibling pattern to the
                    // AuditWriterPoisoned discipline in credentials.rs, where
                    // the override-emission IS fatal; here it is not because the
                    // chain state is the source of truth.)
                    Err(_poison) => {
                        signers_manager.mark_audit_writer_degraded();
                        warn!(
                            smart_account = %smart_account_redacted,
                            rule_id = rule.rule_id,
                            signer_id = step.signer_id,
                            request_id,
                            "MigrationPlan::submit: SaVerifierMigrated audit-writer mutex \
                             poisoned; row dropped (non-fatal, on-chain state committed)"
                        );
                    }
                }

                successful_steps.push(SignerStepSubmitOutcome {
                    rule_id: rule.rule_id,
                    signer_id: step.signer_id,
                    remove_tx_hash,
                    add_tx_hash,
                });

                global_step_index = global_step_index.saturating_add(1);
            }
        }

        MigrationSubmitResult {
            total_steps_attempted: global_step_index,
            successful_steps,
            failed_step_index: None,
            failed_step_error: None,
            failed_step_remove_tx_hash: None,
        }
    }
}

// ── Submit internal helpers ───────────────────────────────────────────────────

/// Extracts the `entrypoint` (`&'static str`) and `invoke_args` (`Vec<ScVal>`) from
/// a pre-formed `HostFunction::InvokeContract`.
///
/// Returns `Err(String)` when the `HostFunction` is not `InvokeContract` or when
/// the `function_name` is not a known migration entrypoint.
///
/// # Entrypoint mapping
///
/// The `function_name` bytes in the pre-formed `HostFunction` must match one of the
/// two known migration entrypoints.  The `&'static str` output is used as the
/// `entrypoint` parameter of [`SignersManager::submit_migration_step`].
fn extract_invoke_args(host_function: &HostFunction) -> Result<(&'static str, Vec<ScVal>), String> {
    let args_ref = match host_function {
        HostFunction::InvokeContract(a) => a,
        _ => return Err("HostFunction is not InvokeContract".to_owned()),
    };

    let fn_name = std::str::from_utf8(args_ref.function_name.as_slice())
        .map_err(|e| format!("function_name UTF-8 decode failed: {e}"))?;

    let entrypoint: &'static str = match fn_name {
        "remove_signer" => "remove_signer",
        "add_signer" => "add_signer",
        other => {
            return Err(format!(
                "unexpected migration entrypoint '{other}'; expected 'remove_signer' or 'add_signer'"
            ));
        }
    };

    let args: Vec<ScVal> = args_ref.args.iter().cloned().collect();
    Ok((entrypoint, args))
}

// ── Test-helper constructors (feature-gated) ─────────────────────────────────

/// Test-only constructors for adversarial fixture tests.
///
/// Gated behind `--features test-helpers` so they are never included in
/// production builds. Test-only public helpers must be feature-gated with
/// `#[cfg(any(test, feature = "test-helpers"))]` to prevent inclusion in
/// production binaries.
#[cfg(any(test, feature = "test-helpers"))]
impl SignerMigrationStep {
    /// Constructs a `SignerMigrationStep` for testing.
    ///
    /// # Panics
    ///
    /// Never panics.
    #[doc(hidden)]
    pub fn new_for_test(
        signer_id: u32,
        current_hash_first8: impl Into<String>,
        remove_host_function: HostFunction,
        add_host_function: HostFunction,
    ) -> Self {
        Self {
            signer_id,
            current_hash_first8: current_hash_first8.into(),
            remove_host_function,
            add_host_function,
        }
    }
}

/// Test-only constructors for adversarial fixture tests.
#[cfg(any(test, feature = "test-helpers"))]
impl RuleMigration {
    /// Constructs a `RuleMigration` for testing.
    #[doc(hidden)]
    pub fn new_for_test(
        rule_id: u32,
        current_hash_first8: impl Into<String>,
        signer_steps: Vec<SignerMigrationStep>,
    ) -> Self {
        Self {
            rule_id,
            current_hash_first8: current_hash_first8.into(),
            signer_steps,
        }
    }
}

/// Test-only constructors for `SignerStepSubmitOutcome`.
#[cfg(any(test, feature = "test-helpers"))]
impl SignerStepSubmitOutcome {
    /// Constructs a `SignerStepSubmitOutcome` for testing.
    #[doc(hidden)]
    pub fn new_for_test(
        rule_id: u32,
        signer_id: u32,
        remove_tx_hash: impl Into<String>,
        add_tx_hash: impl Into<String>,
    ) -> Self {
        Self {
            rule_id,
            signer_id,
            remove_tx_hash: remove_tx_hash.into(),
            add_tx_hash: add_tx_hash.into(),
        }
    }
}

/// Test-only constructors for `MigrationSubmitResult`.
#[cfg(any(test, feature = "test-helpers"))]
impl MigrationSubmitResult {
    /// Constructs a `MigrationSubmitResult` for testing.
    ///
    /// Bypasses the `#[non_exhaustive]` restriction for out-of-crate struct literals.
    #[doc(hidden)]
    pub fn new_for_test(
        successful_steps: Vec<SignerStepSubmitOutcome>,
        failed_step_index: Option<usize>,
        failed_step_error: Option<crate::SaError>,
        total_steps_attempted: usize,
    ) -> Self {
        Self {
            successful_steps,
            failed_step_index,
            failed_step_error,
            failed_step_remove_tx_hash: None,
            total_steps_attempted,
        }
    }

    /// Constructs a `MigrationSubmitResult` for testing with a failed remove hash.
    #[doc(hidden)]
    pub fn new_for_test_with_failed_remove_tx_hash(
        successful_steps: Vec<SignerStepSubmitOutcome>,
        failed_step_index: Option<usize>,
        failed_step_error: Option<crate::SaError>,
        failed_step_remove_tx_hash: Option<String>,
        total_steps_attempted: usize,
    ) -> Self {
        Self {
            successful_steps,
            failed_step_index,
            failed_step_error,
            failed_step_remove_tx_hash,
            total_steps_attempted,
        }
    }
}

/// Test-only constructors for adversarial fixture tests.
#[cfg(any(test, feature = "test-helpers"))]
impl MigrationPlan {
    /// Constructs a `MigrationPlan` for testing.
    ///
    /// `warnings` is derived automatically from `affected_rules` (same logic as
    /// the planner); `rules_skipped_count` defaults to `0`.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_test(
        smart_account: ScAddress,
        from_hash: [u8; 32],
        to_hash: [u8; 32],
        to_verifier_addr: ScAddress,
        affected_rules: Vec<RuleMigration>,
        destination_audit_status: crate::verifier_allowlist::VerifierAuditStatus,
        request_id: impl Into<String>,
    ) -> Self {
        let total_tx: usize = affected_rules.iter().map(|r| r.transaction_count()).sum();
        let warnings = build_warnings(total_tx);
        Self {
            smart_account,
            from_hash,
            to_hash,
            to_verifier_addr,
            affected_rules,
            destination_audit_status,
            request_id: request_id.into(),
            warnings,
            rules_skipped_count: 0,
            audit_log_missing: vec![],
        }
    }
}

// ── MigrationPlanner ──────────────────────────────────────────────────────────

/// Builder for [`MigrationPlan`] objects.
///
/// Wraps a [`SignersManager`] reference for network access. Read-only: no
/// transactions are submitted, no keys are loaded.
///
pub struct MigrationPlanner<'a> {
    signers_manager: &'a SignersManager,
    /// Maximum rule-ID scan bound for [`list_active_context_rules`].
    ///
    /// Resolves to the profile's `smart_account_max_context_rule_scan_id` if set,
    /// otherwise defaults to [`DEFAULT_MAX_SCAN_ID`]. Capped at profile-load time
    /// by `UPPER_BOUND_MAX_SCAN_ID`.
    max_scan_id: u32,
}

impl<'a> MigrationPlanner<'a> {
    /// Constructs a new `MigrationPlanner` with the default scan bound.
    ///
    /// Uses [`crate::managers::rules::DEFAULT_MAX_SCAN_ID`] as the rule-ID scan bound.
    /// For deployments with a higher historical rule count (including deletions), use
    /// [`Self::with_max_scan_id`] to override.
    #[must_use]
    pub fn new(signers_manager: &'a SignersManager) -> Self {
        Self {
            signers_manager,
            max_scan_id: crate::managers::rules::DEFAULT_MAX_SCAN_ID,
        }
    }

    /// Overrides the maximum rule-ID scan bound.
    ///
    /// Pass the resolved `profile.smart_account_max_context_rule_scan_id` value
    /// (defaulting to [`crate::managers::rules::DEFAULT_MAX_SCAN_ID`] when `None`).
    /// The caller is responsible
    /// for validating the value is within `UPPER_BOUND_MAX_SCAN_ID` (enforced at
    /// profile-load time).
    #[must_use]
    pub fn with_max_scan_id(mut self, max_scan_id: u32) -> Self {
        self.max_scan_id = max_scan_id;
        self
    }

    /// Constructs a [`MigrationPlan`] for the given smart account and verifier
    /// address pair.
    ///
    /// # Arguments
    ///
    /// - `smart_account` — the smart-account contract's [`ScAddress`].
    /// - `from_hash` — SHA-256 of the source verifier WASM (32 bytes). Identifies
    ///   which `External` signers are candidates.
    /// - `to_verifier_addr` — destination verifier contract address. The planner
    ///   queries its WASM hash from chain and validates against [`VERIFIER_ALLOWLIST`].
    /// - `request_id` — caller-supplied UUID for audit-log correlation.
    ///
    /// # Pre-flight gates (fail-CLOSED)
    ///
    /// 1. Destination verifier hash MUST be in [`VERIFIER_ALLOWLIST`]
    ///    (else `VerifierMigrationFailed { phase: "preflight_destination_unknown" }`).
    /// 2. Destination audit status MUST be `Audited`, `Provisional`, or `Unaudited`.
    ///    `Revoked` → [`SaError::VerifierWasmRevoked`].
    ///    `Retired` → [`SaError::VerifierWasmRetired`].
    /// 3. Destination contract MUST be immutable
    ///    (else `VerifierMigrationFailed { phase: "preflight_destination_mutable" }`).
    ///
    /// # Errors
    ///
    /// - [`SaError::VerifierMigrationFailed`] with `phase: "preflight_destination_unknown"` —
    ///   destination hash not in [`VERIFIER_ALLOWLIST`].
    /// - [`SaError::VerifierMigrationFailed`] with `phase: "preflight_destination_mutable"` —
    ///   destination contract has an admin/owner key in instance storage.
    /// - [`SaError::VerifierMigrationFailed`] with `phase: "plan_build"` —
    ///   RPC failure during rule enumeration or hash fetch.
    /// - [`SaError::VerifierWasmRevoked`] — destination is allowlisted but revoked.
    /// - [`SaError::VerifierWasmRetired`] — destination is allowlisted but retired.
    /// - [`SaError::NetworkRpcDivergence`] — primary and secondary RPC disagree.
    pub async fn build(
        &self,
        smart_account: ScAddress,
        from_hash: [u8; 32],
        to_verifier_addr: ScAddress,
        request_id: &str,
    ) -> Result<MigrationPlan, SaError> {
        let smart_account_strkey = scaddress_to_strkey(&smart_account)?;
        let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
        let to_verifier_strkey = scaddress_to_strkey(&to_verifier_addr)?;
        let to_verifier_redacted = redact_strkey_first5_last5(&to_verifier_strkey);

        debug!(
            smart_account = %smart_account_redacted,
            to_verifier = %to_verifier_redacted,
            request_id,
            "MigrationPlanner::build: starting pre-flight"
        );

        // ── Pre-flight 1+2+3: destination hash, audit status, immutability ──────

        // Query destination verifier WASM hash from chain (two-RPC consultation).
        // Rule ID 0 is a synthetic sentinel — not a real context-rule ID; used
        // only for the forensic error fields of `NetworkRpcDivergence`.
        let to_hash_opt = fetch_observed_wasm_hash(
            self.signers_manager.primary_rpc_client(),
            self.signers_manager.secondary_rpc_client(),
            &to_verifier_addr,
            0,
            &smart_account_redacted,
            request_id,
        )
        .await
        .map_err(|e| SaError::VerifierMigrationFailed {
            phase: MIGRATION_PHASES[2], // "plan_build"
            smart_account_redacted: RedactedStrkey::from_already_redacted(
                smart_account_redacted.clone(),
            ),
            detail: format!("destination verifier wasm-hash fetch failed: {e}"),
            request_id: request_id.to_owned(),
        })?;

        let to_hash = to_hash_opt.ok_or_else(|| SaError::VerifierMigrationFailed {
            phase: MIGRATION_PHASES[0], // "preflight_destination_unknown"
            smart_account_redacted: RedactedStrkey::from_already_redacted(
                smart_account_redacted.clone(),
            ),
            detail: format!(
                "destination verifier contract at {to_verifier_redacted} has no deployed WASM \
                 (contract not found or not a contract instance)"
            ),
            request_id: request_id.to_owned(),
        })?;

        let to_hash_first8: String = to_hash[..8].iter().map(|b| format!("{b:02x}")).collect();

        // Pre-flight 1: destination hash must be in VERIFIER_ALLOWLIST.
        let allowlist_entry = VERIFIER_ALLOWLIST
            .iter()
            .find(|e| e.wasm_hash == to_hash)
            .ok_or_else(|| SaError::VerifierMigrationFailed {
                phase: MIGRATION_PHASES[0], // "preflight_destination_unknown"
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                detail: format!(
                    "destination verifier wasm hash {to_hash_first8} is not in VERIFIER_ALLOWLIST"
                ),
                request_id: request_id.to_owned(),
            })?;

        // Pre-flight 2: destination audit status — refuse Revoked / Retired.
        let destination_audit_status = allowlist_entry.audit_status.clone();
        match &destination_audit_status {
            VerifierAuditStatus::Revoked { reason, .. } => {
                return Err(SaError::VerifierWasmRevoked {
                    rule_id: 0,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted.clone(),
                    ),
                    verifier_hash_first8: to_hash_first8.clone(),
                    revoked_reason: (*reason).to_owned(),
                    request_id: request_id.to_owned(),
                });
            }
            VerifierAuditStatus::Retired { .. } => {
                return Err(SaError::VerifierWasmRetired {
                    rule_id: 0,
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted.clone(),
                    ),
                    verifier_hash_first8: to_hash_first8.clone(),
                    request_id: request_id.to_owned(),
                });
            }
            VerifierAuditStatus::Audited { .. }
            | VerifierAuditStatus::Provisional { .. }
            | VerifierAuditStatus::Unaudited => {
                // Accepted — continue to mutability check. Migration
                // preflight refuses only statuses that record a disclosed
                // problem (`Revoked`, `Retired`); allowlist membership, not
                // the audit status, is what admits a verifier.
            }
        }

        // Pre-flight 3: destination contract must be immutable.
        let mutability = detect_contract_mutability(
            self.signers_manager.primary_rpc_client(),
            self.signers_manager.secondary_rpc_client(),
            &to_verifier_addr,
            0,
            &smart_account_redacted,
            request_id,
        )
        .await
        .map_err(|e| SaError::VerifierMigrationFailed {
            phase: MIGRATION_PHASES[2], // "plan_build"
            smart_account_redacted: RedactedStrkey::from_already_redacted(
                smart_account_redacted.clone(),
            ),
            detail: format!("destination verifier mutability check failed: {e}"),
            request_id: request_id.to_owned(),
        })?;

        if let MutabilityStatus::Mutable {
            admin_or_owner_key, ..
        } = mutability
        {
            return Err(SaError::VerifierMigrationFailed {
                phase: MIGRATION_PHASES[1], // "preflight_destination_mutable"
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                detail: format!(
                    "destination verifier at {to_verifier_redacted} has a non-zero \
                     {admin_or_owner_key} key in instance storage — mutable contracts \
                     are refused as migration destinations"
                ),
                request_id: request_id.to_owned(),
            });
        }

        debug!(
            smart_account = %smart_account_redacted,
            to_hash_first8 = %to_hash_first8,
            request_id,
            "MigrationPlanner::build: pre-flight passed; building rule-signer inventory"
        );

        // ── Enumerate affected rules and build RuleMigration entries ────────────

        let (affected_rules, rules_skipped_count, audit_log_missing) = self
            .collect_affected_rules(
                &smart_account,
                &smart_account_redacted,
                from_hash,
                to_hash,
                &to_verifier_addr,
                request_id,
            )
            .await
            .map_err(|e| SaError::VerifierMigrationFailed {
                phase: MIGRATION_PHASES[2], // "plan_build"
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted.clone(),
                ),
                detail: format!("rule-signer inventory failed: {e}"),
                request_id: request_id.to_owned(),
            })?;

        let total_tx: usize = affected_rules.iter().map(|r| r.transaction_count()).sum();
        let warnings = build_warnings(total_tx);

        debug!(
            smart_account = %smart_account_redacted,
            affected_rule_count = affected_rules.len(),
            total_transaction_count = total_tx,
            rules_skipped_count,
            audit_log_missing_count = audit_log_missing.len(),
            warnings_count = warnings.len(),
            request_id,
            "MigrationPlanner::build: plan ready"
        );

        Ok(MigrationPlan {
            smart_account,
            from_hash,
            to_hash,
            to_verifier_addr,
            affected_rules,
            destination_audit_status,
            request_id: request_id.to_owned(),
            warnings,
            rules_skipped_count,
            audit_log_missing,
        })
    }

    /// Enumerates all context rules on the smart account and collects those
    /// whose External signers reference a verifier with `from_hash`.
    ///
    /// Uses [`ContextRuleManager::list_active_context_rules`] for sparse-ID-safe
    /// enumeration (sparse-ID-safe: correctly handles deleted rule IDs without
    /// silently missing rules beyond the count value).
    ///
    /// # Stage 1: gap count from list_active_context_rules
    ///
    /// `enumeration.rules_skipped` reflects IDs in `[0, max_scan_id)` that
    /// returned `Ok(None)` from `get_rule` — deleted or unallocated IDs.
    ///
    /// # Stage 2: per-rule skip count
    ///
    /// `rules_skipped_count` additionally counts rules whose
    /// `fetch_external_signers_for_rule` call failed (decode error).
    /// [`MigrationPlan::submit`] re-checks before submitting.
    ///
    /// Returns `(affected_rules, rules_skipped_count, audit_log_missing)` on success.
    ///
    /// Returns a `SaError` (already wrapped by the caller into
    /// `VerifierMigrationFailed { phase: "plan_build" }`) on RPC failure in the
    /// count-fetch, enumeration, or wasm-hash-fetch phases.
    async fn collect_affected_rules(
        &self,
        smart_account: &ScAddress,
        smart_account_redacted: &str,
        from_hash: [u8; 32],
        to_hash: [u8; 32],
        to_verifier_addr: &ScAddress,
        request_id: &str,
    ) -> Result<(Vec<RuleMigration>, usize, Vec<u32>), SaError> {
        let from_hash_first8: String = from_hash[..8].iter().map(|b| format!("{b:02x}")).collect();
        let to_hash_first8: String = to_hash[..8].iter().map(|b| format!("{b:02x}")).collect();

        // ── Stage 1: sparse-ID-safe enumeration via list_active_context_rules ──
        //
        // Build a temporary ContextRuleManager from the signers_manager config.
        // The audit_writer from signers_manager feeds the RPC-drop cross-check.
        let crm_config = ContextRuleManagerConfig::new(
            self.signers_manager.primary_rpc_client().url().to_owned(),
            self.signers_manager.network_passphrase_ref(),
            self.signers_manager.timeout_ref(),
            self.signers_manager.chain_id_ref().to_owned(),
        );
        let crm_config =
            crm_config.with_audit_writer(self.signers_manager.audit_writer_arc_migration());
        let crm = ContextRuleManager::new(crm_config)?;

        let source_strkey = stellar_agent_core::constants::SIMULATE_SENTINEL_G;
        let enumeration = crm
            .list_active_context_rules(smart_account.clone(), source_strkey, self.max_scan_id)
            .await?;

        let audit_log_missing = enumeration.audit_log_missing.clone();

        debug!(
            smart_account = %smart_account_redacted,
            returned_count = enumeration.rules.len(),
            active_count_on_chain = enumeration.active_count_on_chain,
            anomalous_skipped = enumeration.rules_skipped,
            gaps_seen = enumeration.gaps_seen,
            audit_log_missing_count = audit_log_missing.len(),
            request_id,
            "MigrationPlanner: list_active_context_rules returned {} active rules",
            enumeration.rules.len()
        );

        // Surface malicious-RPC live-rule-drop suspicion at the migration-planner
        // attribution layer. The primitive (`list_active_context_rules`) already
        // emits a `warn!` at `rules.rs`; this row carries the planner-side
        // `request_id` for forensic correlation across the dry-run output.
        if !audit_log_missing.is_empty() {
            warn!(
                smart_account = %smart_account_redacted,
                missing_count = audit_log_missing.len(),
                missing_rule_ids = ?audit_log_missing,
                request_id,
                "MigrationPlanner: audit-log records rule IDs not returned by RPC enumeration; possible malicious-RPC drop"
            );
        }

        // ── Stage 2: per-rule External-signer inventory ───────────────────────

        let mut affected: Vec<RuleMigration> = Vec::new();
        // rules_skipped accumulates stage-1 anomalous skip count + stage-1
        // legitimate-gap count + stage-2 decode-failure count.  The sum
        // semantics (anomalous + gaps) are preserved for backwards-compat with
        // the migrate-verifier dry-run envelope; the on-chain authoritative count
        // is in enumeration.active_count_on_chain for any caller needing that
        // distinction.
        let mut rules_skipped: usize = enumeration
            .rules_skipped
            .saturating_add(enumeration.gaps_seen);

        for summary in &enumeration.rules {
            let rule_id = summary.rule_id;

            // Fetch full External signer data for this rule.
            let external_signers = match self
                .fetch_external_signers_for_rule(
                    smart_account,
                    smart_account_redacted,
                    rule_id,
                    request_id,
                )
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        smart_account = %smart_account_redacted,
                        rule_id,
                        error = %e,
                        request_id,
                        "MigrationPlanner: get_context_rule failed for rule {rule_id}; skipping"
                    );
                    // Defensive skip in dry-run mode; the submit path re-checks before submitting.
                    rules_skipped = rules_skipped.saturating_add(1);
                    continue;
                }
            };

            let mut steps: Vec<SignerMigrationStep> = Vec::new();

            for ext in external_signers {
                // Fetch the wasm hash of this signer's verifier contract (two-RPC).
                let observed_hash_opt = fetch_observed_wasm_hash(
                    self.signers_manager.primary_rpc_client(),
                    self.signers_manager.secondary_rpc_client(),
                    &ext.verifier_addr,
                    rule_id,
                    smart_account_redacted,
                    request_id,
                )
                .await?;

                let observed_hash = match observed_hash_opt {
                    Some(h) => h,
                    None => {
                        warn!(
                            smart_account = %smart_account_redacted,
                            rule_id,
                            signer_id = ext.signer_id,
                            request_id,
                            "MigrationPlanner: External signer verifier has no WASM; skipping"
                        );
                        continue;
                    }
                };

                if observed_hash != from_hash {
                    // Verifier hash does not match from_hash — not an affected signer.
                    continue;
                }

                // Build `remove_signer(rule_id, signer_id)` HostFunction.
                // OZ: `packages/accounts/src/smart_account/mod.rs:405-408` (SHA `a9c4216`).
                let remove_host_function = build_invoke_host_function(
                    smart_account,
                    "remove_signer",
                    vec![ScVal::U32(rule_id), ScVal::U32(ext.signer_id)],
                )
                .map_err(|detail| SaError::VerifierMigrationFailed {
                    phase: MIGRATION_PHASES[2],
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    detail,
                    request_id: request_id.to_owned(),
                })?;

                // Build `add_signer(rule_id, Signer::External(new_verifier, key_data))`.
                // OZ `Signer::External(Address, Bytes)` ScVal:
                // `ScVal::Vec([Symbol("External"), Address(new_verifier_addr), Bytes(key_data)])`
                // `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`).
                let new_signer_scval =
                    build_external_signer_scval(to_verifier_addr, &ext.key_data_full).map_err(
                        |detail| SaError::VerifierMigrationFailed {
                            phase: MIGRATION_PHASES[2],
                            smart_account_redacted: RedactedStrkey::from_already_redacted(
                                smart_account_redacted,
                            ),
                            detail,
                            request_id: request_id.to_owned(),
                        },
                    )?;

                // OZ: `packages/accounts/src/smart_account/mod.rs:374-377` (SHA `a9c4216`).
                let add_host_function = build_invoke_host_function(
                    smart_account,
                    "add_signer",
                    vec![ScVal::U32(rule_id), new_signer_scval],
                )
                .map_err(|detail| SaError::VerifierMigrationFailed {
                    phase: MIGRATION_PHASES[2],
                    smart_account_redacted: RedactedStrkey::from_already_redacted(
                        smart_account_redacted,
                    ),
                    detail,
                    request_id: request_id.to_owned(),
                })?;

                steps.push(SignerMigrationStep {
                    signer_id: ext.signer_id,
                    current_hash_first8: from_hash_first8.clone(),
                    remove_host_function,
                    add_host_function,
                });
            }

            if !steps.is_empty() {
                debug!(
                    smart_account = %smart_account_redacted,
                    rule_id,
                    affected_signer_count = steps.len(),
                    from_hash_first8 = %from_hash_first8,
                    to_hash_first8 = %to_hash_first8,
                    request_id,
                    "MigrationPlanner: rule {rule_id} has {} affected External signers",
                    steps.len()
                );
                affected.push(RuleMigration {
                    rule_id,
                    current_hash_first8: from_hash_first8.clone(),
                    signer_steps: steps,
                });
            }
        }

        // Sort by rule_id ascending for deterministic ordering.
        affected.sort_by_key(|r| r.rule_id);

        Ok((affected, rules_skipped, audit_log_missing))
    }

    /// Fetches the `get_context_rules_count` value from the primary RPC.
    /// Fetches all `External` signer data for a given rule from the primary RPC.
    ///
    /// Returns the full `ExternalSignerData` (signer_id + verifier_addr + key_data_full)
    /// for each `Signer::External` on the rule. `Delegated` signers are skipped.
    async fn fetch_external_signers_for_rule(
        &self,
        smart_account: &ScAddress,
        smart_account_redacted: &str,
        rule_id: u32,
        request_id: &str,
    ) -> Result<Vec<ExternalSignerData>, SaError> {
        let result = simulate_read_only(
            self.signers_manager.primary_rpc_client().url(),
            smart_account.clone(),
            "get_context_rule",
            vec![ScVal::U32(rule_id)],
            None,
            &self.signers_manager.network_passphrase_ref(),
            self.signers_manager.timeout_ref(),
        )
        .await
        .map_err(|e| SaError::VerifierMigrationFailed {
            phase: MIGRATION_PHASES[2],
            smart_account_redacted: RedactedStrkey::from_already_redacted(smart_account_redacted),
            detail: format!("get_context_rule({rule_id}) simulation failed: {e}"),
            request_id: request_id.to_owned(),
        })?;

        decode_external_signers_from_context_rule(
            result,
            rule_id,
            smart_account_redacted,
            request_id,
        )
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Decodes all `Signer::External` entries from a `get_context_rule` simulation result.
///
/// Parses the `signer_ids` and `signers` fields of the `ContextRule` `ScVal::Map`
/// and returns [`ExternalSignerData`] for each `External(Address, Bytes)` signer.
/// `Delegated` signers are silently skipped (not affected by verifier migration).
///
/// # Byte-layout citation
///
/// `ContextRule` struct fields at `packages/accounts/src/smart_account/storage.rs:155-174`
/// (SHA `a9c4216`). `Signer::External(Address, Bytes)` ScVal encoding:
/// `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`).
fn decode_external_signers_from_context_rule(
    val: ScVal,
    rule_id: u32,
    smart_account_redacted: &str,
    request_id: &str,
) -> Result<Vec<ExternalSignerData>, SaError> {
    let map = match val {
        ScVal::Map(Some(m)) => m,
        other => {
            return Err(SaError::VerifierMigrationFailed {
                phase: MIGRATION_PHASES[2],
                smart_account_redacted: RedactedStrkey::from_already_redacted(
                    smart_account_redacted,
                ),
                detail: format!("get_context_rule({rule_id}): expected ScVal::Map, got {other:?}"),
                request_id: request_id.to_owned(),
            });
        }
    };

    let mut signer_ids: Vec<u32> = Vec::new();
    let mut signers_scvals: Vec<ScVal> = Vec::new();

    for entry in map.iter() {
        let key = match &entry.key {
            ScVal::Symbol(s) => std::str::from_utf8(s.as_slice()).unwrap_or("").to_owned(),
            _ => continue,
        };
        match key.as_str() {
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
            _ => {}
        }
    }

    // Match signer_ids to signer ScVals by index position (parallel slice).
    // OZ parallel `signer_ids` / `signers` array alignment:
    // `packages/accounts/src/smart_account/storage.rs:155-174` (SHA `a9c4216`).
    let result: Vec<ExternalSignerData> = signer_ids
        .into_iter()
        .zip(signers_scvals)
        .filter_map(|(sid, sval)| decode_external_signer_scval(sid, sval))
        .collect();

    Ok(result)
}

/// Decodes a single `Signer::External(Address, Bytes)` from an OZ `Signer` ScVal.
///
/// Returns `None` for `Delegated` signers (not affected by verifier migration)
/// and for unrecognised variant tags.
///
/// # Byte-layout citation
///
/// `Signer::External(Address, Bytes)` ScVal:
/// `ScVal::Vec([Symbol("External"), Address(verifier_addr), Bytes(key_data)])`
/// `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`).
fn decode_external_signer_scval(signer_id: u32, val: ScVal) -> Option<ExternalSignerData> {
    let items = match val {
        ScVal::Vec(Some(v)) => v,
        _ => return None,
    };
    let items: Vec<&ScVal> = items.iter().collect();

    if items.len() < 3 {
        return None;
    }

    let tag = match items[0] {
        ScVal::Symbol(s) => std::str::from_utf8(s.as_slice()).unwrap_or("").to_owned(),
        _ => return None,
    };

    if tag != "External" {
        return None; // Delegated or unknown — not affected by verifier migration
    }

    let verifier_addr = match items[1] {
        ScVal::Address(a) => a.clone(),
        _ => return None,
    };

    let key_data_full = match items[2] {
        ScVal::Bytes(ScBytes(b)) => b.as_slice().to_vec(),
        _ => return None,
    };

    Some(ExternalSignerData {
        signer_id,
        verifier_addr,
        key_data_full,
    })
}

/// Builds a `HostFunction::InvokeContract` for a direct call on a Soroban contract.
///
/// Constructs `InvokeContractArgs { contract_address, function_name, args }`.
/// Returns `Err(String)` on symbol or VecM encoding failure (caller wraps into
/// `SaError::VerifierMigrationFailed`).
///
/// # CAP-46
///
/// One `InvokeHostFunctionOp` per transaction. This function produces the
/// `HostFunction` for one step of the migration.
fn build_invoke_host_function(
    contract: &ScAddress,
    function_name: &str,
    args: Vec<ScVal>,
) -> Result<HostFunction, String> {
    let symbol = ScSymbol::try_from(function_name)
        .map_err(|e| format!("ScSymbol({function_name:?}) failed: {e:?}"))?;
    let args_vecm: VecM<ScVal> = args
        .try_into()
        .map_err(|e| format!("args VecM encoding failed: {e:?}"))?;
    Ok(HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract.clone(),
        function_name: symbol,
        args: args_vecm,
    }))
}

/// Builds an OZ `Signer::External(Address, Bytes)` ScVal for the `add_signer` call.
///
/// # Byte-layout citation
///
/// `Signer::External(Address, Bytes)` ScVal encoding:
/// `ScVal::Vec([Symbol("External"), Address(verifier_addr), Bytes(key_data)])`
/// `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`).
fn build_external_signer_scval(
    verifier_addr: &ScAddress,
    key_data: &[u8],
) -> Result<ScVal, String> {
    let tag = ScVal::Symbol(
        ScSymbol::try_from("External").map_err(|e| format!("Symbol(External) failed: {e:?}"))?,
    );
    let addr_val = ScVal::Address(verifier_addr.clone());
    let key_bytes: stellar_xdr::BytesM = key_data
        .to_vec()
        .try_into()
        .map_err(|e| format!("key_data BytesM failed: {e:?}"))?;
    let bytes_val = ScVal::Bytes(ScBytes(key_bytes));
    let vec_inner: VecM<ScVal> = vec![tag, addr_val, bytes_val]
        .try_into()
        .map_err(|e| format!("VecM[External,addr,bytes] failed: {e:?}"))?;
    Ok(ScVal::Vec(Some(ScVec(vec_inner))))
}

// ── Warning builder ───────────────────────────────────────────────────────────

/// Builds the `warnings` field for a [`MigrationPlan`].
///
/// Returns a non-empty `Vec<String>` when `total_transaction_count > 2`.  The
/// inter-transaction failure hazard is surfaced so operators can assess it before
/// authorising execution:
///
/// - Between paired `remove_signer` / `add_signer` transactions a rule's signer
///   set is degraded.
/// - If `add_signer` fails after `remove_signer` succeeds, the rule may lose its
///   authorisation signer.  If the rule's threshold equalled its pre-migration
///   signer count, the rule may be bricked (`ThresholdUnreachable`).
/// - Re-running `migrate-verifier` after a partial failure re-plans from the
///   current on-chain state (already-migrated signers no longer match `from_hash`).
///
/// A single-signer migration (exactly 1 affected External signer = 2 txs)
/// produces an empty `warnings` because the hazard resolves atomically at rule
/// scope: either both transactions succeed or the rule is back to its pre-migration
/// state on the first failure.  The warning fires at `> 2` transactions where
/// a partial commit on one rule leaves a second rule's transition unstarted.
pub(crate) fn build_warnings(total_transaction_count: usize) -> Vec<String> {
    if total_transaction_count > 2 {
        vec![format!(
            "This migration produces {total_transaction_count} separate Soroban \
             transactions (one remove_signer and one add_signer per affected \
             External signer per context rule). Between paired remove/add \
             transactions the rule's signer set is degraded; if the add_signer \
             tx fails after remove_signer succeeds, the rule may be left without \
             its authorisation signer. Re-run migrate-verifier after a partial \
             failure to resume from the current on-chain state."
        )]
    } else {
        vec![]
    }
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

    use super::*;
    use stellar_xdr::{ContractId, Hash, ScAddress};

    // ── MigrationPlan display helpers ─────────────────────────────────────────

    /// `from_hash_first8` returns the first 8 hex bytes (16 hex chars) of `from_hash`.
    #[test]
    fn from_hash_first8_returns_correct_hex() {
        let mut from_hash = [0u8; 32];
        from_hash[..8].copy_from_slice(&[0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90]);
        let plan = MigrationPlan {
            smart_account: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            from_hash,
            to_hash: [0u8; 32],
            to_verifier_addr: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            affected_rules: vec![],
            destination_audit_status: VerifierAuditStatus::Unaudited,
            request_id: "test".to_owned(),
            warnings: vec![],
            rules_skipped_count: 0,
            audit_log_missing: vec![],
        };
        // 8 bytes × 2 hex chars/byte = 16 chars.
        assert_eq!(plan.from_hash_first8(), "abcdef1234567890");
    }

    /// `to_hash_first8` returns the first 8 hex bytes (16 hex chars) of `to_hash`.
    #[test]
    fn to_hash_first8_returns_correct_hex() {
        let mut to_hash = [0u8; 32];
        to_hash[..8].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        let plan = MigrationPlan {
            smart_account: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            from_hash: [0u8; 32],
            to_hash,
            to_verifier_addr: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            affected_rules: vec![],
            destination_audit_status: VerifierAuditStatus::Unaudited,
            request_id: "test".to_owned(),
            warnings: vec![],
            rules_skipped_count: 0,
            audit_log_missing: vec![],
        };
        assert_eq!(plan.to_hash_first8(), "1122334455667788");
    }

    /// `total_transaction_count` is 2 * total signer_steps across all rules.
    #[test]
    fn total_transaction_count_is_two_per_step() {
        let dummy_hf = || {
            HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                function_name: ScSymbol::try_from("remove_signer").unwrap(),
                args: VecM::default(),
            })
        };
        let step = || SignerMigrationStep {
            signer_id: 0,
            current_hash_first8: "00000000".to_owned(),
            remove_host_function: dummy_hf(),
            add_host_function: dummy_hf(),
        };
        let affected_rules = vec![
            RuleMigration {
                rule_id: 1,
                current_hash_first8: "aabbccdd".to_owned(),
                signer_steps: vec![step(), step()], // 2 signers → 4 txs
            },
            RuleMigration {
                rule_id: 2,
                current_hash_first8: "aabbccdd".to_owned(),
                signer_steps: vec![step()], // 1 signer → 2 txs
            },
        ];
        let total_tx: usize = affected_rules.iter().map(|r| r.transaction_count()).sum();
        let warnings = build_warnings(total_tx);
        let plan = MigrationPlan {
            smart_account: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            from_hash: [0u8; 32],
            to_hash: [1u8; 32],
            to_verifier_addr: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            affected_rules,
            destination_audit_status: VerifierAuditStatus::Unaudited,
            request_id: "test".to_owned(),
            warnings,
            rules_skipped_count: 0,
            audit_log_missing: vec![],
        };
        assert_eq!(plan.total_transaction_count(), 6, "2 rules: 4+2 = 6 txs");
        // 6 txs > 2 → warnings non-empty.
        assert!(
            !plan.warnings.is_empty(),
            "6-tx plan must produce inter-tx failure warning"
        );
    }

    // ── ScVal encoding helpers ────────────────────────────────────────────────

    /// `build_external_signer_scval` produces `ScVal::Vec([Symbol("External"), Address, Bytes])`.
    ///
    /// # Byte-layout citation
    ///
    /// `Signer::External(Address, Bytes)` ScVal encoding:
    /// `packages/accounts/src/smart_account/storage.rs:96-102` (SHA `a9c4216`).
    #[test]
    fn build_external_signer_scval_shape() {
        let addr = ScAddress::Contract(ContractId(Hash([0x42u8; 32])));
        let key_data = vec![0x01u8, 0x02u8, 0x03u8];
        let val = build_external_signer_scval(&addr, &key_data).unwrap();

        let items = match val {
            ScVal::Vec(Some(v)) => v,
            _ => panic!("expected ScVal::Vec"),
        };
        let items: Vec<&ScVal> = items.iter().collect();
        assert_eq!(items.len(), 3, "External signer ScVal must have 3 elements");

        match items[0] {
            ScVal::Symbol(s) => assert_eq!(s.as_slice(), b"External"),
            _ => panic!("items[0] must be Symbol(\"External\")"),
        }
        assert!(
            matches!(items[1], ScVal::Address(_)),
            "items[1] must be Address"
        );
        assert!(
            matches!(items[2], ScVal::Bytes(_)),
            "items[2] must be Bytes"
        );
    }

    /// `build_invoke_host_function` produces `HostFunction::InvokeContract` with the
    /// correct function name and argument count.
    #[test]
    fn build_invoke_host_function_produces_correct_shape() {
        let addr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let hf =
            build_invoke_host_function(&addr, "remove_signer", vec![ScVal::U32(1), ScVal::U32(2)])
                .unwrap();
        match hf {
            HostFunction::InvokeContract(args) => {
                assert_eq!(args.function_name.as_slice(), b"remove_signer");
                assert_eq!(args.args.len(), 2);
            }
            _ => panic!("expected InvokeContract"),
        }
    }

    /// `decode_external_signer_scval` returns `None` for `Delegated` signers.
    #[test]
    fn decode_external_signer_returns_none_for_delegated() {
        let addr = ScVal::Address(ScAddress::Contract(ContractId(Hash([0u8; 32]))));
        let tag = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let vec_inner: VecM<ScVal> = vec![tag, addr].try_into().unwrap();
        let val = ScVal::Vec(Some(ScVec(vec_inner)));
        assert!(
            decode_external_signer_scval(0, val).is_none(),
            "Delegated signer must return None"
        );
    }

    /// `decode_external_signer_scval` extracts full `key_data_full` for External signers.
    ///
    /// Validates that the full 65 bytes are preserved (not truncated to 16 like
    /// `SignerPubkey::External.key_data_first16`).
    #[test]
    fn decode_external_signer_preserves_full_key_data() {
        let verifier_addr = ScAddress::Contract(ContractId(Hash([0x42u8; 32])));
        let key_data = vec![0xAAu8; 65]; // 65 bytes — longer than 16-byte truncation
        let val = build_external_signer_scval(&verifier_addr, &key_data).unwrap();
        let ext = decode_external_signer_scval(7, val).expect("must decode");
        assert_eq!(ext.signer_id, 7);
        assert_eq!(
            ext.key_data_full, key_data,
            "full key_data must be preserved without truncation"
        );
    }

    // ── extract_invoke_args ───────────────────────────────────────────────────

    /// `extract_invoke_args` returns `("remove_signer", args)` for a
    /// `HostFunction::InvokeContract` with `function_name = "remove_signer"`.
    ///
    /// Exercises the happy path for both known migration entrypoints.
    #[test]
    fn extract_invoke_args_remove_signer_returns_static_str() {
        let contract = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let args_in = vec![ScVal::U32(3), ScVal::U32(7)];
        let hf = build_invoke_host_function(&contract, "remove_signer", args_in.clone()).unwrap();
        let (ep, args_out) = extract_invoke_args(&hf).expect("remove_signer must decode");
        assert_eq!(
            ep, "remove_signer",
            "entrypoint must be the &'static str \"remove_signer\""
        );
        // Verify the static string identity (pointer equality not required, value sufficient).
        assert_eq!(args_out.len(), 2, "two args must round-trip");
        assert_eq!(args_out[0], ScVal::U32(3));
        assert_eq!(args_out[1], ScVal::U32(7));
    }

    /// `extract_invoke_args` returns `("add_signer", args)` for a
    /// `HostFunction::InvokeContract` with `function_name = "add_signer"`.
    #[test]
    fn extract_invoke_args_add_signer_returns_static_str() {
        let contract = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let hf = build_invoke_host_function(&contract, "add_signer", vec![ScVal::U32(1)]).unwrap();
        let (ep, args_out) = extract_invoke_args(&hf).expect("add_signer must decode");
        assert_eq!(ep, "add_signer");
        assert_eq!(args_out.len(), 1);
        assert_eq!(args_out[0], ScVal::U32(1));
    }

    /// `extract_invoke_args` returns `Err` when the `HostFunction` variant is not
    /// `InvokeContract`.
    ///
    /// `HostFunction::UploadContractWasm` is used as the non-InvokeContract variant;
    /// `extract_invoke_args` must reject it with a message containing
    /// "not InvokeContract".
    #[test]
    fn extract_invoke_args_rejects_non_invoke_contract() {
        // An UploadContractWasm HostFunction is the simplest non-InvokeContract variant.
        // BytesM::default() is empty WASM bytes — structurally valid for this test.
        let hf = HostFunction::UploadContractWasm(stellar_xdr::BytesM::default());
        let err =
            extract_invoke_args(&hf).expect_err("non-InvokeContract HostFunction must be rejected");
        assert!(
            err.contains("not InvokeContract"),
            "error must mention 'not InvokeContract'; got: {err}"
        );
    }

    /// `extract_invoke_args` returns `Err` for an `InvokeContract` with an
    /// unrecognised `function_name`.
    ///
    /// "set_threshold" is used as an example of a valid OZ entrypoint that is NOT
    /// a migration entrypoint. The error must identify the unexpected name.
    #[test]
    fn extract_invoke_args_rejects_unknown_entrypoint() {
        let contract = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let hf = build_invoke_host_function(&contract, "set_threshold", vec![]).unwrap();
        let err = extract_invoke_args(&hf).expect_err("unknown entrypoint must be rejected");
        assert!(
            err.contains("set_threshold"),
            "error must name the unexpected entrypoint; got: {err}"
        );
        assert!(
            err.contains("remove_signer") || err.contains("add_signer"),
            "error must indicate the expected entrypoints; got: {err}"
        );
    }

    // ── build_warnings boundary conditions ───────────────────────────────────

    /// `build_warnings` returns empty for 0 transactions.
    #[test]
    fn build_warnings_empty_for_zero_tx() {
        assert!(
            build_warnings(0).is_empty(),
            "0 transactions must produce no warnings"
        );
    }

    /// `build_warnings` returns empty for exactly 1 transaction.
    ///
    /// 1 transaction is below the 2-transaction minimum for a single signer step
    /// (remove + add) and cannot represent a complete migration pair, but the
    /// guard is defined as `> 2` so 1 and 2 both return empty.
    #[test]
    fn build_warnings_empty_for_one_tx() {
        assert!(
            build_warnings(1).is_empty(),
            "1 transaction must produce no warnings"
        );
    }

    /// `build_warnings` returns empty for exactly 2 transactions (one signer step).
    ///
    /// A single-signer migration (1 remove + 1 add = 2 txs) is atomic at rule
    /// scope; the hazard only applies when a second rule or signer is involved.
    /// The threshold is `> 2`, so exactly 2 must not trigger the warning.
    #[test]
    fn build_warnings_empty_for_two_tx() {
        assert!(
            build_warnings(2).is_empty(),
            "exactly 2 transactions must produce no warnings (single-signer atomic pair)"
        );
    }

    /// `build_warnings` returns exactly one warning string for 3 transactions.
    ///
    /// 3 is the first value above the `> 2` threshold. The warning must include
    /// the transaction count and refer to the inter-tx failure hazard.
    #[test]
    fn build_warnings_fires_at_three_tx() {
        let warnings = build_warnings(3);
        assert_eq!(
            warnings.len(),
            1,
            "exactly 1 warning must be produced for 3 txs"
        );
        let w = &warnings[0];
        assert!(
            w.contains("3"),
            "warning must include the transaction count (3); got: {w}"
        );
        assert!(
            w.contains("remove_signer") && w.contains("add_signer"),
            "warning must name the operation pair; got: {w}"
        );
        assert!(
            w.contains("migrate-verifier"),
            "warning must reference the re-run command; got: {w}"
        );
    }

    /// `build_warnings` warning string includes the actual count for large inputs.
    #[test]
    fn build_warnings_includes_count_in_message() {
        let warnings = build_warnings(100);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("100"),
            "warning must embed the exact transaction count; got: {}",
            warnings[0]
        );
    }

    // ── RuleMigration::transaction_count ─────────────────────────────────────

    /// `transaction_count()` returns `0` when there are no signer steps.
    ///
    /// A `RuleMigration` with zero `signer_steps` represents a rule that had no
    /// affected External signers (e.g. after a partial migration already removed them).
    #[test]
    fn rule_migration_transaction_count_zero_for_empty_steps() {
        let rule = RuleMigration {
            rule_id: 5,
            current_hash_first8: "aabbccdd".to_owned(),
            signer_steps: vec![],
        };
        assert_eq!(
            rule.transaction_count(),
            0,
            "zero signer steps must yield zero transactions"
        );
    }

    // ── decode_external_signer_scval edge cases ───────────────────────────────

    /// `decode_external_signer_scval` returns `None` for a non-Vec `ScVal` input.
    ///
    /// The OZ `Signer` ScVal is always a `ScVal::Vec`; other discriminants are
    /// never valid and must be silently dropped.
    #[test]
    fn decode_external_signer_returns_none_for_non_vec_input() {
        // ScVal::U32 is a scalar, never a valid Signer encoding.
        assert!(
            decode_external_signer_scval(0, ScVal::U32(42)).is_none(),
            "ScVal::U32 must return None (not a Vec)"
        );
        // ScVal::Bool is similarly invalid.
        assert!(
            decode_external_signer_scval(0, ScVal::Bool(true)).is_none(),
            "ScVal::Bool must return None (not a Vec)"
        );
    }

    /// `decode_external_signer_scval` returns `None` for a `ScVal::Vec` with fewer
    /// than 3 elements.
    ///
    /// The `Signer::External(Address, Bytes)` encoding requires exactly 3 elements:
    /// `[Symbol("External"), Address, Bytes]`. Truncated inputs must be rejected.
    #[test]
    fn decode_external_signer_returns_none_for_short_vec() {
        // Single-element vec (just the tag).
        let tag = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let one_elem: VecM<ScVal> = vec![tag.clone()].try_into().unwrap();
        assert!(
            decode_external_signer_scval(0, ScVal::Vec(Some(ScVec(one_elem)))).is_none(),
            "1-element vec must return None"
        );

        // Two-element vec (tag + address, missing key bytes).
        let addr = ScVal::Address(ScAddress::Contract(ContractId(Hash([0u8; 32]))));
        let two_elem: VecM<ScVal> = vec![tag, addr].try_into().unwrap();
        assert!(
            decode_external_signer_scval(0, ScVal::Vec(Some(ScVec(two_elem)))).is_none(),
            "2-element vec must return None"
        );
    }

    /// `decode_external_signer_scval` returns `None` when the first element is not
    /// a `Symbol`.
    ///
    /// Malformed encoding where the discriminant is a `U32` instead of a `Symbol`
    /// must be silently dropped.
    #[test]
    fn decode_external_signer_returns_none_for_non_symbol_tag() {
        let addr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        // First element is U32(0) instead of Symbol("External").
        let bad_tag = ScVal::U32(0);
        let key_bytes: stellar_xdr::BytesM = vec![0x01u8].try_into().unwrap();
        let items: VecM<ScVal> = vec![
            bad_tag,
            ScVal::Address(addr),
            ScVal::Bytes(ScBytes(key_bytes)),
        ]
        .try_into()
        .unwrap();
        let val = ScVal::Vec(Some(ScVec(items)));
        assert!(
            decode_external_signer_scval(0, val).is_none(),
            "non-Symbol first element must return None"
        );
    }

    /// `decode_external_signer_scval` returns `None` when items[1] is not an `Address`.
    ///
    /// The second element of `Signer::External` must be the verifier contract address.
    /// A `U32` in place of the address must be silently dropped.
    #[test]
    fn decode_external_signer_returns_none_for_non_address_verifier() {
        let tag = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let key_bytes: stellar_xdr::BytesM = vec![0x01u8].try_into().unwrap();
        // Second element is U32 instead of Address.
        let items: VecM<ScVal> = vec![
            tag,
            ScVal::U32(999), // wrong type for verifier address
            ScVal::Bytes(ScBytes(key_bytes)),
        ]
        .try_into()
        .unwrap();
        let val = ScVal::Vec(Some(ScVec(items)));
        assert!(
            decode_external_signer_scval(0, val).is_none(),
            "non-Address second element must return None"
        );
    }

    /// `decode_external_signer_scval` returns `None` when items[2] is not `Bytes`.
    ///
    /// The third element of `Signer::External` must be the raw key bytes.
    /// A `Symbol` in place of the bytes must be silently dropped.
    #[test]
    fn decode_external_signer_returns_none_for_non_bytes_key_data() {
        let tag = ScVal::Symbol(ScSymbol::try_from("External").unwrap());
        let addr = ScAddress::Contract(ContractId(Hash([0x42u8; 32])));
        // Third element is a Symbol instead of Bytes.
        let bad_key = ScVal::Symbol(ScSymbol::try_from("not_bytes").unwrap());
        let items: VecM<ScVal> = vec![tag, ScVal::Address(addr), bad_key].try_into().unwrap();
        let val = ScVal::Vec(Some(ScVec(items)));
        assert!(
            decode_external_signer_scval(0, val).is_none(),
            "non-Bytes third element must return None"
        );
    }

    /// `decode_external_signer_scval` returns `None` for an unknown tag string.
    ///
    /// OZ `Signer` only has `"External"` and `"Delegated"` variants (SHA `a9c4216`).
    /// Any other tag (e.g., a future extension) must be silently skipped by the
    /// migration planner, which only affects `External` signers.
    #[test]
    fn decode_external_signer_returns_none_for_unknown_tag() {
        let tag = ScVal::Symbol(ScSymbol::try_from("Unknown").unwrap());
        let addr = ScAddress::Contract(ContractId(Hash([0x11u8; 32])));
        let key_bytes: stellar_xdr::BytesM = vec![0xFFu8; 32].try_into().unwrap();
        let items: VecM<ScVal> = vec![tag, ScVal::Address(addr), ScVal::Bytes(ScBytes(key_bytes))]
            .try_into()
            .unwrap();
        let val = ScVal::Vec(Some(ScVec(items)));
        assert!(
            decode_external_signer_scval(0, val).is_none(),
            "unknown tag must return None"
        );
    }

    // ── decode_external_signers_from_context_rule ─────────────────────────────

    /// `decode_external_signers_from_context_rule` returns `Err` when the input
    /// `ScVal` is not `ScVal::Map(Some(_))`.
    ///
    /// The `get_context_rule` simulation always returns a `Map`; a malformed RPC
    /// response that returns a scalar must be rejected with `VerifierMigrationFailed`.
    #[test]
    fn decode_external_signers_errors_on_non_map_input() {
        // ScVal::U32 is the simplest non-Map input.
        let result = decode_external_signers_from_context_rule(
            ScVal::U32(42),
            1,
            "C_TESTT...TTEST",
            "req-001",
        );
        // ExternalSignerData doesn't impl Debug; use match instead of expect_err.
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("non-Map ScVal must produce an error"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("plan_build"),
            "error must carry the plan_build phase; got: {msg}"
        );
        assert!(
            msg.contains("expected ScVal::Map"),
            "error detail must describe the type mismatch; got: {msg}"
        );
    }

    /// `decode_external_signers_from_context_rule` returns `Err` when the input
    /// is `ScVal::Map(None)` (the XDR null-map encoding).
    ///
    /// `ScVal::Map(None)` represents an explicitly-empty / null map in XDR; it is
    /// distinct from `ScVal::Map(Some(empty_map))` and must also be rejected.
    #[test]
    fn decode_external_signers_errors_on_null_map() {
        let result = decode_external_signers_from_context_rule(
            ScVal::Map(None),
            2,
            "C_TESTT...TTEST",
            "req-002",
        );
        // ExternalSignerData doesn't impl Debug; use match instead of expect_err.
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("ScVal::Map(None) must produce an error"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("expected ScVal::Map"),
            "error must describe the mismatch; got: {msg}"
        );
    }

    /// `decode_external_signers_from_context_rule` returns an empty vec when the
    /// map has correct structure but `signer_ids` and `signers` are both empty.
    ///
    /// A rule with no signers is degenerate but structurally valid; the decoder
    /// must return `Ok([])` rather than erroring.
    #[test]
    fn decode_external_signers_empty_for_empty_signer_lists() {
        use stellar_xdr::{ScMap, ScMapEntry};
        // Build a ContextRule-shaped map with empty signer_ids and signers vecs.
        let signer_ids_key = ScVal::Symbol(ScSymbol::try_from("signer_ids").unwrap());
        let signers_key = ScVal::Symbol(ScSymbol::try_from("signers").unwrap());
        let empty_vec: VecM<ScVal> = vec![].try_into().unwrap();
        let empty_scvec = ScVal::Vec(Some(ScVec(empty_vec)));
        let entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: signer_ids_key,
                val: empty_scvec.clone(),
            },
            ScMapEntry {
                key: signers_key,
                val: empty_scvec,
            },
        ];
        let scmap: ScMap = entries.try_into().unwrap();
        let val = ScVal::Map(Some(scmap));
        let result =
            decode_external_signers_from_context_rule(val, 0, "C_TESTT...TTEST", "req-003")
                .expect("empty-signer map must succeed");
        assert!(
            result.is_empty(),
            "empty signer lists must produce empty ExternalSignerData vec"
        );
    }

    /// `decode_external_signers_from_context_rule` skips `Delegated` signers and
    /// returns only `External` ones.
    ///
    /// A rule with 1 External and 1 Delegated signer (parallel signer_ids / signers
    /// arrays) must return exactly 1 `ExternalSignerData` entry for the External signer.
    ///
    /// # Byte-layout citation
    ///
    /// OZ parallel `signer_ids` / `signers` alignment:
    /// `packages/accounts/src/smart_account/storage.rs:155-174` (SHA `a9c4216`).
    #[test]
    fn decode_external_signers_filters_delegated_and_returns_external() {
        use stellar_xdr::{ScMap, ScMapEntry};

        let verifier_addr = ScAddress::Contract(ContractId(Hash([0x42u8; 32])));
        let key_data = vec![0xBBu8; 33];

        // Build External signer ScVal.
        let external_scval = build_external_signer_scval(&verifier_addr, &key_data)
            .expect("External ScVal must build");

        // Build Delegated signer ScVal: ScVal::Vec([Symbol("Delegated"), Address]).
        let del_tag = ScVal::Symbol(ScSymbol::try_from("Delegated").unwrap());
        let del_addr = ScVal::Address(ScAddress::Contract(ContractId(Hash([0xDDu8; 32]))));
        let del_inner: VecM<ScVal> = vec![del_tag, del_addr].try_into().unwrap();
        let delegated_scval = ScVal::Vec(Some(ScVec(del_inner)));

        // signer_ids = [10, 20]; signers = [External, Delegated] (parallel arrays).
        let signer_ids_vec: VecM<ScVal> = vec![ScVal::U32(10), ScVal::U32(20)].try_into().unwrap();
        let signers_vec: VecM<ScVal> = vec![external_scval, delegated_scval].try_into().unwrap();

        let entries: Vec<ScMapEntry> = vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signer_ids").unwrap()),
                val: ScVal::Vec(Some(ScVec(signer_ids_vec))),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol::try_from("signers").unwrap()),
                val: ScVal::Vec(Some(ScVec(signers_vec))),
            },
        ];
        let scmap: ScMap = entries.try_into().unwrap();
        let val = ScVal::Map(Some(scmap));

        let result =
            decode_external_signers_from_context_rule(val, 3, "C_TESTT...TTEST", "req-004")
                .expect("mixed-signer map must succeed");

        // Only the External signer must be returned.
        assert_eq!(
            result.len(),
            1,
            "exactly 1 ExternalSignerData must be returned; got {}",
            result.len()
        );
        assert_eq!(
            result[0].signer_id, 10,
            "signer_id for the External signer must be 10"
        );
        assert_eq!(
            result[0].key_data_full, key_data,
            "full key bytes must be preserved"
        );
    }

    /// `decode_external_signers_from_context_rule` ignores map entries whose key
    /// is not a `Symbol` (e.g. a `U32` key).
    ///
    /// Non-Symbol map keys must be silently skipped rather than panicking.
    #[test]
    fn decode_external_signers_ignores_non_symbol_map_keys() {
        use stellar_xdr::{ScMap, ScMapEntry};
        // A map with one entry whose key is U32 (not a Symbol).
        let entries: Vec<ScMapEntry> = vec![ScMapEntry {
            key: ScVal::U32(0), // not a Symbol — must be ignored
            val: ScVal::U32(42),
        }];
        let scmap: ScMap = entries.try_into().unwrap();
        let val = ScVal::Map(Some(scmap));
        let result =
            decode_external_signers_from_context_rule(val, 4, "C_TESTT...TTEST", "req-005")
                .expect("non-Symbol key map must succeed (keys are ignored)");
        assert!(
            result.is_empty(),
            "non-Symbol map keys produce no ExternalSignerData"
        );
    }

    // ── MigrationPlan hash display — all-zero boundary ────────────────────────

    /// `from_hash_first8` returns 16 zero chars for an all-zero `from_hash`.
    ///
    /// Exercises the lower boundary of the hex encoding loop.
    #[test]
    fn from_hash_first8_all_zero_returns_sixteen_zero_chars() {
        let plan = MigrationPlan {
            smart_account: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            from_hash: [0u8; 32],
            to_hash: [0u8; 32],
            to_verifier_addr: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            affected_rules: vec![],
            destination_audit_status: VerifierAuditStatus::Unaudited,
            request_id: "test".to_owned(),
            warnings: vec![],
            rules_skipped_count: 0,
            audit_log_missing: vec![],
        };
        let hex = plan.from_hash_first8();
        assert_eq!(
            hex.len(),
            16,
            "must be exactly 16 hex characters (8 bytes × 2)"
        );
        assert_eq!(
            hex, "0000000000000000",
            "all-zero hash must produce sixteen '0' chars"
        );
    }

    /// `to_hash_first8` returns 16 `"ff"` chars for an all-`0xff` `to_hash`.
    ///
    /// Exercises the upper boundary of the hex encoding loop.
    #[test]
    fn to_hash_first8_all_ff_returns_sixteen_f_chars() {
        let plan = MigrationPlan {
            smart_account: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            from_hash: [0u8; 32],
            to_hash: [0xFFu8; 32],
            to_verifier_addr: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            affected_rules: vec![],
            destination_audit_status: VerifierAuditStatus::Unaudited,
            request_id: "test".to_owned(),
            warnings: vec![],
            rules_skipped_count: 0,
            audit_log_missing: vec![],
        };
        let hex = plan.to_hash_first8();
        assert_eq!(hex.len(), 16, "must be exactly 16 hex characters");
        assert_eq!(
            hex, "ffffffffffffffff",
            "all-0xff hash must produce sixteen 'f' chars"
        );
    }

    // ── build_external_signer_scval with empty key_data ───────────────────────

    /// `build_external_signer_scval` succeeds with empty key_data.
    ///
    /// A zero-byte key payload is structurally valid (BytesM allows zero length);
    /// the resulting ScVal must carry an empty `Bytes(ScBytes([]))`.
    #[test]
    fn build_external_signer_scval_with_empty_key_data() {
        let addr = ScAddress::Contract(ContractId(Hash([0u8; 32])));
        let val = build_external_signer_scval(&addr, &[]).expect("empty key_data must build");
        let items = match val {
            ScVal::Vec(Some(v)) => v,
            _ => panic!("expected ScVal::Vec"),
        };
        let items: Vec<&ScVal> = items.iter().collect();
        assert_eq!(items.len(), 3);
        match items[2] {
            ScVal::Bytes(ScBytes(b)) => {
                assert!(
                    b.is_empty(),
                    "Bytes payload must be empty for empty key_data"
                );
            }
            _ => panic!("items[2] must be Bytes"),
        }
    }

    // ── MigrationPlan::total_transaction_count with single rule ──────────────

    /// `total_transaction_count` returns `2` for a single rule with one signer step.
    ///
    /// Validates the base case: 1 remove + 1 add = 2 transactions, which is the
    /// minimum for a complete migration (below the warning threshold of > 2).
    #[test]
    fn total_transaction_count_single_rule_single_step_is_two() {
        let dummy_hf = || {
            HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
                function_name: ScSymbol::try_from("remove_signer").unwrap(),
                args: VecM::default(),
            })
        };
        let step = SignerMigrationStep {
            signer_id: 0,
            current_hash_first8: "deadbeef".to_owned(),
            remove_host_function: dummy_hf(),
            add_host_function: dummy_hf(),
        };
        let rule = RuleMigration {
            rule_id: 0,
            current_hash_first8: "deadbeef".to_owned(),
            signer_steps: vec![step],
        };
        let plan = MigrationPlan {
            smart_account: ScAddress::Contract(ContractId(Hash([0u8; 32]))),
            from_hash: [0xDEu8; 32],
            to_hash: [0xBEu8; 32],
            to_verifier_addr: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
            affected_rules: vec![rule],
            destination_audit_status: VerifierAuditStatus::Unaudited,
            request_id: "test-single".to_owned(),
            warnings: vec![],
            rules_skipped_count: 0,
            audit_log_missing: vec![],
        };
        assert_eq!(
            plan.total_transaction_count(),
            2,
            "1 rule × 1 signer step × 2 tx/step = 2 total transactions"
        );
        // 2 txs is at the threshold boundary; warnings must be empty.
        assert!(
            plan.warnings.is_empty(),
            "2-tx plan must not trigger inter-tx failure warning"
        );
    }
}
