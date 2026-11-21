//! The submission flow after the policy gate shared by the CLI and MCP server.
//! Each binary renders the results in its own wire form.

pub(crate) mod recovery;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::{AuditWriter, PolicyDecision};
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, SubmissionError, WalletError};
use stellar_agent_core::policy::v1::{CheckedSizing, SizingOutcome};
use stellar_agent_core::profile::receipt::{ReceiptStore, ReceiptStoreError, SubmissionReceipt};
use stellar_agent_core::profile::schema::{Profile, StateDirError};
use stellar_agent_core::wallet::WalletLifecycleError;

use crate::mainnet::consumed::AuthorizationConsumed;
use crate::policy_state::{
    CommittedBatch, DeliveryReport, OperationRecorder, PersistedWindowStore, RECONCILE_BUDGET,
    ReconcileReport, SubmissionHold, WindowStoreError, drain_accounting_obligations,
};
use crate::submission_record::repair_approval_consumption;
use crate::{
    IntentBinding, IntentProof, MainnetSubmitGrant, NetworkContext, OperationAttempt,
    SignedIntentPlan, StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder, envelope_hash_hex,
};

/// Opens the submission receipt store for a profile.
///
/// # Errors
/// Returns a recording refusal when the store cannot be opened.
pub fn open_receipts(profile_name: &str) -> Result<ReceiptStore, WalletError> {
    open_receipt_store(profile_name)
        .map_err(|detail| WalletError::Submission(SubmissionError::RecordUnavailable { detail }))
}

/// Opens the receipt store; a failure is the recording refusal text both
/// binaries render.
fn open_receipt_store(profile_name: &str) -> Result<ReceiptStore, String> {
    ReceiptStore::open(profile_name)
        .map_err(|e| format!("the submission receipt store could not be opened: {e}"))
}

/// Extracts certified sizing or preserves the policy refusal.
///
/// # Errors
/// Returns the policy denial or the caller's unsupported-outcome error.
pub fn checked_sizing(
    outcome: SizingOutcome,
    unsupported: impl FnOnce() -> WalletError,
) -> Result<CheckedSizing, WalletError> {
    match outcome {
        SizingOutcome::Sized(sizing) => Ok(sizing),
        SizingOutcome::Refused(reason) => Err(WalletError::PolicyDenied {
            reason: Box::new(reason),
        }),
        _ => Err(unsupported()),
    }
}

/// Inputs the policy gate supplies to a submission recorder.
pub struct RecorderInputs<'a> {
    /// The governing profile.
    pub profile: &'a Profile,
    /// The profile's store name.
    pub profile_name: String,
    /// The registered tool name in audit rows.
    pub tool: &'static str,
    /// The CAIP-2 chain identifier.
    pub chain_id: String,
    /// The decision admitting the submission.
    pub policy_decision: PolicyDecision,
    /// The sized value legs in audit form.
    pub legs: Vec<ValueLegRecord>,
    /// The writer acquired by the audit preflight.
    pub audit: Option<Arc<Mutex<AuditWriter>>>,
    /// The commit nonce prefix for audit rows.
    pub nonce_id: Option<String>,
    /// The caller's Unix clock in milliseconds.
    pub now_ms: u64,
    /// The mainnet policy provenance the pending row records, when the
    /// submission proceeds under a mainnet decision.
    pub provenance: Option<stellar_agent_core::mainnet::decision::MainnetProvenance>,
    /// The operation attempt the submission sends, opened before the
    /// signature; `None` for a submission without an operation record.
    pub operation: Option<OperationAttempt>,
    /// The independently observed lower bound before exposure.
    pub pre_exposure_ledger: Option<u32>,
    /// The primary readiness observation persisted by the recorder.
    pub observation: Option<crate::policy_state::WindowObservation>,
}

/// Assembles the stores, window entries and signing sizing for a recorder.
pub fn assemble_recorder(
    inputs: RecorderInputs<'_>,
    receipts: ReceiptStore,
    sizing: Option<CheckedSizing>,
) -> WalletSubmissionRecorder<'_> {
    let window_entries = sizing
        .as_ref()
        .map(|sizing| sizing.entries().to_vec())
        .unwrap_or_default();
    let window = PersistedWindowStore::for_profile(&inputs.profile_name);
    let recorder = WalletSubmissionRecorder::new(
        inputs.profile,
        inputs.profile_name,
        inputs.tool,
        Some(inputs.chain_id),
        inputs.policy_decision,
        inputs.legs,
        window_entries,
        receipts,
        window,
        inputs.audit,
        inputs.nonce_id,
        uuid::Uuid::new_v4().to_string(),
        inputs.now_ms,
    );
    let recorder = match inputs.provenance {
        Some(provenance) => recorder.with_provenance(provenance),
        None => recorder,
    }
    .with_operation(inputs.operation)
    .with_pre_exposure_ledger(inputs.pre_exposure_ledger)
    .with_observation(inputs.observation);
    match sizing {
        Some(sizing) => recorder.with_signing_sizing(sizing),
        None => recorder,
    }
}

/// The recorder of a mainnet write, marking entry into the authorized pre-send hook.
///
/// The mark separates the two refusals of the submit that share a code: a
/// refusal of the submit gate before the hook, and a refusal inside it.
pub struct StageMarkedRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    pre_send_entered: AtomicBool,
}

impl<'a> StageMarkedRecorder<'a> {
    /// Wraps a recorder with an unset authorized pre-send mark.
    pub fn new(inner: WalletSubmissionRecorder<'a>) -> Self {
        Self {
            inner,
            pre_send_entered: AtomicBool::new(false),
        }
    }

    /// Whether submission enters [`SubmissionRecorder::pre_send_authorized`].
    #[must_use]
    pub fn pre_send_entered(&self) -> bool {
        self.pre_send_entered.load(Ordering::SeqCst)
    }

    /// Ends the operation attempt as `NotSent` after a refusal with wire
    /// code `code` that came before the authorized pre-send hook: a signer,
    /// attach or submit refusal. Inside the hook the recorder ends the
    /// attempt itself.
    pub fn end_refused_attempt(&self, code: &str) {
        if !self.pre_send_entered() {
            self.inner.end_unsent_attempt(code);
        }
    }

    /// Moves out the transitions the wrapped recorder committed; see
    /// [`WalletSubmissionRecorder::take_committed`].
    pub fn take_committed(&self) -> CommittedBatch {
        self.inner.take_committed()
    }

    /// See [`WalletSubmissionRecorder::complete_owed_approval`].
    pub fn complete_owed_approval(&self) {
        self.inner.complete_owed_approval();
    }
}

impl std::fmt::Debug for StageMarkedRecorder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageMarkedRecorder")
            .field("inner", &self.inner)
            .field("pre_send_entered", &self.pre_send_entered())
            .finish()
    }
}

#[async_trait::async_trait]
impl SubmissionRecorder for StageMarkedRecorder<'_> {
    async fn admit_signed_intent(
        &self,
        plan: &SignedIntentPlan,
    ) -> Result<IntentProof, WalletError> {
        self.inner.admit_signed_intent(plan).await
    }
    async fn cancel_unexposed(&self, proof: IntentProof) -> Result<(), WalletError> {
        self.inner.cancel_unexposed(proof).await
    }
    async fn pre_send_bound(
        &self,
        intent: &SubmissionIntent,
        binding: &IntentBinding<'_>,
    ) -> Result<(), WalletError> {
        self.inner.pre_send_bound(intent, binding).await
    }

    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.inner.pre_send(intent).await
    }

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        self.pre_send_entered.store(true, Ordering::SeqCst);
        self.inner.pre_send_authorized(intent, grant).await
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.inner.outcome(intent, outcome).await;
    }
}

/// Structured recovery details for a submission with an unknown outcome.
///
/// Returns `None` for every error other than a submission timeout, an
/// already-submitted transaction and a hash mismatch: those are the
/// submissions whose outcome the wallet does not know. `reconcile_with`
/// names the tool or verb that resolves the outcome.
pub fn submission_details(
    err: &WalletError,
    signed_xdr: &str,
    reconcile_with: &str,
) -> Option<serde_json::Value> {
    let WalletError::Submission(submission) = err else {
        return None;
    };
    let mut details = serde_json::Map::new();
    match submission {
        SubmissionError::TxTimeout { tx_hash, seconds } => {
            details.insert("tx_hash".to_owned(), tx_hash.clone().into());
            details.insert("timeout_seconds".to_owned(), (*seconds).into());
        }
        SubmissionError::TxAlreadySubmitted { hash } => {
            details.insert("tx_hash".to_owned(), hash.clone().into());
        }
        SubmissionError::HashMismatch { local, server } => {
            details.insert("tx_hash".to_owned(), local.clone().into());
            details.insert("server_tx_hash".to_owned(), server.clone().into());
        }
        _ => return None,
    }
    // The envelope hash names the submission record the operator verbs
    // address. A caller that does not hold the signed bytes reports the
    // transaction hash alone rather than a hash of nothing.
    if !signed_xdr.is_empty() {
        details.insert(
            "envelope_hash".to_owned(),
            envelope_hash_hex(signed_xdr).into(),
        );
    }
    details.insert("recovery".to_owned(), initial_recovery(signed_xdr));
    details.insert("outcome".to_owned(), "unknown".into());
    details.insert("reconcile_with".to_owned(), reconcile_with.into());
    Some(serde_json::Value::Object(details))
}

#[derive(serde::Serialize)]
enum RetryTimeUnavailable {
    MissingBound,
    Overflow,
}

fn initial_recovery(signed_xdr: &str) -> serde_json::Value {
    let bound = crate::operation_entry::envelope_max_time(signed_xdr)
        .ok()
        .filter(|m| *m > 0 && *m != u64::MAX);
    let retry = bound.and_then(crate::policy_state::recovery_expiry);
    let mut result = serde_json::json!({
        "result": "NeedsEvidence",
        "reason": "RecoveryRequired",
        "next_action": "TargetedStatus",
    });
    if let Some(retry) = retry {
        result["earliest_retry_ms"] = retry.into();
    } else {
        result["retry_time_unavailable"] = serde_json::json!(if bound.is_some() {
            RetryTimeUnavailable::Overflow
        } else {
            RetryTimeUnavailable::MissingBound
        });
    }
    result
}

/// Renders a wallet error with submission recovery details when available.
///
/// An error without [`submission_details`] renders as a plain error envelope.
pub fn submission_error_envelope(
    err: &WalletError,
    signed_xdr: &str,
    reconcile_with: &str,
) -> Envelope<()> {
    match submission_details(err, signed_xdr, reconcile_with) {
        Some(details) => Envelope::err_with_details(err, details),
        None => Envelope::err(err),
    }
}

/// Builds the mainnet settlement oracle, logging a client construction refusal.
///
/// Returns `None` off mainnet, when the window store cannot name the chain
/// scope of `profile`, when the profile configures no oracle, and when the
/// oracle client cannot be built. Without an oracle, a negative answer of
/// the primary endpoint settles nothing.
pub fn settlement_oracle(
    window: &PersistedWindowStore,
    profile: &Profile,
    context: &NetworkContext,
) -> Option<StellarRpcClient> {
    let scope = window.chain_scope(profile).ok()?;
    if !scope.chain().is_mainnet() {
        return None;
    }
    match context.oracle_client(profile) {
        Ok(oracle) => oracle,
        Err(error) => {
            tracing::warn!(
                code = %error.code(),
                "window reconcile: the oracle client could not be built; negative answers \
                 of the primary endpoint settle nothing"
            );
            None
        }
    }
}

/// The outcome of a dispatch-time reconciliation pass.
#[derive(Debug)]
pub enum ReconcilePass {
    /// The pass completes over the due reservations.
    Completed(ReconcileReport),
    /// Legacy accounting and bounded recovery completed.
    Recovered {
        /// Legacy accounting counts.
        legacy: ReconcileReport,
        /// Verified recovery results, retained through the finisher.
        recovery: crate::policy_state::RecoveryReport,
    },
    /// The system clock is unavailable, so the pass is skipped.
    ClockUnavailable,
    /// The primary RPC client is unavailable, so the pass is skipped.
    ClientUnavailable,
    /// The pass refuses; every open reservation stands.
    Failed(WindowStoreError),
    /// The legacy stage completes and the recovery stage then refuses.
    ///
    /// The refusal can follow committed sequence work and other completed
    /// receipt projections. Sequence store and identity refusals take
    /// precedence; a repair refusal precedes missing sequence evidence.
    /// A checked receipt repair refusal is a store refusal. Its detail
    /// states the sequence stage's result and names the repaired and refused
    /// decisions, each refusal with its code and detail.
    RecoveryFailed {
        /// The completed legacy report.
        legacy: ReconcileReport,
        /// The first recovery refusal; only validated evidence can commit,
        /// and completed commits stand.
        error: crate::policy_state::RecoveryError,
        /// Readable results even when recovery or projection refuses.
        recovery: crate::policy_state::RecoveryReport,
    },
}

/// Logs the outcome of a dispatch-time reconciliation pass, then drains every
/// owed accounting obligation.
///
/// The drain runs for every pass outcome: a skipped or refused pass leaves
/// the durable obligations of earlier passes in place, and they are
/// delivered here. The writer is the keyed one every value verb uses,
/// acquired only when an audit event is owed.
///
/// # Errors
/// Returns a refusal from accounting delivery or writer acquisition.
pub fn finish_reconciliation(
    profile: &Profile,
    profile_name: &str,
    window: &PersistedWindowStore,
    receipts: Option<&ReceiptStore>,
    pass: &ReconcilePass,
    writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
) -> Result<DeliveryReport, WalletError> {
    match pass {
        ReconcilePass::Completed(report)
        | ReconcilePass::Recovered { legacy: report, .. }
        | ReconcilePass::RecoveryFailed { legacy: report, .. }
            if report.receipt_write_failed > 0 =>
        {
            tracing::warn!(
                profile = %profile_name,
                receipt_write_failed = report.receipt_write_failed,
                "window reconcile: receipt writes stay owed"
            );
        }
        ReconcilePass::Completed(_)
        | ReconcilePass::Recovered { .. }
        | ReconcilePass::RecoveryFailed { .. } => {}
        ReconcilePass::ClockUnavailable => {
            tracing::debug!("window reconcile: system clock unavailable; reservations stand");
        }
        ReconcilePass::ClientUnavailable => {
            tracing::debug!("window reconcile: no primary client; reservations stand");
        }
        ReconcilePass::Failed(error) => tracing::debug!(
            profile = %profile_name,
            error = ?error,
            "window reconcile: pass failed; open reservations stand"
        ),
    }
    match pass {
        ReconcilePass::RecoveryFailed {
            error: crate::policy_state::RecoveryError::Store(WindowStoreError::Invalid { detail }),
            ..
        } if detail.starts_with(SEQUENCES_RECOVERED)
            || detail.starts_with(SEQUENCES_MISSING_EVIDENCE) =>
        {
            tracing::warn!(
                profile = %profile_name,
                detail = %detail,
                "recovery: checked receipt repair refused after sequence recovery; completed work remains committed"
            )
        }
        ReconcilePass::RecoveryFailed {
            error: error @ crate::policy_state::RecoveryError::Context { source, detail, .. },
            ..
        } if detail.starts_with("selected sequences: ")
            || matches!(
                source.as_ref(),
                crate::policy_state::RecoveryError::Context { source, .. }
                    if matches!(source.as_ref(), crate::policy_state::RecoveryError::Store(_))
            ) =>
        {
            tracing::warn!(
                profile = %profile_name,
                code = error.code(),
                error = %error,
                "recovery: the stage refused; durable progress appears in the detail"
            )
        }
        ReconcilePass::RecoveryFailed {
            error: error @ crate::policy_state::RecoveryError::Context { source, detail, .. },
            ..
        } if !detail.is_empty()
            && !matches!(
                source.as_ref(),
                crate::policy_state::RecoveryError::EndpointIdentity(_)
            ) =>
        {
            tracing::warn!(
                profile = %profile_name,
                code = error.code(),
                error = %error,
                "recovery: the stage refused; every sequence stays held"
            )
        }
        ReconcilePass::RecoveryFailed { error, .. }
            if !matches!(error, crate::policy_state::RecoveryError::NeedsEvidence(_)) =>
        {
            tracing::warn!(
                profile = %profile_name,
                code = error.code(),
                error = %error,
                "recovery: the stage refused; unresolved sequences stay held"
            );
        }
        _ => {}
    }
    if let ReconcilePass::Recovered { recovery, .. }
    | ReconcilePass::RecoveryFailed { recovery, .. } = pass
    {
        tracing::debug!(
            evaluated = recovery.evaluated,
            attempts = recovery.attempts.len(),
            "recovery: bounded results retained"
        );
    }
    drain_accounting_obligations(window, profile, profile_name, receipts, writer)
}

/// The prefix of a recovery refusal detail whose sequence stage completed
/// before checked receipt repair refused.
const SEQUENCES_RECOVERED: &str = "sequence recovery completed; ";

/// The prefix when checked receipt repair refuses after an incomplete sequence pass.
const SEQUENCES_MISSING_EVIDENCE: &str = "sequence recovery evidence missing; ";

/// Runs the bounded dispatch-time reconciliation pass.
///
/// On a mainnet profile the pass first applies the operation store's expiry
/// edges once, through the writer `operations_writer` acquires. A record
/// past its window ends before any work reads it. A failure there is logged
/// and the pass continues.
///
/// Successful recovery returns [`ReconcilePass::Recovered`]. A legacy-only pass
/// returns [`ReconcilePass::Completed`], or [`ReconcilePass::Failed`] on refusal.
/// Earlier committed work remains committed.
///
/// After a completed legacy stage, the recovery stage runs the bounded
/// recovery driver of [`crate::policy_state::recover_outcomes`] once, then repairs the receipt of
/// every retained committed recovery decision when `receipts` and the writer are available.
/// Idle passes repair too. Accounting obligations drain in [`finish_reconciliation`].
///
/// The pass binds no host. On mainnet the caller passes clients whose hosts
/// the enablement verified in the same process.
pub async fn reconcile_pass(
    profile: &Profile,
    window: &PersistedWindowStore,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    receipts: Option<&ReceiptStore>,
    now_ms: u64,
    operations_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
) -> ReconcilePass {
    reconcile_pass_committed(
        profile,
        window,
        client,
        oracle,
        receipts,
        now_ms,
        operations_writer,
        &mut CommittedBatch::default(),
    )
    .await
}

/// [`reconcile_pass`], appending the transitions its expiry edges and its
/// recovery driver commit to `committed`, also when a later stage refuses.
#[allow(
    clippy::too_many_arguments,
    reason = "the pass arguments plus the caller's batch"
)]
pub async fn reconcile_pass_committed(
    profile: &Profile,
    window: &PersistedWindowStore,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    receipts: Option<&ReceiptStore>,
    now_ms: u64,
    operations_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
    committed: &mut CommittedBatch,
) -> ReconcilePass {
    reconcile_stages(
        profile,
        window,
        client,
        oracle,
        receipts,
        now_ms,
        operations_writer,
        true,
        committed,
    )
    .await
}

/// Runs [`reconcile_pass`] without its recovery stage.
///
/// An invocation whose business id is already stored replays or conflicts
/// before it builds anything, so it sends no recovery request, changes no
/// recovery state and repairs no checked receipt. The expiry edges and the
/// legacy stage run unchanged.
pub async fn reconcile_legacy_pass(
    profile: &Profile,
    window: &PersistedWindowStore,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    receipts: Option<&ReceiptStore>,
    now_ms: u64,
    operations_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
) -> ReconcilePass {
    reconcile_legacy_pass_committed(
        profile,
        window,
        client,
        oracle,
        receipts,
        now_ms,
        operations_writer,
        &mut CommittedBatch::default(),
    )
    .await
}

/// [`reconcile_legacy_pass`], appending the transitions its expiry edges
/// commit to `committed`.
#[allow(
    clippy::too_many_arguments,
    reason = "the pass arguments plus the caller's batch"
)]
pub async fn reconcile_legacy_pass_committed(
    profile: &Profile,
    window: &PersistedWindowStore,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    receipts: Option<&ReceiptStore>,
    now_ms: u64,
    operations_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
    committed: &mut CommittedBatch,
) -> ReconcilePass {
    reconcile_stages(
        profile,
        window,
        client,
        oracle,
        receipts,
        now_ms,
        operations_writer,
        false,
        committed,
    )
    .await
}

/// Whether `business_id` names a record or tombstone in the verified window.
///
/// The read sends no request, so the caller's request order stays as it is.
/// An absent, unparsable or unreadable id reads as not stored.
#[must_use]
pub fn business_id_is_stored(
    profile: &Profile,
    window: &PersistedWindowStore,
    business_id: Option<&str>,
) -> bool {
    let Some(Ok(business_id)) = business_id.map(crate::policy_state::BusinessId::parse) else {
        return false;
    };
    crate::policy_state::OperationStatus::new(window, profile)
        .view(&business_id)
        .is_ok_and(|view| view.is_some())
}

#[allow(
    clippy::too_many_arguments,
    reason = "the pass arguments plus the stage selection and the caller's batch"
)]
async fn reconcile_stages(
    profile: &Profile,
    window: &PersistedWindowStore,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    receipts: Option<&ReceiptStore>,
    now_ms: u64,
    operations_writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
    recovery: bool,
    committed: &mut CommittedBatch,
) -> ReconcilePass {
    #[cfg(test)]
    RECOVERY_STAGE_TRACE.with_borrow_mut(|trace| trace.push("expire"));
    let writer = if profile.chain_id.is_mainnet() {
        Some(expire_due_operations(
            profile,
            window,
            now_ms,
            operations_writer,
            committed,
        ))
    } else {
        None
    };
    #[cfg(test)]
    RECOVERY_STAGE_TRACE.with_borrow_mut(|trace| trace.push("legacy"));
    let legacy = match window
        .reconcile_due(profile, client, oracle, receipts, now_ms, RECONCILE_BUDGET)
        .await
    {
        Ok(report) => ReconcilePass::Completed(report),
        Err(error) => ReconcilePass::Failed(error),
    };
    if !recovery {
        return legacy;
    }
    #[cfg(test)]
    RECOVERY_STAGE_TRACE.with_borrow_mut(|trace| trace.push("recovery"));
    let (Some(writer), ReconcilePass::Completed(report)) = (writer, &legacy) else {
        return legacy;
    };
    let writer = match writer {
        Ok(writer) => writer,
        Err(error) => {
            let recovery = crate::policy_state::RecoveryReport::refused(
                &crate::policy_state::OperationStatus::new(window, profile),
                None,
                error.code(),
            );
            return ReconcilePass::RecoveryFailed {
                legacy: report.clone(),
                error,
                recovery,
            };
        }
    };
    // The one recovery driver runs first; a projection refusal never starves it.
    let sequences = crate::policy_state::recovery::recover_outcomes_committed(
        window,
        profile,
        crate::policy_state::EndpointPair::from_clients(client, oracle),
        &writer,
        None,
        false,
        committed,
    )
    .await;
    release_ended_after_recovery(window, profile);
    let mut recovery_report = match &sequences {
        Ok(report) => report.clone(),
        Err(error) => error.report().cloned().unwrap_or_else(|| {
            crate::policy_state::RecoveryReport::refused(
                &crate::policy_state::OperationStatus::new(window, profile),
                None,
                error.code(),
            )
        }),
    };
    let sequences = sequences.and_then(crate::policy_state::RecoveryReport::require_evidence);
    #[cfg(test)]
    recovery::tests::trace("sequences");
    let repaired = receipts.map_or(Ok(()), |receipts| {
        recovery::repair_committed_receipts(window, profile, receipts, &writer, None)
    });
    if let Err(error) = &sequences {
        recovery_report.refusal = Some(crate::policy_state::RecoveryRefusal {
            code: error.code(),
            state_unavailable: recovery_report
                .refusal
                .as_ref()
                .is_some_and(|r| r.state_unavailable),
        });
    }
    recovery_report.refresh_settlements(
        &crate::policy_state::OperationStatus::new(window, profile),
        None,
    );
    if let Err(error) = &repaired {
        recovery_report
            .refusal
            .get_or_insert(crate::policy_state::RecoveryRefusal {
                code: error.code(),
                state_unavailable: false,
            });
    }
    match (sequences, repaired) {
        (Err(error), repaired)
            if !matches!(error, crate::policy_state::RecoveryError::NeedsEvidence(_)) =>
        {
            ReconcilePass::RecoveryFailed {
                legacy: report.clone(),
                recovery: recovery_report.clone(),
                error: match repaired {
                    Err(refused) => error.with_context(refused.to_string()),
                    Ok(()) => error,
                },
            }
        }
        (sequences, Err(refused)) => {
            let prefix = if sequences.is_ok() {
                SEQUENCES_RECOVERED
            } else {
                SEQUENCES_MISSING_EVIDENCE
            };
            ReconcilePass::RecoveryFailed {
                legacy: report.clone(),
                recovery: recovery_report.clone(),
                error: crate::policy_state::RecoveryError::Store(WindowStoreError::Invalid {
                    detail: format!("{prefix}{refused}"),
                }),
            }
        }
        (Err(error), Ok(())) => ReconcilePass::RecoveryFailed {
            legacy: report.clone(),
            error,
            recovery: recovery_report,
        },
        (Ok(_), Ok(())) => ReconcilePass::Recovered {
            legacy: report.clone(),
            recovery: recovery_report,
        },
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static RECOVERY_STAGE_TRACE: std::cell::RefCell<Vec<&'static str>> = const { std::cell::RefCell::new(Vec::new()) };
    /// Turns the status lookup's recovery stage off for a control run.
    pub(crate) static STATUS_RECOVERY_DISABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the status lookup runs its recovery stage; always outside tests.
fn status_recovery_enabled() -> bool {
    #[cfg(test)]
    {
        !STATUS_RECOVERY_DISABLED.get()
    }
    #[cfg(not(test))]
    {
        true
    }
}

/// Applies the operation store's expiry edges at `now_ms` and appends the
/// transitions they commit to `committed`.
///
/// The writer is acquired before the window lock, the order every operation
/// step takes. Every refusal is logged: the records stay as they are, and the
/// next pass or step applies the same edges.
fn expire_due_operations(
    profile: &Profile,
    window: &PersistedWindowStore,
    now_ms: u64,
    writer: impl FnOnce() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
    committed: &mut CommittedBatch,
) -> Result<Arc<Mutex<AuditWriter>>, crate::policy_state::RecoveryError> {
    let writer = match writer() {
        Ok(writer) => writer,
        Err(error) => {
            tracing::debug!(
                code = error.code(),
                "operation expiry: no audit writer; expiry edges wait for the next step"
            );
            return Err(crate::policy_state::RecoveryError::Writer(error));
        }
    };
    let Ok(mut guard) = writer.lock() else {
        tracing::warn!("operation expiry: the audit writer mutex is poisoned; expiry skipped");
        return Err(WindowStoreError::Invalid {
            detail: "audit writer mutex is poisoned".into(),
        }
        .into());
    };
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut recorder = OperationRecorder::new(window, profile, &mut *guard, request_id);
    let expired = recorder.expire_due(now_ms);
    committed.append(recorder.take_committed());
    match &expired {
        Ok(0) => {}
        Ok(ended) => tracing::debug!(ended, "operation expiry: records ended"),
        Err(error) => tracing::warn!(
            code = error.submission_code(),
            "operation expiry: the expiry edges could not be applied; records stand"
        ),
    }
    drop(guard);
    Ok(writer)
}

/// Releases the consent evidence of records a recovery pass ended, after the
/// pass returns and outside the window lock. A failure leaves the evidence
/// for the next admission, recovery or revocation and changes no outcome.
fn release_ended_after_recovery(window: &PersistedWindowStore, profile: &Profile) {
    #[cfg(test)]
    RECOVERY_STAGE_TRACE.with_borrow_mut(|trace| trace.push("release"));
    if let Err(error) =
        crate::policy_state::approvals::consent_evidence_maintenance(window, profile)
    {
        tracing::warn!(
            code = error.code(),
            "consent evidence: release after recovery failed; a later sweep retries it"
        );
    }
}

/// Inputs for reconciling and displaying one transaction.
pub struct StatusRequest<'a> {
    /// The governing profile.
    pub profile: &'a Profile,
    /// The profile's store name.
    pub profile_name: &'a str,
    /// The validated transaction hash.
    pub tx_hash: &'a str,
    /// The authenticated spending-window store.
    pub window: &'a PersistedWindowStore,
    /// The primary endpoint.
    pub client: &'a StellarRpcClient,
    /// The mainnet settlement oracle, when available.
    pub oracle: Option<&'a StellarRpcClient>,
    /// Starts one fresh bounded evidence run for this hash's stopped attempt,
    /// before its retry time or after its runs are exhausted. The run resets
    /// the attempt's run count to one, signs and sends nothing, and refuses a
    /// live lease, an earlier clock and unusable metadata. Defaults to false.
    pub retry_recovery: bool,
}

/// The chain observation and the records after reconciliation and delivery.
#[derive(Debug)]
pub struct StatusOutcome {
    /// Recovery results for authenticated mainnet classic attempts.
    pub recovery: crate::policy_state::RecoveryReport,
    /// Authenticated progress after repair, with any current repair failure marked pending.
    pub progress: Option<crate::policy_state::operations::SubmissionProgress>,
    /// Managed cached status or UNKNOWN; otherwise the endpoint's status.
    pub chain_status: String,
    /// The including ledger, when known.
    pub ledger: Option<u32>,
    /// The resulting submission receipt.
    pub record: Option<SubmissionReceipt>,
    /// The resulting open reservation.
    pub reservation: Option<SubmissionHold>,
    /// Whether the reservation belongs to the receipt.
    pub reservation_open: bool,
}

/// A status failure whose wire rendering belongs to the caller.
#[derive(Debug)]
pub enum StatusFailure {
    /// The authenticated window cannot be read.
    WindowUnreadable(WindowStoreError),
    /// Opening the receipt store fails; `detail` is the recording refusal text.
    ReceiptStoreOpen {
        /// The refusal text the caller renders as `submission.record_unavailable`.
        detail: String,
    },
    /// Reading a receipt fails.
    ReceiptStoreRead(ReceiptStoreError),
    /// The system clock cannot be read.
    ClockUnavailable(WalletLifecycleError),
    /// Reconciliation refuses after accounting delivery is attempted.
    ReconcileRefused(WindowStoreError),
    /// Resolving the approval store directory fails.
    ApprovalDirUnavailable(StateDirError),
    /// Repairing approval consumption, or the receipt acknowledgement of that
    /// consumption, refuses. A checked outcome projection refusal is logged
    /// and refuses no status lookup.
    RepairRefused(WalletError),
    /// Querying the chain fails.
    ChainQueryFailed(NetworkError),
    /// The selectors name no retained operation or two different ones.
    SelectorRefused(WalletError),
}

/// Resolves a status call's selectors before any reconciliation. A testnet
/// profile keeps no operation records, so its selectors read nothing and
/// target only the supplied hash.
///
/// # Errors
///
/// [`StatusFailure::SelectorRefused`] with `operation.unknown` or
/// `validation.usage_error`, and [`StatusFailure::WindowUnreadable`].
pub fn select_status(
    profile: &Profile,
    window: &PersistedWindowStore,
    selectors: &crate::policy_state::StatusSelectors,
) -> Result<crate::policy_state::StatusTarget, StatusFailure> {
    if !profile.chain_id.is_mainnet() {
        return Ok(crate::policy_state::StatusTarget {
            operation_id: None,
            tx_hash: selectors.tx_hash.clone(),
        });
    }
    crate::policy_state::OperationStatus::new(window, profile)
        .select(selectors)
        .map_err(StatusFailure::WindowUnreadable)?
        .map_err(StatusFailure::SelectorRefused)
}

/// Projects the targeted operation from the window as the status call left it.
///
/// # Errors
///
/// [`StatusFailure::WindowUnreadable`].
pub fn operation_projection(
    profile: &Profile,
    window: &PersistedWindowStore,
    target: &crate::policy_state::StatusTarget,
) -> Result<Option<crate::policy_state::OperationProjection>, StatusFailure> {
    let Some(id) = &target.operation_id else {
        return Ok(None);
    };
    crate::policy_state::OperationStatus::new(window, profile)
        .projection(id)
        .map_err(StatusFailure::WindowUnreadable)
}

/// Logs the refusal without inferring release state from the failed call.
pub(crate) fn warn_status_recovery_refusal(
    profile_name: &str,
    error: &crate::policy_state::RecoveryError,
) {
    tracing::warn!(
        profile = %profile_name,
        code = error.code(),
        error = %error,
        "transaction status: recovery refused; completed work remains committed"
    );
}

/// One audit-writer acquisition shared by the status steps after
/// reconciliation. The first step that needs the writer acquires it, and a
/// refusal is cached too, so no later step acquires again.
struct OnceWriter<F> {
    acquire: F,
    state: WriterState,
}

enum WriterState {
    Unacquired,
    Acquired(Arc<Mutex<AuditWriter>>),
    Refused(Option<WalletError>),
}

impl<F: Fn() -> Result<Arc<Mutex<AuditWriter>>, WalletError>> OnceWriter<F> {
    fn result(&mut self) -> &mut WriterState {
        if matches!(self.state, WriterState::Unacquired) {
            self.state = match (self.acquire)() {
                Ok(writer) => WriterState::Acquired(writer),
                Err(error) => WriterState::Refused(Some(error)),
            };
        }
        &mut self.state
    }

    /// The acquired writer, or `None` after a refusal.
    fn handle(&mut self) -> Option<Arc<Mutex<AuditWriter>>> {
        match self.result() {
            WriterState::Acquired(writer) => Some(Arc::clone(writer)),
            _ => None,
        }
    }

    /// The acquired writer, or the cached refusal for the drain to report.
    #[expect(
        clippy::expect_used,
        reason = "the drain's FnOnce consumes a refusal once"
    )]
    fn for_drain(&mut self) -> Result<Arc<Mutex<AuditWriter>>, WalletError> {
        let result = match self.result() {
            WriterState::Acquired(writer) => Some(Ok(Arc::clone(writer))),
            WriterState::Refused(refusal) => refusal.take().map(Err),
            WriterState::Unacquired => None,
        };
        // result acquires first, and only the drain's FnOnce takes the error.
        result.expect("the status drain consumes its writer result once")
    }
}

/// Reconciles one transaction and reads its resulting receipt and reservation.
/// Managed hashes use cached recovery evidence or UNKNOWN without an extra RPC.
/// Unmanaged hashes retain the primary lookup.
///
/// Mainnet recovery and accounting delivery use the caller's audit writer.
/// After reconciliation, recovery, the drain and receipt repair share one
/// writer acquisition, made by the first of them that needs it.
///
/// On a mainnet profile, after accounting delivery, the lookup repairs the
/// checked receipt of the transaction's committed recovery decision. A
/// repair refusal is logged with its code and detail, and the lookup
/// continues. Approval repair then reads the receipt again.
///
/// # Errors
/// Returns the typed failure at the step that refuses the status lookup.
pub async fn transaction_status(
    request: StatusRequest<'_>,
    approval_dir: impl FnOnce() -> Result<PathBuf, StateDirError>,
    writer: impl Fn() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
) -> Result<StatusOutcome, StatusFailure> {
    transaction_status_committed(
        request,
        approval_dir,
        writer,
        &mut CommittedBatch::default(),
    )
    .await
}

/// [`transaction_status`], appending the transitions its recovery driver
/// commits to `committed`, also when a later step refuses the lookup.
///
/// On mainnet the caller passes clients whose hosts the enablement verified
/// in the same process.
///
/// # Errors
/// The errors of [`transaction_status`].
pub async fn transaction_status_committed(
    request: StatusRequest<'_>,
    approval_dir: impl FnOnce() -> Result<PathBuf, StateDirError>,
    writer: impl Fn() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
    committed: &mut CommittedBatch,
) -> Result<StatusOutcome, StatusFailure> {
    status_lookup(request, approval_dir, writer, committed, true).await
}

/// [`transaction_status`] without its settlement steps, for a mainnet
/// profile with no verified enablement.
///
/// It runs no reconciliation, no recovery stage, and no release, so no
/// reservation, hold, or outcome changes. It reads the cached recovery
/// results, delivers owed accounting obligations, repairs the receipts of
/// committed decisions, and asks the primary endpoint for a hash with no
/// cached result.
///
/// # Errors
/// The errors of [`transaction_status`], except a reconciliation refusal.
pub async fn transaction_status_unsettled(
    request: StatusRequest<'_>,
    approval_dir: impl FnOnce() -> Result<PathBuf, StateDirError>,
    writer: impl Fn() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
) -> Result<StatusOutcome, StatusFailure> {
    status_lookup(
        request,
        approval_dir,
        writer,
        &mut CommittedBatch::default(),
        false,
    )
    .await
}

/// The status lookup; `settle` runs reconciliation, the recovery stage and
/// its release.
async fn status_lookup(
    request: StatusRequest<'_>,
    approval_dir: impl FnOnce() -> Result<PathBuf, StateDirError>,
    writer: impl Fn() -> Result<Arc<Mutex<AuditWriter>>, WalletError>,
    committed: &mut CommittedBatch,
    settle: bool,
) -> Result<StatusOutcome, StatusFailure> {
    let StatusRequest {
        profile,
        profile_name,
        tx_hash,
        window,
        client,
        oracle,
        retry_recovery,
    } = request;
    let held = window
        .pending_reservations(profile)
        .map_err(StatusFailure::WindowUnreadable)?
        .into_iter()
        .find(|r| r.tx_hash == tx_hash);
    let receipts = open_receipt_store(profile_name)
        .map_err(|detail| StatusFailure::ReceiptStoreOpen { detail })?;
    let receipt = receipts
        .find_by_tx_hash(tx_hash)
        .map_err(StatusFailure::ReceiptStoreRead)?;
    let envelope_hash = receipt
        .as_ref()
        .map(|r| r.envelope_hash.as_str())
        .or_else(|| held.as_ref().map(|r| r.id.as_str()));
    // The caller asked about this transaction by name, so the reservation and
    // the receipt reconcile together with no budget. A submission whose
    // receipt is missing reconciles from its authenticated reservation. On a
    // mainnet profile the oracle witnesses the primary's negative answers.
    if settle && let Some(envelope_hash) = envelope_hash {
        let now_ms =
            stellar_agent_core::timefmt::now_unix_ms().map_err(StatusFailure::ClockUnavailable)?;
        match window
            .reconcile_one(
                profile,
                client,
                oracle,
                Some(&receipts),
                envelope_hash,
                now_ms,
            )
            .await
        {
            Ok(report) if report.receipt_write_failed > 0 => tracing::warn!(
                receipt_write_failed = report.receipt_write_failed,
                "transaction status: reconciliation could not record the receipt"
            ),
            Ok(_) => {}
            Err(error) => {
                // A refused pass leaves the obligations of earlier calls in
                // place; they are delivered before the refusal returns. The
                // drain logs its own refusal and leaves the obligations owed.
                let _ = drain_accounting_obligations(
                    window,
                    profile,
                    profile_name,
                    Some(&receipts),
                    &writer,
                );
                return Err(StatusFailure::ReconcileRefused(error));
            }
        }
    }
    let mut writer = OnceWriter {
        acquire: writer,
        state: WriterState::Unacquired,
    };
    let mut sequences = "not run";
    let mut recovery_report = crate::policy_state::RecoveryReport::default();
    if profile.chain_id.is_mainnet()
        && status_recovery_enabled()
        && let Ok(hash) = stellar_agent_core::hex::decode_hex32(tx_hash)
    {
        let status = crate::policy_state::OperationStatus::new(window, profile);
        recovery_report = crate::policy_state::RecoveryReport::read(
            &status,
            Some(&hash),
            stellar_agent_core::timefmt::now_unix_ms().map_err(StatusFailure::ClockUnavailable)?,
        )
        .map_err(StatusFailure::WindowUnreadable)?;
        if settle && let Some(handle) = writer.handle() {
            let recovered = crate::policy_state::recovery::recover_outcomes_committed(
                window,
                profile,
                crate::policy_state::EndpointPair::from_clients(client, oracle),
                &handle,
                Some(&hash),
                retry_recovery,
                committed,
            )
            .await;
            release_ended_after_recovery(window, profile);
            match recovered {
                Ok(report) => {
                    sequences = if report.missing.is_some() {
                        "evidence missing"
                    } else {
                        "completed"
                    };
                    recovery_report = report;
                }
                Err(error) => {
                    sequences = "refused";
                    recovery_report = error.report().cloned().unwrap_or_else(|| {
                        crate::policy_state::RecoveryReport::refused(
                            &status,
                            Some(&hash),
                            error.code(),
                        )
                    });
                    warn_status_recovery_refusal(profile_name, &error);
                }
            }
        } else if let WriterState::Refused(Some(error)) = &writer.state {
            recovery_report =
                crate::policy_state::RecoveryReport::refused(&status, Some(&hash), error.code());
        }
    }
    // The status answer does not depend on the drain: a refusal is logged by
    // the drain and leaves the obligations owed for a later call.
    let _ = drain_accounting_obligations(window, profile, profile_name, Some(&receipts), || {
        writer.for_drain()
    });
    let repair = if profile.chain_id.is_mainnet()
        && let Ok(hash) = stellar_agent_core::hex::decode_hex32(tx_hash)
    {
        writer.handle().map(|writer| {
            recovery::repair_committed_receipts(window, profile, &receipts, &writer, Some(&hash))
        })
    } else {
        Some(Ok(()))
    };
    if let Some(Err(refused)) = &repair {
        recovery_report
            .refusal
            .get_or_insert(crate::policy_state::RecoveryRefusal {
                code: refused.code(),
                state_unavailable: false,
            });
        // The status answer stands; a later call repeats the refused repair.
        tracing::warn!(
            profile = %profile_name,
            code = refused.code(),
            sequence_recovery = sequences,
            detail = %refused,
            "transaction status: checked receipt repair refused; completed work remains committed"
        );
    }
    // Approval repair reads the receipt after projection, so a restored
    // nonce is consumed in this call.
    let projected = receipts
        .find_by_tx_hash(tx_hash)
        .map_err(StatusFailure::ReceiptStoreRead)?;
    if let Some(record) = &projected
        && record.approval_nonce.is_some()
    {
        let approval_dir = approval_dir().map_err(StatusFailure::ApprovalDirUnavailable)?;
        repair_approval_consumption(
            &receipts,
            &record.envelope_hash,
            &approval_dir,
            profile_name,
            profile.chain_id.is_mainnet().then_some((window, profile)),
        )
        .map_err(StatusFailure::RepairRefused)?;
    }
    if profile.chain_id.is_mainnet()
        && let Ok(hash) = stellar_agent_core::hex::decode_hex32(tx_hash)
    {
        recovery_report.refresh_settlements(
            &crate::policy_state::OperationStatus::new(window, profile),
            Some(&hash),
        );
    }
    let mut progress = if profile.chain_id.is_mainnet()
        && let Ok(hash) = stellar_agent_core::hex::decode_hex32(tx_hash)
    {
        crate::policy_state::OperationStatus::new(window, profile)
            .submission_progress(&hash)
            .map_err(StatusFailure::WindowUnreadable)?
    } else {
        None
    };
    if let Some(progress) = &mut progress
        && progress.decision.is_some_and(|decision| {
            repair.as_ref().is_none_or(|result| {
                result
                    .as_ref()
                    .is_err_and(|refused| refused.includes(decision))
            })
        })
    {
        progress.projection_pending = true;
    }
    let (chain_status, ledger) = if let Some(attempt) = recovery_report
        .attempts
        .iter()
        .min_by_key(|attempt| attempt.settlement.is_none())
    {
        let (status, ledger) = attempt.chain_status();
        (status.to_owned(), ledger)
    } else if recovery_report
        .refusal
        .as_ref()
        .is_some_and(|r| r.state_unavailable)
    {
        ("UNKNOWN".to_owned(), None)
    } else {
        let chain = client
            .get_transaction_status(tx_hash)
            .await
            .map_err(StatusFailure::ChainQueryFailed)?;
        (chain.status, chain.ledger)
    };
    // Both reads reflect reconciliation and the projection of owed accounting decisions.
    let reservation = window
        .pending_reservations(profile)
        .map_err(StatusFailure::WindowUnreadable)?
        .into_iter()
        .find(|r| r.tx_hash == tx_hash);
    let record = receipts
        .find_by_tx_hash(tx_hash)
        .map_err(StatusFailure::ReceiptStoreRead)?;
    let reservation_open = record.as_ref().is_some_and(|record| {
        reservation
            .as_ref()
            .is_some_and(|r| r.id == record.envelope_hash)
    });
    Ok(StatusOutcome {
        recovery: recovery_report,
        progress,
        chain_status,
        ledger,
        record,
        reservation,
        reservation_open,
    })
}

/// Returns true when `value` is 64 lowercase hex characters.
pub fn is_tx_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use super::*;

    /// A reconciliation pass on a mainnet profile applies the operation store's
    /// expiry edges before its other work. A `Sending` attempt whose
    /// authorization expired unused, never claimed and never exposed, ends as
    /// `NotSent`.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(mainnet_clock)]
    #[serial_test::serial]
    async fn reconcile_pass_runs_expire_due() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        use crate::mainnet::fixtures::{self, LedgerFixture, TTL_MS};
        const NOW: u64 = 1_800_000_000_000;
        let fx = LedgerFixture::new("reconcile-expire", NOW);
        let unsigned = fixtures::unsigned_envelope();
        let binding = fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex());
        let (attempt, authorization) = fx.linked_attempt(binding, &[], "order-1");
        assert_eq!(fx.operation_record(attempt)["state"], "sending");
        let later = NOW + TTL_MS + 1;
        fx.clock.set(later);
        let client = StellarRpcClient::new("http://127.0.0.1:1").unwrap();

        let pass = reconcile_pass(&fx.profile, &fx.window, &client, None, None, later, || {
            Ok(Arc::clone(&fx.writer))
        })
        .await;

        assert!(matches!(pass, ReconcilePass::Recovered { .. }), "{pass:?}");
        let record = fx.operation_record(attempt);
        assert_eq!(record["state"], "not_sent", "{record}");
        assert_eq!(
            fx.authorization_record(authorization.id())["state"],
            "expired"
        );
    }

    /// Without `mainnet-write` the full and the legacy dispatch pass both
    /// hand their expiry edge to the caller's batch.
    #[tokio::test]
    #[serial_test::serial]
    async fn flow_batches_keep_expiry_edges_without_the_mainnet_feature() {
        use crate::operation_entry::tests::{StoreLinked, batch_edges};
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        for legacy in [false, true] {
            let linked = StoreLinked::new();
            let attempt = linked.begin(&mut CommittedBatch::default()).unwrap();
            let later = crate::mainnet::clock::now_ms().unwrap() + 120_001;
            linked.fx.clock.set(later);
            let client = StellarRpcClient::new("http://127.0.0.1:1").unwrap();
            let writer = || Ok(Arc::clone(&linked.writer));
            let mut committed = CommittedBatch::default();
            let fx = &linked.fx;
            let pass = if legacy {
                reconcile_legacy_pass_committed(
                    &fx.profile,
                    &fx.store,
                    &client,
                    None,
                    None,
                    later,
                    writer,
                    &mut committed,
                )
                .await
            } else {
                reconcile_pass_committed(
                    &fx.profile,
                    &fx.store,
                    &client,
                    None,
                    None,
                    later,
                    writer,
                    &mut committed,
                )
                .await
            };
            assert!(
                if legacy {
                    matches!(pass, ReconcilePass::Completed(_))
                } else {
                    matches!(pass, ReconcilePass::Recovered { .. })
                },
                "{pass:?}"
            );
            assert_eq!(
                batch_edges(&committed),
                vec![(
                    attempt.operation_id,
                    crate::policy_state::OperationState::NotSent,
                    Some(attempt.attempt_index)
                )],
                "legacy: {legacy}"
            );
        }
    }

    /// The full and the legacy dispatch pass both hand their expiry edge to
    /// the caller's batch.
    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(mainnet_clock)]
    #[serial_test::serial]
    async fn flow_batches_keep_expiry_edges() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        use crate::mainnet::fixtures::{self, LedgerFixture, TTL_MS};
        const NOW: u64 = 1_800_000_000_000;
        for legacy in [false, true] {
            let fx = LedgerFixture::new("reconcile-expire-committed", NOW);
            let unsigned = fixtures::unsigned_envelope();
            let binding = fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex());
            let (attempt, _) = fx.linked_attempt(binding, &[], "order-1");
            let later = NOW + TTL_MS + 1;
            fx.clock.set(later);
            let client = StellarRpcClient::new("http://127.0.0.1:1").unwrap();
            let writer = || Ok(Arc::clone(&fx.writer));
            let mut committed = CommittedBatch::default();
            let pass = if legacy {
                reconcile_legacy_pass_committed(
                    &fx.profile,
                    &fx.window,
                    &client,
                    None,
                    None,
                    later,
                    writer,
                    &mut committed,
                )
                .await
            } else {
                reconcile_pass_committed(
                    &fx.profile,
                    &fx.window,
                    &client,
                    None,
                    None,
                    later,
                    writer,
                    &mut committed,
                )
                .await
            };
            assert!(
                if legacy {
                    matches!(pass, ReconcilePass::Completed(_))
                } else {
                    matches!(pass, ReconcilePass::Recovered { .. })
                },
                "{pass:?}"
            );
            let edges: Vec<_> = committed
                .into_iter()
                .map(|edge| (edge.operation_id(), edge.state(), edge.attempt_index()))
                .collect();
            assert_eq!(
                edges,
                vec![(
                    attempt.operation_id,
                    crate::policy_state::OperationState::NotSent,
                    Some(attempt.attempt_index)
                )],
                "legacy: {legacy}"
            );
        }
    }

    #[test]
    fn checked_sizing_maps_refused_to_policy_denied() {
        let error = checked_sizing(
            SizingOutcome::Refused(stellar_agent_core::policy::DenyReason::EvaluationError {
                detail: "sizing refusal".to_owned(),
            }),
            || unreachable!(),
        )
        .unwrap_err();
        let WalletError::PolicyDenied { reason } = error else {
            panic!("expected policy denial");
        };
        assert!(
            matches!(*reason, stellar_agent_core::policy::DenyReason::EvaluationError { detail } if detail == "sizing refusal")
        );
    }

    #[test]
    fn submission_details_recovery_required() {
        use stellar_agent_test_support::signed_envelope::SignedTestEnvelope;
        let errors = [
            SubmissionError::TxTimeout {
                tx_hash: "ab".repeat(32),
                seconds: 30,
            },
            SubmissionError::TxAlreadySubmitted {
                hash: "ab".repeat(32),
            },
            SubmissionError::HashMismatch {
                local: "ab".repeat(32),
                server: "cd".repeat(32),
            },
        ];
        let edge = u64::MAX / 1000 - 6;
        for error in errors {
            let error = WalletError::Submission(error);
            for bound in [0, 1, edge, edge + 1, u64::MAX - 1, u64::MAX] {
                let signed = SignedTestEnvelope::builder([1; 32])
                    .time_bounds(0, bound)
                    .build();
                let details = submission_details(&error, signed.envelope_xdr(), "status").unwrap();
                let recovery = &details["recovery"];
                assert_eq!(details["tx_hash"], "ab".repeat(32));
                assert_eq!(
                    details["envelope_hash"],
                    envelope_hash_hex(signed.envelope_xdr())
                );
                assert_eq!(recovery["result"], "NeedsEvidence");
                assert_eq!(recovery["reason"], "RecoveryRequired");
                assert_eq!(recovery["next_action"], "TargetedStatus");
                if bound == 1 || bound == edge {
                    assert_eq!(recovery["earliest_retry_ms"], (bound + 6) * 1000);
                    assert!(recovery.get("retry_time_unavailable").is_none());
                } else {
                    assert!(recovery.get("earliest_retry_ms").is_none());
                    assert_eq!(
                        recovery["retry_time_unavailable"],
                        if bound == 0 || bound == u64::MAX {
                            "MissingBound"
                        } else {
                            "Overflow"
                        }
                    );
                }
                assert!(recovery.get("attempt_index").is_none());
            }
            for text in ["", "malformed"] {
                let details = submission_details(&error, text, "status").unwrap();
                assert_eq!(
                    details["recovery"]["retry_time_unavailable"],
                    "MissingBound"
                );
                assert!(details["recovery"].get("earliest_retry_ms").is_none());
            }
        }
    }

    #[test]
    fn submission_details_names_the_reconcile_verb() {
        let error = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: "ab".repeat(32),
            seconds: 30,
        });
        for verb in ["stellar_transaction_status", "stellar-agent tx status"] {
            let details = submission_details(&error, "", verb).unwrap();
            assert_eq!(details["reconcile_with"], verb);
            assert_eq!(details["outcome"], "unknown");
        }
    }

    #[test]
    #[serial_test::serial]
    fn settlement_oracle_preserves_the_configured_mainnet_client() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        use stellar_agent_core::profile::schema::{PrimaryProviderRecord, ProviderRecord};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let window = PersistedWindowStore::at_path(dir.path().join("oracle.window"));
        let mut profile = Profile::builder_mainnet_named(
            "flow-oracle",
            "https://primary.example",
            "signer",
            "account",
            "nonce",
            "account",
        )
        .primary_provider(PrimaryProviderRecord::new("Primary", "primary.example"))
        .oracle_provider_url(url::Url::parse("https://oracle.example").unwrap())
        .oracle_provider(ProviderRecord::new("Oracle", "oracle.example", true))
        .build();
        let context = NetworkContext::from_profile(&profile);
        assert!(settlement_oracle(&window, &profile, &context).is_some());
        profile.chain_id = stellar_agent_core::profile::caip2::Caip2::Testnet;
        let context = NetworkContext::from_profile(&profile);
        assert!(settlement_oracle(&window, &profile, &context).is_none());
    }

    #[cfg(feature = "mainnet-write")]
    #[tokio::test]
    #[serial_test::serial(mainnet_clock)]
    #[serial_test::serial]
    async fn stage_marked_recorder_marks_only_the_authorized_pre_send() {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        use crate::mainnet::fixtures::{self, LedgerFixture};
        let fx = LedgerFixture::new("stage-mark", 1000);
        let unsigned = fixtures::unsigned_envelope();
        let signed = fixtures::signed_envelope();
        let intent = fixtures::intent(&signed);
        let authorization = fx.mint(
            fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
            &[],
            None,
            "stage-approval",
        );
        let recorder = StageMarkedRecorder::new(fx.recorder(vec![], Some(Arc::clone(&fx.writer))));
        assert!(!recorder.pre_send_entered());
        let _ = recorder.pre_send(&intent).await;
        assert!(!recorder.pre_send_entered());
        recorder
            .outcome(
                &intent,
                &SubmissionOutcome::Success {
                    ledger: 1500,
                    created_at: None,
                },
            )
            .await;
        assert!(!recorder.pre_send_entered());
        let _ = recorder
            .pre_send_authorized(&intent, MainnetSubmitGrant::Tx(authorization))
            .await;
        assert!(recorder.pre_send_entered());
        assert!(format!("{recorder:?}").contains("pre_send_entered: true"));
    }

    #[test]
    fn accepts_a_lowercase_64_hex_hash() {
        assert!(is_tx_hash(&"ab".repeat(32)));
    }

    #[test]
    fn refuses_uppercase_wrong_length_and_non_hex() {
        assert!(!is_tx_hash(&"AB".repeat(32)));
        assert!(!is_tx_hash(&"ab".repeat(31)));
        assert!(!is_tx_hash(&"zz".repeat(32)));
    }
}
