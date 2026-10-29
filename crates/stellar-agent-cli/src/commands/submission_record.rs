//! Building the durable-submission recorder, reconciling what stands open, and
//! reporting what the submit layer refused.
//!
//! Every value verb that broadcasts records its submission before the
//! transaction is sent, and settles that record against what the network
//! answers. The construction is identical across the verbs, so it lives here
//! once, alongside the reconciliation pass each verb runs before its policy
//! gate and the mapping that turns the three unresolved-submission refusals
//! into a response an operator or an agent can act on.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use stellar_agent_core::approval::witness::ApprovalWitness;
use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::envelope::Envelope;
use stellar_agent_core::error::{NetworkError, SubmissionError, WalletError};
use stellar_agent_core::policy::v1::{ValueClass, ValueEffects};
use stellar_agent_core::policy::{McpToolRegistration, ToolDescriptor, ToolValueKind};
use stellar_agent_core::profile::receipt::{
    ReceiptStatus, ReceiptStore, ReleaseEvidence, SettledRow,
};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::cross_check::CrossCheckWitness;
use stellar_agent_network::mainnet::audit_readiness::AuditReadiness;
use stellar_agent_network::mainnet::authorization::MainnetTxSignAuthorization;
use stellar_agent_network::mainnet::consumed::AuthorizationConsumed;
use stellar_agent_network::policy_state::{PersistedWindowStore, RECONCILE_BUDGET};
use stellar_agent_network::{
    ApprovalTombstone, AuditWriterHandle, MainnetSubmitGrant, MainnetWriteContext, NetworkContext,
    StellarRpcClient, SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
    WalletSubmissionRecorder, envelope_hash_hex,
};

use crate::common::profile_access::ProfileOrigin;

/// The verb this binary names as the way to reconcile a submission whose
/// outcome is not known.
pub(crate) const RECONCILE_VERB: &str = "stellar-agent tx status";

/// Everything a value verb knows about the submission it is about to make.
pub(crate) struct SubmitRecord<'a> {
    /// The profile the submission is made under.
    pub profile: &'a Profile,
    /// The operator's resolved profile name.
    pub profile_name: String,
    /// The verb whose policy engine is rebuilt to size the action, as it
    /// appears in `policy.toml` diagnostics.
    pub verb: &'static str,
    /// The registered tool name, as it appears in the audit log.
    pub tool: &'static str,
    /// The policy decision that admitted this submission.
    pub policy_decision: stellar_agent_core::audit_log::PolicyDecision,
    /// CAIP-2 chain identifier for the audit rows.
    pub chain_id: &'a str,
    /// The value effects the policy gate sized. `None` records no window
    /// entries and no legs.
    pub effects: Option<&'a ValueEffects>,
    /// The audit writer the origin-aware pre-flight acquired. `None` only on a
    /// synthesized zero-configuration profile, which has no audit log to write
    /// to.
    pub audit: Option<Arc<Mutex<AuditWriter>>>,
    /// The caller's clock in unix milliseconds.
    pub now_ms: u64,
}

/// Builds the recorder for one submission.
///
/// The window entries come from the policy engine's own accounting for this
/// action, rebuilt from the profile the same way the gate's engine was: the
/// SAME derivation the gate evaluated and the audit rows carry.
///
/// # Errors
///
/// Returns `submission.record_unavailable` when the receipt store cannot be
/// opened, the policy engine cannot be rebuilt, or it cannot account for the
/// action. All three refuse the submission: a send the wallet cannot record is
/// one it cannot reconcile, cap, or audit afterwards.
pub(crate) fn build_recorder(
    record: SubmitRecord<'_>,
) -> Result<WalletSubmissionRecorder<'_>, WalletError> {
    let receipts = ReceiptStore::open(&record.profile_name).map_err(|e| {
        record_unavailable(format!(
            "the submission receipt store could not be opened: {e}"
        ))
    })?;

    let legs: Vec<ValueLegRecord> = record
        .effects
        .map(|e| e.legs().iter().map(Into::into).collect())
        .unwrap_or_default();

    let window_entries = match record.effects {
        Some(effects) => {
            let engine = crate::commands::policy_engine::build_v1_policy_engine(
                record.verb,
                &record.profile.policy.engine,
                record.profile,
                &record.profile_name,
            )
            .map_err(|e| {
                record_unavailable(format!("the policy engine could not be rebuilt: {e}"))
            })?;
            engine
                .record_confirmed(
                    &descriptor_for(record.tool, record.chain_id),
                    record.profile,
                    &ValueClass::Value(effects.clone()),
                )
                .map_err(|e| {
                    record_unavailable(format!(
                        "the policy engine could not account for this action: {e}"
                    ))
                })?
        }
        None => Vec::new(),
    };

    Ok(WalletSubmissionRecorder::new(
        record.profile,
        record.profile_name.clone(),
        record.tool,
        Some(record.chain_id.to_owned()),
        record.policy_decision,
        legs,
        window_entries,
        receipts,
        PersistedWindowStore::for_profile(&record.profile_name),
        record.audit,
        None,
        uuid::Uuid::new_v4().to_string(),
        record.now_ms,
    ))
}

/// What a mainnet write's recorder records, prepared before the
/// authorization is minted.
///
/// Everything that can fail is done here: the receipt store is open, the
/// approval directory is resolved, and the clock is read. Binding to the
/// minted authorization cannot fail, so no refusal falls between the mint and
/// the signer.
pub(crate) struct PreparedMainnetRecorder<'a> {
    profile: &'a Profile,
    profile_name: String,
    tool: &'static str,
    chain_id: String,
    decision: stellar_agent_core::audit_log::PolicyDecision,
    legs: Vec<ValueLegRecord>,
    receipts: ReceiptStore,
    window: PersistedWindowStore,
    audit: AuditWriterHandle,
    request_id: String,
    now_ms: u64,
    witness: Option<&'a CrossCheckWitness>,
    tombstone: ApprovalTombstone,
}

/// Prepares the recorder of a mainnet write under `context`.
///
/// The legs are the evaluation's `effects`; the window entries come from the
/// authorization at [`PreparedMainnetRecorder::bind_authorized`], never from
/// a rebuilt engine. The audit writer is the one `readiness` verified. The
/// confirmation entry `approval` names is tombstoned when the submission
/// settles.
///
/// # Errors
///
/// `submission.record_unavailable` when the receipt store cannot be opened,
/// the approval directory cannot be resolved, or the clock cannot be read.
pub(crate) fn prepare_mainnet_recorder<'a>(
    context: &'a MainnetWriteContext,
    tool: &'static str,
    decision: stellar_agent_core::audit_log::PolicyDecision,
    effects: Option<&ValueEffects>,
    readiness: &AuditReadiness,
    witness: Option<&'a CrossCheckWitness>,
    approval: &ApprovalWitness,
) -> Result<PreparedMainnetRecorder<'a>, WalletError> {
    let profile_name = context.profile_name().to_owned();
    let receipts = ReceiptStore::open(&profile_name).map_err(|e| {
        record_unavailable(format!(
            "the submission receipt store could not be opened: {e}"
        ))
    })?;
    let store_dir = crate::commands::approve::approval_store_dir().map_err(|e| {
        record_unavailable(format!(
            "the approval store directory could not be resolved: {e}"
        ))
    })?;
    let now_ms = stellar_agent_network::mainnet::clock::now_ms()
        .map_err(|e| record_unavailable(format!("the clock could not be read: {e}")))?;
    let legs: Vec<ValueLegRecord> = effects
        .map(|e| e.legs().iter().map(Into::into).collect())
        .unwrap_or_default();
    Ok(PreparedMainnetRecorder {
        profile: context.profile(),
        tombstone: ApprovalTombstone {
            store_dir,
            profile_name: profile_name.clone(),
            approval_nonce: approval.nonce().to_owned(),
        },
        window: PersistedWindowStore::for_profile(&profile_name),
        chain_id: context.chain().caip2_str().to_owned(),
        profile_name,
        tool,
        decision,
        legs,
        receipts,
        audit: Arc::clone(readiness.writer()),
        request_id: uuid::Uuid::new_v4().to_string(),
        now_ms,
        witness,
    })
}

impl<'a> PreparedMainnetRecorder<'a> {
    /// The request identifier shared by this write's audit records.
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Binds the prepared recorder to the minted `authorization`, whose
    /// window entries it records, with the witness and the confirmation's
    /// tombstone.
    #[must_use]
    pub(crate) fn bind_authorized(
        self,
        authorization: &MainnetTxSignAuthorization,
    ) -> StageMarkedRecorder<'a> {
        let recorder = WalletSubmissionRecorder::new_authorized(
            self.profile,
            self.profile_name,
            self.tool,
            Some(self.chain_id),
            self.decision,
            self.legs,
            authorization,
            self.receipts,
            self.window,
            Some(self.audit),
            None,
            self.request_id,
            self.now_ms,
        )
        .with_witness(self.witness)
        .with_approval(Some(self.tombstone));
        StageMarkedRecorder {
            inner: recorder,
            pre_send_entered: AtomicBool::new(false),
        }
    }
}

/// The recorder of a mainnet write, marking whether the submit reached the
/// authorized pre-send hook.
///
/// The mark separates the two refusals of the submit that share a code: a
/// refusal of the submit gate before the hook, and a refusal inside it.
pub(crate) struct StageMarkedRecorder<'a> {
    inner: WalletSubmissionRecorder<'a>,
    pre_send_entered: AtomicBool,
}

impl StageMarkedRecorder<'_> {
    /// Whether [`SubmissionRecorder::pre_send_authorized`] was entered.
    #[must_use]
    pub(crate) fn pre_send_entered(&self) -> bool {
        self.pre_send_entered.load(Ordering::SeqCst)
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

/// Reconstructs the [`ToolDescriptor`] the gate evaluated against.
fn descriptor_for(tool: &'static str, chain_id: &str) -> ToolDescriptor {
    let reg = McpToolRegistration {
        name: tool,
        destructive_hint: true,
        read_only_hint: false,
        chain_id_required: true,
        value_kind: ToolValueKind::MovesValue,
    };
    let mut descriptor = ToolDescriptor::from_registration(&reg);
    descriptor.chain_id = chain_id.to_owned();
    descriptor
}

/// The oracle a reconciliation pass of `profile` asks before a negative
/// answer of the primary endpoint settles a mainnet reservation, built from
/// the profile.
///
/// See [`settlement_oracle_in`].
pub(crate) fn settlement_oracle(profile: &Profile) -> Option<StellarRpcClient> {
    settlement_oracle_in(profile, &NetworkContext::from_profile(profile))
}

/// The oracle a reconciliation pass of `profile` asks before a negative
/// answer of the primary endpoint settles a mainnet reservation, built as
/// `context` builds its clients.
///
/// `None` for a profile on another chain, whose pass never reads an oracle,
/// and for a mainnet profile that names none. An oracle client that cannot
/// be built is logged and also yields `None`: the pass then keeps every
/// reservation the primary reports as failed or unknown, as it does when the
/// oracle cannot be reached.
pub(crate) fn settlement_oracle_in(
    profile: &Profile,
    context: &NetworkContext,
) -> Option<StellarRpcClient> {
    if !profile.chain_id.is_mainnet() {
        return None;
    }
    match context.oracle_client(profile) {
        Ok(oracle) => oracle,
        Err(e) => {
            tracing::warn!(
                code = %e.code(),
                "window reconcile: the oracle client could not be built; negative answers of \
                 the primary endpoint settle nothing this pass"
            );
            None
        }
    }
}

/// Settles the reservations that have stood long enough to be settleable,
/// before the policy gate counts them.
///
/// A reservation counts against the operator's caps while it stands, so a
/// verb that is about to be gated asks the chain about the oldest few first.
/// Reconciliation is not a gate of its own: a pass that cannot reach the
/// endpoint leaves every reservation standing and the verb continues, because
/// counting a reservation that may still apply is the safe direction.
///
/// On a mainnet profile `oracle` witnesses the primary endpoint's negative
/// answers; [`settlement_oracle`] builds it.
///
/// The settled rows are written under the audit binding check of `origin`,
/// so a synthesized profile records no binding.
pub(crate) async fn reconcile_open_reservations(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
    client: &StellarRpcClient,
    oracle: Option<&StellarRpcClient>,
    now_ms: u64,
) {
    let receipts = match ReceiptStore::open(profile_name) {
        Ok(store) => Some(store),
        Err(e) => {
            tracing::debug!(
                profile = %profile_name,
                error = %e,
                "window reconcile: receipt store unavailable; receipts are not updated by this pass"
            );
            None
        }
    };
    let window = PersistedWindowStore::for_profile(profile_name);
    let report = match window
        .reconcile_due(
            profile,
            client,
            oracle,
            receipts.as_ref(),
            now_ms,
            RECONCILE_BUDGET,
        )
        .await
    {
        Ok(report) => report,
        Err(e) => {
            tracing::debug!(
                profile = %profile_name,
                error = ?e,
                "window reconcile: pass failed; open reservations stand"
            );
            return;
        }
    };

    // A submission the pass settled is owed the value-action row it never got
    // to write. The writer is the same keyed one the verb itself uses, so a
    // log that cannot be appended leaves the row owed rather than the
    // settlement undone.
    if report.settled.is_empty() {
        return;
    }
    let Some(audit) = settled_rows_writer(profile, profile_name, origin) else {
        tracing::debug!(
            profile = %profile_name,
            settled = report.settled.len(),
            "window reconcile: no audit writer; the settled rows stay owed"
        );
        return;
    };
    for settled in &report.settled {
        write_settled_row_with_evidence(
            profile,
            profile_name,
            &audit,
            &settled.envelope_hash,
            &settled.tx_hash,
            &settled.status,
            settled.release_code,
            settled.ledger,
            stellar_agent_core::audit_log::PolicyDecision::Allow,
        );
    }
}

/// The writer for the rows a reconciliation pass settled, acquired under the
/// audit binding check of `origin`.
///
/// `None` when no writer is acquirable or the binding refuses; the settled
/// rows then stay owed.
fn settled_rows_writer(
    profile: &Profile,
    profile_name: &str,
    origin: ProfileOrigin,
) -> Option<Arc<Mutex<AuditWriter>>> {
    match crate::commands::value_audit::require_value_audit_writer_for_origin(
        profile,
        profile_name,
        origin,
    ) {
        Ok(writer) => writer,
        Err(e) => {
            tracing::debug!(
                profile = %profile_name,
                code = %e.code(),
                "window reconcile: audit writer refused"
            );
            None
        }
    }
}

/// Writes the value-action row that settles a reconciled submission whose
/// receipt carries no release evidence.
///
/// See [`write_settled_row_with_evidence`].
#[allow(
    clippy::too_many_arguments,
    reason = "settlement carries submission identity and the reconciliation decision"
)]
pub(crate) fn write_settled_row(
    profile: &Profile,
    profile_name: &str,
    audit: &Arc<Mutex<AuditWriter>>,
    envelope_hash: &str,
    tx_hash: &str,
    status: &ReceiptStatus,
    ledger: Option<u32>,
    reconciliation_decision: stellar_agent_core::audit_log::PolicyDecision,
) {
    write_settled_row_with_evidence(
        profile,
        profile_name,
        audit,
        envelope_hash,
        tx_hash,
        status,
        None,
        ledger,
        reconciliation_decision,
    );
}

/// Writes the value-action row that settles a reconciled submission.
///
/// The row carries the SAME value legs the gate sized, read back from the
/// pending row this submission wrote before it was sent: they were derived
/// once, at the gate, and are never re-derived here. `ledger` is the ledger
/// the chain reports the transaction in.
///
/// Non-fatal: the chain has already answered, and the settled record is the
/// receipt and the spending window. A row that cannot be appended is logged,
/// and the receipt keeps what a later run needs to write it. A settlement
/// lookup that cannot read the retained history is logged at WARN with the
/// profile, the envelope hash, and the error, and writes nothing: whether the
/// row is owed is unknown, and a row written on a guess could count one spend
/// twice. A later run retries the lookup and appends any row still owed.
#[allow(
    clippy::too_many_arguments,
    reason = "settlement carries submission identity, its evidence and the reconciliation decision"
)]
pub(crate) fn write_settled_row_with_evidence(
    profile: &Profile,
    profile_name: &str,
    audit: &Arc<Mutex<AuditWriter>>,
    envelope_hash: &str,
    tx_hash: &str,
    status: &ReceiptStatus,
    release_code: Option<ReleaseEvidence>,
    ledger: Option<u32>,
    reconciliation_decision: stellar_agent_core::audit_log::PolicyDecision,
) {
    match settled_row(
        profile,
        envelope_hash,
        tx_hash,
        status,
        release_code,
        ledger,
        reconciliation_decision,
    ) {
        Ok(Some(entry)) => crate::commands::value_audit::emit_value_audit_row_with_writer(
            audit,
            profile_name,
            entry,
        ),
        Ok(None) => {}
        Err(error) => tracing::warn!(
            profile = %profile_name,
            envelope_hash = %envelope_hash,
            error = %error,
            "settlement lookup could not read the audit history; settled row NOT emitted"
        ),
    }
}

/// Appends the value-action row that settles a reconciled submission, and
/// reports a failed append.
///
/// `Ok` means the log carries the settled row: it was found in the retained
/// history, it was appended now, or the submission owes none. An operator
/// verb that is about to close the submission's record calls this first, so
/// the record is closed only once its settlement is in the log. A history
/// that cannot be read refuses, because it cannot show that the row is
/// there.
///
/// # Errors
///
/// The append failure, mapped as every strict audit append maps it, to an
/// `audit.*` code (`audit.tip_anchor_mismatch` included); a poisoned writer
/// mutex is `audit.chain_key_unavailable`. A settlement lookup that cannot
/// read the retained history keeps the verifier's `audit.*` code and message.
#[allow(
    clippy::too_many_arguments,
    reason = "settlement carries submission identity, its evidence and the reconciliation decision"
)]
pub(crate) fn append_settled_row(
    profile: &Profile,
    profile_name: &str,
    audit: &Arc<Mutex<AuditWriter>>,
    envelope_hash: &str,
    tx_hash: &str,
    status: &ReceiptStatus,
    release_code: Option<ReleaseEvidence>,
    reconciliation_decision: stellar_agent_core::audit_log::PolicyDecision,
) -> Result<(), Envelope<()>> {
    let Some(entry) = settled_row(
        profile,
        envelope_hash,
        tx_hash,
        status,
        release_code,
        None,
        reconciliation_decision,
    )
    .map_err(|error| Envelope::err_raw(error.wire_code(), error.to_string()))?
    else {
        return Ok(());
    };
    let mut guard = audit.lock().map_err(|_| {
        Envelope::err(&crate::commands::value_audit::audit_writer_open_failed(
            profile_name,
        ))
    })?;
    crate::commands::value_audit::append_value_audit_row_strict(&mut guard, profile_name, entry)
        .map_err(|error| Envelope::err(&error))
}

/// The value-action row a reconciled submission still owes the log, or
/// `None` when it owes none.
///
/// A `Success` receipt owes a `value_action_submitted` row and a `Failed` one
/// a `value_action_failed` row under its failure code. An `Ambiguous` receipt
/// released on chain evidence owes a `value_action_failed` row under the
/// evidence's wire code: the reservation is gone, and the log records why.
/// Every other status leaves the outcome open, which is what the pending row
/// already records: a pending receipt, and an ambiguous one whose retention
/// window closed. A receipt an operator cleared owes no row by design; the
/// `submission_receipt_cleared` row records the clear.
///
/// The settlement lookup reads the retained history, newest file first. A
/// settled row found there means the submission is accounted for, so a
/// repeated reconciliation writes nothing. A status that owes no row returns
/// before the lookup.
///
/// # Errors
///
/// The lookup's integrity error when a visited file cannot be read or its
/// chain does not verify. Whether a row is owed is then unknown, which the
/// caller handles: [`write_settled_row_with_evidence`] logs it and writes
/// nothing, and [`append_settled_row`] refuses.
fn settled_row(
    profile: &Profile,
    envelope_hash: &str,
    tx_hash: &str,
    status: &ReceiptStatus,
    release_code: Option<ReleaseEvidence>,
    ledger: Option<u32>,
    reconciliation_decision: stellar_agent_core::audit_log::PolicyDecision,
) -> Result<
    Option<stellar_agent_core::audit_log::AuditEntry>,
    stellar_agent_core::audit_log::AuditLogIntegrityError,
> {
    use stellar_agent_core::audit_log::{AuditEntry, reader::ValueActionSettlement};

    let Some(row) = status.settled_row(release_code) else {
        return Ok(None);
    };

    let (tool, chain_id, legs, nonce_id, policy_decision, approval_nonce, witness) =
        match stellar_agent_core::audit_log::reader::try_value_action_settlement(
            &profile.audit_log_path,
            envelope_hash,
        )? {
            // Already accounted for. Reconciliation is repeatable, and a second
            // row would count one spend twice.
            ValueActionSettlement::Settled => return Ok(None),
            ValueActionSettlement::Owed(pending) => (
                pending.tool,
                pending.chain_id,
                pending.legs,
                pending.nonce_id,
                pending.policy_decision,
                pending.approval_nonce,
                pending.witness,
            ),
            // No pending row survives in retained history, so its sizing is
            // unavailable. The outcome still belongs in the log, under the name
            // of the surface that settled it.
            ValueActionSettlement::OwedWithoutLegs => (
                RECONCILE_VERB.to_owned(),
                profile.chain_id.caip2_str().to_owned().into(),
                Vec::new(),
                None,
                reconciliation_decision,
                None,
                None,
            ),
        };
    let chain_id: Option<String> = chain_id;
    let tx_redacted = stellar_agent_network::redact_tx_hash(tx_hash);
    let request_id = uuid::Uuid::new_v4().to_string();
    Ok(Some(match row {
        SettledRow::Submitted => AuditEntry::new_value_action_submitted(
            tool,
            chain_id,
            legs,
            tx_redacted.as_str(),
            ledger.unwrap_or(0),
            policy_decision,
            Some(envelope_hash.to_owned()),
            nonce_id,
            approval_nonce,
            &request_id,
            witness,
        ),
        SettledRow::Failed { code } => AuditEntry::new_value_action_failed(
            tool,
            chain_id,
            legs,
            tx_redacted.as_str(),
            code,
            policy_decision,
            Some(envelope_hash.to_owned()),
            nonce_id,
            approval_nonce,
            &request_id,
        ),
    }))
}

/// Renders a submit-path error, attaching the structured detail the three
/// unknown-outcome codes need.
///
/// `submission.tx_timeout`, `submission.tx_already_submitted` and
/// `submission.hash_mismatch` all describe a transaction whose outcome only
/// reconciliation can settle, and the caller needs the full transaction hash
/// to do it. The message stays redacted; the hash travels as data.
///
/// A policy denial from the reservation write renders as this binary's gate
/// denials do, under `verb`. Every other error renders as a wallet error.
pub(crate) fn error_envelope(err: &WalletError, signed_xdr: &str, verb: &str) -> Envelope<()> {
    if let Some(envelope) = policy_denial_envelope(err, verb) {
        return envelope;
    }
    match submission_details(err, signed_xdr) {
        Some(details) => Envelope::<()>::err_with_details(err, details),
        None => Envelope::<()>::err(err),
    }
}

/// The refusal envelope for a policy denial reported by the submit path, or
/// `None` for every other error.
///
/// The spending-window reservation write re-applies the governing criterion's
/// comparison under its own lock and refuses a submission the window can no
/// longer admit. That refusal is the same decision the gate makes, so it is
/// reported the same way: the criterion's own wire code, and the wording
/// `policy_engine`'s deny arm uses for `verb`.
pub(crate) fn policy_denial_envelope(err: &WalletError, verb: &str) -> Option<Envelope<()>> {
    let WalletError::PolicyDenied { reason } = err else {
        return None;
    };
    let message = match reason.as_ref() {
        stellar_agent_core::policy::DenyReason::EvaluationError { detail } => {
            format!("{verb} operation denied by operator policy: {detail}")
        }
        _ => format!("{verb} operation denied by operator policy"),
    };
    Some(Envelope::<()>::err_raw(reason.wire_code(), message))
}

/// The wire code a submission that was never sent reports. A pre-send
/// refusal, so it carries no `details`.
const UNRESOLVED_RECORD_UNAVAILABLE: &str = "submission.record_unavailable";

/// An unresolved submission reported by a verb that holds the typed DeFi or
/// smart-account error rather than a [`WalletError`].
///
/// The submit layer's refusal reaches those verbs through
/// `SaError::SubmissionUnresolved` and `DefiAdapterError::SubmissionUnresolved`,
/// which carry the wire code and the identifiers. Flattening them to a generic
/// failure would leave the operator with a redacted message and no hash, which
/// is the state the durable record exists to remove.
pub(crate) struct UnresolvedSubmission<'a> {
    /// The stable `submission.*` code for the condition.
    pub wire_code: &'static str,
    /// The redacted operator-facing message.
    pub message: &'a str,
    /// The transaction to reconcile, in full.
    pub tx_hash: Option<&'a str>,
    /// The submission record's identity, when the verb holds it.
    pub envelope_hash: Option<&'a str>,
    /// The submission timeout in seconds, on the one condition that has one.
    pub timeout_seconds: Option<u64>,
}

impl UnresolvedSubmission<'_> {
    /// The `details` object the recovery protocol reads, or `None`.
    ///
    /// Only the three codes that describe a transaction whose outcome is
    /// unknown carry one. `submission.record_unavailable` is a pre-send
    /// refusal: nothing was sent, there is no transaction to reconcile, and an
    /// `outcome: "unknown"` on it would say the opposite of what happened.
    fn details(&self) -> Option<serde_json::Value> {
        if self.wire_code == UNRESOLVED_RECORD_UNAVAILABLE {
            return None;
        }
        let mut details = serde_json::Map::new();
        if let Some(tx_hash) = self.tx_hash {
            details.insert("tx_hash".to_owned(), tx_hash.into());
        }
        if let Some(envelope_hash) = self.envelope_hash {
            details.insert("envelope_hash".to_owned(), envelope_hash.into());
        }
        if let Some(seconds) = self.timeout_seconds {
            details.insert("timeout_seconds".to_owned(), seconds.into());
        }
        details.insert("outcome".to_owned(), "unknown".into());
        details.insert("reconcile_with".to_owned(), RECONCILE_VERB.into());
        Some(serde_json::Value::Object(details))
    }

    /// The envelope this submission is reported in.
    pub(crate) fn envelope(&self) -> Envelope<()> {
        match self.details() {
            Some(details) => Envelope::<()>::err_raw_with_details(
                self.wire_code,
                self.message.to_owned(),
                details,
            ),
            None => Envelope::<()>::err_raw(self.wire_code, self.message.to_owned()),
        }
    }
}

/// Reads an unresolved submission out of a smart-account error, or `None`.
pub(crate) fn unresolved_from_sa(
    error: &stellar_agent_smart_account::SaError,
) -> Option<UnresolvedSubmission<'_>> {
    match error {
        stellar_agent_smart_account::SaError::SubmissionUnresolved {
            kind,
            message,
            tx_hash,
            envelope_hash,
            timeout_seconds,
        } => Some(UnresolvedSubmission {
            wire_code: kind.wire_code(),
            message,
            tx_hash: tx_hash.as_deref(),
            envelope_hash: envelope_hash.as_deref(),
            timeout_seconds: *timeout_seconds,
        }),
        _ => None,
    }
}

/// Reads an unresolved submission out of a DeFi adapter error, or `None`.
pub(crate) fn unresolved_from_defi(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
) -> Option<UnresolvedSubmission<'_>> {
    match error {
        stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code,
            message,
            tx_hash,
            envelope_hash,
            timeout_seconds,
        } => Some(UnresolvedSubmission {
            wire_code,
            message,
            tx_hash: tx_hash.as_deref(),
            envelope_hash: envelope_hash.as_deref(),
            timeout_seconds: *timeout_seconds,
        }),
        _ => None,
    }
}

/// Renders a DeFi submit failure and returns the process exit code.
///
/// A policy denial renders as this binary's gate denials do, under `verb`. A
/// mainnet refusal reports `network.mainnet_write_forbidden`. An unresolved
/// submission keeps its `submission.*` code and its `details`; everything else
/// is reported under `fallback_code`.
pub(crate) fn render_defi_submit_error(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
    verb: &str,
    fallback_code: &str,
) -> i32 {
    crate::common::render::render_json(&defi_submit_error_envelope(error, verb, fallback_code));
    1
}

/// The refusal envelope a DeFi submit failure is reported in.
///
/// A policy denial reads as this binary's gate denials read, under `verb`. A
/// mainnet refusal reports `network.mainnet_write_forbidden`. An unresolved
/// submission keeps its `submission.*` code and its `details`; everything else
/// is reported under `fallback_code`.
fn defi_submit_error_envelope(
    error: &stellar_agent_defi::adapter::DefiAdapterError,
    verb: &str,
    fallback_code: &str,
) -> Envelope<()> {
    if let stellar_agent_defi::adapter::DefiAdapterError::PolicyDenied { reason } = error {
        return Envelope::<()>::err_raw(
            reason.wire_code(),
            format!("{verb} operation denied by operator policy"),
        );
    }
    if matches!(
        error,
        stellar_agent_defi::adapter::DefiAdapterError::MainnetWriteForbidden
    ) {
        return Envelope::<()>::err(&WalletError::Network(NetworkError::MainnetWriteForbidden));
    }
    match unresolved_from_defi(error) {
        Some(unresolved) => unresolved.envelope(),
        None => Envelope::<()>::err_raw(fallback_code, error.to_string()),
    }
}

/// Renders a submit-path error for a verb whose other submission failures
/// carry their own wire code.
///
/// The three unknown-outcome codes are reported unchanged, with their
/// reconciliation detail: an agent told the submission failed under a
/// verb-specific code would rebuild and re-submit, which is exactly what a
/// transaction that may still apply forbids. A policy denial keeps the
/// criterion's own code, so an agent reads a refused cap as a refused cap.
/// Everything else keeps `fallback_code`.
pub(crate) fn error_envelope_with_fallback(
    err: &WalletError,
    signed_xdr: &str,
    verb: &str,
    fallback_code: &str,
) -> Envelope<()> {
    if let Some(envelope) = policy_denial_envelope(err, verb) {
        return envelope;
    }
    match submission_details(err, signed_xdr) {
        Some(details) => Envelope::<()>::err_with_details(err, details),
        None => Envelope::<()>::err_raw(fallback_code, err.message()),
    }
}

/// The structured detail for the three codes that carry one, or `None`.
fn submission_details(err: &WalletError, signed_xdr: &str) -> Option<serde_json::Value> {
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
    details.insert("outcome".to_owned(), "unknown".into());
    details.insert("reconcile_with".to_owned(), RECONCILE_VERB.into());
    Some(serde_json::Value::Object(details))
}

fn record_unavailable(detail: impl Into<String>) -> WalletError {
    WalletError::Submission(SubmissionError::RecordUnavailable {
        detail: detail.into(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    const SIGNED_XDR: &str = "AAAAAgAAAAA=";

    /// The settled rows' writer applies the binding check of the origin: a
    /// synthesized profile records no binding and refuses a changed one, and a
    /// persisted profile records an absent one.
    #[test]
    #[serial_test::serial]
    fn the_settled_rows_writer_applies_the_binding_check_of_the_origin() {
        use stellar_agent_core::audit_log::AuditBinding;
        use stellar_agent_network::keyring::{KeyringAuditBindingStore, rotate_keyring_secret_32};

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let keyed = |name: &str| {
            let mut profile = Profile::builder_testnet_named(name, "s", name, "n", name).build();
            profile.audit_log_path = dir.path().join(name).join("audit.jsonl");
            let coord = &profile.audit_log_hash_chain_key_id;
            rotate_keyring_secret_32(&coord.service, &coord.account).unwrap();
            profile
        };
        let recorded = |name: &str| {
            KeyringAuditBindingStore::for_profile(name)
                .load_raw()
                .unwrap()
                .is_some()
        };

        let synthesized = keyed("reconcile-synthesized");
        assert!(
            settled_rows_writer(
                &synthesized,
                "reconcile-synthesized",
                ProfileOrigin::Synthesized
            )
            .is_some()
        );
        assert!(
            !recorded("reconcile-synthesized"),
            "a synthesized profile records no binding"
        );

        let persisted = keyed("reconcile-persisted");
        assert!(
            settled_rows_writer(&persisted, "reconcile-persisted", ProfileOrigin::Persisted)
                .is_some()
        );
        assert!(
            recorded("reconcile-persisted"),
            "a persisted profile records its binding"
        );

        let mut changed = keyed("reconcile-changed");
        KeyringAuditBindingStore::for_profile("reconcile-changed")
            .store(&AuditBinding::for_profile(&changed))
            .unwrap();
        changed.audit_log_path = dir.path().join("repointed").join("audit.jsonl");
        assert!(
            settled_rows_writer(&changed, "reconcile-changed", ProfileOrigin::Synthesized)
                .is_none(),
            "a changed binding leaves the settled rows owed"
        );
        assert!(!dir.path().join("repointed").exists());
    }

    #[test]
    fn timeout_carries_the_full_hash_and_the_recovery_protocol() {
        let hash = "ab".repeat(32);
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: hash.clone(),
            seconds: 30,
        });
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let details = envelope.error.as_ref().unwrap().details.as_ref().unwrap();
        assert_eq!(details["tx_hash"], hash);
        assert_eq!(details["timeout_seconds"], 30);
        assert_eq!(details["outcome"], "unknown");
        assert_eq!(details["reconcile_with"], RECONCILE_VERB);
        assert_eq!(details["envelope_hash"], envelope_hash_hex(SIGNED_XDR));
    }

    #[test]
    fn timeout_message_stays_redacted() {
        let hash = "ab".repeat(32);
        let err = WalletError::Submission(SubmissionError::TxTimeout {
            tx_hash: hash.clone(),
            seconds: 30,
        });
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let message = &envelope.error.as_ref().unwrap().message;
        assert!(!message.contains(&hash), "message must stay redacted");
        assert!(message.contains("..."));
    }

    #[test]
    fn other_errors_carry_no_details() {
        let err = WalletError::Submission(SubmissionError::TxMalformed {
            detail: "txINSUFFICIENT_FEE".to_owned(),
        });
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        assert!(envelope.error.as_ref().unwrap().details.is_none());
    }

    /// A DeFi submit failure whose outcome is unknown keeps the submission
    /// code and carries the transaction to reconcile.
    #[test]
    fn a_defi_unresolved_submission_reports_the_submission_code_and_details() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code: "submission.tx_timeout",
            message: "transaction 'aaaaaaaa...bbbbbbbb' was not confirmed within 30s".to_owned(),
            tx_hash: Some("ab".repeat(32)),
            envelope_hash: Some("cd".repeat(32)),
            timeout_seconds: Some(30),
        };

        let unresolved = unresolved_from_defi(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.tx_timeout");
        let details = rendered.details.as_ref().unwrap();
        assert_eq!(details["tx_hash"], "ab".repeat(32));
        assert_eq!(details["envelope_hash"], "cd".repeat(32));
        assert_eq!(details["outcome"], "unknown");
        assert_eq!(details["reconcile_with"], RECONCILE_VERB);
    }

    /// A smart-account submit failure whose outcome is unknown does the same.
    #[test]
    fn a_smart_account_unresolved_submission_reports_the_submission_code() {
        let error = stellar_agent_smart_account::SaError::SubmissionUnresolved {
            kind: stellar_agent_smart_account::SubmissionUnresolvedKind::AlreadySubmitted,
            message: "a pending record already holds this sequence".to_owned(),
            tx_hash: Some("ef".repeat(32)),
            envelope_hash: None,
            timeout_seconds: None,
        };

        let unresolved = unresolved_from_sa(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.tx_already_submitted");
        let details = rendered.details.as_ref().unwrap();
        assert_eq!(details["tx_hash"], "ef".repeat(32));
        assert!(
            details.get("envelope_hash").is_none(),
            "a verb that holds no signed bytes reports the transaction hash alone"
        );
    }

    #[test]
    fn multicall_timeout_preserves_full_hash_in_details() {
        let tx_hash = "ab".repeat(32);
        let envelope_hash = "cd".repeat(32);
        let error = stellar_agent_smart_account::SaError::SubmissionUnresolved {
            kind: stellar_agent_smart_account::SubmissionUnresolvedKind::Timeout,
            message: "transaction 'abababab...abababab' was not confirmed within 2s".to_owned(),
            tx_hash: Some(tx_hash.clone()),
            envelope_hash: Some(envelope_hash.clone()),
            timeout_seconds: Some(2),
        };
        let rendered = serde_json::to_value(
            unresolved_from_sa(&error)
                .expect("typed multicall timeout")
                .envelope(),
        )
        .unwrap();
        assert_eq!(rendered["error"]["code"], "submission.tx_timeout");
        assert_eq!(rendered["error"]["details"]["tx_hash"], tx_hash);
        assert_eq!(rendered["error"]["details"]["envelope_hash"], envelope_hash);
        assert_eq!(rendered["error"]["details"]["timeout_seconds"], 2);
        assert_eq!(
            rendered["error"]["details"]["reconcile_with"],
            RECONCILE_VERB
        );
        assert!(
            !rendered["error"]["message"]
                .as_str()
                .unwrap()
                .contains(&tx_hash)
        );
    }

    /// Every other failure keeps the surface's own code.
    #[test]
    fn a_failure_that_moved_nothing_is_not_an_unresolved_submission() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::Network {
            reason: "endpoint unreachable".to_owned(),
        };
        assert!(unresolved_from_defi(&error).is_none());
    }

    /// A timeout carries the window it ran out of.
    #[test]
    fn a_defi_timeout_carries_its_timeout_seconds() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code: "submission.tx_timeout",
            message: "not confirmed".to_owned(),
            tx_hash: Some("ab".repeat(32)),
            envelope_hash: None,
            timeout_seconds: Some(45),
        };
        let unresolved = unresolved_from_defi(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let details = envelope.error.as_ref().unwrap().details.as_ref().unwrap();
        assert_eq!(details["timeout_seconds"], 45);
    }

    /// A per-period cap the reservation write refused reports the criterion's
    /// own code and reads as this binary's gate denials read.
    #[test]
    fn a_refused_reservation_reports_the_gate_code_and_wording() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "policy.deny.per_period_cap_exceeded");
        assert_eq!(rendered.message, "pay operation denied by operator policy");
        assert!(
            rendered.details.is_none(),
            "nothing was sent, so there is no transaction to reconcile"
        );
    }

    /// Clock refusals identify the host-clock offset on the CLI response.
    #[test]
    fn a_clock_refusal_reports_the_host_clock_offset() {
        let detail = stellar_agent_core::policy::v1::criteria::state_store::StateStoreError::ClockSkewExceeded {
            entry_ts_ms: 1_031_000, now_ms: 1_000_000,
        }.to_string();
        let err = WalletError::PolicyDenied {
            reason: Box::new(stellar_agent_core::policy::DenyReason::EvaluationError { detail }),
        };
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let error = envelope.error.as_ref().unwrap();
        assert_eq!(error.code, "policy.deny.evaluation_error");
        assert!(error.message.contains("host clock is 31000 ms behind"));
    }

    #[test]
    fn a_refused_rate_limited_reservation_reports_the_gate_code() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(stellar_agent_core::policy::DenyReason::RateLimitExceeded {
                window: "1m".to_owned(),
                max_calls: 1,
                calls_in_window: 1,
            }),
        };
        let envelope = error_envelope(&err, SIGNED_XDR, "claim");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "policy.deny.rate_limit_exceeded");
        assert_eq!(
            rendered.message,
            "claim operation denied by operator policy"
        );
    }

    /// A verb whose other submission failures carry their own code keeps the
    /// denial rather than flattening it into that fallback.
    #[test]
    fn a_verb_with_a_fallback_code_keeps_the_denial() {
        let err = WalletError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        let envelope =
            error_envelope_with_fallback(&err, SIGNED_XDR, "trustline", "trustline.submit_failed");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(
            rendered.code, "policy.deny.per_period_cap_exceeded",
            "a refused cap must not read as a submission failure"
        );
        assert_eq!(
            rendered.message,
            "trustline operation denied by operator policy"
        );
    }

    /// A DeFi verb reports the denial rather than its own submit-failure code.
    #[test]
    fn a_defi_verb_keeps_the_denial_rather_than_its_submit_failure_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::PolicyDenied {
            reason: Box::new(
                stellar_agent_core::policy::DenyReason::PerPeriodCapExceeded {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                    attempted_stroops: 600,
                    period_used_stroops: 600,
                },
            ),
        };
        let envelope = defi_submit_error_envelope(&error, "trade", "dex.submit_failed");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(
            rendered.code, "policy.deny.per_period_cap_exceeded",
            "a refused cap must not read as a submit failure"
        );
        assert_eq!(
            rendered.message,
            "trade operation denied by operator policy"
        );
        assert!(rendered.details.is_none());
    }

    /// A DeFi mainnet refusal reports the canonical code, not the verb's
    /// submit-failure code.
    #[test]
    fn a_defi_mainnet_refusal_reports_the_canonical_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::MainnetWriteForbidden;
        for (verb, fallback) in [
            ("trade", "dex.submit_failed"),
            ("vault deposit", "vault.submit_failed"),
        ] {
            let envelope = defi_submit_error_envelope(&error, verb, fallback);
            let rendered = envelope.error.as_ref().unwrap();
            assert_eq!(
                rendered.code, "network.mainnet_write_forbidden",
                "verb {verb}"
            );
            assert!(rendered.details.is_none());
        }
    }

    /// Every other DeFi failure still reports under the verb's own code.
    #[test]
    fn a_defi_network_failure_still_reports_the_fallback_code() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::Network {
            reason: "endpoint unreachable".to_owned(),
        };
        let envelope = defi_submit_error_envelope(&error, "trade", "dex.submit_failed");
        assert_eq!(envelope.error.as_ref().unwrap().code, "dex.submit_failed");
    }

    /// A store this binary cannot write still reports a record it could not
    /// make, under the code that names exactly that.
    #[test]
    fn a_record_that_cannot_be_written_is_still_record_unavailable() {
        let err = record_unavailable("the spending-window reservation could not be written");
        let envelope = error_envelope(&err, SIGNED_XDR, "pay");
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.record_unavailable");
        assert!(rendered.details.is_none());
    }

    /// A submission that was never sent carries no `details`.
    ///
    /// There is no transaction to reconcile, and `outcome: "unknown"` would
    /// say the opposite of what happened.
    #[test]
    fn a_pre_send_refusal_carries_no_details() {
        let error = stellar_agent_defi::adapter::DefiAdapterError::SubmissionUnresolved {
            wire_code: "submission.record_unavailable",
            message: "the receipt store could not be written".to_owned(),
            tx_hash: None,
            envelope_hash: None,
            timeout_seconds: None,
        };
        let unresolved = unresolved_from_defi(&error).expect("an unresolved submission");
        let envelope = unresolved.envelope();
        let rendered = envelope.error.as_ref().unwrap();
        assert_eq!(rendered.code, "submission.record_unavailable");
        assert!(
            rendered.details.is_none(),
            "a pre-send refusal carries no details; got {:?}",
            rendered.details
        );
    }
    #[test]
    fn settlement_rows_preserve_pending_approval_context() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        for approved in [false, true] {
            for failed in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let mut profile =
                    Profile::builder_testnet("signer", "default", "nonce", "default").build();
                profile.audit_log_path = dir.path().join("audit.jsonl");
                let audit = Arc::new(Mutex::new(
                    AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
                ));
                let decision = if approved {
                    PolicyDecision::RequireApproval
                } else {
                    PolicyDecision::Allow
                };
                let nonce = approved.then(|| "approval-binding".to_owned());
                audit
                    .lock()
                    .unwrap()
                    .write_entry(AuditEntry::new_value_action_pending(
                        "stellar_pay_commit",
                        "stellar:testnet",
                        Vec::new(),
                        "transaction",
                        "source",
                        7,
                        decision.clone(),
                        Some("envelope".to_owned()),
                        None,
                        nonce.clone(),
                        "pending-request",
                        None,
                    ))
                    .unwrap();
                let status = if failed {
                    ReceiptStatus::Failed {
                        code: "ledger.failed".to_owned(),
                    }
                } else {
                    ReceiptStatus::Success
                };
                write_settled_row(
                    &profile,
                    "audit-settlement",
                    &audit,
                    "envelope",
                    "transaction",
                    &status,
                    Some(9),
                    PolicyDecision::Allow,
                );
                let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect();
                assert_eq!(rows.len(), 2);
                assert_eq!(
                    rows[1]["policy_decision"],
                    serde_json::to_value(decision).unwrap()
                );
                assert_eq!(
                    rows[1]["approval_nonce"],
                    serde_json::to_value(nonce).unwrap()
                );
                assert_eq!(rows[1]["tool"], "stellar_pay_commit");
            }
        }
    }

    /// Each receipt outcome selects the audit row and code it owes.
    #[test]
    fn settlement_rows_follow_receipt_status_and_evidence() {
        use stellar_agent_core::audit_log::PolicyDecision;

        for (status, evidence, expected) in [
            (
                ReceiptStatus::Success,
                None,
                Some(("value_action_submitted", None)),
            ),
            (
                ReceiptStatus::Failed {
                    code: "ledger.failed".to_owned(),
                },
                None,
                Some(("value_action_failed", Some("ledger.failed"))),
            ),
            (
                ReceiptStatus::Ambiguous,
                Some(ReleaseEvidence::TimeBoundPassed),
                Some(("value_action_failed", Some("submission.time_bound_passed"))),
            ),
            (
                ReceiptStatus::Ambiguous,
                Some(ReleaseEvidence::SequenceConsumed),
                Some(("value_action_failed", Some("submission.sequence_consumed"))),
            ),
            (ReceiptStatus::Ambiguous, None, None),
            (ReceiptStatus::Pending, None, None),
            (ReceiptStatus::Reorged, None, None),
            (
                ReceiptStatus::ClearedByOperator,
                Some(ReleaseEvidence::TimeBoundPassed),
                None,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut profile =
                Profile::builder_testnet("row-kind", "default", "nonce", "default").build();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            let audit = Arc::new(Mutex::new(
                AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
            ));
            write_settled_row_with_evidence(
                &profile,
                "row-kind",
                &audit,
                "envelope",
                "transaction",
                &status,
                evidence,
                Some(9),
                PolicyDecision::Allow,
            );
            let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            if let Some((kind, code)) = expected {
                assert_eq!(rows.len(), 1, "{status:?}/{evidence:?}");
                assert_eq!(rows[0]["kind"], kind);
                assert_eq!(rows[0]["code"], serde_json::to_value(code).unwrap());
            } else {
                assert!(rows.is_empty(), "{status:?}/{evidence:?}: {rows:?}");
            }
        }
    }

    /// A log at `path` whose active file holds no row for `"envelope"` and
    /// whose archive holds that submission's pending row ahead of a broken
    /// link, so a lookup for it reaches the break.
    fn history_with_a_broken_archive(path: &std::path::Path) -> Arc<Mutex<AuditWriter>> {
        use stellar_agent_core::audit_log::rotation::test_seam::set_rotation_threshold;
        use stellar_agent_core::audit_log::test_helpers::break_newest_archive_link;
        use stellar_agent_core::audit_log::{
            AuditEntry, NewToolInvocation, PolicyDecision, reader::ValueActionSettlement,
            reader::try_value_action_settlement,
        };

        let unrelated = |request_id: &str| {
            AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "stellar_balance",
                "stellar:testnet",
                Vec::new(),
                PolicyDecision::Allow,
                request_id,
            ))
        };
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(path.to_path_buf(), None).unwrap(),
        ));
        {
            let mut guard = audit.lock().unwrap();
            guard
                .write_entry(AuditEntry::new_value_action_pending(
                    "stellar_pay_commit",
                    "stellar:testnet",
                    Vec::new(),
                    "transaction",
                    "source",
                    7,
                    PolicyDecision::Allow,
                    Some("envelope".to_owned()),
                    None,
                    None,
                    "pending-request",
                    None,
                ))
                .unwrap();
            guard.write_entry(unrelated("archived")).unwrap();
            let size = std::fs::metadata(path).unwrap().len();
            let threshold = set_rotation_threshold(path, size);
            guard.write_entry(unrelated("active")).unwrap();
            drop(threshold);
        }
        assert!(matches!(
            try_value_action_settlement(path, "envelope").unwrap(),
            ValueActionSettlement::Owed(_)
        ));
        break_newest_archive_link(path);
        audit
    }

    /// A settlement lookup that cannot read the retained history writes no
    /// settled row and logs why: `tx status` settles through this helper, and
    /// whether the row is owed is unknown.
    #[test]
    fn an_unreadable_history_writes_no_settled_row_and_logs_it() {
        use stellar_agent_core::audit_log::PolicyDecision;

        let dir = tempfile::tempdir().unwrap();
        let mut profile =
            Profile::builder_testnet("signer", "unreadable", "nonce", "unreadable").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = history_with_a_broken_archive(&profile.audit_log_path);
        let active = std::fs::read(&profile.audit_log_path).unwrap();
        let logs = stellar_agent_test_support::with_captured_logs(|| {
            write_settled_row_with_evidence(
                &profile,
                "unreadable",
                &audit,
                "envelope",
                "transaction",
                &ReceiptStatus::Success,
                None,
                Some(9),
                PolicyDecision::Allow,
            );
        });
        assert_eq!(
            std::fs::read(&profile.audit_log_path).unwrap(),
            active,
            "no settled row is written"
        );
        let line = logs
            .lines()
            .find(|line| line.contains("settled row NOT emitted"));
        assert!(
            line.is_some_and(|line| line.contains("WARN")
                && line.contains("unreadable")
                && line.contains("envelope")
                && line.contains("audit.chain_broken")),
            "the skipped row is logged with the profile, the hash, and the error: {logs}"
        );
    }

    /// The strict settlement refuses when the lookup cannot read the retained
    /// history, so a clear never proceeds past a settlement it could not see.
    #[test]
    fn an_unreadable_history_refuses_the_strict_settlement() {
        use stellar_agent_core::audit_log::PolicyDecision;

        let dir = tempfile::tempdir().unwrap();
        let mut profile =
            Profile::builder_testnet("signer", "strict-unreadable", "nonce", "strict-unreadable")
                .build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = history_with_a_broken_archive(&profile.audit_log_path);
        let active = std::fs::read(&profile.audit_log_path).unwrap();
        let refused = append_settled_row(
            &profile,
            "strict-unreadable",
            &audit,
            "envelope",
            "transaction",
            &ReceiptStatus::Ambiguous,
            Some(ReleaseEvidence::SequenceConsumed),
            PolicyDecision::Allow,
        )
        .expect_err("a history that cannot be read refuses the strict settlement");
        let error = refused.error.as_ref().expect("error");
        assert_eq!(error.code, "audit.chain_broken", "{refused:?}");
        assert!(
            error.message.contains("audit.chain_broken"),
            "the refusal names the integrity error: {refused:?}"
        );
        assert!(
            !error.message.contains("on open"),
            "a lookup failure is not a writer-open failure: {refused:?}"
        );
        assert_eq!(
            std::fs::read(&profile.audit_log_path).unwrap(),
            active,
            "no settled row is written"
        );
    }

    #[test]
    fn pending_witness_survives_cli_reconciliation() {
        use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision};
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet("signer", "witness", "nonce", "witness").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        let witness = stellar_agent_core::audit_log::CrossCheckRecord {
            provider: "https://oracle.example".to_owned(),
            ledger: 123,
            inputs_digest: "09".repeat(32),
            kinds: vec![stellar_agent_core::cross_check::WitnessEntry::SourceAccount],
        };
        audit
            .lock()
            .unwrap()
            .write_entry(AuditEntry::new_value_action_pending(
                "stellar_pay_commit",
                "stellar:testnet",
                vec![],
                "transaction",
                "source",
                7,
                PolicyDecision::Allow,
                Some("envelope".to_owned()),
                None,
                None,
                "pending-request",
                Some(witness.clone()),
            ))
            .unwrap();
        write_settled_row(
            &profile,
            "witness",
            &audit,
            "envelope",
            "transaction",
            &ReceiptStatus::Success,
            Some(124),
            PolicyDecision::Allow,
        );
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["kind"], "value_action_submitted");
        assert_eq!(rows[1]["witness"], serde_json::to_value(&witness).unwrap());
        assert_eq!(rows[0]["witness"], rows[1]["witness"]);
    }
}
