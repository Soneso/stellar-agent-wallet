//! Durable record of a submission, written before the transaction is sent.
//!
//! # Why the record comes first
//!
//! `sendTransaction` returning an error, or the confirmation poll running out
//! of time, says nothing about whether the signed bytes reached the network.
//! The submit layer cannot tell a refused connection from a lost response, and
//! a transaction that landed after the poll gave up still moved value. A
//! record written only on the confirmed path therefore leaves the wallet with
//! no memory of a submission that may have applied: the spend is uncounted,
//! the audit log is silent, and the next attempt at the same intent has
//! nothing to refuse against.
//!
//! So the record is written first. [`SubmissionRecorder::pre_send`] runs after
//! the endpoint identity probe and the signature-binding check, immediately
//! before the send, and refuses the send when it cannot write.
//! [`SubmissionRecorder::outcome`] runs at every exit after the send and
//! settles the record against what the network said. A transport failure and a
//! poll timeout settle nothing: the record stands until reconciliation or an
//! operator resolves it.
//!
//! # The audit tip anchor
//!
//! Where the wallet's recorder writes through a keyed audit writer, a
//! submission is sent only while the audit log's tip anchor covers its pending
//! row. The recorder checks the anchor twice. The first check runs before the
//! receipt, the pending row, or the reservation exists, so a refusal there has
//! nothing to undo. The second runs right after the pending row is appended,
//! under the writer guard that appended it, so it covers the row itself and
//! any outbox row the append drained ahead of it. A refusal at the second check
//! comes after the pending row: the recorder attempts the release of the
//! reservation, the `value_action_failed` row that closes the pending row, and
//! the removal of the receipt, each best-effort and logged. Nothing is sent.
//!
//! A failed row settles every pending row that carries the same envelope hash.
//! After an anchor refusal, the recorder attempts to close the row once its
//! checks pass. With window entries, the reservation's duplicate check under
//! the window lock must find no pending or confirmed record for the hash.
//! Without window entries, the receipt gate must record a new receipt, so no
//! other receipt carries the hash. A resend that the duplicate check refuses
//! keeps its row open, and the original submission's settlement closes both.
//! For a `record_pending` error other than the duplicate refusal, the recorder
//! also attempts to close the row. The duplicate check may not run before that
//! error, so ownership can remain unproven.
//!
//! After receipt loss, a closing row can also settle the original submission.
//! Without current window entries, a reservation from an earlier stateful
//! policy can remain and let reconciliation recover its identity. Without
//! that reservation, reconciliation has no record left to settle it by.
//! An outcome row the original process writes later wins the lookup.
//!
//! # Identity
//!
//! Two identities address a submission:
//!
//! - The envelope hash, `SHA-256` over the signed envelope XDR, keys the
//!   receipt and the window reservation. It is the identity of these exact
//!   bytes.
//! - `(source account, sequence)` is the identity the network enforces: at
//!   most one transaction per pair can ever apply. A rebuilt envelope for the
//!   same intent picks a fresh fee from live fee stats and hashes differently,
//!   so the pair, not the hash, is what makes a duplicate submission
//!   recognisable.
//!
//! The transaction hash, `SHA-256(network_id ‖ tagged transaction)`, is
//! computed locally from the decoded envelope before the send and is what the
//! agent reconciles with afterwards.

use std::sync::{Arc, Mutex, MutexGuard};

use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, WriterError};
use stellar_agent_core::error::{SubmissionError, ValidationError, WalletError};
use stellar_agent_core::profile::receipt::{
    BeginSubmissionOutcome, ReceiptStatus, ReceiptStore, ReceiptStoreError,
};
use stellar_agent_core::profile::schema::Profile;

use crate::policy_state::{PersistedWindowStore, SubmissionHold, WindowStoreError};
use crate::sequence_floor::SequenceFloorHook;
use crate::submit::redact_tx_hash;
use stellar_agent_core::observability::redact::redact_strkey_first5_last5 as redact_account;

// ─────────────────────────────────────────────────────────────────────────────
// SubmissionIntent
// ─────────────────────────────────────────────────────────────────────────────

/// What the submit layer knows about a transaction it is about to send.
///
/// Every field is derived from the decoded envelope and the reads that precede
/// the send, so the submit layer can build it without knowing anything about
/// the verb that produced the envelope. What the verb knows — which tool, which
/// chain, which value legs — belongs to the recorder implementation the verb
/// constructs.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionIntent {
    /// `SHA-256` over the signed envelope XDR, 64 lowercase hex characters.
    /// Keys the receipt and the window reservation.
    pub envelope_hash: String,

    /// `SHA-256(network_id ‖ tagged transaction)`, 64 lowercase hex
    /// characters, computed locally before the send.
    pub tx_hash: String,

    /// The account whose sequence the transaction consumes, a `G...` strkey.
    /// For a fee-bump this is the INNER transaction's source.
    pub source: String,

    /// The sequence number the transaction consumes. For a fee-bump this is
    /// the INNER transaction's sequence.
    pub sequence: i64,

    /// `TimeBounds.maxTime` in absolute unix seconds; `0` means no time bound,
    /// matching the XDR.
    pub max_time: u64,

    /// The endpoint's latest ledger immediately before the send, read from the
    /// `getLedgerEntries` response the signature-binding check already makes.
    pub submission_ledger: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// SubmissionOutcome
// ─────────────────────────────────────────────────────────────────────────────

/// What became of a submission after the send.
///
/// Matched exhaustively at every consumer: the record disposition differs per
/// variant, so a new way for a submission to end has to make every recorder
/// fail to compile rather than fall into a catch-all that settles it by
/// accident. The enum carries no `#[non_exhaustive]` for that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionOutcome {
    /// The transaction was included in ledger `ledger`.
    Success {
        /// The ledger sequence the transaction confirmed in.
        ledger: u32,
        /// Close time of the applying ledger, in unix seconds.
        created_at: Option<i64>,
    },

    /// The transaction applied and failed. The confirmation poll reported
    /// `FAILED` with a `TransactionResult`.
    OnChainFailed {
        /// Stable wire code for the failure, from the same XDR mapping the
        /// returned error uses.
        code: String,
    },

    /// The send step refused the bytes definitively: `sendTransaction`
    /// answered `ERROR` with a real `TransactionResult`; no value moved, and the
    /// refusal is not retried.
    Rejected {
        /// Stable wire code for the refusal.
        code: String,
        /// Non-secret diagnostic detail, carrying the result code the endpoint
        /// reported.
        error: String,
    },

    /// The transaction was accepted for inclusion and was not confirmed within
    /// the submission timeout. It may still apply.
    Timeout {
        /// The locally computed transaction hash to reconcile against.
        tx_hash: String,
    },

    /// The send left the outcome unknown after the bytes may have been
    /// transmitted.
    ///
    /// Covers every post-send condition that settles nothing: a transport
    /// failure the layer cannot classify as transmitted or not, an endpoint
    /// that stops answering the confirmation poll, and an endpoint whose
    /// reported transaction hash does not describe the transaction that was
    /// sent.
    TransportAfterSend {
        /// Non-secret diagnostic detail naming the condition.
        error: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// SubmissionRecorder
// ─────────────────────────────────────────────────────────────────────────────

/// The seam through which the submit layer records a submission.
///
/// Object-safe: call sites hold `Option<&dyn SubmissionRecorder>`, and a call
/// site with nothing to record passes `None` and keeps the plain submit
/// behaviour.
#[async_trait::async_trait]
pub trait SubmissionRecorder: Send + Sync {
    /// Records the submission as sent with an unknown outcome, immediately
    /// before `sendTransaction`.
    ///
    /// # Errors
    ///
    /// Returning an error refuses the send. Implementations return one when
    /// the record cannot be written or the audit log's tip anchor does not
    /// cover it, when a pending record already holds this transaction's
    /// `(source, sequence)`, and when the spending window already holds these
    /// signed bytes.
    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError>;

    /// Settles the record against what the network said.
    ///
    /// Runs at every exit after the send. It cannot fail the caller: the
    /// transaction is already beyond recall, so a failure here is logged and
    /// the record stands.
    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome);
}

// ─────────────────────────────────────────────────────────────────────────────
// Wallet implementation
// ─────────────────────────────────────────────────────────────────────────────

/// The audit writer a recorder writes its rows through.
pub type AuditWriterHandle = Arc<Mutex<AuditWriter>>;

/// The approval entry a commit spends, and where to find it.
#[derive(Debug, Clone)]
pub struct ApprovalTombstone {
    /// Directory holding the profile's pending-approval store.
    pub store_dir: std::path::PathBuf,
    /// Profile name, which names the store file inside that directory.
    pub profile_name: String,
    /// The approval nonce the commit presented.
    pub approval_nonce: String,
}

/// Everything the wallet's recorder needs that the submit layer does not know.
///
/// Built by the verb that is about to submit. The optional halves are the
/// parts only one binary has: the sequence floor is process-local state the
/// MCP server owns, and the approval entry exists only on a commit path that
/// presented one.
pub struct WalletSubmissionRecorder<'a> {
    witness: Option<stellar_agent_core::audit_log::CrossCheckRecord>,
    profile: &'a Profile,
    profile_name: String,
    tool: &'static str,
    chain_id: Option<String>,
    policy_decision: PolicyDecision,
    legs: Vec<ValueLegRecord>,
    window_entries: Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
    receipts: ReceiptStore,
    window: PersistedWindowStore,
    audit: Option<AuditWriterHandle>,
    nonce_id: Option<String>,
    request_id: String,
    now_ms: u64,
    sequence_floor: Option<&'a dyn SequenceFloorHook>,
    approval: Option<ApprovalTombstone>,
    caller_writes_confirmed_row: bool,
}

impl std::fmt::Debug for WalletSubmissionRecorder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletSubmissionRecorder")
            .field("profile_name", &self.profile_name)
            .field("tool", &self.tool)
            .field("chain_id", &self.chain_id)
            .field("window_entry_count", &self.window_entries.len())
            .field("has_audit_writer", &self.audit.is_some())
            .field("has_sequence_floor", &self.sequence_floor.is_some())
            .field("has_approval", &self.approval.is_some())
            .finish()
    }
}

impl<'a> WalletSubmissionRecorder<'a> {
    /// Carries a completed oracle comparison into the pending and submitted audit rows.
    #[must_use]
    pub fn with_witness(mut self, witness: Option<&crate::cross_check::CrossCheckWitness>) -> Self {
        self.witness = witness.map(crate::cross_check::CrossCheckWitness::record);
        self
    }

    /// Builds a recorder for one submission.
    ///
    /// `window_entries` are the window entries the policy engine sized for this
    /// action: the SAME derivation the gate evaluated and the audit rows carry.
    /// Each carries the limit its governing criterion compared the call
    /// against. `legs` is that same sizing in its audit-row form.
    ///
    /// `audit` is `None` only where the profile has no audit log to write to,
    /// which is the synthesized zero-configuration origin; every persisted
    /// profile supplies a writer and the pending row fails closed against it.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "one construction site per verb; every field is call-site context the submit layer cannot derive"
    )]
    pub fn new(
        profile: &'a Profile,
        profile_name: impl Into<String>,
        tool: &'static str,
        chain_id: Option<String>,
        policy_decision: PolicyDecision,
        legs: Vec<ValueLegRecord>,
        window_entries: Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry>,
        receipts: ReceiptStore,
        window: PersistedWindowStore,
        audit: Option<AuditWriterHandle>,
        nonce_id: Option<String>,
        request_id: impl Into<String>,
        now_ms: u64,
    ) -> Self {
        Self {
            profile,
            profile_name: profile_name.into(),
            tool,
            chain_id,
            policy_decision,
            legs,
            window_entries,
            receipts,
            window,
            audit,
            nonce_id,
            request_id: request_id.into(),
            now_ms,
            sequence_floor: None,
            approval: None,
            caller_writes_confirmed_row: false,
            witness: None,
        }
    }

    /// States that the caller writes the value-action row for a confirmed
    /// submission itself.
    ///
    /// One settled row per confirmed send. A verb whose own response contract
    /// is carried by a row of its own — `stellar_sep43_sign_and_submit_transaction`
    /// writes an opaque-action row naming what it signed — would otherwise
    /// produce two rows for one send.
    ///
    /// The caller's row has to carry the submission's envelope hash on the
    /// outer entry. That is what closes out the pending row this recorder
    /// wrote before the send: the settlement lookup matches on it, and a row
    /// that does not carry it leaves the pending row owed and lets a later
    /// reconciliation append a second settled row for the same send.
    ///
    /// Only the confirmed arm is affected. A submission the chain reports as
    /// failed still gets its `value_action_failed` row from the recorder, so
    /// the pending row is settled whatever the outcome.
    #[must_use]
    pub fn with_caller_written_confirmed_row(mut self) -> Self {
        self.caller_writes_confirmed_row = true;
        self
    }

    /// Attaches the process-local confirmed-sequence floor, which only the
    /// long-lived MCP server holds.
    #[must_use]
    pub fn with_sequence_floor(mut self, hook: Option<&'a dyn SequenceFloorHook>) -> Self {
        self.sequence_floor = hook;
        self
    }

    /// Attaches the approval entry this commit spends, which only a commit
    /// path that presented one has.
    #[must_use]
    pub fn with_approval(mut self, approval: Option<ApprovalTombstone>) -> Self {
        self.approval = approval;
        self
    }

    fn reservation(&self, intent: &SubmissionIntent) -> SubmissionHold {
        SubmissionHold {
            id: intent.envelope_hash.clone(),
            tx_hash: intent.tx_hash.clone(),
            source: intent.source.clone(),
            sequence: intent.sequence,
            max_time: intent.max_time,
            pending_since_ms: self.now_ms,
            submission_ledger: intent.submission_ledger,
            operator_required: false,
        }
    }

    /// Refuses the submission while the audit log's tip anchor is behind and
    /// cannot be repaired, before anything for the submission is written.
    ///
    /// Takes the writer guard only for the check and drops it on return. No
    /// writer, no check: the pending row is skipped there too.
    ///
    /// # Errors
    ///
    /// The refusal [`Self::audit_refusal`] maps the writer's error to.
    fn require_anchor_before_row(&self) -> Result<(), WalletError> {
        let Some(writer) = self.audit.as_ref() else {
            return Ok(());
        };
        lock_audit(writer)?
            .require_anchor_current()
            .map_err(|error| self.audit_refusal(error, BEFORE_ROW_CONTEXT))
    }

    /// Writes the pending audit row and checks that the tip anchor covers it.
    ///
    /// Fails closed where a writer exists: an unrecorded submission is one the
    /// value audit cannot account for. Where the profile has no audit log at
    /// all there is nothing to fail against, and the submission proceeds.
    ///
    /// The anchor check runs under the guard that appended the row, so no
    /// other append through this writer lands between the two. The guard is
    /// dropped on return, before any closing row is written. A row the anchor
    /// does not cover is durable, so it comes back as
    /// [`AnchorAfterRow::Behind`] rather than as an error: `pre_send` closes
    /// it only after the reservation step has decided whether this submission
    /// owns its envelope hash.
    ///
    /// # Errors
    ///
    /// The refusal for a row that could not be appended; no row exists then.
    fn write_pending_row(&self, intent: &SubmissionIntent) -> Result<AnchorAfterRow, WalletError> {
        let Some(writer) = self.audit.as_ref() else {
            return Ok(AnchorAfterRow::Current);
        };
        let entry = AuditEntry::new_value_action_pending(
            self.tool,
            self.chain_id.clone(),
            self.legs.clone(),
            redact_tx_hash(&intent.tx_hash),
            redact_account(&intent.source),
            intent.sequence,
            self.policy_decision.clone(),
            Some(intent.envelope_hash.clone()),
            self.nonce_id.clone(),
            self.approval
                .as_ref()
                .map(|approval| approval.approval_nonce.clone()),
            &self.request_id,
            self.witness.clone(),
        );
        let mut guard = lock_audit(writer)?;
        guard
            .write_entry(entry)
            .map_err(|error| self.audit_refusal(error, APPEND_CONTEXT))?;
        Ok(match guard.require_anchor_current() {
            Ok(()) => AnchorAfterRow::Current,
            Err(error) => AnchorAfterRow::Behind(self.audit_refusal(error, AFTER_ROW_CONTEXT)),
        })
    }

    /// Maps an audit-writer failure on the pending-row path to the refusal the
    /// caller reports.
    ///
    /// A tip-anchor mismatch keeps its own code, because only `audit reanchor`
    /// addresses it. Every other failure is `submission.record_unavailable`:
    /// `context` names the step, and the writer error's text follows it with
    /// its `audit.*` sub-code where it has one, `audit.tip_anchor_unavailable`
    /// for an anchor that cannot be written.
    fn audit_refusal(&self, error: WriterError, context: &str) -> WalletError {
        match error {
            WriterError::TipAnchorMismatch { reason, .. } => {
                WalletError::Validation(ValidationError::AuditTipAnchorMismatch {
                    profile: self.profile_name.clone(),
                    reason: reason.to_owned(),
                })
            }
            other => record_unavailable(format!("{context}: {other}")),
        }
    }

    /// Writes a settling audit row. The transaction is already beyond recall,
    /// so a failure is logged and does not disturb the caller.
    fn write_outcome_row(&self, entry: AuditEntry) {
        let Some(writer) = self.audit.as_ref() else {
            return;
        };
        match writer.lock() {
            Ok(mut guard) => {
                if let Err(e) = guard.write_entry(entry) {
                    tracing::warn!(
                        profile = %self.profile_name,
                        tool = %self.tool,
                        error = %e,
                        "submission record: outcome row NOT emitted"
                    );
                }
            }
            Err(_) => {
                tracing::warn!(
                    profile = %self.profile_name,
                    tool = %self.tool,
                    "submission record: audit writer mutex poisoned; outcome row NOT emitted"
                );
            }
        }
    }

    /// Advances the process-local sequence floor for this source account.
    ///
    /// Recorded on every outcome where the transaction may have applied, not
    /// only on a confirmed one: a transaction whose outcome is unknown may
    /// have consumed the sequence, and a build that assumes otherwise picks
    /// one the network will reject.
    async fn record_floor(&self, intent: &SubmissionIntent) {
        if let Some(hook) = self.sequence_floor {
            hook.record_confirmed(&intent.source, intent.sequence).await;
        }
    }

    /// Completes the receipt's durable approval-consumption obligation.
    fn tombstone_approval(&self, intent: &SubmissionIntent) {
        let Some(approval) = self.approval.as_ref() else {
            return;
        };
        if let Err(error) = repair_approval_consumption(
            &self.receipts,
            &intent.envelope_hash,
            &approval.store_dir,
            &approval.profile_name,
        ) {
            tracing::warn!(
                profile = %self.profile_name,
                tool = %self.tool,
                error = %error,
                "submission record: approval consumption remains owed; status retries it"
            );
        }
    }
}

/// Completes a sent receipt's approval tombstone and acknowledges it durably.
///
/// The receipt holds the nonce until a definitive send refusal releases it.
/// A failed approval write or acknowledgement leaves the obligation available
/// to the next status call, and the commit gate continues to refuse reuse.
///
/// # Errors
///
/// Returns `submission.record_unavailable` if either store cannot be read or
/// written, or the approval names a different transaction.
pub fn repair_approval_consumption(
    receipts: &ReceiptStore,
    envelope_hash: &str,
    approval_dir: &std::path::Path,
    profile_name: &str,
) -> Result<(), WalletError> {
    use stellar_agent_core::approval::{ApprovalKind, ConsumedOutcome};
    let receipt = receipts
        .get(envelope_hash)
        .map_err(|e| receipt_store_refusal(&e))?;
    let Some(receipt) = receipt else {
        return Ok(());
    };
    let Some(nonce) = receipt.approval_nonce.as_deref() else {
        return Ok(());
    };
    if !receipt.submitted || receipt.approval_consumed {
        return Ok(());
    }
    let mut store = stellar_agent_core::approval::retry::open_with_retry(
        &approval_dir.join(format!("{profile_name}.toml")),
        stellar_agent_core::approval::retry::DEFAULT_RETRY_ATTEMPTS,
        stellar_agent_core::approval::retry::DEFAULT_RETRY_BACKOFF,
    )
    .map_err(|e| record_unavailable(format!("approval consumption store unavailable: {e}")))?;
    if let Some(entry) = store.get(nonce)
        && let ApprovalKind::Consumed { tx_hash, .. } = &entry.kind
    {
        if tx_hash != &receipt.tx_hash {
            return Err(record_unavailable(
                "approval consumption names a different transaction",
            ));
        }
    } else {
        let outcome = if receipt.status.is_definitive_outcome() {
            ConsumedOutcome::Confirmed
        } else {
            ConsumedOutcome::Unknown
        };
        store
            .consume(nonce, &receipt.tx_hash, outcome)
            .map_err(|e| {
                record_unavailable(format!("approval consumption could not be written: {e}"))
            })?;
    }
    receipts
        .mark_approval_consumed(envelope_hash)
        .map_err(|e| receipt_store_refusal(&e))
}

#[async_trait::async_trait]
impl SubmissionRecorder for WalletSubmissionRecorder<'_> {
    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        // The audit tip anchor first. A behind anchor that cannot be repaired
        // refuses here, before the receipt, the row, or the reservation
        // exists, so the refusal has nothing to undo.
        self.require_anchor_before_row()?;

        // Then the replay identity. `begin_submission` answers it and the
        // envelope-hash gate under one lock hold, in that order: the second
        // check writes this submission's own receipt, which carries this
        // submission's `(source, sequence)`.
        match self.receipts.begin_submission_with_approval(
            &intent.envelope_hash,
            &intent.tx_hash,
            &intent.source,
            intent.sequence,
            intent.max_time,
            intent.submission_ledger,
            self.approval.as_ref().map(|a| a.approval_nonce.as_str()),
        ) {
            Ok(BeginSubmissionOutcome::Recorded) => {}
            Ok(
                BeginSubmissionOutcome::DuplicateSequence(existing)
                | BeginSubmissionOutcome::DuplicateApproval(existing),
            ) => {
                return Err(WalletError::Submission(
                    SubmissionError::TxAlreadySubmitted {
                        hash: existing.tx_hash,
                    },
                ));
            }
            Ok(BeginSubmissionOutcome::AlreadyPresent(existing)) => {
                return Err(WalletError::Submission(
                    SubmissionError::TxAlreadySubmitted {
                        hash: existing.tx_hash,
                    },
                ));
            }
            Err(e) => return Err(receipt_store_refusal(&e)),
        }

        // From here the receipt exists and holds the pair. Every remaining
        // step is undone on failure, so a submission that never reached the
        // network leaves the sequence free for the retry the refusal invites.
        //
        // The window file is the other record of these exact bytes: its
        // reservation id is the envelope hash. A receipt lost while that
        // reservation stands lets the gate above admit a resend of the same
        // bytes, so the window is asked before the pending row is written. A
        // refusal here writes no row, which leaves the original submission's
        // settlement owed until its own reconciliation writes it. The window
        // is consulted only where this submission takes a reservation; a
        // policy without a stateful criterion keeps no window records.
        if !self.window_entries.is_empty() && window_precheck_enabled() {
            let refusal = match self
                .window
                .holds_reservation(self.profile, &intent.envelope_hash)
            {
                Ok(false) => None,
                Ok(true) => Some(already_submitted(intent)),
                Err(e) => Some(reservation_refusal(e, intent)),
            };
            if let Some(refusal) = refusal {
                self.unwind(intent, UnwoundAfter::Receipt, refusal.code());
                return Err(refusal);
            }
        }

        let anchor = match self.write_pending_row(intent) {
            Ok(anchor) => anchor,
            Err(e) => {
                self.unwind(intent, UnwoundAfter::Receipt, e.code());
                return Err(e);
            }
        };

        if self.window_entries.is_empty() {
            // The receipt gate recorded a new receipt, so no other receipt
            // carries this hash. An older stateful policy can still have a
            // reservation for it. Cleanup attempts to close an uncovered row here.
            if let AnchorAfterRow::Behind(refusal) = anchor {
                self.unwind(intent, UnwoundAfter::PendingRow, refusal.code());
                return Err(refusal);
            }
        } else {
            if let Err(e) = self.window.record_pending(
                self.profile,
                &self.window_entries,
                &self.reservation(intent),
            ) {
                // A duplicate found under the lock is a resend of bytes another
                // process reserved between the check above and this write. The
                // pending row just written names the same envelope hash as that
                // submission's, so the settled row its reconciliation writes
                // closes both, and this row stays open. Every other refusal
                // attempts to close the row, even if the duplicate check did
                // not run, whatever the anchor check found.
                let reached = match e {
                    WindowStoreError::DuplicateReservation => UnwoundAfter::Receipt,
                    _ => UnwoundAfter::PendingRow,
                };
                let refusal = reservation_refusal(e, intent);
                self.unwind(intent, reached, refusal.code());
                return Err(refusal);
            }
            // The reservation's duplicate check under the window lock found
            // no record carrying this hash, so the reservation and the row are
            // this submission's, and a pending row the anchor does not cover is
            // closed out with them.
            if let AnchorAfterRow::Behind(refusal) = anchor {
                self.unwind(intent, UnwoundAfter::Reservation, refusal.code());
                return Err(refusal);
            }
        }

        // Last, and immediately before the send: `submitted` is what says the
        // bytes left, and it is the flag that makes the receipt un-abandonable.
        // Setting it earlier would strand a receipt for a submission a later
        // failure stopped.
        if let Err(e) = self.mark_submitted(&intent.envelope_hash) {
            let refusal = receipt_store_refusal(&e);
            self.unwind(intent, UnwoundAfter::Reservation, refusal.code());
            return Err(refusal);
        }

        Ok(())
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        match outcome {
            SubmissionOutcome::Success { ledger, created_at } => {
                self.finalize_receipt(intent, ReceiptStatus::Success, Some(*ledger));
                if !self.caller_writes_confirmed_row {
                    self.write_outcome_row(AuditEntry::new_value_action_submitted(
                        self.tool,
                        self.chain_id.clone(),
                        self.legs.clone(),
                        redact_tx_hash(&intent.tx_hash),
                        *ledger,
                        self.policy_decision.clone(),
                        Some(intent.envelope_hash.clone()),
                        self.nonce_id.clone(),
                        self.approval
                            .as_ref()
                            .map(|approval| approval.approval_nonce.clone()),
                        &self.request_id,
                        self.witness.clone(),
                    ));
                }
                self.settle_window(intent, WindowSettlement::Confirm(*created_at));
                self.record_floor(intent).await;
                self.tombstone_approval(intent);
            }
            SubmissionOutcome::OnChainFailed { code } => {
                self.finalize_receipt(intent, ReceiptStatus::Failed { code: code.clone() }, None);
                self.write_failed_row(intent, code);
                self.settle_window(intent, WindowSettlement::Release);
                self.record_floor(intent).await;
                self.tombstone_approval(intent);
            }
            SubmissionOutcome::Rejected { code, .. } => {
                // A definitive refusal releases the approval hold in the same
                // receipt write that records the failed send.
                if let Err(error) = self
                    .receipts
                    .finalize_send_refusal(&intent.envelope_hash, code)
                {
                    tracing::warn!(error = %error, "submission record: send refusal could not be persisted");
                }
                self.write_failed_row(intent, code);
                self.settle_window(intent, WindowSettlement::Release);
            }
            SubmissionOutcome::Timeout { .. } | SubmissionOutcome::TransportAfterSend { .. } => {
                // The transaction may still apply. The receipt, the pending
                // audit row and the reservation all stand, and only
                // reconciliation or an operator clears them.
                self.record_floor(intent).await;
                self.tombstone_approval(intent);
            }
        }
    }
}

/// Turns a refused reservation write into the error the caller reports.
///
/// A bucket that can no longer admit the spend is a policy denial, reported
/// under the wire code the gate reports for the same reason and carrying the
/// same typed reason. A window that already holds these bytes is a
/// resubmission, reported as `submission.tx_already_submitted` with the
/// transaction to reconcile. Every other refusal is a record the wallet could
/// not write, which is what `submission.record_unavailable` names. All of
/// them refuse the send.
fn reservation_refusal(error: WindowStoreError, intent: &SubmissionIntent) -> WalletError {
    match error {
        WindowStoreError::PolicyDenied { reason } => WalletError::PolicyDenied { reason },
        WindowStoreError::DuplicateReservation => already_submitted(intent),
        other => record_unavailable(format!(
            "the spending-window reservation could not be written: {other:?}"
        )),
    }
}

/// The refusal of a resend of bytes the wallet has already recorded: the
/// caller reconciles the transaction it names rather than sending again.
fn already_submitted(intent: &SubmissionIntent) -> WalletError {
    WalletError::Submission(SubmissionError::TxAlreadySubmitted {
        hash: intent.tx_hash.clone(),
    })
}

/// Which way a reservation is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowSettlement {
    /// The spend was real; the records stay and keep counting.
    Confirm(Option<i64>),
    /// The spend did not happen; the records go.
    Release,
}

/// What the tip-anchor check right after the pending row found.
#[derive(Debug)]
enum AnchorAfterRow {
    /// The anchor covers the pending row, or there is no audit writer.
    Current,
    /// The anchor does not cover the pending row. The refusal is returned
    /// once the reservation step has decided how the row is closed.
    Behind(WalletError),
}

/// How far `pre_send` got before it failed, which says what has to be undone.
///
/// A refusal at the tip-anchor check before the receipt gate, or at the
/// receipt gate itself, has nothing of this attempt to undo and uses none of
/// these.
///
/// A failed row settles every pending row that carries its envelope hash.
/// After an anchor refusal with window entries, the recorder attempts to close
/// the row only after `record_pending` succeeds. Without window entries, the
/// receipt gate records a new receipt and is the only duplicate check. It does
/// not consult a reservation from an earlier stateful policy. For a
/// `record_pending` error other than the duplicate refusal, the recorder also
/// attempts to close the row. That error can precede the duplicate decision,
/// so it does not prove exclusive ownership of the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnwoundAfter {
    /// The receipt must be removed. A failed pending-row append leaves no
    /// row. On a duplicate reservation refusal the pending row exists and
    /// stays open for the original submission's settlement.
    Receipt,
    /// The receipt and the pending audit row exist. The recorder attempts to
    /// close the row after a nonduplicate reservation error or, without window
    /// entries, an anchor refusal.
    PendingRow,
    /// The receipt, the pending row, and the reservation exist: a pending row
    /// the tip anchor does not cover after the reservation was admitted, or a
    /// receipt that could not be marked submitted.
    Reservation,
}

impl WalletSubmissionRecorder<'_> {
    /// Marks the receipt submitted.
    ///
    /// A failure here is an I/O or lock condition inside the receipt store,
    /// which no test can provoke between two calls the recorder makes back to
    /// back. Under `test-hooks` a toggle stands in for that condition; the
    /// refusal it produces and the unwind above it are the production ones.
    fn mark_submitted(&self, envelope_hash: &str) -> Result<(), ReceiptStoreError> {
        #[cfg(feature = "test-hooks")]
        if FAIL_MARK_SUBMITTED.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ReceiptStoreError::WriterLocked);
        }
        self.receipts.mark_submitted(envelope_hash)
    }

    /// Undoes what `pre_send` wrote for a submission that was never sent.
    ///
    /// The refusal tells the caller nothing left the wallet and invites a
    /// retry. That retry rebuilds at the same sequence, so the records this
    /// attempt wrote have to go: a receipt left behind would refuse the retry
    /// as a duplicate, and a reservation left behind would count a spend that
    /// never happened against the operator's caps.
    ///
    /// Every step is best-effort and logged: the release, the closing row,
    /// and the receipt removal are each attempted whether or not the one
    /// before it succeeded. The receipt is removed last, because it is the
    /// record the other two are keyed to. `code` is the wire code of the
    /// refusal that stopped the submission; the row that closes out the
    /// pending row carries it, so the audit log names a cap refusal as the
    /// policy denial it is and an uncovered row as
    /// `submission.record_unavailable`. The closing row takes the writer guard
    /// again, so no caller holds it here, and it is a plain append: it lands
    /// during an anchor outage too.
    fn unwind(&self, intent: &SubmissionIntent, reached: UnwoundAfter, code: &str) {
        if reached == UnwoundAfter::Reservation {
            self.settle_window(intent, WindowSettlement::Release);
        }
        if matches!(
            reached,
            UnwoundAfter::PendingRow | UnwoundAfter::Reservation
        ) {
            // The pending row is in an append-only log and cannot be taken
            // back, so it is closed out instead.
            self.write_failed_row(intent, code);
        }
        if let Err(e) = self.receipts.abandon_pre_submit(&intent.envelope_hash) {
            tracing::warn!(
                profile = %self.profile_name,
                tool = %self.tool,
                error = %e,
                "submission record: the receipt for an unsent submission could not be removed; \
                 its sequence stays held until an operator clears it"
            );
        }
    }

    fn finalize_receipt(
        &self,
        intent: &SubmissionIntent,
        status: ReceiptStatus,
        ledger: Option<u32>,
    ) {
        if let Err(e) = self
            .receipts
            .finalize(&intent.envelope_hash, status, ledger)
        {
            tracing::warn!(
                profile = %self.profile_name,
                tool = %self.tool,
                error = %e,
                "submission record: receipt finalize failed; the receipt still reports pending"
            );
        }
    }

    fn write_failed_row(&self, intent: &SubmissionIntent, code: &str) {
        self.write_outcome_row(AuditEntry::new_value_action_failed(
            self.tool,
            self.chain_id.clone(),
            self.legs.clone(),
            redact_tx_hash(&intent.tx_hash),
            code,
            self.policy_decision.clone(),
            Some(intent.envelope_hash.clone()),
            self.nonce_id.clone(),
            self.approval
                .as_ref()
                .map(|approval| approval.approval_nonce.clone()),
            &self.request_id,
        ));
    }

    fn settle_window(&self, intent: &SubmissionIntent, settlement: WindowSettlement) {
        if self.window_entries.is_empty() {
            return;
        }
        let result = match settlement {
            WindowSettlement::Confirm(created_at) => {
                self.window
                    .confirm(self.profile, &intent.envelope_hash, created_at)
            }
            WindowSettlement::Release => self.window.release(self.profile, &intent.envelope_hash),
        };
        if let Err(e) = result {
            tracing::warn!(
                profile = %self.profile_name,
                tool = %self.tool,
                error = ?e,
                settlement = ?settlement,
                "submission record: window reservation settle failed; the reservation stands \
                 until reconciliation"
            );
        }
    }
}

/// Forces the `mark_submitted` step of `pre_send` to fail, so the unwind that
/// follows it is reachable from a test.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static FAIL_MARK_SUBMITTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Skips the window pre-check so tests reach its in-lock duplicate backstop.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static SKIP_WINDOW_PRECHECK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the recorder checks for held bytes before writing its pending row.
fn window_precheck_enabled() -> bool {
    #[cfg(feature = "test-hooks")]
    if SKIP_WINDOW_PRECHECK.load(std::sync::atomic::Ordering::Acquire) {
        return false;
    }
    true
}

/// The refusal context for a tip anchor that cannot be repaired before the
/// pending row.
const BEFORE_ROW_CONTEXT: &str = "the audit log is not ready for the pending value-action row";

/// The refusal context for a pending row that could not be appended.
const APPEND_CONTEXT: &str = "the pending value-action row could not be appended";

/// The refusal context for a pending row the tip anchor does not cover.
const AFTER_ROW_CONTEXT: &str =
    "the pending value-action row is not covered by the audit tip anchor";

/// Takes the audit writer's guard, refusing on a poisoned mutex.
fn lock_audit(writer: &AuditWriterHandle) -> Result<MutexGuard<'_, AuditWriter>, WalletError> {
    writer.lock().map_err(|_| {
        record_unavailable(
            "the audit writer mutex is poisoned, so the submission cannot be recorded",
        )
    })
}

fn record_unavailable(detail: impl Into<String>) -> WalletError {
    WalletError::Submission(SubmissionError::RecordUnavailable {
        detail: detail.into(),
    })
}

/// Maps a receipt-store failure to the refusal it causes.
fn receipt_store_refusal(e: &ReceiptStoreError) -> WalletError {
    record_unavailable(format!("the submission receipt could not be written: {e}"))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn record_unavailable_carries_the_wire_code() {
        let err = record_unavailable("receipt store is not writable");
        assert_eq!(err.code(), "submission.record_unavailable");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn pending_and_submitted_rows_carry_the_witness() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet("signer", "witness", "nonce", "witness").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        let witness = crate::cross_check::CrossCheckWitness::for_crate_tests(
            "https://oracle.example",
            123,
            [9; 32],
            vec![stellar_agent_core::cross_check::WitnessEntry::SourceAccount],
        );
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "witness",
            "stellar_pay_commit",
            Some("stellar:testnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            vec![],
            ReceiptStore::open_at(dir.path(), "witness").unwrap(),
            PersistedWindowStore::at_path(dir.path().join("window.json")),
            Some(audit),
            None,
            "request",
            1_000,
        )
        .with_witness(Some(&witness));
        let intent = SubmissionIntent {
            envelope_hash: "a".repeat(64),
            tx_hash: "b".repeat(64),
            source: stellar_strkey::ed25519::PublicKey([7; 32])
                .to_string()
                .to_string(),
            sequence: 7,
            max_time: 0,
            submission_ledger: 123,
        };
        recorder.pre_send(&intent).await.unwrap();
        recorder
            .outcome(
                &intent,
                &SubmissionOutcome::Success {
                    ledger: 124,
                    created_at: Some(1),
                },
            )
            .await;
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["kind"], "value_action_pending");
        assert_eq!(rows[1]["kind"], "value_action_submitted");
        for row in rows {
            assert_eq!(
                row["witness"],
                serde_json::to_value(witness.record()).unwrap()
            );
        }
    }

    /// Runs the in-lock duplicate backstop: a first submission reserves the
    /// bytes, its receipt is lost, and a resend of the same bytes skips the
    /// window pre-check. `before_resend` runs between the receipt loss and
    /// the resend. Returns the resend's refusal, after asserting what both
    /// the plain and the anchor-outage cases leave behind: no receipt, one
    /// reservation, two open pending rows, and the original settlement owed.
    #[cfg(all(feature = "test-helpers", feature = "test-hooks"))]
    async fn assert_duplicate_backstop_keeps_the_pending_row_open(
        access: Option<stellar_agent_core::audit_log::tip_anchor::KeyedAuditAccess>,
        before_resend: impl FnOnce(),
    ) -> WalletError {
        use stellar_agent_core::audit_log::reader::{
            ValueActionSettlement, try_value_action_settlement,
        };
        use stellar_agent_core::policy::v1::criteria::state_store::{
            StateKey, WindowEntry, WindowLimit,
        };

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet("backstop", "s", "n", "a").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), access).unwrap(),
        ));
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let receipts = ReceiptStore::open_at(dir.path(), "backstop").unwrap();
        let window = PersistedWindowStore::at_path(dir.path().join("backstop.window"));
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "backstop",
            "stellar_pay_commit",
            Some("stellar:testnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            vec![WindowEntry::new(
                StateKey::new("backstop", 1, "native", 86_400),
                now,
                10,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000,
                },
            )],
            receipts.clone(),
            window.clone(),
            Some(audit.clone()),
            None,
            "request",
            now,
        );
        let intent = SubmissionIntent {
            envelope_hash: "7a".repeat(32),
            tx_hash: "8b".repeat(32),
            source: format!("{}", stellar_strkey::ed25519::PublicKey([7; 32])),
            sequence: 7,
            max_time: 0,
            submission_ledger: 123,
        };
        recorder.pre_send(&intent).await.unwrap();
        std::fs::remove_file(receipts.file_path().unwrap()).unwrap();
        before_resend();
        SKIP_WINDOW_PRECHECK.store(true, std::sync::atomic::Ordering::Release);
        let refused = recorder.pre_send(&intent).await;
        SKIP_WINDOW_PRECHECK.store(false, std::sync::atomic::Ordering::Release);
        let refused = refused.unwrap_err();
        assert_eq!(refused.code(), "submission.tx_already_submitted");
        assert!(receipts.get(&intent.envelope_hash).unwrap().is_none());
        assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);
        drop(recorder);
        drop(audit);
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows.iter().all(|row| row["kind"] == "value_action_pending"));
        assert!(matches!(
            try_value_action_settlement(&profile.audit_log_path, &intent.envelope_hash).unwrap(),
            ValueActionSettlement::Owed(_)
        ));
        refused
    }

    /// The in-lock duplicate refusal keeps the original settlement owed.
    #[cfg(all(feature = "test-helpers", feature = "test-hooks"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn duplicate_backstop_keeps_the_pending_row_open() {
        assert_duplicate_backstop_keeps_the_pending_row_open(None, || {}).await;
    }

    /// A resend whose pending row the tip anchor does not cover and whose
    /// reservation write meets the original's reservation is refused as the
    /// duplicate it is, and its row stays open: the anchor refusal closes a
    /// row only once the reservation step found no other record of the bytes.
    #[cfg(all(feature = "test-helpers", feature = "test-hooks"))]
    #[tokio::test]
    #[serial_test::serial]
    async fn an_uncovered_duplicate_keeps_the_pending_row_open() {
        use stellar_agent_core::audit_log::tip_anchor::{
            InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore,
        };

        let store = Arc::new(InMemoryTipAnchorStore::new());
        let access = KeyedAuditAccess::new(
            zeroize::Zeroizing::new([0x5c; 32]),
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        );
        // The resend's pending-row anchor write and its immediate retry fail,
        // and so does the retry under the guard right after the row.
        let refused = assert_duplicate_backstop_keeps_the_pending_row_open(Some(access), || {
            store.fail_next_writes(3);
        })
        .await;
        assert!(
            !refused.message().contains("audit.tip_anchor_unavailable"),
            "the duplicate refusal is reported, not the anchor refusal: {refused:?}"
        );
        assert_eq!(
            store.writes().len(),
            1,
            "only the original row was anchored"
        );
    }
}
