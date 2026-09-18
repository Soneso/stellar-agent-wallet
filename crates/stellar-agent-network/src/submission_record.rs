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

use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, WriterError};
use stellar_agent_core::error::{SubmissionError, ValidationError, WalletError};
use stellar_agent_core::profile::receipt::{
    BeginSubmissionOutcome, ReceiptStatus, ReceiptStore, ReceiptStoreError,
};
use stellar_agent_core::profile::schema::Profile;

use crate::policy_state::{PersistedWindowStore, WindowReservation};
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
    /// answered `ERROR` with a real `TransactionResult`. Nothing was queued,
    /// no value moved, and the refusal is not retried.
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
    /// the record cannot be written, and when a pending record already holds
    /// this transaction's `(source, sequence)`.
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
    profile: &'a Profile,
    profile_name: String,
    tool: &'static str,
    chain_id: Option<String>,
    legs: Vec<ValueLegRecord>,
    window_entries: Vec<(
        stellar_agent_core::policy::v1::criteria::state_store::StateKey,
        u64,
        i128,
    )>,
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
    /// Builds a recorder for one submission.
    ///
    /// `window_entries` are the `(state key, timestamp, amount)` triples the
    /// policy engine sized for this action — the SAME derivation the gate
    /// evaluated and the audit rows carry. `legs` is that same sizing in its
    /// audit-row form.
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
        legs: Vec<ValueLegRecord>,
        window_entries: Vec<(
            stellar_agent_core::policy::v1::criteria::state_store::StateKey,
            u64,
            i128,
        )>,
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

    fn reservation(&self, intent: &SubmissionIntent) -> WindowReservation {
        WindowReservation {
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

    /// Writes the pending audit row.
    ///
    /// Fails closed where a writer exists: an unrecorded submission is one the
    /// value audit cannot account for. Where the profile has no audit log at
    /// all there is nothing to fail against, and the submission proceeds.
    fn write_pending_row(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        let Some(writer) = self.audit.as_ref() else {
            return Ok(());
        };
        let entry = AuditEntry::new_value_action_pending(
            self.tool,
            self.chain_id.clone(),
            self.legs.clone(),
            redact_tx_hash(&intent.tx_hash),
            redact_account(&intent.source),
            intent.sequence,
            PolicyDecision::Allow,
            Some(intent.envelope_hash.clone()),
            self.nonce_id.clone(),
            &self.request_id,
        );
        let mut guard = writer.lock().map_err(|_| {
            record_unavailable(
                "the audit writer mutex is poisoned, so the submission cannot be recorded",
            )
        })?;
        guard.write_entry(entry).map_err(|error| match error {
            WriterError::TipAnchorMismatch { reason, .. } => {
                WalletError::Validation(ValidationError::AuditTipAnchorMismatch {
                    profile: self.profile_name.clone(),
                    reason: reason.to_owned(),
                })
            }
            other => record_unavailable(format!(
                "the pending value-action row could not be appended: {other}"
            )),
        })
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
        // The replay identity first. `begin_submission` answers it and the
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
        if let Err(e) = self.write_pending_row(intent) {
            self.unwind(intent, UnwoundAfter::Receipt);
            return Err(e);
        }

        if !self.window_entries.is_empty()
            && let Err(e) = self.window.record_pending(
                self.profile,
                &self.window_entries,
                &self.reservation(intent),
            )
        {
            self.unwind(intent, UnwoundAfter::PendingRow);
            return Err(record_unavailable(format!(
                "the spending-window reservation could not be written: {e:?}"
            )));
        }

        // Last, and immediately before the send: `submitted` is what says the
        // bytes left, and it is the flag that makes the receipt un-abandonable.
        // Setting it earlier would strand a receipt for a submission a later
        // failure stopped.
        if let Err(e) = self.mark_submitted(&intent.envelope_hash) {
            self.unwind(intent, UnwoundAfter::Reservation);
            return Err(receipt_store_refusal(&e));
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
                        PolicyDecision::Allow,
                        Some(intent.envelope_hash.clone()),
                        self.nonce_id.clone(),
                        &self.request_id,
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

/// Which way a reservation is settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowSettlement {
    /// The spend was real; the records stay and keep counting.
    Confirm(Option<i64>),
    /// The spend did not happen; the records go.
    Release,
}

/// How far `pre_send` got before it failed, which says what has to be undone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnwoundAfter {
    /// The receipt exists; nothing else was written.
    Receipt,
    /// The receipt and the pending audit row exist.
    PendingRow,
    /// The receipt, the pending row and the reservation exist.
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
    /// Every step is best-effort and logged. The receipt is removed last,
    /// because it is the record the other two are keyed to.
    fn unwind(&self, intent: &SubmissionIntent, reached: UnwoundAfter) {
        if reached == UnwoundAfter::Reservation {
            self.settle_window(intent, WindowSettlement::Release);
        }
        if matches!(
            reached,
            UnwoundAfter::PendingRow | UnwoundAfter::Reservation
        ) {
            // The pending row is in an append-only log and cannot be taken
            // back, so it is closed out instead.
            self.write_failed_row(intent, RECORD_UNAVAILABLE_CODE);
        }
        if let Err(e) = self.receipts.abandon_pre_submit(&intent.envelope_hash) {
            tracing::warn!(
                profile = %self.profile_name,
                tool = %self.tool,
                error = %e,
                "submission record: the receipt for an unsent submission could not be removed;                  its sequence stays held until an operator clears it"
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
            PolicyDecision::Allow,
            Some(intent.envelope_hash.clone()),
            self.nonce_id.clone(),
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

/// Builds the refusal that stops a send whose record cannot be written.
/// The wire code a submission that was never sent reports, and the code the
/// closing audit row carries for it.
const RECORD_UNAVAILABLE_CODE: &str = "submission.record_unavailable";

/// Forces the `mark_submitted` step of `pre_send` to fail, so the unwind that
/// follows it is reachable from a test.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static FAIL_MARK_SUBMITTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
}
