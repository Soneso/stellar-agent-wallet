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
//! On the unauthorized path, after receipt loss a closing row can also settle
//! the original submission.
//! Without current window entries, a reservation from an earlier stateful
//! policy can remain and let reconciliation recover its identity. Without
//! that reservation, reconciliation has no record left to settle it by.
//! An outcome row the original process writes later wins the lookup.
//!
//! # A mainnet grant
//!
//! [`SubmissionRecorder::pre_send_authorized`] is the branch a submission
//! under a mainnet grant takes in place of `pre_send`. The wallet's recorder
//! claims a receipt and checks window reservations. Under one writer guard it
//! checks retained audit ownership, appends a pending row, and reads fresh audit
//! facts. An owed settlement refuses before the row even
//! when the original policy had no holds. It then consumes the grant's
//! authorization in the ledger instead of recording a
//! reservation: the authorization's holds become this submission's pending
//! window records and the authorization is used. The audit facts the
//! consumption compares are read under the guard that appended the pending
//! row, and a tip the anchor does not cover refuses before the consumption. A
//! refusal of the consumption unwinds as a reservation refusal does, and a
//! failure after it releases the converted records and leaves the
//! authorization used. The proof it returns is what the send depends on.
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

use stellar_agent_core::audit_log::reader::{ValueActionSettlement, try_value_action_settlement};
use stellar_agent_core::audit_log::schema::ValueLegRecord;
use stellar_agent_core::audit_log::writer::{AuditWriter, VerifiedTipFacts};
use stellar_agent_core::audit_log::{AuditEntry, PolicyDecision, WriterError};
use stellar_agent_core::error::{NetworkError, SubmissionError, ValidationError, WalletError};
use stellar_agent_core::profile::receipt::{
    BeginSubmissionOutcome, ReceiptStatus, ReceiptStore, ReceiptStoreError,
};
use stellar_agent_core::profile::schema::Profile;

use crate::mainnet::consumed::AuthorizationConsumed;
use crate::mainnet::refusal::AuthorizedPathError;
use crate::mainnet::{AuditFacts, AuthorizationDomain, MainnetPrecondition, RecomputedFacts};
use crate::policy_state::{
    ConsumptionBinding, PersistedWindowStore, SubmissionBinding, SubmissionHold, WindowStoreError,
};
use crate::sequence_floor::SequenceFloorHook;
use crate::submit::{MainnetSubmitGrant, redact_tx_hash};
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

    /// Records the submission and consumes the grant's mainnet authorization,
    /// immediately before `sendTransaction`, in place of
    /// [`Self::pre_send`].
    ///
    /// The returned proof is what the send depends on, and only this crate
    /// can construct one: an implementation that consumes nothing keeps the
    /// default, which refuses.
    ///
    /// # Errors
    ///
    /// Returning an error refuses the send. The default returns
    /// `network.mainnet_authorization_refused`; the wallet's recorder also
    /// returns the refusals of [`Self::pre_send`] and of the consumption.
    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        let _ = (intent, grant);
        Err(WalletError::Network(
            NetworkError::MainnetAuthorizationRefused,
        ))
    }

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

    /// Builds a recorder whose settlement entries are the authorization's minted holds.
    #[allow(
        clippy::too_many_arguments,
        reason = "the recorder binds the complete submission context"
    )]
    pub fn new_authorized(
        profile: &'a Profile,
        profile_name: impl Into<String>,
        tool: &'static str,
        chain_id: Option<String>,
        policy_decision: PolicyDecision,
        legs: Vec<ValueLegRecord>,
        authorization: &crate::mainnet::authorization::MainnetTxSignAuthorization,
        receipts: ReceiptStore,
        window: PersistedWindowStore,
        audit: Option<AuditWriterHandle>,
        nonce_id: Option<String>,
        request_id: impl Into<String>,
        now_ms: u64,
    ) -> Self {
        Self::new(
            profile,
            profile_name,
            tool,
            chain_id,
            policy_decision,
            legs,
            authorization.entries().to_vec(),
            receipts,
            window,
            audit,
            nonce_id,
            request_id,
            now_ms,
        )
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
        let mut guard = lock_audit(writer)?;
        guard
            .write_entry(self.pending_entry(intent))
            .map_err(|error| self.audit_refusal(error, APPEND_CONTEXT))?;
        Ok(match guard.require_anchor_current() {
            Ok(()) => AnchorAfterRow::Current,
            Err(error) => AnchorAfterRow::Behind(self.audit_refusal(error, AFTER_ROW_CONTEXT)),
        })
    }

    /// The pending value-action row of a submission.
    fn pending_entry(&self, intent: &SubmissionIntent) -> AuditEntry {
        AuditEntry::new_value_action_pending(
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
        )
    }

    /// Maps an audit-writer failure on the pending-row path to the refusal the
    /// caller reports.
    ///
    /// A tip-anchor mismatch and a missing anchor the log shows was written
    /// keep their own codes, because only `audit reanchor` addresses them.
    /// Every other failure is `submission.record_unavailable`:
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
            WriterError::TipAnchorMissing { evidence, .. } => {
                WalletError::Validation(ValidationError::AuditTipAnchorMissing {
                    profile: self.profile_name.clone(),
                    evidence: evidence.describe().to_owned(),
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

        self.claim_receipt(intent)?;
        // The unauthorized path checks reservations only when it sizes entries.
        if !self.window_entries.is_empty() {
            self.window_precheck(intent)?;
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

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        self.consume_for_submission(intent, grant)
            .map_err(|error| error.report("pre_send_authorized"))
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

/// A refused consumption, as the authorized branch reports it.
#[derive(Debug)]
enum ConsumptionRefusal {
    /// The ledger refused a precondition; reported as the generic mainnet
    /// refusal, with the precondition logged.
    Precondition(MainnetPrecondition),
    /// Any other refusal, reported as `pre_send` reports a reservation
    /// refusal.
    Error(WalletError),
}

impl ConsumptionRefusal {
    /// The wire code the closing row of an unwound submission carries.
    fn code(&self) -> &'static str {
        match self {
            Self::Precondition(_) => authorization_refused_code(),
            Self::Error(error) => error.code(),
        }
    }
}

/// Turns a refused consumption into the refusal the caller reports.
fn consumption_refusal(error: WindowStoreError, intent: &SubmissionIntent) -> ConsumptionRefusal {
    match error {
        WindowStoreError::AuthorizationRefused { precondition } => {
            ConsumptionRefusal::Precondition(precondition)
        }
        WindowStoreError::DuplicateConsumption => {
            ConsumptionRefusal::Error(already_submitted(intent))
        }
        other => ConsumptionRefusal::Error(reservation_refusal(other, intent)),
    }
}

/// The audit facts a consumption compares, from a verified tip.
///
/// A tip the anchor does not cover after the writer's repair and drain has no
/// anchored count to compare, so it yields none and the consumption is
/// refused before it is entered.
fn covered_audit_facts(facts: VerifiedTipFacts) -> Option<AuditFacts> {
    if !facts.anchor_covers_tip {
        return None;
    }
    Some(AuditFacts {
        segment: facts.segment_start_hash,
        log_path_digest: facts.log_path_sha256,
        anchored_count: facts.entry_count,
    })
}

/// The wire code of a mainnet authorization refusal, which the closing row of
/// an unwound authorized submission carries.
fn authorization_refused_code() -> &'static str {
    WalletError::Network(NetworkError::MainnetAuthorizationRefused).code()
}

/// Decodes a 64-character hex hash of a submission intent.
fn decode_intent_hash(hex: &str) -> Result<[u8; 32], WalletError> {
    stellar_agent_core::hex::decode_hex32(hex).map_err(|e| {
        record_unavailable(format!(
            "a submission hash is not 32 hex-encoded bytes: {e}"
        ))
    })
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
/// On the unauthorized path, after an anchor refusal with window entries,
/// the recorder attempts to close the row only after `record_pending` succeeds.
/// Without window entries, the receipt gate records a new receipt and is the
/// only duplicate check. It does not consult a reservation from an earlier
/// stateful policy. For a `record_pending` error other than the duplicate refusal,
/// the recorder also attempts to close the row. That error can precede the
/// duplicate decision, so it does not prove exclusive ownership of the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnwoundAfter {
    /// The receipt must be removed. A failed pending-row append leaves no
    /// row. On a duplicate reservation refusal the pending row exists and
    /// stays open for the original submission's settlement.
    Receipt,
    /// The receipt and the pending audit row exist. The recorder attempts to
    /// close the row after a prior consumption, a nonduplicate reservation or
    /// consumption error, an authorized tip error or uncovered tip, or an
    /// unauthorized anchor refusal without window entries.
    PendingRow,
    /// The receipt, the pending row, and the reservation exist: a pending row
    /// the tip anchor does not cover after the reservation was admitted, or a
    /// receipt that could not be marked submitted.
    Reservation,
}

impl WalletSubmissionRecorder<'_> {
    /// Claims the submission's receipt: the replay identity and the
    /// envelope-hash gate.
    ///
    /// # Errors
    ///
    /// `submission.tx_already_submitted` for a pair, an approval, or bytes
    /// another receipt holds, and `submission.record_unavailable` when the
    /// receipt store fails. Nothing of this attempt exists then.
    fn claim_receipt(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        // `begin_submission` answers the replay identity and the
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
            Ok(BeginSubmissionOutcome::Recorded) => Ok(()),
            Ok(
                BeginSubmissionOutcome::DuplicateSequence(existing)
                | BeginSubmissionOutcome::DuplicateApproval(existing)
                | BeginSubmissionOutcome::AlreadyPresent(existing),
            ) => Err(WalletError::Submission(
                SubmissionError::TxAlreadySubmitted {
                    hash: existing.tx_hash,
                },
            )),
            Err(e) => Err(receipt_store_refusal(&e)),
        }
    }

    /// Asks the window whether it already holds these signed bytes, after the
    /// receipt claim and before the pending row. A refusal undoes the receipt
    /// without writing a closing row for the original submission.
    ///
    /// The authorized path always checks, even when the recorder sizes no
    /// entries: an earlier submission can hold a reservation for these bytes.
    /// The unauthorized path checks only when its recorder sizes entries.
    ///
    /// # Errors
    ///
    /// `submission.tx_already_submitted` for held bytes, and the refusal of
    /// an unreadable window.
    fn window_precheck(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        if !window_precheck_enabled() {
            return Ok(());
        }
        let refusal = match self
            .window
            .holds_reservation(self.profile, &intent.envelope_hash)
        {
            Ok(false) => return Ok(()),
            Ok(true) => already_submitted(intent),
            Err(e) => reservation_refusal(e, intent),
        };
        self.unwind(intent, UnwoundAfter::Receipt, refusal.code());
        Err(refusal)
    }

    /// Refuses bytes whose original pending row still owes settlement.
    ///
    /// The receipt can be lost even when the original policy had no window
    /// entries. The audit row preserves ownership in that case. The caller holds
    /// the writer guard through this lookup, the append, and the fresh tip read.
    /// A read error fails closed; neither refusal writes a closing row.
    fn settlement_precheck(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        #[cfg(feature = "test-hooks")]
        if SKIP_SETTLEMENT_PRECHECK.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let refusal = match try_value_action_settlement(
            &self.profile.audit_log_path,
            &intent.envelope_hash,
        ) {
            Ok(ValueActionSettlement::Owed(_)) => already_submitted(intent),
            Ok(ValueActionSettlement::OwedWithoutLegs | ValueActionSettlement::Settled) => {
                return Ok(());
            }
            Err(error) => record_unavailable(format!("audit settlement lookup failed: {error}")),
        };
        Err(refusal)
    }

    /// The wallet's consumption of a mainnet grant for one submission.
    ///
    /// Without an audit writer nothing is recorded or consumed: the audit
    /// facts the ledger compares cannot be read. Otherwise the receipt claim and
    /// window check precede the writer guard. The settlement lookup, pending-row
    /// append, and fresh audit facts share that guard, so rotation cannot hide
    /// an owed row between the lookup and the append.
    ///
    /// The authorization is consumed with this submission's binding, the recomputed
    /// content digest, the digest of the recorder's own window entries, and those
    /// facts. Consumption runs even when the recorder sizes no window entries, so
    /// an authorization without holds becomes used too.
    ///
    /// Unwind stages: a settlement or window-check refusal, a writer-lock or
    /// pending-row append failure, and a duplicate reservation take the receipt
    /// stage. This leaves the original submission's open row open. A duplicate
    /// consumption takes the pending-row stage: the guarded lookup established
    /// that no retained original row was owed at append time. A tip read error,
    /// an uncovered tip, and every other consumption refusal also take that stage,
    /// which leaves every open authorization and hold as it was.
    ///
    /// A receipt that cannot be marked submitted after consumption takes the
    /// reservation stage. This releases the converted window records by envelope
    /// hash and never reopens the used authorization.
    fn consume_for_submission(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, AuthorizedPathError> {
        let MainnetSubmitGrant::Tx(authorization) = grant;
        let Some(writer) = self.audit.as_ref() else {
            return Err(AuthorizedPathError::Refused(
                MainnetPrecondition::AuditNotAnchored,
            ));
        };
        let envelope_hash = decode_intent_hash(&intent.envelope_hash)?;
        let tx_hash = decode_intent_hash(&intent.tx_hash)?;
        self.require_anchor_before_row()?;
        self.claim_receipt(intent)?;
        self.window_precheck(intent)?;

        let audit = match self.write_pending_row_with_facts(writer, intent) {
            Ok(Some(audit)) => audit,
            Ok(None) => {
                self.unwind(
                    intent,
                    UnwoundAfter::PendingRow,
                    authorization_refused_code(),
                );
                return Err(AuthorizedPathError::Refused(
                    MainnetPrecondition::AuditNotAnchored,
                ));
            }
            Err((error, reached)) => {
                self.unwind(intent, reached, error.code());
                return Err(AuthorizedPathError::Wallet(error));
            }
        };

        let content_digest =
            crate::mainnet::digest::content_digest(AuthorizationDomain::Transaction, &tx_hash);
        let expect = authorization.consume_expect(&RecomputedFacts {
            content_digest,
            entries_digest: crate::mainnet::digest::entries_digest(authorization.entries()),
            audit,
        });
        let binding = ConsumptionBinding::Transaction(SubmissionBinding {
            fee_bump: None,
            envelope_hash,
            tx_hash,
            source: intent.source.clone(),
            sequence: intent.sequence,
            max_time: intent.max_time,
            pending_since_ms: self.now_ms,
            submission_ledger: intent.submission_ledger,
        });
        let authorization_id = authorization.id();
        if let Err(e) =
            self.window
                .consume_authorization(self.profile, authorization_id, &expect, &binding)
        {
            // A duplicate found under the lock is a resend of bytes another
            // submission reserved: its pending row names the same envelope
            // hash and stays open for that submission's settlement. A prior
            // consumption without a reservation closes this resend's own row:
            // the guarded lookup found no retained original row still owed.
            let reached = match e {
                WindowStoreError::DuplicateReservation => UnwoundAfter::Receipt,
                _ => UnwoundAfter::PendingRow,
            };
            let refusal = consumption_refusal(e, intent);
            self.unwind(intent, reached, refusal.code());
            return Err(match refusal {
                ConsumptionRefusal::Precondition(precondition) => {
                    AuthorizedPathError::Refused(precondition)
                }
                ConsumptionRefusal::Error(error) => AuthorizedPathError::Wallet(error),
            });
        }

        if let Err(e) = self.mark_submitted(&intent.envelope_hash) {
            let refusal = receipt_store_refusal(&e);
            self.unwind(intent, UnwoundAfter::Reservation, refusal.code());
            return Err(refusal.into());
        }
        Ok(AuthorizationConsumed::new(
            envelope_hash,
            content_digest,
            authorization_id,
        ))
    }

    /// Checks retained settlement, appends the pending row, and reads fresh
    /// audit facts under one writer guard.
    ///
    /// `Ok(None)` is a row the anchor does not cover after the writer's own
    /// repair and drain: the row is durable and is closed by the caller's
    /// unwind.
    ///
    /// # Errors
    ///
    /// A refusal with the stage reached: receipt for a writer lock, settlement
    /// lookup, or append refusal; pending row for a failure to verify the tip.
    fn write_pending_row_with_facts(
        &self,
        writer: &AuditWriterHandle,
        intent: &SubmissionIntent,
    ) -> Result<Option<AuditFacts>, (WalletError, UnwoundAfter)> {
        let mut guard = lock_audit(writer).map_err(|error| (error, UnwoundAfter::Receipt))?;
        self.settlement_precheck(intent)
            .map_err(|error| (error, UnwoundAfter::Receipt))?;
        self.append_pending_row(&mut guard, intent)
            .map_err(|error| {
                (
                    self.audit_refusal(error, APPEND_CONTEXT),
                    UnwoundAfter::Receipt,
                )
            })?;
        let facts = guard.verified_tip_facts().map_err(|error| {
            (
                self.audit_refusal(error, AFTER_ROW_CONTEXT),
                UnwoundAfter::PendingRow,
            )
        })?;
        #[cfg(feature = "test-hooks")]
        if UNCOVERED_AUTHORIZED_TIP.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(None);
        }
        Ok(covered_audit_facts(facts))
    }

    /// Appends the pending row of an authorized submission.
    ///
    /// Under `test-hooks` a toggle fails the append with an I/O error before
    /// it is attempted, which stands in for a write or sync failure after
    /// which the writer still accepts the next row; the refusal it produces
    /// and the unwind above it are the production ones.
    fn append_pending_row(
        &self,
        writer: &mut AuditWriter,
        intent: &SubmissionIntent,
    ) -> Result<(), WriterError> {
        #[cfg(feature = "test-hooks")]
        if FAIL_PENDING_ROW_APPEND.load(std::sync::atomic::Ordering::Acquire) {
            return Err(WriterError::Io(std::io::Error::other(
                "the pending-row append failed",
            )));
        }
        writer.write_entry(self.pending_entry(intent))
    }

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

/// Forces the pending-row append of an authorized submission to fail while
/// the writer still accepts the next row, so the unwind that follows it is
/// observable from a test.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static FAIL_PENDING_ROW_APPEND: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Skips the window pre-check so tests reach its in-lock duplicate backstop.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static SKIP_WINDOW_PRECHECK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Skips the retained settlement lookup to exercise reservation ownership
/// and the consumption backstop independently.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
static SKIP_SETTLEMENT_PRECHECK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Reports an authorized pending row's tip facts as uncovered after the initial
/// anchor check, so tests can exercise the pending-row unwind.
///
/// Only compiled when the `test-hooks` Cargo feature is enabled. Never include
/// `test-hooks` in production or release builds.
#[cfg(feature = "test-hooks")]
static UNCOVERED_AUTHORIZED_TIP: std::sync::atomic::AtomicBool =
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

    /// Verified tip facts with a distinct value in every field.
    fn verified_tip(anchor_covers_tip: bool) -> VerifiedTipFacts {
        VerifiedTipFacts {
            segment_start_hash: [1; 32],
            entry_count: 7,
            tip_hash: [2; 32],
            log_path_sha256: [3; 32],
            anchor_covers_tip,
        }
    }

    /// A covered tip yields its segment, its log path digest, and its entry
    /// count as the anchored count.
    #[test]
    fn a_covered_tip_yields_its_audit_facts() {
        assert_eq!(
            covered_audit_facts(verified_tip(true)),
            Some(AuditFacts {
                segment: [1; 32],
                log_path_digest: [3; 32],
                anchored_count: 7,
            })
        );
    }

    /// A tip the anchor does not cover after the writer's repair and drain
    /// yields no facts, so the consumption is refused before it is entered.
    #[test]
    fn a_tip_the_anchor_does_not_cover_yields_no_audit_facts() {
        assert_eq!(covered_audit_facts(verified_tip(false)), None);
    }

    // ── The authorized branch ─────────────────────────────────────────────────

    #[cfg(feature = "mainnet-write")]
    mod authorized {
        #![allow(clippy::panic, reason = "unit tests; a failed match is a failed test")]

        use serial_test::serial;
        use stellar_agent_core::audit_log::AuditOutbox;
        use stellar_agent_core::audit_log::reader::{
            ValueActionSettlement, try_value_action_settlement,
        };
        use stellar_agent_test_support::signed_envelope::SignedTestEnvelope;

        use super::*;
        use crate::mainnet::AuthorizationId;
        use crate::mainnet::authorization::MainnetTxSignAuthorization;
        use crate::mainnet::fixtures::{self, LedgerFixture, keyed_writer, tip_facts};
        use crate::policy_state::DomainBinding;

        const NOW: u64 = 1_800_000_000_000;

        /// A signed mainnet envelope, the binding of its unsigned form, and
        /// its submission intent.
        struct Submission {
            binding: DomainBinding,
            intent: SubmissionIntent,
        }

        fn submission() -> Submission {
            let unsigned = fixtures::unsigned_envelope();
            let signed: SignedTestEnvelope = fixtures::signed_envelope();
            Submission {
                binding: fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
                intent: fixtures::intent(&signed),
            }
        }

        /// A rebuilt envelope with the same source and sequence and a different amount.
        fn rebuilt_submission() -> Submission {
            let unsigned = SignedTestEnvelope::builder(fixtures::SIGNER_SEED)
                .network_passphrase(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
                .sequence(fixtures::SEQUENCE)
                .amount_stroops(200)
                .unsigned()
                .build();
            let signed = SignedTestEnvelope::builder(fixtures::SIGNER_SEED)
                .network_passphrase(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
                .sequence(fixtures::SEQUENCE)
                .amount_stroops(200)
                .build();
            Submission {
                binding: fixtures::tx_binding(unsigned.envelope_xdr(), unsigned.tx_hash_hex()),
                intent: fixtures::intent(&signed),
            }
        }

        fn holds(
            fx: &LedgerFixture,
            amount: i128,
        ) -> Vec<stellar_agent_core::policy::v1::criteria::state_store::WindowEntry> {
            vec![fixtures::hold(&fx.name, fx.now, amount)]
        }

        /// Mints a grant over `submission` holding `holds` under `nonce`.
        fn grant(
            fx: &LedgerFixture,
            submission: &Submission,
            holds: &[stellar_agent_core::policy::v1::criteria::state_store::WindowEntry],
            nonce: &str,
        ) -> (AuthorizationId, MainnetTxSignAuthorization) {
            let authorization = fx.mint(submission.binding.clone(), holds, None, nonce);
            (authorization.id(), authorization)
        }

        fn refused(
            result: Result<AuthorizationConsumed, AuthorizedPathError>,
        ) -> MainnetPrecondition {
            match result {
                Err(AuthorizedPathError::Refused(precondition)) => precondition,
                other => panic!("expected a refusal, got {other:?}"),
            }
        }

        fn wallet_refusal(
            result: Result<AuthorizationConsumed, AuthorizedPathError>,
        ) -> WalletError {
            match result {
                Err(AuthorizedPathError::Wallet(error)) => error,
                other => panic!("expected a wallet error, got {other:?}"),
            }
        }

        fn receipt(
            fx: &LedgerFixture,
            intent: &SubmissionIntent,
        ) -> Option<stellar_agent_core::profile::receipt::SubmissionReceipt> {
            fx.receipts.get(&intent.envelope_hash).unwrap()
        }

        fn reservations(fx: &LedgerFixture) -> usize {
            fx.window.pending_reservations(&fx.profile).unwrap().len()
        }

        /// Holds the `test-hooks` toggle `flag` set while it lives.
        #[cfg(feature = "test-hooks")]
        struct Toggle(&'static std::sync::atomic::AtomicBool);

        #[cfg(feature = "test-hooks")]
        impl Toggle {
            fn set(flag: &'static std::sync::atomic::AtomicBool) -> Self {
                flag.store(true, std::sync::atomic::Ordering::Release);
                Self(flag)
            }
        }

        #[cfg(feature = "test-hooks")]
        impl Drop for Toggle {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::Release);
            }
        }

        /// A grant is consumed with the submission: the record is used, its
        /// holds are the submission's pending records, the pending row is
        /// written, the receipt is claimed and marked submitted, and the proof
        /// names the envelope, its content, and the authorization.
        #[tokio::test]
        #[serial]
        async fn a_grant_is_consumed_with_the_submission() {
            let fx = LedgerFixture::new("consume", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");
            assert!(fx.is_open(id));
            let recorder = fx.recorder(holds, Some(Arc::clone(&fx.writer)));

            let proof = recorder
                .pre_send_authorized(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .await
                .expect("a valid grant is consumed");

            let envelope_hash = decode_intent_hash(&sub.intent.envelope_hash).unwrap();
            let tx_hash = decode_intent_hash(&sub.intent.tx_hash).unwrap();
            assert_eq!(*proof.envelope_hash(), envelope_hash);
            assert_eq!(
                *proof.content_digest(),
                crate::mainnet::digest::content_digest(AuthorizationDomain::Transaction, &tx_hash)
            );
            assert_eq!(proof.authorization_id(), id);
            assert!(!fx.is_open(id), "the record is used");
            assert!(
                fx.window
                    .holds_reservation(&fx.profile, &sub.intent.envelope_hash)
                    .unwrap(),
                "the holds are the submission's pending records"
            );
            assert_eq!(reservations(&fx), 1);
            assert_eq!(fx.audit_kinds(), ["value_action_pending"]);
            assert!(
                receipt(&fx, &sub.intent)
                    .expect("the receipt is claimed")
                    .submitted
            );
        }

        /// An authorization minted without holds is consumed by a recorder
        /// that sizes no window entries, and nothing is reserved.
        #[tokio::test]
        #[serial]
        async fn an_empty_entries_grant_still_consumes() {
            let fx = LedgerFixture::new("consume-empty", NOW);
            let sub = submission();
            let (id, authorization) = grant(&fx, &sub, &[], "approval-1");
            let recorder = fx.recorder(vec![], Some(Arc::clone(&fx.writer)));

            recorder
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .expect("a grant without holds is consumed");

            assert!(!fx.is_open(id), "the record is used");
            assert_eq!(reservations(&fx), 0);
            assert_eq!(fx.audit_kinds(), ["value_action_pending"]);
        }

        /// A second grant for the same bytes after their receipt was lost is
        /// refused at the window check, before the consumption: the first
        /// record stays used, the second stays open, and the first pending
        /// row stays open for its own settlement.
        #[tokio::test]
        #[serial]
        async fn a_second_grant_after_a_lost_receipt_refuses_at_the_window_check() {
            let fx = LedgerFixture::new("consume-lost-receipt", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (first, authorization) = grant(&fx, &sub, &holds, "approval-1");
            fx.recorder(holds.clone(), Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
            let (second, authorization) = grant(&fx, &sub, &holds, "approval-2");

            #[cfg(feature = "test-hooks")]
            let _settlement = Toggle::set(&SKIP_SETTLEMENT_PRECHECK);
            let error = wallet_refusal(
                fx.recorder(holds, Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization)),
            );

            assert_eq!(error.code(), "submission.tx_already_submitted");
            assert!(!fx.is_open(first), "the first record stays used");
            assert!(fx.is_open(second), "the second record stays open");
            assert_eq!(reservations(&fx), 1);
            assert!(
                receipt(&fx, &sub.intent).is_none(),
                "the receipt stage is undone"
            );
            assert_eq!(fx.audit_kinds(), ["value_action_pending"]);
            assert!(matches!(
                try_value_action_settlement(&fx.profile.audit_log_path, &sub.intent.envelope_hash)
                    .unwrap(),
                ValueActionSettlement::Owed(_)
            ));
        }

        /// With the window check skipped, the consumption itself finds the
        /// bytes reserved and refuses as a duplicate at the receipt stage:
        /// the second pending row stays open beside the first, and no hold is
        /// released.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn a_duplicate_at_the_consumption_takes_the_receipt_stage() {
            let fx = LedgerFixture::new("consume-duplicate", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (first, authorization) = grant(&fx, &sub, &holds, "approval-1");
            fx.recorder(holds.clone(), Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
            let (second, authorization) = grant(&fx, &sub, &holds, "approval-2");

            let result = {
                let _skip = Toggle::set(&SKIP_WINDOW_PRECHECK);
                let _settlement = Toggle::set(&SKIP_SETTLEMENT_PRECHECK);
                fx.recorder(holds, Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
            };

            assert_eq!(
                wallet_refusal(result).code(),
                "submission.tx_already_submitted"
            );
            assert!(!fx.is_open(first));
            assert!(
                fx.is_open(second),
                "the refused consumption leaves the record open"
            );
            assert_eq!(reservations(&fx), 1, "the first submission's holds stay");
            assert!(receipt(&fx, &sub.intent).is_none());
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending", "value_action_pending"],
                "both pending rows stay open"
            );
        }

        /// Exercises window ownership independently of retained audit ownership.
        #[cfg(feature = "test-hooks")]
        async fn empty_recorder_duplicate(skip_precheck: bool, second_has_holds: bool) {
            let fx = LedgerFixture::new("consume-empty-duplicate", NOW);
            let sub = submission();
            let entries = holds(&fx, 100);
            let (first, authorization) = grant(&fx, &sub, &entries, "approval-1");
            fx.recorder(entries.clone(), Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            let original_reservations = fx.window.pending_reservations(&fx.profile).unwrap();
            std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
            let second_entries = if second_has_holds { entries } else { vec![] };
            let (second, authorization) = grant(&fx, &sub, &second_entries, "approval-2");
            let result = {
                let _settlement = Toggle::set(&SKIP_SETTLEMENT_PRECHECK);
                let _skip = skip_precheck.then(|| Toggle::set(&SKIP_WINDOW_PRECHECK));
                fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
            };
            assert_eq!(
                wallet_refusal(result).code(),
                "submission.tx_already_submitted"
            );
            assert!(!fx.is_open(first));
            assert!(fx.is_open(second));
            assert_eq!(
                fx.window.pending_reservations(&fx.profile).unwrap(),
                original_reservations,
                "the original reservation stays"
            );
            assert!(receipt(&fx, &sub.intent).is_none());
            let expected_rows = if skip_precheck { 2 } else { 1 };
            assert_eq!(
                fx.audit_kinds(),
                vec!["value_action_pending"; expected_rows]
            );
            assert!(matches!(
                try_value_action_settlement(&fx.profile.audit_log_path, &sub.intent.envelope_hash)
                    .unwrap(),
                ValueActionSettlement::Owed(_)
            ));
        }

        /// A recorder with no entries still checks the original reservation.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn an_empty_recorder_preserves_a_lost_receipts_open_row() {
            empty_recorder_duplicate(false, true).await;
        }

        /// A duplicate refuses before a mismatched entries digest can close a row.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn duplicate_reservation_precedes_the_entries_comparison() {
            empty_recorder_duplicate(true, true).await;
        }

        /// A grant without holds still refuses bytes with an existing reservation.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn duplicate_reservation_refuses_an_authorization_without_holds() {
            empty_recorder_duplicate(true, false).await;
        }

        /// Fresh bytes consume with a fresh grant after another receipt is lost.
        #[tokio::test]
        #[serial]
        async fn an_empty_recorder_consumes_unheld_bytes_after_a_lost_receipt() {
            let fx = LedgerFixture::new("consume-empty-unheld", NOW);
            let first_sub = submission();
            let entries = holds(&fx, 100);
            let (first, authorization) = grant(&fx, &first_sub, &entries, "approval-1");
            fx.recorder(entries, Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&first_sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
            // A different amount changes the bytes and hash, with the same source and sequence.
            let sub = rebuilt_submission();
            assert_ne!(first_sub.intent.envelope_hash, sub.intent.envelope_hash);
            let (second, authorization) = grant(&fx, &sub, &[], "approval-2");
            fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            fx.assert_used_without_holds(first);
            fx.assert_used_without_holds(second);
            assert_eq!(reservations(&fx), 1);
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending", "value_action_pending"]
            );
        }

        /// Replays a consumed envelope with no reservation after its receipt
        /// is lost. Retained audit ownership must refuse before any new row.
        #[cfg(feature = "test-hooks")]
        async fn stateless_duplicate(uncovered_tip: bool, tip_error: bool) {
            let fx = LedgerFixture::new("consume-stateless-duplicate", NOW);
            let sub = submission();
            let (first, authorization) = grant(&fx, &sub, &[], "approval-1");
            fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
            let (second, authorization) = grant(&fx, &sub, &[], "approval-2");
            let result = {
                let _uncovered = uncovered_tip.then(|| Toggle::set(&UNCOVERED_AUTHORIZED_TIP));
                if tip_error {
                    fx.anchors.fail_next_writes(64);
                }
                fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
            };

            assert_eq!(
                wallet_refusal(result).code(),
                "submission.tx_already_submitted"
            );
            assert!(!fx.is_open(first), "the original authorization stays used");
            assert!(fx.is_open(second), "the fresh authorization stays open");
            assert_eq!(reservations(&fx), 0, "the original policy had no holds");
            assert!(
                receipt(&fx, &sub.intent).is_none(),
                "the receipt stage is undone"
            );
            assert!(
                matches!(
                    try_value_action_settlement(
                        &fx.profile.audit_log_path,
                        &sub.intent.envelope_hash
                    )
                    .unwrap(),
                    ValueActionSettlement::Owed(_)
                ),
                "the original settlement stays owed"
            );
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending"],
                "no later row is written"
            );
        }

        /// Retained audit ownership protects a consumed envelope without holds.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn stateless_duplicate_refuses_before_a_new_row() {
            stateless_duplicate(false, false).await;
        }

        /// An uncovered later tip cannot close the original stateless submission.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn stateless_duplicate_refuses_before_an_uncovered_tip() {
            stateless_duplicate(true, false).await;
        }

        /// A later tip read error cannot close the original stateless submission.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn stateless_duplicate_refuses_before_a_tip_error() {
            stateless_duplicate(false, true).await;
        }

        /// A settled original with a lost receipt refuses the resend and closes
        /// exactly the resend's new row, leaving the envelope settled.
        #[tokio::test]
        #[serial]
        async fn a_settled_consumption_closes_only_the_resends_row() {
            for (label, outcome, settled_kind) in [
                (
                    "rejected",
                    SubmissionOutcome::Rejected {
                        code: "transaction.failed".to_owned(),
                        error: "definitive refusal".to_owned(),
                    },
                    "value_action_failed",
                ),
                (
                    "failed",
                    SubmissionOutcome::OnChainFailed {
                        code: "transaction.failed".to_owned(),
                    },
                    "value_action_failed",
                ),
                (
                    "succeeded",
                    SubmissionOutcome::Success {
                        ledger: 512,
                        created_at: Some(1_800_000_001),
                    },
                    "value_action_submitted",
                ),
            ] {
                let fx = LedgerFixture::new(label, NOW);
                let sub = submission();
                let (first, authorization) = grant(&fx, &sub, &[], "approval-1");
                let recorder = fx.recorder(vec![], Some(Arc::clone(&fx.writer)));
                recorder
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                    .unwrap();
                recorder.outcome(&sub.intent, &outcome).await;
                assert_eq!(fx.audit_kinds(), ["value_action_pending", settled_kind]);
                std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
                let (second, authorization) = grant(&fx, &sub, &[], "approval-2");

                let error = wallet_refusal(
                    recorder
                        .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization)),
                );

                assert_eq!(error.code(), "submission.tx_already_submitted");
                fx.assert_used_without_holds(first);
                assert!(fx.is_open(second), "the resend's grant stays open");
                assert_eq!(reservations(&fx), 0);
                assert!(receipt(&fx, &sub.intent).is_none());
                assert_eq!(
                    fx.audit_kinds(),
                    [
                        "value_action_pending",
                        settled_kind,
                        "value_action_pending",
                        "value_action_failed",
                    ],
                    "the resend adds one pending row and exactly one closing row"
                );
                assert!(matches!(
                    try_value_action_settlement(
                        &fx.profile.audit_log_path,
                        &sub.intent.envelope_hash
                    )
                    .unwrap(),
                    ValueActionSettlement::Settled
                ));
            }
        }

        /// A settlement read error removes only the receipt and preserves the
        /// open grant without appending a pending or closing row.
        #[tokio::test]
        #[serial]
        async fn a_settlement_lookup_error_takes_the_receipt_stage() {
            let mut fx = LedgerFixture::new("consume-settlement-error", NOW);
            let sub = submission();
            let (id, authorization) = grant(&fx, &sub, &[], "approval-1");
            let audit_path = fx.profile.audit_log_path.clone();
            let before = std::fs::read(&audit_path).unwrap();
            // A directory makes the reader fail while the writer remains usable.
            fx.profile.audit_log_path = fx.dir.path().to_path_buf();

            let error = wallet_refusal(
                fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization)),
            );

            assert_eq!(error.code(), "submission.record_unavailable");
            assert!(error.to_string().contains("audit settlement lookup failed"));
            assert!(fx.is_open(id));
            assert_eq!(reservations(&fx), 0);
            assert!(receipt(&fx, &sub.intent).is_none());
            assert_eq!(std::fs::read(audit_path).unwrap(), before);
        }

        /// The row-writing step acquires the writer guard before looking up an
        /// owed row, so a lock refusal wins over that row's duplicate refusal.
        #[test]
        #[serial]
        fn the_settlement_lookup_requires_the_writer_guard() {
            let fx = LedgerFixture::new("consume-settlement-guard", NOW);
            let sub = submission();
            let recorder = fx.recorder(vec![], Some(Arc::clone(&fx.writer)));
            fx.writer
                .lock()
                .unwrap()
                .write_entry(recorder.pending_entry(&sub.intent))
                .unwrap();
            let (error, reached) = recorder
                .write_pending_row_with_facts(&fx.writer, &sub.intent)
                .unwrap_err();
            assert_eq!(error.code(), "submission.tx_already_submitted");
            assert_eq!(reached, UnwoundAfter::Receipt);
            assert_eq!(fx.audit_kinds(), ["value_action_pending"]);

            let writer = Arc::clone(&fx.writer);
            assert!(
                std::thread::spawn(move || {
                    let _guard = writer.lock().unwrap();
                    panic!("poison the audit writer for the lock refusal");
                })
                .join()
                .is_err()
            );

            let (error, reached) = recorder
                .write_pending_row_with_facts(&fx.writer, &sub.intent)
                .unwrap_err();

            assert_eq!(error.code(), "submission.record_unavailable");
            assert!(error.to_string().contains("audit writer mutex is poisoned"));
            assert_eq!(reached, UnwoundAfter::Receipt);
            assert_eq!(fx.audit_kinds(), ["value_action_pending"]);
            assert!(matches!(
                try_value_action_settlement(&fx.profile.audit_log_path, &sub.intent.envelope_hash)
                    .unwrap(),
                ValueActionSettlement::Owed(_)
            ));
        }

        /// Fresh bytes and a fresh grant consume after a stateless receipt loss.
        #[tokio::test]
        #[serial]
        async fn stateless_fresh_bytes_consume_after_a_lost_receipt() {
            let fx = LedgerFixture::new("consume-stateless-fresh", NOW);
            let original = submission();
            let (first, authorization) = grant(&fx, &original, &[], "approval-1");
            fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&original.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            std::fs::remove_file(fx.receipts.file_path().unwrap()).unwrap();
            let fresh = rebuilt_submission();
            assert_ne!(original.intent.envelope_hash, fresh.intent.envelope_hash);
            let (second, authorization) = grant(&fx, &fresh, &[], "approval-2");
            fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                .consume_for_submission(&fresh.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            fx.assert_used_without_holds(first);
            fx.assert_used_without_holds(second);
            assert_eq!(reservations(&fx), 0);
            assert!(receipt(&fx, &fresh.intent).unwrap().submitted);
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending", "value_action_pending"]
            );
            assert!(matches!(
                try_value_action_settlement(
                    &fx.profile.audit_log_path,
                    &original.intent.envelope_hash
                )
                .unwrap(),
                ValueActionSettlement::Owed(_)
            ));
        }

        /// An uncovered tip for fresh bytes closes only that submission's row.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn an_uncovered_tip_closes_a_fresh_submissions_row() {
            let fx = LedgerFixture::new("consume-uncovered", NOW);
            let sub = submission();
            let (id, authorization) = grant(&fx, &sub, &[], "approval-1");
            let result = {
                let _uncovered = Toggle::set(&UNCOVERED_AUTHORIZED_TIP);
                fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
            };
            assert_eq!(refused(result), MainnetPrecondition::AuditNotAnchored);
            assert!(fx.is_open(id));
            assert!(receipt(&fx, &sub.intent).is_none());
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending", "value_action_failed"]
            );
        }

        /// A receipt that cannot be marked submitted after the consumption
        /// releases the converted holds and closes the row; the record stays
        /// used.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn a_failed_mark_submitted_releases_the_converted_holds() {
            let fx = LedgerFixture::new("consume-mark-submitted", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");

            let result = {
                let _fail = Toggle::set(&FAIL_MARK_SUBMITTED);
                fx.recorder(holds, Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
            };

            assert_eq!(
                wallet_refusal(result).code(),
                "submission.record_unavailable"
            );
            assert!(!fx.is_open(id), "the record stays used");
            assert_eq!(reservations(&fx), 0, "the converted holds are released");
            assert!(receipt(&fx, &sub.intent).is_none());
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending", "value_action_failed"]
            );
        }

        /// A receipt for the same source and sequence refuses the claim,
        /// before anything of this submission is written or consumed.
        #[tokio::test]
        #[serial]
        async fn a_duplicate_sequence_refuses_before_the_consumption() {
            let fx = LedgerFixture::new("consume-sequence", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");
            fx.receipts
                .begin_submission_with_approval(
                    &"cd".repeat(32),
                    &"ef".repeat(32),
                    &sub.intent.source,
                    sub.intent.sequence,
                    0,
                    100,
                    None,
                )
                .unwrap();

            let error = wallet_refusal(
                fx.recorder(holds, Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization)),
            );

            assert_eq!(error.code(), "submission.tx_already_submitted");
            assert!(fx.is_open(id), "the record stays open");
            assert_eq!(reservations(&fx), 0);
            assert!(fx.audit_kinds().is_empty());
        }

        /// Without an audit writer the grant is refused before the receipt,
        /// the row, or the consumption.
        #[tokio::test]
        #[serial]
        async fn a_missing_audit_writer_refuses_before_anything_is_recorded() {
            let fx = LedgerFixture::new("consume-no-writer", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");

            assert_eq!(
                refused(
                    fx.recorder(holds, None)
                        .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                ),
                MainnetPrecondition::AuditNotAnchored
            );
            assert!(fx.is_open(id));
            assert!(receipt(&fx, &sub.intent).is_none());
            assert!(fx.audit_kinds().is_empty());
        }

        /// A pending row the tip anchor does not cover, because its anchor
        /// write and the writer's repair of it fail, refuses before the
        /// consumption and closes the row; every hold stays with the open
        /// record.
        #[tokio::test]
        #[serial]
        async fn an_anchor_that_does_not_cover_the_row_refuses_before_the_consumption() {
            let fx = LedgerFixture::new("consume-anchor", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");
            fx.anchors.fail_next_writes(64);

            let error = wallet_refusal(
                fx.recorder(holds, Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization)),
            );
            assert_eq!(error.code(), "submission.record_unavailable");
            assert!(error.message().contains(AFTER_ROW_CONTEXT), "{error:?}");
            assert!(
                error.message().contains("audit.tip_anchor_unavailable"),
                "{error:?}"
            );
            assert!(fx.is_open(id), "the record stays open");
            assert_eq!(reservations(&fx), 0);
            assert!(receipt(&fx, &sub.intent).is_none());
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending", "value_action_failed"]
            );
        }

        /// A pending row that cannot be appended, behind an outbox row that
        /// does not parse, refuses before the consumption: no row exists, and
        /// the record stays open.
        #[tokio::test]
        #[serial]
        async fn a_pending_row_that_cannot_be_appended_refuses_before_the_consumption() {
            let fx = LedgerFixture::new("consume-append", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");
            let outbox = AuditOutbox::for_log(&fx.profile.audit_log_path);
            std::fs::write(outbox.path(), b"not an audit entry\n").unwrap();

            let error = wallet_refusal(
                fx.recorder(holds, Some(Arc::clone(&fx.writer)))
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization)),
            );

            assert_eq!(error.code(), "submission.record_unavailable");
            assert!(error.message().contains(APPEND_CONTEXT), "{error:?}");
            assert!(fx.is_open(id));
            assert!(receipt(&fx, &sub.intent).is_none());
            assert!(fx.audit_kinds().is_empty());
        }

        /// A pending row whose append fails while the writer still accepts
        /// the next row refuses at the receipt stage: no closing row is
        /// written for a row that never landed, while the closing-row path
        /// itself still appends.
        #[cfg(feature = "test-hooks")]
        #[tokio::test]
        #[serial]
        async fn a_pending_row_append_failure_takes_the_receipt_stage() {
            let fx = LedgerFixture::new("consume-append-transient", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");
            let recorder = fx.recorder(holds, Some(Arc::clone(&fx.writer)));

            let error = {
                let _fail = Toggle::set(&FAIL_PENDING_ROW_APPEND);
                wallet_refusal(
                    recorder
                        .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization)),
                )
            };

            assert_eq!(error.code(), "submission.record_unavailable");
            assert!(error.message().contains(APPEND_CONTEXT), "{error:?}");
            assert!(fx.is_open(id), "the record stays open");
            assert_eq!(reservations(&fx), 0);
            assert!(receipt(&fx, &sub.intent).is_none());
            assert!(
                fx.audit_kinds().is_empty(),
                "no closing row for a row that never landed"
            );
            recorder.write_failed_row(&sub.intent, error.code());
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_failed"],
                "the writer accepts the next row"
            );
        }

        #[tokio::test]
        #[serial]
        async fn authorized_branch_hashes_grant_entries() {
            let fx = LedgerFixture::new("consume-grant-entries", NOW);
            let sub = submission();
            let (id, mut authorization) = grant(&fx, &sub, &holds(&fx, 100), "approval-1");
            let recorder = WalletSubmissionRecorder::new_authorized(
                &fx.profile,
                fx.name.clone(),
                "stellar_pay_commit",
                Some("stellar:mainnet".into()),
                PolicyDecision::Allow,
                vec![],
                &authorization,
                fx.receipts.clone(),
                fx.window.clone(),
                Some(Arc::clone(&fx.writer)),
                None,
                "request",
                NOW,
            );
            authorization.0.entries = holds(&fx, 101);
            assert_eq!(
                refused(
                    recorder
                        .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                ),
                MainnetPrecondition::EntriesDigest
            );
            assert!(fx.is_open(id));
            assert_eq!(reservations(&fx), 0);
            assert!(receipt(&fx, &sub.intent).is_none());
        }

        #[tokio::test]
        #[serial]
        async fn authorized_recorder_settles_minted_holds() {
            for success in [true, false] {
                let fx = LedgerFixture::new("authorized-settle", NOW);
                let sub = submission();
                let (_, authorization) = grant(&fx, &sub, &holds(&fx, 100), "approval-1");
                let recorder = WalletSubmissionRecorder::new_authorized(
                    &fx.profile,
                    fx.name.clone(),
                    "stellar_pay_commit",
                    Some("stellar:mainnet".into()),
                    PolicyDecision::Allow,
                    vec![],
                    &authorization,
                    fx.receipts.clone(),
                    fx.window.clone(),
                    Some(Arc::clone(&fx.writer)),
                    None,
                    "request",
                    NOW,
                );
                assert!(!recorder.window_entries.is_empty());
                assert_eq!(recorder.window_entries, authorization.entries());
                recorder
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                    .unwrap();
                let outcome = if success {
                    SubmissionOutcome::Success {
                        ledger: 100,
                        created_at: Some(i64::try_from(NOW / 1000).unwrap()),
                    }
                } else {
                    SubmissionOutcome::Rejected {
                        code: "transaction.failed".into(),
                        error: "refused".into(),
                    }
                };
                recorder.outcome(&sub.intent, &outcome).await;
                assert_eq!(reservations(&fx), 0);
                let bytes = std::fs::read(fx.dir.path().join("state.window")).unwrap();
                let wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
                assert_eq!(
                    wire["entries"].as_array().map_or(0, Vec::len),
                    usize::from(success)
                );
            }
        }

        /// A definitive refusal of the send releases the converted window
        /// records, leaves the authorization used, closes the pending row with
        /// a failed row, and releases the receipt's hold on the approval.
        #[tokio::test]
        #[serial]
        async fn a_definitive_rejection_releases_the_converted_rows() {
            let fx = LedgerFixture::new("authorized-rejected", NOW);
            let sub = submission();
            let (id, authorization) = grant(&fx, &sub, &holds(&fx, 100), "approval-1");
            let recorder = WalletSubmissionRecorder::new_authorized(
                &fx.profile,
                fx.name.clone(),
                "stellar_pay_commit",
                Some("stellar:mainnet".into()),
                PolicyDecision::RequireApproval,
                vec![],
                &authorization,
                fx.receipts.clone(),
                fx.window.clone(),
                Some(Arc::clone(&fx.writer)),
                None,
                "request",
                NOW,
            )
            .with_approval(Some(ApprovalTombstone {
                store_dir: fx.dir.path().join("approvals"),
                profile_name: fx.name.clone(),
                approval_nonce: "approval-nonce-1".into(),
            }));
            recorder
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            assert_eq!(reservations(&fx), 1);
            assert!(
                fx.receipts
                    .find_by_approval_nonce("approval-nonce-1")
                    .unwrap()
                    .is_some()
            );
            recorder
                .outcome(
                    &sub.intent,
                    &SubmissionOutcome::Rejected {
                        code: "transaction.failed".into(),
                        error: "refused".into(),
                    },
                )
                .await;
            assert_eq!(reservations(&fx), 0);
            let bytes = std::fs::read(fx.dir.path().join("state.window")).unwrap();
            let wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
            assert!(
                wire["entries"].as_array().is_none_or(Vec::is_empty),
                "the converted records are released: {wire}"
            );
            assert!(!fx.is_open(id), "the used authorization is not reopened");
            assert!(
                fx.receipts
                    .find_by_approval_nonce("approval-nonce-1")
                    .unwrap()
                    .is_none(),
                "the refused send releases the approval"
            );
            assert_eq!(
                fx.audit_kinds(),
                ["value_action_pending", "value_action_failed"]
            );
        }

        #[tokio::test]
        #[serial]
        async fn used_authorization_is_not_consumed_twice() {
            for has_holds in [true, false] {
                let fx = LedgerFixture::new("used-once", NOW);
                let sub = submission();
                let entries = if has_holds { holds(&fx, 100) } else { vec![] };
                let (_, authorization) = grant(&fx, &sub, &entries, "approval-1");
                let id = authorization.id();
                let tx_hash = decode_intent_hash(&sub.intent.tx_hash).unwrap();
                let expect = authorization.consume_expect(&RecomputedFacts {
                    content_digest: crate::mainnet::digest::content_digest(
                        AuthorizationDomain::Transaction,
                        &tx_hash,
                    ),
                    entries_digest: crate::mainnet::digest::entries_digest(authorization.entries()),
                    audit: covered_audit_facts(tip_facts(&fx.writer)).unwrap(),
                });
                let mut binding = SubmissionBinding {
                    fee_bump: None,
                    envelope_hash: decode_intent_hash(&sub.intent.envelope_hash).unwrap(),
                    tx_hash,
                    source: sub.intent.source.clone(),
                    sequence: sub.intent.sequence,
                    max_time: sub.intent.max_time,
                    pending_since_ms: NOW,
                    submission_ledger: sub.intent.submission_ledger,
                };
                let recorder = WalletSubmissionRecorder::new_authorized(
                    &fx.profile,
                    fx.name.clone(),
                    "stellar_pay_commit",
                    Some("stellar:mainnet".into()),
                    PolicyDecision::Allow,
                    vec![],
                    &authorization,
                    fx.receipts.clone(),
                    fx.window.clone(),
                    Some(Arc::clone(&fx.writer)),
                    None,
                    "request",
                    NOW,
                );
                recorder
                    .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                    .unwrap();
                let before = std::fs::read(fx.dir.path().join("state.window")).unwrap();
                let error = fx
                    .window
                    .consume_authorization(
                        &fx.profile,
                        id,
                        &expect,
                        &ConsumptionBinding::Transaction(binding.clone()),
                    )
                    .unwrap_err();
                assert!(
                    matches!(
                        (&error, has_holds),
                        (WindowStoreError::DuplicateReservation, true)
                            | (WindowStoreError::DuplicateConsumption, false)
                    ),
                    "{error:?}"
                );
                binding.envelope_hash = [9; 32];
                assert!(matches!(
                    fx.window.consume_authorization(
                        &fx.profile,
                        id,
                        &expect,
                        &ConsumptionBinding::Transaction(binding)
                    ),
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::NotOpen
                    })
                ));
                assert_eq!(
                    std::fs::read(fx.dir.path().join("state.window")).unwrap(),
                    before
                );
                fx.assert_used_without_holds(id);
            }
        }

        /// The audit facts of a writer over another log are refused.
        #[tokio::test]
        #[serial]
        async fn audit_facts_of_another_log_are_refused() {
            let fx = LedgerFixture::new("consume-other-log", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let (id, authorization) = grant(&fx, &sub, &holds, "approval-1");
            let (other, _anchors) = keyed_writer(&fx.dir.path().join("other.jsonl"));

            assert_eq!(
                refused(
                    fx.recorder(holds, Some(other))
                        .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                ),
                MainnetPrecondition::AuditLogPath
            );
            assert!(fx.is_open(id));
            assert_eq!(reservations(&fx), 0);
        }

        /// An authorization whose audit proof names another segment of the
        /// log than the recorder's writer is refused.
        #[tokio::test]
        #[serial]
        async fn audit_facts_of_another_segment_are_refused() {
            let fx = LedgerFixture::new("consume-other-segment", NOW);
            let sub = submission();
            let holds = holds(&fx, 100);
            let mut facts = tip_facts(&fx.writer);
            facts.segment_start_hash[0] ^= 0x01;
            let authorization =
                fx.mint_with_facts(sub.binding.clone(), &holds, None, "approval-1", facts);
            let id = authorization.id();

            assert_eq!(
                refused(
                    fx.recorder(holds, Some(Arc::clone(&fx.writer)))
                        .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                ),
                MainnetPrecondition::AuditSegment
            );
            assert!(fx.is_open(id));
        }
    }
}
