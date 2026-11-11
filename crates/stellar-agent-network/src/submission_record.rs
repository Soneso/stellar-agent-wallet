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
//! [`SubmissionRecorder::outcome`] runs at every exit after the send. A
//! reported success is recorded on the receipt and in the reservation, which
//! keeps counting through its accounting horizon. A reported failure, a
//! refused send, a transport failure and a poll timeout leave the receipt, the
//! pending row and the reservation standing. Every sent outcome consumes the
//! approval nonce. A reservation ends at its accounting horizon or, without an
//! execution bound, at an operator clear.
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
//! that reservation, reconciliation has no record left to reconcile it by.
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
    ConsumptionBinding, ConsumptionExposure, ExposureIdentity, OperationId, OperationRecorder,
    OperationResult, OperationState, PersistedWindowStore, SubmissionBinding, SubmissionHold,
    TransitionEvidence, WindowStoreError,
};
use crate::sequence_floor::SequenceFloorHook;
use crate::submit::{MainnetSubmitGrant, redact_tx_hash};
use stellar_agent_core::observability::redact::redact_strkey_first5_last5 as redact_account;

/// A pending-writer boundary observer for lock-discipline tests.
#[cfg(feature = "test-hooks")]
pub type PendingWriterHook = Arc<dyn Fn(&Profile, &PersistedWindowStore) + Send + Sync>;

#[cfg(feature = "test-hooks")]
static PENDING_WRITER_HOOK: Mutex<Option<PendingWriterHook>> = Mutex::new(None);

/// Restores the pending-writer observer when the fixture ends.
#[cfg(feature = "test-hooks")]
#[must_use]
pub struct PendingWriterHookGuard(Option<PendingWriterHook>);

#[cfg(feature = "test-hooks")]
impl Drop for PendingWriterHookGuard {
    fn drop(&mut self) {
        *PENDING_WRITER_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = self.0.take();
    }
}

/// Installs an observer immediately before pending-row writer acquisition.
#[cfg(feature = "test-hooks")]
pub fn observe_pending_writer_for_test(hook: PendingWriterHook) -> PendingWriterHookGuard {
    PendingWriterHookGuard(
        PENDING_WRITER_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(hook),
    )
}

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
    /// The network for envelope hashing and validation.
    pub chain_scope: crate::policy_state::ChainScope,
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
    /// Independent provenance bound to this submission.
    pub submission_anchor: Option<crate::policy_state::SubmissionAnchor>,

    /// The instant after which no `sendTransaction` attempt of this
    /// submission starts, in Unix milliseconds on the clock of
    /// [`crate::mainnet::clock::now_ms`]; `None` when the attempt has no
    /// send-by instant.
    ///
    /// A mainnet submission derives it from the envelope's `maxTime` less the
    /// send margin. Another submission carries the send-by instant its caller
    /// passed, converted at the moment the intent is built.
    pub send_by_ms: Option<u64>,
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
    /// The endpoint reports inclusion in ledger `ledger`.
    Success {
        /// The ledger sequence the transaction confirmed in.
        ledger: u32,
        /// Close time of the applying ledger, in unix seconds.
        created_at: Option<i64>,
    },

    /// An endpoint reports failure. Possible spending remains reserved.
    OnChainFailed {
        /// Stable wire code for the failure, from the same XDR mapping the
        /// returned error uses.
        code: String,
    },

    /// The endpoint refuses exposed bytes. The observation authorizes no refund.
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
    /// that stops answering the confirmation poll, an endpoint whose
    /// reported transaction hash does not describe the transaction that was
    /// sent, and on mainnet a negative answer no independent witness
    /// confirms: a send refusal, and a `FAILED` confirmation the oracle does
    /// not report as `FAILED` itself.
    TransportAfterSend {
        /// Non-secret diagnostic detail naming the condition.
        error: String,
    },

    /// No `sendTransaction` attempt started: the send-by instant passed after
    /// the pre-send record and before the first attempt. The bytes never left
    /// the wallet, so the transaction cannot apply.
    ///
    /// Reported only for a submission without a bound signed intent.
    NotSent {
        /// Stable wire code of the refusal the caller receives.
        code: String,
        /// Non-secret diagnostic detail naming the condition.
        error: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// SubmissionRecorder
// ─────────────────────────────────────────────────────────────────────────────

/// The seam through which the submit layer records a submission.
///
/// Object-safe. A smart-account signing flow admits its intent through
/// [`Self::admit_signed_intent`] before its first signature and binds its final
/// envelope through [`Self::pre_send_bound`]. Another call site with nothing
/// to record passes `None`.
#[async_trait::async_trait]
pub trait SubmissionRecorder: Send + Sync {
    /// Admits all authority before its first signature.
    ///
    /// # Errors
    /// Refuses when this recorder does not support intent admission.
    async fn admit_signed_intent(
        &self,
        _plan: &crate::SignedIntentPlan,
    ) -> Result<crate::IntentProof, WalletError> {
        Err(crate::signed_intent::unavailable("unsupported_recorder"))
    }

    /// Cancels an admission whose proof remains unconsumed.
    ///
    /// # Errors
    /// Refuses when this recorder does not support intent cancellation.
    async fn cancel_unexposed(&self, _proof: crate::IntentProof) -> Result<(), WalletError> {
        Err(crate::signed_intent::unavailable("unsupported_recorder"))
    }

    /// Binds the final envelope before recording its submission.
    ///
    /// # Errors
    /// Refuses when this recorder does not support intent binding.
    async fn pre_send_bound(
        &self,
        _intent: &SubmissionIntent,
        _binding: &crate::IntentBinding<'_>,
    ) -> Result<(), WalletError> {
        Err(crate::signed_intent::unavailable("unsupported_recorder"))
    }

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
    /// Runs at every exit after the pre-send record: after the send, and with
    /// [`SubmissionOutcome::NotSent`] when no send attempt started. It cannot
    /// fail the caller: a sent transaction is already beyond recall, so a
    /// failure here is logged and the record stands.
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

/// The operation attempt a submission advances: the record and the attempt
/// that `begin_attempt` opened before the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationAttempt {
    /// The operation the submission serves.
    pub operation_id: OperationId,
    /// The attempt the submission sends, starting at 1.
    pub attempt_index: u32,
}

/// How an operation attempt ends at the submitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttemptEnd {
    /// No send of the attempt's payload started; `code` names the refusal.
    NotSent {
        /// The wire code of the refusal that stopped the attempt.
        code: String,
    },
    /// The payload was exposed and may have reached the network.
    SentOutcomeUnknown {
        /// The network transaction hash, when the payload is a transaction.
        tx_hash: Option<[u8; 32]>,
    },
}

/// Records the end of `attempt` in the operation store of `profile`.
///
/// A `NotSent` end proves that no send started, so the attempt's
/// authorization gets its `Always` release row of class `proved_unspent` in
/// the same commit, also after a committed exposure. A `SentOutcomeUnknown`
/// end needs the attempt's committed exposure. A repeated end in the same
/// state writes nothing.
///
/// The writer lock is taken before the window lock.
///
/// # Errors
///
/// The operation store's refusals, rendered as
/// [`crate::operation_entry::operation_refusal`] renders them, and
/// `submission.record_unavailable` for a poisoned writer.
pub fn end_operation_attempt(
    window: &PersistedWindowStore,
    profile: &Profile,
    writer: &AuditWriterHandle,
    request_id: &str,
    attempt: OperationAttempt,
    end: &AttemptEnd,
) -> Result<(), WalletError> {
    let (to, evidence) = match end {
        AttemptEnd::NotSent { code } => (
            OperationState::NotSent,
            TransitionEvidence {
                result: Some(OperationResult {
                    error_code: Some(code.clone()),
                    ..OperationResult::default()
                }),
                send_never_started: true,
                ..TransitionEvidence::default()
            },
        ),
        AttemptEnd::SentOutcomeUnknown { tx_hash } => (
            OperationState::SentOutcomeUnknown,
            TransitionEvidence {
                result: Some(OperationResult {
                    tx_hash: *tx_hash,
                    ..OperationResult::default()
                }),
                ..TransitionEvidence::default()
            },
        ),
    };
    let mut guard = lock_audit(writer)?;
    OperationRecorder::new(window, profile, &mut *guard, request_id)
        .transition(
            attempt.operation_id,
            Some(attempt.attempt_index),
            to,
            &evidence,
        )
        .map(|_| ())
        .map_err(crate::operation_entry::operation_refusal)
}

/// Everything the wallet's recorder needs that the submit layer does not know.
///
/// Built by the verb that is about to submit. The optional halves are the
/// parts only one binary has: the sequence floor is process-local state the
/// MCP server owns, and the approval entry exists only on a commit path that
/// presented one.
pub struct WalletSubmissionRecorder<'a> {
    signing_sizing: Option<stellar_agent_core::policy::v1::CheckedSizing>,
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
    provenance: Option<stellar_agent_core::mainnet::decision::MainnetProvenance>,
    operation: Option<OperationAttempt>,
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
            .field("has_provenance", &self.provenance.is_some())
            .field("operation", &self.operation)
            .finish()
    }
}

impl<'a> WalletSubmissionRecorder<'a> {
    /// Attaches the policy engine's checked sizing for signing admission.
    #[must_use]
    pub fn with_signing_sizing(
        mut self,
        sizing: stellar_agent_core::policy::v1::CheckedSizing,
    ) -> Self {
        self.signing_sizing = Some(sizing);
        self
    }

    /// Carries a completed oracle comparison into the pending audit row.
    #[must_use]
    pub fn with_witness(mut self, witness: Option<&crate::cross_check::CrossCheckWitness>) -> Self {
        self.witness = witness.map(crate::cross_check::CrossCheckWitness::record);
        self
    }

    /// Carries the mainnet policy provenance into the pending audit row: the
    /// policy digest and the deciding rule's index.
    #[must_use]
    pub fn with_provenance(
        mut self,
        provenance: stellar_agent_core::mainnet::decision::MainnetProvenance,
    ) -> Self {
        self.provenance = Some(provenance);
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
            signing_sizing: None,
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
            witness: None,
            provenance: None,
            operation: None,
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

    /// Attaches the operation attempt this submission sends.
    ///
    /// The consumption of the grant then commits the attempt's exposure in its
    /// own commit. Every end of the submission ends the attempt: `NotSent`
    /// where no send started, `SentOutcomeUnknown` after the send.
    #[must_use]
    pub fn with_operation(mut self, operation: Option<OperationAttempt>) -> Self {
        self.operation = operation;
        self
    }

    /// Ends the operation attempt as `NotSent` for a submission the submit
    /// layer refused before any pre-send record. Without an operation
    /// attempt or an audit writer it does nothing.
    pub fn end_unsent_attempt(&self, code: &str) {
        self.end_attempt(&AttemptEnd::NotSent {
            code: code.to_owned(),
        });
    }

    /// Records `end` for the recorder's operation attempt. The submission's
    /// own result stands either way, so a failure is logged; the attempt
    /// then stays `Sending` until recovery reads it.
    fn end_attempt(&self, end: &AttemptEnd) {
        let (Some(attempt), Some(writer)) = (self.operation, self.audit.as_ref()) else {
            return;
        };
        if let Err(error) = end_operation_attempt(
            &self.window,
            self.profile,
            writer,
            &self.request_id,
            attempt,
            end,
        ) {
            tracing::warn!(
                profile = %self.profile_name,
                tool = %self.tool,
                code = error.code(),
                "submission record: the operation attempt's end was not recorded; it stays \
                 sending until recovery reads it"
            );
        }
    }

    fn reservation(&self, intent: &SubmissionIntent) -> SubmissionHold {
        SubmissionHold {
            chain_scope: intent.chain_scope,
            id: intent.envelope_hash.clone(),
            tx_hash: intent.tx_hash.clone(),
            source: intent.source.clone(),
            sequence: intent.sequence,
            max_time: intent.max_time,
            pending_since_ms: self.now_ms,
            submission_ledger: intent.submission_ledger,
            submission_anchor: intent.submission_anchor.clone(),
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
        #[cfg(feature = "test-hooks")]
        {
            let hook = PENDING_WRITER_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(hook) = hook {
                hook(self.profile, &self.window);
            }
        }
        let mut guard = lock_audit(writer)?;
        guard
            .write_entry(self.pending_entry(intent))
            .map_err(|error| self.audit_refusal(error, APPEND_CONTEXT))?;
        Ok(match guard.require_anchor_current() {
            Ok(()) => AnchorAfterRow::Current,
            Err(error) => AnchorAfterRow::Behind(self.audit_refusal(error, AFTER_ROW_CONTEXT)),
        })
    }

    /// The pending value-action row of a submission, with the recorder's
    /// policy provenance when it carries one.
    fn pending_entry(&self, intent: &SubmissionIntent) -> AuditEntry {
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
        match &self.provenance {
            Some(provenance) => entry.with_provenance(provenance),
            None => entry,
        }
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
/// The receipt holds the nonce durably, and every sent outcome consumes it,
/// a refused send included. A failed approval write or acknowledgement leaves
/// a retryable consumption repair for the next status call, and the commit
/// gate continues to refuse reuse.
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
    async fn admit_signed_intent(
        &self,
        plan: &crate::SignedIntentPlan,
    ) -> Result<crate::IntentProof, WalletError> {
        let sizing = self
            .signing_sizing
            .as_ref()
            .filter(|sizing| sizing.entries() == self.window_entries)
            .ok_or_else(|| crate::signed_intent::unavailable("sizing_unverified"))?;
        crate::signed_intent::admit_checked(self.profile, &self.window, sizing, plan)
    }

    async fn cancel_unexposed(&self, proof: crate::IntentProof) -> Result<(), WalletError> {
        if proof.intent_id.is_none() {
            return Ok(());
        }
        self.window
            .cancel_signed_intent(self.profile, proof)
            .map_err(crate::signed_intent::store_refusal)
    }

    async fn pre_send_bound(
        &self,
        intent: &SubmissionIntent,
        binding: &crate::IntentBinding<'_>,
    ) -> Result<(), WalletError> {
        let Some(id) = binding.exposure.intent_id() else {
            return self.pre_send(intent).await;
        };
        self.require_submission_scope(intent)
            .map_err(crate::signed_intent::store_refusal)?;
        self.require_anchor_before_row()?;
        let facts = crate::BindFacts::from_envelope(
            binding.envelope,
            intent.chain_scope.chain().network_passphrase(),
        )
        .map_err(crate::signed_intent::mismatch)?;
        if facts.envelope_hash != intent.envelope_hash || facts.tx_hash != intent.tx_hash {
            return Err(crate::signed_intent::mismatch("envelope"));
        }
        self.window
            .bind_signed_intent(self.profile, id, &facts, &self.window_entries)
            .map_err(crate::signed_intent::store_refusal)?;
        self.pre_send_inner(intent, Some(id))
    }

    async fn pre_send(&self, intent: &SubmissionIntent) -> Result<(), WalletError> {
        self.pre_send_inner(intent, None)
    }

    async fn pre_send_authorized(
        &self,
        intent: &SubmissionIntent,
        grant: MainnetSubmitGrant,
    ) -> Result<AuthorizationConsumed, WalletError> {
        self.consume_for_submission(intent, grant)
            .map_err(|error| error.report("pre_send_authorized"))
            .inspect_err(|error| self.end_unsent_attempt(error.code()))
    }

    async fn outcome(&self, intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        if let Err(error) = self.require_submission_scope(intent) {
            tracing::warn!(profile = %self.profile_name, tool = %self.tool, ?error,
                "submission record: outcome not recorded; the receipt and reservation stand until reconciliation");
            return;
        }
        match outcome {
            SubmissionOutcome::Success { ledger, created_at } => {
                self.end_sent_attempt(intent);
                self.finalize_receipt(intent, ReceiptStatus::Success, Some(*ledger));
                self.settle_window(intent, WindowSettlement::Confirm(*created_at));
                self.record_floor(intent).await;
                self.tombstone_approval(intent);
            }
            SubmissionOutcome::OnChainFailed { .. }
            | SubmissionOutcome::Rejected { .. }
            | SubmissionOutcome::Timeout { .. }
            | SubmissionOutcome::TransportAfterSend { .. } => {
                // The transaction may still apply. The receipt, the pending
                // audit row and the reservation all stand. The reservation
                // ends at its accounting horizon or, without an execution
                // bound, at an operator clear.
                self.end_sent_attempt(intent);
                self.record_floor(intent).await;
                self.tombstone_approval(intent);
            }
            SubmissionOutcome::NotSent { code, .. } => {
                // No attempt carried the bytes, so nothing can apply: the
                // sequence is not consumed and no floor is recorded, and the
                // approval stays unspent. The window records are released,
                // converted mainnet holds included, the pending row is closed
                // with `code`, and the receipt that holds the sequence is
                // removed. A used mainnet authorization stays used.
                self.end_unsent_attempt(code);
                self.close_unsent_records(intent, UnwoundAfter::Reservation, code);
                self.remove_receipt(intent, ReceiptStore::abandon_unsent);
            }
        }
    }
}

impl WalletSubmissionRecorder<'_> {
    /// Ends the operation attempt of a sent submission as
    /// `SentOutcomeUnknown` with its transaction hash: only the recovery
    /// passes settle what the network did with the bytes.
    fn end_sent_attempt(&self, intent: &SubmissionIntent) {
        self.end_attempt(&AttemptEnd::SentOutcomeUnknown {
            tx_hash: stellar_agent_core::hex::decode_hex32(&intent.tx_hash).ok(),
        });
    }
}

impl WalletSubmissionRecorder<'_> {
    fn pre_send_inner(
        &self,
        intent: &SubmissionIntent,
        linked: Option<&str>,
    ) -> Result<(), WalletError> {
        self.require_submission_scope(intent)
            .map_err(|error| reservation_refusal(error, intent))?;
        // The audit tip anchor precedes the receipt, row, and reservation.
        // A refusal here has nothing to undo.
        self.require_anchor_before_row()?;

        self.claim_receipt(intent)?;
        // The unauthorized path checks reservations only when it sizes entries.
        if !self.window_entries.is_empty() {
            self.window_precheck(intent, linked.is_some())?;
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
            let recorded = match linked {
                Some(id) => self.window.record_pending_linked(
                    self.profile,
                    &self.window_entries,
                    &self.reservation(intent),
                    id,
                ),
                None => self.window.record_pending(
                    self.profile,
                    &self.window_entries,
                    &self.reservation(intent),
                ),
            };
            if let Err(e) = recorded {
                // A duplicate found under the lock is a resend of bytes another
                // process reserved between the check above and this write. The
                // pending row just written names the same envelope hash as that
                // submission's and stays open with it. Every other refusal
                // attempts to close the row, even if the duplicate check did
                // not run, whatever the anchor check found.
                let reached = match e {
                    WindowStoreError::DuplicateReservation => UnwoundAfter::Receipt,
                    _ => UnwoundAfter::PendingRow,
                };
                let refusal = signing_reservation_refusal(e, intent, linked.is_some());
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
}

/// Reports a refused signed intent write through the intent error,
/// keeping a duplicate reservation as a resubmission.
fn signing_reservation_refusal(
    error: WindowStoreError,
    intent: &SubmissionIntent,
    signed_intent: bool,
) -> WalletError {
    if signed_intent && !matches!(error, WindowStoreError::DuplicateReservation) {
        crate::signed_intent::store_refusal(error)
    } else {
        reservation_refusal(error, intent)
    }
}

/// Turns a refused reservation write into the error the caller reports.
///
/// A bucket that cannot admit the spend is a policy denial, reported
/// under the wire code the gate reports for the same reason and carrying the
/// same typed reason. A window that already holds these bytes is a
/// resubmission, reported as `submission.tx_already_submitted` with the
/// transaction to reconcile. Every other refusal is a record the wallet could
/// not write, which is what `submission.record_unavailable` names. All of
/// them refuse the send.
fn reservation_refusal(error: WindowStoreError, intent: &SubmissionIntent) -> WalletError {
    if let Some(error) = error.chain_validation_error() {
        return WalletError::Validation(error);
    }
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

    /// Requires the envelope's network to agree with this submission's accounting.
    ///
    /// Window entries debit the authenticated store, so the comparison reads
    /// it. Without entries the submission debits nothing. The admission creates
    /// the window directory and its lock file. It reads the generation entry of
    /// the registered keyring store to detect a deleted window file. With no
    /// window state on disk, an admission without entries writes no accounting
    /// state. With window state on disk, it may advance or prune retained
    /// intents, which writes the file and the generation entry. The envelope
    /// answers to the profile alone.
    fn require_submission_scope(&self, intent: &SubmissionIntent) -> Result<(), WindowStoreError> {
        if self.window_entries.is_empty() {
            return intent.chain_scope.require_profile(self.profile);
        }
        self.window
            .require_chain_scope(self.profile, &intent.chain_scope)
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
    fn window_precheck(
        &self,
        intent: &SubmissionIntent,
        signed_intent: bool,
    ) -> Result<(), WalletError> {
        if !window_precheck_enabled() {
            return Ok(());
        }
        let refusal = match self
            .window
            .holds_reservation(self.profile, &intent.envelope_hash)
        {
            Ok(false) => return Ok(()),
            Ok(true) => already_submitted(intent),
            Err(e) => signing_reservation_refusal(e, intent, signed_intent),
        };
        self.unwind(intent, UnwoundAfter::Receipt, refusal.code());
        Err(refusal)
    }

    /// Refuses bytes whose original pending row still owes settlement.
    ///
    /// The receipt can be lost even when the original policy had no window
    /// entries. The audit row preserves ownership in that case. The lookup
    /// reads through `writer`, the guard the caller holds through this lookup,
    /// the append, and the fresh tip read, so it sees only rows up to the
    /// writer's verified tip. A read error fails closed; neither refusal
    /// writes a closing row.
    fn settlement_precheck(
        &self,
        writer: &AuditWriter,
        intent: &SubmissionIntent,
    ) -> Result<(), WalletError> {
        #[cfg(feature = "test-hooks")]
        if SKIP_SETTLEMENT_PRECHECK.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let refusal = match try_value_action_settlement(writer, &intent.envelope_hash) {
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
        self.window
            .require_chain_scope(self.profile, &intent.chain_scope)
            .map_err(|error| reservation_refusal(error, intent))?;
        self.require_anchor_before_row()?;
        self.claim_receipt(intent)?;
        self.window_precheck(intent, false)?;

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
            chain_scope: Some(intent.chain_scope),
            fee_bump: None,
            envelope_hash,
            tx_hash,
            source: intent.source.clone(),
            sequence: intent.sequence,
            max_time: intent.max_time,
            pending_since_ms: self.now_ms,
            submission_ledger: intent.submission_ledger,
            submission_anchor: intent.submission_anchor.clone().map(Box::new),
        });
        let authorization_id = authorization.id();
        let consumed = match self.operation {
            Some(attempt) => {
                let mut guard = match lock_audit(writer) {
                    Ok(guard) => guard,
                    Err(error) => {
                        self.unwind(intent, UnwoundAfter::PendingRow, error.code());
                        return Err(AuthorizedPathError::Wallet(error));
                    }
                };
                self.window.consume_authorization_exposing(
                    self.profile,
                    authorization_id,
                    &expect,
                    &binding,
                    ConsumptionExposure {
                        operation_id: attempt.operation_id,
                        attempt_index: attempt.attempt_index,
                        identity: ExposureIdentity::Classic {
                            envelope_sha256: envelope_hash,
                            tx_hash,
                            sequence: intent.sequence,
                            max_time: intent.max_time,
                            receipt: intent.envelope_hash.clone(),
                        },
                        audit: &mut *guard,
                        request_id: &self.request_id,
                    },
                )
            }
            None => {
                self.window
                    .consume_authorization(self.profile, authorization_id, &expect, &binding)
            }
        };
        if let Err(e) = consumed {
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
        self.settlement_precheck(&guard, intent)
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
        self.end_unsent_attempt(code);
        self.close_unsent_records(intent, reached, code);
        self.remove_receipt(intent, ReceiptStore::abandon_pre_submit);
    }

    /// The release and the closing row of [`Self::unwind`], for the stages
    /// `reached` names.
    fn close_unsent_records(&self, intent: &SubmissionIntent, reached: UnwoundAfter, code: &str) {
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
    }

    /// Removes the receipt of an unsent submission through `abandon`, which
    /// decides which receipt states it removes.
    fn remove_receipt(
        &self,
        intent: &SubmissionIntent,
        abandon: fn(&ReceiptStore, &str) -> Result<(), ReceiptStoreError>,
    ) {
        if let Err(e) = abandon(&self.receipts, &intent.envelope_hash) {
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
            WindowSettlement::Release => self
                .window
                .pre_exposure_cancellation(self.profile, &intent.envelope_hash)
                .and_then(|decision| {
                    self.window
                        .apply_accounting_decision(self.profile, decision)
                        .map(|_| ())
                }),
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

    #[tokio::test]
    #[serial_test::serial]
    async fn bound_mismatch_refuses_at_gate_and_bind() {
        use crate::signed_intent::test_helpers::intent_fixture_kind;
        use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
        use stellar_agent_core::profile::caip2::Caip2;
        use stellar_xdr::{LedgerBounds, Preconditions, PreconditionsV2, TransactionEnvelope};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet_named(
            "intent",
            "bound-recorder",
            "account",
            "bound-recorder-nonce",
            "account",
        )
        .build();
        let window = PersistedWindowStore::at_path(dir.path().join("intent.window"));
        let (fixture, mut envelope) = intent_fixture_kind(2);
        let plan = fixture.with_envelope_max_ledger(50).unwrap();
        let set_bound = |envelope: &mut TransactionEnvelope, maximum: Option<u32>| {
            let TransactionEnvelope::Tx(tx) = envelope else {
                unreachable!()
            };
            tx.tx.cond = Preconditions::V2(PreconditionsV2 {
                time_bounds: None,
                ledger_bounds: maximum.map(|max_ledger| LedgerBounds {
                    min_ledger: 0,
                    max_ledger,
                }),
                min_seq_num: None,
                min_seq_age: stellar_xdr::Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: Default::default(),
            });
        };
        set_bound(&mut envelope, Some(50));
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "intent",
            "test",
            Some("stellar:testnet".into()),
            PolicyDecision::Allow,
            vec![],
            plan.legs().to_vec(),
            ReceiptStore::open_at(dir.path(), "intent").unwrap(),
            window.clone(),
            None,
            None,
            "fixture",
            1000,
        )
        .with_signing_sizing(
            CheckedSizing::for_test(SizingBasis::MeasuredValue, plan.legs().to_vec()).unwrap(),
        );
        let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
        let exposure = recorder.admit_signed_intent(&plan).await.unwrap().expose();
        let before = std::fs::read(window.path()).unwrap();
        let before_views =
            serde_json::to_value(window.signed_intents("intent", &profile).unwrap()).unwrap();
        for maximum in [None, Some(0), Some(49), Some(51)] {
            let mut changed = envelope.clone();
            set_bound(&mut changed, maximum);
            let facts =
                crate::BindFacts::from_envelope(&changed, Caip2::Testnet.network_passphrase())
                    .unwrap_or_else(|_| {
                        crate::BindFacts::from_envelope(
                            &envelope,
                            Caip2::Testnet.network_passphrase(),
                        )
                        .unwrap()
                    });
            let (source, sequence) = crate::submit::replay_identity(&changed).unwrap();
            let intent = SubmissionIntent {
                chain_scope: crate::policy_state::ChainScope::for_chain(Caip2::Testnet),
                envelope_hash: facts.envelope_hash,
                tx_hash: facts.tx_hash,
                source,
                sequence,
                max_time: 0,
                submission_ledger: 1,
                submission_anchor: None,
                send_by_ms: None,
            };
            let binding = crate::IntentBinding::new(&exposure, &changed);
            let error = recorder
                .pre_send_bound(&intent, &binding)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    WalletError::Submission(SubmissionError::IntentBindingMismatch {
                        field: "expiration"
                    })
                ),
                "{maximum:?}: {error:?}"
            );
            assert_eq!(std::fs::read(window.path()).unwrap(), before);
            assert_eq!(
                serde_json::to_value(window.signed_intents("intent", &profile).unwrap()).unwrap(),
                before_views
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn entryless_admission_commits_progress() {
        use crate::policy_state::ChainScope;
        use crate::signing::ledger_witness::LedgerWitnessCapability;
        use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
        use stellar_agent_core::profile::caip2::Caip2;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile =
            Profile::builder_testnet_named("intent", "entryless", "account", "nonce", "account")
                .build();
        std::fs::write(dir.path().join("intent.toml"), "chain_id = \"stellar:testnet\"\nrpc_url = \"https://primary.example/rpc\"\nsecondary_rpc_url = \"https://secondary.example/rpc\"\n").unwrap();
        let window = PersistedWindowStore::at_path(dir.path().join("intent.window"))
            .with_profile_directory("intent", dir.path().to_owned());
        let receipts = ReceiptStore::open_at(dir.path(), "intent").unwrap();
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "intent",
            "fixture",
            Some("stellar:testnet".into()),
            PolicyDecision::Allow,
            vec![],
            vec![],
            receipts,
            window.clone(),
            None,
            None,
            "fixture",
            1000,
        )
        .with_signing_sizing(
            CheckedSizing::for_test(SizingBasis::NoApplicableLimit, vec![]).unwrap(),
        );
        let (mut plan, envelope) = crate::signed_intent::test_helpers::intent_fixture_plan(1, 60);
        let stellar_xdr::TransactionEnvelope::Tx(tx) = &envelope else {
            unreachable!()
        };
        let stellar_xdr::OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
            unreachable!()
        };
        plan = plan
            .classify_purpose(&op.host_function, None)
            .unwrap()
            .with_envelope_max_ledger(100)
            .unwrap();
        let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
        let _proof = recorder.admit_signed_intent(&plan).await.unwrap();
        assert!(!window.path().exists());
        let _exposure = window
            .admit_signed_intent(&profile, &plan)
            .unwrap()
            .expose();
        clock.set(2000);
        let instant = tokio::time::Instant::now();
        let witness = LedgerWitnessCapability::for_test(
            ChainScope::for_chain(Caip2::Testnet),
            [
                "https://primary.example/rpc",
                "https://secondary.example/rpc",
            ],
            [101, 102],
            [instant, instant],
            [1999, 2000],
            instant + std::time::Duration::from_secs(10),
        )
        .unwrap();
        let candidate = crate::signed_intent::test_helpers::intent_fixture_plan(2, 1)
            .0
            .with_capability(witness);
        let _proof = recorder.admit_signed_intent(&candidate).await.unwrap();
        let views = window.signed_intents("intent", &profile).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].expiry_observed_at_ms, Some(2000));
        assert_eq!(views[0].accounting_horizon, "62000");
        clock.set(2000 + 604_800_000);
        let _proof = recorder.admit_signed_intent(&candidate).await.unwrap();
        assert_eq!(window.signed_intents("intent", &profile).unwrap().len(), 1);
        clock.set(2001 + 604_800_000);
        let _proof = recorder.admit_signed_intent(&candidate).await.unwrap();
        assert!(
            window
                .signed_intents("intent", &profile)
                .unwrap()
                .is_empty()
        );
        std::fs::remove_file(window.path()).unwrap();
        let error = recorder
            .admit_signed_intent(&candidate)
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error,
            WalletError::Submission(
                stellar_agent_core::SubmissionError::IntentRecordUnavailable {
                    class: "window_unavailable"
                }
            )
        ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn final_submission_links_and_charges_once() {
        use crate::signed_intent::test_helpers::intent_fixture_plan;
        use stellar_agent_core::policy::v1::criteria::{
            WindowLimit,
            state_store::{PolicyStateStore, StateKey, WindowEntry},
        };
        use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
        use stellar_agent_core::profile::caip2::Caip2;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet_named(
            "intent",
            "bind-once",
            "account",
            "bind-once-nonce",
            "account",
        )
        .build();
        let window = PersistedWindowStore::at_path(dir.path().join("intent.window"));
        let receipts = ReceiptStore::open_at(dir.path(), "intent").unwrap();
        let (plan, envelope) = intent_fixture_plan(1, 60);
        let sizing =
            CheckedSizing::for_test(SizingBasis::MeasuredValue, plan.legs().to_vec()).unwrap();
        let mut recorder = WalletSubmissionRecorder::new(
            &profile,
            "intent",
            "test",
            Some("stellar:testnet".into()),
            PolicyDecision::Allow,
            vec![],
            plan.legs().to_vec(),
            receipts,
            window.clone(),
            None,
            None,
            "request",
            1000,
        )
        .with_signing_sizing(sizing);
        let exposure = recorder.admit_signed_intent(&plan).await.unwrap().expose();
        let make_intent = |envelope: &stellar_xdr::TransactionEnvelope| {
            let facts =
                crate::BindFacts::from_envelope(envelope, Caip2::Testnet.network_passphrase())
                    .unwrap();
            let (source, sequence) = crate::submit::replay_identity(envelope).unwrap();
            SubmissionIntent {
                chain_scope: crate::policy_state::ChainScope::for_chain(Caip2::Testnet),
                envelope_hash: facts.envelope_hash,
                tx_hash: facts.tx_hash,
                source,
                sequence,
                max_time: 0,
                submission_ledger: 1,
                submission_anchor: None,
                send_by_ms: None,
            }
        };
        let intent = make_intent(&envelope);
        let binding = crate::IntentBinding::new(&exposure, &envelope);
        recorder.pre_send_bound(&intent, &binding).await.unwrap();
        assert_eq!(
            recorder
                .pre_send_bound(&intent, &binding)
                .await
                .unwrap_err()
                .code(),
            "submission.tx_already_submitted"
        );
        let assert_totals = |window: &PersistedWindowStore, profile: &Profile, amount, calls| {
            let state = PolicyStateStore::new();
            PersistedWindowStore::at_path(window.path().to_path_buf())
                .load_into("intent", profile, &state)
                .unwrap();
            for duration in [60, 120] {
                assert_eq!(
                    state
                        .query_window(
                            &StateKey::new("intent", 1, "native", duration),
                            stellar_agent_core::timefmt::now_unix_ms().unwrap()
                        )
                        .unwrap(),
                    (amount, calls)
                );
                assert_eq!(
                    state
                        .query_window(
                            &StateKey::new("intent", 1, "rate_limit", duration),
                            stellar_agent_core::timefmt::now_unix_ms().unwrap()
                        )
                        .unwrap(),
                    (i128::from(calls), calls)
                );
            }
        };
        assert_totals(&window, &profile, 60, 1);
        let dir_c = tempfile::tempdir().unwrap();
        let profile_c = Profile::builder_testnet_named(
            "intent-confirm",
            "bind-once",
            "account",
            "confirm-nonce",
            "account",
        )
        .build();
        let window_c = PersistedWindowStore::at_path(dir_c.path().join("intent.window"));
        let (plan_c, envelope_c) = intent_fixture_plan(3, 60);
        let sizing_c =
            CheckedSizing::for_test(SizingBasis::MeasuredValue, plan_c.legs().to_vec()).unwrap();
        let recorder_c = WalletSubmissionRecorder::new(
            &profile_c,
            "intent",
            "test",
            Some("stellar:testnet".into()),
            PolicyDecision::Allow,
            vec![],
            plan_c.legs().to_vec(),
            ReceiptStore::open_at(dir_c.path(), "intent").unwrap(),
            window_c.clone(),
            None,
            None,
            "request",
            1000,
        )
        .with_signing_sizing(sizing_c);
        let exposure_c = recorder_c
            .admit_signed_intent(&plan_c)
            .await
            .unwrap()
            .expose();
        let intent_c = make_intent(&envelope_c);
        recorder_c
            .pre_send_bound(
                &intent_c,
                &crate::IntentBinding::new(&exposure_c, &envelope_c),
            )
            .await
            .unwrap();
        recorder_c
            .outcome(
                &intent_c,
                &SubmissionOutcome::Success {
                    ledger: 2,
                    created_at: None,
                },
            )
            .await;
        assert_totals(&window_c, &profile_c, 60, 1);
        let intents_c = window_c.signed_intents("intent", &profile_c).unwrap();
        assert_eq!(intents_c.len(), 1);
        assert_eq!(
            intents_c[0].status,
            "authorization exposed, submission bound"
        );
        let wire_c: serde_json::Value =
            serde_json::from_slice(&std::fs::read(window_c.path()).unwrap()[32..]).unwrap();
        assert_eq!(
            wire_c["entries"].as_array().unwrap().len(),
            plan_c.legs().len()
        );
        for entry in wire_c["entries"].as_array().unwrap() {
            let records = entry["records"].as_array().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["status"], "exposure");
            assert!(records[0]["observed_at_ms"].is_u64());
            assert_eq!(records[0]["signed_intent"], exposure_c.intent_id().unwrap());
        }
        recorder.settle_window(&intent, WindowSettlement::Release);
        assert!(window.pending_reservations(&profile).unwrap().is_empty());
        assert_eq!(
            window.signed_intents("intent", &profile).unwrap()[0].status,
            "authorization exposed, submission bound"
        );
        assert_totals(&window, &profile, 60, 1);
        recorder
            .outcome(
                &intent,
                &SubmissionOutcome::Success {
                    ledger: 2,
                    created_at: None,
                },
            )
            .await;
        assert_totals(&window, &profile, 60, 1);
        let (plan_b, envelope_b) = intent_fixture_plan(2, 60);
        let legs: Vec<_> = plan_b
            .legs()
            .iter()
            .map(|entry| {
                let limit = match entry.limit() {
                    WindowLimit::Amount { asset, window, .. } => WindowLimit::Amount {
                        asset: asset.clone(),
                        window: window.clone(),
                        max_stroops: 120,
                    },
                    WindowLimit::Count { window, .. } => WindowLimit::Count {
                        window: window.clone(),
                        max_calls: 2,
                    },
                    other => other.clone(),
                };
                WindowEntry::new(
                    entry.key().clone(),
                    entry.timestamp_ms(),
                    entry.amount(),
                    limit,
                )
            })
            .collect();
        recorder.window_entries = legs.clone();
        recorder.signing_sizing =
            Some(CheckedSizing::for_test(SizingBasis::MeasuredValue, legs).unwrap());
        let exposure_b = recorder
            .admit_signed_intent(&plan_b)
            .await
            .unwrap()
            .expose();
        recorder.window_entries.pop();
        let error = recorder
            .pre_send_bound(
                &make_intent(&envelope_b),
                &crate::IntentBinding::new(&exposure_b, &envelope_b),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WalletError::Submission(SubmissionError::IntentBindingMismatch { field: "legs" })
        ));
        assert_totals(&window, &profile, 120, 2);
        assert!(
            window
                .signed_intents("intent", &profile)
                .unwrap()
                .iter()
                .any(|i| i.intent_id == exposure_b.intent_id().unwrap()
                    && i.status == "authorization exposed, submission unknown")
        );
        assert!(window.pending_reservations(&profile).unwrap().is_empty());
        assert_different_final_intent_cannot_consume_reservation().await;
        assert_recorder_links_prune_to_zero().await;
    }

    async fn assert_recorder_links_prune_to_zero() {
        use crate::policy_state::ChainScope;
        use crate::signing::ledger_witness::LedgerWitnessCapability;
        use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
        use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
        use stellar_agent_core::profile::caip2::Caip2;
        use stellar_xdr::{LedgerBounds, Preconditions, PreconditionsV2, TransactionEnvelope};
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile::builder_testnet_named(
            "intent",
            "pruned-link",
            "account",
            "pruned-link-nonce",
            "account",
        )
        .build();
        std::fs::write(dir.path().join("intent.toml"), "chain_id = \"stellar:testnet\"\nrpc_url = \"https://primary.example/rpc\"\nsecondary_rpc_url = \"https://secondary.example/rpc\"\n").unwrap();
        let window = PersistedWindowStore::at_path(dir.path().join("intent.window"))
            .with_profile_directory("intent", dir.path().to_owned());
        let receipts = ReceiptStore::open_at(dir.path(), "intent").unwrap();
        let (fixture, mut envelope) = crate::signed_intent::test_helpers::intent_fixture_kind(2);
        let TransactionEnvelope::Tx(tx) = &mut envelope else {
            unreachable!()
        };
        tx.tx.cond = Preconditions::V2(PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: Some(LedgerBounds {
                min_ledger: 0,
                max_ledger: 50,
            }),
            min_seq_num: None,
            min_seq_age: stellar_xdr::Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: Default::default(),
        });
        let stellar_xdr::OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
            unreachable!()
        };
        let plan = fixture
            .with_envelope_max_ledger(50)
            .unwrap()
            .classify_purpose(&op.host_function, None)
            .unwrap();
        assert_eq!(
            plan.purpose(),
            Some(&crate::signed_intent::IntentPurpose::Invoke)
        );
        assert_eq!(plan.check_envelope(&envelope), Ok(()));
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "intent",
            "test",
            Some("stellar:testnet".into()),
            PolicyDecision::Allow,
            vec![],
            plan.legs().to_vec(),
            receipts.clone(),
            window.clone(),
            None,
            None,
            "pruned-link",
            1000,
        )
        .with_signing_sizing(
            CheckedSizing::for_test(SizingBasis::MeasuredValue, plan.legs().to_vec()).unwrap(),
        );
        let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
        let exposure = recorder.admit_signed_intent(&plan).await.unwrap().expose();
        let facts = crate::BindFacts::from_envelope(&envelope, Caip2::Testnet.network_passphrase())
            .unwrap();
        let (source, sequence) = crate::submit::replay_identity(&envelope).unwrap();
        let intent = SubmissionIntent {
            chain_scope: ChainScope::for_chain(Caip2::Testnet),
            envelope_hash: facts.envelope_hash,
            tx_hash: facts.tx_hash,
            source,
            sequence,
            max_time: 0,
            submission_ledger: 1,
            submission_anchor: None,
            send_by_ms: None,
        };
        recorder
            .pre_send_bound(&intent, &crate::IntentBinding::new(&exposure, &envelope))
            .await
            .unwrap();
        let standing = window.pending_reservations(&profile).unwrap();
        assert_eq!(standing.len(), 1);
        assert_eq!(standing[0].id, intent.envelope_hash);
        clock.set(2000);
        let instant = tokio::time::Instant::now();
        let witness = LedgerWitnessCapability::for_test(
            ChainScope::for_chain(Caip2::Testnet),
            [
                "https://primary.example/rpc",
                "https://secondary.example/rpc",
            ],
            [101, 102],
            [instant, instant],
            [1999, 2000],
            instant + std::time::Duration::from_secs(10),
        )
        .unwrap();
        window.observe_signed_intents(&profile, &witness).unwrap();
        assert_eq!(
            window.signed_intents("intent", &profile).unwrap()[0].expiry_observed_at_ms,
            Some(2000)
        );
        clock.set(2001 + 604_800_000);
        window.observe_signed_intents(&profile, &witness).unwrap();
        let reopened = PersistedWindowStore::at_path(window.path().to_owned());
        assert!(
            reopened
                .signed_intents("intent", &profile)
                .unwrap()
                .is_empty()
        );
        let state = PolicyStateStore::new();
        reopened.load_into("intent", &profile, &state).unwrap();
        for bucket in ["native", "rate_limit"] {
            for seconds in [60, 604_800] {
                assert_eq!(
                    state
                        .query_window(
                            &StateKey::new("intent", 1, bucket, seconds),
                            2001 + 604_800_000
                        )
                        .unwrap(),
                    (0, 0)
                );
            }
        }
        assert_eq!(reopened.pending_reservations(&profile).unwrap(), standing);
        assert_eq!(
            receipts.get(&intent.envelope_hash).unwrap().unwrap().status,
            ReceiptStatus::Pending
        );
        let wire: serde_json::Value =
            serde_json::from_slice(&std::fs::read(window.path()).unwrap()[32..]).unwrap();
        assert_eq!(wire["entries"].as_array().unwrap().len(), plan.legs().len());
        for entry in wire["entries"].as_array().unwrap() {
            let records = entry["records"].as_array().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["signed_intent"], exposure.intent_id().unwrap());
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn different_final_intent_cannot_consume_reservation() {
        assert_different_final_intent_cannot_consume_reservation().await;
    }

    async fn assert_different_final_intent_cannot_consume_reservation() {
        use crate::signed_intent::test_helpers::intent_fixture_kind;
        use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
        use stellar_agent_core::policy::v1::{CheckedSizing, SizingBasis};
        use stellar_xdr::*;
        let cases = [
            "credential",
            "nonce",
            "expiration",
            "invocation",
            "context_rule_ids",
            "external_verifier",
            "external_key",
            "delegated",
            "host_invocation",
            "envelope_source",
            "envelope_sequence",
            "duplicate",
            "added",
            "removed",
            "legs",
            "chain",
            "operation_source",
            "envelope_bound_missing",
            "envelope_bound_zero",
            "envelope_bound_smaller",
            "envelope_bound_larger",
            "purpose",
        ];
        let mut mismatches = Vec::new();
        for case in cases {
            stellar_agent_test_support::keyring_mock::install().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let profile = Profile::builder_testnet_named(
                "intent",
                "binding",
                "account",
                "binding-nonce",
                "account",
            )
            .build();
            let window = PersistedWindowStore::at_path(dir.path().join("intent.window"));
            let receipts = ReceiptStore::open_at(dir.path(), "intent").unwrap();
            let (fixture, mut envelope) = intent_fixture_kind(2);
            let TransactionEnvelope::Tx(tx) = &mut envelope else {
                unreachable!()
            };
            tx.tx.cond = Preconditions::V2(PreconditionsV2 {
                time_bounds: None,
                ledger_bounds: Some(LedgerBounds {
                    min_ledger: 0,
                    max_ledger: 50,
                }),
                min_seq_num: None,
                min_seq_age: Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: VecM::default(),
            });
            let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                unreachable!()
            };
            let plan = fixture
                .with_envelope_max_ledger(50)
                .unwrap()
                .classify_purpose(&op.host_function, None)
                .unwrap();
            assert_eq!(
                plan.purpose(),
                Some(&crate::signed_intent::IntentPurpose::Invoke)
            );
            assert_eq!(
                plan.subjects()
                    .iter()
                    .filter_map(crate::IntentSubject::expiration)
                    .max(),
                Some(100)
            );
            assert_eq!(plan.check_envelope(&envelope), Ok(()));
            let entries = plan.legs().to_vec();
            let sizing =
                CheckedSizing::for_test(SizingBasis::MeasuredValue, entries.clone()).unwrap();
            let mut recorder = WalletSubmissionRecorder::new(
                &profile,
                "intent",
                "test",
                Some("stellar:testnet".into()),
                PolicyDecision::Allow,
                vec![],
                entries,
                receipts,
                window.clone(),
                None,
                None,
                "request",
                1000,
            )
            .with_signing_sizing(sizing);
            let exposure = recorder.admit_signed_intent(&plan).await.unwrap().expose();
            let before = std::fs::read(window.path()).unwrap();
            let TransactionEnvelope::Tx(tx) = &mut envelope else {
                unreachable!()
            };
            if case == "envelope_source" {
                tx.tx.source_account = MuxedAccount::Ed25519(Uint256([9; 32]));
            }
            if case == "envelope_sequence" {
                tx.tx.seq_num.0 += 1;
            }
            if case.starts_with("envelope_bound_") {
                let Preconditions::V2(conditions) = &mut tx.tx.cond else {
                    unreachable!()
                };
                conditions.ledger_bounds = match case {
                    "envelope_bound_missing" => None,
                    _ => Some(LedgerBounds {
                        min_ledger: 0,
                        max_ledger: match case {
                            "envelope_bound_zero" => 0,
                            "envelope_bound_smaller" => 49,
                            _ => 51,
                        },
                    }),
                };
            }
            let mut operations = tx.tx.operations.to_vec();
            if case == "operation_source" {
                operations[0].source_account = Some(MuxedAccount::Ed25519(Uint256([9; 32])));
            }
            let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
                unreachable!()
            };
            if case == "host_invocation" || case == "purpose" {
                let HostFunction::InvokeContract(call) = &mut op.host_function else {
                    unreachable!()
                };
                call.function_name = ScSymbol::try_from(if case == "purpose" {
                    "schedule"
                } else {
                    "other"
                })
                .unwrap();
            }
            let mut auth = op.auth.to_vec();
            if case == "duplicate" {
                auth.push(auth[0].clone());
            }
            if case == "added" {
                let mut added = auth[0].clone();
                if let SorobanCredentials::Address(credentials) = &mut added.credentials {
                    credentials.nonce += 1;
                }
                auth.push(added);
            }
            if case == "removed" {
                auth.clear();
            }
            if let Some(entry) = auth.first_mut() {
                if case == "invocation" {
                    entry.root_invocation.sub_invocations =
                        vec![entry.root_invocation.clone()].try_into().unwrap();
                }
                let SorobanCredentials::Address(credentials) = &mut entry.credentials else {
                    unreachable!()
                };
                match case {
                    "credential" => {
                        credentials.address = ScAddress::Contract(ContractId(Hash([9; 32])))
                    }
                    "nonce" => credentials.nonce += 1,
                    "expiration" => credentials.signature_expiration_ledger += 1,
                    "context_rule_ids" | "external_verifier" | "external_key" | "delegated" => {
                        let ScVal::Map(Some(fields)) = &credentials.signature else {
                            unreachable!()
                        };
                        let mut fields = fields.to_vec();
                        if case == "context_rule_ids" {
                            fields[0].val =
                                ScVal::Vec(Some(vec![ScVal::U32(4)].try_into().unwrap()));
                        } else {
                            let ScVal::Map(Some(signers)) = &fields[1].val else {
                                unreachable!()
                            };
                            let mut signers = signers.to_vec();
                            for signer in &mut signers {
                                let ScVal::Vec(Some(key)) = &signer.key else {
                                    unreachable!()
                                };
                                let mut key = key.to_vec();
                                let ScVal::Symbol(tag) = &key[0] else {
                                    unreachable!()
                                };
                                let delegated = tag.0.as_slice() == b"Delegated";
                                if case == "delegated" && delegated {
                                    key[1] = ScVal::Address(ScAddress::Account(AccountId(
                                        PublicKey::PublicKeyTypeEd25519(Uint256([8; 32])),
                                    )));
                                }
                                if case == "external_verifier" && !delegated {
                                    key[1] = ScVal::Address(ScAddress::Contract(ContractId(Hash(
                                        [8; 32],
                                    ))));
                                }
                                if case == "external_key" && !delegated {
                                    key[2] = ScVal::Bytes(ScBytes(vec![8; 32].try_into().unwrap()));
                                }
                                signer.key = ScVal::Vec(Some(key.try_into().unwrap()));
                            }
                            signers.sort_by(|a, b| a.key.cmp(&b.key));
                            fields[1].val = ScVal::Map(Some(signers.try_into().unwrap()));
                        }
                        credentials.signature = ScVal::Map(Some(fields.try_into().unwrap()));
                    }
                    _ => {}
                }
            }
            op.auth = auth.try_into().unwrap();
            tx.tx.operations = operations.try_into().unwrap();
            if case == "legs" {
                let entry = &recorder.window_entries[0];
                recorder.window_entries[0] =
                    stellar_agent_core::policy::v1::criteria::state_store::WindowEntry::new(
                        entry.key().clone(),
                        entry.timestamp_ms(),
                        entry.amount() + 1,
                        entry.limit().clone(),
                    );
            }
            let chain = if case == "chain" {
                stellar_agent_core::profile::caip2::Caip2::Mainnet
            } else {
                stellar_agent_core::profile::caip2::Caip2::Testnet
            };
            let encoded = envelope.to_xdr_base64(Limits::none()).unwrap();
            let (source, sequence) = crate::submit::replay_identity(&envelope).unwrap();
            let intent = SubmissionIntent {
                chain_scope: crate::policy_state::ChainScope::for_chain(chain),
                envelope_hash: crate::submit::envelope_hash_hex(&encoded),
                tx_hash: crate::submit::compute_local_tx_hash_hex(
                    &envelope,
                    chain.network_passphrase(),
                )
                .unwrap(),
                source,
                sequence,
                max_time: 0,
                submission_ledger: 1,
                submission_anchor: None,
                send_by_ms: None,
            };
            let result = recorder
                .pre_send_bound(&intent, &crate::IntentBinding::new(&exposure, &envelope))
                .await;
            let expected = match case {
                "credential" | "duplicate" | "added" | "removed" => "auth_subjects",
                "external_verifier" | "external_key" | "delegated" => "signers",
                "operation_source" => "envelope_source",
                "envelope_bound_missing"
                | "envelope_bound_zero"
                | "envelope_bound_smaller"
                | "envelope_bound_larger" => "expiration",
                other => other,
            };
            let refused = if case == "chain" {
                result
                    .as_ref()
                    .is_err_and(|error| error.code() == "policy.window_chain_mismatch")
            } else {
                matches!(&result, Err(WalletError::Submission(SubmissionError::IntentBindingMismatch { field })) if *field == expected)
            };
            if !refused {
                mismatches.push(format!("{case}: expected {expected}, got {result:?}"));
                continue;
            }
            assert_eq!(std::fs::read(window.path()).unwrap(), before, "{case}");
            assert!(window.pending_reservations(&profile).unwrap().is_empty());
            let intents = window.signed_intents("intent", &profile).unwrap();
            assert_eq!(intents.len(), 1, "{case}");
            assert_eq!(
                intents[0].status, "authorization exposed, submission unknown",
                "{case}"
            );
            let state = PolicyStateStore::new();
            window.load_into("intent", &profile, &state).unwrap();
            assert_eq!(
                state
                    .query_window(
                        &StateKey::new("intent", 1, "native", 60),
                        stellar_agent_core::timefmt::now_unix_ms().unwrap()
                    )
                    .unwrap(),
                (60, 1),
                "{case}"
            );
        }
        assert!(
            mismatches.is_empty(),
            "final facts lack their required refusal: {mismatches:?}"
        );
    }

    #[test]
    fn record_unavailable_carries_the_wire_code() {
        let err = record_unavailable("receipt store is not writable");
        assert_eq!(err.code(), "submission.record_unavailable");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn scope_refusals_preserve_submission_state_and_warn_for_outcomes() {
        use stellar_agent_core::profile::caip2::Caip2;
        use stellar_agent_test_support::log_capture::CaptureWriter;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile =
            Profile::builder_testnet_named("scope-recorder", "s", "a", "n", "a").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        let window = PersistedWindowStore::at_path(dir.path().join("state.window"));
        window.record_and_persist(&profile, &[]).unwrap();
        let receipts = ReceiptStore::open_at(dir.path(), "scope-recorder").unwrap();
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "scope-recorder",
            "stellar_pay_commit",
            Some("stellar:testnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            vec![],
            receipts.clone(),
            window.clone(),
            Some(audit),
            None,
            "request",
            1_000,
        );
        let mut intent = SubmissionIntent {
            chain_scope: crate::policy_state::ChainScope::for_chain(Caip2::Mainnet),
            envelope_hash: "a".repeat(64),
            tx_hash: "b".repeat(64),
            source: stellar_strkey::ed25519::PublicKey([7; 32])
                .to_string()
                .to_string(),
            sequence: 7,
            max_time: 0,
            submission_ledger: 123,
            submission_anchor: None,
            send_by_ms: None,
        };
        let audit_before = std::fs::read(&profile.audit_log_path).unwrap();
        let window_before = std::fs::read(dir.path().join("state.window")).unwrap();
        assert_eq!(
            recorder.pre_send(&intent).await.unwrap_err().code(),
            "policy.window_chain_mismatch"
        );
        assert!(receipts.get(&intent.envelope_hash).unwrap().is_none());
        assert_eq!(
            std::fs::read(&profile.audit_log_path).unwrap(),
            audit_before
        );
        assert_eq!(
            std::fs::read(dir.path().join("state.window")).unwrap(),
            window_before
        );
        intent.chain_scope = crate::policy_state::ChainScope::for_chain(Caip2::Testnet);
        recorder.pre_send(&intent).await.unwrap();
        let receipt_before = std::fs::read(receipts.file_path().unwrap()).unwrap();
        let audit_before = std::fs::read(&profile.audit_log_path).unwrap();
        let window_before = std::fs::read(dir.path().join("state.window")).unwrap();
        intent.chain_scope = crate::policy_state::ChainScope::for_chain(Caip2::Mainnet);
        let capture = CaptureWriter::new();
        let _inert = stellar_agent_test_support::log_capture::inert_dispatcher();
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_writer(capture.clone())
                .finish(),
        );
        for outcome in [
            SubmissionOutcome::Success {
                ledger: 124,
                created_at: Some(1),
            },
            SubmissionOutcome::Rejected {
                code: "tx.failed".to_owned(),
                error: "synthetic refusal".to_owned(),
            },
        ] {
            capture.clear();
            recorder.outcome(&intent, &outcome).await;
            let log = capture.captured_str();
            assert!(
                log.contains(
                    "outcome not recorded; the receipt and reservation stand until reconciliation"
                ),
                "{log}"
            );
            assert!(
                log.contains("scope-recorder")
                    && log.contains("stellar_pay_commit")
                    && log.contains("ChainMismatch"),
                "{log}"
            );
            assert_eq!(
                std::fs::read(receipts.file_path().unwrap()).unwrap(),
                receipt_before
            );
            assert_eq!(
                std::fs::read(&profile.audit_log_path).unwrap(),
                audit_before
            );
            assert_eq!(
                std::fs::read(dir.path().join("state.window")).unwrap(),
                window_before
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn entryless_submission_reads_no_window_state() {
        use stellar_agent_core::profile::caip2::Caip2;
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile =
            Profile::builder_testnet_named("entryless-recorder", "s", "a", "n", "a").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        // Any read of this file refuses: the keyring holds no key for it.
        let state = dir.path().join("state.window");
        std::fs::write(&state, b"unverifiable").unwrap();
        let receipts = ReceiptStore::open_at(dir.path(), "entryless-recorder").unwrap();
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "entryless-recorder",
            "stellar_pay_commit",
            Some("stellar:testnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            vec![],
            receipts.clone(),
            PersistedWindowStore::at_path(state.clone()),
            Some(audit),
            None,
            "request",
            1_000,
        );
        let intent = SubmissionIntent {
            chain_scope: crate::policy_state::ChainScope::for_chain(Caip2::Testnet),
            envelope_hash: "a".repeat(64),
            tx_hash: "b".repeat(64),
            source: stellar_strkey::ed25519::PublicKey([7; 32])
                .to_string()
                .to_string(),
            sequence: 7,
            max_time: 0,
            submission_ledger: 123,
            submission_anchor: None,
            send_by_ms: None,
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
        assert_eq!(
            receipts.get(&intent.envelope_hash).unwrap().unwrap().status,
            ReceiptStatus::Success
        );
        assert_eq!(std::fs::read(&state).unwrap(), b"unverifiable");
    }

    /// The provenance the recorder tests attach, and its pending-row form.
    fn test_provenance() -> stellar_agent_core::mainnet::decision::MainnetProvenance {
        stellar_agent_core::mainnet::decision::MainnetProvenance {
            policy_digest: [3; 32],
            policy_sequence: 4,
            rule_index: 2,
            evaluated_at_ms: 1_000,
        }
    }

    /// Asserts that `row` carries [`test_provenance`]: the policy digest as
    /// lowercase hex and the deciding rule's index.
    fn assert_row_carries_test_provenance(row: &serde_json::Value) {
        assert_eq!(row["policy_digest"], "03".repeat(32), "{row}");
        assert_eq!(row["rule_index"], 2, "{row}");
    }

    /// The pending row carries the witness and the policy provenance whether
    /// the recorder is built directly or assembled from recorder inputs, and
    /// a success writes no submitted row.
    #[tokio::test]
    #[serial_test::serial]
    async fn pending_row_carries_the_witness_and_success_writes_no_submitted_row() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let witness = crate::cross_check::CrossCheckWitness::for_crate_tests(
            "https://oracle.example",
            123,
            [9; 32],
            vec![stellar_agent_core::cross_check::WitnessEntry::SourceAccount],
        );
        for assembled in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut profile =
                Profile::builder_testnet("signer", "witness", "nonce", "witness").build();
            profile.audit_log_path = dir.path().join("audit.jsonl");
            let audit = Arc::new(Mutex::new(
                AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
            ));
            let receipts = ReceiptStore::open_at(dir.path(), "witness").unwrap();
            let recorder = if assembled {
                crate::submission_flow::assemble_recorder(
                    crate::submission_flow::RecorderInputs {
                        profile: &profile,
                        profile_name: "witness".to_owned(),
                        tool: "stellar_pay_commit",
                        chain_id: "stellar:testnet".to_owned(),
                        policy_decision: PolicyDecision::Allow,
                        legs: vec![],
                        audit: Some(audit),
                        nonce_id: None,
                        now_ms: 1_000,
                        provenance: Some(test_provenance()),
                        operation: None,
                    },
                    receipts,
                    None,
                )
            } else {
                WalletSubmissionRecorder::new(
                    &profile,
                    "witness",
                    "stellar_pay_commit",
                    Some("stellar:testnet".to_owned()),
                    PolicyDecision::Allow,
                    vec![],
                    vec![],
                    receipts,
                    PersistedWindowStore::at_path(dir.path().join("window.json")),
                    Some(audit),
                    None,
                    "request",
                    1_000,
                )
                .with_provenance(test_provenance())
            }
            .with_witness(Some(&witness));
            let intent = SubmissionIntent {
                chain_scope: crate::policy_state::ChainScope::for_chain(
                    stellar_agent_core::profile::caip2::Caip2::Testnet,
                ),
                envelope_hash: "a".repeat(64),
                tx_hash: "b".repeat(64),
                source: stellar_strkey::ed25519::PublicKey([7; 32])
                    .to_string()
                    .to_string(),
                sequence: 7,
                max_time: 0,
                submission_ledger: 123,
                submission_anchor: None,
                send_by_ms: None,
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
            assert_eq!(rows.len(), 1, "assembled={assembled}");
            assert_eq!(rows[0]["kind"], "value_action_pending");
            assert_eq!(
                rows[0]["witness"],
                serde_json::to_value(witness.record()).unwrap()
            );
            assert_row_carries_test_provenance(&rows[0]);
        }
    }

    /// An unsent outcome unwinds the record of a submission whose send never
    /// started: the reservation is released, the pending row is settled by
    /// its closing row, no receipt remains, and a new record at the same
    /// source and sequence passes.
    #[tokio::test]
    #[serial_test::serial]
    async fn an_unsent_outcome_unwinds_the_record() {
        use stellar_agent_core::policy::v1::criteria::state_store::{
            StateKey, WindowEntry, WindowLimit,
        };

        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut profile = Profile::builder_testnet("unsent", "s", "n", "a").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let receipts = ReceiptStore::open_at(dir.path(), "unsent").unwrap();
        let window = PersistedWindowStore::at_path(dir.path().join("unsent.window"));
        let recorder = WalletSubmissionRecorder::new(
            &profile,
            "unsent",
            "stellar_pay_commit",
            Some("stellar:testnet".to_owned()),
            PolicyDecision::Allow,
            vec![],
            vec![WindowEntry::new(
                StateKey::new("unsent", 1, "native", 86_400),
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
        let intent = |envelope_hash: &str, tx_hash: &str| SubmissionIntent {
            chain_scope: crate::policy_state::ChainScope::for_chain(
                stellar_agent_core::profile::caip2::Caip2::Testnet,
            ),
            envelope_hash: envelope_hash.repeat(32),
            tx_hash: tx_hash.repeat(32),
            source: format!("{}", stellar_strkey::ed25519::PublicKey([7; 32])),
            sequence: 7,
            max_time: 0,
            submission_ledger: 123,
            submission_anchor: None,
            send_by_ms: Some(now + 1_000),
        };
        let unsent = intent("7a", "8b");
        recorder.pre_send(&unsent).await.unwrap();
        assert!(
            receipts
                .get(&unsent.envelope_hash)
                .unwrap()
                .unwrap()
                .submitted
        );
        assert_eq!(window.pending_reservations(&profile).unwrap().len(), 1);

        recorder
            .outcome(
                &unsent,
                &SubmissionOutcome::NotSent {
                    code: "network.rpc_timeout".to_owned(),
                    error: "nothing was sent".to_owned(),
                },
            )
            .await;

        assert!(
            window.pending_reservations(&profile).unwrap().is_empty(),
            "the reservation is released"
        );
        assert!(matches!(
            try_value_action_settlement(&audit.lock().unwrap(), &unsent.envelope_hash).unwrap(),
            ValueActionSettlement::Settled
        ));
        assert!(
            receipts.get(&unsent.envelope_hash).unwrap().is_none(),
            "no receipt remains"
        );
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0]["kind"], "value_action_pending");
        assert_eq!(rows[1]["kind"], "value_action_failed");
        assert_eq!(rows[1]["code"], "network.rpc_timeout");

        let rebuilt = intent("9c", "ad");
        recorder
            .pre_send(&rebuilt)
            .await
            .expect("the source and sequence are free again");
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
        let keyed = access.is_some();
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
            chain_scope: crate::policy_state::ChainScope::for_chain(
                stellar_agent_core::profile::caip2::Caip2::Testnet,
            ),
            envelope_hash: "7a".repeat(32),
            tx_hash: "8b".repeat(32),
            source: format!("{}", stellar_strkey::ed25519::PublicKey([7; 32])),
            sequence: 7,
            max_time: 0,
            submission_ledger: 123,
            submission_anchor: None,
            send_by_ms: None,
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
        assert!(matches!(
            try_value_action_settlement(&audit.lock().unwrap(), &intent.envelope_hash).unwrap(),
            ValueActionSettlement::Owed(_)
        ));
        drop(audit);
        let mut rows: Vec<serde_json::Value> = std::fs::read_to_string(&profile.audit_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        if keyed {
            // A keyed writer opens the log with its entry-tag boundary row.
            assert_eq!(rows.remove(0)["kind"], "audit_entry_tags_started");
        }
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows.iter().all(|row| row["kind"] == "value_action_pending"));
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
            2,
            "only the boundary row and the original row were anchored"
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
            entry_tags_in_force: true,
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

        /// Asserts that the attempt ended as `NotSent` with `code`, and that
        /// its authorization carries the `Always` release row of class
        /// `proved_unspent`.
        fn assert_not_sent(
            fx: &LedgerFixture,
            attempt: OperationAttempt,
            authorization: AuthorizationId,
            code: &str,
        ) {
            let record = fx.operation_record(attempt);
            assert_eq!(record["state"], "not_sent", "{record}");
            assert_eq!(record["attempts"][0]["outcome"], "not_sent", "{record}");
            assert_eq!(record["result"]["error_code"], code, "{record}");
            let auth = fx.authorization_record(authorization);
            assert_eq!(auth["native_release"]["class"], "proved_unspent", "{auth}");
            assert_eq!(auth["native_release"]["bound"], "always", "{auth}");
        }

        /// A signer refusal after the attempt began ends it as `NotSent` with
        /// the refusal's code, and the attempt's authorization gets its
        /// `Always` release row in the same commit. Once the pre-send hook
        /// was entered the stage-marked recorder leaves the end to the hook.
        #[tokio::test]
        #[serial]
        async fn sign_failure_records_not_sent_with_an_always_row() {
            let fx = LedgerFixture::new("operation-sign-failure", NOW);
            let sub = submission();
            let (attempt, authorization) = fx.linked_attempt(sub.binding.clone(), &[], "order-1");
            assert_eq!(fx.operation_record(attempt)["state"], "sending");
            let staged = crate::submission_flow::StageMarkedRecorder::new(
                fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                    .with_operation(Some(attempt)),
            );

            staged.end_refused_attempt("auth.signer_unavailable");

            assert_not_sent(&fx, attempt, authorization.id(), "auth.signer_unavailable");
            assert!(
                fx.audit_kinds()
                    .iter()
                    .any(|kind| kind == "operation_transition"),
                "{:?}",
                fx.audit_kinds()
            );

            let fx = LedgerFixture::new("operation-sign-failure-entered", NOW);
            let (attempt, authorization) = fx.linked_attempt(sub.binding.clone(), &[], "order-2");
            let staged = crate::submission_flow::StageMarkedRecorder::new(
                fx.recorder(vec![], Some(Arc::clone(&fx.writer)))
                    .with_operation(Some(attempt)),
            );
            staged
                .pre_send_authorized(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .await
                .unwrap();
            let before = fx.operation_record(attempt);
            staged.end_refused_attempt("network.rpc_timeout");
            assert_eq!(fx.operation_record(attempt), before);
            assert_eq!(before["state"], "sending");
        }

        /// The recorder's outcome ends the attempt, after the exposure the
        /// consumption committed. The `NotSent` arm ends it as `NotSent` with
        /// an `Always` release row. Every other arm ends it as
        /// `SentOutcomeUnknown` with the transaction hash.
        #[tokio::test]
        #[serial]
        async fn outcome_maps_not_sent_and_every_other_arm() {
            let sub = submission();
            let tx_hash = sub.intent.tx_hash.clone();
            let arms = [
                (
                    "operation-outcome-not-sent",
                    SubmissionOutcome::NotSent {
                        code: "network.rpc_timeout".to_owned(),
                        error: "nothing was sent".to_owned(),
                    },
                ),
                (
                    "operation-outcome-success",
                    SubmissionOutcome::Success {
                        ledger: 1005,
                        created_at: None,
                    },
                ),
                (
                    "operation-outcome-failed",
                    SubmissionOutcome::OnChainFailed {
                        code: "submission.tx_failed".to_owned(),
                    },
                ),
                (
                    "operation-outcome-rejected",
                    SubmissionOutcome::Rejected {
                        code: "submission.tx_rejected".to_owned(),
                        error: "rejected".to_owned(),
                    },
                ),
                (
                    "operation-outcome-timeout",
                    SubmissionOutcome::Timeout {
                        tx_hash: tx_hash.clone(),
                    },
                ),
                (
                    "operation-outcome-transport",
                    SubmissionOutcome::TransportAfterSend {
                        error: "connection reset".to_owned(),
                    },
                ),
            ];
            for (label, outcome) in arms {
                let fx = LedgerFixture::new(label, NOW);
                let holds = holds(&fx, 100);
                let (attempt, authorization) =
                    fx.linked_attempt(sub.binding.clone(), &holds, "order-1");
                let id = authorization.id();
                let recorder = fx
                    .recorder(holds, Some(Arc::clone(&fx.writer)))
                    .with_operation(Some(attempt));
                recorder
                    .pre_send_authorized(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                    .await
                    .unwrap();
                assert!(
                    fx.operation_record(attempt)["attempts"][0]["exposure"].is_object(),
                    "{label}: the consumption commits the exposure"
                );

                recorder.outcome(&sub.intent, &outcome).await;

                if let SubmissionOutcome::NotSent { code, .. } = &outcome {
                    assert_not_sent(&fx, attempt, id, code);
                } else {
                    let record = fx.operation_record(attempt);
                    assert_eq!(record["state"], "sent_outcome_unknown", "{label}: {record}");
                    assert_eq!(record["result"]["tx_hash"], tx_hash.as_str(), "{label}");
                    assert!(
                        fx.authorization_record(id).get("native_release").is_none(),
                        "{label}: the spend stays counted"
                    );
                }
            }
        }

        /// A grant without holds, consumed by a recorder that sizes no window
        /// entries, records both stages of its attempt. The consumption commits
        /// the exposure with the attempt still `Sending`, and the outcome then
        /// records `SentOutcomeUnknown`.
        #[tokio::test]
        #[serial]
        async fn zero_entry_path_records_both_stages() {
            let fx = LedgerFixture::new("operation-zero-entry", NOW);
            let sub = submission();
            let (attempt, authorization) = fx.linked_attempt(sub.binding.clone(), &[], "order-1");
            let recorder = fx
                .recorder(vec![], Some(Arc::clone(&fx.writer)))
                .with_operation(Some(attempt));

            recorder
                .pre_send_authorized(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .await
                .unwrap();
            let exposed = fx.operation_record(attempt);
            assert_eq!(exposed["state"], "sending", "{exposed}");
            assert_eq!(
                exposed["attempts"][0]["exposure"]["identity"]["classic"]["tx_hash"],
                sub.intent.tx_hash.as_str(),
                "{exposed}"
            );
            assert_eq!(reservations(&fx), 0);

            recorder
                .outcome(
                    &sub.intent,
                    &SubmissionOutcome::Success {
                        ledger: 1005,
                        created_at: None,
                    },
                )
                .await;
            let ended = fx.operation_record(attempt);
            assert_eq!(ended["state"], "sent_outcome_unknown", "{ended}");
            assert_eq!(ended["attempts"][0]["outcome"], "sent_outcome_unknown");
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
                try_value_action_settlement(
                    &fx.writer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                    &sub.intent.envelope_hash
                )
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
                try_value_action_settlement(
                    &fx.writer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                    &sub.intent.envelope_hash
                )
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
                        &fx.writer
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
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

        /// An endpoint report with a lost receipt refuses resend and preserves
        /// the original pending audit row.
        #[tokio::test]
        #[serial]
        async fn endpoint_outcomes_keep_stateless_consumption_open() {
            for (label, outcome) in [
                (
                    "rejected",
                    SubmissionOutcome::Rejected {
                        code: "transaction.failed".to_owned(),
                        error: "definitive refusal".to_owned(),
                    },
                ),
                (
                    "failed",
                    SubmissionOutcome::OnChainFailed {
                        code: "transaction.failed".to_owned(),
                    },
                ),
                (
                    "succeeded",
                    SubmissionOutcome::Success {
                        ledger: 512,
                        created_at: Some(1_800_000_001),
                    },
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
                assert_eq!(fx.audit_kinds(), ["value_action_pending"]);
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
                    ["value_action_pending"],
                    "an uncertain original refuses the resend before any new row"
                );
                assert!(matches!(
                    try_value_action_settlement(
                        &fx.writer
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                        &sub.intent.envelope_hash
                    )
                    .unwrap(),
                    ValueActionSettlement::Owed(_)
                ));
            }
        }

        /// A settlement read error removes only the receipt and preserves the
        /// open grant without appending a pending or closing row.
        #[tokio::test]
        #[serial]
        async fn a_settlement_lookup_error_takes_the_receipt_stage() {
            let fx = LedgerFixture::new("consume-settlement-error", NOW);
            let sub = submission();
            let (id, authorization) = grant(&fx, &sub, &[], "approval-1");
            let audit_path = fx.profile.audit_log_path.clone();
            let before = std::fs::read(&audit_path).unwrap();
            // A directory at an archive's name makes the reader fail while the
            // writer remains usable.
            let mut archive = audit_path.clone().into_os_string();
            archive.push(".20260428T123456");
            std::fs::create_dir(archive).unwrap();

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

        /// The settlement lookup reads through the held guard: a failed row
        /// appended past the writer's verified tip does not settle the owed
        /// pending row, so the precheck refuses the bytes as submitted.
        #[test]
        #[serial]
        fn the_precheck_reads_through_the_held_guard() {
            let fx = LedgerFixture::new("consume-settlement-bound", NOW);
            let sub = submission();
            let recorder = fx.recorder(vec![], Some(Arc::clone(&fx.writer)));
            fx.writer
                .lock()
                .unwrap()
                .write_entry(recorder.pending_entry(&sub.intent))
                .unwrap();
            stellar_agent_core::audit_log::test_helpers::append_forged_entry(
                &fx.profile.audit_log_path,
                AuditEntry::new_value_action_failed(
                    "stellar_pay_commit",
                    Some("stellar:pubnet".to_owned()),
                    vec![],
                    "6ba7aaac...69060003",
                    "submission.failed",
                    PolicyDecision::Allow,
                    Some(sub.intent.envelope_hash.clone()),
                    None,
                    None,
                    "req-forged-failed",
                ),
                |_| None,
            );

            let guard = fx.writer.lock().unwrap();
            let error = recorder
                .settlement_precheck(&guard, &sub.intent)
                .unwrap_err();
            assert_eq!(error.code(), "submission.tx_already_submitted");
        }

        /// A planted quarantine row whose count reaches back over the owed
        /// pending row hides nothing once the operator's re-anchor quarantines
        /// it: the precheck refuses the bytes as submitted, as it does without
        /// the planted row.
        #[test]
        #[serial]
        fn a_quarantined_forged_quarantine_row_leaves_the_precheck_refusing() {
            use stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore;
            use stellar_agent_core::audit_log::writer::ReanchorAcknowledgement;
            use stellar_agent_core::audit_log::{KeyedAuditAccess, TipAnchorStore};

            let fx = LedgerFixture::new("consume-settlement-quarantine", NOW);
            let sub = submission();
            let recorder = fx.recorder(vec![], Some(Arc::clone(&fx.writer)));
            let path = fx.dir.path().join("quarantine.jsonl");
            let store = Arc::new(InMemoryTipAnchorStore::new());
            let key = [0x5c; 32];
            let open = || {
                AuditWriter::open(
                    path.clone(),
                    Some(KeyedAuditAccess::new(
                        zeroize::Zeroizing::new(key),
                        Arc::clone(&store) as Arc<dyn TipAnchorStore>,
                    )),
                )
                .unwrap()
            };
            open()
                .write_entry(recorder.pending_entry(&sub.intent))
                .unwrap();
            stellar_agent_core::audit_log::test_helpers::append_forged_entry(
                &path,
                AuditEntry::new_audit_entries_quarantined(1_000, "req-forged-quarantine"),
                |_| None,
            );
            let mut repair = AuditWriter::open_for_reanchor(
                path.clone(),
                Some(zeroize::Zeroizing::new(key)),
                Arc::clone(&store) as Arc<dyn TipAnchorStore>,
            )
            .unwrap();
            let report = repair
                .reanchor_acknowledging(&[
                    ReanchorAcknowledgement::UnauthenticatedTail,
                    ReanchorAcknowledgement::Rollback,
                ])
                .unwrap();
            assert_eq!(report.quarantined, 1);
            drop(repair);

            let writer = open();
            let error = recorder
                .settlement_precheck(&writer, &sub.intent)
                .unwrap_err();
            assert_eq!(error.code(), "submission.tx_already_submitted");
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
                try_value_action_settlement(
                    &fx.writer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                    &sub.intent.envelope_hash
                )
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
                    &fx.writer
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
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
            let outbox = AuditOutbox::for_log(
                &fx.profile.audit_log_path,
                crate::keyring::KeyringTipAnchorStore::shared(
                    &fx.profile.audit_log_hash_chain_key_id,
                    &fx.profile.audit_log_path,
                ),
            );
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

        /// A recorder built from an authorization writes the policy
        /// provenance it carries into the pending row its consume appends.
        #[tokio::test]
        #[serial]
        async fn authorized_pending_row_carries_the_provenance() {
            let fx = LedgerFixture::new("authorized-provenance", NOW);
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
            )
            .with_provenance(test_provenance());
            recorder
                .consume_for_submission(&sub.intent, MainnetSubmitGrant::Tx(authorization))
                .unwrap();
            let pending: Vec<serde_json::Value> =
                std::fs::read_to_string(&fx.profile.audit_log_path)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .filter(|row| row["kind"] == "value_action_pending")
                    .collect();
            assert_eq!(pending.len(), 1, "{pending:?}");
            assert_row_carries_test_provenance(&pending[0]);
        }

        #[tokio::test]
        #[serial]
        async fn authorized_recorder_retains_minted_exposure() {
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
                assert_eq!(reservations(&fx), 1);
                let bytes = std::fs::read(fx.dir.path().join("state.window")).unwrap();
                let wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
                assert_eq!(wire["entries"].as_array().map_or(0, Vec::len), 1);
            }
        }

        /// A reported refusal retains converted exposure, leaves the authorization
        /// used and the audit row pending, and tombstones the consumed approval.
        #[tokio::test]
        #[serial]
        async fn a_reported_rejection_retains_the_converted_rows() {
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
            assert_eq!(reservations(&fx), 1);
            let bytes = std::fs::read(fx.dir.path().join("state.window")).unwrap();
            let wire: serde_json::Value = serde_json::from_slice(&bytes[32..]).unwrap();
            assert!(
                wire["entries"]
                    .as_array()
                    .is_some_and(|entries| entries.len() == 1),
                "exposed records retain capacity: {wire}"
            );
            assert!(!fx.is_open(id), "the used authorization is not reopened");
            assert!(
                fx.receipts
                    .find_by_approval_nonce("approval-nonce-1")
                    .unwrap()
                    .is_some(),
                "the exposed receipt retains its approval binding"
            );
            assert_eq!(fx.audit_kinds(), ["value_action_pending"]);
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
                    chain_scope: Some(crate::policy_state::ChainScope::for_chain(
                        stellar_agent_core::profile::caip2::Caip2::Mainnet,
                    )),
                    fee_bump: None,
                    envelope_hash: decode_intent_hash(&sub.intent.envelope_hash).unwrap(),
                    tx_hash,
                    source: sub.intent.source.clone(),
                    sequence: sub.intent.sequence,
                    max_time: sub.intent.max_time,
                    pending_since_ms: NOW,
                    submission_ledger: sub.intent.submission_ledger,
                    submission_anchor: None,
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
