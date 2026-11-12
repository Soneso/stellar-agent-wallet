//! Persisted per-profile policy window-state store.
//!
//! Backs the stateful policy criteria (`per_period_cap`, `rate_limit`,
//! `bundle_per_period_cap`, `bundle_rate_limit`): the in-memory
//! [`stellar_agent_core::policy::v1::PolicyStateStore`] `PolicyEngineV1` owns
//! is reconstructed fresh at process start with no accumulated history, so
//! without a durable backing store those criteria evaluate every call against
//! zero history and never actually cap anything across calls.
//!
//! [`PersistedWindowStore`] closes that gap: one HMAC-protected, single-writer
//! JSON file per profile at
//! [`stellar_agent_core::profile::schema::default_policy_window_state_path_for`]
//! (`<state>/stellar-agent/policy/<profile>.window`), shared by every process
//! (MCP server, CLI) that evaluates or records against that profile.
//!
//! # Crate placement
//!
//! This store lives in `stellar-agent-network`, not `stellar-agent-core`,
//! because it needs [`crate::keyring::rotate_keyring_secret_32`] /
//! [`crate::keyring::load_hmac_key_32`] to mint and load its HMAC key, and
//! `stellar-agent-core` does not (and must not) depend on
//! `stellar-agent-network` (the dependency runs the other way — verified via
//! the workspace `Cargo.toml` dependency graph). [`stellar_agent_core::policy::v1::PolicyStateStore`]
//! stays the engine-facing in-memory type, unchanged.
//!
//! # Refresh shape (per-process-lifetime discipline)
//!
//! The CLI is a fresh process per invocation: `PolicyEngineV1::new_with_store`
//! is constructed once, hydrated once via [`PersistedWindowStore::load_into`],
//! evaluates, and — on a confirmed commit — records and exits. There is
//! nothing to go stale within that lifetime.
//!
//! The MCP server is a LONG-LIVED process: a single `PolicyEngineV1` instance
//! serves every dispatch for the life of the server. Hydrating it once at
//! construction and never again would mean a CLI-written (or a sibling MCP
//! request's) accumulated entry never becomes visible to this process's
//! evaluations — the server would silently evaluate stateful criteria against
//! a startup-frozen snapshot. `dispatch_gate_inner`
//! (`stellar-agent-mcp::tools::common`) closes this: before every evaluation,
//! it calls [`stellar_agent_core::policy::PolicyEngine::window_state_store`]
//! to reach the engine's in-memory store, `clear()`s it, and re-populates it
//! via `load_into` from the CURRENT on-disk file. This is a REPLACE, not a
//! merge: clearing before re-loading is what prevents an entry a concurrent
//! process has already pruned or a reset has cleared from lingering in this
//! process's view. Construction-time hydration is kept in addition (not
//! replaced by the per-dispatch refresh): it makes the server refuse to
//! start at all on a tampered/unparseable store file, rather than deferring
//! that discovery to first dispatch.
//!
//! # Admission
//!
//! A call passes through the window in three steps.
//!
//! 1. **Evaluation at dispatch.** The policy gate reads this store into the
//!    engine's in-memory view and evaluates the call against it, before the
//!    transaction is built and signed.
//! 2. **Reservation under the lock.** Immediately before the send,
//!    [`PersistedWindowStore::record_pending`] takes the store's exclusive
//!    lock, re-reads and verifies the file, and re-applies the governing
//!    criterion's own comparison against what the file holds at that moment.
//!    Time passes between the two steps, and the profile is shared by every
//!    process on the host, so the state the gate read is not necessarily the
//!    state the reservation meets. A batch any bucket can no longer admit is
//!    refused as [`WindowStoreError::PolicyDenied`], carrying the denial the
//!    criterion produces for that condition, and nothing is written. Each
//!    entry carries the limit that governs it
//!    ([`stellar_agent_core::policy::v1::criteria::state_store::WindowLimit`]),
//!    which is policy rather than history and is never persisted.
//! 3. **Settlement on confirmation.** The reservation counts against every
//!    window criterion while it stands and becomes confirmed spend, or is
//!    released, when the chain answers.
//!
//! Admission is whole-batch: the entries of one submission are written
//! together or not at all, and entries of one batch on one key are measured
//! against each other, so a single call cannot overshoot a bucket by spreading
//! its spend across legs.
//!
//! # Reservation settlement
//!
//! Exposure counts through the signed execution deadline and each admitted
//! window duration. A reported success uses the later of first local observation
//! and the deadline. Reported chain time remains a report. Missing deadlines
//! retain capacity indefinitely; repeat reports preserve the first observation.
//!
//! Endpoint failure, absence, consumed sequence, and time claims release no
//! capacity and create no definitive failed row. A checked accounting decision
//! binds chain, reservation, generation, and evidence. Conservative expiry
//! records `submission.accounting_expired` with the chain outcome unknown.
//! Accounting expiry creates a durable audit obligation in the same
//! authenticated successor. Delivery verifies retained history, appends at
//! most one event per decision identifier in that history, and commits
//! acknowledgement.
//! An explicit operator clear records its acknowledgement before releasing
//! untimed exposure. Bounded clears preserve the accounting horizon.
//!
//! A reservation id names one signed envelope. Duplicate admission refuses
//! under the store lock. Independent witness anchors bind the subject, chain,
//! oracle ledger, authority, digest, and local acquisition time. Legacy bare
//! ledgers remain unanchored observations.
//!
//! # Wire format
//!
//! `[32-byte HMAC-SHA256 tag] || [canonical JSON body]`, mirroring
//! [`crate::counterparty::cache`]'s embedded-tag convention (tag prefix, not a
//! sidecar file) — chosen because, like the counterparty cache, this store has
//! exactly one file per profile and no cross-file chain to protect, so an
//! embedded tag needs no extra file-discovery bookkeeping. `i128` amounts
//! serialise as decimal strings (the `wire_stroops::i128` / audit
//! `i128_decimal_str` convention), never a bare JSON number, so no value is
//! silently truncated by a JSON-number-as-f64 reader. The body also carries a
//! `generation: u64` field; see "Anti-rollback" below.
//!
//! Version 5 authenticates a [`ChainScope`] on the snapshot, each pending
//! debit, and each transaction consumption binding. Its canonical chain and
//! passphrase hash identify one accounting authority, including both sides of
//! a prepared commit. Pruning retains that authority even with no live debits.
//!
//! Versions 1 through 4 decode for integrity checks. An existing snapshot is
//! usable only with complete authenticated scope for all retained history and
//! any prepared successor. A missing scope refuses automatic migration,
//! including an empty snapshot with a committed generation. Profile TOML and
//! receipts cannot establish provenance. Only an absent file and absent
//! protected generation establish a new authority.
//! No verb recovers such state in this release; create a profile under a new name.
//!
//! # Integrity
//!
//! HMAC-SHA256 over a context-separation label plus the exact JSON body
//! bytes, keyed by the profile's `policy_window_state_key_id` keyring
//! coordinate ([`stellar_agent_core::profile::schema::KeyringEntryRef::default_policy_window_state_key`]).
//! A verification failure (mismatched tag, truncated file, or unparseable
//! JSON) is fail-closed: [`load_into`](PersistedWindowStore::load_into)
//! returns an error rather than a partial or empty read, so the stateful
//! criteria that would consult it deny via
//! [`stellar_agent_core::policy::PolicyError::CriterionEvaluationFailed`]
//! instead of silently under-counting.
//!
//! # Anti-rollback: the generation counter
//!
//! HMAC integrity alone does not detect a VALID-LOOKING file from the wrong
//! point in time: an attacker (or an operator's backup/restore tooling) with
//! filesystem access can delete the store file (silently resetting
//! accumulated history to empty) or restore an older, genuinely-signed
//! snapshot (silently rewinding accumulated history) — both bypass every cap
//! without ever failing the HMAC check, because the restored bytes are
//! authentic.
//!
//! A second keyring entry — derived from `policy_window_state_key_id` by
//! suffixing `-generation` onto its `account` field, same `service` — holds a
//! monotonic generation and a SHA-256 commitment to its canonical body, updated
//! together. Numeric counters remain readable for version 1 and 2 files.
//! A settled debit, recorded by
//! [`record_and_persist`](PersistedWindowStore::record_and_persist) or
//! [`record_authorized`](PersistedWindowStore::record_authorized), commits the
//! trusted state before replacing the file, so a failed write refuses later
//! spends. A pending record, the settlement of a reservation and a verified
//! reset commit through the prepared image: they write both the current and
//! candidate snapshots before committing the candidate's generation and digest,
//! so a failed write leaves an authenticated, readable store at either crash
//! checkpoint. An abandoned candidate cannot substitute for a different committed
//! body sharing its generation. Readers reject missing, rolled-back, or
//! substituted state. Initialisation also commits the counter first and fails
//! closed if its file write fails. Key rotation re-signs the existing body while
//! preserving its trusted commitment.
//!
//! # Concurrency
//!
//! [`lock::WindowStoreLock`] is an OFD-advisory exclusive lock on a file in the
//! policy-state directory named by the window-state keyring entry, because the
//! HMAC key, the generation commitment, and the policy pin are named by that
//! entry. It serialises every read-modify-write (record, reset, resign, and
//! every authorization transition) across every store handle over the entry,
//! whatever store path a handle names. It lives in
//! [`stellar_agent_core::policy::state_lock`] and is re-exported here, so the
//! policy pin of [`stellar_agent_core::policy::pin`] is read, written, and
//! compared under the same guard. [`load_into`](PersistedWindowStore::load_into) does not take the
//! lock: the file is only ever replaced via atomic rename (temp file +
//! `sync_data` + rename + parent-directory fsync, mirroring
//! [`stellar_agent_core::audit_log`]'s rotation `write_sidecar_atomic`
//! precedent), so a concurrent reader never observes a torn write.
//!
//! # Retention
//!
//! Entries older than the largest supported criterion window (`1w` =
//! 604,800 s) are pruned on every write once confirmed. Pending records are retained.
//! Accounting-expiry records are retained until audit acknowledgement and
//! receipt projection both complete. Settled authorization records stay while
//! their approval can still be presented, and a window state reset keeps them.
//!
//! A signed intent counts from its admission before the first signature.
//! Envelope cancellation, unwinding and reconciliation never release it.
//!
//! Operation records follow [`operations`]: a terminal record keeps its full
//! form for seven days, at most 256 such records stay, and older ones become
//! tombstones kept for 30 days, at most 1,024. A record whose authorization
//! has no release row stays whatever its age, and so does that authorization.
//! Removing an authorization with a ledger or close-time release bound raises
//! the window's admissible floors in the same commit.
//!
//! Approval records retain consent payloads until the operation ends or execution expires.
//! Identity, disposition, clocks and receipt digests remain for seven days after both windows end.
//! At most 256 closed records stay; records inside either window remain protected.
//! Reset refuses pending approvals inside their waiting windows and preserves every other approval record.

pub mod approvals;
pub mod ledger;
pub mod lock;
pub mod operations;
mod reset_consent;
pub mod store;

use lock::StateLockError;

pub use approvals::{
    APPROVAL_CLOSED_MAX, APPROVAL_EXECUTION_MAX_MS, APPROVAL_RECORD_MAX, APPROVAL_RULE_TTL_MAX_MS,
    ApprovalRecorder, ApprovalState, ApprovalStatus, ApprovalView, Consent, ConsentPayload,
    PendingApprovalFacts, WireApproval,
};
pub use ledger::{
    ClaimExpect, ConsumeExpect, ConsumeReceipt, ConsumptionBinding, DomainBinding, FeeBumpFacts,
    MAX_OPEN_AUTHORIZATIONS, MintAuthority, MintRequest, MintedRecord, OpenAuthorization,
    PolicyAuthorityBinding, SubmissionBinding, WindowReservation,
};
pub use operations::{
    AdmissibleFloors, AgreedOutcome, AttemptAuthorization, AttemptEnvelope, AttemptRequest,
    AttemptStarted, BoundedText, BusinessId, CapacityDetail, ClearForm, CommitBinding, CommitId,
    CommitTarget, ConsumptionExposure, EndpointCoverage, EvidenceAnswer, EvidenceAuditFacts,
    EvidenceClassification, EvidenceEndpoint, EvidenceInput, EvidenceRowInput,
    EvidenceSequenceClass, EvidenceVerdict, ExposureIdentity, IntentSlot, LookupOutcome,
    NotIncludedProof, OpenOutcome, OpenRequest, OperationAudit, OperationAuthority,
    OperationHandle, OperationId, OperationKind, OperationLink, OperationRecorder, OperationResult,
    OperationState, OperationStatus, OperationTool, OperationView, RecoveryUpdate,
    SequenceReleaseInput, SlotKind, TransitionEvidence, WindowObservation, X402Intent,
};
pub use store::{
    AccountingDecision, ChainScope, DeliveryReport, MintOutcome, OwedAccountingExpiries,
    OwnerResetSignature, POLICY_STATE_KEY_FIELD, PersistedWindowStore, RECONCILE_BUDGET,
    RECONCILE_MIN_AGE_MS, REPORTED_SUCCESS_CODE, RETENTION_EXPIRED_CODE, ReconcileFailure,
    ReconcileFailureKind, ReconcileReport, ReportedAnswer, ResetConsent, ResetError, ResetOutcome,
    ResetRecord, ScheduleTerminal, SettledSubmission, SignedIntentLegView, SignedIntentView,
    StateDefect, SubmissionAnchor, SubmissionHold, UnrecordedAnswer, deliver_accounting_expiries,
    deliver_accounting_expiry, drain_accounting_obligations, project_accounting_expiries,
};

/// Records a confirmed call's contribution into `engine`'s window state and
/// persists the new entries to the on-disk store for `profile_name`.
///
/// Records unconditionally, without admission, for spend that has already
/// applied on-chain. Authorized external settlement records through
/// [`record_authorized_window_state`] instead. `value`
/// MUST be the SAME [`stellar_agent_core::policy::v1::ValueClass`] the
/// original gate evaluated (the single-derivation invariant).
///
/// Non-fatal by design: the on-chain action already committed and is
/// irreversible, so a recording failure here is surfaced via `tracing::warn!`
/// rather than propagated. A
/// failed record means the NEXT call under-counts against the accumulated
/// window — that is loud in the log, not silent.
pub fn record_confirmed_window_state(
    engine: &dyn stellar_agent_core::policy::PolicyEngine,
    tool: &stellar_agent_core::policy::ToolDescriptor,
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    value: &stellar_agent_core::policy::v1::ValueClass,
) {
    let recorded = match engine.record_confirmed(tool, profile, value) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                profile = %profile_name,
                tool = %tool.name,
                error = %e,
                "policy window-state record_confirmed failed post-confirm; the next call's \
                 accumulated window total under-counts this one"
            );
            return;
        }
    };
    if recorded.is_empty() {
        return;
    }
    let window_store = PersistedWindowStore::for_profile(profile_name);
    if let Err(e) = window_store.record_and_persist(profile, &recorded) {
        tracing::warn!(
            profile = %profile_name,
            tool = %tool.name,
            error = ?e,
            "policy window-state persist failed post-confirm; the next call's accumulated \
             window total under-counts this one"
        );
    }
}

/// Records authorized external-settlement value before payment signing and
/// propagates every failure to the caller.
///
/// MPP and x402 call this before constructing payment credentials, so an
/// accounting refusal withholds the authorization.
///
/// # Errors
///
/// Returns a typed window-store error when in-memory accounting or durable
/// persistence fails, or the shared window cannot admit the authorization.
pub fn record_authorized_window_state(
    engine: &dyn stellar_agent_core::policy::PolicyEngine,
    tool: &stellar_agent_core::policy::ToolDescriptor,
    profile: &stellar_agent_core::profile::schema::Profile,
    profile_name: &str,
    value: &stellar_agent_core::policy::v1::ValueClass,
) -> Result<(), WindowStoreError> {
    let recorded = engine
        .record_confirmed(tool, profile, value)
        .map_err(|error| WindowStoreError::Invalid {
            detail: format!("policy authorization accounting failed: {error}"),
        })?;
    if recorded.is_empty() {
        return Ok(());
    }
    PersistedWindowStore::for_profile(profile_name)
        .record_authorized(profile, &recorded)
        .map(|_outcome| ())
}

/// Error variants for [`PersistedWindowStore`] operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WindowStoreError {
    /// A signing or binding differs from the admitted authority.
    #[error("the signed intent differs at {field}")]
    IntentBindingMismatch {
        /// The fixed mismatching field.
        field: &'static str,
    },
    /// The window holds signed authority that cannot be reset.
    #[error(
        "the spending window holds signed intents (authorization exposed, submission unknown: {exposed}; bound: {bound}); the reset refuses while any stands.{separator}{explanation}",
        separator = if .explanation.is_empty() { "" } else { " " }
    )]
    SignedIntentLive {
        /// Applicable purpose and endpoint explanations.
        explanation: String,
        /// The number of intents without a bound submission.
        exposed: usize,
        /// The number of intents with a bound submission.
        bound: usize,
    },
    /// The selected network disagrees with authenticated spending state.
    #[error(
        "the profile network disagrees with authenticated spending state. Restore the profile's network, or create a profile under a new name."
    )]
    ChainMismatch,

    /// Retained state has no complete authenticated network provenance.
    #[error(
        "spending state has no complete authenticated network provenance. No verb recovers such state in this release; create a profile under a new name."
    )]
    ChainUnverifiable,

    /// Another process or task holds the exclusive write lock.
    #[error("policy window-state store writer is locked by another process")]
    WriterLocked,

    /// An I/O error occurred reading or writing the store file or lock file.
    #[error("policy window-state store I/O error: {kind:?}")]
    Io {
        /// The underlying I/O error kind.
        kind: std::io::ErrorKind,
    },

    /// The store file is structurally invalid (truncated, missing the
    /// expected HMAC prefix, or not valid JSON).
    #[error("policy window-state store file is invalid: {detail}")]
    Invalid {
        /// Operator-facing detail. MUST NOT include key material.
        detail: String,
    },

    /// The authenticated file was written by a newer build.
    #[error(
        "policy window-state version must be supported by this build; use the build that wrote \
         the file"
    )]
    UnsupportedVersion,

    /// The store file's HMAC tag does not match the recomputed value —
    /// tampering, corruption, or a stale key.
    #[error("policy window-state store HMAC mismatch — possible tampering or rotation")]
    HmacMismatch,

    /// The store file's `generation` does not match the keyring-held
    /// generation counter, or one of the two is present without the other —
    /// a deleted-and-recreated file, a restored older snapshot, or a deleted
    /// generation counter. See the module docs' "Anti-rollback" section.
    ///
    /// For a mainnet profile in a build with mainnet writes, this condition,
    /// like every other unverifiable state, refuses as
    /// `MainnetStateUnverifiable` naming its defect instead.
    #[error(
        "policy window-state store generation mismatch, possible deletion or rollback. \
         No verb recovers such state in this release; create a profile under a new name."
    )]
    GenerationMismatch,

    /// The HMAC keyring entry could not be loaded or minted.
    #[error("policy window-state store keyring error: {detail}")]
    Keyring {
        /// Operator-facing detail. MUST NOT include key material.
        detail: String,
    },

    /// The HMAC key's coordinate sits in the owner key namespace, or the
    /// loaded key equals the profile's owner public key. Nothing is minted.
    #[error(
        "policy window-state store key refused (validation.key_matches_owner_public_key): \
         `policy_window_state_key_id` is an owner public key or sits in the owner key namespace"
    )]
    KeyMatchesOwnerPublicKey,

    /// The profile key coordinate names the reserved installation service.
    #[error(
        "`policy_window_state_key_id` names the reserved service `stellar-agent-toolsets` (validation.installation_key_coordinate)"
    )]
    InstallationKeyCoordinate,

    /// A window bucket cannot admit the reservation.
    ///
    /// Produced by [`PersistedWindowStore::record_pending`] when it re-applies
    /// the governing criterion's comparison under the store's lock, against
    /// the state the file holds at that moment, and the batch would take a
    /// bucket past its limit. Nothing is written: the batch is admitted whole
    /// or refused whole.
    ///
    /// `reason` is the denial the criterion itself produces for the same
    /// condition, built from the limit the entry carries, so the surface that
    /// reports it names the gate's own wire code.
    #[error("policy denied this reservation: {}", reason.wire_code())]
    PolicyDenied {
        /// The typed denial, built from the refused entry's limit.
        reason: Box<stellar_agent_core::policy::DenyReason>,
    },

    /// The window state holds an accounting-expiry audit obligation that
    /// delivery has not acknowledged.
    ///
    /// Produced by [`PersistedWindowStore::reset`] before either callback
    /// runs. The successor would erase the obligation, so the reset refuses
    /// until the owed `submission_accounting_expired` event is delivered. The
    /// reset changes no window state.
    #[error(
        "the spending window owes an accounting audit event that is not delivered yet; the \
         reset refuses until it is"
    )]
    AccountingAuditOwed,

    /// The reset names a profile other than the one the profile's owner
    /// coordinate names. The reset changes no window state.
    #[error("the window state reset names a profile other than the one the profile file names")]
    ResetProfileMismatch,

    /// The reset requires the policy owner's signature and presents none.
    #[error("the window state reset requires the policy owner's signature")]
    ResetOwnerRequired,

    /// The enrolled owner cannot be read or decoded under the reset guard.
    #[error("the enrolled owner cannot be read for the window state reset: {0}")]
    ResetOwnerUnreadable(
        /// The classified owner entry failure.
        stellar_agent_core::error::WalletError,
    ),

    /// The reset is signed by a key other than the selected policy owner. The
    /// reset changes no window state.
    #[error("the window state reset signature names an owner other than the selected policy owner")]
    ResetOwnerMismatch {
        /// The owner public key the presented signature names.
        presented: [u8; 32],
        /// The owner public key selected from the pin or enrollment.
        pinned: [u8; 32],
    },

    /// The reset presents an owner signature and no policy pin names an owner.
    /// The reset changes no window state.
    #[error("no policy pin names an owner for this window state store")]
    ResetPinAbsent,

    /// The policy pin cannot be read under the reset's lock. The reset changes
    /// no window state.
    #[error("the policy pin cannot be read for the window state reset: {0}")]
    ResetPinUnreadable(
        /// The pin read failure.
        stellar_agent_core::policy::pin::PinError,
    ),

    /// The mainnet enablement nonce cannot be read. The reset changes no
    /// window state.
    #[error("the mainnet enablement nonce cannot be read for the window state reset: {0}")]
    ResetEnablementUnreadable(
        /// The nonce read failure.
        stellar_agent_core::error::ValidationError,
    ),

    /// The owner signature does not verify over this reset's statement. The
    /// reset changes no window state.
    #[error("the owner's signature does not verify over this window state reset")]
    ResetSignatureInvalid,

    /// The latest reset already consumes this request id.
    #[error("{0}", stellar_agent_core::policy::PolicyError::ResetConsentReplayed)]
    ResetConsentReplayed,

    /// The file already holds a record under the reservation's id.
    ///
    /// Produced by [`PersistedWindowStore::record_pending`], and by
    /// [`PersistedWindowStore::consume_authorizations`] for an envelope the
    /// window holds, under the store's lock. The id is the envelope hash of the
    /// signed bytes, so the window has already counted these bytes: the
    /// submission that wrote the record settles them. The duplicate is refused
    /// before another reservation can count that spend. Nothing is written.
    #[error("the spending window already holds a reservation for these signed bytes")]
    DuplicateReservation,

    /// An earlier authorization consumed this transaction's envelope hash.
    ///
    /// Produced by [`PersistedWindowStore::consume_authorizations`] under the
    /// store's lock, even when the earlier authorization had no holds.
    /// Nothing is written.
    #[error("the authorization ledger already consumed these signed bytes")]
    DuplicateConsumption,

    /// A mainnet authorization transition refused: a precondition of the mint,
    /// the consumption, or the invalidation does not hold. The store file is not written.
    #[error("the mainnet authorization ledger refused: {precondition}")]
    AuthorizationRefused {
        /// The broken precondition.
        precondition: crate::mainnet::MainnetPrecondition,
    },

    /// The store of a mainnet profile cannot be verified, so neither its
    /// spend history nor its authorizations are known.
    ///
    /// Produced in place of the generic integrity errors for a mainnet
    /// profile in a build with mainnet writes. No verb recovers such state in this release; create a profile under a new name.
    #[cfg(feature = "mainnet-write")]
    #[error(
        "policy.window_state_unverifiable: the policy window-state of this mainnet profile \
         cannot be verified ({defect}). No verb recovers such state in this release; create a profile under a new name."
    )]
    MainnetStateUnverifiable {
        /// The defect found.
        defect: StateDefect,
    },

    /// The business id names a retained operation or tombstone with another
    /// intent digest or slot kind, or an attempt presents an envelope other
    /// than the one its record holds. Nothing is written.
    #[error(
        "operation.business_id_conflict: the business id names a retained operation with \
         another intent"
    )]
    BusinessIdConflict,

    /// A commit presents a business id other than the one its preparation
    /// opened. Nothing is written.
    #[error(
        "operation.business_id_mismatch: the business id differs from the one the \
         preparation opened"
    )]
    BusinessIdMismatch,

    /// A new operation record, its intent or its envelope exceeds an
    /// allowance of the spending window, or an attempt's envelope does.
    /// Nothing is written.
    #[error("operation.capacity: the spending window cannot hold the operation ({detail})")]
    OperationCapacity {
        /// The exceeded limit.
        detail: operations::CapacityDetail,
    },

    /// The operation already has an attempt in progress. Nothing is written.
    #[error("operation.attempt_open: the operation already has an attempt in progress")]
    AttemptOpen,

    /// The operation has made every attempt it may make. Nothing is written.
    #[error("operation.attempt_limit: the operation has made all of its attempts")]
    AttemptLimit,

    /// The reset refuses because an operation has not reached a terminal
    /// state. The reset changes no window state.
    #[error(
        "reset.operations_open: the spending window holds {open} open operation(s); the reset \
         refuses until each ends"
    )]
    OperationsOpen {
        /// The number of operations outside a terminal state.
        open: usize,
    },

    /// The reset refuses while approvals remain inside their waiting windows.
    #[error("reset.approvals_pending: the spending window holds {pending} pending approval(s)")]
    ApprovalsPending {
        /// The number of pending approvals inside their waiting windows.
        pending: usize,
    },

    /// The audit row of an operation step could not be appended. The step
    /// is not committed.
    #[error("audit.append_failed: the operation step's audit row was not appended ({detail})")]
    AuditAppendFailed {
        /// The writer's failure. MUST NOT include key material.
        detail: String,
    },

    /// An operation record reached a state its rules exclude: an edge
    /// outside the state table, or a commit identifier beyond the record's
    /// allowance. Nothing is written.
    #[error("internal.unexpected_state: {detail}")]
    UnexpectedState {
        /// The broken rule.
        detail: String,
    },

    /// The reset of a mainnet profile's verifiable store refuses because a
    /// mainnet authorization is still open. The reset changes no window state.
    #[cfg(feature = "mainnet-write")]
    #[error(
        "the policy window-state holds {open} open mainnet authorization(s); the reset refuses \
         until each is used or expires"
    )]
    OpenAuthorizations {
        /// The number of effective open authorizations.
        open: usize,
    },
}

/// The sentence that ends a refusal of state no verb recovers.
const NO_RECOVERY_NOTICE: &str =
    "No verb recovers such state in this release; create a profile under a new name.";

impl From<StateLockError> for WindowStoreError {
    fn from(error: StateLockError) -> Self {
        match error {
            StateLockError::WriterLocked => Self::WriterLocked,
            StateLockError::Io { kind } => Self::Io { kind },
            _ => Self::Io {
                kind: std::io::ErrorKind::Other,
            },
        }
    }
}

impl WindowStoreError {
    /// The value-free validation refusal for an authenticated scope failure.
    #[must_use]
    pub fn chain_validation_error(&self) -> Option<stellar_agent_core::error::ValidationError> {
        use stellar_agent_core::error::ValidationError;
        match self {
            Self::ChainMismatch => Some(ValidationError::WindowChainMismatch),
            Self::ChainUnverifiable => Some(ValidationError::WindowChainUnverifiable),
            _ => None,
        }
    }

    /// The wallet refusal an operation store failure names, when it names
    /// one: the business id, capacity, attempt, reset, audit and state-rule
    /// refusals of the operation section.
    #[must_use]
    pub fn operation_error(&self) -> Option<stellar_agent_core::error::WalletError> {
        use stellar_agent_core::error::{InternalError, SubmissionError, ValidationError};
        Some(match self {
            Self::BusinessIdConflict => ValidationError::OperationBusinessIdConflict.into(),
            Self::BusinessIdMismatch => ValidationError::OperationBusinessIdMismatch.into(),
            Self::OperationCapacity { detail } => SubmissionError::OperationCapacity {
                detail: detail.label(),
            }
            .into(),
            Self::AttemptOpen => SubmissionError::OperationAttemptOpen.into(),
            Self::AttemptLimit => SubmissionError::OperationAttemptLimit.into(),
            Self::OperationsOpen { open } => {
                ValidationError::ResetOperationsOpen { open: *open }.into()
            }
            Self::ApprovalsPending { pending } => {
                ValidationError::ResetApprovalsPending { pending: *pending }.into()
            }
            Self::AuditAppendFailed { detail } => ValidationError::AuditAppendFailed {
                detail: detail.clone(),
            }
            .into(),
            Self::UnexpectedState { detail } => InternalError::UnexpectedState {
                detail: detail.clone(),
            }
            .into(),
            _ => return None,
        })
    }

    /// The business code for a state read or submission reservation refusal.
    #[must_use]
    pub fn submission_code(&self) -> &'static str {
        if let Some(error) = self.chain_validation_error() {
            return error.code();
        }
        self.operation_error()
            .map_or("submission.record_unavailable", |error| error.code())
    }

    /// Ends `refusal` with the no-recovery sentence when the store failed its
    /// integrity check. A backend failure can clear, and the other unverifiable
    /// states carry the sentence in their own text.
    #[must_use]
    pub fn with_recovery_notice(&self, refusal: String) -> String {
        if matches!(self, Self::HmacMismatch | Self::Invalid { .. }) {
            format!("{refusal}. {NO_RECOVERY_NOTICE}")
        } else {
            refusal
        }
    }
}

#[cfg(test)]
pub(super) mod reset_test {
    use super::store::{OwnerResetSignature, ResetConsent, ResetRecord};

    /// The owner public key for the fixture seed.
    pub(super) fn owner_of(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    /// Signs the exact reset statement with the fixture seed.
    pub(super) fn signed_by(seed: u8, row: &ResetRecord<'_>) -> ResetConsent {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        ResetConsent {
            owner_signature: Some(OwnerResetSignature {
                owner: owner_of(seed),
                signature: stellar_agent_core::policy::v1::signature::sign(
                    &row.statement_digest(),
                    &key,
                ),
            }),
        }
    }
}

#[cfg(test)]
mod display_tests {
    use super::WindowStoreError;

    #[test]
    fn signed_intent_live_explanation_has_only_its_required_space() {
        let base = "the spending window holds signed intents (authorization exposed, submission unknown: 1; bound: 2); the reset refuses while any stands.";
        for (explanation, expected) in [
            ("", base.to_owned()),
            ("Retained intent.", format!("{base} Retained intent.")),
        ] {
            let error = WindowStoreError::SignedIntentLive {
                explanation: explanation.into(),
                exposed: 1,
                bound: 2,
            };
            assert_eq!(error.to_string(), expected);
        }
    }
}
