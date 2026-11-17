//! The authenticated record of one mainnet approval.
//!
//! Consent fixes an execution window. Minting consumes the record in the
//! authorization's generation commit, and only its operation can reuse it.

use std::collections::HashSet;

pub mod status;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::WalletError;
use stellar_agent_core::approval::{
    AttestationBinding, AttestationScope, AttestedApprover, AttestedLifetime, load_attestation_key,
    mainnet_attestation_version,
    presence::MainnetPresenceReceipt,
    subject::{SubjectKind, length_prefixed},
    verify_attestation,
    witness::{
        ApprovalConsentFacts, ApprovalDisposition, ApprovalFacts, ApprovalPayloadFacts,
        ApprovalRecordFacts, ApprovalWitness, ApprovedKind,
    },
};
use stellar_agent_core::audit_log::{
    AuditOutbox, EvidenceReservation, OutboxRowRef, PolicyDecision, WriterError,
    audit_writer_refusal,
};
use stellar_agent_core::policy::state_lock::WindowStoreLock;
use stellar_agent_core::profile::{
    Profile, name::profile_name_for_approval, owner_key::OwnerKeyContext,
};

use super::WindowStoreError;
use super::notices::CommittedBatch;
use super::operations::{
    APPROVAL_NONCE_MAX, CapacityDetail, FILE_THRESHOLD, OperationAudit, OperationId, OperationLink,
    OperationRecorder, Session, WindowSection,
};
use super::store::{PersistedWindowStore, RETENTION_MS, WIRE_VERSION_OPERATIONS, WireFile, now_ms};
use crate::mainnet::{MainnetPrecondition, types::hex32};

/// The longest execution window after consent, in milliseconds: the
/// witness's own bound, so the record and the witness agree on it.
pub const APPROVAL_EXECUTION_MAX_MS: u64 =
    stellar_agent_core::approval::witness::APPROVAL_EXECUTION_MAX_MS;
/// The longest approval rule lifetime, in milliseconds.
pub const APPROVAL_RULE_TTL_MAX_MS: u64 = 86_400_000;
/// The closed-record cap; records inside either window remain protected.
pub const APPROVAL_CLOSED_MAX: usize = 256;
/// The serialized record allowance, including a receipt at its decoded bounds.
pub const APPROVAL_RECORD_MAX: usize = 16_384;
const PROCESS_UID_MAX: usize = 256;
const ID_DOMAIN: &[u8] = b"stellar-agent-wallet/approval-record/v1";

/// The stored disposition of an approval. Expiry is derived from its clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Consent or execution can still occur within the applicable window.
    Pending,
    /// The linked operation consumes the approval at its first mint.
    Consumed,
    /// Every later mint refuses.
    Revoked,
}

/// The signed pending facts and the operation's intent digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApprovalFacts {
    /// The inbox nonce.
    pub nonce: String,
    /// The kind the witness approves.
    pub kind: ApprovedKind,
    /// The subject's binding convention.
    pub subject_kind: SubjectKind,
    /// The signed subject.
    pub subject: [u8; 32],
    /// The linked operation's intent digest.
    pub intent_digest: [u8; 32],
    /// The inbox's signed creation time.
    pub created_at_ms: u64,
    /// The inbox's signed waiting expiry.
    pub waiting_expires_at_ms: u64,
    /// The governing rule's lifetime.
    pub rule_ttl_ms: u64,
}

/// The retained inputs for reconstructing the consent attestation, under the
/// version the record's subject kind selects.
// The other inputs are the record's identity, subject, kind and signed times.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPayload {
    /// The authenticated attestation bytes.
    #[serde(with = "hex32")]
    pub attestation: [u8; 32],
    /// The receipt containing the approver credential and verified time.
    pub receipt: MainnetPresenceReceipt,
    /// The signed inbox process identifier.
    pub process_uid: String,
    /// The retained queued consent reference for delivery enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbox_row: Option<OutboxRowRef>,
    /// The original consent challenge subject, required for intent payloads.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::ledger::opt_hex32"
    )]
    pub challenge_subject: Option<[u8; 32]>,
    /// Why no queued reference is retained; present exactly when
    /// `outbox_row` is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_provenance: Option<RowProvenance>,
}

/// Where the consent audit row of a payload without a queued reference went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowProvenance {
    /// The consenting process wrote the row to the audit log directly.
    Written,
    /// The consent was recovered from an attested inbox entry, and the
    /// row's queue reference, if any, was not retained.
    Recovered,
}

/// The consent audit row of one consent, as its producer knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentRow {
    /// The row went to the audit log directly.
    Written,
    /// The row waits in the keyed outbox under this reference.
    Queued(OutboxRowRef),
    /// The consent is recovered from an attested inbox entry.
    Recovered,
}

impl ConsentPayload {
    /// The payload of `attestation` and `receipt`, stating where its row went.
    /// The challenge subject stays empty; `record_consent` fills it for an
    /// intent record.
    #[must_use]
    pub fn new(
        attestation: [u8; 32],
        receipt: MainnetPresenceReceipt,
        process_uid: String,
        row: ConsentRow,
    ) -> Self {
        let (outbox_row, row_provenance) = match row {
            ConsentRow::Written => (None, Some(RowProvenance::Written)),
            ConsentRow::Queued(reference) => (Some(reference), None),
            ConsentRow::Recovered => (None, Some(RowProvenance::Recovered)),
        };
        Self {
            attestation,
            receipt,
            process_uid,
            outbox_row,
            challenge_subject: None,
            row_provenance,
        }
    }

    fn row_consistent(&self) -> bool {
        self.outbox_row.is_some() != self.row_provenance.is_some()
    }

    /// A stored payload names at most one of a reference and a provenance.
    /// A payload with neither is the earlier direct form, which reads as
    /// stored.
    fn row_readable(&self) -> bool {
        self.outbox_row.is_none() || self.row_provenance.is_none()
    }
}

impl std::fmt::Debug for ConsentPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentPayload").finish_non_exhaustive()
    }
}

/// The successful sink that produced a consent row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentProvenance {
    /// The direct writer anchored the row before returning success.
    DirectAnchored,
    /// The outbox returned a reference whose delivery must be checked.
    Queued,
}

/// Delivery metadata authenticated by the enclosing window commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentDeliveryV1 {
    #[serde(deserialize_with = "delivery_version")]
    v: u8,
    #[serde(with = "hex32")]
    identity: [u8; 32],
    provenance: ConsentProvenance,
}

fn delivery_version<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    let version = u8::deserialize(d)?;
    if version != 1 {
        return Err(serde::de::Error::custom(
            "unsupported consent delivery version",
        ));
    }
    Ok(version)
}

impl ConsentDeliveryV1 {
    /// Records successful strict direct anchoring for an authenticated identity.
    #[must_use]
    pub fn direct_anchored(identity: [u8; 32]) -> Self {
        Self {
            v: 1,
            identity,
            provenance: ConsentProvenance::DirectAnchored,
        }
    }

    /// Records a queued sink for an authenticated identity.
    #[must_use]
    pub fn queued(identity: [u8; 32]) -> Self {
        Self {
            v: 1,
            identity,
            provenance: ConsentProvenance::Queued,
        }
    }

    fn matches(&self, id: [u8; 32], reference: Option<&OutboxRowRef>) -> bool {
        self.identity == id && (self.provenance == ConsentProvenance::Queued) == reference.is_some()
    }
}

/// The immutable consent clock and receipt identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    /// The receipt's verified time.
    pub consent_at_ms: u64,
    /// The exclusive execution boundary.
    pub execution_expires_at_ms: u64,
    /// The receipt digest, retained after payload release.
    #[serde(with = "hex32")]
    pub receipt_sha256: [u8; 32],
    /// Reconstruction inputs, released when execution ends or the operation ends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<ConsentPayload>,
    /// Authenticated sink provenance, retained after payload release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<ConsentDeliveryV1>,
}

/// One approval in the authenticated profile and chain scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireApproval {
    /// The domain-separated digest of profile and nonce.
    #[serde(with = "hex32")]
    pub id: [u8; 32],
    /// The inbox nonce.
    pub nonce: String,
    /// The approved kind.
    #[serde(with = "approved_kind")]
    pub kind: ApprovedKind,
    /// The subject's binding convention.
    pub subject_kind: SubjectKind,
    /// The signed subject.
    #[serde(with = "hex32")]
    pub subject: [u8; 32],
    /// The operation slot's intent digest.
    #[serde(with = "hex32")]
    pub intent_digest: [u8; 32],
    /// The only operation this approval authorizes.
    pub operation_id: OperationId,
    /// The stored disposition.
    pub state: ApprovalState,
    /// The signed inbox creation time.
    pub created_at_ms: u64,
    /// The exclusive signed waiting boundary.
    pub waiting_expires_at_ms: u64,
    /// The governing rule's lifetime.
    pub rule_ttl_ms: u64,
    /// The write-once consent.
    pub consent: Option<Consent>,
    /// The first mint's time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at_ms: Option<u64>,
    /// The revocation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<u64>,
    /// The operation closure, revocation or end of both clocks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at_ms: Option<u64>,
}

impl WireApproval {
    fn expiry(&self) -> u64 {
        self.consent
            .as_ref()
            .map_or(self.waiting_expires_at_ms, |c| c.execution_expires_at_ms)
    }

    fn both_ended(&self, now: u64) -> bool {
        now >= self.waiting_expires_at_ms && now >= self.expiry()
    }

    fn view(&self, now: u64) -> ApprovalView {
        ApprovalView {
            record: self.clone(),
            expired: now >= self.expiry(),
        }
    }

    /// The immutable pending facts authenticated by this record's store.
    #[must_use]
    pub fn facts(&self) -> PendingApprovalFacts {
        PendingApprovalFacts {
            nonce: self.nonce.clone(),
            kind: self.kind,
            subject_kind: self.subject_kind,
            subject: self.subject,
            intent_digest: self.intent_digest,
            created_at_ms: self.created_at_ms,
            waiting_expires_at_ms: self.waiting_expires_at_ms,
            rule_ttl_ms: self.rule_ttl_ms,
        }
    }
}

/// A record and its expiry at the store clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalView {
    /// The authenticated record, with any released payload omitted.
    pub record: WireApproval,
    /// Whether the applicable exclusive boundary passes.
    pub expired: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ApprovalsSection {
    pub(super) records: Vec<WireApproval>,
}

pub(super) fn has_content(wire: &WireFile) -> bool {
    !section_absent(&wire.approvals)
}

pub(super) fn section_absent(section: &Option<ApprovalsSection>) -> bool {
    section.as_ref().is_none_or(|s| s.records.is_empty())
}

fn records(wire: &WireFile) -> &[WireApproval] {
    wire.approvals
        .as_ref()
        .map_or(&[], |s| s.records.as_slice())
}

fn unexpected(detail: &str) -> WindowStoreError {
    WindowStoreError::UnexpectedState {
        detail: detail.to_owned(),
    }
}

fn invalid(detail: &str) -> WindowStoreError {
    WindowStoreError::Invalid {
        detail: detail.to_owned(),
    }
}

fn serialized_len(value: &impl Serialize) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |v| v.len())
}

fn record_id(profile: &str, nonce: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ID_DOMAIN);
    length_prefixed(&mut hash, profile.as_bytes());
    length_prefixed(&mut hash, nonce.as_bytes());
    hash.finalize().into()
}

fn waiting_valid(created: u64, expiry: u64, ttl: u64) -> bool {
    (1..=APPROVAL_RULE_TTL_MAX_MS).contains(&ttl) && created.checked_add(ttl) == Some(expiry)
}

fn execution_expiry(at: u64, ttl: u64) -> Result<u64, WindowStoreError> {
    at.checked_add(ttl.min(APPROVAL_EXECUTION_MAX_MS))
        .ok_or_else(|| unexpected("the approval execution clock overflows"))
}

fn check_consent_time(record: &WireApproval, at: u64) -> Result<(), WindowStoreError> {
    if record.state != ApprovalState::Pending
        || at < record.created_at_ms
        || at >= record.waiting_expires_at_ms
    {
        return Err(unexpected(
            "the approval cannot receive consent outside its waiting window",
        ));
    }
    Ok(())
}

fn inbox_kind(kind: ApprovedKind) -> Result<&'static str, WindowStoreError> {
    match kind {
        ApprovedKind::Payment => Ok("PaymentSimulated"),
        ApprovedKind::Claim => Ok("ClaimSimulated"),
        ApprovedKind::Trustline => Ok("TrustlineSimulated"),
        ApprovedKind::X402Payment => Ok("X402Payment"),
        _ => Err(unexpected("the approval kind is unsupported")),
    }
}

mod approved_kind {
    use super::*;
    pub fn serialize<S: serde::Serializer>(kind: &ApprovedKind, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match kind {
            ApprovedKind::Payment => "payment",
            ApprovedKind::Claim => "claim",
            ApprovedKind::Trustline => "trustline",
            ApprovedKind::X402Payment => "x402_payment",
            _ => return Err(serde::ser::Error::custom("unsupported approval kind")),
        })
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<ApprovedKind, D::Error> {
        match String::deserialize(d)?.as_str() {
            "payment" => Ok(ApprovedKind::Payment),
            "claim" => Ok(ApprovedKind::Claim),
            "trustline" => Ok(ApprovedKind::Trustline),
            "x402_payment" => Ok(ApprovedKind::X402Payment),
            _ => Err(serde::de::Error::custom("unsupported approval kind")),
        }
    }
}

/// The approval section's validation, reset and retention hooks.
pub(super) struct Approvals;

impl WindowSection for Approvals {
    type Survivors = Option<ApprovalsSection>;

    fn validate(wire: &WireFile) -> Result<(), WindowStoreError> {
        if has_content(wire)
            && (wire.version < WIRE_VERSION_OPERATIONS
                || wire.chain_scope.as_ref()
                    != Some(&super::store::ChainScope::for_chain(
                        stellar_agent_core::profile::caip2::Caip2::Mainnet,
                    )))
        {
            return Err(invalid(
                "approval records require a scoped mainnet version 11 image",
            ));
        }
        let mut ids = HashSet::new();
        let mut nonces = HashSet::new();
        let mut operations = HashSet::new();
        for record in records(wire) {
            if !ids.insert(record.id)
                || !nonces.insert(&record.nonce)
                || !operations.insert(record.operation_id)
                || record.nonce.is_empty()
                || record.nonce.len() > APPROVAL_NONCE_MAX
                || !waiting_valid(
                    record.created_at_ms,
                    record.waiting_expires_at_ms,
                    record.rule_ttl_ms,
                )
                || record
                    .closed_at_ms
                    .is_some_and(|at| at < record.created_at_ms)
                || serialized_len(record) > APPROVAL_RECORD_MAX
            {
                return Err(invalid(
                    "an approval has inconsistent identity, clocks or bounds",
                ));
            }
            if let Some(op) = wire
                .operations
                .as_ref()
                .and_then(|s| s.records.iter().find(|op| op.id == record.operation_id))
                && (op.approval_record_id != Some(record.id)
                    || op.intent.intent_digest() != record.intent_digest
                    || record.id != record_id(&op.profile, &record.nonce))
            {
                return Err(invalid("an approval does not match its operation"));
            }
            if let Some(consent) = &record.consent {
                if consent.consent_at_ms < record.created_at_ms
                    || consent.consent_at_ms >= record.waiting_expires_at_ms
                    || execution_expiry(consent.consent_at_ms, record.rule_ttl_ms).ok()
                        != Some(consent.execution_expires_at_ms)
                {
                    return Err(invalid("an approval has inconsistent consent clocks"));
                }
                if let Some(payload) = &consent.payload
                    && (payload.process_uid.is_empty()
                        || payload.process_uid.len() > PROCESS_UID_MAX
                        || !payload.row_readable()
                        || payload.receipt.digest() != Some(consent.receipt_sha256)
                        || payload.challenge_subject.is_some()
                            != (record.subject_kind == SubjectKind::IntentDigest)
                        || payload.receipt.verified_at_unix_ms() != consent.consent_at_ms)
                {
                    return Err(invalid("an approval has inconsistent consent payload"));
                }
            }
            if record.consumed_at_ms.is_some_and(|at| {
                record
                    .consent
                    .as_ref()
                    .is_none_or(|c| at < c.consent_at_ms || at >= c.execution_expires_at_ms)
            }) || record.revoked_at_ms.is_some_and(|at| {
                at < record.created_at_ms
                    || record.consumed_at_ms.is_some_and(|consumed| at < consumed)
            }) {
                return Err(invalid("an approval has inconsistent disposition clocks"));
            }
            let consistent = match record.state {
                ApprovalState::Pending => {
                    record.consumed_at_ms.is_none() && record.revoked_at_ms.is_none()
                }
                ApprovalState::Consumed => {
                    record.consent.is_some()
                        && record.consumed_at_ms.is_some()
                        && record.revoked_at_ms.is_none()
                }
                ApprovalState::Revoked => record.revoked_at_ms.is_some(),
            };
            if !consistent {
                return Err(invalid("an approval disposition lacks its required facts"));
            }
        }
        Ok(())
    }

    fn on_reset(wire: Option<&WireFile>, now: u64) -> Result<Self::Survivors, WindowStoreError> {
        let Some(wire) = wire else { return Ok(None) };
        let pending = records(wire)
            .iter()
            .filter(|r| r.state == ApprovalState::Pending && now < r.waiting_expires_at_ms)
            .count();
        if pending > 0 {
            return Err(WindowStoreError::ApprovalsPending { pending });
        }
        Ok(wire.approvals.clone())
    }

    fn prune(wire: &mut WireFile, now: u64) {
        let Some(section) = &mut wire.approvals else {
            return;
        };
        for record in &mut section.records {
            let terminal = wire.operations.as_ref().and_then(|s| {
                s.records
                    .iter()
                    .find(|op| op.id == record.operation_id)
                    .filter(|op| op.state.is_terminal())
                    .and_then(|op| op.closed_at_ms)
                    .or_else(|| {
                        s.tombstones
                            .iter()
                            .find(|op| op.id == record.operation_id)
                            .map(|op| op.closed_at_ms)
                    })
            });
            if let Some(consent) = &mut record.consent
                && (terminal.is_some() || now >= consent.execution_expires_at_ms)
            {
                consent.payload = None;
            }
            if record.closed_at_ms.is_none() {
                record.closed_at_ms = terminal.or_else(|| {
                    record
                        .both_ended(now)
                        .then_some(record.waiting_expires_at_ms.max(record.expiry()))
                });
            }
        }
        section.records.retain(|r| {
            !r.both_ended(now)
                || now.saturating_sub(
                    r.waiting_expires_at_ms
                        .max(r.expiry())
                        .max(r.closed_at_ms.unwrap_or(0)),
                ) < RETENTION_MS
        });
        let mut closed: Vec<_> = section
            .records
            .iter()
            .filter(|r| r.both_ended(now))
            .map(|r| {
                (
                    r.closed_at_ms
                        .unwrap_or_else(|| r.waiting_expires_at_ms.max(r.expiry())),
                    r.id,
                )
            })
            .collect();
        closed.sort_unstable();
        let evict: HashSet<_> = closed
            .iter()
            .take(closed.len().saturating_sub(APPROVAL_CLOSED_MAX))
            .map(|(_, id)| *id)
            .collect();
        section.records.retain(|r| !evict.contains(&r.id));
    }
}

/// Counts the calls into [`ApprovalRecorder`] and [`ApprovalStatus`] by
/// window-state file, so a test proves that a path makes none.
#[cfg(any(test, feature = "test-helpers"))]
pub mod facade_calls {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static CALLS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    pub(super) fn note(path: &Path) {
        if let Ok(mut calls) = CALLS.lock() {
            calls.push(path.to_path_buf());
        }
    }

    /// The facade calls on the window-state file at `path` in this process,
    /// reads included.
    #[must_use]
    pub fn count(path: &Path) -> usize {
        CALLS.lock().map_or(0, |calls| {
            calls.iter().filter(|p| p.as_path() == path).count()
        })
    }
}

/// Records approval changes under one window lock and one generation commit.
#[derive(Debug)]
pub struct ApprovalRecorder<'a> {
    recorder: OperationRecorder<'a>,
    store: &'a PersistedWindowStore,
    profile: &'a Profile,
}

impl<'a> ApprovalRecorder<'a> {
    /// Uses the operation recorder's audit ordering and commit boundary.
    #[must_use]
    pub fn new(
        store: &'a PersistedWindowStore,
        profile: &'a Profile,
        audit: &'a mut dyn OperationAudit,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            recorder: OperationRecorder::new(store, profile, audit, request_id),
            store,
            profile,
        }
    }

    /// Moves out the transitions this recorder's steps committed since the
    /// last call; see [`OperationRecorder::take_committed`].
    pub fn take_committed(&mut self) -> CommittedBatch {
        self.recorder.take_committed()
    }

    /// Notes one facade call for the test observer.
    fn observed(&self) {
        #[cfg(any(test, feature = "test-helpers"))]
        facade_calls::note(self.store.path());
    }

    /// Opens a pending record, links its operation and records the waiting edge.
    ///
    /// The same commit stores `decision` as the operation's prepare decision
    /// and ends its waiting window with the signed waiting expiry.
    ///
    /// # Errors
    ///
    /// Refuses inconsistent facts, conflicting identities, capacity, audit failures and store errors.
    pub fn open_pending(
        &mut self,
        operation_id: OperationId,
        facts: &PendingApprovalFacts,
        decision: PolicyDecision,
    ) -> Result<ApprovalView, WindowStoreError> {
        self.observed();
        self.recorder.run(None, |session| {
            if !waiting_valid(
                facts.created_at_ms,
                facts.waiting_expires_at_ms,
                facts.rule_ttl_ms,
            ) || facts.nonce.is_empty()
                || facts.nonce.len() > APPROVAL_NONCE_MAX
            {
                return Err(unexpected(
                    "the signed approval waiting facts are inconsistent",
                ));
            }
            inbox_kind(facts.kind)?;
            let id = record_id(&profile_name_for_approval(session.profile), &facts.nonce);
            if let Some(existing) = records(&session.wire)
                .iter()
                .find(|r| r.nonce == facts.nonce || r.operation_id == operation_id)
            {
                if existing.id == id
                    && existing.operation_id == operation_id
                    && existing.facts() == *facts
                {
                    return Ok(existing.view(session.now));
                }
                return Err(unexpected(
                    "the approval nonce or operation already names another record",
                ));
            }
            if serialized_len(session.original) >= FILE_THRESHOLD {
                return Err(WindowStoreError::OperationCapacity {
                    detail: CapacityDetail::FileSize,
                });
            }
            session.await_approval(operation_id, id, facts, decision)?;
            let record = WireApproval {
                id,
                nonce: facts.nonce.clone(),
                kind: facts.kind,
                subject_kind: facts.subject_kind,
                subject: facts.subject,
                intent_digest: facts.intent_digest,
                operation_id,
                state: ApprovalState::Pending,
                created_at_ms: facts.created_at_ms,
                waiting_expires_at_ms: facts.waiting_expires_at_ms,
                rule_ttl_ms: facts.rule_ttl_ms,
                consent: None,
                consumed_at_ms: None,
                revoked_at_ms: None,
                closed_at_ms: None,
            };
            let view = record.view(session.now);
            session
                .wire
                .approvals
                .get_or_insert_with(ApprovalsSection::default)
                .records
                .push(record);
            session.changed = true;
            Ok(view)
        })
    }

    /// Stores verified consent once, retaining the signed attestation reconstruction inputs.
    ///
    /// # Errors
    ///
    /// Refuses a mismatched witness, receipt or attestation, a second consent, invalid clocks and store errors.
    pub fn record_consent(
        &mut self,
        id: [u8; 32],
        witness: &ApprovalWitness,
        payload: &ConsentPayload,
    ) -> Result<ApprovalView, WindowStoreError> {
        self.record_consent_inner(id, witness, payload, None)
    }

    /// [`Self::record_consent`] with the authenticated sink `delivery` of
    /// `payload`'s row.
    ///
    /// A repeated commit returns the stored record only when its receipt,
    /// delivery and queued reference equal these. After payload release it
    /// refuses, as does a revoked record. After successful validation, a
    /// failed commit stands unless an authenticated reread shows this exact
    /// record committed.
    ///
    /// # Errors
    ///
    /// The refusals of [`Self::record_consent`], a delivery that does not
    /// match the record identity or the payload's sink, and stored consent
    /// with other delivery facts.
    pub fn record_consent_with_delivery(
        &mut self,
        id: [u8; 32],
        witness: &ApprovalWitness,
        payload: &ConsentPayload,
        delivery: ConsentDeliveryV1,
    ) -> Result<ApprovalView, WindowStoreError> {
        self.record_consent_inner(id, witness, payload, Some(delivery))
    }

    /// Reserves consent evidence for the committed pending record of
    /// `operation`, after its window transaction ends.
    ///
    /// The authenticated record must hold `facts` exactly, link `operation`,
    /// and be live. Its signed waiting expiry and rule lifetime fix the
    /// deadline. The read takes no window lock.
    ///
    /// # Errors
    ///
    /// `internal.unexpected_state` for an absent, revoked, unlinked or
    /// different record, `submission.record_unavailable` for store
    /// failures, and the evidence refusals of
    /// [`AuditOutbox::reserve_evidence`], including
    /// `approval.evidence_capacity`.
    pub fn reserve_consent_evidence(
        &mut self,
        operation: OperationId,
        facts: &PendingApprovalFacts,
        outbox: &AuditOutbox,
    ) -> Result<EvidenceReservation, WalletError> {
        self.observed();
        let refusal = crate::operation_entry::operation_refusal;
        let name = profile_name_for_approval(self.profile);
        let id = record_id(&name, &facts.nonce);
        let wire = self
            .store
            .read_for_inspection(self.profile)
            .map_err(refusal)?
            .unwrap_or_default();
        let linked = wire.operations.as_ref().is_some_and(|s| {
            s.records
                .iter()
                .any(|op| op.id == operation && op.approval_record_id == Some(id))
        });
        let record = records(&wire)
            .iter()
            .find(|r| {
                r.id == id
                    && r.operation_id == operation
                    && r.facts() == *facts
                    && r.state != ApprovalState::Revoked
            })
            .filter(|_| linked)
            .ok_or_else(|| {
                refusal(unexpected(
                    "the committed approval does not match the admitted facts",
                ))
            })?;
        let deadline =
            EvidenceReservation::deadline(record.waiting_expires_at_ms, record.rule_ttl_ms)
                .map_err(|error| audit_writer_refusal(&name, &error))?;
        outbox.reserve_evidence(id, deadline, now_ms().map_err(refusal)?)
    }

    fn record_consent_inner(
        &mut self,
        id: [u8; 32],
        witness: &ApprovalWitness,
        payload: &ConsentPayload,
        delivery: Option<ConsentDeliveryV1>,
    ) -> Result<ApprovalView, WindowStoreError> {
        self.observed();
        let integrated = delivery.is_some();
        let mut expected = None;
        let result = self.recorder.run(None, |session| {
            let profile = session.profile;
            let record = session
                .wire
                .approvals
                .as_mut()
                .and_then(|s| s.records.iter_mut().find(|r| r.id == id))
                .ok_or_else(|| unexpected("the approval record is absent"))?;
            if integrated && record.state == ApprovalState::Revoked {
                return Err(unexpected("the approval record is revoked"));
            }
            let digest = payload
                .receipt
                .digest()
                .ok_or_else(|| unexpected("the receipt is malformed"))?;
            if witness.profile() != profile_name_for_approval(profile)
                || witness.chain() != profile.chain_id
                || witness.nonce() != record.nonce
                || witness.kind() != record.kind
                || witness.subject() != record.subject
                || witness.created_at_ms() != record.created_at_ms
                || witness.expires_at_ms() != record.waiting_expires_at_ms
                || witness.presence_receipt_digest() != digest
                || payload.receipt.policy_digest_hex()
                    != stellar_agent_core::hex::encode(&witness.policy_digest())
            {
                return Err(unexpected(
                    "the approval witness does not match the record and receipt",
                ));
            }
            if delivery
                .as_ref()
                .is_some_and(|d| !d.matches(id, payload.outbox_row.as_ref()))
            {
                return Err(unexpected(
                    "the consent delivery does not match its identity and sink",
                ));
            }
            if let Some(consent) = &record.consent {
                if delivery.is_some()
                    && (consent.delivery != delivery
                        || consent
                            .payload
                            .as_ref()
                            .is_none_or(|p| p.outbox_row != payload.outbox_row))
                {
                    return Err(unexpected(
                        "the approval already holds different delivery facts",
                    ));
                }
                if consent.receipt_sha256 == digest {
                    return Ok(record.view(session.now));
                }
                return Err(unexpected("the approval already holds another consent"));
            }
            let at = payload.receipt.verified_at_unix_ms();
            check_consent_time(record, at)?;
            let mut payload = payload.clone();
            if record.subject_kind == SubjectKind::IntentDigest {
                payload.challenge_subject =
                    Some(witness.challenge_subject().ok_or_else(|| {
                        unexpected("the intent witness lacks its challenge subject")
                    })?);
            }
            verify_payload(profile, record, &payload)?;
            record.consent = Some(Consent {
                consent_at_ms: at,
                execution_expires_at_ms: execution_expiry(at, record.rule_ttl_ms)?,
                receipt_sha256: digest,
                payload: Some(payload),
                delivery,
            });
            if serialized_len(record) > APPROVAL_RECORD_MAX {
                return Err(invalid("the approval record exceeds its allowance"));
            }
            if integrated {
                expected = Some(record.clone());
            }
            session.changed = true;
            Ok(record.view(session.now))
        });
        result.or_else(|error| {
            let Some(expected) = expected else {
                return Err(error);
            };
            #[cfg(test)]
            admission_tests::after_failed_commit(self.store.path());
            match ApprovalStatus::new(self.store, self.profile).view(id) {
                Ok(Some(view)) if view.record == expected => Ok(view),
                _ => Err(error),
            }
        })
    }

    /// Revokes a live approval without an operation transition or audit row.
    ///
    /// # Errors
    ///
    /// Refuses an absent record, a clock before creation and store errors.
    pub fn revoke(&mut self, id: [u8; 32]) -> Result<ApprovalView, WindowStoreError> {
        self.observed();
        self.recorder.run(None, |session| revoke_step(session, id))
    }

    /// [`Self::revoke`] under `lock`, the exclusive policy-state guard the
    /// caller holds across its whole request. The write takes no lock.
    ///
    /// # Errors
    ///
    /// As [`Self::revoke`]; a guard of another window-state entry refuses
    /// and changes nothing.
    pub fn revoke_held(
        &mut self,
        lock: &WindowStoreLock,
        id: [u8; 32],
    ) -> Result<ApprovalView, WindowStoreError> {
        self.observed();
        self.recorder
            .run_held(lock, None, |session| revoke_step(session, id))
    }
}

/// Records explicit delivery through the ordinary consent transaction for fixtures.
///
/// # Errors
/// Returns pending-record, witness, payload, delivery consistency and store refusals.
#[cfg(any(test, feature = "test-helpers"))]
pub fn record_consent_with_row_for_test(
    recorder: &mut ApprovalRecorder<'_>,
    operation: OperationId,
    facts: &PendingApprovalFacts,
    witness: &ApprovalWitness,
    payload: &ConsentPayload,
    outbox_row: Option<OutboxRowRef>,
    delivery: ConsentDeliveryV1,
) -> Result<ApprovalView, WindowStoreError> {
    let id = recorder
        .open_pending(operation, facts, PolicyDecision::RequireApproval)?
        .record
        .id;
    let mut payload = payload.clone();
    payload.outbox_row = outbox_row;
    payload.row_provenance = outbox_row.is_none().then_some(RowProvenance::Written);
    recorder.record_consent_inner(id, witness, &payload, Some(delivery))
}

/// Seeds delivery on an already consented fixture record, preserving its proof and clocks.
/// The ordinary consent transaction still refuses replacing delivery facts.
///
/// # Errors
/// Returns store errors and refuses missing consent, existing delivery or an inconsistent sink.
#[cfg(any(test, feature = "test-helpers"))]
pub fn seed_existing_consent_delivery_for_test(
    recorder: &mut ApprovalRecorder<'_>,
    id: [u8; 32],
    outbox_row: Option<OutboxRowRef>,
    delivery: ConsentDeliveryV1,
) -> Result<ApprovalView, WindowStoreError> {
    recorder.recorder.run(None, |session| {
        if !delivery.matches(id, outbox_row.as_ref()) {
            return Err(unexpected("the fixture delivery does not match its sink"));
        }
        let record = session
            .wire
            .approvals
            .as_mut()
            .and_then(|section| section.records.iter_mut().find(|record| record.id == id))
            .ok_or_else(|| unexpected("the fixture approval is absent"))?;
        let consent = record
            .consent
            .as_mut()
            .ok_or_else(|| unexpected("the fixture consent is absent"))?;
        if consent.delivery.is_some() {
            return Err(unexpected(
                "the fixture consent already holds delivery facts",
            ));
        }
        let payload = consent
            .payload
            .as_mut()
            .ok_or_else(|| unexpected("the fixture consent payload is absent"))?;
        payload.outbox_row = outbox_row;
        payload.row_provenance = outbox_row.is_none().then_some(RowProvenance::Written);
        consent.delivery = Some(delivery);
        session.changed = true;
        Ok(record.view(session.now))
    })
}

/// Revokes the live record `id` in `session`.
fn revoke_step(session: &mut Session<'_>, id: [u8; 32]) -> Result<ApprovalView, WindowStoreError> {
    let record = session
        .wire
        .approvals
        .as_mut()
        .and_then(|s| s.records.iter_mut().find(|r| r.id == id))
        .ok_or_else(|| unexpected("the approval record is absent"))?;
    if record.state == ApprovalState::Revoked || session.now >= record.expiry() {
        return Ok(record.view(session.now));
    }
    if session.now < record.created_at_ms
        || record.consumed_at_ms.is_some_and(|at| session.now < at)
    {
        return Err(unexpected("revocation precedes the approval"));
    }
    record.state = ApprovalState::Revoked;
    record.revoked_at_ms = Some(session.now);
    record.closed_at_ms = Some(session.now);
    session.changed = true;
    Ok(record.view(session.now))
}

fn verify_payload(
    profile: &Profile,
    record: &WireApproval,
    payload: &ConsentPayload,
) -> Result<(), WindowStoreError> {
    if payload.process_uid.is_empty() || payload.process_uid.len() > PROCESS_UID_MAX {
        return Err(unexpected(
            "the signed process identifier exceeds its allowance",
        ));
    }
    if !payload.row_consistent() {
        return Err(unexpected(
            "the consent payload needs exactly one of a row reference and a row provenance",
        ));
    }
    let name = profile_name_for_approval(profile);
    let key = load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(&name, profile),
    )
    .map_err(|_| unexpected("the approval attestation key is unavailable"))?;
    let key: &[u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| unexpected("the approval attestation key has an invalid length"))?;
    let approver = AttestedApprover::MainnetPasskey {
        credential_id_b64url: payload.receipt.credential_id_b64url(),
    };
    let scope = AttestationScope::pending_for_subject(
        mainnet_attestation_version(record.subject_kind),
        AttestedLifetime::new(
            inbox_kind(record.kind)?,
            record.created_at_ms,
            record.waiting_expires_at_ms,
        ),
        Some(&approver),
        Some(&payload.receipt),
        record.subject_kind,
    )
    .ok_or_else(|| unexpected("the approval attestation scope is invalid"))?;
    if !verify_attestation(
        key,
        &AttestationBinding::new(&name, profile.chain_id.caip2_str()),
        &record.nonce,
        &record.subject,
        &payload.process_uid,
        &scope,
        &payload.attestation,
    ) {
        return Err(unexpected(
            "the retained approval attestation does not verify",
        ));
    }
    Ok(())
}

/// Reads authenticated approvals without writing or reconciliation.
#[derive(Debug, Clone, Copy)]
pub struct ApprovalStatus<'a> {
    store: &'a PersistedWindowStore,
    profile: &'a Profile,
}

/// Delivery classification after binding an authenticated record to a verified witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedConsentDelivery {
    /// The compiled kind capability does not require delivery enforcement.
    Unenforced,
    /// Strict direct anchoring succeeded for this identity.
    DirectAnchored {
        /// The full approval identity.
        identity: [u8; 32],
    },
    /// This exact queued reference needs Delivered membership.
    Queued {
        /// The full approval identity.
        identity: [u8; 32],
        /// The successful append's reference.
        reference: OutboxRowRef,
    },
    /// Authenticated expiry, revocation or operation termination ends authority.
    Ended {
        /// The full approval identity.
        identity: [u8; 32],
    },
}

/// Whether all production paths of this kind enforce consent delivery.
#[must_use]
pub fn consent_evidence_enforced(kind: ApprovedKind) -> bool {
    match kind {
        ApprovedKind::Payment
        | ApprovedKind::Claim
        | ApprovedKind::Trustline
        | ApprovedKind::X402Payment => false,
        _ => false,
    }
}

/// Requires an authenticated inventory of every grant in the owner scope of
/// `profile` before an integrated request is admitted.
///
/// The scope spans every profile that shares the owner coordinate, with its
/// pending reservations, live and retryable consumed grants and unintegrated
/// earlier grants. An initialized evidence image or an empty inbox does not
/// account for them. This build holds no such inventory, so every scope
/// refuses.
///
/// # Errors
///
/// `audit.outbox_evidence_unusable` naming the unavailable inventory.
pub fn require_consent_evidence_inventory(profile: &str) -> Result<(), WalletError> {
    #[cfg(any(test, feature = "test-helpers"))]
    if inventory_test_override::enabled(profile) {
        return Ok(());
    }
    Err(audit_writer_refusal(
        profile,
        &WriterError::OutboxEvidenceUnusable {
            reason: "owner-scope inventory unavailable",
        },
    ))
}

#[cfg(any(test, feature = "test-helpers"))]
mod inventory_test_override {
    use std::sync::{Mutex, PoisonError};
    static READY: Mutex<Vec<String>> = Mutex::new(Vec::new());

    pub(super) fn enabled(profile: &str) -> bool {
        READY
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|name| name == profile)
    }

    /// Stands in for an authenticated complete inventory of one profile's
    /// owner scope in a fixture, until dropped. Production builds exclude it.
    #[derive(Debug)]
    pub struct ConsentEvidenceInventoryGuard(String);

    impl ConsentEvidenceInventoryGuard {
        /// Installs the fixture inventory of `profile`.
        #[must_use]
        pub fn new(profile: &str) -> Self {
            READY
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(profile.to_owned());
            Self(profile.to_owned())
        }
    }

    impl Drop for ConsentEvidenceInventoryGuard {
        fn drop(&mut self) {
            let mut ready = READY.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(index) = ready.iter().rposition(|name| *name == self.0) {
                ready.remove(index);
            }
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub use inventory_test_override::ConsentEvidenceInventoryGuard;

/// Whether this profile's producers and consumers use integrated consent
/// for `kind`. Production capabilities remain closed until every route is ready.
#[must_use]
pub fn delivery_enforced(profile: &str, kind: ApprovedKind) -> bool {
    #[cfg(any(test, feature = "test-helpers"))]
    if delivery_test_override::enabled(profile, kind) {
        return true;
    }
    let _ = profile;
    consent_evidence_enforced(kind)
}

/// Requires the verified consent window at the greater of wall time and evidence floor.
///
/// # Errors
/// Returns clock errors or the exclusive `ApprovalExpired` refusal.
pub fn require_consent_evidence_time(
    witness: &ApprovalWitness,
    floor_ms: u64,
) -> Result<(), WalletError> {
    let now = crate::mainnet::clock::now_ms()?.max(floor_ms);
    if now < witness.consent_at_ms() || now >= witness.execution_expires_at_ms() {
        return Err(crate::mainnet::MainnetAuthorizationError::Refused(
            MainnetPrecondition::ApprovalExpired,
        )
        .into());
    }
    Ok(())
}

impl<'a> ApprovalStatus<'a> {
    /// Reads the profile's authenticated approval section.
    #[must_use]
    pub fn new(store: &'a PersistedWindowStore, profile: &'a Profile) -> Self {
        Self { store, profile }
    }

    fn find(
        &self,
        predicate: impl Fn(&WireApproval) -> bool,
    ) -> Result<Option<ApprovalView>, WindowStoreError> {
        #[cfg(any(test, feature = "test-helpers"))]
        facade_calls::note(self.store.path());
        let Some(mut wire) = self.store.read_for_inspection(self.profile)? else {
            return Ok(None);
        };
        let now = now_ms()?;
        Approvals::prune(&mut wire, now);
        Ok(records(&wire)
            .iter()
            .find(|r| predicate(r))
            .map(|r| r.view(now)))
    }

    /// Looks up a record identity.
    ///
    /// # Errors
    ///
    /// Returns integrity, clock, keyring and I/O errors from inspection.
    pub fn view(&self, id: [u8; 32]) -> Result<Option<ApprovalView>, WindowStoreError> {
        self.find(|r| r.id == id)
    }

    /// Looks up an inbox nonce.
    ///
    /// # Errors
    ///
    /// Returns integrity, clock, keyring and I/O errors from inspection.
    pub fn find_by_nonce(&self, nonce: &str) -> Result<Option<ApprovalView>, WindowStoreError> {
        self.find(|r| r.nonce == nonce)
    }

    /// Looks up the record linked to an operation.
    ///
    /// # Errors
    ///
    /// Returns integrity, clock, keyring and I/O errors from inspection.
    pub fn find_by_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<ApprovalView>, WindowStoreError> {
        self.find(|r| r.operation_id == operation_id)
    }

    /// Projects authenticated durable proof facts without writing or opening the inbox.
    /// Released payloads remain absent; consent clocks and receipt digests survive.
    ///
    /// # Errors
    ///
    /// Returns integrity, clock, keyring and I/O errors from inspection.
    pub fn facts_by_nonce(&self, nonce: &str) -> Result<Option<ApprovalFacts>, WindowStoreError> {
        Ok(self
            .find_by_nonce(nonce)?
            .map(|view| Self::facts(view.record, self.profile)))
    }

    fn facts(record: WireApproval, profile: &Profile) -> ApprovalFacts {
        ApprovalFacts::new(
            profile_name_for_approval(profile),
            profile.chain_id,
            ApprovalRecordFacts {
                id: record.id,
                operation_id: *record.operation_id.as_bytes(),
                nonce: record.nonce,
                disposition: match record.state {
                    ApprovalState::Pending => ApprovalDisposition::Pending,
                    ApprovalState::Consumed => ApprovalDisposition::Consumed,
                    ApprovalState::Revoked => ApprovalDisposition::Revoked,
                },
                consumed_at_ms: record.consumed_at_ms,
                revoked_at_ms: record.revoked_at_ms,
                kind: record.kind,
                subject_kind: record.subject_kind,
                subject: record.subject,
                intent_digest: record.intent_digest,
                created_at_ms: record.created_at_ms,
                expires_at_ms: record.waiting_expires_at_ms,
                rule_ttl_ms: record.rule_ttl_ms,
                consent: record.consent.map(|consent| ApprovalConsentFacts {
                    consent_at_ms: consent.consent_at_ms,
                    execution_expires_at_ms: consent.execution_expires_at_ms,
                    receipt_sha256: consent.receipt_sha256,
                    payload: consent.payload.map(|payload| ApprovalPayloadFacts {
                        attestation: payload.attestation,
                        receipt: payload.receipt,
                        process_uid: payload.process_uid,
                        challenge_subject: payload.challenge_subject,
                        outbox_row: payload.outbox_row,
                    }),
                }),
            },
        )
    }

    /// Binds retained delivery facts to a verified witness without pruning the inspected image.
    /// Ended classification supplies no authority and does not release evidence.
    ///
    /// # Errors
    /// Returns store errors or `ApprovalConsentMissing` for incomplete or inconsistent bindings.
    pub fn consent_delivery(
        &self,
        witness: &ApprovalWitness,
    ) -> Result<VerifiedConsentDelivery, WindowStoreError> {
        let name = profile_name_for_approval(self.profile);
        if !delivery_enforced(&name, witness.kind()) {
            return Ok(VerifiedConsentDelivery::Unenforced);
        }
        let missing = || WindowStoreError::AuthorizationRefused {
            precondition: MainnetPrecondition::ApprovalConsentMissing,
        };
        let wire = self
            .store
            .read_for_inspection(self.profile)?
            .ok_or_else(missing)?;
        let record = records(&wire)
            .iter()
            .find(|r| r.nonce == witness.nonce())
            .ok_or_else(missing)?;
        let consent = record.consent.as_ref().ok_or_else(missing)?;
        let delivery = consent.delivery.as_ref().ok_or_else(missing)?;
        if witness.profile() != name
            || witness.chain() != self.profile.chain_id
            || record.id != record_id(&name, witness.nonce())
            || record.kind != witness.kind()
            || record.subject_kind != witness.subject_kind()
            || record.subject != witness.subject()
            || record.created_at_ms != witness.created_at_ms()
            || record.waiting_expires_at_ms != witness.expires_at_ms()
            || consent.consent_at_ms != witness.consent_at_ms()
            || consent.receipt_sha256 != witness.presence_receipt_digest()
            || delivery.identity != record.id
        {
            return Err(missing());
        }
        let reference = consent.payload.as_ref().and_then(|p| p.outbox_row.as_ref());
        if delivery.provenance == ConsentProvenance::DirectAnchored && reference.is_some() {
            return Err(missing());
        }
        let ended = record.state == ApprovalState::Revoked
            || now_ms()?
                >= consent
                    .execution_expires_at_ms
                    .min(witness.execution_expires_at_ms())
            || wire.operations.as_ref().is_some_and(|s| {
                s.records
                    .iter()
                    .any(|op| op.id == record.operation_id && op.state.is_terminal())
                    || s.tombstones.iter().any(|op| op.id == record.operation_id)
            });
        if ended {
            return Ok(VerifiedConsentDelivery::Ended {
                identity: record.id,
            });
        }
        if consent.payload.is_none() {
            return Err(missing());
        }
        Ok(match delivery.provenance {
            ConsentProvenance::DirectAnchored => VerifiedConsentDelivery::DirectAnchored {
                identity: record.id,
            },
            ConsentProvenance::Queued => VerifiedConsentDelivery::Queued {
                identity: record.id,
                reference: reference.cloned().ok_or_else(missing)?,
            },
        })
    }
}

#[cfg(any(test, feature = "test-helpers"))]
mod delivery_test_override {
    use super::*;
    use std::sync::{Mutex, PoisonError};
    static ENABLED: Mutex<Vec<(String, u8)>> = Mutex::new(Vec::new());

    pub(super) fn enabled(profile: &str, kind: ApprovedKind) -> bool {
        ENABLED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(name, tag)| name == profile && *tag == kind.tag())
    }

    /// Enables one profile and kind for a fixture, restoring its previous setting on drop.
    #[derive(Debug)]
    pub struct ConsentEvidenceEnforcementGuard(String, u8);

    impl ConsentEvidenceEnforcementGuard {
        /// Installs a profile-scoped override. Production builds exclude this API.
        #[must_use]
        pub fn new(profile: &str, kind: ApprovedKind) -> Self {
            ENABLED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((profile.to_owned(), kind.tag()));
            Self(profile.to_owned(), kind.tag())
        }
    }

    impl Drop for ConsentEvidenceEnforcementGuard {
        fn drop(&mut self) {
            let mut enabled = ENABLED.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(index) = enabled
                .iter()
                .rposition(|entry| entry == &(self.0.clone(), self.1))
            {
                enabled.remove(index);
            }
        }
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub use delivery_test_override::ConsentEvidenceEnforcementGuard;

/// The consent bound, including the signed expiry for an envelope approval.
pub(super) fn record_cap(section: &Option<ApprovalsSection>, nonce: &str) -> Option<u64> {
    let record = section
        .as_ref()?
        .records
        .iter()
        .find(|r| r.nonce == nonce)?;
    let end = record.consent.as_ref()?.execution_expires_at_ms;
    Some(if record.subject_kind == SubjectKind::EnvelopeText {
        end.min(record.waiting_expires_at_ms)
    } else {
        end
    })
}

/// Checks retained approval state on the caller's authenticated image.
/// An absent record keeps the inbox authority path.
pub(super) fn check_record(
    wire: &WireFile,
    nonce: &str,
    operation: Option<OperationId>,
    now: u64,
) -> Result<Option<u64>, WindowStoreError> {
    let Some(record) = records(wire).iter().find(|r| r.nonce == nonce) else {
        return Ok(None);
    };
    let refuse = |precondition| WindowStoreError::AuthorizationRefused { precondition };
    if record.state == ApprovalState::Revoked {
        return Err(refuse(MainnetPrecondition::ApprovalRevoked));
    }
    if record.state == ApprovalState::Consumed && operation != Some(record.operation_id) {
        return Err(refuse(MainnetPrecondition::ApprovalNonceReused));
    }
    let Some(consent) = &record.consent else {
        return Err(refuse(if now < record.waiting_expires_at_ms {
            MainnetPrecondition::ApprovalConsentMissing
        } else {
            MainnetPrecondition::ApprovalExpired
        }));
    };
    let cap = record_cap(&wire.approvals, nonce);
    if consent.payload.is_none() || now < consent.consent_at_ms || cap.is_some_and(|end| now >= end)
    {
        return Err(refuse(MainnetPrecondition::ApprovalExpired));
    }
    if operation != Some(record.operation_id) {
        return Err(refuse(MainnetPrecondition::ApprovalNonceReused));
    }
    Ok(cap)
}

/// Consumes on the caller's successor image; its mint commits this change.
pub(super) fn consume(
    wire: &mut WireFile,
    nonce: &str,
    operation: Option<OperationLink>,
    now: u64,
) -> Result<(), WindowStoreError> {
    check_record(wire, nonce, operation.map(|link| link.operation_id), now)?;
    let Some(record) = wire
        .approvals
        .as_mut()
        .and_then(|s| s.records.iter_mut().find(|r| r.nonce == nonce))
    else {
        return Ok(());
    };
    if record.state == ApprovalState::Pending {
        record.state = ApprovalState::Consumed;
        record.consumed_at_ms = Some(now);
    }
    Ok(())
}

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
pub(crate) mod durable_tests;

#[cfg(test)]
pub(in crate::policy_state) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test assertions"
    )]

    use super::super::ledger::{DomainBinding, MintAuthority, MintRequest};
    use super::super::operations::{
        BusinessId, IntentSlot, OpenOutcome, OpenRequest, OperationKind, OperationState,
        OperationTool,
    };
    use super::*;
    use crate::mainnet::{
        MainnetConsumer,
        clock::{TestClockGuard, set_now_ms_for_test},
        digest::BindingFacts,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use serial_test::serial;
    use stellar_agent_core::approval::{
        ConsentAudit, ConsentAuthorization, Surface, attest_and_persist,
        mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture},
        store::{PendingApproval, PendingApprovalStore},
        subject::approval_subject_classic,
        witness::{ApprovalExpectation, verify_approval, verify_intent_approval},
    };
    use stellar_agent_core::audit_log::AuditEntry;

    include!("approvals/mint_tests.rs");

    #[derive(Default)]
    pub(in crate::policy_state) struct Rows {
        pub(in crate::policy_state) entries: Vec<AuditEntry>,
        pub(in crate::policy_state) fail: bool,
    }

    impl OperationAudit for Rows {
        fn append(&mut self, entry: AuditEntry) -> Result<(), String> {
            if self.fail {
                return Err("test audit failure".to_owned());
            }
            self.entries.push(entry);
            Ok(())
        }
    }

    pub(in crate::policy_state) struct Fx {
        pub(in crate::policy_state) fixture: MainnetConsentFixture,
        pub(in crate::policy_state) store: PersistedWindowStore,
        pub(in crate::policy_state) clock: TestClockGuard,
        pub(in crate::policy_state) rows: Rows,
        pub(in crate::policy_state) operation: OperationId,
        pub(in crate::policy_state) facts: PendingApprovalFacts,
        pub(in crate::policy_state) witness: ApprovalWitness,
        pub(in crate::policy_state) payload: ConsentPayload,
        pub(in crate::policy_state) entry: PendingApproval,
    }

    pub(super) fn proof(
        fixture: &MainnetConsentFixture,
        entry: &PendingApproval,
        name: &str,
    ) -> (ApprovalWitness, ConsentPayload) {
        let policy = fixture.current_policy();
        let mut inbox = PendingApprovalStore::open(fixture.home().join(name)).unwrap();
        inbox
            .insert(entry.clone(), entry.created_at_unix_ms)
            .unwrap();
        let presence = fixture.presence(entry, &policy);
        let mut audit = fixture.audit_writer();
        let blob = attest_and_persist(
            &mut inbox,
            entry,
            &ATTESTATION_KEY,
            &fixture.binding(),
            Surface::Cli,
            ConsentAudit::Writer(&mut audit),
            ConsentAuthorization::Mainnet {
                presence,
                policy: &policy,
            },
            |_, _| Err("unsupported test grant".to_owned()),
        )
        .unwrap()
        .unwrap();
        let attestation = URL_SAFE_NO_PAD.decode(blob).unwrap().try_into().unwrap();
        let approved = inbox.get(&entry.approval_nonce).unwrap();
        let receipt = approved.mainnet_presence.as_ref().unwrap().clone();
        let (kind, subject) = match &entry.kind {
            stellar_agent_core::approval::store::ApprovalKind::PaymentSimulated {
                envelope_xdr_b64,
                ..
            } => (
                ApprovedKind::Payment,
                approval_subject_classic(envelope_xdr_b64),
            ),
            stellar_agent_core::approval::store::ApprovalKind::X402Payment {
                intent_digest,
                home_domain: None,
                ..
            } => (
                ApprovedKind::X402Payment,
                stellar_agent_core::approval::subject::approval_subject_x402(intent_digest),
            ),
            _ => panic!("expected payment"),
        };
        let witness = verify_approval(
            &inbox,
            fixture.profile(),
            fixture.name(),
            &entry.approval_nonce,
            &attestation,
            &ApprovalExpectation { kind, subject },
            &policy,
            receipt.verified_at_unix_ms(),
        )
        .unwrap();
        (
            witness,
            ConsentPayload::new(
                attestation,
                receipt,
                entry.process_uid.clone(),
                ConsentRow::Written,
            ),
        )
    }

    impl Fx {
        pub(in crate::policy_state) fn new(ttl: u64) -> Self {
            Self::with_intent(
                ttl,
                IntentSlot::Canonical {
                    intent_digest: [1; 32],
                    intent: serde_json::json!({"op":"pay"}),
                },
                Some(ttl),
            )
        }

        /// An entry of lifetime `ttl` and an operation over `intent` opened
        /// with `rule_ttl_ms`.
        fn with_intent(ttl: u64, intent: IntentSlot, rule_ttl_ms: Option<u64>) -> Self {
            let fixture = MainnetConsentFixture::new("approvals");
            let entry = fixture.payment(ttl);
            Self::with_entry(fixture, entry, ttl, intent, rule_ttl_ms)
        }

        pub(super) fn x402(ttl: u64) -> Self {
            use stellar_xdr::{
                ContractId, Hash, Int128Parts, InvokeContractArgs, ScAddress, ScVal,
                SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
            };
            let fixture = MainnetConsentFixture::new("approvals");
            let asset = ScAddress::Contract(ContractId(Hash([3; 32])));
            let payer = ScAddress::Contract(ContractId(Hash([4; 32])));
            let pay_to = ScAddress::Contract(ContractId(Hash([5; 32])));
            let root = SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: asset.clone(),
                    function_name: "transfer".try_into().unwrap(),
                    args: vec![
                        ScVal::Address(payer.clone()),
                        ScVal::Address(pay_to.clone()),
                        ScVal::I128(Int128Parts { hi: 0, lo: 10 }),
                    ]
                    .try_into()
                    .unwrap(),
                }),
                sub_invocations: vec![].try_into().unwrap(),
            };
            let mut entry = PendingApproval::new_x402_pending(
                &<sha2::Sha256 as sha2::Digest>::digest(
                    stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE.as_bytes(),
                )
                .into(),
                &root,
                None,
                "1000".to_owned(),
                ttl,
            )
            .unwrap();
            // Keep the signed bound before the consent bound even within one clock tick.
            entry.created_at_unix_ms -= 1;
            entry.expires_at_unix_ms -= 1;
            let stellar_agent_core::approval::store::ApprovalKind::X402Payment {
                intent_digest,
                ..
            } = &entry.kind
            else {
                panic!("x402 entry")
            };
            let intent = IntentSlot::X402 {
                intent_digest: *intent_digest,
                intent: super::super::operations::X402Intent {
                    network: fixture.profile().chain_id.to_string(),
                    asset: asset.to_string(),
                    payer: payer.to_string(),
                    pay_to: pay_to.to_string(),
                    amount: "10".to_owned(),
                },
            };
            Self::with_entry(fixture, entry, ttl, intent, Some(ttl))
        }

        fn with_entry(
            fixture: MainnetConsentFixture,
            mut entry: PendingApproval,
            ttl: u64,
            intent: IntentSlot,
            rule_ttl_ms: Option<u64>,
        ) -> Self {
            let intent_digest = intent.intent_digest();
            let x402 = matches!(intent, IntentSlot::X402 { .. });
            entry.process_uid = "1000".to_owned();
            let (witness, payload) = proof(&fixture, &entry, "first.toml");
            let now = payload.receipt.verified_at_unix_ms();
            let clock = set_now_ms_for_test(now);
            let store = PersistedWindowStore::at_path(
                stellar_agent_core::profile::schema::default_policy_window_state_path_for(
                    fixture.name(),
                ),
            );
            let mut rows = Rows::default();
            let opened = OperationRecorder::new(&store, fixture.profile(), &mut rows, "request")
                .open(&OpenRequest {
                    business_id: BusinessId::parse("order-1").unwrap(),
                    tool: if x402 {
                        OperationTool::X402CreatePayment
                    } else {
                        OperationTool::CliPay
                    },
                    kind: if x402 {
                        OperationKind::X402Payment
                    } else {
                        OperationKind::Pay
                    },
                    intent,
                    envelope_xdr: (!x402).then(|| "AAAA".to_owned()),
                    prepared_decision: None,
                    rule_ttl_ms,
                })
                .unwrap();
            let OpenOutcome::New(handle) = opened else {
                panic!("expected new operation")
            };
            let facts = PendingApprovalFacts {
                nonce: witness.nonce().to_owned(),
                kind: witness.kind(),
                subject_kind: SubjectKind::EnvelopeText,
                subject: witness.subject(),
                intent_digest,
                created_at_ms: witness.created_at_ms(),
                waiting_expires_at_ms: witness.expires_at_ms(),
                rule_ttl_ms: ttl,
            };
            Self {
                fixture,
                store,
                clock,
                rows,
                operation: handle.id(),
                facts,
                witness,
                payload,
                entry,
            }
        }

        pub(in crate::policy_state) fn recorder(&mut self) -> ApprovalRecorder<'_> {
            ApprovalRecorder::new(
                &self.store,
                self.fixture.profile(),
                &mut self.rows,
                "request",
            )
        }

        pub(in crate::policy_state) fn open(&mut self) -> ApprovalView {
            let operation = self.operation;
            let facts = self.facts.clone();
            self.recorder()
                .open_pending(operation, &facts, PolicyDecision::RequireApproval)
                .unwrap()
        }

        pub(in crate::policy_state) fn consent(&mut self) -> ApprovalView {
            let id = self.id();
            ApprovalRecorder::new(
                &self.store,
                self.fixture.profile(),
                &mut self.rows,
                "request",
            )
            .record_consent(id, &self.witness, &self.payload)
            .unwrap()
        }

        pub(in crate::policy_state) fn id(&self) -> [u8; 32] {
            record_id(self.fixture.name(), &self.facts.nonce)
        }
        pub(in crate::policy_state) fn wire(&self) -> WireFile {
            self.store
                .read_for_inspection(self.fixture.profile())
                .unwrap()
                .unwrap()
        }
        pub(in crate::policy_state) fn bytes(&self) -> Vec<u8> {
            std::fs::read(self.store.path()).unwrap()
        }
        pub(in crate::policy_state) fn view(&self) -> ApprovalView {
            ApprovalStatus::new(&self.store, self.fixture.profile())
                .view(self.id())
                .unwrap()
                .unwrap()
        }

        pub(in crate::policy_state) fn mint_request(&self) -> MintRequest {
            let policy = self.fixture.current_policy();
            MintRequest {
                chain: self.fixture.profile().chain_id,
                consumer: MainnetConsumer::CliPay,
                binding: DomainBinding::Transaction {
                    unsigned_envelope_sha256: [1; 32],
                    tx_hash: [2; 32],
                    source: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned(),
                    sequence: 1,
                },
                policy_sequence: policy.sequence(),
                policy_digest: policy.digest(),
                authority: MintAuthority::Approval {
                    nonce: self.facts.nonce.clone(),
                    expires_at_ms: u64::MAX,
                },
                chain_deadline_ms: None,
                authorization_ttl_ms: 120_000,
                bindings: BindingFacts {
                    endpoint: None,
                    signer: [2; 32],
                    policy: [3; 32],
                    enablement: [4; 32],
                    witness: None,
                    reservation: None,
                    authority: [7; 32],
                    audit: [8; 32],
                },
                holds: vec![],
                parent: None,
                operation: Some(OperationLink {
                    operation_id: self.operation,
                    attempt_index: 1,
                }),
                floor: None,
                native_reservation: None,
            }
        }

        fn delivery(
            &mut self,
            provenance: ConsentProvenance,
            reference: Option<OutboxRowRef>,
        ) -> Result<ApprovalView, WindowStoreError> {
            let delivery = match provenance {
                ConsentProvenance::Queued => ConsentDeliveryV1::queued(self.id()),
                ConsentProvenance::DirectAnchored => {
                    let path = self.fixture.home().join("strict-direct.log");
                    if !path.exists() {
                        use stellar_agent_core::audit_log::{
                            AuditWriter, KeyedAuditAccess, tip_anchor::InMemoryTipAnchorStore,
                        };
                        let mut writer = AuditWriter::open(
                            path,
                            Some(KeyedAuditAccess::new(
                                zeroize::Zeroizing::new([42; 32]),
                                std::sync::Arc::new(InMemoryTipAnchorStore::new()),
                            )),
                        )
                        .unwrap();
                        writer
                            .prepare_entry()
                            .unwrap()
                            .write_anchored(AuditEntry::new_approval_attested(
                                self.witness.kind().kind_name(),
                                "stellar_pay_commit",
                                None,
                                self.witness.nonce(),
                                "cli",
                                "strict-direct",
                            ))
                            .unwrap();
                    }
                    ConsentDeliveryV1::direct_anchored(self.id())
                }
            };
            record_consent_with_row_for_test(
                &mut ApprovalRecorder::new(
                    &self.store,
                    self.fixture.profile(),
                    &mut self.rows,
                    "delivery",
                ),
                self.operation,
                &self.facts,
                &self.witness,
                &self.payload,
                reference,
                delivery,
            )
        }

        fn reference(&self, file: &str) -> OutboxRowRef {
            use stellar_agent_core::audit_log::{
                AuditOutbox, AuditWriter, KeyedAuditAccess, tip_anchor::InMemoryTipAnchorStore,
            };
            let path = self.fixture.home().join(file);
            let anchor = std::sync::Arc::new(InMemoryTipAnchorStore::new());
            let mut writer = AuditWriter::open(
                path.clone(),
                Some(KeyedAuditAccess::new(
                    zeroize::Zeroizing::new([42; 32]),
                    anchor.clone(),
                )),
            )
            .unwrap();
            writer.initialize_consent_evidence().unwrap();
            let outbox =
                AuditOutbox::for_log_keyed(&path, anchor, zeroize::Zeroizing::new([42; 32]));
            let reservation = outbox
                .reserve_evidence(
                    self.id(),
                    self.facts.waiting_expires_at_ms + 300_000,
                    self.witness.consent_at_ms(),
                )
                .unwrap();
            let row = AuditEntry::new_approval_attested(
                "PaymentSimulated",
                "stellar_pay_commit",
                None,
                &self.facts.nonce,
                "cli",
                file,
            );
            let reference = outbox
                .with_evidence_reservation(reservation)
                .append_queued(&row)
                .unwrap();
            writer.drain_outbox().unwrap();
            reference
        }

        pub(in crate::policy_state) fn edit(&mut self, change: impl FnOnce(&mut WireFile)) {
            OperationRecorder::new(
                &self.store,
                self.fixture.profile(),
                &mut self.rows,
                "snapshot",
            )
            .run(None, |session| {
                change(&mut session.wire);
                session.changed = true;
                Ok(())
            })
            .unwrap();
        }

        fn classify(&self) -> Result<VerifiedConsentDelivery, WindowStoreError> {
            ApprovalStatus::new(&self.store, self.fixture.profile()).consent_delivery(&self.witness)
        }
    }

    #[test]
    #[serial]
    fn delivery_classifier_binds_witness() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for field in [
            "kind",
            "convention",
            "subject",
            "created",
            "waiting",
            "receipt",
            "identity",
            "metadata",
            "consent",
            "reference",
            "direct_row",
            "record",
        ] {
            let mut fx = Fx::new(300_000);
            let _enabled =
                ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
            fx.open();
            let reference = fx.reference("delivery.log");
            fx.delivery(ConsentProvenance::Queued, Some(reference))
                .unwrap();
            assert_eq!(
                fx.classify().unwrap(),
                VerifiedConsentDelivery::Queued {
                    identity: fx.id(),
                    reference
                }
            );
            // Every edited snapshot passes the store's authenticated commit validation.
            // Kind changes only kind, so its comparison cannot hide behind another mismatch.
            fx.edit(|wire| {
                let record = &mut wire.approvals.as_mut().unwrap().records[0];
                match field {
                    "kind" => record.kind = ApprovedKind::Claim,
                    "convention" => {
                        record.subject_kind = SubjectKind::IntentDigest;
                        let consent = record.consent.as_mut().unwrap();
                        consent.payload.as_mut().unwrap().challenge_subject = Some(record.subject);
                    }
                    "subject" => record.subject[0] ^= 1,
                    "created" => {
                        record.created_at_ms -= 1;
                        record.rule_ttl_ms += 1;
                        record.consent.as_mut().unwrap().execution_expires_at_ms += 1;
                    }
                    "waiting" => {
                        record.waiting_expires_at_ms += 1;
                        record.rule_ttl_ms += 1;
                        record.consent.as_mut().unwrap().execution_expires_at_ms += 1;
                    }
                    "receipt" => {
                        let consent = record.consent.as_mut().unwrap();
                        let payload = consent.payload.as_mut().unwrap();
                        let mut value = serde_json::to_value(&payload.receipt).unwrap();
                        value["request_id"] = uuid::Uuid::new_v4().to_string().into();
                        payload.receipt = serde_json::from_value(value).unwrap();
                        consent.receipt_sha256 = payload.receipt.digest().unwrap();
                    }
                    "identity" => {
                        record
                            .consent
                            .as_mut()
                            .unwrap()
                            .delivery
                            .as_mut()
                            .unwrap()
                            .identity[0] ^= 1
                    }
                    "metadata" => record.consent.as_mut().unwrap().delivery = None,
                    "consent" => record.consent = None,
                    "reference" => {
                        record
                            .consent
                            .as_mut()
                            .unwrap()
                            .payload
                            .as_mut()
                            .unwrap()
                            .outbox_row = None
                    }
                    "direct_row" => {
                        record.consent.as_mut().unwrap().delivery =
                            Some(ConsentDeliveryV1::direct_anchored(record.id))
                    }
                    "record" => wire.approvals = None,
                    _ => unreachable!(),
                }
            });
            let classified = fx.classify();
            assert!(
                matches!(
                    &classified,
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::ApprovalConsentMissing
                    })
                ),
                "binding {field}: {classified:?}"
            );
        }
        let mut fx = Fx::new(300_000);
        let _enabled =
            ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
        fx.delivery(ConsentProvenance::DirectAnchored, None)
            .unwrap();
        assert_eq!(
            fx.classify().unwrap(),
            VerifiedConsentDelivery::DirectAnchored { identity: fx.id() }
        );
    }

    #[test]
    #[serial]
    fn enforcement_activation_requires_complete_producers() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let mut fx = Fx::new(300_000);
        for kind in [
            ApprovedKind::Payment,
            ApprovedKind::Claim,
            ApprovedKind::Trustline,
            ApprovedKind::X402Payment,
        ] {
            assert!(!consent_evidence_enforced(kind));
        }
        assert_eq!(fx.classify().unwrap(), VerifiedConsentDelivery::Unenforced);
        let enabled =
            ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
        assert!(
            matches!(
                fx.classify(),
                Err(WindowStoreError::AuthorizationRefused {
                    precondition: MainnetPrecondition::ApprovalConsentMissing
                })
            ),
            "enabled absence refuses"
        );
        fx.open();
        fx.consent();
        assert!(fx.classify().is_err(), "legacy metadata is incomplete");
        drop(enabled);
        let id = fx.id();
        fx.edit(|wire| {
            wire.approvals.as_mut().unwrap().records[0]
                .consent
                .as_mut()
                .unwrap()
                .delivery = Some(ConsentDeliveryV1::direct_anchored(id))
        });
        assert_eq!(
            fx.classify().unwrap(),
            VerifiedConsentDelivery::Unenforced,
            "metadata never enables a kind"
        );
        let _other = ConsentEvidenceEnforcementGuard::new("other-profile", ApprovedKind::Payment);
        assert_eq!(fx.classify().unwrap(), VerifiedConsentDelivery::Unenforced);
    }

    #[test]
    #[serial]
    fn effective_floor_prevents_expired_use() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let mut fx = Fx::new(300_000);
        let _enabled =
            ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
        fx.delivery(ConsentProvenance::DirectAnchored, None)
            .unwrap();
        assert!(matches!(
            fx.classify().unwrap(),
            VerifiedConsentDelivery::DirectAnchored { .. }
        ));
        let end = fx.witness.execution_expires_at_ms();
        fx.clock.set(end - 1);
        require_consent_evidence_time(&fx.witness, 0).unwrap();
        for (wall, floor) in [
            (end, 0),
            (end + 1, 0),
            (fx.witness.consent_at_ms(), end),
            (fx.witness.consent_at_ms() - 1, 0),
        ] {
            fx.clock.set(wall);
            let error = require_consent_evidence_time(&fx.witness, floor).unwrap_err();
            assert_eq!(error.code(), "network.mainnet_authorization_refused");
            assert!(
                matches!(
                    error,
                    WalletError::Network(
                        stellar_agent_core::error::NetworkError::MainnetAuthorizationRefused
                    )
                ),
                "expired wall {wall}, floor {floor}"
            );
        }
    }

    #[test]
    #[serial]
    fn same_receipt_cannot_replace_delivery() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        for queued in [false, true] {
            let mut fx = Fx::new(300_000);
            fx.open();
            let reference = queued.then(|| fx.reference("first-delivery.log"));
            let provenance = if queued {
                ConsentProvenance::Queued
            } else {
                ConsentProvenance::DirectAnchored
            };
            // A first consent whose delivery disagrees with its row refuses
            // and writes nothing: queued without a reference, and direct
            // with one.
            let unconsented = fx.bytes();
            for (row, delivery) in [
                (ConsentRow::Written, ConsentDeliveryV1::queued(fx.id())),
                (
                    ConsentRow::Queued(queued_reference(1)),
                    ConsentDeliveryV1::direct_anchored(fx.id()),
                ),
            ] {
                let payload = ConsentPayload::new(
                    fx.payload.attestation,
                    fx.payload.receipt.clone(),
                    fx.payload.process_uid.clone(),
                    row,
                );
                let mut rows = Rows::default();
                let refused =
                    ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut rows, "first")
                        .record_consent_with_delivery(fx.id(), &fx.witness, &payload, delivery)
                        .unwrap_err();
                assert_eq!(
                    refused.to_string(),
                    unexpected("the consent delivery does not match its identity and sink")
                        .to_string()
                );
                assert_eq!(fx.bytes(), unconsented);
                assert!(fx.view().record.consent.is_none());
            }
            let first = fx.delivery(provenance, reference).unwrap();
            let before = fx.bytes();
            assert_eq!(fx.delivery(provenance, reference).unwrap(), first);
            assert_eq!(fx.bytes(), before);
            let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
            assert_eq!(
                ApprovalStatus::new(&reopened, fx.fixture.profile())
                    .view(fx.id())
                    .unwrap(),
                Some(first)
            );
            let other = if queued {
                None
            } else {
                Some(fx.reference("other-delivery.log"))
            };
            assert!(
                fx.delivery(
                    if queued {
                        ConsentProvenance::DirectAnchored
                    } else {
                        ConsentProvenance::Queued
                    },
                    other
                )
                .is_err(),
                "same receipt cannot replace provenance"
            );
            if queued {
                let different = fx.reference("second-delivery.log");
                assert!(
                    fx.delivery(ConsentProvenance::Queued, Some(different))
                        .is_err(),
                    "same receipt cannot replace reference"
                );
            }
            assert_eq!(fx.bytes(), before);
        }
    }

    #[test]
    #[serial]
    fn open_pending_links_and_awaits_in_one_commit() {
        let mut fx = Fx::new(300_000);
        let before = fx.wire();
        let bytes = fx.bytes();
        let facts = fx.facts.clone();
        let operation = fx.operation;
        fx.rows.fail = true;
        assert!(matches!(
            fx.recorder()
                .open_pending(operation, &facts, PolicyDecision::RequireApproval),
            Err(WindowStoreError::AuditAppendFailed { .. })
        ));
        assert_eq!(fx.bytes(), bytes);
        fx.rows.fail = false;
        let rows = fx.rows.entries.len();
        let view = fx.open();
        let after = fx.wire();
        assert_eq!(after.generation, before.generation + 1);
        assert_eq!(after.approvals.as_ref().unwrap().records, vec![view.record]);
        let op = &after.operations.as_ref().unwrap().records[0];
        assert_eq!(op.approval_record_id, Some(fx.id()));
        assert_eq!(op.state, OperationState::AwaitingApproval);
        assert_eq!(op.history.len(), 2);
        assert_eq!(fx.rows.entries.len(), rows + 1);
    }

    /// The approval recorder's drain moves out the waiting edge once, with
    /// the operation's identity, business id, history time and the durable
    /// record id `find_by_nonce` reports.
    #[test]
    #[serial]
    fn recorder_drains_once_including_approval() {
        let mut fx = Fx::new(300_000);
        let operation = fx.operation;
        let facts = fx.facts.clone();
        let mut recorder = fx.recorder();
        recorder
            .open_pending(operation, &facts, PolicyDecision::RequireApproval)
            .unwrap();
        let batch = recorder.take_committed();
        assert!(recorder.take_committed().is_empty());
        let found = ApprovalStatus::new(&fx.store, fx.fixture.profile())
            .find_by_nonce(&facts.nonce)
            .unwrap()
            .unwrap();
        let record = fx.wire().operations.unwrap().records.remove(0);
        let edges: Vec<_> = batch
            .into_iter()
            .map(|edge| {
                (
                    edge.operation_id(),
                    edge.business_id().as_str().to_owned(),
                    edge.state(),
                    edge.attempt_index(),
                    edge.at_ms(),
                    edge.approval_record_id(),
                )
            })
            .collect();
        assert_eq!(
            edges,
            vec![(
                operation,
                "order-1".to_owned(),
                OperationState::AwaitingApproval,
                None,
                record.history.last().unwrap().at_ms,
                Some(found.record.id),
            )]
        );
    }

    /// Over the consent commit's sink, consent commits without an audit
    /// writer, and a step that appends a row fails as `audit.append_failed`.
    #[test]
    #[serial]
    fn consent_commit_needs_no_audit_writer() {
        use crate::operation_entry::ConsentOnlyAudit;
        let mut fx = Fx::new(300_000);
        let (operation, facts) = (fx.operation, fx.facts.clone());
        let before = fx.bytes();
        assert!(matches!(
            ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut ConsentOnlyAudit, "r")
                .open_pending(operation, &facts, PolicyDecision::RequireApproval),
            Err(WindowStoreError::AuditAppendFailed { .. })
        ));
        assert_eq!(fx.bytes(), before);
        fx.open();
        let id = fx.id();
        let view =
            ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut ConsentOnlyAudit, "r")
                .record_consent(id, &fx.witness, &fx.payload)
                .unwrap();
        assert_eq!(
            view.record.consent.unwrap().payload,
            Some(fx.payload.clone())
        );
    }

    #[test]
    #[serial]
    fn find_by_operation_reads_without_writing() {
        let mut fx = Fx::new(300_000);
        let operation = fx.operation;
        let find = |fx: &Fx, id| {
            ApprovalStatus::new(&fx.store, fx.fixture.profile())
                .find_by_operation(id)
                .unwrap()
        };
        assert_eq!(find(&fx, operation), None);
        let opened = fx.open();
        let bytes = fx.bytes();
        assert_eq!(find(&fx, operation), Some(opened));
        assert_eq!(find(&fx, OperationId::random()), None);
        assert_eq!(fx.bytes(), bytes);
    }

    /// The open commit stores the prepare decision and moves the waiting
    /// expiry from the open's 600-second default to the signed waiting
    /// expiry, capped at the envelope's end.
    #[test]
    #[serial]
    fn open_stores_the_prepare_decision_and_the_earlier_waiting_end() {
        for ttl in [300_000, 3_600_000] {
            let mut fx = Fx::with_intent(
                ttl,
                IntentSlot::Canonical {
                    intent_digest: [1; 32],
                    intent: serde_json::json!({"op":"pay"}),
                },
                None,
            );
            let before = fx.wire().operations.unwrap().records[0].clone();
            assert_eq!(before.prepared_decision, None);
            assert_eq!(
                before.waiting_expires_at_ms,
                fx.payload.receipt.verified_at_unix_ms() + 600_000
            );
            fx.open();
            let after = fx.wire().operations.unwrap().records[0].clone();
            assert_eq!(
                after.prepared_decision,
                Some(serde_json::json!("require_approval"))
            );
            assert_eq!(after.waiting_expires_at_ms, fx.facts.waiting_expires_at_ms);
        }
        let probe = Fx::new(3_600_000);
        let end_s = (probe.facts.waiting_expires_at_ms - 60_000) / 1_000;
        drop(probe);
        let mut fx = Fx::with_intent(
            3_600_000,
            IntentSlot::Envelope {
                unsigned_envelope_sha256: [2; 32],
                intent_digest: [1; 32],
                max_time: end_s,
            },
            Some(3_600_000),
        );
        fx.open();
        let after = fx.wire().operations.unwrap().records[0].clone();
        assert_eq!(after.waiting_expires_at_ms, end_s * 1_000);
        assert!(after.waiting_expires_at_ms < fx.facts.waiting_expires_at_ms);
    }

    #[test]
    #[serial]
    fn open_pending_refuses_a_non_prepared_or_linked_operation() {
        for linked in [false, true] {
            let mut fx = Fx::new(300_000);
            if linked {
                OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
                    .link_approval(fx.operation, [9; 32])
                    .unwrap();
            } else {
                OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
                    .transition(
                        fx.operation,
                        None,
                        OperationState::AwaitingApproval,
                        &super::super::operations::TransitionEvidence::default(),
                    )
                    .unwrap();
            }
            let before = fx.bytes();
            let facts = fx.facts.clone();
            let operation = fx.operation;
            assert!(matches!(
                fx.recorder()
                    .open_pending(operation, &facts, PolicyDecision::RequireApproval),
                Err(WindowStoreError::UnexpectedState { .. })
            ));
            assert_eq!(fx.bytes(), before);
        }
    }

    #[test]
    #[serial]
    fn open_pending_with_the_same_facts_returns_the_record() {
        let mut fx = Fx::new(300_000);
        let first = fx.open();
        let bytes = fx.bytes();
        assert_eq!(fx.open(), first);
        assert_eq!(fx.bytes(), bytes);
        let mut changed = fx.facts.clone();
        changed.nonce.push('x');
        let operation = fx.operation;
        assert!(
            fx.recorder()
                .open_pending(operation, &changed, PolicyDecision::RequireApproval)
                .is_err()
        );
        let facts = fx.facts.clone();
        assert!(
            fx.recorder()
                .open_pending(
                    OperationId::random(),
                    &facts,
                    PolicyDecision::RequireApproval,
                )
                .is_err()
        );
        assert_eq!(fx.bytes(), bytes);
    }

    #[test]
    #[serial]
    fn open_pending_refuses_a_waiting_expiry_other_than_created_plus_ttl() {
        let mut fx = Fx::new(300_000);
        let operation = fx.operation;
        let before = fx.bytes();
        for offset in [-1i64, 1] {
            let mut facts = fx.facts.clone();
            facts.waiting_expires_at_ms = facts
                .waiting_expires_at_ms
                .checked_add_signed(offset)
                .unwrap();
            assert!(
                fx.recorder()
                    .open_pending(operation, &facts, PolicyDecision::RequireApproval)
                    .is_err()
            );
        }
        for ttl in [0, 86_400_001, u64::MAX] {
            let mut facts = fx.facts.clone();
            facts.rule_ttl_ms = ttl;
            facts.waiting_expires_at_ms = facts.created_at_ms.saturating_add(ttl);
            assert!(
                fx.recorder()
                    .open_pending(operation, &facts, PolicyDecision::RequireApproval)
                    .is_err()
            );
        }
        assert_eq!(fx.bytes(), before);
    }

    #[test]
    #[serial]
    fn consent_sets_both_clocks_once() {
        for (ttl, execution) in [(86_400_000, 900_000), (300_000, 300_000)] {
            let mut fx = Fx::new(ttl);
            fx.open();
            let id = fx.id();
            let mut recorder =
                ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request");
            let view = recorder
                .record_consent(id, &fx.witness, &fx.payload)
                .unwrap();
            // A consent write names no state edge, so it adds no entry.
            assert!(recorder.take_committed().is_empty());
            let consent = view.record.consent.unwrap();
            assert_eq!(
                consent.consent_at_ms,
                fx.payload.receipt.verified_at_unix_ms()
            );
            assert_eq!(
                consent.execution_expires_at_ms,
                consent.consent_at_ms + execution
            );
            assert_eq!(
                view.record.waiting_expires_at_ms,
                fx.facts.waiting_expires_at_ms
            );
            let bytes = fx.bytes();
            fx.consent();
            assert_eq!(fx.bytes(), bytes);
            let (witness, payload) = proof(&fx.fixture, &fx.entry, "second.toml");
            let id = fx.id();
            assert!(matches!(
                fx.recorder().record_consent(id, &witness, &payload),
                Err(WindowStoreError::UnexpectedState { .. })
            ));
            assert_eq!(fx.bytes(), bytes);
        }
    }

    #[test]
    #[serial]
    fn consent_requires_the_matching_witness() {
        for field in 0..6 {
            let mut fx = Fx::new(300_000);
            match field {
                0 => fx.facts.nonce.push('x'),
                1 => fx.facts.kind = ApprovedKind::Claim,
                2 => fx.facts.subject = [8; 32],
                3 => {
                    fx.facts.created_at_ms -= 1;
                    fx.facts.rule_ttl_ms += 1;
                }
                4 => {
                    fx.facts.waiting_expires_at_ms += 1;
                    fx.facts.rule_ttl_ms += 1;
                }
                _ => {
                    let mut receipt = serde_json::to_value(&fx.payload.receipt).unwrap();
                    receipt["verified_at_unix_ms"] =
                        serde_json::json!(fx.payload.receipt.verified_at_unix_ms() + 1);
                    fx.payload.receipt = serde_json::from_value(receipt).unwrap();
                }
            }
            let record = fx.open().record;
            fx.payload.attestation = stellar_agent_core::approval::compute_attestation_v5(
                &ATTESTATION_KEY,
                &fx.fixture.binding(),
                &record.nonce,
                &record.subject,
                &fx.payload.process_uid,
                &AttestedLifetime::new(
                    inbox_kind(record.kind).unwrap(),
                    record.created_at_ms,
                    record.waiting_expires_at_ms,
                ),
                &AttestedApprover::MainnetPasskey {
                    credential_id_b64url: fx.payload.receipt.credential_id_b64url(),
                },
                &fx.payload.receipt,
            );
            let before = fx.bytes();
            let id = fx.id();
            assert!(
                ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
                    .record_consent(id, &fx.witness, &fx.payload)
                    .is_err(),
                "field {field}"
            );
            assert_eq!(fx.bytes(), before);
        }
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.payload.attestation[0] ^= 1;
        let id = fx.id();
        assert!(
            ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
                .record_consent(id, &fx.witness, &fx.payload)
                .is_err()
        );
    }

    /// The durable record reconstructs an intent-digest consent under
    /// version 6: the intent witness's genuine consent verifies and stores,
    /// and a version 5 blob over the same facts refuses.
    #[test]
    #[serial]
    fn durable_consent_selects_the_layout_by_subject_kind() {
        let ttl = 300_000;
        let fixture = MainnetConsentFixture::new("approvals");
        let policy = fixture.current_policy();
        let (mut entry, intent) = fixture.intent_payment(ttl);
        entry.process_uid = "1000".to_owned();
        let (inbox, surfaced) = fixture.intent_consent(&entry, &intent);
        let attestation: [u8; 32] = URL_SAFE_NO_PAD
            .decode(surfaced.unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let receipt = inbox
            .get(&entry.approval_nonce)
            .unwrap()
            .mainnet_presence
            .clone()
            .unwrap();
        let witness = verify_intent_approval(
            &inbox,
            fixture.profile(),
            fixture.name(),
            &entry.approval_nonce,
            &attestation,
            &intent,
            &fixture.decision(ttl),
            &policy,
            receipt.verified_at_unix_ms(),
        )
        .unwrap();
        drop(inbox);
        let _clock = set_now_ms_for_test(receipt.verified_at_unix_ms());
        let store = PersistedWindowStore::at_path(
            stellar_agent_core::profile::schema::default_policy_window_state_path_for(
                fixture.name(),
            ),
        );
        let digest = *intent.digest().as_bytes();
        let mut rows = Rows::default();
        let opened = OperationRecorder::new(&store, fixture.profile(), &mut rows, "request")
            .open(&OpenRequest {
                business_id: BusinessId::parse("order-6").unwrap(),
                tool: OperationTool::CliPay,
                kind: OperationKind::Pay,
                intent: IntentSlot::Canonical {
                    intent_digest: digest,
                    intent: serde_json::json!({"op":"pay"}),
                },
                envelope_xdr: Some("AAAA".to_owned()),
                prepared_decision: None,
                rule_ttl_ms: Some(ttl),
            })
            .unwrap();
        let OpenOutcome::New(handle) = opened else {
            panic!("expected new operation")
        };
        let facts = PendingApprovalFacts {
            nonce: witness.nonce().to_owned(),
            kind: witness.kind(),
            subject_kind: SubjectKind::IntentDigest,
            subject: witness.subject(),
            intent_digest: digest,
            created_at_ms: witness.created_at_ms(),
            waiting_expires_at_ms: witness.expires_at_ms(),
            rule_ttl_ms: ttl,
        };
        assert_eq!(witness.subject(), digest);
        let record = ApprovalRecorder::new(&store, fixture.profile(), &mut rows, "request")
            .open_pending(handle.id(), &facts, PolicyDecision::RequireApproval)
            .unwrap()
            .record;
        let id = record.id;
        let version_5 = stellar_agent_core::approval::compute_attestation_v5(
            &ATTESTATION_KEY,
            &fixture.binding(),
            &record.nonce,
            &record.subject,
            &entry.process_uid,
            &AttestedLifetime::new(
                inbox_kind(record.kind).unwrap(),
                record.created_at_ms,
                record.waiting_expires_at_ms,
            ),
            &AttestedApprover::MainnetPasskey {
                credential_id_b64url: receipt.credential_id_b64url(),
            },
            &receipt,
        );
        let before = std::fs::read(store.path()).unwrap();
        let refused = ConsentPayload::new(
            version_5,
            receipt.clone(),
            entry.process_uid.clone(),
            ConsentRow::Written,
        );
        assert!(
            ApprovalRecorder::new(&store, fixture.profile(), &mut rows, "request")
                .record_consent(id, &witness, &refused)
                .is_err(),
            "a version 5 blob on an intent record"
        );
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        let payload = ConsentPayload::new(
            attestation,
            receipt.clone(),
            entry.process_uid.clone(),
            ConsentRow::Written,
        );
        let view = ApprovalRecorder::new(&store, fixture.profile(), &mut rows, "request")
            .record_consent(id, &witness, &payload)
            .unwrap();
        let consent = view.record.consent.unwrap();
        assert_eq!(consent.consent_at_ms, receipt.verified_at_unix_ms());
        assert_eq!(consent.execution_expires_at_ms, consent.consent_at_ms + ttl);
        assert_eq!(
            consent.execution_expires_at_ms,
            witness.execution_expires_at_ms()
        );
        let challenge = stellar_agent_core::approval::presence::mainnet_consent_subject(
            &entry,
            &fixture.binding(),
        )
        .unwrap();
        assert_ne!(challenge, digest);
        assert_eq!(witness.challenge_subject(), Some(challenge));
        let mut retained = payload;
        retained.challenge_subject = Some(challenge);
        assert_eq!(consent.payload, Some(retained));
    }

    #[test]
    #[serial]
    fn consent_at_or_after_the_waiting_expiry_refuses() {
        let mut fx = Fx::new(300_000);
        let record = fx.open().record;
        for (at, accepted) in [
            (record.created_at_ms - 1, false),
            (record.created_at_ms, true),
            (record.waiting_expires_at_ms - 1, true),
            (record.waiting_expires_at_ms, false),
            (record.waiting_expires_at_ms + 1, false),
        ] {
            assert_eq!(check_consent_time(&record, at).is_ok(), accepted, "{at}");
        }
    }

    #[test]
    #[serial]
    fn record_consent_refuses_revocation_and_waiting_expiry() {
        for revoked in [true, false] {
            let mut fx = Fx::new(300_000);
            let record = fx.open().record;
            let id = fx.id();
            if revoked {
                fx.recorder().revoke(id).unwrap();
            } else {
                // A receipt at the boundary no longer matches its verified witness.
                let mut receipt = serde_json::to_value(&fx.payload.receipt).unwrap();
                receipt["verified_at_unix_ms"] = serde_json::json!(record.waiting_expires_at_ms);
                fx.payload.receipt = serde_json::from_value(receipt).unwrap();
                assert_eq!(
                    fx.payload.receipt.verified_at_unix_ms(),
                    record.waiting_expires_at_ms
                );
            }
            let before = fx.bytes();
            let rows = fx.rows.entries.len();
            let result =
                ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
                    .record_consent(id, &fx.witness, &fx.payload);
            assert!(
                matches!(result, Err(WindowStoreError::UnexpectedState { .. })),
                "revoked {revoked}: {result:?}"
            );
            assert_eq!(fx.bytes(), before);
            assert_eq!(fx.rows.entries.len(), rows);
            assert!(fx.view().record.consent.is_none());
        }
    }

    #[test]
    #[serial]
    fn restart_keeps_state_and_both_windows() {
        let mut fx = Fx::new(300_000);
        fx.open();
        let expected = fx.consent();
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        assert_eq!(
            ApprovalStatus::new(&reopened, fx.fixture.profile())
                .view(fx.id())
                .unwrap(),
            Some(expected)
        );
        let request = fx.mint_request();
        fx.store
            .mint_authorization(fx.fixture.profile(), &request)
            .unwrap();
        let expected = fx.view();
        assert_eq!(expected.record.state, ApprovalState::Consumed);
        assert_eq!(
            ApprovalStatus::new(&reopened, fx.fixture.profile())
                .view(fx.id())
                .unwrap(),
            Some(expected)
        );
    }

    #[test]
    #[serial]
    fn payload_drops_when_the_operation_ends_or_the_window_closes() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        // No sink is the earlier consent without delivery facts; the other
        // two decorate that same consent with authenticated delivery.
        for queued in [None, Some(false), Some(true)] {
            let mut fx = Fx::new(300_000);
            fx.open();
            fx.consent();
            if let Some(queued) = queued {
                let reference = queued.then(|| fx.reference("prune-delivery.log"));
                let delivery = if queued {
                    ConsentDeliveryV1::queued(fx.id())
                } else {
                    ConsentDeliveryV1::direct_anchored(fx.id())
                };
                let id = fx.id();
                seed_existing_consent_delivery_for_test(
                    &mut fx.recorder(),
                    id,
                    reference,
                    delivery,
                )
                .unwrap();
            }
            let request = fx.mint_request();
            fx.store
                .mint_authorization(fx.fixture.profile(), &request)
                .unwrap();
            let current = fx.wire();
            let record = &current.approvals.as_ref().unwrap().records[0];
            let consent = record.consent.as_ref().unwrap();
            assert!(consent.payload.is_some());
            assert_eq!(consent.delivery.is_some(), queued.is_some());
            for terminal in [false, true] {
                let mut wire = current.clone();
                let now = if terminal {
                    consent.consent_at_ms
                } else {
                    consent.execution_expires_at_ms
                };
                if terminal {
                    let op = &mut wire.operations.as_mut().unwrap().records[0];
                    op.state = OperationState::Succeeded;
                    op.closed_at_ms = Some(now);
                }
                Approvals::prune(&mut wire, now);
                let after = wire.approvals.unwrap().records.remove(0);
                let mut expected = consent.clone();
                expected.payload = None;
                assert_eq!(
                    after.consent,
                    Some(expected),
                    "provenance survives payload release"
                );
                assert_eq!(after.waiting_expires_at_ms, record.waiting_expires_at_ms);
            }
        }
    }

    #[test]
    #[serial]
    fn consumed_evidence_survives_same_operation_retry() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        // Each ending runs while both consent clocks are live, except the
        // expiry itself, so only its own predicate classifies it as ended.
        for ending in ["terminal", "expiry", "revoked", "tombstone"] {
            let mut fx = Fx::new(300_000);
            let _enabled =
                ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
            fx.open();
            let reference = fx.reference("retry-delivery.log");
            fx.delivery(ConsentProvenance::Queued, Some(reference))
                .unwrap();
            let request = fx.mint_request();
            fx.store
                .mint_authorization(fx.fixture.profile(), &request)
                .unwrap();
            assert_eq!(fx.view().record.state, ApprovalState::Consumed);
            assert_eq!(
                fx.classify().unwrap(),
                VerifiedConsentDelivery::Queued {
                    identity: fx.id(),
                    reference
                }
            );
            use super::super::operations::{
                AttemptAuthorization, AttemptEnvelope, AttemptRequest, LookupOutcome,
                TransitionEvidence,
            };
            let mut recorder =
                OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "retry");
            let Some(LookupOutcome::Resumable(handle)) = recorder
                .lookup(&BusinessId::parse("order-1").unwrap())
                .unwrap()
            else {
                panic!("live operation");
            };
            recorder
                .begin_attempt(
                    &handle,
                    &AttemptRequest {
                        envelope: Some(AttemptEnvelope {
                            xdr: "AAAA".to_owned(),
                            unsigned_envelope_sha256: [1; 32],
                        }),
                        authorization: AttemptAuthorization::Mint(Box::new(request.clone())),
                        send_by_ms: u64::MAX,
                    },
                )
                .expect("same-operation second mint remains live");
            match ending {
                "terminal" => {
                    recorder
                        .transition(
                            fx.operation,
                            Some(1),
                            OperationState::NotSent,
                            &TransitionEvidence::default(),
                        )
                        .unwrap();
                }
                "expiry" => fx
                    .clock
                    .set(fx.view().record.consent.unwrap().execution_expires_at_ms),
                "revoked" => {
                    let id = fx.id();
                    fx.recorder().revoke(id).unwrap();
                    assert_eq!(fx.view().record.state, ApprovalState::Revoked);
                }
                _ => {
                    let now = fx.witness.consent_at_ms();
                    fx.edit(|wire| {
                        let section = wire.operations.as_mut().unwrap();
                        let op = section.records.remove(0);
                        section
                            .tombstones
                            .push(super::super::operations::WireTombstone {
                                id: op.id,
                                business_id: op.business_id,
                                state: OperationState::NotSent,
                                result: op.result,
                                intent_digest: op.intent.intent_digest(),
                                slot_kind: op.intent.kind(),
                                closed_at_ms: now,
                            });
                    });
                    assert_ne!(fx.view().record.state, ApprovalState::Revoked);
                }
            }
            assert!(
                ending == "expiry" || !fx.view().expired,
                "{ending} keeps live clocks"
            );
            assert_eq!(
                fx.classify().unwrap(),
                VerifiedConsentDelivery::Ended { identity: fx.id() },
                "{ending}"
            );
            assert!(
                fx.store
                    .mint_authorization(fx.fixture.profile(), &request)
                    .is_err(),
                "ended authority cannot mint"
            );
        }
    }

    #[test]
    #[serial]
    fn status_reads_write_nothing() {
        let mut fx = Fx::new(300_000);
        fx.open();
        let expiry = fx.consent().record.consent.unwrap().execution_expires_at_ms;
        fx.clock.set(expiry);
        let bytes = fx.bytes();
        let status = ApprovalStatus::new(&fx.store, fx.fixture.profile());
        let view = status.view(fx.id()).unwrap().unwrap();
        assert!(view.expired);
        assert!(view.record.consent.as_ref().unwrap().payload.is_none());
        assert_eq!(status.find_by_nonce(&fx.facts.nonce).unwrap(), Some(view));
        assert_eq!(fx.bytes(), bytes);
    }

    #[test]
    #[serial]
    fn revoke_is_idempotent_and_writes_nothing_after_the_window() {
        for expired in [false, true] {
            let mut fx = Fx::new(300_000);
            fx.open();
            let expiry = fx.consent().record.consent.unwrap().execution_expires_at_ms;
            if expired {
                fx.clock.set(expiry);
            }
            let before = fx.bytes();
            let rows = fx.rows.entries.len();
            let operation_before = fx.wire().operations.unwrap().records.remove(0);
            assert_eq!(operation_before.state, OperationState::AwaitingApproval);
            let id = fx.id();
            let mut recorder = fx.recorder();
            let view = recorder.revoke(id).unwrap();
            // A revocation names no state edge, so it adds no entry.
            assert!(recorder.take_committed().is_empty());
            assert_eq!(
                view.record.state,
                if expired {
                    ApprovalState::Pending
                } else {
                    ApprovalState::Revoked
                }
            );
            if expired {
                assert_eq!(fx.bytes(), before);
            }
            let bytes = fx.bytes();
            assert_eq!(fx.recorder().revoke(id).unwrap(), view);
            assert_eq!(fx.bytes(), bytes);
            assert_eq!(fx.rows.entries.len(), rows);
            let operation_after = fx.wire().operations.unwrap().records.remove(0);
            assert_eq!(operation_after.state, OperationState::AwaitingApproval);
            assert_eq!(
                operation_after.history.len(),
                operation_before.history.len()
            );
        }
    }

    #[test]
    #[serial]
    fn validate_refuses_every_inconsistent_record() {
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let valid = fx.wire();
        Approvals::validate(&valid).unwrap();
        for field in 0..6 {
            let mut wire = valid.clone();
            let section = wire.approvals.as_mut().unwrap();
            let r = &mut section.records[0];
            match field {
                0 => {
                    r.state = ApprovalState::Consumed;
                    r.consumed_at_ms = Some(r.created_at_ms);
                    r.consent = None;
                }
                1 => {
                    let mut another = r.clone();
                    another.id = [9; 32];
                    section.records.push(another);
                }
                2 => r.waiting_expires_at_ms += 1,
                3 => r.consent.as_mut().unwrap().execution_expires_at_ms += 1,
                4 => r.state = ApprovalState::Revoked,
                _ => r.id = [9; 32],
            }
            assert!(Approvals::validate(&wire).is_err(), "field {field}");
        }
    }

    #[test]
    #[serial]
    fn retention_keeps_live_records_and_evicts_the_oldest_closed() {
        let mut fx = Fx::new(300_000);
        let template = fx.open().record;
        let now = template.waiting_expires_at_ms + 10;
        let mut wire = fx.wire();
        let section = wire.approvals.as_mut().unwrap();
        section.records.clear();
        for n in 0..=APPROVAL_CLOSED_MAX {
            let mut r = template.clone();
            r.id = Sha256::digest(n.to_be_bytes()).into();
            r.closed_at_ms = Some(template.waiting_expires_at_ms + u64::try_from(n).unwrap());
            section.records.push(r);
        }
        let oldest = section.records[0].id;
        let mut live = template.clone();
        live.id = [0xee; 32];
        live.waiting_expires_at_ms = now + RETENTION_MS * 2;
        live.closed_at_ms = Some(template.created_at_ms);
        section.records.push(live.clone());
        Approvals::prune(&mut wire, now);
        assert_eq!(records(&wire).len(), APPROVAL_CLOSED_MAX + 1);
        assert!(!records(&wire).iter().any(|r| r.id == oldest));
        assert!(records(&wire).iter().any(|r| r.id == live.id));
        Approvals::prune(&mut wire, now + RETENTION_MS + 300);
        assert_eq!(records(&wire), &[live]);
    }

    #[test]
    #[serial]
    fn largest_approval_record_fits_its_bound() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let mut fx = Fx::new(86_400_000);
        fx.open();
        let mut record = fx.consent().record;
        record.state = ApprovalState::Consumed;
        record.kind = ApprovedKind::X402Payment;
        record.nonce = "\u{0001}".repeat(APPROVAL_NONCE_MAX);
        record.created_at_ms = u64::MAX;
        record.waiting_expires_at_ms = u64::MAX;
        record.rule_ttl_ms = u64::MAX;
        record.consumed_at_ms = Some(u64::MAX);
        record.revoked_at_ms = Some(u64::MAX);
        record.closed_at_ms = Some(u64::MAX);
        let c = record.consent.as_mut().unwrap();
        c.delivery = Some(ConsentDeliveryV1::queued(record.id));
        c.consent_at_ms = u64::MAX;
        c.execution_expires_at_ms = u64::MAX;
        let payload = c.payload.as_mut().unwrap();
        payload.process_uid = "\u{0001}".repeat(PROCESS_UID_MAX);
        payload.outbox_row = Some(
            serde_json::from_value(serde_json::json!({
                "g": u64::MAX, "s": u64::MAX, "digest": format!("sha256:{}", "ff".repeat(32)),
            }))
            .unwrap(),
        );
        payload.row_provenance = None;
        let mut receipt = serde_json::to_value(&payload.receipt).unwrap();
        receipt["version"] = serde_json::json!(2);
        receipt["policy_sequence"] = serde_json::json!(i64::MIN);
        for field in [
            "issued_at_unix_ms",
            "expires_at_unix_ms",
            "verified_at_unix_ms",
        ] {
            receipt[field] = serde_json::json!(u64::MAX);
        }
        let host = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        receipt["expected_origin"] = serde_json::json!(format!("https://{host}:65535"));
        receipt["cert_spki_sha256"] = serde_json::json!("ff".repeat(32));
        receipt["listener_policy_digest"] = serde_json::json!("ff".repeat(32));
        receipt["assertion"]["credential_id"] = serde_json::json!(
            vec![255u8; stellar_agent_core::approval::presence::CREDENTIAL_ID_MAX_BYTES]
        );
        receipt["assertion"]["authenticator_data"] = serde_json::json!(vec![255u8; 37]);
        receipt["assertion"]["client_data_json"] = serde_json::json!(vec![255u8; 1024]);
        receipt["assertion"]["signature_compact"] = serde_json::json!(vec![127u8; 64]);
        payload.receipt = serde_json::from_value(receipt).unwrap();
        for queued in [true, false] {
            let consent = record.consent.as_mut().unwrap();
            if !queued {
                consent.delivery = Some(ConsentDeliveryV1::direct_anchored(record.id));
                let payload = consent.payload.as_mut().unwrap();
                payload.outbox_row = None;
                payload.row_provenance = Some(RowProvenance::Written);
            }
            assert!(
                consent.delivery.as_ref().unwrap().matches(
                    record.id,
                    consent.payload.as_ref().unwrap().outbox_row.as_ref()
                ),
                "size fixtures use consistent delivery"
            );
            let bytes = serde_json::to_vec(&record).unwrap();
            assert!(bytes.len() <= APPROVAL_RECORD_MAX, "{}", bytes.len());
            assert_eq!(
                serde_json::from_slice::<WireApproval>(&bytes).unwrap(),
                record
            );
        }
    }

    fn queued_reference(sequence: u64) -> OutboxRowRef {
        serde_json::from_value(serde_json::json!({
            "g": 3, "s": sequence, "digest": format!("sha256:{}", "ab".repeat(32)),
        }))
        .unwrap()
    }

    fn queued(fx: &Fx, sequence: u64) -> ConsentPayload {
        ConsentPayload::new(
            fx.payload.attestation,
            fx.payload.receipt.clone(),
            fx.payload.process_uid.clone(),
            ConsentRow::Queued(queued_reference(sequence)),
        )
    }

    /// A payload without a queued reference names where its row went. The
    /// write refuses a payload that states both or neither, and the
    /// validation refuses one that states both.
    #[test]
    #[serial]
    fn missing_reference_states_its_provenance() {
        let mut fx = Fx::new(300_000);
        for (row, provenance) in [
            (ConsentRow::Written, "written"),
            (ConsentRow::Recovered, "recovered"),
        ] {
            let payload = ConsentPayload::new(
                fx.payload.attestation,
                fx.payload.receipt.clone(),
                fx.payload.process_uid.clone(),
                row,
            );
            let expected = format!(
                "{{\"attestation\":\"{}\",\"receipt\":{},\"process_uid\":{},\"row_provenance\":\"{provenance}\"}}",
                stellar_agent_core::hex::encode(&payload.attestation),
                serde_json::to_string(&payload.receipt).unwrap(),
                serde_json::to_string(&payload.process_uid).unwrap(),
            );
            assert_eq!(serde_json::to_string(&payload).unwrap(), expected);
            assert_eq!(
                serde_json::from_str::<ConsentPayload>(&expected).unwrap(),
                payload
            );
        }
        fx.open();
        let id = fx.id();
        let before = fx.bytes();
        for (outbox_row, row_provenance) in [
            (None, None),
            (Some(queued_reference(7)), Some(RowProvenance::Written)),
        ] {
            let mut payload = fx.payload.clone();
            payload.outbox_row = outbox_row;
            payload.row_provenance = row_provenance;
            assert!(matches!(
                ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
                    .record_consent(id, &fx.witness, &payload),
                Err(WindowStoreError::UnexpectedState { .. })
            ));
            assert_eq!(fx.bytes(), before);
        }
        fx.payload.row_provenance = Some(RowProvenance::Recovered);
        fx.consent();
        let mut wire = fx.wire();
        wire.approvals.as_mut().unwrap().records[0]
            .consent
            .as_mut()
            .unwrap()
            .payload
            .as_mut()
            .unwrap()
            .outbox_row = Some(queued_reference(7));
        assert!(matches!(
            Approvals::validate(&wire),
            Err(WindowStoreError::Invalid { .. })
        ));
    }

    #[test]
    #[serial]
    fn consent_delivery_codec_and_legacy_bytes() {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let mut fx = Fx::new(300_000);
        fx.open();
        let consent = fx.consent().record.consent.unwrap();
        let legacy = format!(
            "{{\"consent_at_ms\":{},\"execution_expires_at_ms\":{},\"receipt_sha256\":\"{}\",\"payload\":{}}}",
            consent.consent_at_ms,
            consent.execution_expires_at_ms,
            stellar_agent_core::hex::encode(&consent.receipt_sha256),
            serde_json::to_string(consent.payload.as_ref().unwrap()).unwrap(),
        );
        assert_eq!(serde_json::to_string(&consent).unwrap(), legacy);
        assert_eq!(serde_json::from_str::<Consent>(&legacy).unwrap(), consent);
        for (name, value) in [
            (
                "direct_anchored",
                ConsentDeliveryV1::direct_anchored([0xab; 32]),
            ),
            ("queued", ConsentDeliveryV1::queued([0xab; 32])),
        ] {
            let canonical = format!(
                "{{\"v\":1,\"identity\":\"{}\",\"provenance\":\"{name}\"}}",
                "ab".repeat(32)
            );
            assert_eq!(serde_json::to_string(&value).unwrap(), canonical);
            assert_eq!(
                serde_json::from_str::<ConsentDeliveryV1>(&canonical).unwrap(),
                value
            );
            let reordered = format!(
                "{{ \"provenance\":\"{name}\", \"identity\":\"{}\", \"v\":1 }}",
                "ab".repeat(32)
            );
            assert_eq!(
                serde_json::from_str::<ConsentDeliveryV1>(&reordered).unwrap(),
                value
            );
            for invalid in [
                canonical.replace("\"v\":1", "\"v\":2"),
                canonical.replace("\"v\":1", "\"v\":0"),
                canonical.replace("\"v\":1", "\"v\":256"),
                canonical.replace("\"v\":1", "\"v\":1,\"v\":1"),
                canonical.replace("\"v\":1,", ""),
                canonical.replace("\"v\":1", "\"v\":1,\"extra\":0"),
                canonical.replace("ab", "AB"),
                canonical.replace(&"ab".repeat(32), "ab"),
                canonical.replace(name, "written"),
            ] {
                assert!(
                    serde_json::from_str::<ConsentDeliveryV1>(&invalid).is_err(),
                    "reject {invalid}"
                );
            }
        }
    }

    /// A window that holds a direct consent payload with neither a reference
    /// nor a provenance reads with that payload as stored, writes nothing on
    /// the read, and its record still mints.
    #[test]
    #[serial]
    fn a_stored_payload_without_reference_or_provenance_reads_unchanged() {
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let mut wire = fx.wire();
        let stored = wire.approvals.as_mut().unwrap().records[0]
            .consent
            .as_mut()
            .unwrap()
            .payload
            .as_mut()
            .unwrap();
        stored.row_provenance = None;
        assert_eq!(stored.outbox_row, None);
        let earlier = stored.clone();
        fx.store
            .seal_unchecked_for_test(fx.fixture.profile(), &wire);
        let before = fx.bytes();
        let read = ApprovalStatus::new(&fx.store, fx.fixture.profile())
            .view(fx.id())
            .map(|view| view.and_then(|view| view.record.consent?.payload));
        assert!(
            matches!(&read, Ok(Some(payload)) if *payload == earlier),
            "the stored payload reads as written: {read:?}"
        );
        assert_eq!(fx.bytes(), before);
        assert_eq!(
            fx.wire().approvals.unwrap().records[0]
                .consent
                .as_ref()
                .unwrap()
                .payload,
            Some(earlier)
        );
        let request = fx.mint_request();
        fx.store
            .mint_authorization(fx.fixture.profile(), &request)
            .unwrap();
        assert_eq!(fx.view().record.state, ApprovalState::Consumed);
    }

    /// A new consent without a reference or a provenance refuses and writes
    /// nothing.
    #[test]
    #[serial]
    fn a_new_consent_without_reference_or_provenance_refuses() {
        let mut fx = Fx::new(300_000);
        fx.open();
        let id = fx.id();
        let before = fx.bytes();
        let mut payload = fx.payload.clone();
        payload.row_provenance = None;
        assert_eq!(payload.outbox_row, None);
        let refused =
            ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "request")
                .record_consent(id, &fx.witness, &payload);
        assert!(
            matches!(refused, Err(WindowStoreError::UnexpectedState { .. })),
            "a new consent states where its row went: {refused:?}"
        );
        assert_eq!(fx.bytes(), before);
        assert_eq!(fx.view().record.consent, None);
    }

    #[test]
    #[serial]
    fn queued_consent_stores_its_reference() {
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.payload = queued(&fx, 7);
        assert_eq!(fx.payload.outbox_row, Some(queued_reference(7)));
        assert_eq!(fx.payload.row_provenance, None);
        let consent = fx.consent().record.consent.unwrap();
        assert_eq!(consent.payload, Some(fx.payload.clone()));
        let stored = fx.wire();
        assert_eq!(
            stored.approvals.unwrap().records[0]
                .consent
                .as_ref()
                .unwrap()
                .payload,
            Some(fx.payload.clone())
        );
        let round_trip: ConsentPayload =
            serde_json::from_slice(&serde_json::to_vec(&fx.payload).unwrap()).unwrap();
        assert_eq!(round_trip, fx.payload);
        let mut intent = fx.payload.clone();
        intent.challenge_subject = Some([0x34; 32]);
        let expected_intent = format!(
            "{},\"challenge_subject\":\"{}\"}}",
            serde_json::to_string(&fx.payload)
                .unwrap()
                .strip_suffix('}')
                .unwrap(),
            "34".repeat(32)
        );
        assert_eq!(serde_json::to_string(&intent).unwrap(), expected_intent);
        assert_eq!(
            serde_json::from_str::<ConsentPayload>(&expected_intent).unwrap(),
            intent
        );
        let mut wire = fx.wire();
        for (kind, subject, valid) in [
            (SubjectKind::EnvelopeText, None, true),
            (SubjectKind::EnvelopeText, Some([0x34; 32]), false),
            (SubjectKind::IntentDigest, None, false),
            (SubjectKind::IntentDigest, Some([0x34; 32]), true),
        ] {
            // Storage validation is isolated from the separately tested HMAC check.
            let record = &mut wire.approvals.as_mut().unwrap().records[0];
            record.subject_kind = kind;
            record
                .consent
                .as_mut()
                .unwrap()
                .payload
                .as_mut()
                .unwrap()
                .challenge_subject = subject;
            assert_eq!(
                Approvals::validate(&wire).is_ok(),
                valid,
                "challenge presence {kind:?} {subject:?}"
            );
        }
        let mut malformed = serde_json::to_value(&fx.payload).unwrap();
        malformed["outbox_row"]["digest"] = "sha256:AB".into();
        assert!(serde_json::from_value::<ConsentPayload>(malformed).is_err());
    }

    #[test]
    #[serial]
    fn a_second_consent_keeps_its_receipt_rule() {
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.payload = queued(&fx, 7);
        let first = fx.consent();
        let before = fx.bytes();
        fx.payload = queued(&fx, 8);
        assert_eq!(
            fx.consent(),
            first,
            "same receipt keeps the original payload"
        );
        assert_eq!(fx.bytes(), before);
        let (witness, mut payload) = proof(&fx.fixture, &fx.entry, "second.toml");
        payload.outbox_row = Some(queued_reference(9));
        payload.row_provenance = None;
        assert_ne!(payload.receipt.digest(), fx.payload.receipt.digest());
        let id = fx.id();
        assert!(matches!(
            fx.recorder().record_consent(id, &witness, &payload),
            Err(WindowStoreError::UnexpectedState { .. })
        ));
        assert_eq!(fx.bytes(), before);
    }
}
