//! The authenticated record of one mainnet approval.
//!
//! Consent fixes an execution window. Minting consumes the record in the
//! authorization's generation commit, and only its operation can reuse it.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::approval::{
    AttestationBinding, AttestationScope, AttestedApprover, AttestedLifetime, load_attestation_key,
    mainnet_attestation_version,
    presence::MainnetPresenceReceipt,
    subject::{SubjectKind, length_prefixed},
    verify_attestation,
    witness::{ApprovalWitness, ApprovedKind},
};
use stellar_agent_core::profile::{
    Profile, name::profile_name_for_approval, owner_key::OwnerKeyContext,
};

use super::WindowStoreError;
use super::operations::{
    APPROVAL_NONCE_MAX, CapacityDetail, FILE_THRESHOLD, OperationAudit, OperationId, OperationLink,
    OperationRecorder, WindowSection,
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
}

impl std::fmt::Debug for ConsentPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentPayload").finish_non_exhaustive()
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

    fn facts(&self) -> PendingApprovalFacts {
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
                        || payload.receipt.digest() != Some(consent.receipt_sha256)
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

/// Records approval changes under one window lock and one generation commit.
#[derive(Debug)]
pub struct ApprovalRecorder<'a> {
    recorder: OperationRecorder<'a>,
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
        }
    }

    /// Opens a pending record, links its operation and records the waiting edge.
    ///
    /// # Errors
    ///
    /// Refuses inconsistent facts, conflicting identities, capacity, audit failures and store errors.
    pub fn open_pending(
        &mut self,
        operation_id: OperationId,
        facts: &PendingApprovalFacts,
    ) -> Result<ApprovalView, WindowStoreError> {
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
            session.await_approval(operation_id, id, facts.intent_digest)?;
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
        self.recorder.run(None, |session| {
            let profile = session.profile;
            let record = session
                .wire
                .approvals
                .as_mut()
                .and_then(|s| s.records.iter_mut().find(|r| r.id == id))
                .ok_or_else(|| unexpected("the approval record is absent"))?;
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
            if let Some(consent) = &record.consent {
                if consent.receipt_sha256 == digest {
                    return Ok(record.view(session.now));
                }
                return Err(unexpected("the approval already holds another consent"));
            }
            let at = payload.receipt.verified_at_unix_ms();
            check_consent_time(record, at)?;
            verify_payload(profile, record, payload)?;
            record.consent = Some(Consent {
                consent_at_ms: at,
                execution_expires_at_ms: execution_expiry(at, record.rule_ttl_ms)?,
                receipt_sha256: digest,
                payload: Some(payload.clone()),
            });
            if serialized_len(record) > APPROVAL_RECORD_MAX {
                return Err(invalid("the approval record exceeds its allowance"));
            }
            session.changed = true;
            Ok(record.view(session.now))
        })
    }

    /// Revokes a live approval without an operation transition or audit row.
    ///
    /// # Errors
    ///
    /// Refuses an absent record, a clock before creation and store errors.
    pub fn revoke(&mut self, id: [u8; 32]) -> Result<ApprovalView, WindowStoreError> {
        self.recorder.run(None, |session| {
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
        })
    }
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
}

/// Consumes on the caller's successor image; its mint commits this change.
pub(super) fn consume(
    wire: &mut WireFile,
    nonce: &str,
    operation: Option<OperationLink>,
    now: u64,
) -> Result<(), WindowStoreError> {
    let Some(record) = wire
        .approvals
        .as_mut()
        .and_then(|s| s.records.iter_mut().find(|r| r.nonce == nonce))
    else {
        return Ok(());
    };
    let refuse = |precondition| WindowStoreError::AuthorizationRefused { precondition };
    if record.state == ApprovalState::Revoked {
        return Err(refuse(MainnetPrecondition::ApprovalRevoked));
    }
    if operation.is_none_or(|link| link.operation_id != record.operation_id) {
        return Err(refuse(MainnetPrecondition::ApprovalNonceReused));
    }
    if now >= record.expiry() {
        return Err(refuse(MainnetPrecondition::ApprovalExpired));
    }
    let Some(consent) = &record.consent else {
        return Err(refuse(MainnetPrecondition::ApprovalConsentMissing));
    };
    if now < consent.consent_at_ms {
        // Mint time must be at or after the recorded consent time.
        return Err(refuse(MainnetPrecondition::ApprovalExpired));
    }
    if record.state == ApprovalState::Pending {
        record.state = ApprovalState::Consumed;
        record.consumed_at_ms = Some(now);
    }
    Ok(())
}

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
        entry: PendingApproval,
    }

    fn proof(
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
        let subject = match &entry.kind {
            stellar_agent_core::approval::store::ApprovalKind::PaymentSimulated {
                envelope_xdr_b64,
                ..
            } => approval_subject_classic(envelope_xdr_b64),
            _ => panic!("expected payment"),
        };
        let witness = verify_approval(
            &inbox,
            fixture.profile(),
            fixture.name(),
            &entry.approval_nonce,
            &attestation,
            &ApprovalExpectation {
                kind: ApprovedKind::Payment,
                subject,
            },
            &policy,
            receipt.verified_at_unix_ms(),
        )
        .unwrap();
        (
            witness,
            ConsentPayload {
                attestation,
                receipt,
                process_uid: entry.process_uid.clone(),
            },
        )
    }

    impl Fx {
        pub(in crate::policy_state) fn new(ttl: u64) -> Self {
            let fixture = MainnetConsentFixture::new("approvals");
            let mut entry = fixture.payment(ttl);
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
                    tool: OperationTool::CliPay,
                    kind: OperationKind::Pay,
                    intent: IntentSlot::Canonical {
                        intent_digest: [1; 32],
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
                subject_kind: SubjectKind::EnvelopeText,
                subject: witness.subject(),
                intent_digest: [1; 32],
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
            self.recorder().open_pending(operation, &facts).unwrap()
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
                native_reservation: None,
            }
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
            fx.recorder().open_pending(operation, &facts),
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
                fx.recorder().open_pending(operation, &facts),
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
        assert!(fx.recorder().open_pending(operation, &changed).is_err());
        let facts = fx.facts.clone();
        assert!(
            fx.recorder()
                .open_pending(OperationId::random(), &facts)
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
            assert!(fx.recorder().open_pending(operation, &facts).is_err());
        }
        for ttl in [0, 86_400_001, u64::MAX] {
            let mut facts = fx.facts.clone();
            facts.rule_ttl_ms = ttl;
            facts.waiting_expires_at_ms = facts.created_at_ms.saturating_add(ttl);
            assert!(fx.recorder().open_pending(operation, &facts).is_err());
        }
        assert_eq!(fx.bytes(), before);
    }

    #[test]
    #[serial]
    fn consent_sets_both_clocks_once() {
        for (ttl, execution) in [(86_400_000, 900_000), (300_000, 300_000)] {
            let mut fx = Fx::new(ttl);
            fx.open();
            let view = fx.consent();
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
            .open_pending(handle.id(), &facts)
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
        let refused = ConsentPayload {
            attestation: version_5,
            receipt: receipt.clone(),
            process_uid: entry.process_uid.clone(),
        };
        assert!(
            ApprovalRecorder::new(&store, fixture.profile(), &mut rows, "request")
                .record_consent(id, &witness, &refused)
                .is_err(),
            "a version 5 blob on an intent record"
        );
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        let payload = ConsentPayload {
            attestation,
            receipt: receipt.clone(),
            process_uid: entry.process_uid.clone(),
        };
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
        assert_eq!(consent.payload, Some(payload));
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
        let mut fx = Fx::new(300_000);
        fx.open();
        fx.consent();
        let request = fx.mint_request();
        fx.store
            .mint_authorization(fx.fixture.profile(), &request)
            .unwrap();
        let current = fx.wire();
        let record = &current.approvals.as_ref().unwrap().records[0];
        let consent = record.consent.as_ref().unwrap();
        assert!(consent.payload.is_some());
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
            assert_eq!(after.consent, Some(expected));
            assert_eq!(after.waiting_expires_at_ms, record.waiting_expires_at_ms);
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
            let view = fx.recorder().revoke(id).unwrap();
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
        c.consent_at_ms = u64::MAX;
        c.execution_expires_at_ms = u64::MAX;
        let payload = c.payload.as_mut().unwrap();
        payload.process_uid = "\u{0001}".repeat(PROCESS_UID_MAX);
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
        let bytes = serde_json::to_vec(&record).unwrap();
        assert!(bytes.len() <= APPROVAL_RECORD_MAX, "{}", bytes.len());
        assert_eq!(
            serde_json::from_slice::<WireApproval>(&bytes).unwrap(),
            record
        );
    }
}
