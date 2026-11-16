//! Read-only durable approval facts and their proof verification.

use super::*;
use crate::approval::attestation::{AttestedApprover, AttestedLifetime};
use crate::approval::presence::MainnetPresenceReceipt;
use crate::audit_log::OutboxRowRef;

/// The durable disposition; expiry is determined from the retained clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDisposition {
    /// Consent or execution can still occur.
    Pending,
    /// The bound operation has consumed the approval.
    Consumed,
    /// Further proof admission refuses.
    Revoked,
}

/// Retained inputs authenticated by the consent attestation.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalPayloadFacts {
    /// The retained attestation bytes.
    pub attestation: [u8; 32],
    /// The original WebAuthn receipt.
    pub receipt: MainnetPresenceReceipt,
    /// The signed process identifier.
    pub process_uid: String,
    /// The original envelope subject for an intent challenge.
    pub challenge_subject: Option<[u8; 32]>,
    /// The queued consent reference, when retained.
    pub outbox_row: Option<OutboxRowRef>,
}

impl std::fmt::Debug for ApprovalPayloadFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalPayloadFacts")
            .finish_non_exhaustive()
    }
}

/// Immutable consent clocks and receipt identity, including after release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalConsentFacts {
    /// The original receipt's verified time.
    pub consent_at_ms: u64,
    /// The exclusive execution boundary.
    pub execution_expires_at_ms: u64,
    /// The retained receipt digest.
    pub receipt_sha256: [u8; 32],
    /// Reconstruction inputs; absent after release.
    pub payload: Option<ApprovalPayloadFacts>,
}

/// A durable record's fields, without granting approval authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecordFacts {
    /// The record identity.
    pub id: [u8; 32],
    /// The bound operation identity.
    pub operation_id: [u8; 16],
    /// The signed approval nonce.
    pub nonce: String,
    /// The stored disposition.
    pub disposition: ApprovalDisposition,
    /// The first consumption time.
    pub consumed_at_ms: Option<u64>,
    /// The revocation time.
    pub revoked_at_ms: Option<u64>,
    /// The approved action kind.
    pub kind: ApprovedKind,
    /// The signed subject convention.
    pub subject_kind: SubjectKind,
    /// The signed subject digest.
    pub subject: [u8; 32],
    /// The operation's intent digest.
    pub intent_digest: [u8; 32],
    /// The signed creation time.
    pub created_at_ms: u64,
    /// The signed waiting expiry.
    pub expires_at_ms: u64,
    /// The signed rule lifetime.
    pub rule_ttl_ms: u64,
    /// The write-once consent, when recorded.
    pub consent: Option<ApprovalConsentFacts>,
}

/// A projection from authenticated storage. Construction grants no authority;
/// only the durable verifiers construct an [`ApprovalWitness`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalFacts {
    profile: String,
    chain: Caip2,
    record: ApprovalRecordFacts,
}

impl ApprovalFacts {
    /// Projects `record` in the authenticated store's profile and chain scope.
    #[must_use]
    pub fn new(profile: String, chain: Caip2, record: ApprovalRecordFacts) -> Self {
        Self {
            profile,
            chain,
            record,
        }
    }

    /// The authenticated profile scope.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The authenticated chain scope.
    #[must_use]
    pub fn chain(&self) -> Caip2 {
        self.chain
    }

    /// The retained record fields.
    #[must_use]
    pub fn record(&self) -> &ApprovalRecordFacts {
        &self.record
    }
}

fn wrong_kind() -> WalletError {
    WalletError::Approval(ApprovalFailure::WrongKind {
        detail: "the approval does not bind this kind of subject".to_owned(),
    })
}

fn expired(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::Expired {
        detail: detail.to_owned(),
    })
}

/// Verifies retained envelope consent using the presented proof and current policy.
/// No inbox read is performed. Consumed records can verify retained consent;
/// the caller must compare the admitted operation identity separately.
///
/// # Errors
///
/// Returns `approval.not_found` for absent facts, `approval.binding_mismatch`
/// for scope mismatches, and `approval.revoked` for revoked records.
/// Missing consent, released payloads, clocks, proof and policy failures refuse
/// with the corresponding approval error, as in [`verify_approval`].
pub fn verify_durable_approval(
    facts: Option<&ApprovalFacts>,
    presented: &[u8; 32],
    profile: &Profile,
    profile_name: &str,
    expected: &ApprovalExpectation,
    policy: &VerifiedPolicy,
    now_ms: u64,
) -> Result<ApprovalWitness, WalletError> {
    verify(
        facts,
        presented,
        profile,
        profile_name,
        expected,
        None,
        policy,
        now_ms,
    )
}

/// Verifies retained canonical intent consent under a fresh classic decision.
/// Allow preserves the signed lifetime; RequireApproval must match that lifetime.
/// The resulting witness keeps the original signed times and consent clock.
///
/// # Errors
///
/// The errors of [`verify_durable_approval`], plus `approval.attestation_invalid`
/// for a decision that does not govern the intent and `approval.wrong_kind`
/// for envelope or x402 facts.
#[allow(
    clippy::too_many_arguments,
    reason = "each input belongs to the verification boundary"
)]
pub fn verify_durable_intent_approval(
    facts: Option<&ApprovalFacts>,
    presented: &[u8; 32],
    profile: &Profile,
    profile_name: &str,
    intent: &ClassicIntent,
    decision: &MainnetDecision,
    policy: &VerifiedPolicy,
    now_ms: u64,
) -> Result<ApprovalWitness, WalletError> {
    verify(
        facts,
        presented,
        profile,
        profile_name,
        &ApprovalExpectation {
            kind: intent.approved_kind(),
            subject: *intent.digest().as_bytes(),
        },
        Some((intent, decision)),
        policy,
        now_ms,
    )
}

fn consent(
    record: &ApprovalRecordFacts,
    now: u64,
) -> Result<(&ApprovalConsentFacts, &ApprovalPayloadFacts), WalletError> {
    if record.disposition == ApprovalDisposition::Revoked {
        return Err(WalletError::Approval(ApprovalFailure::Revoked {
            detail: "this approval has been revoked".to_owned(),
        }));
    }
    let Some(consent) = &record.consent else {
        return Err(if now >= record.expires_at_ms {
            expired("the consent is outside the waiting window")
        } else {
            WalletError::Approval(ApprovalFailure::PresenceRequired)
        });
    };
    let payload = consent
        .payload
        .as_ref()
        .ok_or_else(|| expired("the approval is outside its execution window"))?;
    Ok((consent, payload))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "shared ordered proof verification"
)]
fn verify(
    facts: Option<&ApprovalFacts>,
    presented: &[u8; 32],
    profile: &Profile,
    profile_name: &str,
    expected: &ApprovalExpectation,
    intent: Option<(&ClassicIntent, &MainnetDecision)>,
    policy: &VerifiedPolicy,
    now: u64,
) -> Result<ApprovalWitness, WalletError> {
    let facts = facts.ok_or_else(|| {
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "no durable approval record for that nonce".to_owned(),
        })
    })?;
    if !profile.chain_id.is_mainnet()
        || facts.chain != profile.chain_id
        || facts.profile != profile_name
    {
        return Err(WalletError::Approval(ApprovalFailure::BindingMismatch {
            detail: "the durable approval has another profile or chain".to_owned(),
        }));
    }
    let record = &facts.record;
    let (consent, payload) = consent(record, now)?;
    let subject_kind = if intent.is_some() {
        SubjectKind::IntentDigest
    } else {
        SubjectKind::EnvelopeText
    };
    if record.subject_kind != subject_kind || record.kind != expected.kind {
        return Err(wrong_kind());
    }
    if record.subject != expected.subject {
        return Err(invalid("the approval approves another transaction"));
    }
    let binding = AttestationBinding::new(&facts.profile, facts.chain.caip2_str());
    let approver = AttestedApprover::MainnetPasskey {
        credential_id_b64url: payload.receipt.credential_id_b64url(),
    };
    let scope = AttestationScope::pending_for_subject(
        crate::approval::mainnet_attestation_version(subject_kind),
        AttestedLifetime::new(
            record.kind.kind_name(),
            record.created_at_ms,
            record.expires_at_ms,
        ),
        Some(&approver),
        Some(&payload.receipt),
        subject_kind,
    )
    .ok_or(WalletError::Approval(ApprovalFailure::PresenceRequired))?;
    let key = attestation_key(profile, profile_name)?;
    if !verify_attestation(
        &key,
        &binding,
        &record.nonce,
        &record.subject,
        &payload.process_uid,
        &scope,
        presented,
    ) || payload.receipt.digest() != Some(consent.receipt_sha256)
    {
        return Err(invalid("the attestation does not verify"));
    }
    if record.expires_at_ms.checked_sub(record.created_at_ms) != Some(record.rule_ttl_ms)
        || consent.consent_at_ms != payload.receipt.verified_at_unix_ms()
    {
        return Err(invalid("the consent clocks do not match the signed facts"));
    }
    if let Some((intent, decision)) = intent {
        if !matches!(
            decision.decision(),
            Decision::Allow | Decision::RequireApproval(_)
        ) || *decision.scope() != AuthorityScope::Classic
            || decision.profile() != profile_name
            || decision.chain_id() != binding.chain_id
            || decision.policy_digest() != policy.digest()
            || *intent.base().policy_digest() != policy.digest()
            || intent.base().chain_id() != binding.chain_id
            || (matches!(decision.decision(), Decision::RequireApproval(_))
                && decision.governing_ttl_ms() != record.rule_ttl_ms)
        {
            return Err(invalid("the decision does not govern this approval"));
        }
    } else if now < record.created_at_ms || now >= record.expires_at_ms {
        return Err(expired("the approval is outside its lifetime"));
    }
    let execution = intent_clocks(
        record.created_at_ms,
        record.expires_at_ms,
        consent.consent_at_ms,
        record.rule_ttl_ms,
        now,
    )?;
    if now >= consent.execution_expires_at_ms {
        return Err(expired("the approval is outside its execution window"));
    }
    let current =
        MainnetApprovalAuthority::for_profile(profile_name)?.load_current_compare_only()?;
    if current.profile().chain_id != profile.chain_id || !current.is(policy) {
        return Err(WalletError::Approval(
            ApprovalFailure::PresencePolicyUnavailable,
        ));
    }
    super::super::presence::verify_receipt_for_facts(
        facts,
        &binding,
        policy,
        intent.map(|(intent, _)| intent),
        now,
    )?;
    Ok(ApprovalWitness {
        profile: facts.profile.clone(),
        chain: facts.chain,
        nonce: record.nonce.clone(),
        kind: record.kind,
        subject: record.subject,
        created_at_ms: record.created_at_ms,
        expires_at_ms: record.expires_at_ms,
        presence_receipt_digest: consent.receipt_sha256,
        policy_digest: policy.digest(),
        subject_kind,
        consent_at_ms: consent.consent_at_ms,
        execution_expires_at_ms: execution.min(consent.execution_expires_at_ms),
        challenge_subject: payload.challenge_subject,
    })
}
