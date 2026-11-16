//! Non-consuming verification of strictly loaded approval evidence.
//!
//! Inspection grants no signing or retry authority. A commit still compares
//! its independent expected subject and checks receipt and nonce single use.
//! Expiry is a view at the supplied time, with no durable clock watermark.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

use super::attestation::{AttestationScope, AttestedApprover, AttestedLifetime};
use super::presence::{MainnetPresenceReceipt, approval_view_subject};
use super::subject::SubjectKind;
use super::witness::{ApprovalDisposition, ApprovalFacts, ApprovedKind, inbox_kind};
use super::{ApprovalError, ApprovalKind, AttestationBinding, PendingApproval};
use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::policy::v1::{PolicyStateStore, verified};
use crate::profile::{caip2::Caip2, owner_key::OwnerKeyContext, schema::Profile};

/// The closed diagnostic reasons, ordered by the inspection boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionReason {
    /// The stored approval was consumed.
    Consumed,
    /// The operator rejected the stored approval.
    Rejected,
    /// The durable approval was revoked.
    Revoked,
    /// Stored proof or its bindings do not verify.
    AttestationInvalid,
    /// Required provenance, retained proof, key or policy is unavailable.
    VerificationUnavailable,
    /// The applicable stored upper clock boundary has passed.
    Expired,
    /// The receipt names another policy signature.
    PolicyResigned,
    /// The policy has no key for the receipt's credential.
    CredentialRemoved,
    /// The attestation layout does not belong to this subject kind.
    KindMismatch,
    /// Consent or inspection falls outside the signed execution window.
    WindowClosed,
    /// Every applicable check passed.
    Ok,
}

/// A diagnostic result, without an approval witness or consumption effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Inspection {
    /// Whether the retained evidence verifies at the supplied time.
    pub valid: bool,
    /// The first applicable diagnostic reason.
    pub reason: InspectionReason,
}

impl Inspection {
    fn because(reason: InspectionReason) -> Self {
        Self {
            valid: reason == InspectionReason::Ok,
            reason,
        }
    }

    /// Required evidence or verification context could not be loaded.
    #[must_use]
    pub fn unavailable() -> Self {
        Self::because(InspectionReason::VerificationUnavailable)
    }
}

/// Stored evidence from the inbox or the authenticated durable reader.
#[derive(Debug, Clone, Copy)]
pub enum InspectionEntry<'a> {
    /// A strictly decoded inbox entry, cloned before releasing its lock.
    Pending(&'a PendingApproval),
    /// Facts from the authenticated durable store, selected by public nonce.
    Durable(&'a ApprovalFacts),
}

/// Additional authenticated execution bounds. They can only narrow the
/// lifetime verified from the retained consent.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionWindow {
    /// The inclusive consent boundary.
    pub consent_at_ms: u64,
    /// The exclusive execution boundary.
    pub expires_at_ms: u64,
}

/// One verification context, loaded after kind and structural checks.
/// The key is zeroized on drop; debug output contains no key or proof bytes.
pub struct InspectionContext<'a> {
    key: Zeroizing<[u8; 32]>,
    policy: Option<VerifiedPolicy>,
    profile: &'a str,
    chain: Caip2,
    execution_window: Option<ExecutionWindow>,
}

impl std::fmt::Debug for InspectionContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InspectionContext").finish_non_exhaustive()
    }
}

impl<'a> InspectionContext<'a> {
    /// Prechecks stored evidence before loading the gate's HMAC key and one
    /// compare-only signed policy. Testnet never reads a policy or its pin.
    /// `Ok(None)` identifies an unsupported inbox kind.
    ///
    /// # Errors
    /// Returns the first tombstone, structural or unavailable inspection.
    pub fn for_entry(
        entry: InspectionEntry<'_>,
        profile_name: &'a str,
        profile: &Profile,
        execution_window: Option<ExecutionWindow>,
    ) -> Result<Option<Self>, Inspection> {
        if precheck(entry, profile_name, profile.chain_id)?.is_none() {
            return Ok(None);
        }
        let key = super::load_attestation_key(
            &profile.attestation_key_id,
            &OwnerKeyContext::for_profile(profile_name, profile),
        )
        .map_err(|_| Inspection::unavailable())?;
        let key = Zeroizing::new(
            key.as_slice()
                .try_into()
                .map_err(|_| Inspection::unavailable())?,
        );
        let policy = if profile.chain_id.is_mainnet() {
            Some(load_policy(profile_name, profile).ok_or_else(Inspection::unavailable)?)
        } else {
            None
        };
        Ok(Some(Self {
            key,
            policy,
            profile: profile_name,
            chain: profile.chain_id,
            execution_window,
        }))
    }
}

fn load_policy(name: &str, profile: &Profile) -> Option<VerifiedPolicy> {
    let owner = super::presence_policy::read_owner_key(profile).ok()?;
    let path = crate::profile::schema::default_policy_dir()
        .ok()?
        .join(format!("{name}.toml"));
    let window_path = crate::profile::schema::default_policy_window_state_path_for(name);
    verified::inspect_verified_policy(
        &verified::PolicyLoad {
            path: &path,
            profile,
            profile_name: name,
            owner_pubkey: &owner,
            owner_source: verified::OwnerKeySource::Keyring,
            window_path: &window_path,
        },
        PolicyStateStore::new(),
    )
    .verified
    .ok()
}

/// Inspects stored evidence using a freshly loaded context. Unsupported inbox
/// kinds return `None`; callers must report unsupported validity as null.
#[must_use]
pub fn inspect_stored_approval(
    entry: InspectionEntry<'_>,
    now_ms: u64,
    profile_name: &str,
    profile: &Profile,
    execution_window: Option<ExecutionWindow>,
) -> Option<Inspection> {
    match InspectionContext::for_entry(entry, profile_name, profile, execution_window) {
        Ok(Some(ctx)) => Some(inspect_approval(entry, now_ms, &ctx)),
        Ok(None) => None,
        Err(inspection) => Some(inspection),
    }
}

/// Verifies stored proof without loading, consuming, repairing or auditing.
/// The context supplies no independent commit expectation or spend permission.
#[must_use]
pub fn inspect_approval(
    entry: InspectionEntry<'_>,
    now_ms: u64,
    ctx: &InspectionContext<'_>,
) -> Inspection {
    let proof = match precheck(entry, ctx.profile, ctx.chain) {
        Ok(Some(proof)) => proof,
        Ok(None) => return Inspection::unavailable(),
        Err(result) => return result,
    };
    Inspection::because(inspect_proof(entry, &proof, now_ms, ctx))
}

struct Proof<'a> {
    nonce: &'a str,
    uid: &'a str,
    kind: &'a str,
    subject_kind: SubjectKind,
    subject: [u8; 32],
    created: u64,
    expires: u64,
    version: u32,
    approver: AttestedApprover,
    receipt: Option<&'a MainnetPresenceReceipt>,
    attestation: [u8; 32],
}

fn supported(kind: &ApprovalKind) -> bool {
    matches!(
        kind,
        ApprovalKind::PaymentSimulated { .. }
            | ApprovalKind::ClaimSimulated { .. }
            | ApprovalKind::TrustlineSimulated { .. }
            | ApprovalKind::X402Payment { .. }
    )
}

fn precheck<'a>(
    entry: InspectionEntry<'a>,
    profile: &str,
    chain: Caip2,
) -> Result<Option<Proof<'a>>, Inspection> {
    use InspectionReason as R;
    let invalid = || Inspection::because(R::AttestationInvalid);
    let proof = match entry {
        InspectionEntry::Pending(entry) => {
            match entry.kind {
                ApprovalKind::Consumed { .. } => return Err(Inspection::because(R::Consumed)),
                ApprovalKind::Rejected { .. } => return Err(Inspection::because(R::Rejected)),
                _ if !supported(&entry.kind) => return Ok(None),
                _ => {}
            }
            if entry.expires_at_unix_ms < entry.created_at_unix_ms {
                return Err(invalid());
            }
            let attestation = entry
                .attestation_blob_b64
                .as_ref()
                .and_then(|blob| URL_SAFE_NO_PAD.decode(blob).ok())
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(invalid)?;
            if entry
                .mainnet_presence
                .as_ref()
                .is_some_and(|r| !r.is_well_formed())
                || matches!(entry.attestation_version, 5 | 6) && entry.mainnet_presence.is_none()
            {
                return Err(invalid());
            }
            super::verify_stored_destination(&entry.kind).map_err(|_| invalid())?;
            let subject =
                approval_view_subject(entry, &AttestationBinding::new(profile, chain.caip2_str()))
                    .map_err(|_| invalid())?;
            if !matches!(entry.attestation_version, 4..=6) {
                return Err(Inspection::unavailable());
            }
            let approver = entry
                .attested_approver
                .clone()
                .ok_or_else(Inspection::unavailable)?;
            // The inbox retains the envelope, but no canonical intent digest.
            // That digest and the original challenge subject need durable facts.
            if entry.subject_kind == SubjectKind::IntentDigest {
                return Err(Inspection::unavailable());
            }
            Proof {
                nonce: &entry.approval_nonce,
                uid: &entry.process_uid,
                kind: entry.kind.kind_name(),
                subject_kind: entry.subject_kind,
                subject,
                created: entry.created_at_unix_ms,
                expires: entry.expires_at_unix_ms,
                version: entry.attestation_version,
                approver,
                receipt: entry.mainnet_presence.as_ref(),
                attestation,
            }
        }
        InspectionEntry::Durable(facts) => {
            let record = facts.record();
            match record.disposition {
                ApprovalDisposition::Consumed => return Err(Inspection::because(R::Consumed)),
                ApprovalDisposition::Revoked => return Err(Inspection::because(R::Revoked)),
                ApprovalDisposition::Pending => {}
            }
            if record.expires_at_ms < record.created_at_ms {
                return Err(invalid());
            }
            let consent = record.consent.as_ref().ok_or_else(invalid)?;
            let payload = consent
                .payload
                .as_ref()
                .ok_or_else(Inspection::unavailable)?;
            if !payload.receipt.is_well_formed() {
                return Err(invalid());
            }
            Proof {
                nonce: &record.nonce,
                uid: &payload.process_uid,
                kind: inbox_kind(record.kind),
                subject_kind: record.subject_kind,
                subject: record.subject,
                created: record.created_at_ms,
                expires: record.expires_at_ms,
                version: super::mainnet_attestation_version(record.subject_kind),
                approver: AttestedApprover::MainnetPasskey {
                    credential_id_b64url: payload.receipt.credential_id_b64url(),
                },
                receipt: Some(&payload.receipt),
                attestation: payload.attestation,
            }
        }
    };
    Ok(Some(proof))
}

fn inspect_proof(
    entry: InspectionEntry<'_>,
    proof: &Proof<'_>,
    now: u64,
    ctx: &InspectionContext<'_>,
) -> InspectionReason {
    use InspectionReason as R;
    let canonical = proof.subject_kind == SubjectKind::IntentDigest;
    let consent = proof
        .receipt
        .map(MainnetPresenceReceipt::verified_at_unix_ms);
    let expiry = match entry {
        InspectionEntry::Durable(facts) => facts
            .record()
            .consent
            .as_ref()
            .map(|c| c.execution_expires_at_ms),
        InspectionEntry::Pending(_) => Some(proof.expires),
    };
    if expiry.is_some_and(|expiry| now >= expiry) || (!canonical && now >= proof.expires) {
        return R::Expired;
    }
    if ctx.chain.is_mainnet() {
        let Some(policy) = &ctx.policy else {
            return R::VerificationUnavailable;
        };
        if let Some(receipt) = proof.receipt {
            if !receipt.names_policy(policy) {
                return R::PolicyResigned;
            }
            if policy.mainnet().is_none_or(|body| {
                !body.approval_credentials.iter().any(|credential| {
                    credential.credential_id_b64url() == receipt.credential_id_b64url()
                })
            }) {
                return R::CredentialRemoved;
            }
        }
    }
    let scope = AttestationScope::pending_for_subject(
        proof.version,
        AttestedLifetime::new(proof.kind, proof.created, proof.expires),
        Some(&proof.approver),
        proof.receipt,
        proof.subject_kind,
    );
    let Some(scope) = scope else {
        return if proof.version != super::mainnet_attestation_version(proof.subject_kind)
            && proof.version != super::PENDING_ATTESTATION_VERSION
        {
            R::KindMismatch
        } else {
            R::AttestationInvalid
        };
    };
    if canonical && (proof.kind == inbox_kind(ApprovedKind::X402Payment) || consent.is_none()) {
        return R::KindMismatch;
    }
    if now < proof.created
        || consent.is_some_and(|at| at < proof.created || at >= proof.expires || at > now)
        || ctx
            .execution_window
            .is_some_and(|window| now < window.consent_at_ms || now >= window.expires_at_ms)
    {
        return R::WindowClosed;
    }
    if canonical
        && consent.is_some_and(|at| {
            at.checked_add(900_000.min(proof.expires - proof.created))
                .is_none_or(|end| now >= end)
        })
    {
        return R::WindowClosed;
    }
    if ctx.chain.is_mainnet()
        != matches!(scope, AttestationScope::V5(..) | AttestationScope::V6(..))
    {
        return R::AttestationInvalid;
    }
    let binding = AttestationBinding::new(ctx.profile, ctx.chain.caip2_str());
    if !super::verify_attestation(
        &ctx.key,
        &binding,
        proof.nonce,
        &proof.subject,
        proof.uid,
        &scope,
        &proof.attestation,
    ) {
        return R::AttestationInvalid;
    }
    if let InspectionEntry::Durable(facts) = entry {
        let record = facts.record();
        if facts.profile() != ctx.profile
            || facts.chain() != ctx.chain
            || (canonical && record.subject != record.intent_digest)
            || record.expires_at_ms.checked_sub(record.created_at_ms) != Some(record.rule_ttl_ms)
            || record.consent.as_ref().is_none_or(|c| {
                Some(c.consent_at_ms) != consent
                    || proof.receipt.and_then(MainnetPresenceReceipt::digest)
                        != Some(c.receipt_sha256)
            })
        {
            return R::AttestationInvalid;
        }
    }
    if let (Some(policy), Some(receipt)) = (&ctx.policy, proof.receipt) {
        let digest = canonical.then_some(&proof.subject);
        let verified = match entry {
            InspectionEntry::Pending(entry) => super::presence::verify_receipt_for_inspection(
                entry, receipt, &binding, policy, digest, now,
            ),
            InspectionEntry::Durable(facts) => super::presence::verify_receipt_for_inspection(
                facts, receipt, &binding, policy, digest, now,
            ),
        };
        if verified.is_err() {
            return R::AttestationInvalid;
        }
    }
    R::Ok
}

/// Strictly opens and clones the first matching nonce, releasing the inbox
/// sidecar before the caller reads policy or durable state. It never collects.
///
/// # Errors
/// Every open failure is `approval.store_open_failed` with a safe cause class.
pub fn read_pending_approval(
    path: &std::path::Path,
    nonce: &str,
) -> Result<Option<PendingApproval>, WalletError> {
    super::open_with_retry(
        path,
        super::DEFAULT_RETRY_ATTEMPTS,
        super::DEFAULT_RETRY_BACKOFF,
    )
    .map(|store| store.get(nonce).cloned())
    .map_err(|error| store_open_error(&error))
}

/// Maps status opening failures without exposing stored values or paths.
#[must_use]
pub fn store_open_error(error: &ApprovalError) -> WalletError {
    let cause = match error {
        ApprovalError::WriterLocked => "lock",
        ApprovalError::Permission { .. } => "permission",
        ApprovalError::Io { .. } => "I/O",
        ApprovalError::Toml { .. } => "decoding",
        ApprovalError::InvalidNonceLength { .. } => "nonce decoding",
        ApprovalError::InvalidEntry { .. } => "entry decoding",
        _ => "store",
    };
    WalletError::Approval(ApprovalFailure::StoreOpenFailed {
        detail: format!("approval store open failed: {cause}"),
    })
}

#[cfg(test)]
mod tests;
