//! The approval witness proves that a pending mainnet approval record
//! approves one subject. The record carries a version 5 or 6 attestation
//! with a verified WebAuthn presence: version 5 on an envelope-text record,
//! version 6 on an intent-digest record. When the witness is produced, the
//! record is live and the current owner-signed policy still authorizes it.
//!
//! [`verify_approval`] produces it for an envelope-text record, and
//! [`verify_intent_approval`] for an intent-digest record. Each producer
//! reads the record from the pending store by nonce. It reads the
//! attestation key from the keyring and the current signed policy from the
//! wallet's own locations. It derives the key coordinate and the owner
//! context from the profile exactly as the approve path does.
//!
//! From its caller, each producer takes only the store, the profile, the
//! nonce, the presented attestation, the policy the caller authorizes under,
//! and the time. The envelope producer also takes the expected kind and
//! subject. The intent producer also requires a canonical intent and a
//! governing decision. A witness therefore records facts the producer
//! establishes, and its fields are private:
//!
//! ```compile_fail,E0451
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn forge(p: ApprovalWitness) -> ApprovalWitness { ApprovalWitness { ..p } }
//! ```
//!
//! The import alone resolves:
//!
//! ```
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need(_: Option<ApprovalWitness>) {}
//! need(None);
//! ```
//!
//! The witness implements none of `Serialize`, `Deserialize`, `Default`, or
//! `Clone`:
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: serde::Serialize>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: serde::de::DeserializeOwned>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: Default>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! ```compile_fail,E0277
//! use stellar_agent_core::approval::witness::ApprovalWitness;
//! fn need<T: Clone>() {}
//! need::<ApprovalWitness>();
//! ```
//!
//! # Mainnet only, versions 5 and 6 only
//!
//! A witness is mainnet proof, and both producers refuse every binding that
//! is not mainnet. The record must carry a mainnet passkey approver and its
//! presence receipt under the layout its subject kind selects. That is
//! version 5 for the envelope text and version 6 for the intent digest. A
//! version 4 local or remote approval, which a terminal, a same-user process
//! or the remote allowlist can produce, is no proof, however genuine its
//! HMAC. Each producer refuses the other subject kind with
//! `approval.wrong_kind`.
//!
//! # Clocks
//!
//! A witness keeps the signed pending times, which its fact digest covers.
//! It also reports the consent time, the receipt's verified time, and the
//! exclusive execution expiry. An envelope witness has the signed expiry as
//! its execution expiry and requires the pending lifetime to be live.
//!
//! An intent witness requires `created <= consent < waiting expiry` and
//! `consent <= now < consent + min(900 s, governing TTL)`. It applies no
//! pending-expiry check. A restart or a retry recomputes the same clocks
//! from signed inputs, and nothing extends either one.
//!
//! # The current policy decides
//!
//! The producer loads the current owner-signed policy of the profile again,
//! comparing it with the pin without advancing it, and requires it to be the
//! policy the caller authorizes under and the policy the receipt names. It
//! then verifies the stored assertion again under the key that policy signs
//! for the credential, over the challenge recomputed from the record. A
//! credential the owner removed at a higher sequence, a policy signed since
//! the consent, or an unsigned edit produces no witness. The read is fresh
//! for every call. The pending-store lock precedes the window-state lock,
//! and the window-state lock is released before assertion verification.

use super::attest::{decode_sha256_hex, load_attestation_key};
use super::attestation::{AttestationBinding, AttestationScope, verify_attestation};
use super::intent::ClassicIntent;
use super::presence::MAINNET_CHAIN_ID;
use super::presence_policy::{CurrentMainnetApprovalPolicy, MainnetApprovalAuthority};
use super::store::{ApprovalKind, PendingApproval, PendingApprovalStore};
use super::subject::{SubjectKind, approval_subject_classic};
use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::decision::{AuthorityScope, MainnetDecision};
use crate::mainnet::fact::{FACT_LABEL_APPROVAL, FactDigest};
use crate::mainnet::verified_policy::VerifiedPolicy;
use crate::policy::Decision;
use crate::profile::caip2::Caip2;
use crate::profile::owner_key::OwnerKeyContext;
use crate::profile::schema::Profile;

/// The approval kinds a mainnet proof accepts, each a classic transaction
/// whose subject is [`approval_subject_classic`] of the record's envelope.
///
/// Account creation shares the payment kind, as its approval record does.
/// Every other record kind refuses as mainnet proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovedKind {
    /// An x402 Soroban payment intent.
    X402Payment,
    /// A `PaymentSimulated` record: payments and account creation.
    Payment,
    /// A `ClaimSimulated` record.
    Claim,
    /// A `TrustlineSimulated` record.
    Trustline,
}

impl ApprovedKind {
    /// The kind's one-byte tag in the approval fact digest.
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Payment => 1,
            Self::Claim => 2,
            Self::Trustline => 3,
            Self::X402Payment => 4,
        }
    }

    /// The inbox kind name of the record kind, as approval audit rows carry it.
    #[must_use]
    pub fn kind_name(self) -> &'static str {
        match self {
            Self::Payment => "PaymentSimulated",
            Self::Claim => "ClaimSimulated",
            Self::Trustline => "TrustlineSimulated",
            Self::X402Payment => "X402Payment",
        }
    }
}

/// What the caller requires the approval to approve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalExpectation {
    /// The record kind the action needs.
    pub kind: ApprovedKind,
    /// The subject the caller computed from the action it is about to
    /// authorize.
    pub subject: [u8; 32],
}

/// Proof that a version 5 or 6 attestation with a verified presence
/// approves `subject`. [`verify_approval`] produces it for an envelope-text
/// record under version 5, and [`verify_intent_approval`] for an
/// intent-digest record under version 6. At production time, the record is
/// live and the current owner-signed policy authorizes it.
///
/// See the module documentation for the producer and the sealing.
/// The `profile` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.profile; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `chain` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.chain; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `nonce` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.nonce; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `kind` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.kind; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `subject` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.subject; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `created_at_ms` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.created_at_ms; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `expires_at_ms` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.expires_at_ms; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `subject_kind` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.subject_kind; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `consent_at_ms` field cannot be projected outside this crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.consent_at_ms; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
/// The `execution_expires_at_ms` field cannot be projected outside this
/// crate.
///
/// ```compile_fail,E0616
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn inspect(p: &ApprovalWitness) { let _ = &p.execution_expires_at_ms; }
/// ```
///
/// ```
/// use stellar_agent_core::approval::witness::ApprovalWitness;
/// fn need(_: Option<ApprovalWitness>) {}
/// need(None);
/// ```
///
pub struct ApprovalWitness {
    profile: String,
    chain: Caip2,
    nonce: String,
    kind: ApprovedKind,
    subject: [u8; 32],
    created_at_ms: u64,
    expires_at_ms: u64,
    presence_receipt_digest: [u8; 32],
    policy_digest: [u8; 32],
    subject_kind: SubjectKind,
    consent_at_ms: u64,
    execution_expires_at_ms: u64,
}

/// The longest execution window after consent, in milliseconds. An intent
/// witness expires at the consent time plus the shorter of this and the
/// governing lifetime.
pub const APPROVAL_EXECUTION_MAX_MS: u64 = 900_000;

impl std::fmt::Debug for ApprovalWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalWitness")
            .field("profile", &self.profile)
            .field("chain", &self.chain.caip2_str())
            .field("kind", &self.kind)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("subject_kind", &self.subject_kind)
            .field("consent_at_ms", &self.consent_at_ms)
            .field("execution_expires_at_ms", &self.execution_expires_at_ms)
            .finish_non_exhaustive()
    }
}

impl ApprovalWitness {
    /// The profile the approval was attested for.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The chain the approval was attested for.
    #[must_use]
    pub fn chain(&self) -> Caip2 {
        self.chain
    }

    /// The approval nonce.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The approved record kind.
    #[must_use]
    pub fn kind(&self) -> ApprovedKind {
        self.kind
    }

    /// The approved subject.
    #[must_use]
    pub fn subject(&self) -> [u8; 32] {
        self.subject
    }

    /// When the record was created, in Unix milliseconds, as the version 5
    /// or 6 attestation covers it.
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// When the pending record expires, in Unix milliseconds: the stored
    /// expiry the version 5 or 6 attestation covers.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The binding convention of [`Self::subject`]: the envelope text for a
    /// [`verify_approval`] witness, the canonical intent digest for a
    /// [`verify_intent_approval`] witness.
    #[must_use]
    pub fn subject_kind(&self) -> SubjectKind {
        self.subject_kind
    }

    /// When the operator consented, in Unix milliseconds: the verified time
    /// of the presence receipt the attestation binds.
    #[must_use]
    pub fn consent_at_ms(&self) -> u64 {
        self.consent_at_ms
    }

    /// The exclusive execution boundary, in Unix milliseconds. An envelope
    /// witness reports its signed expiry. An intent witness reports the
    /// consent time plus the shorter of [`APPROVAL_EXECUTION_MAX_MS`] and the
    /// governing lifetime.
    #[must_use]
    pub fn execution_expires_at_ms(&self) -> u64 {
        self.execution_expires_at_ms
    }

    /// The digest of the presence receipt the attestation binds.
    #[must_use]
    pub fn presence_receipt_digest(&self) -> [u8; 32] {
        self.presence_receipt_digest
    }

    /// The BLAKE3 digest of the owner-signed policy the witness was verified
    /// under. An authorization under another policy refuses.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    /// The fact digest under `stellar-agent-authz-fact:approval:v1`.
    ///
    /// Fields, in order: `lp(profile)`, `lp(chain)` as its CAIP-2 text,
    /// `lp(nonce)`, the kind's one-byte tag, the 32-byte subject,
    /// `u64be(created_at_ms)`, `u64be(expires_at_ms)`, the 32-byte presence
    /// receipt digest, and the 32-byte policy digest.
    #[must_use]
    pub fn fact_digest(&self) -> [u8; 32] {
        let mut digest = FactDigest::new(FACT_LABEL_APPROVAL);
        digest
            .bytes(self.profile.as_bytes())
            .bytes(self.chain.caip2_str().as_bytes())
            .bytes(self.nonce.as_bytes())
            .tag(self.kind.tag())
            .fixed(&self.subject)
            .u64(self.created_at_ms)
            .u64(self.expires_at_ms)
            .fixed(&self.presence_receipt_digest)
            .fixed(&self.policy_digest);
        digest.finish()
    }
}

fn invalid(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::AttestationInvalid {
        detail: detail.to_owned(),
    })
}

/// Verifies the approval `nonce` as mainnet proof for `expected` under
/// `policy` and returns its witness.
///
/// In order:
///
/// 1. `profile` must be a mainnet profile; every other chain refuses.
/// 2. The record is read from `pending` by `nonce`. A rejected or consumed
///    record refuses. So does a kind other than the [`ApprovedKind`]s or
///    other than `expected.kind`, and a record whose subject kind is not the
///    envelope text.
/// 3. The record must store attestation version 5 with a mainnet passkey
///    approver and a presence receipt for the same credential.
/// 4. The subject is recomputed from the record; it must equal the stored
///    digest and `expected.subject`.
/// 5. The attestation key is loaded from `profile.attestation_key_id`,
///    refused when it is or may be the owner public key of `profile_name`,
///    and the attestation must verify under version 5 over the record's
///    nonce, subject, process UID, kind, lifetime, approver and receipt.
/// 6. `created_at <= now_ms < expires_at` on the stored, attested times.
/// 7. The current owner-signed policy of `profile_name` is loaded again
///    without advancing the pin; it must be a mainnet policy for the same
///    chain and be `policy` (sequence, digest and owner).
/// 8. The receipt must name `policy`, its times must satisfy the challenge
///    bounds, and its raw assertion must verify again under the key `policy`
///    signs for the credential, over the challenge recomputed from the
///    record and the binding.
///
/// The witness's expiry is the stored expiry, which is also its execution
/// expiry, and its consent time is the receipt's verified time. A caller
/// that governs the approval by a shorter lifetime compares
/// [`ApprovalWitness::created_at_ms`] and [`ApprovalWitness::expires_at_ms`]
/// with it.
///
/// # Errors
///
/// - `approval.binding_mismatch` for a profile that is not mainnet.
/// - `approval.not_found`, `approval.rejected`, `approval.consumed`, or
///   `approval.wrong_kind` for the record.
/// - `approval.presence_required` for a record without a version 5
///   attestation, a mainnet passkey approver and its receipt.
/// - `approval.attestation_invalid` for a subject mismatch or an attestation
///   that does not verify.
/// - `approval.expired` outside the record's lifetime.
/// - The key loader's errors, including the owner-key refusal.
/// - `approval.presence_policy_unavailable` when the current policy cannot
///   be loaded or is not `policy`, or the receipt names another policy.
/// - `approval.presence_invalid` for a receipt that does not verify again.
#[allow(
    clippy::too_many_arguments,
    reason = "the producer takes each input it does not derive itself"
)]
pub fn verify_approval(
    pending: &PendingApprovalStore,
    profile: &Profile,
    profile_name: &str,
    nonce: &str,
    attestation: &[u8; 32],
    expected: &ApprovalExpectation,
    policy: &VerifiedPolicy,
    now_ms: u64,
) -> Result<ApprovalWitness, WalletError> {
    verify_approval_with(
        pending,
        profile,
        profile_name,
        nonce,
        attestation,
        expected,
        policy,
        now_ms,
        |name| MainnetApprovalAuthority::for_profile(name)?.load_current_compare_only(),
    )
}

/// [`verify_approval`] for a caller that holds `admission`: the current
/// policy is read through its guard, and no lock is taken.
///
/// # Errors
///
/// As [`verify_approval`].
#[allow(
    clippy::too_many_arguments,
    reason = "the producer takes each input it does not derive itself"
)]
pub fn verify_approval_admitted(
    pending: &PendingApprovalStore,
    profile: &Profile,
    profile_name: &str,
    nonce: &str,
    attestation: &[u8; 32],
    expected: &ApprovalExpectation,
    policy: &VerifiedPolicy,
    now_ms: u64,
    admission: &super::presence_policy::PolicyAdmission,
) -> Result<ApprovalWitness, WalletError> {
    verify_approval_with(
        pending,
        profile,
        profile_name,
        nonce,
        attestation,
        expected,
        policy,
        now_ms,
        |name| MainnetApprovalAuthority::for_profile(name)?.load_admitted(admission),
    )
}

/// [`verify_approval`] with the current policy read by `current` from the
/// profile name.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the producer takes each input it does not derive itself, in its documented order"
)]
pub(crate) fn verify_approval_with(
    pending: &PendingApprovalStore,
    profile: &Profile,
    profile_name: &str,
    nonce: &str,
    attestation: &[u8; 32],
    expected: &ApprovalExpectation,
    policy: &VerifiedPolicy,
    now_ms: u64,
    current: impl FnOnce(&str) -> Result<CurrentMainnetApprovalPolicy, WalletError>,
) -> Result<ApprovalWitness, WalletError> {
    let RecordFacts {
        binding,
        record,
        kind,
        subject,
        stored_digest,
    } = read_mainnet_record(pending, profile, profile_name, nonce)?;
    if kind != expected.kind {
        return Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "the approval is for another kind of action".to_owned(),
        }));
    }
    if record.subject_kind != SubjectKind::EnvelopeText {
        return Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "the approval binds a canonical intent".to_owned(),
        }));
    }
    let Some(scope @ AttestationScope::V5(_, _, receipt)) = record.attestation_scope() else {
        return Err(WalletError::Approval(ApprovalFailure::PresenceRequired));
    };
    if stored_digest != subject || subject != expected.subject {
        return Err(invalid("the approval approves another transaction"));
    }
    let key = attestation_key(profile, profile_name)?;
    if !verify_attestation(
        &key,
        &binding,
        &record.approval_nonce,
        &subject,
        &record.process_uid,
        &scope,
        attestation,
    ) {
        return Err(invalid("the attestation does not verify"));
    }
    if record.created_at_unix_ms > now_ms || now_ms >= record.expires_at_unix_ms {
        return Err(WalletError::Approval(ApprovalFailure::Expired {
            detail: "the approval is outside its lifetime".to_owned(),
        }));
    }
    let current = current(profile_name)?;
    if current.profile().chain_id != profile.chain_id || !current.is(policy) {
        return Err(WalletError::Approval(
            ApprovalFailure::PresencePolicyUnavailable,
        ));
    }
    let stored = verify_stored_mainnet_presence(record, receipt, &binding, policy, now_ms)?;
    Ok(ApprovalWitness {
        profile: profile_name.to_owned(),
        chain: profile.chain_id,
        nonce: record.approval_nonce.clone(),
        kind,
        subject,
        created_at_ms: record.created_at_unix_ms,
        expires_at_ms: record.expires_at_unix_ms,
        presence_receipt_digest: stored.receipt_digest,
        policy_digest: policy.digest(),
        subject_kind: SubjectKind::EnvelopeText,
        consent_at_ms: receipt.verified_at_unix_ms(),
        execution_expires_at_ms: record.expires_at_unix_ms,
    })
}

/// Verifies the approval `nonce` as mainnet proof for the canonical
/// `intent` governed by `decision` under `policy`, and returns its witness.
///
/// In order:
///
/// 1. The first steps of [`verify_approval`] run unchanged: a mainnet
///    profile, the record by `nonce`, its summary consistency, and a
///    rejected, consumed or unsupported kind. An x402 record refuses.
/// 2. The record's subject kind must be the intent digest, and its kind
///    must be `intent`'s [`ClassicIntent::approved_kind`].
/// 3. The record must store attestation version 6 with a mainnet passkey
///    approver and its receipt. The stored envelope digest must equal the
///    digest recomputed from the record. The attestation key loads as for
///    [`verify_approval`], and the attestation must verify under version 6
///    over `intent`'s digest.
/// 4. `decision` must be `RequireApproval` with classic scope for this
///    profile, the mainnet chain and `policy`'s digest, which `intent` must
///    also name. Its governing lifetime must equal the signed lifetime.
/// 5. The clocks of [`intent_clocks`] must hold at `now_ms`, with the
///    receipt's verified time as the consent time. No pending-expiry check
///    applies.
/// 6. The current owner-signed policy is loaded again as for
///    [`verify_approval`], and the receipt must verify again with `intent`.
///
/// The witness subject is `intent`'s digest. Its signed times are the
/// record's, and its execution expiry is the consent time plus the shorter
/// of [`APPROVAL_EXECUTION_MAX_MS`] and the governing lifetime.
///
/// # Errors
///
/// - The errors of [`verify_approval`]'s first steps.
/// - `approval.wrong_kind` for an x402 record, an envelope-text record, or a
///   record of another kind than `intent`'s.
/// - `approval.presence_required` for a record without a version 6
///   attestation, a mainnet passkey approver and its receipt.
/// - `approval.attestation_invalid` for a subject mismatch, an attestation
///   that does not verify, or a decision that does not govern this
///   approval.
/// - `approval.expired` when the consent or execution clock fails.
/// - `approval.presence_policy_unavailable` and `approval.presence_invalid`
///   as for [`verify_approval`].
#[allow(
    clippy::too_many_arguments,
    reason = "the producer takes each input it does not derive itself"
)]
pub fn verify_intent_approval(
    pending: &PendingApprovalStore,
    profile: &Profile,
    profile_name: &str,
    nonce: &str,
    attestation: &[u8; 32],
    intent: &ClassicIntent,
    decision: &MainnetDecision,
    policy: &VerifiedPolicy,
    now_ms: u64,
) -> Result<ApprovalWitness, WalletError> {
    verify_intent_approval_with(
        pending,
        profile,
        profile_name,
        nonce,
        attestation,
        intent,
        decision,
        policy,
        now_ms,
        |name| MainnetApprovalAuthority::for_profile(name)?.load_current_compare_only(),
    )
}

/// [`verify_intent_approval`] with the current policy read by `current`
/// from the profile name.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the producer takes each input it does not derive itself, in its documented order"
)]
pub(crate) fn verify_intent_approval_with(
    pending: &PendingApprovalStore,
    profile: &Profile,
    profile_name: &str,
    nonce: &str,
    attestation: &[u8; 32],
    intent: &ClassicIntent,
    decision: &MainnetDecision,
    policy: &VerifiedPolicy,
    now_ms: u64,
    current: impl FnOnce(&str) -> Result<CurrentMainnetApprovalPolicy, WalletError>,
) -> Result<ApprovalWitness, WalletError> {
    let RecordFacts {
        binding,
        record,
        kind,
        subject,
        stored_digest,
    } = read_mainnet_record(pending, profile, profile_name, nonce)?;
    if kind == ApprovedKind::X402Payment {
        return Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "an x402 approval binds no canonical intent".to_owned(),
        }));
    }
    if record.subject_kind != SubjectKind::IntentDigest || kind != intent.approved_kind() {
        return Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "the approval does not bind this kind of intent".to_owned(),
        }));
    }
    let Some(scope @ AttestationScope::V6(_, _, receipt)) = record.attestation_scope() else {
        return Err(WalletError::Approval(ApprovalFailure::PresenceRequired));
    };
    if stored_digest != subject {
        return Err(invalid("the approval approves another transaction"));
    }
    let key = attestation_key(profile, profile_name)?;
    let intent_digest = *intent.digest().as_bytes();
    if !verify_attestation(
        &key,
        &binding,
        &record.approval_nonce,
        &intent_digest,
        &record.process_uid,
        &scope,
        attestation,
    ) {
        return Err(invalid("the attestation does not verify"));
    }
    let signed_lifetime = record
        .expires_at_unix_ms
        .checked_sub(record.created_at_unix_ms);
    if !matches!(decision.decision(), Decision::RequireApproval(_))
        || *decision.scope() != AuthorityScope::Classic
        || decision.profile() != profile_name
        || decision.chain_id() != binding.chain_id
        || decision.policy_digest() != policy.digest()
        || *intent.base().policy_digest() != policy.digest()
        || signed_lifetime != Some(decision.governing_ttl_ms())
    {
        return Err(invalid("the decision does not govern this approval"));
    }
    let consent_at_ms = receipt.verified_at_unix_ms();
    let execution_expires_at_ms = intent_clocks(
        record.created_at_unix_ms,
        record.expires_at_unix_ms,
        consent_at_ms,
        decision.governing_ttl_ms(),
        now_ms,
    )?;
    let current = current(profile_name)?;
    if current.profile().chain_id != profile.chain_id || !current.is(policy) {
        return Err(WalletError::Approval(
            ApprovalFailure::PresencePolicyUnavailable,
        ));
    }
    let stored = super::presence::verify_receipt_for_intent(
        record,
        receipt,
        &binding,
        policy,
        Some(intent),
        now_ms,
    )?;
    Ok(ApprovalWitness {
        profile: profile_name.to_owned(),
        chain: profile.chain_id,
        nonce: record.approval_nonce.clone(),
        kind,
        subject: intent_digest,
        created_at_ms: record.created_at_unix_ms,
        expires_at_ms: record.expires_at_unix_ms,
        presence_receipt_digest: stored.receipt_digest,
        policy_digest: policy.digest(),
        subject_kind: SubjectKind::IntentDigest,
        consent_at_ms,
        execution_expires_at_ms,
    })
}

/// The clocks of an intent approval, from signed inputs only.
///
/// Consent must fall in the waiting window, `created <= consent_at <
/// waiting_expires`, and `now` in the execution window, `consent_at <= now <
/// consent_at + min(APPROVAL_EXECUTION_MAX_MS, governing_ttl_ms)`. Both
/// upper boundaries are exclusive. Returns the execution expiry, the same
/// value at every call for the same inputs.
///
/// # Errors
///
/// `approval.expired` when either window fails or the arithmetic overflows.
pub fn intent_clocks(
    created: u64,
    waiting_expires: u64,
    consent_at: u64,
    governing_ttl_ms: u64,
    now: u64,
) -> Result<u64, WalletError> {
    let expired = |detail: &str| {
        WalletError::Approval(ApprovalFailure::Expired {
            detail: detail.to_owned(),
        })
    };
    if consent_at < created || consent_at >= waiting_expires {
        return Err(expired("the consent is outside the waiting window"));
    }
    let execution_expires = consent_at
        .checked_add(APPROVAL_EXECUTION_MAX_MS.min(governing_ttl_ms))
        .ok_or_else(|| expired("the execution clock overflows"))?;
    if now < consent_at || now >= execution_expires {
        return Err(expired("the approval is outside its execution window"));
    }
    Ok(execution_expires)
}

/// The facts every producer reads from the record before its own checks.
struct RecordFacts<'a> {
    binding: AttestationBinding<'a>,
    record: &'a PendingApproval,
    kind: ApprovedKind,
    subject: [u8; 32],
    stored_digest: [u8; 32],
}

/// The shared first steps of both producers, in order: a mainnet profile,
/// the record by `nonce`, its summary consistency, and its kind. A rejected
/// or consumed record and a kind that is no mainnet proof refuse. The
/// subject is recomputed from the record: the envelope text's digest for a
/// classic kind, the verified x402 subject for an x402 payment.
fn read_mainnet_record<'a>(
    pending: &'a PendingApprovalStore,
    profile: &'a Profile,
    profile_name: &'a str,
    nonce: &str,
) -> Result<RecordFacts<'a>, WalletError> {
    let chain_id = profile.chain_id.caip2_str();
    if chain_id != MAINNET_CHAIN_ID || !profile.chain_id.is_mainnet() {
        return Err(WalletError::Approval(ApprovalFailure::BindingMismatch {
            detail: "an approval witness is mainnet proof only".to_owned(),
        }));
    }
    let binding = AttestationBinding::new(profile_name, chain_id);
    let record = pending.get(nonce).ok_or_else(|| {
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "no pending approval with that nonce".to_owned(),
        })
    })?;
    if let Some(summary) = super::attest::classic_entry_summary(&record.kind) {
        summary?;
    }
    let (kind, subject, stored_digest) = match &record.kind {
        ApprovalKind::PaymentSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            ApprovedKind::Payment,
            approval_subject_classic(envelope_xdr_b64),
            decode_sha256_hex(envelope_sha256_hex)?,
        ),
        ApprovalKind::ClaimSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            ApprovedKind::Claim,
            approval_subject_classic(envelope_xdr_b64),
            decode_sha256_hex(envelope_sha256_hex)?,
        ),
        ApprovalKind::TrustlineSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            ApprovedKind::Trustline,
            approval_subject_classic(envelope_xdr_b64),
            decode_sha256_hex(envelope_sha256_hex)?,
        ),
        ApprovalKind::X402Payment {
            intent_digest,
            root_invocation_xdr,
            home_domain,
            ..
        } => {
            let subject = super::subject::verified_x402_subject(
                intent_digest,
                root_invocation_xdr,
                home_domain.as_deref(),
                profile.chain_id.network_passphrase(),
            )?;
            (ApprovedKind::X402Payment, subject, subject)
        }
        ApprovalKind::Rejected { .. } => {
            return Err(WalletError::Approval(ApprovalFailure::Rejected {
                detail: "the operator rejected this approval".to_owned(),
            }));
        }
        ApprovalKind::Consumed { .. } => {
            return Err(WalletError::Approval(ApprovalFailure::Consumed {
                detail: "this approval was already spent on a submission".to_owned(),
            }));
        }
        other => {
            return Err(WalletError::Approval(ApprovalFailure::WrongKind {
                detail: format!("{} approvals are no mainnet proof", other.kind_name()),
            }));
        }
    };
    Ok(RecordFacts {
        binding,
        record,
        kind,
        subject,
        stored_digest,
    })
}

/// The attestation key of `profile`, refused when it is or may be the owner
/// public key of `profile_name`.
fn attestation_key(
    profile: &Profile,
    profile_name: &str,
) -> Result<zeroize::Zeroizing<[u8; 32]>, WalletError> {
    let key = load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(profile_name, profile),
    )?;
    let key: [u8; 32] = key.as_slice().try_into().map_err(|_| {
        WalletError::Approval(ApprovalFailure::KeyLengthError {
            detail: format!("attestation key must be 32 bytes, got {}", key.len()),
        })
    })?;
    Ok(zeroize::Zeroizing::new(key))
}

/// Verifies a stored presence receipt as the consent to `record` under
/// `policy`: the receipt checks of [`super::presence`], never a live proof.
fn verify_stored_mainnet_presence(
    record: &super::store::PendingApproval,
    receipt: &super::presence::MainnetPresenceReceipt,
    binding: &AttestationBinding<'_>,
    policy: &VerifiedPolicy,
    now_ms: u64,
) -> Result<super::presence::StoredPresence, WalletError> {
    super::presence::verify_receipt(record, receipt, binding, policy, now_ms)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::approval::attestation::{
        AttestedApprover, compute_attestation_v4, compute_attestation_v5,
    };
    use crate::approval::mainnet_fixtures::{ATTESTATION_KEY, MainnetConsentFixture};
    use crate::approval::presence::MainnetPresenceReceipt;
    use crate::approval::store::{ConsumedOutcome, DEFAULT_TTL_MS, PendingApproval};
    use crate::approval::subject::approval_subject_x402;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serial_test::serial;
    use sha2::Digest as _;
    use stellar_agent_test_support::webauthn::TestAuthenticator;

    const NAME: &str = "witness";

    /// A mainnet consent to `entry` through the production attester: the
    /// store holding it, the nonce, the surfaced blob, and the policy the
    /// consent bound.
    struct Consented {
        store: PendingApprovalStore,
        nonce: String,
        blob: [u8; 32],
        policy: VerifiedPolicy,
    }

    fn consent(fixture: &MainnetConsentFixture, entry: &PendingApproval) -> Consented {
        let policy = fixture.current_policy();
        let (store, surfaced) = fixture.consent(entry);
        let blob = URL_SAFE_NO_PAD
            .decode(surfaced.expect("a classic or x402 consent surfaces its blob"))
            .unwrap()
            .try_into()
            .unwrap();
        Consented {
            store,
            nonce: entry.approval_nonce.clone(),
            blob,
            policy,
        }
    }

    fn payment_expectation(entry: &PendingApproval) -> ApprovalExpectation {
        let ApprovalKind::PaymentSimulated {
            envelope_xdr_b64, ..
        } = &entry.kind
        else {
            unreachable!()
        };
        ApprovalExpectation {
            kind: ApprovedKind::Payment,
            subject: approval_subject_classic(envelope_xdr_b64),
        }
    }

    fn verify(
        fixture: &MainnetConsentFixture,
        consented: &Consented,
        expected: &ApprovalExpectation,
        policy: &VerifiedPolicy,
        now_ms: u64,
    ) -> Result<ApprovalWitness, WalletError> {
        verify_approval(
            &consented.store,
            fixture.profile(),
            fixture.name(),
            &consented.nonce,
            &consented.blob,
            expected,
            policy,
            now_ms,
        )
    }

    fn now() -> u64 {
        crate::timefmt::now_unix_ms().unwrap()
    }

    fn receipt_of(store: &PendingApprovalStore, nonce: &str) -> MainnetPresenceReceipt {
        store
            .get(nonce)
            .unwrap()
            .mainnet_presence
            .clone()
            .expect("a mainnet consent stores its receipt")
    }

    /// A mainnet consent yields a witness of exactly the record's facts, and
    /// its fact digest follows the documented layout, receipt and policy
    /// digests included.
    #[test]
    #[serial]
    fn a_mainnet_presence_approval_yields_its_witness() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let consented = consent(&fixture, &entry);
        let expected = payment_expectation(&entry);
        let witness = verify(&fixture, &consented, &expected, &consented.policy, now()).unwrap();
        let receipt = receipt_of(&consented.store, &consented.nonce);
        assert_eq!(witness.profile(), NAME);
        assert_eq!(witness.chain(), Caip2::Mainnet);
        assert_eq!(witness.nonce(), entry.approval_nonce);
        assert_eq!(witness.kind(), ApprovedKind::Payment);
        assert_eq!(witness.subject(), expected.subject);
        assert_eq!(witness.created_at_ms(), entry.created_at_unix_ms);
        assert_eq!(witness.expires_at_ms(), entry.expires_at_unix_ms);
        assert_eq!(witness.presence_receipt_digest(), receipt.digest().unwrap());
        assert_eq!(witness.policy_digest(), consented.policy.digest());

        let mut preimage = FACT_LABEL_APPROVAL.to_vec();
        for field in [
            NAME.as_bytes(),
            b"stellar:mainnet",
            entry.approval_nonce.as_bytes(),
        ] {
            preimage.extend(u32::try_from(field.len()).unwrap().to_be_bytes());
            preimage.extend(field);
        }
        preimage.push(1);
        preimage.extend(expected.subject);
        preimage.extend(entry.created_at_unix_ms.to_be_bytes());
        preimage.extend(entry.expires_at_unix_ms.to_be_bytes());
        preimage.extend(receipt.digest().unwrap());
        preimage.extend(consented.policy.digest());
        let independent: [u8; 32] = sha2::Sha256::digest(&preimage).into();
        assert_eq!(witness.fact_digest(), independent);
    }

    /// The witness holds from the moment the consent was verified to the
    /// last millisecond of the stored lifetime, and refuses before creation
    /// and at the expiry itself.
    #[test]
    #[serial]
    fn freshness_holds_on_the_stored_boundaries() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let consented = consent(&fixture, &entry);
        let expected = payment_expectation(&entry);
        let verified_at = receipt_of(&consented.store, &consented.nonce).verified_at_unix_ms();
        let policy = &consented.policy;
        assert!(verify(&fixture, &consented, &expected, policy, verified_at).is_ok());
        assert!(
            verify(
                &fixture,
                &consented,
                &expected,
                policy,
                entry.expires_at_unix_ms - 1
            )
            .is_ok()
        );
        for refused in [entry.created_at_unix_ms - 1, entry.expires_at_unix_ms] {
            assert_eq!(
                verify(&fixture, &consented, &expected, policy, refused)
                    .unwrap_err()
                    .code(),
                "approval.expired",
                "{refused}"
            );
        }
        assert_eq!(
            verify(&fixture, &consented, &expected, policy, verified_at - 1)
                .unwrap_err()
                .code(),
            "approval.presence_invalid",
            "no witness predates its consent"
        );
    }

    /// An approval that expired unused, whose stored creation and expiry are
    /// then moved forward in the file, does not verify: version 5 covers both.
    #[test]
    #[serial]
    fn moving_an_expired_mainnet_approval_forward_refuses() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let consented = consent(&fixture, &entry);
        let expected = payment_expectation(&entry);
        let after_expiry = entry.expires_at_unix_ms + 1;
        assert_eq!(
            verify(
                &fixture,
                &consented,
                &expected,
                &consented.policy,
                after_expiry
            )
            .unwrap_err()
            .code(),
            "approval.expired"
        );

        let text = std::fs::read_to_string(fixture.store_path()).unwrap();
        let mut doc: toml_edit::DocumentMut = text.parse().unwrap();
        let table = doc["pending"]
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
            .find(|t| t["approval_nonce"].as_str() == Some(entry.approval_nonce.as_str()))
            .unwrap();
        let shift = i64::try_from(DEFAULT_TTL_MS).unwrap();
        for field in ["created_at_unix_ms", "expires_at_unix_ms"] {
            let stored = table[field].as_integer().unwrap();
            table[field] = toml_edit::value(stored + shift);
        }
        let moved_path = fixture.home().join("moved.toml");
        std::fs::write(&moved_path, doc.to_string()).unwrap();
        let moved = Consented {
            store: PendingApprovalStore::open(moved_path).unwrap(),
            nonce: consented.nonce.clone(),
            blob: consented.blob,
            policy: consented.policy.clone(),
        };
        assert_eq!(
            verify(&fixture, &moved, &expected, &moved.policy, after_expiry)
                .unwrap_err()
                .code(),
            "approval.attestation_invalid"
        );
    }

    /// A version 4 record on a mainnet profile, with the genuine blob of a
    /// local or remote approver, is no mainnet proof.
    #[test]
    #[serial]
    fn a_genuine_version_4_record_refuses_as_mainnet_proof() {
        let fixture = MainnetConsentFixture::new(NAME);
        let policy = fixture.current_policy();
        for approver in [
            AttestedApprover::Local,
            AttestedApprover::Remote {
                credential_id_b64url: "AAECAw".to_owned(),
            },
        ] {
            let entry = fixture.payment(DEFAULT_TTL_MS);
            let expected = payment_expectation(&entry);
            let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
            store.insert(entry.clone(), now()).unwrap();
            let blob = compute_attestation_v4(
                &ATTESTATION_KEY,
                &fixture.binding(),
                &entry.approval_nonce,
                &expected.subject,
                &entry.process_uid,
                &entry.attested_lifetime(),
                &approver,
            );
            store
                .record_attestation_at(&entry.approval_nonce, blob, approver.clone(), now())
                .unwrap();
            let consented = Consented {
                store,
                nonce: entry.approval_nonce.clone(),
                blob,
                policy: policy.clone(),
            };
            assert_eq!(
                verify(&fixture, &consented, &expected, &policy, now())
                    .unwrap_err()
                    .code(),
                "approval.presence_required",
                "{approver:?}"
            );
        }
    }

    /// An attestation computed with another key does not verify against the
    /// key the producer loads, and the record's own blob does not verify once
    /// the keyring holds another key.
    #[test]
    #[serial]
    fn a_wrong_key_attestation_refuses_against_the_loaded_key() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let mut consented = consent(&fixture, &entry);
        let expected = payment_expectation(&entry);
        let receipt = receipt_of(&consented.store, &consented.nonce);
        let genuine = consented.blob;
        consented.blob = compute_attestation_v5(
            &[0x11; 32],
            &fixture.binding(),
            &entry.approval_nonce,
            &expected.subject,
            &entry.process_uid,
            &entry.attested_lifetime(),
            &AttestedApprover::MainnetPasskey {
                credential_id_b64url: receipt.credential_id_b64url(),
            },
            &receipt,
        );
        let policy = consented.policy.clone();
        assert_eq!(
            verify(&fixture, &consented, &expected, &policy, now())
                .unwrap_err()
                .code(),
            "approval.attestation_invalid"
        );
        consented.blob = genuine;
        let coordinate = &fixture.profile().attestation_key_id;
        keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode([0x11; 32]))
            .unwrap();
        assert_eq!(
            verify(&fixture, &consented, &expected, &policy, now())
                .unwrap_err()
                .code(),
            "approval.attestation_invalid"
        );
    }

    /// The kind, the subject, the chain, rejection, consumption, and an
    /// unknown nonce each refuse on their own.
    #[test]
    #[serial]
    fn each_mismatch_refuses_on_its_own() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let mut consented = consent(&fixture, &entry);
        let expected = payment_expectation(&entry);
        let policy = consented.policy.clone();

        let other_kind = ApprovalExpectation {
            kind: ApprovedKind::Claim,
            ..expected
        };
        assert_eq!(
            verify(&fixture, &consented, &other_kind, &policy, now())
                .unwrap_err()
                .code(),
            "approval.wrong_kind"
        );
        let other_subject = ApprovalExpectation {
            subject: [7; 32],
            ..expected
        };
        assert_eq!(
            verify(&fixture, &consented, &other_subject, &policy, now())
                .unwrap_err()
                .code(),
            "approval.attestation_invalid"
        );
        let testnet =
            crate::profile::schema::Profile::builder_testnet("a", "acct", "n", "acct").build();
        assert_eq!(
            verify_approval(
                &consented.store,
                &testnet,
                NAME,
                &consented.nonce,
                &consented.blob,
                &expected,
                &policy,
                now(),
            )
            .unwrap_err()
            .code(),
            "approval.binding_mismatch"
        );
        let unknown = Consented {
            store: PendingApprovalStore::open(fixture.home().join("empty.toml")).unwrap(),
            nonce: consented.nonce.clone(),
            blob: consented.blob,
            policy: policy.clone(),
        };
        assert_eq!(
            verify(&fixture, &unknown, &expected, &policy, now())
                .unwrap_err()
                .code(),
            "approval.not_found"
        );

        consented
            .store
            .consume(
                &consented.nonce,
                &"ab".repeat(32),
                ConsumedOutcome::Confirmed,
            )
            .unwrap();
        assert_eq!(
            verify(&fixture, &consented, &expected, &policy, now())
                .unwrap_err()
                .code(),
            "approval.consumed"
        );

        let rejected = fixture.payment(DEFAULT_TTL_MS);
        let mut store = PendingApprovalStore::open(fixture.home().join("rejected.toml")).unwrap();
        store.insert(rejected.clone(), now()).unwrap();
        assert!(
            store
                .reject(&rejected.approval_nonce, now(), DEFAULT_TTL_MS)
                .unwrap()
        );
        let rejected = Consented {
            store,
            nonce: rejected.approval_nonce.clone(),
            blob: [0; 32],
            policy: policy.clone(),
        };
        assert_eq!(
            verify(&fixture, &rejected, &expected, &policy, now())
                .unwrap_err()
                .code(),
            "approval.rejected"
        );
    }

    /// A payment, a claim, a trustline and an x402 payment consented with
    /// presence each yield a witness of their own kind and subject.
    #[test]
    #[serial]
    fn every_mainnet_kind_yields_a_version_5_witness() {
        let fixture = MainnetConsentFixture::new(NAME);
        let uid = super::super::process_uid_for_attestation().unwrap();
        let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
        let claim = super::super::fixtures::claim_pending(
            &source,
            [9; 32],
            None,
            100,
            7,
            uid.clone(),
            DEFAULT_TTL_MS,
        );
        let trustline = super::super::fixtures::trustline_pending(
            &source,
            "USD",
            &source,
            Some(100),
            100,
            7,
            uid,
            DEFAULT_TTL_MS,
        );
        let x402 = x402_entry();
        let ApprovalKind::X402Payment { intent_digest, .. } = &x402.kind else {
            unreachable!()
        };
        let x402_subject = approval_subject_x402(intent_digest);
        let classic_subject = |entry: &PendingApproval| match &entry.kind {
            ApprovalKind::ClaimSimulated {
                envelope_xdr_b64, ..
            }
            | ApprovalKind::TrustlineSimulated {
                envelope_xdr_b64, ..
            } => approval_subject_classic(envelope_xdr_b64),
            other => panic!("{}", other.kind_name()),
        };
        let cases = [
            (ApprovedKind::Claim, classic_subject(&claim), claim),
            (
                ApprovedKind::Trustline,
                classic_subject(&trustline),
                trustline,
            ),
            (ApprovedKind::X402Payment, x402_subject, x402),
        ];
        for (kind, subject, entry) in cases {
            let consented = consent(&fixture, &entry);
            let witness = verify(
                &fixture,
                &consented,
                &ApprovalExpectation { kind, subject },
                &consented.policy,
                now(),
            )
            .unwrap();
            assert_eq!(witness.kind(), kind);
            assert_eq!(witness.subject(), subject);
            assert_eq!(
                consented
                    .store
                    .get(&consented.nonce)
                    .unwrap()
                    .attestation_version,
                5
            );
        }
    }

    /// A version 5 record whose stored claim envelope carries a memo that is
    /// not UTF-8 refuses as inconsistent before any HMAC or assertion work,
    /// although its blob is genuine for that envelope.
    #[test]
    #[serial]
    fn a_version_5_claim_with_a_non_utf8_memo_refuses_as_inconsistent() {
        use stellar_xdr::{Limits, Memo, ReadXdr as _, TransactionEnvelope, WriteXdr as _};
        let fixture = MainnetConsentFixture::new(NAME);
        let genuine = consent(&fixture, &fixture.payment(DEFAULT_TTL_MS));
        let receipt = receipt_of(&genuine.store, &genuine.nonce);
        let source = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
        let xdr = super::super::fixtures::claim_envelope(&source, [9; 32], 100, 7);
        let TransactionEnvelope::Tx(mut tx) =
            TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).unwrap()
        else {
            unreachable!()
        };
        tx.tx.memo = Memo::Text(vec![0xff, 0xfe].try_into().unwrap());
        let xdr = TransactionEnvelope::Tx(tx)
            .to_xdr_base64(Limits::none())
            .unwrap();
        let (id, strkey) = super::super::fixtures::balance_ids([9; 32]);
        let entry = PendingApproval::new_claim_pending(
            xdr.clone(),
            xdr.as_bytes(),
            id,
            strkey,
            "XLM".to_owned(),
            1,
            source.to_string(),
            100,
            7,
            super::super::process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        let subject = approval_subject_classic(&xdr);
        let approver = AttestedApprover::MainnetPasskey {
            credential_id_b64url: receipt.credential_id_b64url(),
        };
        let blob = compute_attestation_v5(
            &ATTESTATION_KEY,
            &fixture.binding(),
            &entry.approval_nonce,
            &subject,
            &entry.process_uid,
            &entry.attested_lifetime(),
            &approver,
            &receipt,
        );
        let mut store = PendingApprovalStore::open(fixture.home().join("memo.toml")).unwrap();
        store.insert(entry.clone(), now()).unwrap();
        store
            .record_mainnet_attestation_at(&entry.approval_nonce, blob, approver, receipt, now())
            .unwrap();
        let record = Consented {
            store,
            nonce: entry.approval_nonce.clone(),
            blob,
            policy: genuine.policy.clone(),
        };
        assert_eq!(
            verify(
                &fixture,
                &record,
                &ApprovalExpectation {
                    kind: ApprovedKind::Claim,
                    subject
                },
                &genuine.policy,
                now(),
            )
            .unwrap_err()
            .code(),
            "approval.entry_inconsistent"
        );
    }

    fn x402_entry() -> PendingApproval {
        use stellar_xdr::{
            AccountId, ContractId, Hash, InvokeContractArgs, PublicKey, ScAddress, ScVal,
            SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256,
        };
        let account = |byte| {
            ScVal::Address(ScAddress::Account(AccountId(
                PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
            )))
        };
        let root = SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([3; 32]))),
                function_name: "transfer".try_into().unwrap(),
                args: vec![account(4), account(5), ScVal::from(10_i128)]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: vec![].try_into().unwrap(),
        };
        PendingApproval::new_x402_pending(
            &sha2::Sha256::digest(Caip2::Mainnet.network_passphrase().as_bytes()).into(),
            &root,
            None,
            super::super::process_uid_for_attestation().unwrap(),
            DEFAULT_TTL_MS,
        )
        .unwrap()
    }

    /// A stored receipt whose assertion fails verification refuses although
    /// its version 5 blob, recomputed over the altered receipt, verifies: the
    /// witness checks the raw assertion again under the signed key.
    #[test]
    #[serial]
    fn mainnet_witness_reverifies_the_assertion() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let consented = consent(&fixture, &entry);
        let expected = payment_expectation(&entry);
        let policy = consented.policy.clone();
        let genuine = receipt_of(&consented.store, &consented.nonce);

        let mut wire = serde_json::to_value(&genuine).unwrap();
        let client = wire["assertion"]["client_data_json"]
            .as_array_mut()
            .unwrap();
        assert_eq!(client.pop().unwrap(), serde_json::json!(b'}'));
        client.extend(b",\"extra\":1}".iter().map(|b| serde_json::json!(b)));
        let altered: MainnetPresenceReceipt = serde_json::from_value(wire).unwrap();
        assert!(altered.is_well_formed());

        let approver = AttestedApprover::MainnetPasskey {
            credential_id_b64url: altered.credential_id_b64url(),
        };
        let blob = compute_attestation_v5(
            &ATTESTATION_KEY,
            &fixture.binding(),
            &entry.approval_nonce,
            &expected.subject,
            &entry.process_uid,
            &entry.attested_lifetime(),
            &approver,
            &altered,
        );
        let mut store = PendingApprovalStore::open(fixture.home().join("altered.toml")).unwrap();
        store.insert(entry.clone(), now()).unwrap();
        store
            .record_mainnet_attestation_at(&entry.approval_nonce, blob, approver, altered, now())
            .unwrap();
        let altered = Consented {
            store,
            nonce: entry.approval_nonce.clone(),
            blob,
            policy: policy.clone(),
        };
        assert_eq!(
            verify(&fixture, &altered, &expected, &policy, now())
                .unwrap_err()
                .code(),
            "approval.presence_invalid"
        );
        assert!(verify(&fixture, &consented, &expected, &policy, now()).is_ok());
    }

    /// The witness reads the current owner-signed policy again: a credential
    /// removed at a higher sequence, a policy re-signed at a higher sequence
    /// with the same credential, an unsigned edit, and a policy signed by
    /// another owner each refuse an approval consented before. A caller that
    /// authorizes under the new policy is refused as well, because the receipt
    /// names the old one.
    #[test]
    #[serial]
    fn mainnet_witness_reloads_current_policy() {
        let other = TestAuthenticator::from_seed([0x33; 32], vec![0x44; 16]);
        let fixture_auth = stellar_agent_test_support::webauthn::fixture_authenticator();
        type Change = fn(&mut MainnetConsentFixture, &TestAuthenticator, &TestAuthenticator);
        let changes: [(&str, Change); 4] = [
            ("credential removed", |fixture, other, _| {
                fixture.sign_policy(&[other]);
            }),
            ("same credential re-signed", |fixture, _, own| {
                fixture.sign_policy(&[own]);
            }),
            ("unsigned edit", |fixture, _, _| {
                let path = fixture.policy_path();
                let text = std::fs::read_to_string(&path).unwrap();
                assert!(text.contains("ttl_secs = 3600"));
                std::fs::write(&path, text.replace("ttl_secs = 3600", "ttl_secs = 3601")).unwrap();
            }),
            ("another owner", |fixture, _, own| {
                let body = fixture.policy_body(fixture.sequence(), &[own]);
                fixture.write_signed_by(&body, &ed25519_dalek::SigningKey::from_bytes(&[12; 32]));
            }),
        ];
        for (label, change) in changes {
            let mut fixture = MainnetConsentFixture::new(NAME);
            let entry = fixture.payment(DEFAULT_TTL_MS);
            let consented = consent(&fixture, &entry);
            let expected = payment_expectation(&entry);
            let policy = consented.policy.clone();
            assert!(
                verify(&fixture, &consented, &expected, &policy, now()).is_ok(),
                "{label}"
            );
            change(&mut fixture, &other, &fixture_auth);
            assert_eq!(
                verify(&fixture, &consented, &expected, &policy, now())
                    .unwrap_err()
                    .code(),
                "approval.presence_policy_unavailable",
                "{label}"
            );
            if let Ok(current) = fixture.authority().load_current_compare_only() {
                assert_eq!(
                    verify(&fixture, &consented, &expected, current.policy(), now())
                        .unwrap_err()
                        .code(),
                    "approval.presence_policy_unavailable",
                    "{label}: the receipt names the old policy"
                );
            }
        }
    }

    /// A mainnet consent to an intent-digest record through the production
    /// attester, with the intent it binds and the signed entry.
    struct IntentConsented {
        store: PendingApprovalStore,
        entry: PendingApproval,
        intent: ClassicIntent,
        blob: [u8; 32],
        policy: VerifiedPolicy,
    }

    /// Consents to an intent payment that lives `ttl_ms`, after `edit`
    /// adjusts the entry before it is inserted.
    fn intent_consent(
        fixture: &MainnetConsentFixture,
        ttl_ms: u64,
        edit: impl FnOnce(&mut PendingApproval),
    ) -> IntentConsented {
        let policy = fixture.current_policy();
        let (mut entry, intent) = fixture.intent_payment(ttl_ms);
        edit(&mut entry);
        let (store, surfaced) = fixture.intent_consent(&entry, &intent);
        let blob = URL_SAFE_NO_PAD
            .decode(surfaced.expect("an intent consent surfaces its blob"))
            .unwrap()
            .try_into()
            .unwrap();
        IntentConsented {
            store,
            entry,
            intent,
            blob,
            policy,
        }
    }

    fn verify_intent(
        fixture: &MainnetConsentFixture,
        consented: &IntentConsented,
        intent: &ClassicIntent,
        decision: &MainnetDecision,
        now_ms: u64,
    ) -> Result<ApprovalWitness, WalletError> {
        verify_intent_approval(
            &consented.store,
            fixture.profile(),
            fixture.name(),
            &consented.entry.approval_nonce,
            &consented.blob,
            intent,
            decision,
            &consented.policy,
            now_ms,
        )
    }

    /// Both witness producers read the current policy. A writer that holds
    /// the policy-state lock through the retries refuses each as busy; an
    /// invalid policy file refuses each as unavailable, also under the
    /// writer. Once both are gone, each yields its witness.
    #[test]
    #[serial]
    fn mainnet_witness_loads_answer_busy_and_unavailable_apart() {
        let fixture = MainnetConsentFixture::new(NAME);
        let decision = fixture.decision(DEFAULT_TTL_MS);
        let expect = |code: &dyn Fn() -> Option<String>| {
            let busy = Some("approval.presence_policy_busy".to_owned());
            let unavailable = Some("approval.presence_policy_unavailable".to_owned());
            let writer = crate::policy::state_lock::WindowStoreLock::acquire_for(
                &crate::profile::schema::default_policy_window_state_path_for(NAME),
                &fixture.profile().policy_window_state_key_id,
            )
            .unwrap();
            assert_eq!(code(), busy);
            let path = fixture.policy_path();
            let signed = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, "not a policy").unwrap();
            assert_eq!(code(), unavailable);
            drop(writer);
            assert_eq!(code(), unavailable);
            std::fs::write(&path, signed).unwrap();
            assert_eq!(code(), None);
        };
        {
            let entry = fixture.payment(DEFAULT_TTL_MS);
            let consented = consent(&fixture, &entry);
            let expected = payment_expectation(&entry);
            expect(&|| {
                verify(&fixture, &consented, &expected, &consented.policy, now())
                    .err()
                    .map(|error| error.code().to_owned())
            });
        }
        let intents = intent_consent(&fixture, DEFAULT_TTL_MS, |_| {});
        expect(&|| {
            verify_intent(&fixture, &intents, &intents.intent, &decision, now())
                .err()
                .map(|error| error.code().to_owned())
        });
    }

    /// The fixture store file with `edit` applied to the record `nonce`,
    /// opened as a store at another path.
    fn edited_store(
        fixture: &MainnetConsentFixture,
        nonce: &str,
        name: &str,
        edit: impl FnOnce(&mut toml_edit::Table),
    ) -> PendingApprovalStore {
        let text = std::fs::read_to_string(fixture.store_path()).unwrap();
        let mut doc: toml_edit::DocumentMut = text.parse().unwrap();
        let table = doc["pending"]
            .as_array_of_tables_mut()
            .unwrap()
            .iter_mut()
            .find(|t| t["approval_nonce"].as_str() == Some(nonce))
            .unwrap();
        edit(table);
        let path = fixture.home().join(name);
        std::fs::write(&path, doc.to_string()).unwrap();
        PendingApprovalStore::open(path).unwrap()
    }

    /// Editing the stored subject kind, with or without the version, makes
    /// both producers refuse, for an envelope record and an intent record.
    #[test]
    #[serial]
    fn a_flipped_subject_kind_refuses_in_both_directions() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let envelope = consent(&fixture, &entry);
        assert!(
            verify(
                &fixture,
                &envelope,
                &payment_expectation(&entry),
                &envelope.policy,
                now()
            )
            .is_ok()
        );
        let Consented {
            store,
            blob: envelope_blob,
            ..
        } = envelope;
        drop(store);
        let intents = intent_consent(&fixture, 3_600_000, |_| {});
        let decision = fixture.decision(3_600_000);
        assert!(verify_intent(&fixture, &intents, &intents.intent, &decision, now()).is_ok());

        /// A label, the record it edits, the edit, and the codes the envelope
        /// and intent producers answer.
        type FlipCase = (
            &'static str,
            &'static str,
            fn(&mut toml_edit::Table),
            &'static str,
            &'static str,
        );
        let cases: [FlipCase; 4] = [
            (
                "envelope to intent",
                "envelope",
                |t| {
                    t["subject_kind"] = toml_edit::value("intent-digest");
                },
                "approval.wrong_kind",
                "approval.presence_required",
            ),
            (
                "envelope to intent with version 6",
                "envelope",
                |t| {
                    t["subject_kind"] = toml_edit::value("intent-digest");
                    t["attestation_version"] = toml_edit::value(6);
                },
                "approval.wrong_kind",
                "approval.attestation_invalid",
            ),
            (
                "intent to envelope",
                "intent",
                |t| {
                    assert!(t.remove("subject_kind").is_some());
                },
                "approval.presence_required",
                "approval.wrong_kind",
            ),
            (
                "intent to envelope with version 5",
                "intent",
                |t| {
                    assert!(t.remove("subject_kind").is_some());
                    t["attestation_version"] = toml_edit::value(5);
                },
                "approval.attestation_invalid",
                "approval.wrong_kind",
            ),
        ];
        for (index, (label, record, edit, envelope_code, intent_code)) in
            cases.into_iter().enumerate()
        {
            let (record, blob) = match record {
                "envelope" => (&entry, envelope_blob),
                _ => (&intents.entry, intents.blob),
            };
            let nonce = record.approval_nonce.as_str();
            let store = edited_store(&fixture, nonce, &format!("flip{index}.toml"), edit);
            let envelope_result = verify_approval(
                &store,
                fixture.profile(),
                fixture.name(),
                nonce,
                &blob,
                &payment_expectation(record),
                &intents.policy,
                now(),
            );
            assert_eq!(
                envelope_result.unwrap_err().code(),
                envelope_code,
                "{label}"
            );
            let intent_result = verify_intent_approval(
                &store,
                fixture.profile(),
                fixture.name(),
                nonce,
                &blob,
                &intents.intent,
                &decision,
                &intents.policy,
                now(),
            );
            assert_eq!(intent_result.unwrap_err().code(), intent_code, "{label}");
        }
    }

    /// An intent witness takes its consent time from the receipt, 60 s
    /// after the record's creation. Its execution expiry is the consent plus
    /// the capped governing lifetime. Its signed times stay the record's, and
    /// its subject is the intent digest.
    #[test]
    #[serial]
    fn intent_witness_uses_receipt_time_and_governing_ttl() {
        for (ttl_ms, window_ms) in [(86_400_000, 900_000), (300_000, 300_000)] {
            let fixture = MainnetConsentFixture::new(NAME);
            let consented = intent_consent(&fixture, ttl_ms, |entry| {
                entry.created_at_unix_ms -= 60_000;
                entry.expires_at_unix_ms -= 60_000;
            });
            let receipt = receipt_of(&consented.store, &consented.entry.approval_nonce);
            let consent_at = receipt.verified_at_unix_ms();
            assert!(
                consent_at >= consented.entry.created_at_unix_ms + 60_000,
                "consent follows creation by at least 60 s"
            );
            let witness = verify_intent(
                &fixture,
                &consented,
                &consented.intent,
                &fixture.decision(ttl_ms),
                consent_at,
            )
            .unwrap();
            assert_eq!(witness.subject_kind(), SubjectKind::IntentDigest);
            assert_eq!(witness.consent_at_ms(), consent_at, "{ttl_ms}");
            assert_eq!(
                witness.execution_expires_at_ms(),
                consent_at + window_ms,
                "{ttl_ms}"
            );
            assert_eq!(witness.created_at_ms(), consented.entry.created_at_unix_ms);
            assert_eq!(witness.expires_at_ms(), consented.entry.expires_at_unix_ms);
            assert_eq!(
                witness.expires_at_ms() - witness.created_at_ms(),
                ttl_ms,
                "the signed lifetime is the rule lifetime"
            );
            assert_eq!(witness.subject(), *consented.intent.digest().as_bytes());
            assert_eq!(witness.kind(), ApprovedKind::Payment);
            assert_eq!(witness.nonce(), consented.entry.approval_nonce);
            assert_eq!(witness.presence_receipt_digest(), receipt.digest().unwrap());
            assert_eq!(witness.policy_digest(), consented.policy.digest());
        }
    }

    /// An intent consented 60 s after its creation under a 300 s rule
    /// verifies after a reopen and twice past its waiting expiry. The clocks
    /// stay the same, and the witness refuses at its execution expiry.
    #[test]
    #[serial]
    fn intent_witness_restarts_after_waiting_expiry() {
        let fixture = MainnetConsentFixture::new(NAME);
        let consented = intent_consent(&fixture, 300_000, |entry| {
            entry.created_at_unix_ms -= 60_000;
            entry.expires_at_unix_ms -= 60_000;
        });
        let decision = fixture.decision(300_000);
        let nonce = consented.entry.approval_nonce.clone();
        let consent_at = receipt_of(&consented.store, &nonce).verified_at_unix_ms();
        let waiting = consented.entry.expires_at_unix_ms;
        let execution = consent_at + 300_000;
        assert!(consent_at >= consented.entry.created_at_unix_ms + 60_000);
        assert!(execution > waiting + 59_000);
        let IntentConsented {
            store,
            entry,
            intent,
            blob,
            policy,
        } = consented;
        drop(store);
        let reopened = IntentConsented {
            store: PendingApprovalStore::open(fixture.store_path()).unwrap(),
            entry,
            intent,
            blob,
            policy,
        };
        let mut clocks = Vec::new();
        for at in [waiting, waiting + 59_000] {
            let witness =
                verify_intent(&fixture, &reopened, &reopened.intent, &decision, at).unwrap();
            clocks.push((
                witness.created_at_ms(),
                witness.expires_at_ms(),
                witness.consent_at_ms(),
                witness.execution_expires_at_ms(),
            ));
        }
        assert_eq!(clocks[0], clocks[1], "a retry recomputes identical clocks");
        assert_eq!(
            clocks[0],
            (
                reopened.entry.created_at_unix_ms,
                waiting,
                consent_at,
                execution
            )
        );
        assert_eq!(
            verify_intent(&fixture, &reopened, &reopened.intent, &decision, execution)
                .unwrap_err()
                .code(),
            "approval.expired"
        );
    }

    /// The pure clocks refuse at both exclusive boundaries and before the
    /// lower ones, for an uncapped and a capped governing lifetime.
    #[test]
    fn intent_clocks_check_both_exclusive_boundaries() {
        let created = 1_000_000;
        for (ttl, window) in [(86_400_000, 900_000), (300_000, 300_000)] {
            let waiting = created + ttl;
            let expired = |result: Result<u64, WalletError>| {
                assert_eq!(result.unwrap_err().code(), "approval.expired", "{ttl}");
            };
            expired(intent_clocks(created, waiting, waiting, ttl, waiting));
            expired(intent_clocks(created, waiting, created - 1, ttl, created));
            assert_eq!(
                intent_clocks(created, waiting, waiting - 1, ttl, waiting - 1).unwrap(),
                waiting - 1 + window
            );
            assert_eq!(
                intent_clocks(created, waiting, created, ttl, created).unwrap(),
                created + window
            );
            let consent = created + 10_000;
            let execution = consent + window;
            expired(intent_clocks(created, waiting, consent, ttl, consent - 1));
            assert_eq!(
                intent_clocks(created, waiting, consent, ttl, execution - 1).unwrap(),
                execution,
                "{ttl}"
            );
            expired(intent_clocks(created, waiting, consent, ttl, execution));
            expired(intent_clocks(created, waiting, consent, ttl, execution + 1));
        }
        assert_eq!(
            intent_clocks(1, u64::MAX, u64::MAX - 1, 300_000, u64::MAX - 1)
                .unwrap_err()
                .code(),
            "approval.expired",
            "an overflowing execution clock refuses"
        );
    }

    /// The intent witness reverifies the intent, the decision and the
    /// stored receipt: each mismatch refuses on its own, and the matching
    /// set yields the witness.
    #[test]
    #[serial]
    #[allow(clippy::too_many_lines, reason = "one case per refused input")]
    fn intent_witness_reverifies_intent_decision_and_receipt() {
        use crate::approval::intent::{IntentAsset, IntentBase, IntentPayload};
        use crate::policy::{ApprovalRequest, Decision};
        let fixture = MainnetConsentFixture::new(NAME);
        let decision = fixture.decision(3_600_000);
        let (_, any_intent) = fixture.intent_payment(3_600_000);
        let envelope_entry = fixture.payment(DEFAULT_TTL_MS);
        let envelope = consent(&fixture, &envelope_entry);
        assert_eq!(
            verify_intent_approval(
                &envelope.store,
                fixture.profile(),
                fixture.name(),
                &envelope.nonce,
                &envelope.blob,
                &any_intent,
                &decision,
                &envelope.policy,
                now(),
            )
            .unwrap_err()
            .code(),
            "approval.wrong_kind",
            "an envelope-text record"
        );
        drop(envelope);
        let consented = intent_consent(&fixture, 3_600_000, |_| {});
        let at = now();
        assert!(verify_intent(&fixture, &consented, &consented.intent, &decision, at).is_ok());
        let base = consented.intent.base();
        let intent_with = |payload: IntentPayload, policy_digest: [u8; 32]| {
            ClassicIntent::new(
                IntentBase::new(
                    base.chain_id().to_owned(),
                    base.source().to_owned(),
                    policy_digest,
                    base.fee_bound_stroops(),
                    base.memo().clone(),
                )
                .unwrap(),
                payload,
            )
            .unwrap()
        };
        let other_amount = intent_with(
            IntentPayload::Pay {
                destination: crate::approval::mainnet_fixtures::ALLOWED_DESTINATION.to_owned(),
                asset: IntentAsset::Native,
                amount_stroops: 11,
            },
            consented.policy.digest(),
        );
        let trustline = intent_with(
            IntentPayload::Trustline {
                issuer: crate::approval::mainnet_fixtures::ALLOWED_DESTINATION.to_owned(),
                code: "USDC".to_owned(),
                limit_stroops: 0,
            },
            consented.policy.digest(),
        );
        for (label, intent, code) in [
            (
                "another intent",
                &other_amount,
                "approval.attestation_invalid",
            ),
            ("another kind", &trustline, "approval.wrong_kind"),
        ] {
            assert_eq!(
                verify_intent(&fixture, &consented, intent, &decision, at)
                    .unwrap_err()
                    .code(),
                code,
                "{label}"
            );
        }

        let decided = |decision: Decision,
                       policy_digest: [u8; 32],
                       profile: &str,
                       chain: &str,
                       ttl: u64,
                       scope: AuthorityScope| {
            MainnetDecision::for_test(
                decision,
                None,
                policy_digest,
                consented.policy.sequence(),
                0,
                profile,
                chain,
                at,
                ttl,
                scope,
            )
        };
        let require = || Decision::RequireApproval(ApprovalRequest::new("d".to_owned(), 3_600));
        let digest = consented.policy.digest();
        let decisions = [
            (
                "allow",
                decided(
                    Decision::Allow,
                    digest,
                    NAME,
                    MAINNET_CHAIN_ID,
                    3_600_000,
                    AuthorityScope::Classic,
                ),
            ),
            (
                "another profile",
                decided(
                    require(),
                    digest,
                    "other",
                    MAINNET_CHAIN_ID,
                    3_600_000,
                    AuthorityScope::Classic,
                ),
            ),
            (
                "another chain",
                decided(
                    require(),
                    digest,
                    NAME,
                    "stellar:testnet",
                    3_600_000,
                    AuthorityScope::Classic,
                ),
            ),
            (
                "another policy",
                decided(
                    require(),
                    [0x77; 32],
                    NAME,
                    MAINNET_CHAIN_ID,
                    3_600_000,
                    AuthorityScope::Classic,
                ),
            ),
            (
                "another governing lifetime",
                decided(
                    require(),
                    digest,
                    NAME,
                    MAINNET_CHAIN_ID,
                    3_599_999,
                    AuthorityScope::Classic,
                ),
            ),
            (
                "another scope",
                decided(
                    require(),
                    digest,
                    NAME,
                    MAINNET_CHAIN_ID,
                    3_600_000,
                    AuthorityScope::X402Authenticated {
                        home_domain: "example.com".to_owned(),
                        tool: "stellar_x402_create_payment".to_owned(),
                    },
                ),
            ),
        ];
        for (label, other) in &decisions {
            assert_eq!(
                verify_intent(&fixture, &consented, &consented.intent, other, at)
                    .unwrap_err()
                    .code(),
                "approval.attestation_invalid",
                "{label}"
            );
        }

        // A record whose blob the key holder recomputed over an intent that
        // names another policy, or over a receipt whose assertion fails,
        // refuses although its attestation verifies.
        let genuine = receipt_of(&consented.store, &consented.entry.approval_nonce);
        let mut wire = serde_json::to_value(&genuine).unwrap();
        let client = wire["assertion"]["client_data_json"]
            .as_array_mut()
            .unwrap();
        assert_eq!(client.pop().unwrap(), serde_json::json!(b'}'));
        client.extend(b",\"extra\":1}".iter().map(|b| serde_json::json!(b)));
        let altered: MainnetPresenceReceipt = serde_json::from_value(wire).unwrap();
        assert!(altered.is_well_formed());
        let foreign_policy = intent_with(consented.intent.payload().clone(), [0x77; 32]);
        for (index, (label, receipt, intent, code)) in [
            (
                "an invalid stored assertion",
                altered,
                &consented.intent,
                "approval.presence_invalid",
            ),
            (
                "an intent of another policy",
                genuine.clone(),
                &foreign_policy,
                "approval.attestation_invalid",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let entry = &consented.entry;
            let approver = AttestedApprover::MainnetPasskey {
                credential_id_b64url: receipt.credential_id_b64url(),
            };
            let blob = crate::approval::attestation::compute_attestation_v6(
                &ATTESTATION_KEY,
                &fixture.binding(),
                &entry.approval_nonce,
                intent.digest().as_bytes(),
                &entry.process_uid,
                &entry.attested_lifetime(),
                &approver,
                &receipt,
            );
            let mut store =
                PendingApprovalStore::open(fixture.home().join(format!("forged{index}.toml")))
                    .unwrap();
            store.insert(entry.clone(), now()).unwrap();
            store
                .record_mainnet_attestation_at(
                    &entry.approval_nonce,
                    blob,
                    approver,
                    receipt,
                    now(),
                )
                .unwrap();
            assert_eq!(
                store
                    .get(&entry.approval_nonce)
                    .unwrap()
                    .attestation_version,
                6
            );
            let forged = IntentConsented {
                store,
                entry: entry.clone(),
                intent: intent.clone(),
                blob,
                policy: consented.policy.clone(),
            };
            assert_eq!(
                verify_intent(&fixture, &forged, intent, &decision, now())
                    .unwrap_err()
                    .code(),
                code,
                "{label}"
            );
        }
        assert!(verify_intent(&fixture, &consented, &consented.intent, &decision, now()).is_ok());
    }

    /// Producing an intent witness and reopening the store leave the inbox
    /// bytes unchanged, and the fact digest follows the documented layout
    /// over the signed times.
    #[test]
    #[serial]
    fn intent_witness_keeps_signed_bytes_and_fact_digest_layout() {
        let fixture = MainnetConsentFixture::new(NAME);
        let consented = intent_consent(&fixture, 3_600_000, |_| {});
        let decision = fixture.decision(3_600_000);
        let before = std::fs::read(fixture.store_path()).unwrap();
        let witness =
            verify_intent(&fixture, &consented, &consented.intent, &decision, now()).unwrap();
        assert_eq!(std::fs::read(fixture.store_path()).unwrap(), before);
        let IntentConsented {
            store,
            entry,
            intent,
            blob,
            policy,
        } = consented;
        drop(store);
        let reopened = IntentConsented {
            store: PendingApprovalStore::open(fixture.store_path()).unwrap(),
            entry,
            intent,
            blob,
            policy,
        };
        let again = verify_intent(&fixture, &reopened, &reopened.intent, &decision, now()).unwrap();
        assert_eq!(std::fs::read(fixture.store_path()).unwrap(), before);
        assert_eq!(again.fact_digest(), witness.fact_digest());

        let receipt = receipt_of(&reopened.store, &reopened.entry.approval_nonce);
        let mut preimage = FACT_LABEL_APPROVAL.to_vec();
        for field in [
            NAME.as_bytes(),
            b"stellar:mainnet",
            reopened.entry.approval_nonce.as_bytes(),
        ] {
            preimage.extend(u32::try_from(field.len()).unwrap().to_be_bytes());
            preimage.extend(field);
        }
        preimage.push(1);
        preimage.extend(reopened.intent.digest().as_bytes());
        preimage.extend(reopened.entry.created_at_unix_ms.to_be_bytes());
        preimage.extend(reopened.entry.expires_at_unix_ms.to_be_bytes());
        preimage.extend(receipt.digest().unwrap());
        preimage.extend(reopened.policy.digest());
        let independent: [u8; 32] = sha2::Sha256::digest(&preimage).into();
        assert_eq!(witness.fact_digest(), independent);
        assert_eq!(witness.created_at_ms(), reopened.entry.created_at_unix_ms);
        assert_eq!(witness.expires_at_ms(), reopened.entry.expires_at_unix_ms);
        assert_ne!(
            witness.expires_at_ms(),
            witness.execution_expires_at_ms(),
            "the signed expiry and the execution expiry differ here"
        );
    }

    /// An envelope witness reports the envelope text, the receipt's verified
    /// time as consent, and the signed expiry as its execution expiry.
    #[test]
    #[serial]
    fn envelope_witness_reports_its_pending_lifetime() {
        let fixture = MainnetConsentFixture::new(NAME);
        let entry = fixture.payment(DEFAULT_TTL_MS);
        let consented = consent(&fixture, &entry);
        let expected = payment_expectation(&entry);
        let witness = verify(&fixture, &consented, &expected, &consented.policy, now()).unwrap();
        let receipt = receipt_of(&consented.store, &consented.nonce);
        assert_eq!(witness.subject_kind(), SubjectKind::EnvelopeText);
        assert_eq!(witness.consent_at_ms(), receipt.verified_at_unix_ms());
        assert_eq!(witness.execution_expires_at_ms(), entry.expires_at_unix_ms);
        assert_eq!(witness.expires_at_ms(), entry.expires_at_unix_ms);
        assert!(
            witness.execution_expires_at_ms() - witness.consent_at_ms() > APPROVAL_EXECUTION_MAX_MS,
            "the execution cap does not apply to an envelope witness"
        );
    }
}
