//! The approval witness: proof that a pending mainnet approval record,
//! attested under version 5 with a verified WebAuthn presence, approves one
//! subject, is live, and is still authorized by the current owner-signed
//! policy when the witness is produced.
//!
//! [`verify_approval`] is the only producer. It reads the record from the
//! pending store by nonce, the attestation key from the keyring, and the
//! current signed policy from the wallet's own locations itself, derives the
//! key coordinate and the owner context from the profile exactly as the
//! approve path does, and accepts nothing else from its caller but the
//! nonce, the presented attestation, the binding, the expectation, the
//! policy the caller authorizes under, and the time. A witness therefore
//! records facts the producer established, and its fields are private:
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
//! # Mainnet only, version 5 only
//!
//! A witness is mainnet proof, and [`verify_approval`] refuses every binding
//! that is not mainnet. The record must carry a version 5 attestation with a
//! mainnet passkey approver and its presence receipt: a version 4 local or
//! remote approval, which a terminal, a same-user process or the remote
//! allowlist can produce, is no proof, however genuine its HMAC.
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
use super::presence::MAINNET_CHAIN_ID;
use super::presence_policy::{CurrentMainnetApprovalPolicy, MainnetApprovalAuthority};
use super::store::{ApprovalKind, PendingApprovalStore};
use super::subject::approval_subject_classic;
use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::fact::{FACT_LABEL_APPROVAL, FactDigest};
use crate::mainnet::verified_policy::VerifiedPolicy;
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

/// Proof that a version 5 attestation with a verified presence approves
/// `subject`, was live at the time [`verify_approval`] checked it, and is
/// authorized by the current owner-signed policy at that time.
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
}

impl std::fmt::Debug for ApprovalWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalWitness")
            .field("profile", &self.profile)
            .field("chain", &self.chain.caip2_str())
            .field("kind", &self.kind)
            .field("expires_at_ms", &self.expires_at_ms)
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
    /// attestation covers it.
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// When the approval expires, in Unix milliseconds: the stored expiry the
    /// version 5 attestation covers.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
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
///    record refuses, and so does a kind other than the [`ApprovedKind`]s or
///    other than `expected.kind`.
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
/// The witness's expiry is the stored expiry. A caller that governs the
/// approval by a shorter lifetime compares [`ApprovalWitness::created_at_ms`]
/// and [`ApprovalWitness::expires_at_ms`] with it.
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
    if kind != expected.kind {
        return Err(WalletError::Approval(ApprovalFailure::WrongKind {
            detail: "the approval is for another kind of action".to_owned(),
        }));
    }
    let Some(scope @ AttestationScope::V5(_, _, receipt)) = record.attestation_scope() else {
        return Err(WalletError::Approval(ApprovalFailure::PresenceRequired));
    };
    if stored_digest != subject || subject != expected.subject {
        return Err(invalid("the approval approves another transaction"));
    }
    let key = load_attestation_key(
        &profile.attestation_key_id,
        &OwnerKeyContext::for_profile(profile_name, profile),
    )?;
    let key: [u8; 32] = key.as_slice().try_into().map_err(|_| {
        WalletError::Approval(ApprovalFailure::KeyLengthError {
            detail: format!("attestation key must be 32 bytes, got {}", key.len()),
        })
    })?;
    let key = zeroize::Zeroizing::new(key);
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
    })
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
}
