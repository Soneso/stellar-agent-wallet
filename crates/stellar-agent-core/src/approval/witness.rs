//! The approval witness: proof that a pending approval record, attested by
//! the operator under version 3, approves one subject and is live.
//!
//! [`verify_approval`] is the only producer. It reads the record from the
//! pending store by nonce and the attestation key from the keyring itself,
//! derives the key coordinate and the owner context from the profile exactly
//! as the approve path does, and accepts nothing else from its caller but
//! the nonce, the presented attestation, the binding, the expectation, and
//! the time. A witness therefore records facts the producer established, and
//! its fields are private:
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
//! # Why version 3
//!
//! The pending file is not a security boundary, and a version 2 attestation
//! covers the profile, chain, nonce, subject, and process UID only. Under
//! version 2, a record's kind and lifetime are whatever the file says. A
//! version 3 attestation also covers them, so the witness's expiry is the
//! one the operator approved.

use super::attest::{decode_sha256_hex, load_attestation_key};
use super::attestation::{
    ATTESTATION_VERSION, AttestationBinding, AttestationScope, verify_attestation,
};
use super::store::{ApprovalKind, PendingApprovalStore};
use super::subject::approval_subject_classic;
use crate::error::{ApprovalFailure, WalletError};
use crate::mainnet::fact::{FACT_LABEL_APPROVAL, FactDigest};
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

/// Proof that a version 3 attestation approves `subject` and was live at the
/// time [`verify_approval`] checked it.
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

    /// When the record was created, in Unix milliseconds, as the version 3
    /// attestation covers it.
    #[must_use]
    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    /// When the approval expires, in Unix milliseconds: the stored expiry the
    /// version 3 attestation covers.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The fact digest under `stellar-agent-authz-fact:approval:v1`.
    ///
    /// Fields, in order: `lp(profile)`, `lp(chain)` as its CAIP-2 text,
    /// `lp(nonce)`, the kind's one-byte tag, the 32-byte subject,
    /// `u64be(created_at_ms)`, and `u64be(expires_at_ms)`.
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
            .u64(self.expires_at_ms);
        digest.finish()
    }
}

fn invalid(detail: &str) -> WalletError {
    WalletError::Approval(ApprovalFailure::AttestationInvalid {
        detail: detail.to_owned(),
    })
}

/// Verifies the approval `nonce` as mainnet proof for `expected` and returns
/// its witness.
///
/// In order:
///
/// 1. `binding` must name `profile_name` and `profile`'s chain.
/// 2. The record is read from `pending` by `nonce`. A rejected or consumed
///    record refuses, and so does a kind other than the three
///    [`ApprovedKind`]s or other than `expected.kind`.
/// 3. The record must store attestation version 3.
/// 4. The subject is recomputed from the record's envelope text; it must
///    equal the stored digest and `expected.subject`.
/// 5. The attestation key is loaded from `profile.attestation_key_id`,
///    refused when it is or may be the owner public key of `profile_name`,
///    and the attestation must verify under version 3 over the record's
///    nonce, subject, process UID, kind, and lifetime.
/// 6. `created_at <= now_ms < expires_at` on the stored, attested times.
///
/// The witness's expiry is the stored expiry. A caller that governs the
/// approval by a shorter lifetime compares [`ApprovalWitness::created_at_ms`]
/// and [`ApprovalWitness::expires_at_ms`] with it.
///
/// # Errors
///
/// - `approval.not_found`, `approval.rejected`, `approval.consumed`, or
///   `approval.wrong_kind` for the record.
/// - `approval.attestation_invalid` for a version other than 3, a subject
///   mismatch, or an attestation that does not verify.
/// - `approval.expired` outside the record's lifetime.
/// - The key loader's errors, including the owner-key refusal.
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
    now_ms: u64,
) -> Result<ApprovalWitness, WalletError> {
    let binding = AttestationBinding::new(profile_name, profile.chain_id.caip2_str());
    let record = pending.get(nonce).ok_or_else(|| {
        WalletError::Approval(ApprovalFailure::NotFound {
            detail: "no pending approval with that nonce".to_owned(),
        })
    })?;
    let (kind, envelope_xdr_b64, envelope_sha256_hex) = match &record.kind {
        ApprovalKind::PaymentSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (ApprovedKind::Payment, envelope_xdr_b64, envelope_sha256_hex),
        ApprovalKind::ClaimSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (ApprovedKind::Claim, envelope_xdr_b64, envelope_sha256_hex),
        ApprovalKind::TrustlineSimulated {
            envelope_xdr_b64,
            envelope_sha256_hex,
            ..
        } => (
            ApprovedKind::Trustline,
            envelope_xdr_b64,
            envelope_sha256_hex,
        ),
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
    if record.attestation_version != ATTESTATION_VERSION {
        return Err(invalid(
            "the approval's attestation does not cover its kind and lifetime; \
             approve the action again",
        ));
    }
    let subject = approval_subject_classic(envelope_xdr_b64);
    if decode_sha256_hex(envelope_sha256_hex)? != subject || subject != expected.subject {
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
        &AttestationScope::V3(record.attested_lifetime()),
        attestation,
    ) {
        return Err(invalid("the attestation does not verify"));
    }
    if record.created_at_unix_ms > now_ms || now_ms >= record.expires_at_unix_ms {
        return Err(WalletError::Approval(ApprovalFailure::Expired {
            detail: "the approval is outside its lifetime".to_owned(),
        }));
    }
    Ok(ApprovalWitness {
        profile: profile_name.to_owned(),
        chain: profile.chain_id,
        nonce: record.approval_nonce.clone(),
        kind,
        subject,
        created_at_ms: record.created_at_unix_ms,
        expires_at_ms: record.expires_at_unix_ms,
    })
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
    use crate::approval::attestation::{AttestedLifetime, compute_attestation};
    use crate::approval::store::{DEFAULT_TTL_MS, PendingApproval};
    use crate::profile::schema::KeyringEntryRef;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serial_test::serial;
    use stellar_agent_test_support::keyring_mock;
    use tempfile::TempDir;

    const NAME: &str = "witness";
    const ENVELOPE: &str = "AAAAAgAAAAA=";
    const KEY: [u8; 32] = [0x5a; 32];

    struct Fixture {
        _dir: TempDir,
        path: std::path::PathBuf,
        profile: Profile,
        nonce: String,
        blob: [u8; 32],
        created: u64,
        expires: u64,
    }

    fn profile() -> Profile {
        Profile::builder_mainnet_named(NAME, "https://rpc.example.invalid", "s", "a", "n", "a")
            .build()
    }

    fn put_key(entry: &KeyringEntryRef, key: &[u8; 32]) {
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&URL_SAFE_NO_PAD.encode(key))
            .unwrap();
    }

    fn binding() -> AttestationBinding<'static> {
        AttestationBinding::new(NAME, "stellar:mainnet")
    }

    /// A payment approval for [`ENVELOPE`], attested with [`KEY`] under the
    /// record's own kind and lifetime, the way the approve path attests.
    fn fixture() -> Fixture {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(format!("{NAME}.toml"));
        let profile = profile();
        put_key(&profile.attestation_key_id, &KEY);
        let entry = PendingApproval::new_payment_pending(
            ENVELOPE.to_owned(),
            ENVELOPE.as_bytes(),
            stellar_strkey::ed25519::PublicKey([1; 32])
                .to_string()
                .to_string(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            7,
            "1000".to_owned(),
            DEFAULT_TTL_MS,
        )
        .unwrap();
        assert_eq!(entry.attestation_version, ATTESTATION_VERSION);
        let nonce = entry.approval_nonce.clone();
        let created = entry.created_at_unix_ms;
        let expires = entry.expires_at_unix_ms;
        let blob = compute_attestation(
            &KEY,
            &binding(),
            &nonce,
            &approval_subject_classic(ENVELOPE),
            "1000",
            &entry.attested_lifetime(),
        );
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        store.insert(entry, created).unwrap();
        store.record_attestation_at(&nonce, blob, created).unwrap();
        Fixture {
            _dir: dir,
            path,
            profile,
            nonce,
            blob,
            created,
            expires,
        }
    }

    fn expectation() -> ApprovalExpectation {
        ApprovalExpectation {
            kind: ApprovedKind::Payment,
            subject: approval_subject_classic(ENVELOPE),
        }
    }

    fn verify(f: &Fixture, blob: &[u8; 32], now: u64) -> Result<ApprovalWitness, WalletError> {
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        verify_approval(
            &store,
            &f.profile,
            NAME,
            &f.nonce,
            blob,
            &expectation(),
            now,
        )
    }

    /// Rewrites `field = value` lines of the pending file, the way anyone
    /// with write access to it can.
    fn rewrite(path: &std::path::Path, field: &str, value: u64) {
        let text = std::fs::read_to_string(path).unwrap();
        let rewritten = text
            .lines()
            .map(|line| {
                if line.trim_start().starts_with(&format!("{field} =")) {
                    format!("{field} = {value}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, rewritten).unwrap();
    }

    /// An attested, live, matching approval yields a witness of exactly the
    /// record's facts, and its fact digest follows the documented layout.
    #[test]
    #[serial]
    fn a_live_version_3_approval_yields_its_witness() {
        let f = fixture();
        let witness = verify(&f, &f.blob, f.created).unwrap();
        assert_eq!(witness.profile(), NAME);
        assert_eq!(witness.chain(), Caip2::Mainnet);
        assert_eq!(witness.nonce(), f.nonce);
        assert_eq!(witness.kind(), ApprovedKind::Payment);
        assert_eq!(witness.subject(), approval_subject_classic(ENVELOPE));
        assert_eq!(witness.created_at_ms(), f.created);
        assert_eq!(witness.expires_at_ms(), f.expires);

        let mut expected = FACT_LABEL_APPROVAL.to_vec();
        for field in [NAME.as_bytes(), b"stellar:mainnet", f.nonce.as_bytes()] {
            expected.extend(u32::try_from(field.len()).unwrap().to_be_bytes());
            expected.extend(field);
        }
        expected.push(1);
        expected.extend(approval_subject_classic(ENVELOPE));
        expected.extend(f.created.to_be_bytes());
        expected.extend(f.expires.to_be_bytes());
        let independent: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&expected).into();
        assert_eq!(witness.fact_digest(), independent);
    }

    /// The lifetime holds at its first millisecond and refuses before it and
    /// at the expiry itself.
    #[test]
    #[serial]
    fn freshness_holds_on_the_stored_boundaries() {
        let f = fixture();
        assert!(verify(&f, &f.blob, f.created).is_ok());
        assert!(verify(&f, &f.blob, f.expires - 1).is_ok());
        for now in [f.created - 1, f.expires, f.expires + 1] {
            let err = verify(&f, &f.blob, now).unwrap_err();
            assert_eq!(err.code(), "approval.expired", "{now}");
        }
    }

    /// An approval that expired unused, whose stored creation and expiry are
    /// then moved forward in the file, does not verify: version 3 covers both.
    #[test]
    #[serial]
    fn moving_an_expired_approval_forward_refuses() {
        let f = fixture();
        let later = f.expires + 10_000;
        assert_eq!(
            verify(&f, &f.blob, later).unwrap_err().code(),
            "approval.expired"
        );
        rewrite(&f.path, "created_at_unix_ms", later - 1);
        rewrite(&f.path, "expires_at_unix_ms", later + DEFAULT_TTL_MS);
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        let moved = store.get(&f.nonce).unwrap();
        assert_eq!(moved.created_at_unix_ms, later - 1);
        drop(store);
        assert_eq!(
            verify(&f, &f.blob, later).unwrap_err().code(),
            "approval.attestation_invalid"
        );
    }

    /// A record without a stored version reads as version 2 and refuses as
    /// mainnet proof, even with the genuine blob its attestation step wrote.
    #[test]
    #[serial]
    fn a_version_2_record_refuses_as_mainnet_proof() {
        let f = fixture();
        let text = std::fs::read_to_string(&f.path).unwrap();
        let without: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("attestation_version"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&f.path, without).unwrap();
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        assert_eq!(store.get(&f.nonce).unwrap().attestation_version, 2);
        drop(store);
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );
    }

    /// An attestation computed with another key does not verify against the
    /// key the producer loads from the keyring, and the record's own blob does
    /// not verify once the keyring holds another key.
    #[test]
    #[serial]
    fn a_wrong_key_attestation_refuses_against_the_loaded_key() {
        let f = fixture();
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        let record = store.get(&f.nonce).unwrap().clone();
        drop(store);
        let forged = compute_attestation(
            &[0x11; 32],
            &binding(),
            &f.nonce,
            &approval_subject_classic(ENVELOPE),
            "1000",
            &AttestedLifetime::new(
                record.kind.kind_name(),
                record.created_at_unix_ms,
                record.expires_at_unix_ms,
            ),
        );
        assert_eq!(
            verify(&f, &forged, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );
        put_key(&f.profile.attestation_key_id, &[0x11; 32]);
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );
        assert!(verify(&f, &forged, f.created).is_ok());
    }

    /// The kind, the subject, the binding, rejection, consumption, an unknown
    /// nonce, and a missing key each refuse on their own.
    #[test]
    #[serial]
    fn each_mismatch_refuses_on_its_own() {
        let f = fixture();
        let store = PendingApprovalStore::open(f.path.clone()).unwrap();
        let call = |expected: &ApprovalExpectation, profile: &Profile, name: &str, nonce: &str| {
            verify_approval(&store, profile, name, nonce, &f.blob, expected, f.created)
                .map(|_| ())
                .unwrap_err()
                .code()
        };
        assert_eq!(
            call(
                &ApprovalExpectation {
                    kind: ApprovedKind::Claim,
                    ..expectation()
                },
                &f.profile,
                NAME,
                &f.nonce
            ),
            "approval.wrong_kind"
        );
        assert_eq!(
            call(
                &ApprovalExpectation {
                    subject: [0; 32],
                    ..expectation()
                },
                &f.profile,
                NAME,
                &f.nonce
            ),
            "approval.attestation_invalid"
        );
        let mut other = f.profile.clone();
        other.chain_id = Caip2::Testnet;
        assert_eq!(
            call(&expectation(), &other, NAME, &f.nonce),
            "approval.attestation_invalid"
        );
        assert_eq!(
            call(&expectation(), &f.profile, "other", &f.nonce),
            "approval.attestation_invalid"
        );
        assert_eq!(
            call(&expectation(), &f.profile, NAME, "AAAAAAAAAAAAAAAAAAAAAA"),
            "approval.not_found"
        );
        drop(store);

        keyring_core::Entry::new(
            &f.profile.attestation_key_id.service,
            &f.profile.attestation_key_id.account,
        )
        .unwrap()
        .delete_credential()
        .unwrap();
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "auth.keyring_not_found"
        );
        put_key(&f.profile.attestation_key_id, &KEY);

        let mut store = PendingApprovalStore::open(f.path.clone()).unwrap();
        store
            .consume(
                &f.nonce,
                &"ab".repeat(32),
                crate::approval::store::ConsumedOutcome::Unknown,
            )
            .unwrap();
        drop(store);
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.consumed"
        );

        let g = fixture();
        let mut store = PendingApprovalStore::open(g.path.clone()).unwrap();
        store.reject(&g.nonce, g.created, DEFAULT_TTL_MS).unwrap();
        drop(store);
        assert_eq!(
            verify(&g, &g.blob, g.created).unwrap_err().code(),
            "approval.rejected"
        );
    }

    #[test]
    #[serial]
    fn configured_attestation_coordinates_and_owner_context_are_used() {
        let mut f = fixture();
        f.profile.attestation_key_id = KeyringEntryRef::new("custom-attestation", "custom");
        put_key(&KeyringEntryRef::default_attestation_key(NAME), &[8; 32]);
        put_key(&f.profile.attestation_key_id, &KEY);
        assert!(verify(&f, &f.blob, f.created).is_ok());
        f.profile.policy_owner_key_id = KeyringEntryRef::new("custom-owner", "public");
        keyring_core::Entry::new("custom-owner", "public")
            .unwrap()
            .set_password(stellar_strkey::ed25519::PublicKey(KEY).to_string().as_ref())
            .unwrap();
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "validation.key_matches_owner_public_key"
        );
        keyring_core::Entry::new("custom-owner", "public")
            .unwrap()
            .set_password(
                stellar_strkey::ed25519::PublicKey([3; 32])
                    .to_string()
                    .as_ref(),
            )
            .unwrap();
        assert!(verify(&f, &f.blob, f.created).is_ok());
    }

    #[test]
    #[serial]
    fn the_stored_subject_digest_is_compared() {
        let f = fixture();
        assert!(verify(&f, &f.blob, f.created).is_ok());
        let text = std::fs::read_to_string(&f.path).unwrap();
        let good = crate::hex::encode(&approval_subject_classic(ENVELOPE));
        assert!(text.contains(&good));
        std::fs::write(&f.path, text.replace(&good, &"00".repeat(32))).unwrap();
        assert_eq!(
            verify(&f, &f.blob, f.created).unwrap_err().code(),
            "approval.attestation_invalid"
        );
    }

    #[test]
    #[serial]
    fn claim_and_trustline_approvals_yield_witnesses() {
        keyring_mock::install().unwrap();
        let dir = TempDir::new().unwrap();
        let profile = profile();
        put_key(&profile.attestation_key_id, &KEY);
        let address = stellar_strkey::ed25519::PublicKey([1; 32])
            .to_string()
            .to_string();
        let balance = stellar_strkey::ClaimableBalance::V0([1; 32])
            .to_string()
            .to_string();
        let entries = [
            (
                ApprovedKind::Claim,
                PendingApproval::new_claim_pending(
                    ENVELOPE.to_owned(),
                    ENVELOPE.as_bytes(),
                    format!("00000000{}", "01".repeat(32)),
                    balance,
                    "XLM".to_owned(),
                    1,
                    address.clone(),
                    100,
                    7,
                    "1000".to_owned(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
            (
                ApprovedKind::Trustline,
                PendingApproval::new_trustline_pending(
                    ENVELOPE.to_owned(),
                    ENVELOPE.as_bytes(),
                    address.clone(),
                    "USD".to_owned(),
                    address,
                    Some(100),
                    100,
                    7,
                    "1000".to_owned(),
                    DEFAULT_TTL_MS,
                )
                .unwrap(),
            ),
        ];
        for (kind, entry) in entries {
            let nonce = entry.approval_nonce.clone();
            let now = entry.created_at_unix_ms;
            let blob = compute_attestation(
                &KEY,
                &binding(),
                &nonce,
                &approval_subject_classic(ENVELOPE),
                "1000",
                &entry.attested_lifetime(),
            );
            let mut store =
                PendingApprovalStore::open(dir.path().join(format!("{kind:?}.toml"))).unwrap();
            store.insert(entry, now).unwrap();
            store.record_attestation_at(&nonce, blob, now).unwrap();
            let witness = verify_approval(
                &store,
                &profile,
                NAME,
                &nonce,
                &blob,
                &ApprovalExpectation {
                    kind,
                    subject: approval_subject_classic(ENVELOPE),
                },
                now,
            )
            .unwrap();
            assert_eq!(witness.kind(), kind);
        }
    }
}
