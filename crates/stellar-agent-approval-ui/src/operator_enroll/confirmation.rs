//! The terminal confirmation that gates persisting an enrolled credential.
//!
//! The enrollment server stages a verified registration and hands it to the
//! process that started it; it never writes the credential store. That
//! process holds a [`PendingOperatorEnrollment`] and asks the operator for
//! the confirmation code the enrollment page displays.
//! [`PendingOperatorEnrollment::confirm`] compares it, once, with the code of
//! the staged credential; only the [`ConfirmedOperatorEnrollment`] it returns
//! can [`ConfirmedOperatorEnrollment::persist`] an operator credential or
//! [`ConfirmedOperatorEnrollment::into_mainnet_policy_credential`] export a
//! mainnet approval credential, each for its own
//! [`super::EnrollmentPurpose`] only.
//!
//! # The confirmation code
//!
//! The code is the first 16 hexadecimal characters of SHA-256 over the
//! purpose's domain, the 32-byte challenge, the credential ID's length as a
//! big-endian `u32` followed by the ID, and the 65-byte SEC1 public key,
//! shown as four groups of four separated by `-`. The domain is
//! `stellar-agent-operator-enrollment-confirmation:v1` for an operator
//! credential and `stellar-agent-mainnet-approval-enrollment-confirmation:v1`
//! for a mainnet approval credential, so a code of one purpose never
//! confirms the other. The page computes it from the credential its own
//! ceremony created, so a code typed at the terminal matches only when the
//! staged credential is that one. [`ConfirmationCode`] computes and compares
//! it.

use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use stellar_agent_core::approval::MainnetApprovalCredential;
use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::approval::operator_credentials::{
    OperatorApprovalCredential, OperatorApprovalCredentialStore,
};
use stellar_agent_core::approval::webauthn_registration::ConfirmationCode;
#[cfg(any(test, feature = "test-helpers"))]
use stellar_agent_core::approval::webauthn_registration::PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN;

use super::EnrollmentPurpose;
use super::registration::{REGISTRATION_RP_ID, VerifiedOperatorRegistration};

/// Domain separator of an operator credential's confirmation code.
pub(super) const OPERATOR_CODE_DOMAIN: &[u8] = b"stellar-agent-operator-enrollment-confirmation:v1";

/// Domain separator of a mainnet approval credential's confirmation code.
pub(super) const MAINNET_APPROVAL_CODE_DOMAIN: &[u8] =
    b"stellar-agent-mainnet-approval-enrollment-confirmation:v1";

/// The message of a confirmed enrollment used for the other purpose.
const WRONG_PURPOSE_MESSAGE: &str = "The enrollment purpose does not match the requested export.";

/// The operator credential's confirmation code of a credential registered
/// over `challenge`; see [`enrollment_confirmation_code`].
#[cfg(test)]
pub(crate) fn operator_enrollment_confirmation_code(
    challenge: &[u8; 32],
    credential_id: &[u8],
    public_key_sec1: &[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN],
) -> String {
    enrollment_confirmation_code(
        EnrollmentPurpose::RemoteOperator,
        challenge,
        credential_id,
        public_key_sec1,
    )
}

/// The `purpose` confirmation code of a credential registered over
/// `challenge`, in the display form `xxxx-xxxx-xxxx-xxxx` (lowercase
/// hexadecimal) the page shows. The server itself compares only the digits,
/// so this form exists for the tests and the test support that play the
/// page's part.
#[cfg(any(test, feature = "test-helpers"))]
pub(crate) fn enrollment_confirmation_code(
    purpose: EnrollmentPurpose,
    challenge: &[u8; 32],
    credential_id: &[u8],
    public_key_sec1: &[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN],
) -> String {
    ConfirmationCode::compute(
        purpose.code_domain(),
        challenge,
        credential_id,
        public_key_sec1,
    )
    .display()
}

/// A verified registration the server accepted, with the code its page
/// shows. Crosses from the server to the handle; never serialized.
pub(crate) struct StagedEnrollment {
    registration: VerifiedOperatorRegistration,
    expected_code: ConfirmationCode,
    purpose: EnrollmentPurpose,
}

impl StagedEnrollment {
    /// Stages `registration`, accepted for `challenge` by a `purpose`
    /// ceremony.
    pub(crate) fn new(
        registration: VerifiedOperatorRegistration,
        challenge: &[u8; 32],
        purpose: EnrollmentPurpose,
    ) -> Self {
        let expected_code = ConfirmationCode::compute(
            purpose.code_domain(),
            challenge,
            registration.credential_id(),
            registration.public_key_sec1(),
        );
        Self {
            registration,
            expected_code,
            purpose,
        }
    }

    /// The staged registration awaiting confirmation until `deadline`.
    pub(crate) fn with_deadline(self, deadline: Instant) -> PendingOperatorEnrollment {
        PendingOperatorEnrollment {
            staged: self,
            deadline,
        }
    }
}

/// A verified operator credential awaiting the operator's terminal
/// confirmation.
///
/// Returned by [`super::OperatorEnrollHandle::await_completion`]. It carries
/// the ceremony's deadline. It cannot be serialized, and `Debug` shows
/// nothing of the credential or the expected code.
pub struct PendingOperatorEnrollment {
    staged: StagedEnrollment,
    deadline: Instant,
}

impl PendingOperatorEnrollment {
    /// The ceremony deadline after which [`Self::confirm`] refuses.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// The label the operator gave the credential on the enrollment page:
    /// trimmed, 1 to 64 bytes, and free of control characters.
    #[must_use]
    pub fn label(&self) -> &str {
        self.staged.registration.label()
    }

    /// What the ceremony enrolled the credential for.
    #[must_use]
    pub fn purpose(&self) -> EnrollmentPurpose {
        self.staged.purpose
    }

    /// Compares `submitted_code` with the code of the staged credential, at
    /// `now`.
    ///
    /// Consumes the pending enrollment: one code is compared per ceremony,
    /// and a refusal leaves nothing to retry with. The comparison runs in
    /// constant time over the normalized digits.
    ///
    /// # Errors
    ///
    /// - [`OperatorEnrollmentConfirmationError::Expired`] when `now` is at or
    ///   past the ceremony deadline.
    /// - [`OperatorEnrollmentConfirmationError::Mismatch`] when the code is
    ///   malformed or names another credential.
    pub fn confirm(
        self,
        submitted_code: &str,
        now: Instant,
    ) -> Result<ConfirmedOperatorEnrollment, OperatorEnrollmentConfirmationError> {
        if now >= self.deadline {
            return Err(OperatorEnrollmentConfirmationError::Expired);
        }
        if !self.staged.expected_code.matches(submitted_code) {
            return Err(OperatorEnrollmentConfirmationError::Mismatch);
        }
        Ok(ConfirmedOperatorEnrollment {
            registration: self.staged.registration,
            purpose: self.staged.purpose,
        })
    }
}

impl std::fmt::Debug for PendingOperatorEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingOperatorEnrollment")
            .finish_non_exhaustive()
    }
}

/// A credential the operator confirmed at the terminal, ready to persist or
/// export for its purpose.
pub struct ConfirmedOperatorEnrollment {
    registration: VerifiedOperatorRegistration,
    purpose: EnrollmentPurpose,
}

impl ConfirmedOperatorEnrollment {
    /// The mainnet approval credential of a
    /// [`EnrollmentPurpose::MainnetApproval`] ceremony, for the owner to add
    /// to `mainnet.approval_credentials` and sign. Nothing is written.
    ///
    /// # Errors
    ///
    /// - [`OperatorEnrollmentConfirmationError::WrongPurpose`] for an
    ///   operator credential ceremony.
    /// - [`OperatorEnrollmentConfirmationError::CredentialInvalid`] when the
    ///   verified registration has no policy form.
    pub fn into_mainnet_policy_credential(
        self,
    ) -> Result<MainnetApprovalCredential, OperatorEnrollmentConfirmationError> {
        if self.purpose != EnrollmentPurpose::MainnetApproval {
            return Err(OperatorEnrollmentConfirmationError::WrongPurpose);
        }
        MainnetApprovalCredential::from_encoded(
            self.registration.credential_id_b64url(),
            &URL_SAFE_NO_PAD.encode(self.registration.public_key_sec1()),
        )
        .map_err(|_| OperatorEnrollmentConfirmationError::CredentialInvalid)
    }

    /// Enrolls the confirmed credential into `store`, bound to
    /// `rp_id: "localhost"`, and returns the record written.
    ///
    /// # Errors
    ///
    /// [`ApprovalError::Invalid`] for a mainnet approval credential
    /// ceremony, whose credential is exported and never stored here. The
    /// errors of [`OperatorApprovalCredentialStore::enroll`], including
    /// [`ApprovalError::DuplicateCredentialId`] when the ID was enrolled
    /// since the server staged it, and [`ApprovalError::WriterLocked`] under
    /// contention; an [`ApprovalError::Io`] when the system clock reads
    /// before the Unix epoch. Nothing is written on any error.
    pub fn persist(
        self,
        store: &OperatorApprovalCredentialStore,
    ) -> Result<OperatorApprovalCredential, ApprovalError> {
        if self.purpose != EnrollmentPurpose::RemoteOperator {
            return Err(ApprovalError::Invalid {
                reason: WRONG_PURPOSE_MESSAGE.to_owned(),
            });
        }
        let registered_at_unix_ms =
            stellar_agent_core::timefmt::now_unix_ms().map_err(|e| ApprovalError::Io {
                kind: std::io::ErrorKind::Other,
                source: std::io::Error::other(format!("system clock error: {e}")),
            })?;
        let registration = self.registration;
        let credential = OperatorApprovalCredential {
            credential_id_b64url: registration.credential_id_b64url().to_owned(),
            public_key_sec1_b64: URL_SAFE_NO_PAD.encode(registration.public_key_sec1()),
            rp_id: REGISTRATION_RP_ID.to_owned(),
            label: registration.label().to_owned(),
            registered_at_unix_ms,
            sign_count: Some(registration.sign_count()),
        };
        store.enroll(credential.clone())?;
        Ok(credential)
    }
}

impl std::fmt::Debug for ConfirmedOperatorEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmedOperatorEnrollment")
            .finish_non_exhaustive()
    }
}

/// Why [`PendingOperatorEnrollment::confirm`] refused.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorEnrollmentConfirmationError {
    /// The typed code is malformed or is not the staged credential's code.
    #[error("the confirmation code does not match the enrollment page")]
    Mismatch,
    /// The ceremony deadline passed before the code was confirmed.
    #[error("the enrollment ceremony expired before the code was confirmed")]
    Expired,
    /// The confirmed enrollment was requested for another purpose than the
    /// ceremony enrolled it for.
    #[error("The enrollment purpose does not match the requested export.")]
    WrongPurpose,
    /// The verified registration has no mainnet policy form.
    #[error("The enrolled credential is not a valid mainnet approval credential.")]
    CredentialInvalid,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use std::time::Duration;

    use super::super::registration::{RegistrationChallenge, verify_operator_registration};
    use super::super::test_support::SoftwareRegistrar;
    use super::*;

    /// The fixed vector the browser test in `app_shared.test.mjs` shares:
    /// challenge `0x00..=0x1f`, credential ID sixteen `0xa5` bytes, key
    /// `0x04` followed by `0x01..=0x40`.
    fn vector() -> ([u8; 32], Vec<u8>, [u8; 65]) {
        let mut challenge = [0u8; 32];
        for (index, byte) in challenge.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        let mut key = [0u8; 65];
        key[0] = 0x04;
        for (index, byte) in key.iter_mut().enumerate().skip(1) {
            *byte = u8::try_from(index).unwrap();
        }
        (challenge, vec![0xa5; 16], key)
    }

    #[test]
    fn confirmation_code_vectors_match_browser() {
        let (challenge, id, key) = vector();
        assert_eq!(
            operator_enrollment_confirmation_code(&challenge, &id, &key),
            "305b-4244-62ef-fd53"
        );
        let mut other_challenge = challenge;
        other_challenge[0] ^= 1;
        assert_eq!(
            operator_enrollment_confirmation_code(&other_challenge, &id, &key),
            "641f-fb30-29a4-176c"
        );
        let mut other_id = id.clone();
        other_id[0] ^= 1;
        assert_eq!(
            operator_enrollment_confirmation_code(&challenge, &other_id, &key),
            "852e-a601-133f-7a16"
        );
        let mut other_key = key;
        other_key[64] ^= 1;
        assert_eq!(
            operator_enrollment_confirmation_code(&challenge, &id, &other_key),
            "edb8-5c46-9d41-ab10"
        );
        assert_eq!(
            operator_enrollment_confirmation_code(&challenge, &[0xa5; 32], &key),
            "b449-2171-5701-0e67"
        );
    }

    /// The mainnet approval vectors the browser test in
    /// `app_shared.test.mjs` shares: the same inputs under the mainnet
    /// domain give other codes than the operator domain.
    #[test]
    fn mainnet_confirmation_code_vectors_match_browser() {
        let (challenge, id, key) = vector();
        let code = |challenge: &[u8; 32], id: &[u8], key: &[u8; 65]| {
            enrollment_confirmation_code(EnrollmentPurpose::MainnetApproval, challenge, id, key)
        };
        assert_eq!(code(&challenge, &id, &key), "415b-db8a-ac00-4222");
        assert_ne!(
            code(&challenge, &id, &key),
            operator_enrollment_confirmation_code(&challenge, &id, &key)
        );
        let mut other_challenge = challenge;
        other_challenge[0] ^= 1;
        assert_eq!(code(&other_challenge, &id, &key), "67f8-9765-fe91-7daf");
        let mut other_id = id.clone();
        other_id[0] ^= 1;
        assert_eq!(code(&challenge, &other_id, &key), "b965-512c-4df9-c87d");
        let mut other_key = key;
        other_key[64] ^= 1;
        assert_eq!(code(&challenge, &id, &other_key), "504b-3195-bc18-cf46");
        assert_eq!(code(&challenge, &[0xa5; 32], &key), "1c3b-c8a8-faf5-58cb");
    }

    fn pending(deadline: Instant) -> (PendingOperatorEnrollment, String, SoftwareRegistrar) {
        pending_for(EnrollmentPurpose::RemoteOperator, deadline)
    }

    fn pending_for(
        purpose: EnrollmentPurpose,
        deadline: Instant,
    ) -> (PendingOperatorEnrollment, String, SoftwareRegistrar) {
        let registrar = SoftwareRegistrar::new([0x11; 32], vec![0xa5; 16]);
        let challenge =
            RegistrationChallenge::from_parts([0x42; 32], Instant::now() + Duration::from_secs(60));
        let request = registrar
            .builder(challenge.bytes(), "http://localhost:9999")
            .sign_count(9)
            .request();
        let verified = verify_operator_registration(
            &request,
            &challenge,
            "http://localhost:9999",
            Instant::now(),
        )
        .unwrap();
        let code = enrollment_confirmation_code(
            purpose,
            challenge.bytes(),
            verified.credential_id(),
            verified.public_key_sec1(),
        );
        let staged = StagedEnrollment::new(verified, challenge.bytes(), purpose);
        (staged.with_deadline(deadline), code, registrar)
    }

    #[test]
    fn only_the_matching_code_before_the_deadline_persists_the_exact_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("operator.toml"));
        let now = Instant::now();
        let deadline = now + Duration::from_secs(30);

        let (wrong, code, _) = pending(deadline);
        let mut other = code.clone().into_bytes();
        other[0] = if other[0] == b'0' { b'1' } else { b'0' };
        assert_eq!(
            wrong
                .confirm(std::str::from_utf8(&other).unwrap(), now)
                .unwrap_err(),
            OperatorEnrollmentConfirmationError::Mismatch
        );
        let (malformed, _, _) = pending(deadline);
        assert_eq!(
            malformed.confirm("not a code", now).unwrap_err(),
            OperatorEnrollmentConfirmationError::Mismatch
        );
        let (late, code, _) = pending(deadline);
        assert_eq!(
            late.confirm(&code, deadline).unwrap_err(),
            OperatorEnrollmentConfirmationError::Expired
        );
        assert!(store.list().unwrap().is_empty());

        let (staged, code, registrar) = pending(deadline);
        assert_eq!(staged.label(), "laptop");
        assert_eq!(format!("{staged:?}"), "PendingOperatorEnrollment { .. }");
        let confirmed = staged
            .confirm(&code.to_uppercase(), deadline - Duration::from_millis(1))
            .unwrap();
        let persisted = confirmed.persist(&store).unwrap();
        assert_eq!(store.list().unwrap(), vec![persisted.clone()]);
        assert_eq!(
            persisted.credential_id_b64url,
            registrar.credential_id_b64url()
        );
        assert_eq!(
            persisted.public_key_sec1_b64,
            URL_SAFE_NO_PAD.encode(registrar.public_key_sec1())
        );
        assert_eq!(persisted.rp_id, "localhost");
        assert_eq!(persisted.label, "laptop");
        assert_eq!(persisted.sign_count, Some(9));

        let (again, code, _) = pending(deadline);
        assert!(matches!(
            again.confirm(&code, now).unwrap().persist(&store),
            Err(ApprovalError::DuplicateCredentialId { .. })
        ));
        assert_eq!(store.list().unwrap().len(), 1);
    }

    /// A code of one purpose never confirms a ceremony of the other; a
    /// confirmed mainnet approval credential is exported and never
    /// persisted, and a confirmed operator credential is never exported.
    #[test]
    fn export_and_persist_follow_the_purpose() {
        let dir = tempfile::tempdir().unwrap();
        let store = OperatorApprovalCredentialStore::new(dir.path().join("operator.toml"));
        let now = Instant::now();
        let deadline = now + Duration::from_secs(30);

        let (remote, remote_code, _) = pending_for(EnrollmentPurpose::RemoteOperator, deadline);
        let (mainnet, mainnet_code, _) = pending_for(EnrollmentPurpose::MainnetApproval, deadline);
        assert_ne!(remote_code, mainnet_code);
        assert_eq!(
            mainnet.confirm(&remote_code, now).unwrap_err(),
            OperatorEnrollmentConfirmationError::Mismatch
        );
        assert_eq!(
            remote.confirm(&mainnet_code, now).unwrap_err(),
            OperatorEnrollmentConfirmationError::Mismatch
        );

        let (remote, code, _) = pending_for(EnrollmentPurpose::RemoteOperator, deadline);
        assert_eq!(remote.purpose(), EnrollmentPurpose::RemoteOperator);
        assert_eq!(
            remote
                .confirm(&code, now)
                .unwrap()
                .into_mainnet_policy_credential()
                .unwrap_err(),
            OperatorEnrollmentConfirmationError::WrongPurpose
        );
        assert_eq!(
            OperatorEnrollmentConfirmationError::WrongPurpose.to_string(),
            "The enrollment purpose does not match the requested export."
        );

        let (mainnet, code, registrar) = pending_for(EnrollmentPurpose::MainnetApproval, deadline);
        assert_eq!(mainnet.purpose(), EnrollmentPurpose::MainnetApproval);
        let confirmed = mainnet.confirm(&code, now).unwrap();
        let ApprovalError::Invalid { reason } = confirmed.persist(&store).unwrap_err() else {
            panic!("a mainnet approval credential is never stored");
        };
        assert_eq!(reason, WRONG_PURPOSE_MESSAGE);
        assert!(store.list().unwrap().is_empty());

        let (mainnet, code, _) = pending_for(EnrollmentPurpose::MainnetApproval, deadline);
        let exported = mainnet
            .confirm(&code, now)
            .unwrap()
            .into_mainnet_policy_credential()
            .unwrap();
        assert_eq!(exported.credential_id(), registrar.credential_id());
        assert_eq!(exported.public_key_sec1(), &registrar.public_key_sec1());
        assert!(store.list().unwrap().is_empty());
    }
}
