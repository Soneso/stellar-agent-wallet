//! Verification of the WebAuthn registration response the enrollment page
//! posts, against the challenge this server issued.
//!
//! The page asks `POST /enroll/challenge` for a fresh 32-byte challenge, runs
//! `navigator.credentials.create()` over it, and posts the credential ID, the
//! uncompressed SEC1 public key, the label, and the authenticator's
//! `clientDataJSON` and `attestationObject`. [`verify_operator_registration`]
//! accepts the response only when the challenge has not expired, the label
//! passes [`normalized_label`], and the response verifies under
//! [`verify_registration_response`] with the issued challenge, the origin
//! `http://localhost:<bound port>` and the relying-party ID
//! [`REGISTRATION_RP_ID`]. The verifier's module documentation lists every
//! rule it applies and states what a verified `none` registration does and
//! does not establish; the operator's terminal confirmation (see
//! [`super::PendingOperatorEnrollment::confirm`]) is what binds the
//! credential to the operator.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;

use stellar_agent_core::approval::webauthn_registration::{
    CREDENTIAL_ID_MAX_BYTES, MAX_ATTESTATION_OBJECT_BYTES, MAX_CLIENT_DATA_JSON_BYTES,
    PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN, RegistrationExpectation, RegistrationResponse,
    decode_b64url_capped, verify_registration_response,
};

/// The relying-party ID every credential this server registers is bound to.
pub(crate) const REGISTRATION_RP_ID: &str = "localhost";

/// How long an issued challenge stays acceptable, on the session clock.
pub(crate) const REGISTRATION_CHALLENGE_TTL: Duration = Duration::from_secs(300);

/// Maximum accepted trimmed label length in bytes, matching the page's
/// `maxlength="64"` input attribute.
pub(crate) const MAX_LABEL_BYTES: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Challenge
// ─────────────────────────────────────────────────────────────────────────────

/// A single-use registration challenge this server issued.
///
/// The bytes come from the OS CSPRNG and never repeat across ceremonies.
/// `expires_at` is on the session clock of the server's `AuthState`.
pub(crate) struct RegistrationChallenge {
    bytes: [u8; 32],
    expires_at: Instant,
}

impl RegistrationChallenge {
    /// A fresh challenge acceptable until `now + REGISTRATION_CHALLENGE_TTL`.
    pub(crate) fn generate(now: Instant) -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self::from_parts(bytes, now + REGISTRATION_CHALLENGE_TTL)
    }

    /// A challenge with the given bytes and expiry.
    pub(crate) fn from_parts(bytes: [u8; 32], expires_at: Instant) -> Self {
        Self { bytes, expires_at }
    }

    /// The challenge bytes.
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// The challenge in the unpadded base64url form `clientDataJSON` carries.
    pub(crate) fn to_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.bytes)
    }

    /// Whether the challenge has expired at `now`.
    pub(crate) fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// The time left before the challenge expires, zero once it has.
    pub(crate) fn remaining(&self, now: Instant) -> Duration {
        self.expires_at.saturating_duration_since(now)
    }
}

impl std::fmt::Debug for RegistrationChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationChallenge")
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Request and verified registration
// ─────────────────────────────────────────────────────────────────────────────

/// Wire payload for `POST /enroll/credential`.
///
/// Unknown fields refuse, so a client cannot supply a value the server
/// derives itself, such as the signature counter. `Debug` is deliberately
/// not derived: the payload carries a credential ID and a public key, and
/// this crate's tracing layer must never be able to echo either.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollCredentialRequest {
    /// Base64url (no padding) WebAuthn credential ID.
    pub(crate) credential_id_b64url: String,
    /// Base64url (no padding) uncompressed SEC1 P-256 public key.
    pub(crate) public_key_sec1_b64: String,
    /// Operator-chosen label, read from the page's label input.
    pub(crate) label: String,
    /// Base64url (no padding) `clientDataJSON` the authenticator signed over.
    pub(crate) client_data_json: String,
    /// Base64url (no padding) CBOR `attestationObject`.
    pub(crate) attestation_object: String,
}

/// A registration response that passed [`verify_operator_registration`].
///
/// Holds the canonical credential ID, the SEC1 key, the trimmed label, and
/// the signature counter from the authenticator data. Only the verifier
/// constructs one; `Debug` redacts every field.
pub(crate) struct VerifiedOperatorRegistration {
    credential_id_b64url: String,
    credential_id: Vec<u8>,
    public_key_sec1: [u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN],
    label: String,
    sign_count: u32,
}

impl VerifiedOperatorRegistration {
    /// The canonical base64url credential ID.
    pub(crate) fn credential_id_b64url(&self) -> &str {
        &self.credential_id_b64url
    }

    /// The raw credential ID bytes.
    pub(crate) fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The uncompressed SEC1 public key.
    pub(crate) fn public_key_sec1(&self) -> &[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN] {
        &self.public_key_sec1
    }

    /// The operator label as [`normalized_label`] returns it.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// The signature counter the authenticator data carried.
    pub(crate) fn sign_count(&self) -> u32 {
        self.sign_count
    }
}

impl std::fmt::Debug for VerifiedOperatorRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedOperatorRegistration")
            .finish_non_exhaustive()
    }
}

/// Why a registration response was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorRegistrationError {
    /// The response does not satisfy the verification rules.
    Invalid,
    /// The challenge it answers expired.
    Expired,
    /// The ceremony already accepted a registration.
    AlreadyCompleted,
}

/// Verifies `request` as the response to `challenge`, produced at
/// `expected_origin`, at `now` on the session clock.
///
/// `request.label` must pass [`normalized_label`], which also trims it; the route
/// checks it first so that it can answer `label_invalid`.
///
/// # Errors
///
/// - [`OperatorRegistrationError::Expired`] when `challenge` expired at
///   `now`.
/// - [`OperatorRegistrationError::Invalid`] for any rule of
///   [`verify_registration_response`] that the response breaks, or a field
///   that is not canonical unpadded base64url within its cap.
pub(crate) fn verify_operator_registration(
    request: &EnrollCredentialRequest,
    challenge: &RegistrationChallenge,
    expected_origin: &str,
    now: Instant,
) -> Result<VerifiedOperatorRegistration, OperatorRegistrationError> {
    use OperatorRegistrationError::Invalid;

    if challenge.is_expired(now) {
        return Err(OperatorRegistrationError::Expired);
    }
    let label = normalized_label(&request.label).ok_or(Invalid)?;
    let credential_id =
        decode_b64url_capped(&request.credential_id_b64url, CREDENTIAL_ID_MAX_BYTES)
            .ok_or(Invalid)?;
    let public_key_sec1 = decode_b64url_capped(
        &request.public_key_sec1_b64,
        PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN,
    )
    .ok_or(Invalid)?;
    let client_data_json =
        decode_b64url_capped(&request.client_data_json, MAX_CLIENT_DATA_JSON_BYTES)
            .ok_or(Invalid)?;
    let attestation_object =
        decode_b64url_capped(&request.attestation_object, MAX_ATTESTATION_OBJECT_BYTES)
            .ok_or(Invalid)?;

    let verified = verify_registration_response(
        &RegistrationResponse {
            credential_id: &credential_id,
            public_key_sec1: &public_key_sec1,
            client_data_json: &client_data_json,
            attestation_object: &attestation_object,
        },
        &RegistrationExpectation {
            challenge: challenge.bytes(),
            origin: expected_origin,
            rp_id: REGISTRATION_RP_ID,
        },
    )
    .map_err(|_| Invalid)?;

    Ok(VerifiedOperatorRegistration {
        credential_id_b64url: URL_SAFE_NO_PAD.encode(verified.credential_id()),
        credential_id: verified.credential_id().to_vec(),
        public_key_sec1: *verified.public_key_sec1(),
        label: label.to_owned(),
        sign_count: verified.sign_count(),
    })
}

/// The operator label `raw` stands for, or `None` when it is not acceptable.
///
/// `raw` is refused when it holds a control character anywhere, its ends
/// included. Only then is it trimmed, and the trimmed label must be 1 to
/// [`MAX_LABEL_BYTES`] bytes. Trimming therefore removes surrounding
/// whitespace that is not a control and never hides a control.
///
/// The label comes from the browser and the CLI shows it at the terminal
/// before the operator types the confirmation code, so C0 controls, DEL and
/// C1 controls ([`char::is_control`]) refuse: none of them can carry a
/// terminal escape sequence into that prompt.
pub(crate) fn normalized_label(raw: &str) -> Option<&str> {
    if raw.chars().any(char::is_control) {
        return None;
    }
    let label = raw.trim();
    (!label.is_empty() && label.len() <= MAX_LABEL_BYTES).then_some(label)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use sha2::{Digest as _, Sha256};
    use stellar_agent_core::approval::webauthn::{
        FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV,
    };

    use super::super::test_support::{
        CborWriter, RegistrationBuilder, SoftwareRegistrar, cose_es256_key,
    };
    use super::*;

    const ORIGIN: &str = "http://localhost:9999";

    fn challenge() -> RegistrationChallenge {
        RegistrationChallenge::from_parts([0x42; 32], Instant::now() + Duration::from_secs(60))
    }

    fn registrar() -> SoftwareRegistrar {
        SoftwareRegistrar::new([0x11; 32], vec![0xa5; 16])
    }

    fn verify(request: &EnrollCredentialRequest) -> Result<(), OperatorRegistrationError> {
        verify_operator_registration(request, &challenge(), ORIGIN, Instant::now()).map(|_| ())
    }

    fn valid() -> RegistrationBuilder {
        registrar().builder(challenge().bytes(), ORIGIN)
    }

    #[test]
    fn a_valid_none_registration_verifies_with_its_counter_and_trimmed_label() {
        let registrar = registrar();
        let mut request = registrar
            .builder(challenge().bytes(), ORIGIN)
            .sign_count(7)
            .request();
        request.label = "  laptop ".to_owned();
        let verified =
            verify_operator_registration(&request, &challenge(), ORIGIN, Instant::now()).unwrap();
        assert_eq!(verified.credential_id(), [0xa5; 16].as_slice());
        assert_eq!(
            verified.credential_id_b64url(),
            registrar.credential_id_b64url()
        );
        assert_eq!(verified.public_key_sec1(), &registrar.public_key_sec1());
        assert_eq!(verified.label(), "laptop");
        assert_eq!(verified.sign_count(), 7);
        assert!(!format!("{verified:?}").contains(&registrar.credential_id_b64url()));
    }

    /// A control at either end refuses although trimming would remove it,
    /// and one in the middle refuses as well; surrounding spaces trim.
    #[test]
    fn a_control_anywhere_in_the_label_refuses_before_trimming() {
        for control in ['\r', '\u{85}', '\u{1b}'] {
            for label in [
                format!("{control}laptop"),
                format!("lap{control}top"),
                format!("laptop{control}"),
            ] {
                let mut request = valid().request();
                request.label = label.clone();
                assert_eq!(
                    verify_operator_registration(&request, &challenge(), ORIGIN, Instant::now())
                        .unwrap_err(),
                    OperatorRegistrationError::Invalid,
                    "{label:?}"
                );
            }
        }
        let mut request = valid().request();
        request.label = " laptop ".to_owned();
        let verified =
            verify_operator_registration(&request, &challenge(), ORIGIN, Instant::now()).unwrap();
        assert_eq!(verified.label(), "laptop");
    }

    #[test]
    fn registration_validation_matrix() {
        let other_key = SoftwareRegistrar::new([0x22; 32], vec![0xa5; 16]);
        let mut off_curve = registrar().public_key_sec1();
        off_curve[64] ^= 0x01;
        let rp_hash_other: [u8; 32] = Sha256::digest(b"example.com").into();
        let cases: Vec<(&str, EnrollCredentialRequest)> = vec![
            ("type", valid().client_type("webauthn.get").request()),
            ("challenge", valid().challenge(&[0x43; 32]).request()),
            (
                "challenge encoding",
                valid()
                    .client_data_raw(format!(
                        r#"{{"type":"webauthn.create","challenge":"{}=","origin":"{ORIGIN}"}}"#,
                        URL_SAFE_NO_PAD.encode([0x42; 32])
                    ))
                    .request(),
            ),
            ("origin", valid().origin("http://localhost:9998").request()),
            ("origin ip", valid().origin("http://127.0.0.1:9999").request()),
            ("cross origin", valid().cross_origin(Some(true)).request()),
            (
                "cross origin null",
                valid()
                    .client_data_raw(format!(
                        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","crossOrigin":null}}"#,
                        URL_SAFE_NO_PAD.encode([0x42; 32])
                    ))
                    .request(),
            ),
            (
                "cross origin not boolean",
                valid()
                    .client_data_raw(format!(
                        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","crossOrigin":"false"}}"#,
                        URL_SAFE_NO_PAD.encode([0x42; 32])
                    ))
                    .request(),
            ),
            (
                "top origin null",
                valid()
                    .client_data_raw(format!(
                        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","topOrigin":null}}"#,
                        URL_SAFE_NO_PAD.encode([0x42; 32])
                    ))
                    .request(),
            ),
            (
                "label control character",
                {
                    let mut request = valid().request();
                    request.label = "laptop\u{1b}[2K".to_owned();
                    request
                },
            ),
            (
                "label c1 control",
                {
                    let mut request = valid().request();
                    request.label = "lap\u{85}top\u{9b}2J".to_owned();
                    request
                },
            ),
            (
                "label empty",
                {
                    let mut request = valid().request();
                    request.label = "  ".to_owned();
                    request
                },
            ),
            (
                "label oversized",
                {
                    let mut request = valid().request();
                    request.label = "x".repeat(MAX_LABEL_BYTES + 1);
                    request
                },
            ),
            (
                "top origin",
                valid()
                    .client_data_raw(format!(
                        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","topOrigin":"{ORIGIN}"}}"#,
                        URL_SAFE_NO_PAD.encode([0x42; 32])
                    ))
                    .request(),
            ),
            (
                "duplicate client data field",
                valid()
                    .client_data_raw(format!(
                        r#"{{"type":"webauthn.create","challenge":"{c}","challenge":"{c}","origin":"{ORIGIN}"}}"#,
                        c = URL_SAFE_NO_PAD.encode([0x42; 32])
                    ))
                    .request(),
            ),
            ("client data not json", valid().client_data_raw("not json".to_owned()).request()),
            ("rp id hash", valid().rp_id_hash(rp_hash_other).request()),
            ("user present", valid().flags(FLAG_UV | FLAG_AT).request()),
            ("user verified", valid().flags(FLAG_UP | FLAG_AT).request()),
            ("attested data flag", valid().flags(FLAG_UP | FLAG_UV).request()),
            (
                "backup state without eligibility",
                valid().flags(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BS).request(),
            ),
            ("credential id", valid().attested_credential_id(vec![0xa6; 16]).request()),
            (
                "posted credential id",
                {
                    let mut request = valid().request();
                    request.credential_id_b64url = URL_SAFE_NO_PAD.encode([0xa6; 16]);
                    request
                },
            ),
            (
                "cose algorithm",
                valid()
                    .cose_key(cose_es256_key(&registrar().public_key_sec1(), -8, 1))
                    .request(),
            ),
            (
                "cose curve",
                valid()
                    .cose_key(cose_es256_key(&registrar().public_key_sec1(), -7, 2))
                    .request(),
            ),
            (
                "cose extra label",
                valid()
                    .cose_key({
                        let key = registrar().public_key_sec1();
                        let mut w = CborWriter::default();
                        w.map(6);
                        w.int(1).int(2);
                        w.int(3).int(-7);
                        w.int(-1).int(1);
                        w.int(-2).bytes(&key[1..33]);
                        w.int(-3).bytes(&key[33..]);
                        w.int(4).bytes(&[1]);
                        w.finish()
                    })
                    .request(),
            ),
            (
                "invalid point",
                valid()
                    .cose_key(cose_es256_key(&off_curve, -7, 1))
                    .public_key(off_curve)
                    .request(),
            ),
            (
                "key mismatch",
                {
                    let mut request = valid().request();
                    request.public_key_sec1_b64 =
                        URL_SAFE_NO_PAD.encode(other_key.public_key_sec1());
                    request
                },
            ),
            ("attestation format", valid().format("packed").request()),
            (
                "attestation statement",
                valid()
                    .att_stmt({
                        let mut w = CborWriter::default();
                        w.map(1).text("alg").int(-7);
                        w.finish()
                    })
                    .request(),
            ),
            ("malformed cbor", valid().attestation_object_raw(vec![0xa3, 0x63]).request()),
            (
                "indefinite length",
                valid()
                    .attestation_object_raw({
                        let mut bytes = valid().attestation_object();
                        bytes[0] = 0xbf;
                        bytes.push(0xff);
                        bytes
                    })
                    .request(),
            ),
            (
                "non-minimal length",
                valid()
                    .attestation_object_raw({
                        let mut bytes = vec![0xb8, 0x03];
                        bytes.extend_from_slice(&valid().attestation_object()[1..]);
                        bytes
                    })
                    .request(),
            ),
            ("duplicate cbor key", valid().duplicate_fmt().request()),
            (
                "duplicate extension key",
                valid()
                    .flags(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED)
                    .auth_data_suffix({
                        let mut w = CborWriter::default();
                        w.map(2).text("a").int(1).text("a").int(2);
                        w.finish()
                    })
                    .request(),
            ),
            (
                "trailing attestation bytes",
                valid()
                    .attestation_object_raw({
                        let mut bytes = valid().attestation_object();
                        bytes.push(0x00);
                        bytes
                    })
                    .request(),
            ),
            ("trailing auth data", valid().auth_data_suffix(vec![0x00]).request()),
            (
                "extension without flag",
                valid()
                    .auth_data_suffix({
                        let mut w = CborWriter::default();
                        w.map(0);
                        w.finish()
                    })
                    .request(),
            ),
            (
                "extension flag without map",
                valid().flags(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED).request(),
            ),
            (
                "tagged item",
                valid()
                    .cose_key({
                        let mut bytes = vec![0xc2];
                        bytes.extend(cose_es256_key(&registrar().public_key_sec1(), -7, 1));
                        bytes
                    })
                    .request(),
            ),
            (
                // Well formed apart from its size: a flagged extension map
                // carries the padding, so only the cap refuses it.
                "oversized attestation object",
                valid()
                    .flags(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED)
                    .auth_data_suffix({
                        let mut w = CborWriter::default();
                        w.map(1)
                            .text("pad")
                            .bytes(&vec![0u8; MAX_ATTESTATION_OBJECT_BYTES]);
                        w.finish()
                    })
                    .request(),
            ),
            (
                "oversized client data",
                valid()
                    .client_data_raw(format!(
                        r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","pad":"{}"}}"#,
                        URL_SAFE_NO_PAD.encode([0x42; 32]),
                        "x".repeat(MAX_CLIENT_DATA_JSON_BYTES)
                    ))
                    .request(),
            ),
        ];
        assert_eq!(verify(&valid().request()), Ok(()));
        for (name, request) in cases {
            assert_eq!(
                verify(&request),
                Err(OperatorRegistrationError::Invalid),
                "{name}"
            );
        }
    }

    /// Accepted variants: browser-added client data members, an explicit
    /// `crossOrigin: false`, backup flags that agree, a flagged extension
    /// map, and a label with non-ASCII letters at the length limit.
    #[test]
    fn tolerated_registration_variants_verify() {
        let cases = [
            valid().cross_origin(Some(false)).request(),
            {
                let mut request = valid().request();
                request.label = format!("Büro {}", "x".repeat(MAX_LABEL_BYTES - 6));
                request
            },
            valid()
                .client_data_raw(format!(
                    r#"{{"type":"webauthn.create","challenge":"{}","origin":"{ORIGIN}","other_keys_can_be_added_here":"x"}}"#,
                    URL_SAFE_NO_PAD.encode([0x42; 32])
                ))
                .request(),
            valid().flags(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE | FLAG_BS).request(),
            valid().flags(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_BE).request(),
            valid()
                .flags(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED)
                .auth_data_suffix({
                    let mut w = CborWriter::default();
                    w.map(1).text("credProtect").int(2);
                    w.finish()
                })
                .request(),
        ];
        for (index, request) in cases.iter().enumerate() {
            assert_eq!(verify(request), Ok(()), "case {index}");
        }
    }

    #[test]
    fn an_expired_challenge_refuses_before_anything_else() {
        let challenge = challenge();
        let request = valid().request();
        let at_expiry = challenge.expires_at;
        assert!(
            verify_operator_registration(
                &request,
                &challenge,
                ORIGIN,
                at_expiry - Duration::from_millis(1)
            )
            .is_ok()
        );
        assert_eq!(
            verify_operator_registration(&request, &challenge, ORIGIN, at_expiry).unwrap_err(),
            OperatorRegistrationError::Expired
        );
        let mut garbage = valid().request();
        garbage.attestation_object = "!!".to_owned();
        assert_eq!(
            verify_operator_registration(&garbage, &challenge, ORIGIN, at_expiry).unwrap_err(),
            OperatorRegistrationError::Expired
        );
    }

    #[test]
    fn challenge_expiry_and_remaining_time_follow_the_clock() {
        let now = Instant::now();
        let challenge = RegistrationChallenge::generate(now);
        assert_eq!(challenge.remaining(now), REGISTRATION_CHALLENGE_TTL);
        assert!(!challenge.is_expired(now + REGISTRATION_CHALLENGE_TTL - Duration::from_millis(1)));
        assert!(challenge.is_expired(now + REGISTRATION_CHALLENGE_TTL));
        assert_eq!(
            challenge.remaining(now + REGISTRATION_CHALLENGE_TTL),
            Duration::ZERO
        );
        assert_ne!(
            RegistrationChallenge::generate(now).bytes(),
            RegistrationChallenge::generate(now).bytes()
        );
        assert_eq!(format!("{challenge:?}"), "RegistrationChallenge { .. }");
    }
}
