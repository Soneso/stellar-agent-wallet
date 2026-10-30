//! Verification of a WebAuthn registration response against the challenge,
//! origin and relying party its caller issued, and the confirmation code
//! that binds a verified credential to the person at the terminal.
//!
//! A registration page runs `navigator.credentials.create()` over a 32-byte
//! challenge its server issued and posts the credential ID, the uncompressed
//! SEC1 public key, and the authenticator's `clientDataJSON` and
//! `attestationObject`. [`verify_registration_response`] accepts the response
//! only when:
//!
//! - the credential ID is [`CREDENTIAL_ID_MIN_BYTES`] to
//!   [`CREDENTIAL_ID_MAX_BYTES`] bytes and the key is a 65-byte uncompressed
//!   SEC1 point on P-256;
//! - `clientDataJSON` is at most [`MAX_CLIENT_DATA_JSON_BYTES`] bytes, a
//!   JSON object whose `type` is `webauthn.create`, whose `challenge` is the
//!   caller's challenge (compared in constant time), whose `origin` is
//!   exactly the caller's origin, which carries no `topOrigin` member at all,
//!   and whose `crossOrigin` member is absent or `false`;
//! - `attestationObject` is at most [`MAX_ATTESTATION_OBJECT_BYTES`] bytes,
//!   a CBOR map of exactly `fmt`, `attStmt` and `authData`, with
//!   `fmt = "none"` and an empty `attStmt`;
//! - `authData` names the SHA-256 of the caller's relying-party ID as its RP
//!   ID hash, sets the user-present, user-verified and
//!   attested-credential-data flags, never sets backup state without backup
//!   eligibility, carries the posted credential ID, and a COSE EC2 key on
//!   P-256 for ES256 whose point is on the curve and equals the posted SEC1
//!   key; an extension map is accepted only when its flag is set, and nothing
//!   may follow it.
//!
//! # What the verification establishes
//!
//! The `none` attestation format carries no statement about the
//! authenticator, so a verified response is not evidence of certified
//! hardware, and it does not prove possession of the private key: the
//! response is self-asserted by whoever ran the ceremony. It establishes that
//! the response was produced for the caller's challenge, at the caller's
//! origin, for the caller's relying party, with user verification, and that
//! the posted credential ID and key are the ones the authenticator data
//! names. The caller's [`ConfirmationCode`] is what binds the credential to
//! the person at the terminal: the page computes the code from the
//! credential its own ceremony created, and the terminal accepts the
//! credential only when the code typed there is the code of the credential
//! the server holds.
//!
//! # Bounded decoding
//!
//! Both encoded fields are capped before base64 decoding and again after.
//! The CBOR decoder accepts only definite-length items with minimal-length
//! arguments, no tags, no floating-point or undefined values, no duplicate
//! map keys, a bounded nesting depth and item count, and no trailing bytes.
//! It imposes no order on map keys.

mod cbor;

use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use self::cbor::{Cbor, decode_complete, decode_prefix};
use super::webauthn::{FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV};

pub use super::registration_input::{
    CREDENTIAL_ID_MAX_BYTES, CREDENTIAL_ID_MIN_BYTES, PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN,
};

/// The COSE algorithm a registration ceremony requests and the verifier
/// accepts: ES256.
pub const COSE_ALG_ES256: i64 = -7;

/// Maximum decoded `clientDataJSON` size in bytes.
pub const MAX_CLIENT_DATA_JSON_BYTES: usize = 1024;

/// Maximum decoded `attestationObject` size in bytes.
pub const MAX_ATTESTATION_OBJECT_BYTES: usize = 2048;

/// Domain separator of the confirmation code a passkey registration page
/// shows. It differs from every enrollment domain, so a code of one ceremony
/// never confirms another.
pub const PASSKEY_REGISTRATION_CODE_DOMAIN: &[u8] =
    b"stellar-agent-passkey-registration-confirmation:v1";

/// Fixed-length prefix of `authenticatorData` before the credential ID:
/// RP ID hash (32), flags (1), counter (4), AAGUID (16), ID length (2).
const AUTH_DATA_FIXED_LEN: usize = 32 + 1 + 4 + 16 + 2;

/// Number of hexadecimal characters in a confirmation code.
const CONFIRMATION_CODE_HEX_LEN: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
// Encodings
// ─────────────────────────────────────────────────────────────────────────────

/// Decodes canonical unpadded base64url of 1 to `max` bytes.
///
/// An encoding longer than `max` bytes can need is refused before it is
/// decoded, the empty string is refused, and the decoded bytes must encode
/// back to exactly `text`, so one byte string has one accepted text form.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::webauthn_registration::decode_b64url_capped;
///
/// assert_eq!(decode_b64url_capped("AQI", 2), Some(vec![1, 2]));
/// assert_eq!(decode_b64url_capped("AQI", 1), None);
/// assert_eq!(decode_b64url_capped("AQI=", 2), None);
/// assert_eq!(decode_b64url_capped("", 2), None);
/// ```
#[must_use]
pub fn decode_b64url_capped(text: &str, max: usize) -> Option<Vec<u8>> {
    super::presence::decode_canonical_b64url(text, 1, max)
}

/// `bytes` as an uncompressed SEC1 point on P-256, or `None` when it is not
/// 65 bytes, does not start with `0x04`, or is not on the curve.
pub(crate) fn uncompressed_p256_point(
    bytes: &[u8],
) -> Option<[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN]> {
    let key: [u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN] = bytes.try_into().ok()?;
    (key[0] == 0x04 && p256::PublicKey::from_sec1_bytes(&key).is_ok()).then_some(key)
}

// ─────────────────────────────────────────────────────────────────────────────
// Response, expectation and verified registration
// ─────────────────────────────────────────────────────────────────────────────

/// The decoded fields of a registration response, as the page posted them.
///
/// `Debug` shows only the field lengths.
#[derive(Clone, Copy)]
pub struct RegistrationResponse<'a> {
    /// The raw credential ID the page posted.
    pub credential_id: &'a [u8],
    /// The uncompressed SEC1 public key the page posted.
    pub public_key_sec1: &'a [u8],
    /// The raw `clientDataJSON` bytes.
    pub client_data_json: &'a [u8],
    /// The raw CBOR `attestationObject` bytes.
    pub attestation_object: &'a [u8],
}

impl std::fmt::Debug for RegistrationResponse<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationResponse")
            .field("credential_id_len", &self.credential_id.len())
            .field("public_key_sec1_len", &self.public_key_sec1.len())
            .field("client_data_json_len", &self.client_data_json.len())
            .field("attestation_object_len", &self.attestation_object.len())
            .finish()
    }
}

/// What the caller issued the registration ceremony for.
///
/// `Debug` omits the challenge.
#[derive(Clone, Copy)]
pub struct RegistrationExpectation<'a> {
    /// The 32-byte challenge the page passed to `navigator.credentials.create()`.
    pub challenge: &'a [u8; 32],
    /// The exact origin the page was served from, such as
    /// `http://localhost:8080`.
    pub origin: &'a str,
    /// The relying-party ID the credential is bound to, such as `localhost`.
    pub rp_id: &'a str,
}

impl std::fmt::Debug for RegistrationExpectation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationExpectation")
            .field("origin", &self.origin)
            .field("rp_id", &self.rp_id)
            .finish_non_exhaustive()
    }
}

/// A registration response that passed [`verify_registration_response`].
///
/// Only the verifier constructs one; `Debug` shows nothing of it.
pub struct VerifiedRegistration {
    credential_id: Vec<u8>,
    public_key_sec1: [u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN],
    sign_count: u32,
}

impl VerifiedRegistration {
    /// The raw credential ID the authenticator data names.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The uncompressed SEC1 public key the authenticator data names.
    #[must_use]
    pub fn public_key_sec1(&self) -> &[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN] {
        &self.public_key_sec1
    }

    /// The signature counter the authenticator data carried.
    #[must_use]
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }
}

impl std::fmt::Debug for VerifiedRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedRegistration")
            .finish_non_exhaustive()
    }
}

/// Why a registration response was not accepted.
///
/// One value for every rule, so a caller cannot tell an attacker which rule
/// the response broke.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationVerifyError {
    /// The response does not satisfy the verification rules.
    Invalid,
}

impl std::fmt::Display for RegistrationVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the registration response does not verify")
    }
}

impl std::error::Error for RegistrationVerifyError {}

/// Verifies `response` as the answer to the ceremony `expected` describes.
///
/// Applies every rule of the module documentation, in this order: the
/// credential ID bounds and the posted key, the sizes of the client data and
/// the attestation object, the client data, the attestation object and its
/// authenticator data under `expected.rp_id`, and the equality of the
/// attested credential ID and key with the posted ones.
///
/// # Errors
///
/// [`RegistrationVerifyError::Invalid`] for any rule the response breaks.
pub fn verify_registration_response(
    response: &RegistrationResponse<'_>,
    expected: &RegistrationExpectation<'_>,
) -> Result<VerifiedRegistration, RegistrationVerifyError> {
    use RegistrationVerifyError::Invalid;

    if !(CREDENTIAL_ID_MIN_BYTES..=CREDENTIAL_ID_MAX_BYTES).contains(&response.credential_id.len())
    {
        return Err(Invalid);
    }
    let public_key_sec1 = uncompressed_p256_point(response.public_key_sec1).ok_or(Invalid)?;
    if response.client_data_json.len() > MAX_CLIENT_DATA_JSON_BYTES
        || response.attestation_object.len() > MAX_ATTESTATION_OBJECT_BYTES
    {
        return Err(Invalid);
    }

    verify_client_data(
        response.client_data_json,
        expected.challenge,
        expected.origin,
    )?;

    let attested = parse_attestation_object(response.attestation_object, expected.rp_id)?;
    if attested.credential_id != response.credential_id {
        return Err(Invalid);
    }
    if attested.public_key_sec1 != public_key_sec1 {
        return Err(Invalid);
    }

    Ok(VerifiedRegistration {
        credential_id: response.credential_id.to_vec(),
        public_key_sec1,
        sign_count: attested.sign_count,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// clientDataJSON
// ─────────────────────────────────────────────────────────────────────────────

/// The `CollectedClientData` members the verifier reads. Other members are
/// ignored, as WebAuthn requires; a member that appears twice refuses.
///
/// `crossOrigin` and `topOrigin` are `None` only when the member is absent:
/// an explicit JSON `null` is a present member, so `crossOrigin: null`
/// refuses as a non-boolean and `topOrigin: null` refuses as present.
#[derive(Deserialize)]
struct CollectedClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    #[serde(flatten)]
    security: super::webauthn::ClientDataOrigin,
}

fn verify_client_data(
    client_data_json: &[u8],
    challenge: &[u8; 32],
    expected_origin: &str,
) -> Result<(), RegistrationVerifyError> {
    use RegistrationVerifyError::Invalid;

    let client_data: CollectedClientData =
        serde_json::from_slice(client_data_json).map_err(|_| Invalid)?;
    if client_data.kind != "webauthn.create" {
        return Err(Invalid);
    }
    let submitted = decode_b64url_capped(&client_data.challenge, 32).ok_or(Invalid)?;
    if submitted.len() != 32 || !bool::from(submitted.ct_eq(challenge)) {
        return Err(Invalid);
    }
    if !client_data.security.matches(expected_origin) {
        return Err(Invalid);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// attestationObject and authenticatorData
// ─────────────────────────────────────────────────────────────────────────────

/// What the attestation object's authenticator data attests.
struct AttestedCredential<'a> {
    credential_id: &'a [u8],
    public_key_sec1: [u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN],
    sign_count: u32,
}

fn parse_attestation_object<'a>(
    attestation_object: &'a [u8],
    rp_id: &str,
) -> Result<AttestedCredential<'a>, RegistrationVerifyError> {
    use RegistrationVerifyError::Invalid;

    let Cbor::Map(entries) = decode_complete(attestation_object).map_err(|_| Invalid)? else {
        return Err(Invalid);
    };
    if entries.len() != 3 {
        return Err(Invalid);
    }
    let (mut fmt, mut att_stmt, mut auth_data) = (None, None, None);
    for (key, value) in entries {
        match key {
            Cbor::Text("fmt") => fmt = Some(value),
            Cbor::Text("attStmt") => att_stmt = Some(value),
            Cbor::Text("authData") => auth_data = Some(value),
            _ => return Err(Invalid),
        }
    }
    if !matches!(fmt, Some(Cbor::Text("none"))) {
        return Err(Invalid);
    }
    if !matches!(att_stmt, Some(Cbor::Map(ref stmt)) if stmt.is_empty()) {
        return Err(Invalid);
    }
    let Some(Cbor::Bytes(auth_data)) = auth_data else {
        return Err(Invalid);
    };
    parse_auth_data(auth_data, rp_id)
}

fn parse_auth_data<'a>(
    auth_data: &'a [u8],
    rp_id: &str,
) -> Result<AttestedCredential<'a>, RegistrationVerifyError> {
    use RegistrationVerifyError::Invalid;

    if auth_data.len() < AUTH_DATA_FIXED_LEN {
        return Err(Invalid);
    }
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    if auth_data[..32] != rp_id_hash[..] {
        return Err(Invalid);
    }
    let flags = auth_data[32];
    for required in [FLAG_UP, FLAG_UV, FLAG_AT] {
        if flags & required == 0 {
            return Err(Invalid);
        }
    }
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(Invalid);
    }
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    if !(CREDENTIAL_ID_MIN_BYTES..=CREDENTIAL_ID_MAX_BYTES).contains(&id_len) {
        return Err(Invalid);
    }
    let rest = &auth_data[AUTH_DATA_FIXED_LEN..];
    if rest.len() < id_len {
        return Err(Invalid);
    }
    let (credential_id, rest) = rest.split_at(id_len);
    let (cose_key, used) = decode_prefix(rest).map_err(|_| Invalid)?;
    let public_key_sec1 = parse_cose_es256(&cose_key)?;
    let rest = &rest[used..];
    if flags & FLAG_ED != 0 {
        if !matches!(decode_complete(rest), Ok(Cbor::Map(_))) {
            return Err(Invalid);
        }
    } else if !rest.is_empty() {
        return Err(Invalid);
    }
    Ok(AttestedCredential {
        credential_id,
        public_key_sec1,
        sign_count,
    })
}

/// Reads a COSE_Key of exactly the five labels an ES256 EC2 key on P-256
/// has, and returns its point in uncompressed SEC1 form once it is on the
/// curve.
fn parse_cose_es256(
    key: &Cbor<'_>,
) -> Result<[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN], RegistrationVerifyError> {
    use RegistrationVerifyError::Invalid;

    let Cbor::Map(entries) = key else {
        return Err(Invalid);
    };
    if entries.len() != 5 {
        return Err(Invalid);
    }
    let (mut kty, mut alg, mut crv, mut x, mut y) = (false, false, false, None, None);
    for (label, value) in entries {
        match (label.as_integer(), value) {
            (Some(1), value) => kty = value.as_integer() == Some(2),
            (Some(3), value) => alg = value.as_integer() == Some(COSE_ALG_ES256),
            (Some(-1), value) => crv = value.as_integer() == Some(1),
            (Some(-2), Cbor::Bytes(bytes)) if bytes.len() == 32 => x = Some(*bytes),
            (Some(-3), Cbor::Bytes(bytes)) if bytes.len() == 32 => y = Some(*bytes),
            _ => return Err(Invalid),
        }
    }
    let (true, true, true, Some(x), Some(y)) = (kty, alg, crv, x, y) else {
        return Err(Invalid);
    };
    let mut sec1 = [0u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(x);
    sec1[33..].copy_from_slice(y);
    uncompressed_p256_point(&sec1).ok_or(Invalid)
}

// ─────────────────────────────────────────────────────────────────────────────
// Confirmation code
// ─────────────────────────────────────────────────────────────────────────────

/// The confirmation code a registration page shows for the credential its
/// own ceremony created.
///
/// The code is the first 16 lowercase hexadecimal characters of SHA-256 over
/// the domain, the 32-byte challenge, the credential ID's length as a
/// big-endian `u32` followed by the ID, and the 65-byte SEC1 public key. The
/// page shows it as four groups of four separated by `-`. A server holding a
/// verified credential computes the same code from that credential; the code
/// the person types at the terminal matches only when the server's
/// credential is the one the page created.
///
/// `Debug` shows nothing of the digits; there is no `Display` and no serde,
/// so the expected code never reaches a log or a file.
pub struct ConfirmationCode {
    digits: [u8; CONFIRMATION_CODE_HEX_LEN],
}

impl ConfirmationCode {
    /// The code of `credential_id` and `public_key_sec1`, registered over
    /// `challenge`, under `domain`.
    #[must_use]
    pub fn compute(
        domain: &[u8],
        challenge: &[u8; 32],
        credential_id: &[u8],
        public_key_sec1: &[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(challenge);
        let id_len = u32::try_from(credential_id.len()).unwrap_or(u32::MAX);
        hasher.update(id_len.to_be_bytes());
        hasher.update(credential_id);
        hasher.update(public_key_sec1);
        let digest = hasher.finalize();
        let mut digits = [0u8; CONFIRMATION_CODE_HEX_LEN];
        digits.copy_from_slice(
            crate::hex::encode(&digest[..CONFIRMATION_CODE_HEX_LEN / 2]).as_bytes(),
        );
        Self { digits }
    }

    /// Whether `typed` is this code.
    ///
    /// Surrounding whitespace is dropped, `-` and space separators are
    /// removed, and ASCII letters are lowercased; anything that is not then
    /// exactly 16 hexadecimal digits does not match. The comparison of the
    /// digits runs in constant time.
    #[must_use]
    pub fn matches(&self, typed: &str) -> bool {
        normalize_submitted_code(typed)
            .is_some_and(|submitted| bool::from(submitted.ct_eq(&self.digits)))
    }

    /// The code in the form the page shows, `xxxx-xxxx-xxxx-xxxx`. The
    /// server compares only the digits, so this form exists for the tests
    /// and the test support that play the page's part.
    #[cfg(any(test, feature = "test-helpers"))]
    #[must_use]
    pub fn display(&self) -> String {
        let mut display = String::with_capacity(CONFIRMATION_CODE_HEX_LEN + 3);
        for (index, digit) in self.digits.iter().enumerate() {
            if index > 0 && index % 4 == 0 {
                display.push('-');
            }
            display.push(char::from(*digit));
        }
        display
    }
}

impl std::fmt::Debug for ConfirmationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfirmationCode").finish_non_exhaustive()
    }
}

/// Normalizes a typed code: surrounding whitespace is dropped, `-` and space
/// separators are removed, and ASCII letters are lowercased. Anything that
/// is not then exactly 16 hexadecimal digits is malformed.
fn normalize_submitted_code(typed: &str) -> Option<[u8; CONFIRMATION_CODE_HEX_LEN]> {
    let mut digits = [0u8; CONFIRMATION_CODE_HEX_LEN];
    let mut count = 0;
    for byte in typed.trim().bytes() {
        if byte == b'-' || byte == b' ' {
            continue;
        }
        if !byte.is_ascii_hexdigit() || count == CONFIRMATION_CODE_HEX_LEN {
            return None;
        }
        digits[count] = byte.to_ascii_lowercase();
        count += 1;
    }
    (count == CONFIRMATION_CODE_HEX_LEN).then_some(digits)
}

#[cfg(test)]
mod tests;
