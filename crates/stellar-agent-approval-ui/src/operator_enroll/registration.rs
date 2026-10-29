//! Verification of the WebAuthn registration response the enrollment page
//! posts, against the challenge this server issued.
//!
//! The page asks `POST /enroll/challenge` for a fresh 32-byte challenge, runs
//! `navigator.credentials.create()` over it, and posts the credential ID, the
//! uncompressed SEC1 public key, the label, and the authenticator's
//! `clientDataJSON` and `attestationObject`. [`verify_operator_registration`]
//! accepts the response only when:
//!
//! - the label passes [`normalized_label`];
//! - `clientDataJSON` is a JSON object whose `type` is `webauthn.create`,
//!   whose `challenge` is the issued challenge, whose `origin` is exactly
//!   `http://localhost:<bound port>`, which carries no `topOrigin` member at
//!   all, and whose `crossOrigin` member is absent or `false`;
//! - `attestationObject` is a CBOR map of exactly `fmt`, `attStmt` and
//!   `authData`, with `fmt = "none"` and an empty `attStmt`;
//! - `authData` names the SHA-256 of `localhost` as its RP ID hash, sets the
//!   user-present, user-verified and attested-credential-data flags, carries
//!   the posted credential ID, and a COSE EC2 key on P-256 for ES256 whose
//!   point is on the curve and equals the posted SEC1 key; an extension map
//!   is accepted only when its flag is set, and nothing may follow it.
//!
//! # What the verification establishes
//!
//! The `none` attestation format carries no statement about the
//! authenticator, so a verified response is not evidence of certified
//! hardware, and it does not prove possession of the private key: the
//! response is self-asserted by whoever ran the ceremony. It establishes
//! that the response was produced for this server's challenge, at this
//! origin, for `localhost`, with user verification, and that the posted
//! credential ID and key are the ones the authenticator data names. The
//! operator's terminal confirmation (see
//! [`super::PendingOperatorEnrollment::confirm`]) is what binds the
//! credential to the operator.
//!
//! # Bounded decoding
//!
//! Both encoded fields are capped before base64 decoding and again after.
//! The CBOR decoder accepts only definite-length items with minimal-length
//! arguments, no tags, no floating-point or undefined values, no duplicate
//! map keys, a bounded nesting depth and item count, and no trailing bytes.
//! It imposes no order on map keys.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

/// The relying-party ID every credential this server registers is bound to.
pub(crate) const REGISTRATION_RP_ID: &str = "localhost";

/// How long an issued challenge stays acceptable, on the session clock.
pub(crate) const REGISTRATION_CHALLENGE_TTL: Duration = Duration::from_secs(300);

/// The COSE algorithm the ceremony requests and the verifier accepts: ES256.
pub(crate) const COSE_ALG_ES256: i64 = -7;

/// Maximum decoded `clientDataJSON` size in bytes.
pub(crate) const MAX_CLIENT_DATA_JSON_BYTES: usize = 1024;

/// Maximum decoded `attestationObject` size in bytes.
pub(crate) const MAX_ATTESTATION_OBJECT_BYTES: usize = 2048;

/// Minimum credential ID length in raw bytes (CTAP2 §4.2, WebAuthn-2 §5.4.7),
/// the store's own lower bound.
pub(crate) const CREDENTIAL_ID_MIN_BYTES: usize = 16;

/// Maximum credential ID length in raw bytes, the store's own upper bound.
pub(crate) const CREDENTIAL_ID_MAX_BYTES: usize = 64;

/// Length of an uncompressed SEC1 P-256 public key in bytes.
pub(crate) const PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN: usize = 65;

/// Maximum accepted trimmed label length in bytes, matching the page's
/// `maxlength="64"` input attribute.
pub(crate) const MAX_LABEL_BYTES: usize = 64;

/// Deepest CBOR nesting the decoder accepts. The attestation object nests
/// two levels, an extension map at most three.
const CBOR_MAX_DEPTH: usize = 4;

/// Most CBOR items one decode accepts.
const CBOR_MAX_ITEMS: usize = 64;

/// `authenticatorData` flag bits (WebAuthn Level 3 §6.1).
pub(crate) const FLAG_UP: u8 = 0x01;
/// User verified.
pub(crate) const FLAG_UV: u8 = 0x04;
/// Backup eligible.
pub(crate) const FLAG_BE: u8 = 0x08;
/// Backup state.
pub(crate) const FLAG_BS: u8 = 0x10;
/// Attested credential data included.
pub(crate) const FLAG_AT: u8 = 0x40;
/// Extension data included.
pub(crate) const FLAG_ED: u8 = 0x80;

/// Fixed-length prefix of `authenticatorData` before the credential ID:
/// RP ID hash (32), flags (1), counter (4), AAGUID (16), ID length (2).
const AUTH_DATA_FIXED_LEN: usize = 32 + 1 + 4 + 16 + 2;

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
/// - [`OperatorRegistrationError::Invalid`] for any other rule in the module
///   docs that the response breaks.
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
    let credential_id = decode_credential_id(&request.credential_id_b64url).ok_or(Invalid)?;
    let public_key_sec1 = decode_public_key(&request.public_key_sec1_b64).ok_or(Invalid)?;

    let client_data_json =
        decode_capped(&request.client_data_json, MAX_CLIENT_DATA_JSON_BYTES).ok_or(Invalid)?;
    verify_client_data(&client_data_json, challenge, expected_origin)?;

    let attestation_object =
        decode_capped(&request.attestation_object, MAX_ATTESTATION_OBJECT_BYTES).ok_or(Invalid)?;
    let attested = parse_attestation_object(&attestation_object)?;
    if attested.credential_id != credential_id.as_slice() {
        return Err(Invalid);
    }
    if attested.public_key_sec1 != public_key_sec1 {
        return Err(Invalid);
    }

    Ok(VerifiedOperatorRegistration {
        credential_id_b64url: URL_SAFE_NO_PAD.encode(&credential_id),
        credential_id,
        public_key_sec1,
        label: label.to_owned(),
        sign_count: attested.sign_count,
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

/// Decodes a canonical base64url credential ID within the store's bounds.
pub(crate) fn decode_credential_id(b64url: &str) -> Option<Vec<u8>> {
    let bytes = decode_capped(b64url, CREDENTIAL_ID_MAX_BYTES)?;
    (bytes.len() >= CREDENTIAL_ID_MIN_BYTES).then_some(bytes)
}

/// Decodes an uncompressed SEC1 P-256 key and checks that it is a point on
/// the curve.
pub(crate) fn decode_public_key(b64url: &str) -> Option<[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN]> {
    let bytes = decode_capped(b64url, PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN)?;
    let key: [u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN] = bytes.try_into().ok()?;
    (key[0] == 0x04 && p256::PublicKey::from_sec1_bytes(&key).is_ok()).then_some(key)
}

/// Decodes canonical unpadded base64url of at most `max` bytes, refusing a
/// longer encoding before decoding it.
fn decode_capped(b64url: &str, max: usize) -> Option<Vec<u8>> {
    if b64url.len() > (max * 4).div_ceil(3) {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(b64url).ok()?;
    (bytes.len() <= max && URL_SAFE_NO_PAD.encode(&bytes) == b64url).then_some(bytes)
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
    origin: String,
    #[serde(rename = "crossOrigin", default, deserialize_with = "present")]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin", default, deserialize_with = "present")]
    top_origin: Option<serde::de::IgnoredAny>,
}

/// Deserializes a member that is present as `Some`, whatever its value, so
/// that `None` stands for absence alone.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn verify_client_data(
    client_data_json: &[u8],
    challenge: &RegistrationChallenge,
    expected_origin: &str,
) -> Result<(), OperatorRegistrationError> {
    use OperatorRegistrationError::Invalid;

    let client_data: CollectedClientData =
        serde_json::from_slice(client_data_json).map_err(|_| Invalid)?;
    if client_data.kind != "webauthn.create" {
        return Err(Invalid);
    }
    let submitted = decode_capped(&client_data.challenge, 32).ok_or(Invalid)?;
    if submitted.len() != 32 || !bool::from(submitted.ct_eq(challenge.bytes())) {
        return Err(Invalid);
    }
    if client_data.origin != expected_origin {
        return Err(Invalid);
    }
    if client_data.cross_origin == Some(true) || client_data.top_origin.is_some() {
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

fn parse_attestation_object(
    attestation_object: &[u8],
) -> Result<AttestedCredential<'_>, OperatorRegistrationError> {
    use OperatorRegistrationError::Invalid;

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
    parse_auth_data(auth_data)
}

fn parse_auth_data(auth_data: &[u8]) -> Result<AttestedCredential<'_>, OperatorRegistrationError> {
    use OperatorRegistrationError::Invalid;

    if auth_data.len() < AUTH_DATA_FIXED_LEN {
        return Err(Invalid);
    }
    let rp_id_hash = Sha256::digest(REGISTRATION_RP_ID.as_bytes());
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
) -> Result<[u8; PUBLIC_KEY_UNCOMPRESSED_SEC1_LEN], OperatorRegistrationError> {
    use OperatorRegistrationError::Invalid;

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
    if p256::PublicKey::from_sec1_bytes(&sec1).is_err() {
        return Err(Invalid);
    }
    Ok(sec1)
}

// ─────────────────────────────────────────────────────────────────────────────
// Bounded CBOR decoding
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded CBOR item of the subset the attestation object uses.
#[derive(Debug, PartialEq, Eq)]
enum Cbor<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3, valid UTF-8.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Cbor<'a>>),
    /// Major type 5, keys unique.
    Map(Vec<(Cbor<'a>, Cbor<'a>)>),
    /// Simple values 20 and 21.
    Bool(bool),
    /// Simple value 22.
    Null,
}

impl Cbor<'_> {
    /// The item as an integer, when it is one that fits `i64`.
    fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Unsigned(n) => i64::try_from(*n).ok(),
            Self::Negative(n) => i64::try_from(*n).ok().map(|n| -1 - n),
            _ => None,
        }
    }
}

/// Why the CBOR decoder refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Malformed;

/// Decodes exactly one item that spans all of `input`.
fn decode_complete(input: &[u8]) -> Result<Cbor<'_>, Malformed> {
    let (value, used) = decode_prefix(input)?;
    if used == input.len() {
        Ok(value)
    } else {
        Err(Malformed)
    }
}

/// Decodes one item from the start of `input` and returns it with the
/// number of bytes it spans.
fn decode_prefix(input: &[u8]) -> Result<(Cbor<'_>, usize), Malformed> {
    let mut decoder = Decoder {
        input,
        pos: 0,
        items: 0,
    };
    let value = decoder.item(0)?;
    Ok((value, decoder.pos))
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    items: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Malformed> {
        let end = self.pos.checked_add(len).ok_or(Malformed)?;
        let bytes = self.input.get(self.pos..end).ok_or(Malformed)?;
        self.pos = end;
        Ok(bytes)
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Reads the argument of an item head, refusing indefinite lengths,
    /// reserved encodings, and any argument not in its shortest form.
    fn argument(&mut self, info: u8) -> Result<u64, Malformed> {
        let (value, minimum) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (u64::from(self.take(1)?[0]), 24),
            25 => {
                let b = self.take(2)?;
                (u64::from(u16::from_be_bytes([b[0], b[1]])), 0x100)
            }
            26 => {
                let b = self.take(4)?;
                (
                    u64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                    0x1_0000,
                )
            }
            27 => {
                let b = self.take(8)?;
                (
                    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                    0x1_0000_0000,
                )
            }
            _ => return Err(Malformed),
        };
        if value < minimum {
            return Err(Malformed);
        }
        Ok(value)
    }

    fn length(&mut self, info: u8) -> Result<usize, Malformed> {
        usize::try_from(self.argument(info)?).map_err(|_| Malformed)
    }

    fn item(&mut self, depth: usize) -> Result<Cbor<'a>, Malformed> {
        self.items += 1;
        if self.items > CBOR_MAX_ITEMS || depth > CBOR_MAX_DEPTH {
            return Err(Malformed);
        }
        let head = self.take(1)?[0];
        let info = head & 0x1f;
        match head >> 5 {
            0 => Ok(Cbor::Unsigned(self.argument(info)?)),
            1 => Ok(Cbor::Negative(self.argument(info)?)),
            2 => {
                let len = self.length(info)?;
                Ok(Cbor::Bytes(self.take(len)?))
            }
            3 => {
                let len = self.length(info)?;
                let text = std::str::from_utf8(self.take(len)?).map_err(|_| Malformed)?;
                Ok(Cbor::Text(text))
            }
            4 => {
                let len = self.length(info)?;
                if len > self.remaining() {
                    return Err(Malformed);
                }
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Cbor::Array(items))
            }
            5 => {
                let len = self.length(info)?;
                if len > self.remaining() / 2 {
                    return Err(Malformed);
                }
                let mut entries = Vec::with_capacity(len);
                let mut keys: Vec<&'a [u8]> = Vec::with_capacity(len);
                for _ in 0..len {
                    let start = self.pos;
                    let key = self.item(depth + 1)?;
                    let encoded = &self.input[start..self.pos];
                    if keys.contains(&encoded) {
                        return Err(Malformed);
                    }
                    keys.push(encoded);
                    let value = self.item(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Cbor::Map(entries))
            }
            7 => match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(Malformed),
            },
            _ => Err(Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

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
    fn cbor_decoder_refuses_what_it_does_not_accept() {
        for input in [
            &[0x18, 0x05][..],
            &[0x19, 0x00, 0x10],
            &[0x1a, 0x00, 0x00, 0x01, 0x00],
            &[0x1b, 0, 0, 0, 0, 0, 0, 0xff, 0xff],
            &[0x1c],
            &[0x5f, 0xff],
            &[0x62, 0xff, 0xfe],
            &[0xf9, 0x00, 0x00],
            &[0xf7],
            &[0xc1, 0x00],
            &[0xa2, 0x01, 0x02, 0x01, 0x03],
            &[0x81, 0x81, 0x81, 0x81, 0x81, 0x00],
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            assert_eq!(decode_complete(input), Err(Malformed), "{input:02x?}");
        }
        let many: Vec<u8> = std::iter::once(0x98)
            .chain(std::iter::once(CBOR_MAX_ITEMS as u8))
            .chain(std::iter::repeat_n(0x00, CBOR_MAX_ITEMS))
            .collect();
        assert_eq!(decode_complete(&many), Err(Malformed));
        assert_eq!(
            decode_complete(&[0x82, 0x20, 0xf5]),
            Ok(Cbor::Array(vec![Cbor::Negative(0), Cbor::Bool(true)]))
        );
        assert_eq!(decode_complete(&[0x18, 0x18]), Ok(Cbor::Unsigned(24)));
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
