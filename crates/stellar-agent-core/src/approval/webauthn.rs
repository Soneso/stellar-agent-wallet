//! The WebAuthn assertion primitives every verifier in the workspace shares.
//!
//! [`pre_verify_assertion`] checks the byte-level steps of a WebAuthn
//! authentication assertion: the `clientDataJSON` type and challenge, the
//! relying-party ID hash, the user-presence (UP) and user-verification (UV)
//! flags, the backup-eligibility and backup-state (BE/BS) pair, and the
//! ES256 signature over `authenticator_data || SHA-256(client_data_json)`.
//! The mainnet consent verifier in [`super::presence`] and the smart-account
//! signing path both call it, so one implementation enforces these steps.
//!
//! The steps are origin-neutral: the smart-account signing path binds its
//! challenge to an on-chain authorization digest, and the on-chain verifier
//! does not see an origin. A caller that binds an origin, such as the mainnet
//! consent verifier, checks it before calling this primitive.
//!
//! [`normalize_der_to_compact_low_s`] turns the DER signature a browser
//! returns into the 64-byte compact low-S form the primitive consumes.
//!
//! # Steps
//!
//! | Step | Check |
//! |------|-------|
//! | 1 | `clientDataJSON.type == "webauthn.get"` |
//! | 2 | `clientDataJSON.challenge == base64url(challenge)` |
//! | 3 | `authenticator_data[0..32] == rp_id_hash` |
//! | 4 | UP (`flags & 0x01`) set |
//! | 5 | UV (`flags & 0x04`) set, unconditionally |
//! | 6 | not BE=0 with BS=1 |
//! | 7 | ES256 over `authenticator_data || SHA-256(client_data_json)` |
//!
//! Error values name the failed step and carry no input bytes.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::Signature;
use sha2::{Digest as _, Sha256};

/// The step of a WebAuthn assertion that failed.
///
/// The `Display` form is the stable sub-code each verifier maps to its own
/// error contract. The set is closed, so every wrapper maps each reason
/// exhaustively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthnAssertionError {
    /// `clientDataJSON.type` is not `webauthn.get`.
    WrongType,
    /// `clientDataJSON.challenge` is not the base64url form of the challenge.
    ChallengeMismatch,
    /// The authenticator data names another relying-party ID hash.
    WrongRpId,
    /// The authenticator data is shorter than the 37 bytes that hold the
    /// RP-ID hash, the flags and the signature counter.
    AuthDataTooShort,
    /// The user-presence flag is not set.
    UpUnset,
    /// The user-verification flag is not set.
    UvUnset,
    /// The credential is marked backed up but not backup-eligible.
    BeBsInvalid,
    /// The signature does not verify, or the public key is not a P-256 point.
    SignatureInvalid,
    /// `clientDataJSON` is not a JSON object with string `type` and
    /// `challenge` members.
    MalformedClientDataJson,
}

impl std::fmt::Display for WebAuthnAssertionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::WrongType => "wrong_type",
            Self::ChallengeMismatch => "challenge_mismatch",
            Self::WrongRpId => "wrong_rp_id",
            Self::AuthDataTooShort => "auth_data_too_short",
            Self::UpUnset => "up_unset",
            Self::UvUnset => "uv_unset",
            Self::BeBsInvalid => "be_bs_invalid",
            Self::SignatureInvalid => "signature_invalid",
            Self::MalformedClientDataJson => "malformed_client_data_json",
        })
    }
}

impl std::error::Error for WebAuthnAssertionError {}

/// The user-presence flag of the authenticator data.
pub const FLAG_UP: u8 = 0x01;
/// The user-verification flag of the authenticator data.
pub const FLAG_UV: u8 = 0x04;
/// The backup-eligibility flag of the authenticator data.
pub const FLAG_BE: u8 = 0x08;
/// The backup-state flag of the authenticator data.
pub const FLAG_BS: u8 = 0x10;
/// The attested-credential-data flag of the authenticator data.
pub const FLAG_AT: u8 = 0x40;
/// The extension-data flag of the authenticator data.
pub const FLAG_ED: u8 = 0x80;

/// Verifies a WebAuthn assertion with the workspace's ES256 verifier.
///
/// Runs the steps the module documents, in order, and returns the first
/// failure. `pubkey_uncompressed` is the SEC1 uncompressed P-256 point
/// `0x04 || x || y`; `signature_compact` is `r || s`, each 32 bytes big
/// endian; `rp_id_hash` is SHA-256 of the relying-party ID the caller
/// expects.
///
/// # Errors
///
/// The [`WebAuthnAssertionError`] of the first step that fails.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::webauthn::{WebAuthnAssertionError, pre_verify_assertion};
///
/// let error = pre_verify_assertion(&[0; 32], &[4; 65], &[0; 37], b"{}", &[1; 64], &[0; 32])
///     .unwrap_err();
/// assert_eq!(error, WebAuthnAssertionError::MalformedClientDataJson);
/// ```
pub fn pre_verify_assertion(
    challenge: &[u8; 32],
    pubkey_uncompressed: &[u8; 65],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_compact: &[u8; 64],
    rp_id_hash: &[u8; 32],
) -> Result<(), WebAuthnAssertionError> {
    pre_verify_assertion_with(
        challenge,
        pubkey_uncompressed,
        authenticator_data,
        client_data_json,
        signature_compact,
        rp_id_hash,
        verify_es256,
    )
}

/// [`pre_verify_assertion`] with the ES256 check of step 7 supplied by the
/// caller.
///
/// `verify_signature` receives the public key, the signed data
/// `authenticator_data || SHA-256(client_data_json)` (unhashed; the verifier
/// applies SHA-256), and the compact signature, and returns whether the
/// signature verifies. Steps 1 to 6 run here before it is called, so every
/// caller enforces them identically.
///
/// # Errors
///
/// The [`WebAuthnAssertionError`] of the first step that fails, and
/// [`WebAuthnAssertionError::SignatureInvalid`] when `verify_signature`
/// returns `false`.
pub fn pre_verify_assertion_with(
    challenge: &[u8; 32],
    pubkey_uncompressed: &[u8; 65],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_compact: &[u8; 64],
    rp_id_hash: &[u8; 32],
    verify_signature: impl FnOnce(&[u8; 65], &[u8], &[u8; 64]) -> bool,
) -> Result<(), WebAuthnAssertionError> {
    let client_data: ClientDataFields = serde_json::from_slice(client_data_json)
        .map_err(|_| WebAuthnAssertionError::MalformedClientDataJson)?;
    if client_data.type_field != "webauthn.get" {
        return Err(WebAuthnAssertionError::WrongType);
    }
    if client_data.challenge != URL_SAFE_NO_PAD.encode(challenge) {
        return Err(WebAuthnAssertionError::ChallengeMismatch);
    }
    if authenticator_data.len() < 37 {
        return Err(WebAuthnAssertionError::AuthDataTooShort);
    }
    if &authenticator_data[..32] != rp_id_hash {
        return Err(WebAuthnAssertionError::WrongRpId);
    }
    let flags = authenticator_data[32];
    if flags & FLAG_UP == 0 {
        return Err(WebAuthnAssertionError::UpUnset);
    }
    if flags & FLAG_UV == 0 {
        return Err(WebAuthnAssertionError::UvUnset);
    }
    if flags & FLAG_BE == 0 && flags & FLAG_BS != 0 {
        return Err(WebAuthnAssertionError::BeBsInvalid);
    }
    let mut signed = Vec::with_capacity(authenticator_data.len() + 32);
    signed.extend_from_slice(authenticator_data);
    signed.extend_from_slice(&Sha256::digest(client_data_json));
    if verify_signature(pubkey_uncompressed, &signed, signature_compact) {
        Ok(())
    } else {
        Err(WebAuthnAssertionError::SignatureInvalid)
    }
}

/// The `type` and `challenge` members of `clientDataJSON`; other members are
/// ignored by this primitive.
#[derive(serde::Deserialize)]
struct ClientDataFields {
    #[serde(rename = "type")]
    type_field: String,
    challenge: String,
}

/// ES256 over `signed` with the P-256 key `pubkey`: SHA-256 of `signed`,
/// then ECDSA verification of the compact `signature`.
fn verify_es256(pubkey: &[u8; 65], signed: &[u8], signature: &[u8; 64]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(signed, &signature).is_ok()
}

/// A 64-byte compact ECDSA P-256 signature, `r || s` big endian, with `s` in
/// the lower half of the group order.
///
/// Only [`normalize_der_to_compact_low_s`] produces one, so holding one means
/// the low-S form holds. `Debug` shows the length only.
#[derive(Clone, PartialEq, Eq)]
pub struct NormalisedSignature([u8; 64]);

impl NormalisedSignature {
    /// The compact bytes: `r` in 0..32, `s` in 32..64.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for NormalisedSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for NormalisedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NormalisedSignature")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Why a DER signature cannot be normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAuthnSignatureError {
    /// The input is not a strict DER encoding of two P-256 scalars.
    Invalid,
}

impl std::fmt::Display for WebAuthnSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid => f.write_str("The WebAuthn signature is invalid."),
        }
    }
}

impl std::error::Error for WebAuthnSignatureError {}

/// Parses a strict DER ECDSA P-256 signature and returns its compact low-S
/// form, with `true` when `s` was in the upper half and was replaced by
/// `n - s`.
///
/// The DER decoder refuses a wrong outer tag, components other than two
/// INTEGERs, trailing bytes, nonminimal lengths, negative integers, and an
/// integer wider than the P-256 field. Low-S selects one representative of
/// the `(r, s)` and `(r, n - s)` pair; it does not make a signature unique
/// per message.
///
/// # Errors
///
/// [`WebAuthnSignatureError::Invalid`] for any input the decoder refuses.
pub fn normalize_der_to_compact_low_s(
    der_signature: &[u8],
) -> Result<(NormalisedSignature, bool), WebAuthnSignatureError> {
    let signature =
        Signature::from_der(der_signature).map_err(|_| WebAuthnSignatureError::Invalid)?;
    let (normalised, was_high_s) = match signature.normalize_s() {
        Some(low_s) => (low_s, true),
        None => (signature, false),
    };
    Ok((
        NormalisedSignature(normalised.to_bytes().into()),
        was_high_s,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics are the failure mode"
    )]

    use proptest::prelude::*;

    use super::*;

    // A software P-256 key with a fixed scalar (bytes 33..=64), a fixed
    // 32-byte challenge, and authenticator data whose RP-ID hash is 32 zero
    // bytes with UP | UV | BE | BS set.
    const SECRET_KEY_SEED: [u8; 32] = [
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, 64,
    ];
    const CHALLENGE: [u8; 32] = [
        0x4b, 0xb7, 0xa8, 0xb9, 0x96, 0x09, 0xb0, 0xb8, 0xb1, 0xd5, 0x34, 0x69, 0x4b, 0xb1, 0xf3,
        0x1f, 0x12, 0x91, 0x38, 0xa2, 0xf2, 0xa1, 0x1f, 0x8e, 0x87, 0x02, 0xee, 0xdb, 0xb7, 0x92,
        0x92, 0x2e,
    ];
    const AUTH_DATA_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;
    const RP_ID_HASH: [u8; 32] = [0u8; 32];

    fn make_auth_data(flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; 37];
        data[32] = flags;
        data
    }

    fn make_client_data_json(challenge_b64: &str, type_field: &str) -> Vec<u8> {
        format!(
            r#"{{"type": "{type_field}", "challenge": "{challenge_b64}", "origin": "https://example.com", "crossOrigin": false}}"#
        )
        .into_bytes()
    }

    /// The public key of [`SECRET_KEY_SEED`] and its low-S signature over
    /// SHA-256 of `auth_data || SHA-256(client_data_json)`.
    fn sign_fixture(auth_data: &[u8], client_data_json: &[u8]) -> ([u8; 65], [u8; 64]) {
        use p256::SecretKey;
        use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret_key = SecretKey::from_slice(&SECRET_KEY_SEED).unwrap();
        let signing_key = SigningKey::from(&secret_key);
        let mut pubkey = [0u8; 65];
        pubkey.copy_from_slice(secret_key.public_key().to_encoded_point(false).as_bytes());
        let mut message = auth_data.to_vec();
        message.extend_from_slice(&Sha256::digest(client_data_json));
        let digest = Sha256::digest(&message);
        let signature: Signature = signing_key.sign_prehash(&digest).unwrap();
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut compact = [0u8; 64];
        compact.copy_from_slice(&signature.to_bytes());
        (pubkey, compact)
    }

    fn verify_with(
        challenge: &[u8; 32],
        auth_data: &[u8],
        client_data: &[u8],
        rp_id_hash: &[u8; 32],
        sign_over: Option<&[u8]>,
    ) -> Result<(), WebAuthnAssertionError> {
        let (pubkey, sig) = sign_fixture(sign_over.unwrap_or(auth_data), client_data);
        pre_verify_assertion(challenge, &pubkey, auth_data, client_data, &sig, rp_id_hash)
    }

    fn valid_client_data(type_field: &str) -> Vec<u8> {
        make_client_data_json(&URL_SAFE_NO_PAD.encode(CHALLENGE), type_field)
    }

    #[test]
    fn pre_verify_accepts_valid_assertion() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        assert_eq!(
            verify_with(&CHALLENGE, &auth_data, &client_data, &RP_ID_HASH, None),
            Ok(())
        );
    }

    #[test]
    fn pre_verify_rejects_wrong_rp_id() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        assert_eq!(
            verify_with(&CHALLENGE, &auth_data, &client_data, &[0xff; 32], None),
            Err(WebAuthnAssertionError::WrongRpId)
        );
    }

    #[test]
    fn pre_verify_rejects_auth_data_too_short() {
        let client_data = valid_client_data("webauthn.get");
        let full = make_auth_data(AUTH_DATA_FLAGS);
        assert_eq!(
            verify_with(
                &CHALLENGE,
                &[0u8; 36],
                &client_data,
                &RP_ID_HASH,
                Some(&full)
            ),
            Err(WebAuthnAssertionError::AuthDataTooShort)
        );
    }

    #[test]
    fn pre_verify_rejects_up_unset() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS & !FLAG_UP);
        assert_eq!(
            verify_with(&CHALLENGE, &auth_data, &client_data, &RP_ID_HASH, None),
            Err(WebAuthnAssertionError::UpUnset)
        );
    }

    #[test]
    fn pre_verify_rejects_uv_unset() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS & !FLAG_UV);
        assert_eq!(
            verify_with(&CHALLENGE, &auth_data, &client_data, &RP_ID_HASH, None),
            Err(WebAuthnAssertionError::UvUnset)
        );
    }

    #[test]
    fn pre_verify_rejects_be_bs_invalid() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(FLAG_UP | FLAG_UV | FLAG_BS);
        assert_eq!(
            verify_with(&CHALLENGE, &auth_data, &client_data, &RP_ID_HASH, None),
            Err(WebAuthnAssertionError::BeBsInvalid)
        );
    }

    #[test]
    fn pre_verify_rejects_challenge_mismatch() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        assert_eq!(
            verify_with(&[0u8; 32], &auth_data, &client_data, &RP_ID_HASH, None),
            Err(WebAuthnAssertionError::ChallengeMismatch)
        );
    }

    /// A single flipped signature bit fails the ES256 step.
    #[test]
    fn pre_verify_rejects_signature_invalid() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, mut sig) = sign_fixture(&auth_data, &client_data);
        sig[0] ^= 0x01;
        assert_eq!(
            pre_verify_assertion(
                &CHALLENGE,
                &pubkey,
                &auth_data,
                &client_data,
                &sig,
                &RP_ID_HASH
            ),
            Err(WebAuthnAssertionError::SignatureInvalid)
        );
    }

    /// A signature over other authenticator data fails, and a public key that
    /// is not a curve point fails the same step.
    #[test]
    fn pre_verify_binds_the_signed_bytes_and_the_key() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let mut other = auth_data.clone();
        other[36] = 9;
        assert_eq!(
            verify_with(
                &CHALLENGE,
                &auth_data,
                &client_data,
                &RP_ID_HASH,
                Some(&other)
            ),
            Err(WebAuthnAssertionError::SignatureInvalid)
        );
        let (_, sig) = sign_fixture(&auth_data, &client_data);
        let mut off_curve = [0u8; 65];
        off_curve[0] = 4;
        off_curve[64] = 1;
        assert_eq!(
            pre_verify_assertion(
                &CHALLENGE,
                &off_curve,
                &auth_data,
                &client_data,
                &sig,
                &RP_ID_HASH
            ),
            Err(WebAuthnAssertionError::SignatureInvalid)
        );
    }

    #[test]
    fn pre_verify_rejects_wrong_type() {
        let client_data = valid_client_data("webauthn.create");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        assert_eq!(
            verify_with(&CHALLENGE, &auth_data, &client_data, &RP_ID_HASH, None),
            Err(WebAuthnAssertionError::WrongType)
        );
    }

    #[test]
    fn pre_verify_rejects_malformed_client_data_json() {
        let client_data = br#"{"type": "webauthn.get", "origin": "https://example.com"}"#.to_vec();
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        assert_eq!(
            verify_with(&CHALLENGE, &auth_data, &client_data, &RP_ID_HASH, None),
            Err(WebAuthnAssertionError::MalformedClientDataJson)
        );
    }

    /// The caller-supplied ES256 check receives the key, the unhashed signed
    /// data and the signature, and its answer decides step 7.
    #[test]
    fn supplied_signature_check_receives_the_signed_data() {
        let client_data = valid_client_data("webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);
        let mut expected = auth_data.clone();
        expected.extend_from_slice(&Sha256::digest(&client_data));
        let result = pre_verify_assertion_with(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
            |key, signed, signature| {
                assert_eq!(key, &pubkey);
                assert_eq!(signed, expected.as_slice());
                assert_eq!(signature, &sig);
                false
            },
        );
        assert_eq!(result, Err(WebAuthnAssertionError::SignatureInvalid));
    }

    #[test]
    fn error_display_is_the_sub_code() {
        let cases = [
            (WebAuthnAssertionError::WrongType, "wrong_type"),
            (
                WebAuthnAssertionError::ChallengeMismatch,
                "challenge_mismatch",
            ),
            (WebAuthnAssertionError::WrongRpId, "wrong_rp_id"),
            (
                WebAuthnAssertionError::AuthDataTooShort,
                "auth_data_too_short",
            ),
            (WebAuthnAssertionError::UpUnset, "up_unset"),
            (WebAuthnAssertionError::UvUnset, "uv_unset"),
            (WebAuthnAssertionError::BeBsInvalid, "be_bs_invalid"),
            (
                WebAuthnAssertionError::SignatureInvalid,
                "signature_invalid",
            ),
            (
                WebAuthnAssertionError::MalformedClientDataJson,
                "malformed_client_data_json",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.to_string(), code);
        }
        assert_eq!(
            WebAuthnSignatureError::Invalid.to_string(),
            "The WebAuthn signature is invalid."
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// High-S input `s == n - 1` normalizes to `s == 1`, `r` unchanged.
    #[test]
    fn normalize_high_s_vector() {
        let der = hex(
            "3045022001020304050607080910111213141516171819202122232425262728293031320221\
             00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        );
        let (sig, was_high) = normalize_der_to_compact_low_s(&der).unwrap();
        assert!(was_high);
        assert_eq!(
            &sig.as_bytes()[..32],
            hex("0102030405060708091011121314151617181920212223242526272829303132").as_slice()
        );
        assert_eq!(
            &sig.as_bytes()[32..],
            hex("0000000000000000000000000000000000000000000000000000000000000001").as_slice()
        );
    }

    /// Low-S input `s == 5` stays unchanged.
    #[test]
    fn normalize_already_low_s_vector() {
        let r: [u8; 32] = hex("0102030405060708091011121314151617181920212223242526272829303132")
            .try_into()
            .unwrap();
        let mut s = [0u8; 32];
        s[31] = 5;
        let der = Signature::from_scalars(r, s).unwrap().to_der();
        let (sig, was_high) = normalize_der_to_compact_low_s(der.as_bytes()).unwrap();
        assert!(!was_high);
        assert_eq!(&sig.as_bytes()[..32], &r);
        assert_eq!(&sig.as_bytes()[32..], &s);
    }

    /// A wrong outer tag, a bare header, a truncated INTEGER and the
    /// nonminimal encoding of a small `s` are refused.
    #[test]
    fn normalize_rejects_malformed_der() {
        let nonminimal = format!(
            "3044022001020304050607080910111213141516171819202122232425262728293031320220{}05",
            "00".repeat(31)
        );
        for bad in [
            "31450220010203040506070809",
            "300102",
            "3045022001020304050607080910111213141516",
            nonminimal.as_str(),
        ] {
            assert_eq!(
                normalize_der_to_compact_low_s(&hex(bad)),
                Err(WebAuthnSignatureError::Invalid),
                "{bad}"
            );
        }
    }

    /// `(n - 1) / 2` is the largest low-S value and stays; `(n + 1) / 2` is
    /// the smallest high-S value and becomes `(n - 1) / 2`.
    #[test]
    fn normalize_s_at_the_half_order_boundary() {
        let mut r = [0u8; 32];
        r[31] = 1;
        let low: [u8; 32] = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
            .try_into()
            .unwrap();
        let high: [u8; 32] =
            hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9")
                .try_into()
                .unwrap();
        let (kept, was_high) = normalize_der_to_compact_low_s(
            Signature::from_scalars(r, low).unwrap().to_der().as_bytes(),
        )
        .unwrap();
        assert!(!was_high);
        assert_eq!(&kept.as_bytes()[32..], &low);
        let (flipped, was_high) = normalize_der_to_compact_low_s(
            Signature::from_scalars(r, high)
                .unwrap()
                .to_der()
                .as_bytes(),
        )
        .unwrap();
        assert!(was_high);
        assert_eq!(&flipped.as_bytes()[32..], &low);
    }

    /// `Debug` shows the length, never the signature bytes.
    #[test]
    fn normalised_signature_debug_is_length_only() {
        let der = hex(
            "3045022001020304050607080910111213141516171819202122232425262728293031320221\
             00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        );
        let (sig, _) = normalize_der_to_compact_low_s(&der).unwrap();
        let text = format!("{sig:?}");
        assert_eq!(text, "NormalisedSignature { len: 64 }");
    }

    /// Every signature `sign_prehash` produces round-trips through DER into
    /// its low-S compact form.
    #[test]
    fn property_sign_prehash_roundtrip_produces_low_s() {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use rand_core::OsRng;

        let half_order = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
        proptest!(
            ProptestConfig::with_cases(256),
            |(prehash in prop::array::uniform32(any::<u8>()))| {
                let signing_key = SigningKey::random(&mut OsRng);
                let sig: Signature = signing_key
                    .sign_prehash(&prehash)
                    .map_err(|e| TestCaseError::fail(format!("sign_prehash failed: {e:?}")))?;
                let expected: [u8; 64] = sig.normalize_s().unwrap_or(sig).to_bytes().into();
                let (normalised, _) = normalize_der_to_compact_low_s(sig.to_der().as_bytes())
                    .map_err(|e| TestCaseError::fail(format!("normalise failed: {e:?}")))?;
                prop_assert!(&normalised.as_bytes()[32..] <= half_order.as_slice());
                prop_assert_eq!(normalised.as_bytes(), &expected);
            }
        );
    }
}
