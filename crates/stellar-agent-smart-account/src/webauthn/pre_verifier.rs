//! Off-chain WebAuthn assertion pre-verifier.
//!
//! Implements the 7-step pipeline that the wallet applies to every WebAuthn
//! passkey assertion BEFORE chain-submission. Rejecting a malformed assertion
//! here avoids burning a testnet (or mainnet) round-trip when the on-chain OZ
//! `verifiers/webauthn.rs` would have rejected it anyway.
//!
//! # Pipeline
//!
//! | Step | W3C ref | On-chain canonical | Wallet behaviour |
//! |------|---------|-------------------|-----------------|
//! | 1 | §11 | `webauthn.rs:121-126` | `clientDataJSON.type == "webauthn.get"` |
//! | 2 | §12 | `webauthn.rs:151-163` | challenge == `base64url(auth_digest[0..32])` |
//! | 3 | n/a (omitted on-chain) | `webauthn.rs:9-15` | RP-ID-hash defence-in-depth |
//! | 4 | §16 | `webauthn.rs:184-189` | UP bit set |
//! | 5 | §17 | `webauthn.rs:217-221`, `:346` | UV bit unconditionally set |
//! | 6 | spec ext | `webauthn.rs:222-261`, `:347` | BE=0 && BS=1 is invalid |
//! | 7 | §19+20 | `webauthn.rs:350-356` | secp256r1 sig verify via `COSEKey::verify_signature` |
//!
//! # Adapter shim (step 7)
//!
//! Step 7 routes through `webauthn_rs_core::proto::COSEKey::verify_signature`
//! (`webauthn-rs-core/src/crypto.rs:558`), which internally uses OpenSSL with
//! SHA-256 as the message digest (`webauthn-rs-core/src/crypto.rs:30`). The
//! compact 64-byte r||s signature is converted to DER encoding inline before
//! passing it to the OpenSSL verifier; the conversion is a deterministic
//! fixed-cost byte transformation with no external dep.
//!
//! # RP-ID-hash check (step 3)
//!
//! The on-chain OZ verifier **omits** RP-ID-hash validation — per the on-chain
//! docstring in OpenZeppelin stellar-contracts v0.7.1,
//! `packages/accounts/src/verifiers/webauthn.rs:9-15` (SHA `3f81125`):
//! > "RP ID hash validation: Verification of `rpIdHash` in authenticatorData
//! > against expected RP ID hash is omitted."
//!
//! The wallet adds it as an off-chain-only defence-in-depth check. It catches
//! "credential bound to a different RP-ID" UX confusion before chain-submission
//! but is NOT on-chain parity. Step 3 MUST NOT be removed on the grounds that
//! the chain does not enforce it; defence-in-depth is the intent.
//!
//! # Security
//!
//! No raw secret material, signature bytes, or unredacted strkeys are included
//! in any error reason string. The `WebAuthnInvalidReason`
//! enum variants are operator-safe sub-codes.
//!
//! # On-chain authority
//!
//! - OZ `stellar-contracts` v0.7.1 SHA `3f81125`:
//!   `packages/accounts/src/verifiers/webauthn.rs`
//!   (the canonical on-chain authority — the wallet's pre-verifier mirrors
//!   the on-chain `webauthn::verify` 7-step pipeline byte-for-byte).
//!
//! The canonical off-chain signing flow does NOT pre-verify the assertion
//! off-chain — it trusts the OS authenticator output and submits to chain,
//! relying on the on-chain verifier to reject malformed assertions.
//!
//! The wallet's off-chain pre-verifier is **intentional divergence** from
//! that off-chain posture: defence-in-depth (catches credential / RP-ID
//! confusion before chain-submission) plus UX (avoids fee-burn on a
//! malformed assertion). The on-chain OZ verifier remains the canonical
//! authority for every step's correctness; the pre-verifier mirrors it.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use webauthn_rs_core::proto::{COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType, ECDSACurve};

use crate::SaError;
use crate::error::WebAuthnInvalidReason;

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Verify a WebAuthn assertion off-chain before chain-submission.
///
/// Implements the 7-step pipeline:
///
/// 1. `clientDataJSON.type == "webauthn.get"` (W3C step 11;
///    on-chain OZ `webauthn.rs:121-126`, SHA `3f81125`).
/// 2. `clientDataJSON.challenge == base64url(challenge[0..32])` (W3C step 12;
///    on-chain OZ `webauthn.rs:151-163`).
/// 3. `authenticator_data[0..32] == rp_id_hash` (wallet-only defence-in-depth;
///    on-chain OZ `webauthn.rs:9-15` explicitly omits this check).
/// 4. `(authenticator_data[32] & 0x01) != 0` — UP bit (W3C step 16;
///    on-chain `webauthn.rs:184-189`).
/// 5. `(authenticator_data[32] & 0x04) != 0` — UV bit **unconditionally**
///    (W3C step 17; on-chain `webauthn.rs:217-221`, `:346`).
/// 6. `!((flags & 0x08) == 0 && (flags & 0x10) != 0)` — BE/BS validity
///    (on-chain `webauthn.rs:222-261`, `:347`).
/// 7. secp256r1 signature over `sha256(authenticator_data || sha256(client_data_json))`
///    (W3C steps 19+20; on-chain `webauthn.rs:350-356`).
///    Routed through `webauthn_rs_core::proto::COSEKey::verify_signature`
///    (`webauthn-rs-core/src/crypto.rs:558`).
///
/// # Arguments
///
/// - `challenge`: the 32-byte auth-digest used as the challenge value in
///   step 2.
/// - `pubkey_uncompressed`: 65-byte uncompressed secp256r1 public key
///   (`0x04 || x[32] || y[32]`).
/// - `authenticator_data`: raw authenticator-data bytes from the platform
///   authenticator (minimum 37 bytes per W3C spec).
/// - `client_data_json`: raw clientDataJSON bytes (UTF-8 JSON).
/// - `signature_compact`: 64-byte compact r||s secp256r1 signature.
/// - `rp_id_hash`: SHA-256 of the RP-ID (wallet-local expected value; step 3).
///
/// # Errors
///
/// Returns `SaError::WebAuthnAssertionInvalid { reason }` on any failed step.
/// Sub-codes: `wrong_type`, `challenge_mismatch`, `wrong_rp_id`,
/// `auth_data_too_short`, `up_unset`, `uv_unset`, `be_bs_invalid`,
/// `signature_invalid`, `malformed_client_data_json`.
pub fn pre_verify_assertion(
    challenge: &[u8; 32],
    pubkey_uncompressed: &[u8; 65],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_compact: &[u8; 64],
    rp_id_hash: &[u8; 32],
) -> Result<(), SaError> {
    // ── STEP 1 — type field ───────────────────────────────────────────────
    // W3C step 11; on-chain webauthn.rs:121-126.
    let (type_field, challenge_field) = parse_client_data_type_and_challenge(client_data_json)?;
    if type_field != "webauthn.get" {
        return Err(WebAuthnInvalidReason::WrongType.into());
    }

    // ── STEP 2 — challenge binding ────────────────────────────────────────
    // W3C step 12; on-chain webauthn.rs:151-163.
    // The challenge is base64url-no-pad encoding of challenge[0..32]
    // (identical to OZ's base64_url_encode over the first 32 bytes of
    // signature_payload at webauthn.rs:155-158).
    let expected_challenge = URL_SAFE_NO_PAD.encode(challenge);
    if challenge_field != expected_challenge {
        return Err(WebAuthnInvalidReason::ChallengeMismatch.into());
    }

    // ── STEP 3 — RP-ID-hash (wallet-only defence-in-depth) ───────────────
    // NOT on-chain. On-chain webauthn.rs:9-15 explicitly omits this check
    // per the docstring: "RP ID hash validation: Verification of `rpIdHash`
    // in authenticatorData against expected RP ID hash is omitted."
    // Wallet adds it as off-chain hardening against "credential bound to a
    // different RP-ID" UX confusion.
    if authenticator_data.len() < 37 {
        // authenticator_data must be at least 37 bytes to contain rp_id_hash
        // (bytes 0..32) plus the flags byte (byte 32) plus the 4-byte counter.
        return Err(WebAuthnInvalidReason::AuthDataTooShort.into());
    }
    if &authenticator_data[..32] != rp_id_hash {
        return Err(WebAuthnInvalidReason::WrongRpId.into());
    }

    // ── STEP 4 — UP bit ──────────────────────────────────────────────────
    // W3C step 16; on-chain webauthn.rs:184-189 (validate_user_present_bit_set).
    // AUTH_DATA_FLAGS_UP = 0x01 (webauthn.rs:35).
    let flags = authenticator_data[32];
    if (flags & 0x01) == 0 {
        return Err(WebAuthnInvalidReason::UpUnset.into());
    }

    // ── STEP 5 — UV bit (UNCONDITIONAL) ──────────────────────────────────
    // W3C step 17; on-chain webauthn.rs:217-221 (validate_user_verified_bit_set)
    // called UNCONDITIONALLY at webauthn.rs:346.
    // AUTH_DATA_FLAGS_UV = 0x04 (webauthn.rs:37).
    //
    // IMPORTANT: the on-chain OZ verifier at webauthn.rs:346 calls
    // validate_user_verified_bit_set UNCONDITIONALLY. UV-required is not
    // optional; mirroring on-chain semantics is the only correct posture.
    if (flags & 0x04) == 0 {
        return Err(WebAuthnInvalidReason::UvUnset.into());
    }

    // ── STEP 6 — BE/BS validity ───────────────────────────────────────────
    // On-chain webauthn.rs:257-261 (validate_backup_eligibility_and_state)
    // called UNCONDITIONALLY at webauthn.rs:347.
    // AUTH_DATA_FLAGS_BE = 0x08, AUTH_DATA_FLAGS_BS = 0x10 (webauthn.rs:39-41).
    // Invalid state: BE=0 && BS=1 (credential backed up but not eligible).
    if (flags & 0x08) == 0 && (flags & 0x10) != 0 {
        return Err(WebAuthnInvalidReason::BeBsInvalid.into());
    }

    // ── STEP 7 — secp256r1 signature verification ─────────────────────────
    // W3C steps 19+20; on-chain webauthn.rs:350-356.
    //
    // message_digest = sha256(authenticator_data || sha256(client_data_json))
    //
    // Routed through COSEKey::verify_signature (webauthn-rs-core/src/crypto.rs:558),
    // which constructs an OpenSSL ES256 verifier (webauthn-rs-core/src/crypto.rs:30)
    // that internally hashes verification_data with SHA-256. We therefore pass
    // the UNHASHED concatenation (authenticator_data || sha256(client_data_json))
    // as verification_data; OpenSSL performs the outer SHA-256 internally.
    verify_secp256r1_signature(
        pubkey_uncompressed,
        authenticator_data,
        client_data_json,
        signature_compact,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse `type` and `challenge` string values from the raw `clientDataJSON`
/// bytes via [`serde_json::from_slice`].
///
/// Uses a proper JSON parser rather than a hand-rolled scan: clientDataJSON
/// manipulation is a known WebAuthn attack vector, and a sound parser must
/// handle escape sequences, Unicode escapes, and nested string-value
/// collisions correctly. The OZ on-chain verifier uses a `serde_json_core`
/// flat-object parse (`webauthn.rs:325-327`) for the same reason; the wallet
/// uses `serde_json::from_slice` because the off-chain context has no
/// `no_std` constraint.
///
/// Returns `(type_value, challenge_value)` as owned `String`s on success.
///
/// # Errors
///
/// Returns `SaError::WebAuthnAssertionInvalid { reason: MalformedClientDataJson }`
/// if the bytes are not valid UTF-8 JSON, do not deserialize as an object, or
/// the `type` / `challenge` fields are absent / non-string. Any other JSON
/// fields (e.g. `origin`, `crossOrigin`) are ignored — the wallet binds only
/// `type` and `challenge` per W3C steps 11-12 (on-chain `webauthn.rs:121-163`).
fn parse_client_data_type_and_challenge(
    client_data_json: &[u8],
) -> Result<(String, String), SaError> {
    let parsed: ClientDataFields = serde_json::from_slice(client_data_json)
        .map_err(|_| SaError::from(WebAuthnInvalidReason::MalformedClientDataJson))?;

    Ok((parsed.type_field, parsed.challenge))
}

/// Minimal serde-derived view over `clientDataJSON`.
///
/// Only the two fields the wallet actually binds are deserialised:
/// `type` (renamed because `type` is a Rust keyword) and `challenge`. Any
/// other JSON fields present (e.g. `origin`, `crossOrigin`, `tokenBinding`)
/// are accepted and ignored — they are not part of the wallet's W3C step
/// 11-12 binding surface.
#[derive(serde::Deserialize)]
struct ClientDataFields {
    #[serde(rename = "type")]
    type_field: String,
    challenge: String,
}

/// Verify the secp256r1 signature using the webauthn-rs-core adapter.
///
/// Constructs a [`COSEKey`] for the ES256/SECP256R1 algorithm from the 65-byte
/// uncompressed public key, converts the compact 64-byte r||s signature to
/// DER format, then calls `COSEKey::verify_signature`
/// (`webauthn-rs-core/src/crypto.rs:558`).
///
/// The `verification_data` passed to `COSEKey::verify_signature` is the
/// unhashed concatenation `authenticator_data || sha256(client_data_json)`.
/// The OpenSSL ES256 verifier inside the adapter hashes this data with SHA-256
/// internally (`webauthn-rs-core/src/crypto.rs:30`), matching step 20 of the
/// W3C assertion procedure and the on-chain path at `webauthn.rs:350-356`.
///
/// # Errors
///
/// Returns `SaError::WebAuthnAssertionInvalid { reason: SignatureInvalid }` on
/// malformed public-key input, any OpenSSL verification error, or if the
/// signature does not verify.
fn verify_secp256r1_signature(
    pubkey_uncompressed: &[u8; 65],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature_compact: &[u8; 64],
) -> Result<(), SaError> {
    // Build the COSEKey from the 65-byte uncompressed EC point.
    // pubkey_uncompressed layout: 0x04 || x[32] || y[32]
    // (verified by the caller via the `&[u8; 65]` type contract; the 0x04
    // prefix is the SEC1 uncompressed-point tag per X9.62).
    let cose_key =
        build_es256_cose_key(pubkey_uncompressed).ok_or(WebAuthnInvalidReason::SignatureInvalid)?;

    // Build the verification data (unhashed):
    // verification_data = authenticator_data || sha256(client_data_json)
    // On-chain webauthn.rs:349-354 (steps 19+20):
    //   client_data_hash = sha256(client_data)
    //   message_digest   = authenticator_data || client_data_hash
    //   e.crypto().secp256r1_verify(pub_key, sha256(message_digest), signature)
    // The COSEKey::verify_signature OpenSSL backend hashes verification_data
    // with SHA-256 internally (webauthn-rs-core/src/crypto.rs:30), so we pass
    // the unhashed concatenation and let OpenSSL perform the outer hash.
    let client_data_hash = Sha256::digest(client_data_json);
    let mut verification_data = Vec::with_capacity(authenticator_data.len() + 32);
    verification_data.extend_from_slice(authenticator_data);
    verification_data.extend_from_slice(&client_data_hash);

    // Convert compact r||s to DER for OpenSSL.
    // COSEKey::verify_signature delegates to openssl::sign::Verifier::verify_oneshot
    // which expects a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER b }).
    let der_sig = compact_to_der(signature_compact);

    let verified = cose_key
        .verify_signature(&der_sig, &verification_data)
        .map_err(|_| SaError::from(WebAuthnInvalidReason::SignatureInvalid))?;

    if verified {
        Ok(())
    } else {
        Err(WebAuthnInvalidReason::SignatureInvalid.into())
    }
}

/// Build an ES256/SECP256R1 `COSEKey` from a 65-byte uncompressed public key.
///
/// Layout: `0x04 || x[32] || y[32]` (SEC1 X9.62 uncompressed-point format;
/// `webauthn-rs-core/src/interface.rs:144-151` for the `COSEEC2Key` struct).
///
/// Returns `None` if the byte layout is invalid (first byte is not `0x04`).
fn build_es256_cose_key(pubkey_uncompressed: &[u8; 65]) -> Option<COSEKey> {
    // First byte must be the SEC1 uncompressed-point prefix.
    if pubkey_uncompressed[0] != 0x04 {
        return None;
    }
    let x: Vec<u8> = pubkey_uncompressed[1..33].to_vec();
    let y: Vec<u8> = pubkey_uncompressed[33..65].to_vec();

    Some(COSEKey {
        type_: COSEAlgorithm::ES256,
        key: COSEKeyType::EC_EC2(COSEEC2Key {
            curve: ECDSACurve::SECP256R1,
            x: x.into(),
            y: y.into(),
        }),
    })
}

/// Convert a 64-byte compact r||s ECDSA signature to DER encoding.
///
/// DER ECDSA signature layout per RFC 3279 §2.2.3:
/// ```text
/// SEQUENCE {
///   INTEGER r,
///   INTEGER s,
/// }
/// ```
///
/// Each integer is encoded with a leading 0x00 byte if its high bit is set
/// (to indicate a positive value in two's complement). For P-256, r and s are
/// each exactly 32 bytes in compact form, so the DER encoding is at most
/// 2 + 2 + 33 + 2 + 33 = 72 bytes.
///
/// The output length is bounded by P-256's fixed 32-byte r and s components:
/// the DER sequence content is at most 70 bytes and always fits in short-form
/// length encoding, so conversion cannot fail for this input type.
fn compact_to_der(compact: &[u8; 64]) -> Vec<u8> {
    let r = &compact[..32];
    let s = &compact[32..];

    // Strip leading zero bytes then re-add a single 0x00 if high-bit is set.
    let r_enc = encode_der_integer(r);
    let s_enc = encode_der_integer(s);

    // INTEGER tag + length + value for r and s.
    let r_tlv_len = 2 + r_enc.len();
    let s_tlv_len = 2 + s_enc.len();
    let seq_content_len = r_tlv_len + s_tlv_len;

    let mut der = Vec::with_capacity(2 + seq_content_len);
    der.push(0x30); // SEQUENCE tag
    der.push(seq_content_len as u8);
    der.push(0x02); // INTEGER tag for r
    der.push(r_enc.len() as u8);
    der.extend_from_slice(&r_enc);
    der.push(0x02); // INTEGER tag for s
    der.push(s_enc.len() as u8);
    der.extend_from_slice(&s_enc);

    der
}

/// Encode a big-endian unsigned integer as a DER INTEGER value (no tag/length).
///
/// Strips leading zero bytes, then prepends 0x00 if the high bit of the first
/// byte is set (two's complement positive sign). Per P-256, the value is at
/// most 32 bytes; after stripping leading zeros the minimum is 1 byte.
fn encode_der_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zeros (but keep at least one byte).
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        // DER integer 0 encodes as `02 01 00`; keep one byte.
        None => &bytes[bytes.len() - 1..],
    };
    // Prepend 0x00 if high bit is set.
    if stripped[0] & 0x80 != 0 {
        let mut out = Vec::with_capacity(stripped.len() + 1);
        out.push(0x00);
        out.extend_from_slice(stripped);
        out
    } else {
        stripped.to_vec()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(
        clippy::panic,
        reason = "test-only: panics are the correct failure mode"
    )]

    use super::*;

    // ── Fixture constants ─────────────────────────────────────────────────
    //
    // Source: OZ `stellar-contracts` v0.7.1 SHA `3f81125`
    // `examples/multisig-smart-account/webauthn-verifier/src/test.rs:64-93`
    // (the `verify_success` test).
    //
    // The fixture uses a software secp256r1 keypair derived from a fixed
    // 32-byte secret-key seed (bytes 33-64 of the test_rs file's `sign` fn,
    // test.rs:24-27). The challenge is the 32-byte value `payload` at
    // test.rs:70-71. The authenticator_data has flags `UP | UV | BE | BS`
    // (0x01 | 0x04 | 0x08 | 0x10 = 0x1D; test.rs:79-82). The rp_id_hash is
    // 32 zero bytes (authenticator_data[0..32] in encode_authenticator_data;
    // test.rs:45-48).
    //
    // The wallet test reconstructs the signature at test time using the OZ
    // fixture's secret seed: `sign_fixture` (below) calls
    // `p256::ecdsa::SigningKey::sign_prehash` over the message digest
    // `sha256(authenticator_data || sha256(client_data_json))`. The OZ
    // on-chain test (test.rs:23-42) does the same with its own `sign()` helper
    // — same (seed, message digest) input ⇒ same signature bytes.
    // This module requires a real cryptographic signature and reconstructs it
    // via the same software keypair the OZ fixture uses.
    //
    // The secret key seed (test.rs:24-27):
    //   [33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,
    //    49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]
    //
    // The challenge (test.rs:70-71 `payload`):
    //   0x4bb7a8b99609b0b8b1d534694bb1f31f129138a2f2a11f8e8702eedbb792922e

    // Secret key seed from OZ test.rs:24-27 (byte values 33..=64).
    const SECRET_KEY_SEED: [u8; 32] = [
        33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, 64,
    ];

    // Challenge from OZ test.rs:70-71.
    const CHALLENGE: [u8; 32] = [
        0x4b, 0xb7, 0xa8, 0xb9, 0x96, 0x09, 0xb0, 0xb8, 0xb1, 0xd5, 0x34, 0x69, 0x4b, 0xb1, 0xf3,
        0x1f, 0x12, 0x91, 0x38, 0xa2, 0xf2, 0xa1, 0x1f, 0x8e, 0x87, 0x02, 0xee, 0xdb, 0xb7, 0x92,
        0x92, 0x2e,
    ];

    // Authenticator data: 32 zero bytes (rp_id_hash) + flags byte + 4-byte
    // counter. Flags = UP | UV | BE | BS = 0x01 | 0x04 | 0x08 | 0x10 = 0x1D.
    // Source: OZ test.rs:45-49 (`encode_authenticator_data`).
    const AUTH_DATA_FLAGS: u8 = 0x01 | 0x04 | 0x08 | 0x10; // 0x1D

    // RP-ID-hash expected by step 3: all zeros (matches authenticator_data[0..32]
    // from the OZ fixture which uses `[0u8; 37]` with flags at index 32).
    const RP_ID_HASH: [u8; 32] = [0u8; 32];

    /// Build the full authenticator_data bytes matching the OZ fixture.
    fn make_auth_data(flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; 37];
        data[32] = flags;
        data
    }

    /// Build clientDataJSON matching the OZ fixture format.
    /// The challenge field is base64url-no-pad of the 32-byte CHALLENGE.
    fn make_client_data_json(challenge_b64: &str, type_field: &str) -> Vec<u8> {
        format!(
            r#"{{"type": "{type_field}", "challenge": "{challenge_b64}", "origin": "https://example.com", "crossOrigin": false}}"#
        )
        .into_bytes()
    }

    /// Derive the public key and produce a valid compact secp256r1 signature
    /// over the OZ fixture's message digest using the OZ fixture's secret key.
    ///
    /// This mirrors OZ test.rs:23-42 (`sign` function). The message digest is
    /// `sha256(authenticator_data || sha256(client_data_json))` per W3C steps
    /// 19+20 and on-chain `webauthn.rs:349-356`.
    fn sign_fixture(auth_data: &[u8], client_data_json: &[u8]) -> ([u8; 65], [u8; 64]) {
        use p256::SecretKey;
        use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let secret_key = SecretKey::from_slice(&SECRET_KEY_SEED).unwrap();
        let signing_key = SigningKey::from(&secret_key);
        let pubkey_point = secret_key.public_key().to_encoded_point(false);
        let pubkey_bytes = pubkey_point.as_bytes();
        let mut pubkey = [0u8; 65];
        pubkey.copy_from_slice(pubkey_bytes);

        // message_digest = sha256(auth_data || sha256(client_data_json))
        let client_hash = Sha256::digest(client_data_json);
        let mut msg = Vec::with_capacity(auth_data.len() + 32);
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&client_hash);
        let digest = Sha256::digest(&msg);

        let signature: Signature = signing_key.sign_prehash(&digest).unwrap();
        // Apply low-S normalisation (OZ test.rs:37; compact form required by
        // on-chain webauthn.rs which rejects high-S signatures).
        let signature = signature.normalize_s().unwrap_or(signature);
        let sig_bytes = signature.to_bytes();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        (pubkey, sig)
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    /// Verifies that a well-formed assertion passes all 7 steps.
    ///
    /// Uses the OZ test.rs verify_success fixture (test.rs:64-93) with a real
    /// secp256r1 signature produced by the same software keypair.
    #[test]
    fn pre_verify_accepts_valid_assertion() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        let result = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        );
        assert!(result.is_ok(), "valid assertion must pass: {result:?}");
    }

    /// Verifies that an assertion with the wrong RP-ID-hash is rejected (step 3).
    ///
    /// Feeds authenticator_data[0..32] that does not match rp_id_hash.
    /// Assert: `WrongRpId`.
    #[test]
    fn pre_verify_rejects_wrong_rp_id() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        // rp_id_hash is all 0xFF, but authenticator_data[0..32] is all 0x00.
        let wrong_rp_id = [0xFFu8; 32];

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &wrong_rp_id,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:wrong_rp_id",
            "expected wrong_rp_id sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::WrongRpId
                }
            ),
            "expected WrongRpId variant: {err:?}"
        );
    }

    /// Verifies that too-short authenticator_data is rejected before RP-ID comparison.
    ///
    /// Assert: `AuthDataTooShort`.
    #[test]
    fn pre_verify_rejects_auth_data_too_short() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        let full_auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, sig) = sign_fixture(&full_auth_data, &client_data);
        let short_auth_data = [0u8; 36];

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &short_auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:auth_data_too_short",
            "expected auth_data_too_short sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::AuthDataTooShort
                }
            ),
            "expected AuthDataTooShort variant: {err:?}"
        );
    }

    /// Verifies that an assertion with UP bit unset is rejected (step 4).
    ///
    /// Sets authenticator_data[32] with UP cleared (bit 0 = 0).
    /// Assert: `UpUnset`.
    #[test]
    fn pre_verify_rejects_up_unset() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        // UP = bit 0, clear it; keep UV | BE | BS.
        let flags_no_up = AUTH_DATA_FLAGS & !0x01;
        let auth_data = make_auth_data(flags_no_up);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:up_unset",
            "expected up_unset sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::UpUnset
                }
            ),
            "expected UpUnset variant: {err:?}"
        );
    }

    /// Verifies that an assertion with UV bit unset is rejected (step 5).
    ///
    /// Sets authenticator_data[32] with UV cleared (bit 2 = 0).
    /// Assert: `UvUnset`.
    #[test]
    fn pre_verify_rejects_uv_unset() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        // UV = bit 2, clear it; keep UP | BE | BS.
        let flags_no_uv = AUTH_DATA_FLAGS & !0x04;
        let auth_data = make_auth_data(flags_no_uv);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:uv_unset",
            "expected uv_unset sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::UvUnset
                }
            ),
            "expected UvUnset variant: {err:?}"
        );
    }

    /// Verifies that an assertion with BE=0, BS=1 is rejected (step 6).
    ///
    /// Sets authenticator_data[32] with BE cleared and BS set
    /// (`flags & 0x18 == 0x10`). Assert: `BeBsInvalid`.
    #[test]
    fn pre_verify_rejects_be_bs_invalid() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        // BE = bit 3 (0x08), BS = bit 4 (0x10).
        // Clear BE, set BS: flags = UP | UV | BS = 0x01 | 0x04 | 0x10 = 0x15.
        let flags_be0_bs1 = 0x01 | 0x04 | 0x10u8;
        let auth_data = make_auth_data(flags_be0_bs1);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:be_bs_invalid",
            "expected be_bs_invalid sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::BeBsInvalid
                }
            ),
            "expected BeBsInvalid variant: {err:?}"
        );
    }

    /// Verifies that an assertion with a mismatched challenge is rejected (step 2).
    ///
    /// Sets clientDataJSON.challenge to a different base64url value.
    /// Assert: `ChallengeMismatch`.
    #[test]
    fn pre_verify_rejects_challenge_mismatch() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        // Supply a DIFFERENT challenge (all-zeroes) while keeping the
        // clientDataJSON unchanged (which contains CHALLENGE's b64url).
        let wrong_challenge = [0u8; 32];

        let err = pre_verify_assertion(
            &wrong_challenge,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:challenge_mismatch",
            "expected challenge_mismatch sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::ChallengeMismatch
                }
            ),
            "expected ChallengeMismatch variant: {err:?}"
        );
    }

    /// Verifies that an assertion with a tampered signature is rejected (step 7).
    ///
    /// Reconstructs a valid signature, flips one bit, then asserts the
    /// secp256r1 verifier rejects it via `WebAuthnInvalidReason::SignatureInvalid`.
    /// This is the cryptographic gate's fail-closed coverage: a regression
    /// that silently bypassed `COSEKey::verify_signature` would surface here.
    #[test]
    fn pre_verify_rejects_signature_invalid() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        let client_data = make_client_data_json(&challenge_b64, "webauthn.get");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, mut sig) = sign_fixture(&auth_data, &client_data);

        // Flip a single bit in the signature; verification must fail closed.
        sig[0] ^= 0x01;

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:signature_invalid",
            "expected signature_invalid sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::SignatureInvalid
                }
            ),
            "expected SignatureInvalid variant: {err:?}"
        );
    }

    /// Verifies that an assertion with the wrong `type` field is rejected (step 1).
    ///
    /// W3C step 11 requires `clientDataJSON.type == "webauthn.get"`; on-chain
    /// `webauthn.rs:121-126` enforces the same. Feeds `"webauthn.create"` and
    /// asserts `WebAuthnInvalidReason::WrongType`.
    #[test]
    fn pre_verify_rejects_wrong_type() {
        let challenge_b64 = URL_SAFE_NO_PAD.encode(CHALLENGE);
        // `webauthn.create` is the registration ceremony's type — wrong for an
        // authentication assertion.
        let client_data = make_client_data_json(&challenge_b64, "webauthn.create");
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:wrong_type",
            "expected wrong_type sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::WrongType
                }
            ),
            "expected WrongType variant: {err:?}"
        );
    }

    /// Verifies that a clientDataJSON missing the `challenge` field is rejected.
    ///
    /// Asserts `WebAuthnInvalidReason::MalformedClientDataJson`. Exercises the
    /// `serde_json::from_slice` parse-failure branch at
    /// `parse_client_data_type_and_challenge`. Serde-derived parsing is used
    /// for soundness against escape sequences, Unicode escapes, and
    /// nested-string collisions that hand-rolled scanners mishandle.
    #[test]
    fn pre_verify_rejects_malformed_client_data_json() {
        // clientDataJSON missing the `challenge` field — the serde derive
        // requires it, so deserialisation fails with `MalformedClientDataJson`.
        let client_data = br#"{"type": "webauthn.get", "origin": "https://example.com"}"#.to_vec();
        let auth_data = make_auth_data(AUTH_DATA_FLAGS);
        let (pubkey, sig) = sign_fixture(&auth_data, &client_data);

        let err = pre_verify_assertion(
            &CHALLENGE,
            &pubkey,
            &auth_data,
            &client_data,
            &sig,
            &RP_ID_HASH,
        )
        .unwrap_err();

        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:malformed_client_data_json",
            "expected malformed_client_data_json sub-code: {err:?}"
        );
        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::MalformedClientDataJson
                }
            ),
            "expected MalformedClientDataJson variant: {err:?}"
        );
    }
}
