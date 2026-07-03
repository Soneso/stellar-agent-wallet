//! DER → compact + low-S signature normalisation for the WebAuthn signing path.
//!
//! Receives a DER-encoded ECDSA-secp256r1 signature from the platform
//! authenticator and produces the 64-byte compact `r ‖ s` representation
//! (big-endian, low-S canonical) consumed by the External-arm encoders at
//! `webauthn/sig_data.rs`.
//!
//! # Pipeline
//!
//! 1. Parse DER via `p256::ecdsa::Signature::from_der`. The DER decoder
//!    delegates to the `der 0.7.10` crate, which enforces:
//!    - SEQUENCE outer tag (0x30).
//!    - Two INTEGER components (no extra trailing bytes).
//!    - Minimal length encoding.
//!    - No negative integers (sign bit = 0).
//!    - Each integer ≤ 32 bytes (P-256 field size).
//!
//! 2. Normalise s via `Signature::normalize_s` per BIP-0062 / RFC 6979 §4
//!    (low-S canonical form): if s > n/2 replace with n − s. Returns `None`
//!    if already low-S; the `was_high_s_normalised` boolean is `Some(_)`.
//!
//! 3. Serialise to 64-byte compact via `Signature::to_bytes` — 32-byte
//!    big-endian r followed by 32-byte big-endian s, matching the
//!    OpenZeppelin smart-account on-chain wire format
//!    (`signature: BytesN<64>`).
//!    Canonical source: `ecdsa` crate, `Signature::to_bytes`.
//!
//! # Why low-S off-chain
//!
//! The on-chain OpenZeppelin verifier calls
//! `e.crypto().secp256r1_verify(...)` which delegates to the Soroban host
//! at `soroban-env-host-25.0.1/src/crypto/mod.rs:91-109`
//! (`secp256r1_verify_signature` → `p256::ecdsa::VerifyingKey::verify_prehash`).
//! `verify_prehash` accepts both low-S and high-S signatures — low-S is
//! NOT enforced on-chain at this surface. The wallet
//! enforces low-S off-chain as malleability hardening (a high-S signature
//! has a low-S twin that produces an identical commitment, allowing
//! replay-flavoured attacks at upstream systems that don't track
//! signature uniqueness).

use p256::ecdsa::Signature;

use crate::SaError;
use crate::error::WebAuthnInvalidReason;

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// 64-byte compact ECDSA-secp256r1 signature (raw r ‖ s, big-endian, low-S
/// canonical) ready for the External-arm `WebAuthnSigData::signature` field.
///
/// The newtype documents the invariant — low-S canonical — so call-sites
/// that accept `&NormalisedSignature` are self-documenting. Using a newtype
/// rather than a bare `[u8; 64]` also prevents inadvertently mixing a
/// non-normalised compact array into the External-arm pipeline.
///
/// Wire format matches `signature: BytesN<64>` in the OpenZeppelin
/// smart-account contract.
/// Serialisation layout: bytes 0..32 = r (big-endian), bytes 32..64 = s (big-endian).
/// Canonical source: `ecdsa` crate, `Signature::to_bytes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalisedSignature([u8; 64]);

impl NormalisedSignature {
    /// Returns the inner 64-byte compact representation.
    ///
    /// Bytes 0..32 are r (big-endian); bytes 32..64 are s (big-endian, low-S
    /// canonical). Canonical source: `ecdsa` crate, `Signature::to_bytes`.
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

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Normalise a DER-encoded ECDSA-secp256r1 signature to a 64-byte compact
/// representation (32-byte big-endian r ‖ 32-byte big-endian s) with low-S
/// enforced.
///
/// Returns the compact bytes and a `was_high_s_normalised` boolean — `true`
/// iff the input had `s > n/2` and was replaced with `n - s`. The boolean
/// is consumed by the audit-log emission site (see SECURITY below).
///
/// # Errors
///
/// Returns `SaError::WebAuthnAssertionInvalid { reason: WebAuthnInvalidReason::SignatureInvalid }`
/// on DER parse failure. Failures are intentionally collapsed to a single
/// sub-code (see intentional-collapse note in module rustdoc). This includes:
/// - Truncated SEQUENCE.
/// - Wrong outer tag (expected 0x30).
/// - Non-INTEGER components or extra trailing bytes.
/// - Malformed length encoding.
/// - Negative integers (sign bit set in high byte).
/// - INTEGER exceeding the P-256 field size (> 32 bytes).
///
/// # Security
///
/// This function MUST NOT log raw `der_signature` bytes, the parsed
/// `Signature`, the compact output, or any intermediate scalar. The
/// `SaPasskeySignatureNormalised` audit-log event emits only
/// `{ der_input_len, compact_output_len, was_high_s_normalised }` at the
/// call site; this function only returns the boolean to enable that
/// call-site emission.
///
/// # Reference cross-check
///
/// - `from_der` entry point: `ecdsa` crate, `Signature::from_der`.
/// - `normalize_s` low-S algorithm: `ecdsa` crate, `Signature::normalize_s`
///   (`is_high()` + negation `n − s`; BIP-0062 semantics).
/// - `to_bytes` compact format: `ecdsa` crate, `Signature::to_bytes`
///   (32-byte big-endian r ‖ 32-byte big-endian s).
/// - On-chain canonical wire format: the OpenZeppelin smart-account contract
///   (`signature: BytesN<64>`).
pub fn normalize_der_to_compact_low_s(
    der_signature: &[u8],
) -> Result<(NormalisedSignature, bool), SaError> {
    // Step 1: Parse DER.
    //
    // `Signature::from_der` delegates to the `der` crate's SEQUENCE + INTEGER
    // parser. The DER decoder enforces: outer 0x30 tag, two INTEGER components,
    // minimal length encoding, non-negative integers, each integer ≤ 32 bytes
    // (P-256 field size). Negative-path DER coverage is in `ecdsa` crate `der.rs`.
    let signature =
        Signature::from_der(der_signature).map_err(|_| SaError::WebAuthnAssertionInvalid {
            reason: WebAuthnInvalidReason::SignatureInvalid,
        })?;

    // Step 2: Normalise s.
    //
    // `ecdsa` crate `Signature::normalize_s`: returns `Some(normalised)` if
    // s > n/2 (high-S); `None` if already low-S. The negation `−s` computes
    // `n − s` in the scalar field (BIP-0062).
    // P-256 group order n:
    //   `ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`.
    let (normalised, was_high_s) = match signature.normalize_s() {
        Some(low_s) => (low_s, true),
        None => (signature, false),
    };

    // Step 3: Serialise to 64-byte compact.
    //
    // `ecdsa` crate `Signature::to_bytes`: output is bytes 0..32 = r (big-endian),
    // bytes 32..64 = s (big-endian). `C::FieldBytesSize::USIZE` for NistP256 = 32.
    // Matches the on-chain wire format `signature: BytesN<64>` in the
    // OpenZeppelin smart-account contract.
    let compact: [u8; 64] = normalised.to_bytes().into();

    Ok((NormalisedSignature(compact), was_high_s))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test-only")]
    #![allow(clippy::expect_used, reason = "test-only")]
    #![allow(clippy::panic, reason = "test-only")]

    // Cross-check vectors for the high-S and already-low-S cases, plus
    // negative-path vectors for malformed DER inputs.

    use proptest::prelude::*;

    use super::*;
    use crate::error::WebAuthnInvalidReason;

    // ── Helper ────────────────────────────────────────────────────────────────

    /// Decode a lowercase-hex string to a `Vec<u8>`, panicking on bad input.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // ── Cross-check vectors ───────────────────────────────────────────────

    /// Test Vector 1: high-S DER input; s == n − 1 (the largest valid high-S
    /// value). After normalisation s becomes `n − (n − 1) == 1`.
    ///
    /// P-256 group order n (`ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`
    /// at `p256-0.13.2/src/lib.rs:74`); leading 0x00 in DER INTEGER is the sign-bit
    /// indicator required when the high bit of the magnitude byte would be set.
    #[test]
    fn normalize_high_s_matches_kmp_vector_1() {
        // r = 0x010203...3132 (32 bytes)
        // s = n - 1 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550
        //   (leading 0x00 in DER because high bit of 0xff is set)
        let der = hex(
            "3045022001020304050607080910111213141516171819202122232425262728293031320221\
             00ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        );

        // Expected compact: r unchanged, s becomes 1 (n - (n-1) = 1)
        let expected_r = hex("0102030405060708091011121314151617181920212223242526272829303132");
        let expected_s = hex("0000000000000000000000000000000000000000000000000000000000000001");

        let (sig, was_high) =
            normalize_der_to_compact_low_s(&der).expect("vector 1: must parse successfully");

        assert!(
            was_high,
            "s == n - 1 is high-S; was_high_s_normalised must be true"
        );
        assert_eq!(
            &sig.as_bytes()[..32],
            expected_r.as_slice(),
            "r must be unchanged"
        );
        assert_eq!(
            &sig.as_bytes()[32..],
            expected_s.as_slice(),
            "s must be 1 after n - (n-1)"
        );
        assert_eq!(sig.as_bytes().len(), 64);
    }

    /// Test Vector 1b: already low-S DER input; s == 5 (well below n/2).
    ///
    /// No normalisation expected; `was_high_s_normalised` must be `false`.
    ///
    /// # Note on DER encoding
    ///
    /// The original reference vector uses a non-minimal DER encoding for the s INTEGER
    /// (`02 20 0000...0005` — 32 bytes with 31 unnecessary leading zeros). The
    /// `der 0.7.10` crate used by `p256::ecdsa::Signature::from_der` enforces
    /// strict DER minimal encoding and rejects this form per the DER standard.
    /// The semantically equivalent properly-minimal DER is constructed here via
    /// `Signature::from_scalars(r, s).to_der()`, which emits canonical DER.
    /// The cross-check is that the compact output matches the expected bytes
    /// (r unchanged, s = 5 padded to 32 big-endian bytes in the compact form).
    ///
    /// The reference signing flow uses a lenient DER parser;
    /// this is an intentional divergence (strict ≥ lenient for security).
    #[test]
    fn normalize_already_low_s_matches_kmp_vector_1b() {
        // r = 0x010203...3132 (32 bytes); s = 5.
        // Construct via from_scalars → to_der() to get canonical strict-DER.
        // The original reference vector uses non-minimal DER (02 20 0000...0005) which
        // strict `der 0.7.10` rejects; the minimal form is 02 01 05.
        let r_arr: [u8; 32] =
            hex("0102030405060708091011121314151617181920212223242526272829303132")
                .as_slice()
                .try_into()
                .expect("32 bytes");
        let s_arr: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 5;
            b
        };

        let sig = p256::ecdsa::Signature::from_scalars(r_arr, s_arr)
            .expect("valid scalar pair (r=0x01..32, s=5)");
        let der = sig.to_der();

        // Expected compact output: r unchanged, s = 5 (32 big-endian bytes).
        let expected_r = hex("0102030405060708091011121314151617181920212223242526272829303132");
        let expected_s = hex("0000000000000000000000000000000000000000000000000000000000000005");

        let (result, was_high) = normalize_der_to_compact_low_s(der.as_bytes())
            .expect("vector 1b: must parse successfully");

        assert!(
            !was_high,
            "s == 5 is low-S; was_high_s_normalised must be false"
        );
        assert_eq!(
            &result.as_bytes()[..32],
            expected_r.as_slice(),
            "r must be unchanged"
        );
        assert_eq!(
            &result.as_bytes()[32..],
            expected_s.as_slice(),
            "s must be 5 padded to 32 big-endian bytes"
        );
        assert_eq!(result.as_bytes().len(), 64);
    }

    // ── Malformed DER negative-path tests ────────────────────────────────────

    /// Negative-path: outer tag 0x31 instead of 0x30.
    #[test]
    fn reject_malformed_der_wrong_outer_tag() {
        let bad = hex("31450220010203040506070809");

        let err =
            normalize_der_to_compact_low_s(&bad).expect_err("outer tag 0x31 must be rejected");

        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::SignatureInvalid
                }
            ),
            "expected WebAuthnAssertionInvalid::SignatureInvalid, got: {err:?}",
        );
        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:signature_invalid",
        );
    }

    /// Negative-path: 3-byte DER (SEQUENCE header only, no INTEGER content).
    #[test]
    fn reject_short_der() {
        let bad = hex("300102");

        let err = normalize_der_to_compact_low_s(&bad).expect_err("3-byte DER must be rejected");

        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::SignatureInvalid
                }
            ),
            "expected WebAuthnAssertionInvalid::SignatureInvalid, got: {err:?}",
        );
        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:signature_invalid",
        );
    }

    /// Negative-path: truncated DER mid-INTEGER.
    #[test]
    fn reject_truncated_der() {
        let bad = hex("3045022001020304050607080910111213141516");

        let err = normalize_der_to_compact_low_s(&bad).expect_err("truncated DER must be rejected");

        assert!(
            matches!(
                err,
                SaError::WebAuthnAssertionInvalid {
                    reason: WebAuthnInvalidReason::SignatureInvalid
                }
            ),
            "expected WebAuthnAssertionInvalid::SignatureInvalid, got: {err:?}",
        );
        assert_eq!(
            err.wire_code(),
            "sa.webauthn_assertion_invalid:signature_invalid",
        );
    }

    // ── Boundary-value tests ─────────────────────────────────────────────────

    // P-256 group order n:
    //   ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    //
    // (n − 1) / 2 = 7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
    // (n + 1) / 2 = 7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9
    //
    // Boundary values verified against `ecdsa` crate `Signature::normalize_s` semantics.

    /// Boundary: s == (n − 1)/2, the largest LOW-S value — no normalisation.
    ///
    /// `ecdsa` crate `Signature::normalize_s`: `is_high()` returns false when
    /// s ≤ n/2, so the value is returned unchanged.
    #[test]
    fn normalize_s_at_half_order_minus_one_unchanged() {
        // r = 1 (the smallest valid non-zero scalar)
        let r_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        // s = (n − 1) / 2 = 7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
        let s_bytes = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
        let s_arr: [u8; 32] = s_bytes.as_slice().try_into().expect("32 bytes");

        let sig = p256::ecdsa::Signature::from_scalars(r_bytes, s_arr).expect("valid scalar pair");
        let der = sig.to_der();

        let (result, was_high) = normalize_der_to_compact_low_s(der.as_bytes())
            .expect("boundary value (n-1)/2 must parse");

        assert!(
            !was_high,
            "s == (n-1)/2 is the largest low-S value; must not be normalised"
        );
        assert_eq!(
            &result.as_bytes()[32..],
            s_bytes.as_slice(),
            "s must be unchanged"
        );
    }

    /// Boundary: s == (n + 1)/2, the smallest HIGH-S value — must normalise to (n − 1)/2.
    ///
    /// `ecdsa` crate `Signature::normalize_s`: `is_high()` returns true when
    /// s > n/2; negation produces `n - s`.
    #[test]
    fn normalize_s_at_half_order_plus_one_normalised() {
        let r_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        // s = (n + 1) / 2 = 7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9
        let s_high = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9");
        let s_high_arr: [u8; 32] = s_high.as_slice().try_into().expect("32 bytes");
        // After normalisation: n - s = (n-1)/2
        let s_low = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");

        let sig =
            p256::ecdsa::Signature::from_scalars(r_bytes, s_high_arr).expect("valid scalar pair");
        let der = sig.to_der();

        let (result, was_high) = normalize_der_to_compact_low_s(der.as_bytes())
            .expect("boundary value (n+1)/2 must parse");

        assert!(
            was_high,
            "s == (n+1)/2 is the smallest high-S value; must be normalised"
        );
        assert_eq!(
            &result.as_bytes()[32..],
            s_low.as_slice(),
            "normalised s must equal (n-1)/2",
        );
    }

    // ── Property tests ────────────────────────────────────────────────────────

    // P-256 scalar field maximum: n − 1
    // (ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550)
    // Used to clamp proptest-generated 32-byte values to valid non-zero scalars.

    /// Property: for any random valid (r, s) scalar pair, normalise produces a
    /// low-S compact output.
    ///
    /// Generates random 32-byte pairs, clamps them to the P-256 scalar field
    /// [1, n − 1] via `Signature::from_scalars`, converts to DER, and asserts
    /// that `normalize_der_to_compact_low_s` returns `Ok` with the s component
    /// ≤ n/2.
    ///
    /// 1024 iterations.
    #[test]
    fn property_any_valid_signature_produces_low_s_output() {
        // P-256 group order n/2 (the boundary for low-S):
        // 7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
        let half_order = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");

        proptest!(
            ProptestConfig::with_cases(1024),
            |(r_raw in prop::array::uniform32(1u8..), s_raw in prop::array::uniform32(1u8..))| {
                // Clamp to valid non-zero scalars: if from_scalars fails (e.g. value
                // is 0 or ≥ n), substitute a known-valid scalar to keep the test
                // productive without discarding too many cases.
                let sig = match p256::ecdsa::Signature::from_scalars(r_raw, s_raw) {
                    Ok(s) => s,
                    Err(_) => {
                        // The random bytes fell outside [1, n-1]; use a known-valid pair.
                        let mut r_valid = r_raw;
                        r_valid[0] &= 0x7f; // clear high bit to stay under n
                        r_valid[31] |= 0x01; // ensure non-zero
                        let mut s_valid = s_raw;
                        s_valid[0] &= 0x7f;
                        s_valid[31] |= 0x01;
                        match p256::ecdsa::Signature::from_scalars(r_valid, s_valid) {
                            Ok(s) => s,
                            Err(_) => return Ok(()), // skip truly degenerate cases
                        }
                    }
                };

                let der = sig.to_der();
                let (result, _) = normalize_der_to_compact_low_s(der.as_bytes())
                    .map_err(|e| TestCaseError::fail(format!("unexpected error: {e:?}")))?;

                // Assert s component is low-S: s ≤ n/2
                // Compare as big-endian 32-byte arrays (lexicographic ≡ numeric for same length).
                let s_out = &result.as_bytes()[32..];
                prop_assert!(
                    s_out <= half_order.as_slice(),
                    "s component must be ≤ n/2 after normalisation; got s = {s_out:?}",
                );
            }
        );
    }

    /// Property: DER round-trip via `sign_prehash` always produces a low-S output.
    ///
    /// For any signature produced by `sign_prehash`, the normalise function:
    /// 1. Parses the DER without error.
    /// 2. Returns a compact output with s ≤ n/2 (low-S canonical).
    /// 3. Returns compact bytes equal to the low-S normalised version of
    ///    `sig.to_bytes()` (the direct compact form). If the original sig was
    ///    already low-S, `was_high == false` and the bytes are identical to
    ///    `sig.to_bytes()`. If the original was high-S, `was_high == true` and
    ///    the bytes match `sig.normalize_s().unwrap().to_bytes()`.
    ///
    /// Note: `p256::ecdsa::SigningKey::sign_prehash` uses RFC 6979 but does NOT
    /// automatically enforce low-S — the resulting signature may be high-S.
    /// `normalize_der_to_compact_low_s` corrects this unconditionally.
    ///
    /// 1024 iterations.
    #[test]
    fn property_sign_prehash_roundtrip_produces_low_s() {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use rand_core::OsRng;

        // P-256 group order n/2 (boundary for low-S):
        // 7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
        let half_order = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");

        proptest!(
            ProptestConfig::with_cases(1024),
            |(prehash in prop::array::uniform32(any::<u8>()))| {
                // Generate a fresh signing key for each iteration.
                let signing_key = SigningKey::random(&mut OsRng);

                let sig: Signature = signing_key
                    .sign_prehash(&prehash)
                    .map_err(|e| TestCaseError::fail(format!("sign_prehash failed: {e:?}")))?;

                // Compute the expected low-S compact form directly:
                // if the sig is high-S, normalize_s() returns the corrected form;
                // otherwise the sig itself is the low-S form.
                let expected_low_s: [u8; 64] = sig
                    .normalize_s()
                    .unwrap_or(sig)
                    .to_bytes()
                    .into();

                // Round-trip through DER → normalise.
                let der = sig.to_der();
                let (normalised, _was_high) = normalize_der_to_compact_low_s(der.as_bytes())
                    .map_err(|e| TestCaseError::fail(format!("normalise failed: {e:?}")))?;

                // The s component of the normalised output must be low-S.
                let s_out = &normalised.as_bytes()[32..];
                prop_assert!(
                    s_out <= half_order.as_slice(),
                    "s component must be ≤ n/2 after normalisation",
                );

                // The normalised compact bytes must match the expected low-S form.
                prop_assert_eq!(
                    normalised.as_bytes(),
                    &expected_low_s,
                    "normalised bytes must match sig.normalize_s().unwrap_or(sig).to_bytes()",
                );
            }
        );
    }
}
