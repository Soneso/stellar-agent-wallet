//! Auth-digest computation for smart-account signing payloads.
//!
//! The auth digest binds the Soroban `signature_payload` to the
//! `context_rule_ids` that govern which on-chain authorisation rule is applied.
//! Signing the digest rather than the raw payload closes the rule-ID
//! downgrade attack (see [`compute_auth_digest`]).
//!
//! Key type: [`AuthDigest`].
//! Key function: [`compute_auth_digest`].
//!
//! # Producing the `context_rule_ids_xdr` argument
//!
//! Callers build the `context_rule_ids_xdr` argument via
//! [`super::rule_id::encode_context_rule_ids`], which produces the exact
//! byte layout the on-chain contract hashes
//! (`ScVal::Vec(Some(ScVec([ScVal::U32(...)])))`).  Hand-assembling these
//! bytes is a known silent-failure footgun — see the rustdoc on
//! [`compute_auth_digest`] for the byte-layout description.

use std::fmt;

use sha2::{Digest as _, Sha256};
use tracing::debug;

/// A 32-byte SHA-256 auth digest.
///
/// Produced by [`compute_auth_digest`].  The digest is the value that a signer
/// MUST sign instead of the raw `signature_payload` when authorising a
/// Soroban smart-account transaction that carries context rules.
///
/// The signing payload is bound to the context rules by computing
/// `sha256(signature_payload || context_rule_ids_xdr)`.  This closes the
/// rule-ID downgrade attack (by a malicious transaction sponsor), matching
/// the on-chain computation in OpenZeppelin `stellar-accounts` v0.7.1
/// in `smart_account/storage.rs`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::smart_account::auth_digest::{AuthDigest, compute_auth_digest};
///
/// let digest = compute_auth_digest(b"payload", b"rules-xdr");
/// let hex = digest.to_string();
/// assert_eq!(hex.len(), 64);
/// ```
///
/// # `#[non_exhaustive]` exemption
///
/// This is a `#[repr(transparent)]`-equivalent newtype over `[u8; 32]`.  The
/// 32-byte width is a cryptographic constant (SHA-256 output size) and is not
/// expected to grow.  External callers cannot construct `AuthDigest` via
/// struct-literal syntax because the single field is private; the only public
/// constructor is [`compute_auth_digest`].  Adding `#[non_exhaustive]` on a
/// tuple-struct with a private field provides no additional forward-compat
/// guarantee and is therefore omitted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthDigest([u8; 32]);

impl AuthDigest {
    /// Returns a reference to the underlying 32-byte digest array.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::smart_account::auth_digest::compute_auth_digest;
    ///
    /// let digest = compute_auth_digest(b"", b"");
    /// assert_eq!(digest.as_bytes().len(), 32);
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for AuthDigest {
    /// Formats the digest as 64 lowercase hex characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Computes the auth digest that binds a Soroban `signature_payload` to a set
/// of context-rule IDs.
///
/// Returns `sha256(signature_payload || context_rule_ids_xdr)`, matching the
/// OZ v0.7.1 on-chain computation.  Closes the rule-ID downgrade attack.
///
/// This is the preimage that off-chain signers MUST sign when authorising a
/// smart-account transaction governed by one or more context rules.  Signing
/// the raw `signature_payload` instead—without binding the rule IDs—is the
/// rule-ID downgrade vulnerability (exploited by a malicious
/// transaction sponsor).
///
/// # Failure mode if the primitive is skipped
///
/// A signer that signs the raw `signature_payload` instead of this digest
/// produces a signature the v0.7+ `stellar-accounts` contract rejects as
/// invalid during `__check_auth`.  The failure is on-chain at submission
/// time, not at digest-computation time — silent off-chain successes that
/// break on mainnet are the exact failure this primitive exists to prevent.
///
/// # Arguments
///
/// - `signature_payload`: The raw signing payload produced by the Soroban host.
///   32 bytes; the hash bytes of `HashIdPreimageSorobanAuthorization` as
///   computed by `Env::crypto().sha256()` in the guest environment.
/// - `context_rule_ids_xdr`: The XDR serialisation of
///   `AuthPayload::context_rule_ids` (a Soroban `Vec<u32>`).  MUST be the
///   exact bytes produced by `Vec<u32>::to_xdr(env)` in the Soroban guest
///   environment, which on the host side is the XDR encoding of an
///   `ScVal::Vec(Some(ScVec([ScVal::U32(id0), ScVal::U32(id1), ...])))` —
///   a 4-byte `SCV_VEC` discriminant (`0x00000010`), a 4-byte
///   `Option::Some` marker (`0x00000001`), a 4-byte big-endian element
///   count, then per element 4 bytes of `SCV_U32` discriminant
///   (`0x00000003`) followed by the 4-byte big-endian `u32` value.
///   Off-chain callers MUST produce these bytes via
///   [`super::rule_id::encode_context_rule_ids`]; hand-assembling a
///   length-prefixed `u32::to_be_bytes` sequence (or any other layout)
///   will compute a digest that passes [`compute_auth_digest`] but fails
///   on-chain verification, which is the silent-failure footgun this
///   primitive exists to prevent.  Layout verified against OpenZeppelin
///   `stellar-contracts` v0.7.1 (`smart_account/storage.rs`).
///
/// # Examples
///
/// ```
/// use stellar_agent_core::smart_account::auth_digest::compute_auth_digest;
///
/// // Known-answer test: sha256("") == the SHA-256 of the empty string.
/// let digest = compute_auth_digest(b"", b"");
/// assert_eq!(
///     digest.to_string(),
///     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
/// );
/// ```
///
/// # Panics
///
/// Never panics.  SHA-256 is infallible for all inputs.
#[must_use]
pub fn compute_auth_digest(signature_payload: &[u8], context_rule_ids_xdr: &[u8]) -> AuthDigest {
    let mut hasher = Sha256::new();
    hasher.update(signature_payload);
    hasher.update(context_rule_ids_xdr);
    let result = hasher.finalize();
    // INVARIANT: Sha256::finalize always produces exactly 32 bytes.
    // The array conversion is infallible; see sha2 docs.
    let bytes: [u8; 32] = result.into();
    let digest = AuthDigest(bytes);

    // Emits input byte-lengths and the computed digest at debug level.
    // The digest is one-way and does not reveal the preimage, so emitting
    // it at debug level does not leak the payload.
    // Raw `signature_payload` and `context_rule_ids_xdr` bytes are NOT logged;
    // they may contain secret Soroban auth-entry XDR and must never be emitted
    // at any log level.
    debug!(
        target: "stellar_agent_core::smart_account::auth_digest",
        payload_len = signature_payload.len(),
        rules_xdr_len = context_rule_ids_xdr.len(),
        digest = %digest,
        "computed auth digest"
    );

    digest
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    // -------------------------------------------------------------------------
    // Known-answer tests
    // -------------------------------------------------------------------------

    /// Verify that compute_auth_digest(b"", b"") equals sha256("") —
    /// the well-known SHA-256 of the empty string.
    #[test]
    fn empty_inputs_equal_sha256_of_empty_string() {
        let digest = compute_auth_digest(b"", b"");
        assert_eq!(
            digest.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Non-empty KAT: empty payload concatenated with the XDR of an empty
    /// rule-ID list (12-byte `SCV_VEC || Some || 0` preimage).  Ground
    /// truth: `sha256(00 00 00 10 00 00 00 01 00 00 00 00)` computed via
    /// `shasum -a 256` on the 12-byte preimage.
    #[test]
    fn kat_empty_payload_with_empty_rule_ids_xdr() {
        use super::super::rule_id::encode_context_rule_ids;
        let rules_xdr = encode_context_rule_ids(&[]).expect("empty list always encodes");
        let digest = compute_auth_digest(b"", &rules_xdr);
        assert_eq!(
            digest.to_string(),
            "eace280a4f3f1632588cbc4ae1535972fa47b4c4be4818fbf2f3be6fe94f1d4a"
        );
    }

    /// Non-empty KAT: empty payload concatenated with the XDR of
    /// `[ContextRuleId(7), ContextRuleId(42)]` (28-byte preimage).
    /// Ground truth: `sha256` over the 28-byte `ScVal::Vec(Some([U32(7),
    /// U32(42)]))` encoding verified against the `stellar-xdr` MCP
    /// `encode` tool.
    #[test]
    fn kat_empty_payload_with_two_rule_id_xdr() {
        use super::super::rule_id::{ContextRuleId, encode_context_rule_ids};
        let rules_xdr = encode_context_rule_ids(&[ContextRuleId::new(7), ContextRuleId::new(42)])
            .expect("small list always encodes");
        let digest = compute_auth_digest(b"", &rules_xdr);
        assert_eq!(
            digest.to_string(),
            "33cf3370bdaa74e231c1aefa27adb36c4bea56ff1e27e53ff9d5dd0766bf6549"
        );
    }

    /// Verify that concatenation order matters: payload then rule-IDs.
    #[test]
    fn payload_then_rule_ids_not_reversed() {
        // sha256("AB") != sha256("BA") — order is part of the binding.
        let forward = compute_auth_digest(b"A", b"B");
        let reversed = compute_auth_digest(b"B", b"A");
        assert_ne!(forward, reversed);
    }

    /// Verify that a non-empty payload produces a 64-character lowercase hex digest.
    /// The empty-string KAT above is the canonical known-answer test; this test
    /// only validates structural properties of the output format.
    #[test]
    fn known_non_empty_payload_is_64_char_hex() {
        let digest = compute_auth_digest(b"payload", b"rules");
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| "0123456789abcdef".contains(c)));
    }

    #[test]
    fn display_produces_64_lowercase_hex_chars() {
        let digest = compute_auth_digest(b"test", b"data");
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| "0123456789abcdef".contains(c)));
    }

    #[test]
    fn as_bytes_returns_32_bytes() {
        let digest = compute_auth_digest(b"hello", b"world");
        assert_eq!(digest.as_bytes().len(), 32);
    }

    #[test]
    fn copy_and_equality_semantics() {
        let a = compute_auth_digest(b"x", b"y");
        let b = a; // Copy
        assert_eq!(a, b);
    }

    // -------------------------------------------------------------------------
    // Property tests
    // -------------------------------------------------------------------------

    proptest! {
        /// Determinism: identical inputs always produce identical output.
        #[test]
        fn deterministic_same_inputs(
            payload in prop::collection::vec(any::<u8>(), 0..256),
            rules in prop::collection::vec(any::<u8>(), 0..256),
        ) {
            let d1 = compute_auth_digest(&payload, &rules);
            let d2 = compute_auth_digest(&payload, &rules);
            prop_assert_eq!(d1, d2);
        }

        /// Collision resistance (high probability): different inputs produce different output.
        /// SHA-256 collisions are computationally infeasible; this property verifies
        /// the implementation passes distinct inputs through, not that SHA-256 itself
        /// is collision-resistant.
        #[test]
        fn different_inputs_produce_different_output(
            payload_a in prop::collection::vec(any::<u8>(), 0..128),
            rules_a in prop::collection::vec(any::<u8>(), 0..128),
            payload_b in prop::collection::vec(any::<u8>(), 0..128),
            rules_b in prop::collection::vec(any::<u8>(), 0..128),
        ) {
            // Only assert inequality when the combined inputs differ.
            prop_assume!(
                payload_a != payload_b || rules_a != rules_b
            );
            let da = compute_auth_digest(&payload_a, &rules_a);
            let db = compute_auth_digest(&payload_b, &rules_b);
            prop_assert_ne!(da, db);
        }

        /// The auth digest changes when the payload changes, even if rules are the same.
        #[test]
        fn digest_changes_when_payload_changes(
            payload_a in prop::collection::vec(any::<u8>(), 1..128),
            payload_b in prop::collection::vec(any::<u8>(), 1..128),
            rules in prop::collection::vec(any::<u8>(), 0..128),
        ) {
            prop_assume!(payload_a != payload_b);
            let da = compute_auth_digest(&payload_a, &rules);
            let db = compute_auth_digest(&payload_b, &rules);
            prop_assert_ne!(da, db);
        }

        /// The auth digest changes when the rules change, even if payload is the same.
        /// This is the core property that closes the rule-ID downgrade attack: swapping rule IDs changes the digest.
        #[test]
        fn digest_changes_when_rules_change(
            payload in prop::collection::vec(any::<u8>(), 0..128),
            rules_a in prop::collection::vec(any::<u8>(), 1..128),
            rules_b in prop::collection::vec(any::<u8>(), 1..128),
        ) {
            prop_assume!(rules_a != rules_b);
            let da = compute_auth_digest(&payload, &rules_a);
            let db = compute_auth_digest(&payload, &rules_b);
            prop_assert_ne!(da, db);
        }
    }

    // -------------------------------------------------------------------------
    // Observability / log-redaction tests
    //
    // compute_auth_digest emits a debug-level event with input byte-lengths
    // and the output digest. The raw `signature_payload` and
    // `context_rule_ids_xdr` bytes must not appear in captured output — they
    // may contain secret XDR. These tests install a scoped subscriber that
    // captures every event and assert the invariant.
    // -------------------------------------------------------------------------

    use stellar_agent_test_support::{CaptureWriter, assert_no_secret_bytes};

    /// Installs a debug-level JSON subscriber writing to `writer` for the
    /// duration of `f`. `EnvFilter` is not used — the subscriber accepts
    /// every level so `debug!` events land in the capture. Release builds
    /// strip `debug!` at compile time via `release_max_level_info`; the
    /// redaction property still holds in release because no event is emitted.
    fn with_capture<F: FnOnce()>(writer: CaptureWriter, f: F) {
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(writer)
            .finish();
        tracing::subscriber::with_default(subscriber, f);
    }

    // These tests exercise the `debug!` call site inside `compute_auth_digest`.
    // In release profile the `tracing/release_max_level_info` feature strips
    // `debug!` / `trace!` at compile time, so the capture below would be empty
    // and the assertion-of-presence tests would fail.  The gate aligns with
    // tracing's release-strip condition (`cfg(debug_assertions)`).
    #[cfg(debug_assertions)]
    #[test]
    fn log_does_not_leak_payload_bytes() {
        let capture = CaptureWriter::new();
        // A payload chosen to be obviously recognisable if it were to appear.
        let payload = b"recognisable_payload_bytes_do_not_leak_me";
        let rules_xdr = b"recognisable_rules_xdr_do_not_leak_me";

        with_capture(capture.clone(), || {
            let _ = compute_auth_digest(payload, rules_xdr);
        });

        let captured = capture.captured_str();
        assert!(
            captured.contains("\"payload_len\":41"),
            "captured event should include payload length; got: {captured}"
        );
        assert!(
            captured.contains("\"rules_xdr_len\":37"),
            "captured event should include rules-xdr length; got: {captured}"
        );
        assert!(
            !captured.contains("recognisable_payload_bytes_do_not_leak_me"),
            "raw payload bytes must not appear in log: {captured}"
        );
        assert!(
            !captured.contains("recognisable_rules_xdr_do_not_leak_me"),
            "raw rules-xdr bytes must not appear in log: {captured}"
        );

        assert_no_secret_bytes(&capture.captured());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn log_digest_hex_is_present_and_64_chars() {
        let capture = CaptureWriter::new();
        with_capture(capture.clone(), || {
            let _ = compute_auth_digest(b"payload", b"rules");
        });

        let captured = capture.captured_str();
        // The digest field appears as "digest":"<64 hex chars>".
        let marker = "\"digest\":\"";
        let at = captured.find(marker).unwrap_or_else(|| {
            panic!("digest field missing from capture: {captured}");
        });
        let hex_start = at + marker.len();
        let hex_slice = &captured[hex_start..hex_start + 64];
        assert!(
            hex_slice.chars().all(|c| "0123456789abcdef".contains(c)),
            "digest hex is not 64 lowercase hex chars: {hex_slice}"
        );
    }
}
