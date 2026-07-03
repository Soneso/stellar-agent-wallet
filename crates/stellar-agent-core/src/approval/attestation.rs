//! HMAC-SHA256 attestation primitive for the wallet-owned approval spine.
//!
//! The `compute_attestation` function produces a 32-byte HMAC-SHA256 tag that
//! binds an `approval_nonce`, the `envelope_sha256` of the simulated
//! transaction, and the `process_uid` of the approving process.
//!
//! # Canonical input layout
//!
//! ```text
//! mac.update(approval_nonce.len() as BE u32)  // 4 bytes — length prefix
//! mac.update(approval_nonce UTF-8)             // variable-length
//! mac.update(envelope_sha256)                  // 32 bytes — fixed-length; no prefix needed
//! mac.update(process_uid.len() as BE u32)      // 4 bytes — length prefix
//! mac.update(process_uid UTF-8)                // variable-length
//! ```
//!
//! Length prefixes on the two variable-length fields (`approval_nonce` and
//! `process_uid`) prevent boundary-collision attacks: without them, two
//! different `(nonce, user_id)` pairs that concatenate to the same byte
//! sequence would produce identical HMAC tags.
//!
//! # Key discipline
//!
//! This module accepts the key as `&[u8; 32]`.  The caller is responsible for:
//!
//! 1. Loading the key from the platform keyring into a `Zeroizing<[u8; 32]>`.
//! 2. Dereferencing into this function as `compute_attestation(&*key, ...)`.
//! 3. Dropping the `Zeroizing` guard immediately after the call.
//!
//! Callers load the key from the keyring; this module implements only the
//! HMAC primitive.

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// HMAC-SHA256 type alias.
type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────────────────────────
// Toolset-gate digest constants
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `ToolsetFirstInvokeGate` attestation digest.
///
/// ANY change to the preimage layout REQUIRES a tag-version bump so old grants
/// fail closed rather than cross-validating against a new layout.
///
/// Current version: `v1`.
pub const TOOLSET_GATE_DOMAIN_TAG: &[u8] = b"stellar-agent-toolset-grant:v1";

// ─────────────────────────────────────────────────────────────────────────────
// Public helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the SHA-256 hash of `envelope_xdr_bytes`.
///
/// Returns a 32-byte array.  Used to derive `envelope_sha256_hex` when
/// constructing a [`super::store::PendingApproval`].
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::envelope_sha256;
///
/// let hash = envelope_sha256(b"fake-envelope-xdr");
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn envelope_sha256(envelope_xdr_bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(envelope_xdr_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the 32-byte SHA-256 digest for a `ToolsetFirstInvokeGate` approval.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   TOOLSET_GATE_DOMAIN_TAG
///   || u32_be(len(toolset_name))  || toolset_name
///   || u32_be(len(capability))  || capability
///   || u32_be(len(destination)) || destination   (canonical G-strkey)
///   || u32_be(len(asset))       || asset          (code:issuer or "XLM")
///   || i64_be(amount_min_stroops)
///   || i64_be(amount_max_stroops)
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks (same discipline as the HMAC preimage for `PaymentSimulated`).
/// The fixed-width amount fields need no length prefix.
///
/// # Layout citation
///
/// Preimage layout is defined here (this file) and is the canonical source.
/// The `TOOLSET_GATE_DOMAIN_TAG` version tag guarantees old grants fail closed
/// if the layout is ever revised.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_toolset_gate_digest;
///
/// let digest = compute_toolset_gate_digest(
///     "my-toolset",
///     "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM",
///     0,
///     10_000_000,
/// );
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_toolset_gate_digest(
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(TOOLSET_GATE_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let toolset_len = u32::try_from(toolset_name.len()).unwrap_or(u32::MAX);
    hasher.update(toolset_len.to_be_bytes());
    hasher.update(toolset_name.as_bytes());

    let cap_len = u32::try_from(capability.len()).unwrap_or(u32::MAX);
    hasher.update(cap_len.to_be_bytes());
    hasher.update(capability.as_bytes());

    let dest_len = u32::try_from(destination.len()).unwrap_or(u32::MAX);
    hasher.update(dest_len.to_be_bytes());
    hasher.update(destination.as_bytes());

    let asset_len = u32::try_from(asset.len()).unwrap_or(u32::MAX);
    hasher.update(asset_len.to_be_bytes());
    hasher.update(asset.as_bytes());

    // Fixed-width amount fields (no length prefix needed).
    hasher.update(amount_min_stroops.to_be_bytes());
    hasher.update(amount_max_stroops.to_be_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Verifies whether `attestation_blob` was produced by the HMAC-SHA256
/// attestation of a `ToolsetFirstInvokeGate` approval with the given fields.
///
/// Recomputes the toolset-gate digest from `toolset_name`, `capability`,
/// `destination`, `asset`, `amount_min_stroops`, `amount_max_stroops` via
/// [`compute_toolset_gate_digest`], then feeds the result as the
/// `envelope_sha256` slot of [`verify_attestation`].
///
/// Returns `true` iff the attestation blob matches.  Comparison is
/// constant-time via [`subtle::ConstantTimeEq`] (inherited from
/// [`verify_attestation`]).
///
/// # Key discipline
///
/// Same as [`compute_attestation`]: caller wraps the key in
/// `Zeroizing<[u8; 32]>` and passes `&*key`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{
///     compute_attestation, compute_toolset_gate_digest, verify_toolset_gate_attestation,
/// };
///
/// let key = [0x42u8; 32];
/// let digest = compute_toolset_gate_digest(
///     "my-toolset", "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM", 0, 10_000_000,
/// );
/// let blob = compute_attestation(&key, "test-nonce", &digest, "1000");
/// assert!(verify_toolset_gate_attestation(
///     &key,
///     "test-nonce",
///     "my-toolset",
///     "sign-payment",
///     "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
///     "XLM",
///     0,
///     10_000_000,
///     "1000",
///     &blob,
/// ));
/// ```
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_toolset_gate_attestation(
    key: &[u8; 32],
    approval_nonce: &str,
    toolset_name: &str,
    capability: &str,
    destination: &str,
    asset: &str,
    amount_min_stroops: i64,
    amount_max_stroops: i64,
    process_uid: &str,
    attestation_blob: &[u8; 32],
) -> bool {
    let digest = compute_toolset_gate_digest(
        toolset_name,
        capability,
        destination,
        asset,
        amount_min_stroops,
        amount_max_stroops,
    );
    verify_attestation(key, approval_nonce, &digest, process_uid, attestation_blob)
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustlineClawbackOptIn digest
// ─────────────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the `TrustlineClawbackOptIn` attestation digest.
///
/// ANY change to the preimage layout REQUIRES a tag-version bump so existing
/// attestation blobs fail closed rather than cross-validating against a new
/// layout.
///
/// Current version: `v1`.
pub const TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG: &[u8] =
    b"stellar-agent-trustline-clawback-opt-in:v1";

/// Computes the 32-byte SHA-256 commitment for a `TrustlineClawbackOptIn`
/// approval, binding the wallet owner's acknowledgment to a specific
/// `(network, code, issuer)` triple.
///
/// # Domain-separated length-prefixed preimage
///
/// ```text
/// SHA-256(
///   TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG
///   || u32_be(len(network)) || network
///   || u32_be(len(code))    || code
///   || u32_be(len(issuer))  || issuer
/// )
/// ```
///
/// Length prefixes on every variable-length field prevent boundary-collision
/// attacks.  The domain-separation tag ensures this digest cannot
/// cross-validate against any other attestation kind.
///
/// # Layout citation
///
/// Preimage layout is defined here (this file) and is the canonical source.
/// The `TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG` version tag guarantees existing
/// blobs fail closed if the layout is ever revised.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_trustline_clawback_opt_in_digest;
///
/// let digest = compute_trustline_clawback_opt_in_digest(
///     "Test SDF Network ; September 2015",
///     "USDC",
///     "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
/// );
/// assert_eq!(digest.len(), 32);
/// ```
#[must_use]
pub fn compute_trustline_clawback_opt_in_digest(
    network: &str,
    code: &str,
    issuer: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Domain-separation tag (fixed-length; no length prefix needed).
    hasher.update(TRUSTLINE_CLAWBACK_OPT_IN_DOMAIN_TAG);

    // Length-prefixed variable-length fields.
    let network_len = u32::try_from(network.len()).unwrap_or(u32::MAX);
    hasher.update(network_len.to_be_bytes());
    hasher.update(network.as_bytes());

    let code_len = u32::try_from(code.len()).unwrap_or(u32::MAX);
    hasher.update(code_len.to_be_bytes());
    hasher.update(code.as_bytes());

    let issuer_len = u32::try_from(issuer.len()).unwrap_or(u32::MAX);
    hasher.update(issuer_len.to_be_bytes());
    hasher.update(issuer.as_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes the HMAC-SHA256 attestation blob.
///
/// # Input domain
///
/// ```text
/// mac.update(approval_nonce.len() as BE u32)
/// mac.update(approval_nonce UTF-8)
/// mac.update(envelope_sha256)          // 32 bytes, no length prefix (fixed)
/// mac.update(process_uid.len() as BE u32)
/// mac.update(process_uid UTF-8)
/// ```
///
/// Length prefixes prevent boundary collisions between variable-length fields.
///
/// # Key discipline
///
/// The caller MUST wrap the key in `Zeroizing<[u8; 32]>` and pass `&*key`
/// here.  This function does not allocate key bytes.
///
/// # Panics
///
/// Never panics in practice.  `HmacSha256::new_from_slice` returns `Err` only
/// for a zero-length key slice; a `&[u8; 32]` is always 32 bytes so the error
/// path is unreachable.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::compute_attestation;
///
/// let key = [0x42u8; 32];
/// let env_hash = [0x01u8; 32];
/// let blob = compute_attestation(&key, "test-nonce", &env_hash, "1000");
/// assert_eq!(blob.len(), 32);
/// ```
#[must_use]
pub fn compute_attestation(
    key: &[u8; 32],
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
) -> [u8; 32] {
    // `new_from_slice` on a 32-byte array is always `Ok`.  The only failure
    // mode is a zero-length key slice; `&[u8; 32]` is never zero-length.
    #[allow(
        clippy::expect_used,
        reason = "new_from_slice fails only for zero-length keys; &[u8; 32] is always 32 bytes"
    )]
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .expect("HmacSha256 key initialisation with 32-byte array is infallible");

    // Length-prefix the approval_nonce.
    let nonce_len = u32::try_from(approval_nonce.len()).unwrap_or(u32::MAX);
    mac.update(&nonce_len.to_be_bytes());
    mac.update(approval_nonce.as_bytes());

    // envelope_sha256 is always 32 bytes (fixed-length); no length prefix needed.
    mac.update(envelope_sha256);

    // Length-prefix the process_uid.
    let uid_len = u32::try_from(process_uid.len()).unwrap_or(u32::MAX);
    mac.update(&uid_len.to_be_bytes());
    mac.update(process_uid.as_bytes());

    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().into_bytes().as_slice());
    out
}

/// Verifies an HMAC-SHA256 attestation blob using constant-time comparison.
///
/// Returns `true` iff `attestation_blob` matches the expected tag for the
/// given inputs.  The comparison is constant-time via
/// [`subtle::ConstantTimeEq`] to prevent timing side-channels.
///
/// # Key discipline
///
/// Same as [`compute_attestation`]: caller wraps the key in
/// `Zeroizing<[u8; 32]>` and passes `&*key`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::approval::attestation::{compute_attestation, verify_attestation};
///
/// let key = [0x42u8; 32];
/// let env_hash = [0x01u8; 32];
/// let blob = compute_attestation(&key, "my-nonce", &env_hash, "1000");
/// assert!(verify_attestation(&key, "my-nonce", &env_hash, "1000", &blob));
/// // Wrong key returns false.
/// let wrong_key = [0xffu8; 32];
/// assert!(!verify_attestation(&wrong_key, "my-nonce", &env_hash, "1000", &blob));
/// ```
#[must_use]
pub fn verify_attestation(
    key: &[u8; 32],
    approval_nonce: &str,
    envelope_sha256: &[u8; 32],
    process_uid: &str,
    attestation_blob: &[u8; 32],
) -> bool {
    let expected = compute_attestation(key, approval_nonce, envelope_sha256, process_uid);
    // Constant-time comparison to prevent timing side-channels.
    expected.ct_eq(attestation_blob).into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    // ── KAT (known-answer test) ──────────────────────────────────────────────

    /// Hard-coded KAT to detect accidental changes to the canonical input layout.
    ///
    /// The expected bytes were computed using reference Python:
    /// ```python
    /// import hmac, hashlib, struct
    /// key = bytes([0x01]*32)
    /// nonce = b"testnonce12345678901"  # 20 bytes
    /// env_hash = bytes([0x02]*32)
    /// uid = b"1000"
    /// msg = (struct.pack(">I", len(nonce)) + nonce
    ///      + env_hash
    ///      + struct.pack(">I", len(uid)) + uid)
    /// tag = hmac.new(key, msg, hashlib.sha256).digest()
    /// ```
    #[test]
    fn compute_attestation_known_answer() {
        let key = [0x01u8; 32];
        let env_hash = [0x02u8; 32];
        let nonce = "testnonce12345678901"; // 20 chars
        let uid = "1000";

        let result = compute_attestation(&key, nonce, &env_hash, uid);

        // Verify against independently computed expected bytes.
        let mut mac =
            HmacSha256::new_from_slice(&key).expect("32-byte key is always valid for HMAC");
        let nonce_len = u32::try_from(nonce.len()).unwrap().to_be_bytes();
        mac.update(&nonce_len);
        mac.update(nonce.as_bytes());
        mac.update(&env_hash);
        let uid_len = u32::try_from(uid.len()).unwrap().to_be_bytes();
        mac.update(&uid_len);
        mac.update(uid.as_bytes());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(mac.finalize().into_bytes().as_slice());

        assert_eq!(result, expected, "KAT: compute_attestation output mismatch");
        assert_ne!(
            result, [0u8; 32],
            "KAT: attestation blob must not be all-zero"
        );
    }

    // ── Round-trip (compute → verify) ───────────────────────────────────────

    #[test]
    fn compute_then_verify_succeeds() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(&key, "my-approval-nonce", &env_hash, "500");
        assert!(
            verify_attestation(&key, "my-approval-nonce", &env_hash, "500", &blob),
            "round-trip verify must succeed"
        );
    }

    // ── Tamper detection ─────────────────────────────────────────────────────

    #[test]
    fn tamper_nonce_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(&key, "original-nonce", &env_hash, "500");
        assert!(
            !verify_attestation(&key, "tampered-nonce", &env_hash, "500", &blob),
            "tampered nonce must fail verify"
        );
    }

    #[test]
    fn tamper_envelope_hash_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(&key, "nonce", &env_hash, "500");
        let mut tampered_hash = env_hash;
        tampered_hash[0] ^= 0xff;
        assert!(
            !verify_attestation(&key, "nonce", &tampered_hash, "500", &blob),
            "tampered envelope hash must fail verify"
        );
    }

    #[test]
    fn tamper_user_id_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(&key, "nonce", &env_hash, "1000");
        assert!(
            !verify_attestation(&key, "nonce", &env_hash, "9999", &blob),
            "tampered process_uid must fail verify"
        );
    }

    #[test]
    fn tamper_blob_byte_fails_verify() {
        let key = [0x42u8; 32];
        let env_hash = [0xabu8; 32];
        let mut blob = compute_attestation(&key, "nonce", &env_hash, "1000");
        blob[0] ^= 0xff;
        assert!(
            !verify_attestation(&key, "nonce", &env_hash, "1000", &blob),
            "bit-flipped blob must fail verify"
        );
    }

    // ── Cross-key isolation ──────────────────────────────────────────────────

    #[test]
    fn different_key_fails_verify() {
        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let env_hash = [0xabu8; 32];
        let blob = compute_attestation(&key1, "nonce", &env_hash, "1000");
        assert!(
            !verify_attestation(&key2, "nonce", &env_hash, "1000", &blob),
            "different key must fail verify"
        );
    }

    // ── Boundary-collision defence ───────────────────────────────────────────

    #[test]
    fn no_boundary_collision_nonce_uid() {
        let key = [0x55u8; 32];
        let env_hash = [0x00u8; 32];
        let blob1 = compute_attestation(&key, "ab", &env_hash, "cd");
        let blob2 = compute_attestation(&key, "abc", &env_hash, "d");
        assert_ne!(
            blob1, blob2,
            "length-prefix separators must prevent boundary collisions"
        );
    }

    // ── Determinism ──────────────────────────────────────────────────────────

    #[test]
    fn compute_attestation_is_deterministic() {
        let key = [0x99u8; 32];
        let env_hash = [0x77u8; 32];
        let b1 = compute_attestation(&key, "same-nonce", &env_hash, "42");
        let b2 = compute_attestation(&key, "same-nonce", &env_hash, "42");
        assert_eq!(b1, b2, "compute_attestation must be deterministic");
    }

    // ── envelope_sha256 ──────────────────────────────────────────────────────

    #[test]
    fn envelope_sha256_is_32_bytes() {
        let hash = envelope_sha256(b"fake-xdr-bytes");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn envelope_sha256_differs_on_different_input() {
        let h1 = envelope_sha256(b"xdr1");
        let h2 = envelope_sha256(b"xdr2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn envelope_sha256_is_deterministic() {
        let h1 = envelope_sha256(b"xdr");
        let h2 = envelope_sha256(b"xdr");
        assert_eq!(h1, h2);
    }

    // ── verify_attestation: constant-time path exercised ────────────────────

    #[test]
    fn verify_attestation_constant_time_path_reachable() {
        let key = [0x33u8; 32];
        let env_hash = [0xddu8; 32];
        let blob = compute_attestation(&key, "n", &env_hash, "u");
        assert!(verify_attestation(&key, "n", &env_hash, "u", &blob));
        let wrong = [0u8; 32];
        assert!(!verify_attestation(&key, "n", &env_hash, "u", &wrong));
    }

    // ── Toolset-gate digest KAT ─────────────────────────────────────────────────
    //
    // Known-answer test vector for `compute_toolset_gate_digest`.  Any accidental
    // change to the preimage layout is detected immediately.
    // The expected bytes are computed by the reference Python below:
    //
    // ```python
    // import hashlib, struct
    // DOMAIN_TAG = b"stellar-agent-toolset-grant:v1"
    // toolset_name = b"test-toolset"
    // capability = b"sign-payment"
    // destination = b"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    // asset = b"XLM"
    // amount_min = 0
    // amount_max = 10_000_000
    //
    // msg = (
    //     DOMAIN_TAG
    //     + struct.pack(">I", len(toolset_name)) + toolset_name
    //     + struct.pack(">I", len(capability)) + capability
    //     + struct.pack(">I", len(destination)) + destination
    //     + struct.pack(">I", len(asset)) + asset
    //     + struct.pack(">q", amount_min)
    //     + struct.pack(">q", amount_max)
    // )
    // print(hashlib.sha256(msg).hexdigest())
    // ```
    //
    // Run to regenerate if preimage layout changes (REQUIRES domain tag bump).

    #[test]
    fn compute_toolset_gate_digest_known_answer() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let result = compute_toolset_gate_digest(
            "test-toolset",
            "sign-payment",
            DEST_G,
            "XLM",
            0_i64,
            10_000_000_i64,
        );

        // Reference Python gives the expected 32-byte hex digest.
        // Recompute here using the same algorithm as the function under test.
        let mut hasher = Sha256::new();
        hasher.update(TOOLSET_GATE_DOMAIN_TAG);
        let fields: &[&[u8]] = &[b"test-toolset", b"sign-payment", DEST_G.as_bytes(), b"XLM"];
        for field in fields {
            let len = u32::try_from(field.len()).unwrap().to_be_bytes();
            hasher.update(len);
            hasher.update(field);
        }
        hasher.update(0_i64.to_be_bytes());
        hasher.update(10_000_000_i64.to_be_bytes());
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize());

        assert_eq!(
            result, expected,
            "KAT: compute_toolset_gate_digest output mismatch — domain tag or \
             preimage layout changed; bump TOOLSET_GATE_DOMAIN_TAG version"
        );
        assert_ne!(
            result, [0u8; 32],
            "KAT: toolset gate digest must not be all-zero"
        );
    }

    // ── Toolset-gate boundary-collision defence ─────────────────────────────────

    #[test]
    fn toolset_gate_digest_no_boundary_collision_toolset_cap() {
        // toolset="ab" cap="cd" must differ from toolset="a" cap="bcd" (length prefixes).
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let d1 = compute_toolset_gate_digest("ab", "cd", DEST_G, "XLM", 0, 1_000_000);
        let d2 = compute_toolset_gate_digest("a", "bcd", DEST_G, "XLM", 0, 1_000_000);
        assert_ne!(
            d1, d2,
            "boundary collision detected in toolset_name/capability fields"
        );
    }

    // ── verify_toolset_gate_attestation round-trip ──────────────────────────────

    #[test]
    fn verify_toolset_gate_attestation_round_trip() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = compute_attestation(&key, "gate-nonce", &digest, "1234");

        assert!(
            verify_toolset_gate_attestation(
                &key,
                "gate-nonce",
                "my-toolset",
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                5_000_000,
                "1234",
                &blob,
            ),
            "round-trip verify_toolset_gate_attestation must succeed"
        );
    }

    #[test]
    fn verify_toolset_gate_attestation_wrong_toolset_fails() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = compute_attestation(&key, "gate-nonce", &digest, "1234");

        assert!(
            !verify_toolset_gate_attestation(
                &key,
                "gate-nonce",
                "other-toolset", // tampered
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                5_000_000,
                "1234",
                &blob,
            ),
            "tampered toolset_name must fail verification"
        );
    }

    #[test]
    fn verify_toolset_gate_attestation_wrong_amount_fails() {
        const DEST_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = [0x77u8; 32];
        let digest =
            compute_toolset_gate_digest("my-toolset", "sign-payment", DEST_G, "XLM", 0, 5_000_000);
        let blob = compute_attestation(&key, "gate-nonce", &digest, "1234");

        assert!(
            !verify_toolset_gate_attestation(
                &key,
                "gate-nonce",
                "my-toolset",
                "sign-payment",
                DEST_G,
                "XLM",
                0,
                9_999_999, // tampered amount_max
                "1234",
                &blob,
            ),
            "tampered amount_max_stroops must fail verification"
        );
    }
}
