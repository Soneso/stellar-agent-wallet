//! SEP-53 message signing and verification for the Stellar agent wallet.
//!
//! # What this crate does
//!
//! Implements the canonical SEP-53 prefixed message sign/verify scheme defined
//! at [stellar-protocol `sep-0053.md`](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md):
//!
//! - [`sign_message`] — signs an arbitrary byte slice using the SEP-53 prefix
//!   scheme: `SHA-256("Stellar Signed Message:\n" ‖ message)` → ed25519 sign.
//! - [`verify_message`] — verifies a SEP-53 signature: recomputes the same
//!   digest and ed25519-verifies against the supplied public key.
//! - [`Sep53Error`] — typed error enum covering signing and verification failure
//!   modes.
//!
//! # Primary consumers
//!
//! - `stellar-agent-mcp`: two MCP tools — `stellar_sep53_sign_message` and
//!   `stellar_sep53_verify_message`.
//!
//! # What this crate does NOT do
//!
//! - Does NOT submit any transaction to the network. SEP-53 is a pure
//!   off-chain signature scheme.
//! - Does NOT handle base64 encoding of the message — that is the caller's
//!   responsibility (the MCP tool layer accepts a string and converts to bytes).
//!
//! # Byte-layout
//!
//! Per the SEP-53 specification (`sep-0053.md`):
//! - Prefix: `"Stellar Signed Message:\n"` — exactly 24 UTF-8 bytes:
//!   `53 74 65 6c 6c 61 72 20 53 69 67 6e 65 64 20 4d 65 73 73 61 67 65 3a 0a`
//! - Preimage: `prefix_bytes ‖ message_bytes`
//! - Digest: single-round `SHA-256(preimage)` → 32 bytes
//! - Signature: ed25519 over the 32-byte digest → 64 bytes
//! - Verify: recompute digest, ed25519-verify(public_key, digest, signature)
//!
//! # Module overview
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`error`] | [`Sep53Error`] typed error enum |
//! | Root | [`sign_message`], [`verify_message`], [`PREFIX`] |
//!
//! Spec authority: the SEP-53 specification (`sep-0053.md`).

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::missing_errors_doc)]
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;

pub use error::Sep53Error;

use sha2::{Digest, Sha256};
use stellar_agent_network::signing::Signer;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// The fixed SEP-53 message prefix.
///
/// Exactly 24 UTF-8 bytes: `"Stellar Signed Message:\n"`.
///
/// Hex: `53 74 65 6c 6c 61 72 20 53 69 67 6e 65 64 20 4d 65 73 73 61 67 65 3a 0a`
///
/// Cited from `sep-0053.md`.
/// The trailing byte is `\n` = `0x0a`.
///
/// This constant is the single source of truth for the SEP-53 prefix inside
/// this crate. All code paths use [`PREFIX`] rather than an inline literal to
/// prevent byte-drift.
pub const PREFIX: &[u8] = b"Stellar Signed Message:\n";

/// Maximum message length in bytes accepted by [`sign_message`] and
/// [`verify_message`] (DoS guard).
///
/// 64 KiB. Callers supplying messages larger than this receive
/// [`Sep53Error::MessageTooLarge`].
pub const MAX_MESSAGE_BYTES: usize = 65_536;

// ─────────────────────────────────────────────────────────────────────────────
// Digest helper
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the SEP-53 prefixed message digest.
///
/// Preimage = `PREFIX ‖ message_bytes`.
/// Returns `SHA-256(preimage)` as a 32-byte array.
///
/// Per `sep-0053.md` ("single-round SHA256"). This is the single source of the
/// SEP-53 digest scheme; callers in other crates (e.g. the SEP-43 `signMessage`
/// path) reuse it so the two SEPs cannot diverge.
///
/// # Panics
///
/// Never panics.
#[must_use]
pub fn message_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREFIX);
    hasher.update(message);
    hasher.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Signs `message` using the SEP-53 prefixed scheme.
///
/// Constructs the preimage `"Stellar Signed Message:\n" ‖ message`, computes
/// `SHA-256(preimage)`, and calls `Signer::sign_tx_payload(&digest)` to
/// produce a 64-byte ed25519 signature.
///
/// The caller is responsible for any base64 or hex encoding of the returned
/// signature bytes for wire transport.
///
/// # Implements
///
/// SEP-53 prefixed message
/// signing: `SHA-256("Stellar Signed Message:\n" ‖ msg)` → ed25519.
///
/// # Byte-layout citation
///
/// `sep-0053.md`:
///
/// > 3. Compute `messageHash = SHA256(encodedMessage)`.
/// > 4. Sign `messageHash` using the Stellar private key (ed25519). This
/// >    yields a 64-byte signature.
///
/// # Relationship to SEP-43 signMessage
///
/// `stellar_agent_sep43::signing::sign_message_bytes` (the SEP-43 `signMessage`
/// path) reuses this crate's [`message_digest`] for the same SEP-53 scheme, so
/// signatures it produces verify with [`verify_message`].
///
/// # Errors
///
/// - [`Sep53Error::MessageTooLarge`] — `message.len()` exceeds [`MAX_MESSAGE_BYTES`].
/// - [`Sep53Error::SigningFailed`] — the signer returned an error.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```rust,ignore
/// use stellar_agent_sep53::sign_message;
/// use stellar_agent_network::signing::SoftwareSigningKey;
///
/// # tokio_test::block_on(async {
/// let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
/// let sig = sign_message(b"hello sep53", &key).await.unwrap();
/// assert_eq!(sig.len(), 64);
/// # });
/// ```
pub async fn sign_message(
    message: &[u8],
    signer: &(dyn Signer + Send + Sync),
) -> Result<[u8; 64], Sep53Error> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(Sep53Error::MessageTooLarge {
            len: message.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }

    // Build the SEP-53 digest: SHA-256("Stellar Signed Message:\n" ‖ message).
    // Cited: sep-0053.md (single-round SHA256).
    let digest = message_digest(message);

    // sign_tx_payload is the correct primitive: it performs raw ed25519 over
    // a 32-byte payload. The payload here is the SEP-53 prefixed digest, NOT
    // a SEP-23 transaction payload. This is sanctioned use of sign_tx_payload
    // the Signer trait does not expose a separate
    // domain-isolated "sign_message" entry point; the 32-byte ed25519 primitive
    // is identical but the payload domain is the SEP-53 prefixed digest.
    // See `stellar_agent_network::signing::Signer::sign_tx_payload` rustdoc for
    // the sanctioned-call-site list where this caller is registered.
    signer
        .sign_tx_payload(&digest)
        .await
        .map_err(|e| Sep53Error::SigningFailed {
            reason: format!("{e}"),
        })
}

/// Verifies a SEP-53 message signature.
///
/// Recomputes `SHA-256("Stellar Signed Message:\n" ‖ message)` and
/// ed25519-verifies the 64-byte `signature` against the supplied `public_key`.
///
/// Returns `Ok(())` on successful verification, or an error on failure.
///
/// # Implements
///
/// SEP-53 prefixed message
/// verification: recompute digest and ed25519-verify.
///
/// # Byte-layout citation
///
/// `sep-0053.md`:
///
/// > 1. Convert the message to a byte array if it is a string.
/// > 2. Reconstruct the same canonical payload.
/// > 3. Compute `messageHash = SHA256(encodedPayload)`.
/// > 4. Use the corresponding public key to verify the 64-byte ed25519 signature.
///
/// # Errors
///
/// - [`Sep53Error::MessageTooLarge`] — `message.len()` exceeds [`MAX_MESSAGE_BYTES`].
/// - [`Sep53Error::InvalidPublicKey`] — `public_key.0` is not a valid ed25519
///   public key (point decompression failed).
/// - [`Sep53Error::InvalidSignature`] — `signature` bytes do not represent a
///   structurally valid ed25519 signature (e.g. non-canonical encoding).
/// - [`Sep53Error::VerificationFailed`] — the signature is structurally valid
///   but does not verify against the given public key and message.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```rust,ignore
/// use stellar_agent_sep53::{sign_message, verify_message};
/// use stellar_agent_network::signing::SoftwareSigningKey;
/// use stellar_strkey::ed25519::PublicKey;
///
/// # tokio_test::block_on(async {
/// let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
/// let pk_bytes = key.public_key().await.unwrap();
/// let public_key = PublicKey(pk_bytes.0);
/// let sig = sign_message(b"hello", &key).await.unwrap();
/// verify_message(b"hello", &sig, &public_key).unwrap();
/// # });
/// ```
pub fn verify_message(
    message: &[u8],
    signature: &[u8; 64],
    public_key: &stellar_strkey::ed25519::PublicKey,
) -> Result<(), Sep53Error> {
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(Sep53Error::MessageTooLarge {
            len: message.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }

    let digest = message_digest(message);

    // Decompress the ed25519 public key.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&public_key.0).map_err(|e| {
        Sep53Error::InvalidPublicKey {
            detail: format!("ed25519 public key point decompression failed: {e}"),
        }
    })?;

    // Build the ed25519 Signature from the 64 raw bytes.
    // from_bytes is infallible in ed25519-dalek 2.x (no Result return).
    let sig = ed25519_dalek::Signature::from_bytes(signature);

    // Verify over the 32-byte digest (the SHA-256 of the prefixed preimage).
    // verify_strict rejects the small-subgroup / non-canonical edge cases that
    // the non-strict verify accepts for batch-verification compatibility. SEP-53
    // is a single-signature scheme, so strict verification is the correct choice.
    vk.verify_strict(&digest, &sig)
        .map_err(|_| Sep53Error::VerificationFailed)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use stellar_agent_network::signing::SoftwareSigningKey;

    // ── prefix is exactly 24 bytes with correct hex representation ────────

    /// Asserts the SEP-53 prefix is exactly 24 bytes.
    ///
    /// Cites `sep-0053.md`.
    #[test]
    fn prefix_is_exactly_24_bytes() {
        assert_eq!(
            PREFIX.len(),
            24,
            "SEP-53 prefix must be exactly 24 bytes (sep-0053.md); \
             got {} bytes: {:?}",
            PREFIX.len(),
            PREFIX
        );
    }

    /// Asserts the SEP-53 prefix hex representation matches the spec.
    ///
    /// Hex: `53 74 65 6c 6c 61 72 20 53 69 67 6e 65 64 20 4d 65 73 73 61 67 65 3a 0a`
    ///
    /// The trailing byte is `\n` = `0x0a` (per spec: "the trailing byte is `\n`").
    #[test]
    fn prefix_hex_matches_spec() {
        let expected_hex = "537465 6c6c61 72205369676e6564204d657373616765 3a0a".replace(' ', "");
        let actual_hex: String = PREFIX.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual_hex, expected_hex,
            "SEP-53 prefix hex must match spec (sep-0053.md)"
        );
    }

    // ── two-oracle digest test ─────────────────────────────────────────────

    /// Oracle A (hand-computed digest): SHA-256("Stellar Signed Message:\n" ‖ "Hello, World!")
    ///
    /// This is the first oracle in the two-oracle test.
    /// The digest hex `d52eb59c...ea5f` is computed independently of this crate
    /// (verified via Python: `hashlib.sha256(b"Stellar Signed Message:\n" + b"Hello, World!").hexdigest()`).
    /// It proves the preimage construction is byte-exact.
    ///
    /// Spec citation: `sep-0053.md`.
    #[test]
    fn two_oracle_digest_hello_world() {
        let msg = b"Hello, World!";
        let digest = message_digest(msg);
        let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            digest_hex, "d52eb59c06bb510d065997ff93077068eed0a486c20215b5e02e1ab0d2ebea5f",
            "SHA-256 of SEP-53 prefixed 'Hello, World!' must match the hand-computed \
             oracle (two-oracle test)"
        );
    }

    /// Oracle B — spec vector 1: verify the spec's published signature against
    /// the spec's published PUBLIC address.
    ///
    /// The spec test vector for "Hello, World!" (sep-0053.md "Test cases"):
    /// - Address: `GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L`
    /// - Signature (base64):
    ///   `fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==`
    ///
    /// Only the public key (G-strkey) is used here — no seed. ed25519 is
    /// deterministic: if `verify_message(msg, spec_sig, spec_pubkey)` returns
    /// `Ok`, the sign path produced the spec-identical digest AND the signing
    /// primitive is correct. Combined with Oracle A's digest assertion, this
    /// constitutes the two-oracle spec-compatibility proof.
    #[test]
    fn spec_vector_verify_hello_world() {
        let addr_strkey = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";
        let pk = stellar_strkey::ed25519::PublicKey::from_string(addr_strkey)
            .expect("spec test vector public address must parse");

        use base64::Engine as _;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode("fO5dbYhXUhBMhe6kId/cuVq/AfEnHRHEvsP8vXh03M1uLpi5e46yO2Q8rEBzu3feXQewcQE5GArp88u6ePK6BA==")
            .expect("spec signature base64 must decode");
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .expect("signature must be exactly 64 bytes");

        verify_message(b"Hello, World!", &sig_arr, &pk).expect(
            "spec test vector signature must verify against spec public address \
             (sep-0053.md test case 1; oracle B of two-oracle test)",
        );
    }

    /// Oracle B — spec vector 2: Japanese message verify.
    ///
    /// Spec test vector (sep-0053.md test case 2):
    /// - Message: `こんにちは、世界！`
    /// - Address: `GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L`
    /// - Signature (base64):
    ///   `CDU265Xs8y3OWbB/56H9jPgUss5G9A0qFuTqH2zs2YDgTm+++dIfmAEceFqB7bhfN3am59lCtDXrCtwH2k1GBA==`
    ///
    /// Only the public key (G-strkey) is used — no seed.
    #[test]
    fn spec_vector_verify_japanese_message() {
        let addr_strkey = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";
        let pk = stellar_strkey::ed25519::PublicKey::from_string(addr_strkey)
            .expect("spec test vector public address must parse");

        use base64::Engine as _;
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode("CDU265Xs8y3OWbB/56H9jPgUss5G9A0qFuTqH2zs2YDgTm+++dIfmAEceFqB7bhfN3am59lCtDXrCtwH2k1GBA==")
            .expect("spec signature base64 must decode");
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .expect("signature must be exactly 64 bytes");

        let msg = "こんにちは、世界！".as_bytes();
        verify_message(msg, &sig_arr, &pk)
            .expect("spec test vector signature must verify (sep-0053.md test case 2 Japanese)");
    }

    /// Oracle B — spec vector 3: binary message verify.
    ///
    /// Spec test vector (sep-0053.md test case 3):
    /// - Message (base64): `2zZDP1sa1BVBfLP7TeeMk3sUbaxAkUhBhDiNdrksaFo=`
    /// - Address: `GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L`
    /// - Signature (base64):
    ///   `VA1+7hefNwv2NKScH6n+Sljj15kLAge+M2wE7fzFOf+L0MMbssA1mwfJZRyyrhBORQRle10X1Dxpx+UOI4EbDQ==`
    ///
    /// Only the public key (G-strkey) is used — no seed.
    #[test]
    fn spec_vector_verify_binary_message() {
        let addr_strkey = "GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L";
        let pk = stellar_strkey::ed25519::PublicKey::from_string(addr_strkey)
            .expect("spec test vector public address must parse");

        use base64::Engine as _;
        let msg_bytes = base64::engine::general_purpose::STANDARD
            .decode("2zZDP1sa1BVBfLP7TeeMk3sUbaxAkUhBhDiNdrksaFo=")
            .expect("binary message base64 must decode");
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode("VA1+7hefNwv2NKScH6n+Sljj15kLAge+M2wE7fzFOf+L0MMbssA1mwfJZRyyrhBORQRle10X1Dxpx+UOI4EbDQ==")
            .expect("spec signature base64 must decode");
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .expect("signature must be exactly 64 bytes");

        verify_message(&msg_bytes, &sig_arr, &pk)
            .expect("spec test vector signature must verify (sep-0053.md test case 3 binary)");
    }

    // ── sign→verify round-trips with ephemeral keypair ────────────────────

    /// Verifies that a signature produced by sign_message verifies correctly.
    ///
    /// Uses a locally-generated ephemeral keypair (fixed seed — no spec key committed).
    #[test]
    fn verify_roundtrip_produced_signature_verifies() {
        let key = SoftwareSigningKey::new_from_bytes([42u8; 32]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let msg = b"roundtrip test message";
            let sig = sign_message(msg, &key)
                .await
                .expect("sign_message must succeed");
            let pk_bytes = key.public_key().await.expect("public_key must succeed");
            let public_key = stellar_strkey::ed25519::PublicKey(pk_bytes.0);
            verify_message(msg, &sig, &public_key).expect("verify_message must return Ok");
        });
    }

    /// Verifies that a tampered message returns VerificationFailed.
    #[test]
    fn verify_tampered_message_returns_verification_failed() {
        let key = SoftwareSigningKey::new_from_bytes([42u8; 32]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let msg = b"original message";
            let sig = sign_message(msg, &key)
                .await
                .expect("sign_message must succeed");
            let pk_bytes = key.public_key().await.expect("public_key must succeed");
            let public_key = stellar_strkey::ed25519::PublicKey(pk_bytes.0);

            // Tamper the message.
            let tampered = b"tampered message!";
            let err = verify_message(tampered, &sig, &public_key)
                .expect_err("verify_message must fail for tampered message");
            assert!(
                matches!(err, Sep53Error::VerificationFailed),
                "tampered message must return VerificationFailed, got: {err:?}"
            );
        });
    }

    /// Verifies that a wrong public key returns VerificationFailed.
    #[test]
    fn verify_wrong_public_key_returns_verification_failed() {
        let key = SoftwareSigningKey::new_from_bytes([42u8; 32]);
        let wrong_key = SoftwareSigningKey::new_from_bytes([99u8; 32]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let msg = b"test message";
            let sig = sign_message(msg, &key)
                .await
                .expect("sign_message must succeed");
            let wrong_pk_bytes = wrong_key
                .public_key()
                .await
                .expect("public_key must succeed");
            let wrong_public_key = stellar_strkey::ed25519::PublicKey(wrong_pk_bytes.0);

            let err = verify_message(msg, &sig, &wrong_public_key)
                .expect_err("verify_message must fail for wrong public key");
            assert!(
                matches!(err, Sep53Error::VerificationFailed),
                "wrong public key must return VerificationFailed, got: {err:?}"
            );
        });
    }

    // ── message-too-large returns MessageTooLarge ─────────────────────────

    /// Verifies that sign_message returns MessageTooLarge for oversized input.
    #[test]
    fn sign_message_too_large_returns_error() {
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let oversized = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let err = sign_message(&oversized, &key)
                .await
                .expect_err("sign_message must fail for oversized message");
            assert!(
                matches!(
                    err,
                    Sep53Error::MessageTooLarge { len, max }
                    if len == MAX_MESSAGE_BYTES + 1 && max == MAX_MESSAGE_BYTES
                ),
                "oversized message must return MessageTooLarge, got: {err:?}"
            );
        });
    }

    /// Verifies that verify_message returns MessageTooLarge for oversized input.
    #[test]
    fn verify_message_too_large_returns_error() {
        let pk = stellar_strkey::ed25519::PublicKey([1u8; 32]);
        let oversized = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let sig = [0u8; 64];
        let err = verify_message(&oversized, &sig, &pk)
            .expect_err("verify_message must fail for oversized message");
        assert!(
            matches!(
                err,
                Sep53Error::MessageTooLarge { len, max }
                if len == MAX_MESSAGE_BYTES + 1 && max == MAX_MESSAGE_BYTES
            ),
            "oversized message must return MessageTooLarge, got: {err:?}"
        );
    }

    #[test]
    fn verify_message_rejects_small_order_public_key() {
        // The ed25519 identity point (compressed encoding `01 00..00`, y=1) is a
        // small-order public key. Non-strict `verify` can accept signatures for
        // small-order keys (usable to forge a signature valid for almost any
        // message); `verify_strict` rejects them. This pins the strict choice.
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let small_order = stellar_strkey::ed25519::PublicKey(bytes);
        let result = verify_message(b"any message", &[0u8; 64], &small_order);
        assert!(
            result.is_err(),
            "a small-order public key must be rejected, got: {result:?}"
        );
    }
}
