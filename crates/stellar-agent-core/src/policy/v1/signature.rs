//! BLAKE3 digest and ed25519 signature verification for policy documents.
//!
//! Two primitives:
//!
//! 1. [`crate::policy::v1::signature::digest`] — computes a BLAKE3 hash of the canonical policy bytes.
//! 2. [`crate::policy::v1::signature::verify`] — verifies an ed25519 signature over the digest using the
//!    owner public key.
//!
//! ## Dependencies
//!
//! - `ed25519-dalek` is used for signature verification.  No hand-rolled
//!   ed25519.
//! - `blake3` is used for hashing.  `subtle::ConstantTimeEq` is NOT needed
//!   here: `ed25519_dalek::VerifyingKey::verify_strict` is already
//!   internally constant-time on the signature comparison step.
//!
//! ## blake3 non-secret-input note
//!
//! The `canonical_bytes` input to `digest` is the canonical form of the
//! policy file — a non-secret operator-readable document.  BLAKE3's
//! compression function is NOT required to be constant-time for this input
//! (the input is not secret).  If a future change ever passes secret bytes
//! into a `blake3` call, this property must be re-evaluated.
//!
//! ## Caller contract for `verify`
//!
//! The `profile` name is not used inside `verify` itself — it is supplied by
//! the caller in [`crate::policy::v1::loader::load_signed_policy`] when constructing the
//! [`crate::policy::PolicyError::OwnerSignatureInvalid`] error variant.
//! `verify` returns a generic `()` on success or
//! [`crate::policy::PolicyError::OwnerSignatureInvalid`] with the caller-
//! supplied profile name on failure.  The split avoids coupling `signature.rs`
//! to the loader's profile-name plumbing while preserving the typed error.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::policy::PolicyError;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the BLAKE3 digest of `canonical_bytes`.
///
/// The output is a fixed 32-byte array suitable as the pre-image for
/// [`verify`].
///
/// The input MUST be the output of
/// [`super::canonical::canonical_bytes`] — non-secret, policy-file bytes
/// with the `[signature]` table excluded.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::signature::digest;
///
/// let bytes = b"version = 1\nscope = \"profile:default\"\n";
/// let d = digest(bytes);
/// assert_eq!(d.len(), 32);
///
/// // Same input always yields the same digest.
/// assert_eq!(digest(bytes), digest(bytes));
/// ```
#[must_use]
pub fn digest(canonical_bytes: &[u8]) -> [u8; 32] {
    // blake3::hash is deterministic and pure-Rust (the "pure" feature is
    // enabled in the workspace dep, see Cargo.toml comment).
    let h = blake3::hash(canonical_bytes);
    // `as_bytes()` returns `&[u8; 32]`; copy into an owned array.
    *h.as_bytes()
}

/// Verifies an ed25519 signature over `digest` using `owner_pubkey`.
///
/// Uses `ed25519_dalek::VerifyingKey::verify_strict` which is internally
/// constant-time on the signature check (cofactor-checked, no malleability
/// acceptance).
///
/// On success returns `Ok(())`.  On failure returns
/// [`PolicyError::OwnerSignatureInvalid`] with the `profile` name supplied by
/// the caller.  The caller (typically
/// [`crate::policy::v1::loader::load_signed_policy`]) provides `profile` so this function
/// does not need to know the profile name itself.
///
/// # Errors
///
/// Returns [`PolicyError::OwnerSignatureInvalid`] when:
///
/// - `owner_pubkey` is not a valid compressed ed25519 point.
/// - The signature does not verify against `digest` and `owner_pubkey`.
///
/// # Examples
///
/// ```
/// use ed25519_dalek::{SigningKey, Signer};
/// use rand_core::OsRng;
/// use stellar_agent_core::policy::v1::signature::{digest, verify};
///
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let pubkey_bytes = signing_key.verifying_key().to_bytes();
///
/// let canonical = b"version = 1\nscope = \"profile:default\"\n";
/// let d = digest(canonical);
/// let sig_bytes: [u8; 64] = signing_key.sign(&d).to_bytes();
///
/// verify(&d, &sig_bytes, &pubkey_bytes, "alice").unwrap();
/// ```
pub fn verify(
    digest: &[u8; 32],
    signature: &[u8; 64],
    owner_pubkey: &[u8; 32],
    profile: &str,
) -> Result<(), PolicyError> {
    let key =
        VerifyingKey::from_bytes(owner_pubkey).map_err(|_| PolicyError::OwnerSignatureInvalid {
            profile: profile.to_owned(),
        })?;

    let sig = Signature::from_bytes(signature);

    // `verify_strict` requires that the signature passes the cofactor check
    // and rejects the small-subgroup edge cases that `verify` accepts for
    // batch-verification compatibility.  This is the correct choice for a
    // single-signature path.
    key.verify_strict(digest, &sig)
        .map_err(|_| PolicyError::OwnerSignatureInvalid {
            profile: profile.to_owned(),
        })
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

    use ed25519_dalek::Signer;
    use rand_core::OsRng;

    use super::*;

    fn make_keypair() -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    const CANONICAL: &[u8] = b"version = 1\nscope = \"profile:default\"\n";

    // ── digest_deterministic ─────────────────────────────────────────────────

    #[test]
    fn digest_deterministic() {
        let d1 = digest(CANONICAL);
        let d2 = digest(CANONICAL);
        assert_eq!(d1, d2, "digest must be deterministic for the same input");
    }

    #[test]
    fn digest_different_inputs_produce_different_hashes() {
        let d1 = digest(CANONICAL);
        let d2 = digest(b"version = 2\nscope = \"profile:default\"\n");
        assert_ne!(d1, d2, "different inputs must produce different digests");
    }

    // ── verify_valid_signature ───────────────────────────────────────────────

    #[test]
    fn verify_valid_signature() {
        let (sk, pk) = make_keypair();
        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();
        verify(&d, &sig, &pk, "alice").expect("valid signature must verify successfully");
    }

    // ── verify_wrong_key_rejected ────────────────────────────────────────────

    #[test]
    fn verify_wrong_key_rejected() {
        let (sk, _pk) = make_keypair();
        let (_sk2, pk2) = make_keypair();

        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();

        let err = verify(&d, &sig, &pk2, "alice").unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { ref profile } if profile == "alice"),
            "wrong key must produce OwnerSignatureInvalid for the correct profile, got: {err:?}"
        );
    }

    // ── verify_corrupted_sig_rejected ────────────────────────────────────────

    #[test]
    fn verify_corrupted_sig_rejected() {
        let (sk, pk) = make_keypair();
        let d = digest(CANONICAL);
        let mut sig: [u8; 64] = sk.sign(&d).to_bytes();

        // Flip a bit in the signature.
        sig[0] ^= 0x01;

        let err = verify(&d, &sig, &pk, "bob").unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { ref profile } if profile == "bob"),
            "corrupted signature must produce OwnerSignatureInvalid, got: {err:?}"
        );
    }

    // ── verify_invalid_pubkey_rejected ───────────────────────────────────────

    #[test]
    fn verify_invalid_pubkey_rejected() {
        let (sk, _) = make_keypair();
        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();

        // All-zeros is not a valid compressed ed25519 point.
        let invalid_pk = [0u8; 32];
        let result = verify(&d, &sig, &invalid_pk, "charlie");
        // Some all-zero points are accepted as valid group elements by dalek;
        // the sig will still fail to verify since the key doesn't match.
        // Either way the result must not be Ok(()).
        if result.is_ok() {
            panic!("verification with wrong key (all-zeros) must not succeed");
        }
    }

    // ── verify_wrong_digest_rejected ─────────────────────────────────────────

    #[test]
    fn verify_wrong_digest_rejected() {
        let (sk, pk) = make_keypair();
        let d = digest(CANONICAL);
        let sig: [u8; 64] = sk.sign(&d).to_bytes();

        // Verify against a different digest.
        let mut wrong_digest = d;
        wrong_digest[0] ^= 0x01;

        let err = verify(&wrong_digest, &sig, &pk, "dave").unwrap_err();
        assert!(
            matches!(err, PolicyError::OwnerSignatureInvalid { .. }),
            "wrong digest must produce OwnerSignatureInvalid, got: {err:?}"
        );
    }
}
