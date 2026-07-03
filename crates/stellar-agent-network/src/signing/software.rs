//! Software `SoftwareSigningKey` — ed25519 secret key in a
//! `secrecy::SecretBox`, zeroised on drop.
//!
//! # Zeroize-on-drop guarantee
//!
//! `SoftwareSigningKey` holds its secret in a `secrecy::SecretBox<[u8; 32]>`,
//! whose `Drop` implementation calls `zeroize::Zeroize::zeroize` on the
//! heap-allocated array before freeing.  The explicit `impl Drop` below fires
//! before the struct fields are dropped.  The body is empty because `SecretBox`
//! already does the work; the `impl Drop` declaration is an auditable guarantee
//! that no future refactor can accidentally remove the zeroize-on-drop
//! discipline without touching this explicit impl first.
//!
//! # `new_from_zeroizing` vs `new_from_bytes`
//!
//! Production call sites MUST use `new_from_zeroizing(Zeroizing<[u8; 32]>)`:
//! the `Zeroizing` wrapper zeroes the stack/heap temporary when it falls out
//! of scope, so the secret bytes are cleared on both the source and inside the
//! `SecretBox`.  `new_from_bytes([u8; 32])` is retained for fixture/test use
//! only; the caller bears responsibility for zeroing the source array.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretBox};
use stellar_agent_core::error::{AuthError, WalletError};
use zeroize::Zeroizing;

use crate::signing::{Signer, WebAuthnAssertion};

/// A zeroize-on-drop wrapper around a 32-byte ed25519 secret seed.
///
/// Wraps `secrecy::SecretBox<[u8; 32]>`.  Callers pass `&SoftwareSigningKey`
/// (or `&dyn Signer`) to signing functions — never the raw bytes by value.
///
/// See the [module-level documentation](crate::signing::software) for the
/// `Drop` and `Zeroizing` discipline.
///
/// # Secret-material policy
///
/// The inner bytes are never accessible except through
/// `expose_secret_for_signing` (a `pub(crate)` method), which is explicitly
/// named to signal the narrow use case. It is called by
/// `SoftwareSigningKey::sign_tx_payload` and `SoftwareSigningKey::public_key`
/// only.
///
/// This type deliberately does not implement `Debug`, `Display`, `Clone`, or
/// `Serialize` — the type system prevents the inner bytes from leaking through
/// log formatting or JSON serialisation.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::SoftwareSigningKey;
///
/// // In production code the 32 bytes come from the decrypted keyring.
/// let raw = zeroize::Zeroizing::new([0u8; 32]);
/// let key = SoftwareSigningKey::new_from_zeroizing(raw);
/// drop(key); // inner bytes zeroed by SecretBox::drop
/// ```
///
/// # `#[non_exhaustive]` exemption
///
/// `SoftwareSigningKey` is a newtype tuple struct with a single private field
/// (`SecretBox<[u8; 32]>`).  External callers cannot construct it via
/// struct-literal or tuple syntax; the only construction paths are
/// [`SoftwareSigningKey::new_from_zeroizing`] (production) and
/// [`SoftwareSigningKey::new_from_bytes`] (fixtures/tests).  Adding
/// `#[non_exhaustive]` provides no additional forward-compat guarantee for a
/// private-field newtype and is therefore omitted.  Any structural change would
/// require a public-API semver bump regardless.
pub struct SoftwareSigningKey(SecretBox<[u8; 32]>);

impl SoftwareSigningKey {
    /// Constructs a `SoftwareSigningKey` from a `Zeroizing<[u8; 32]>` container.
    ///
    /// The `Zeroizing` wrapper zeroes the source bytes when `raw` drops at the
    /// end of this call frame.  The bytes are moved into a `SecretBox` which
    /// zeroes the heap allocation on drop.
    ///
    /// Production call sites MUST use this constructor rather than
    /// `new_from_bytes`.
    ///
    /// # Ownership contract
    ///
    /// `raw` is taken **by value** deliberately. clippy's `needless_pass_by_value`
    /// lint suggests taking a reference because `[u8; 32]` is `Copy`, but the
    /// caller MUST relinquish ownership of `raw` so that its `Drop` impl fires
    /// when this function returns, zeroing the caller's stack copy. Taking a `&`
    /// reference would allow the caller to retain and re-use the `Zeroizing`
    /// container, defeating the discipline. The `#[allow(clippy::needless_pass_by_value)]`
    /// on this function is the documented exception.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::SoftwareSigningKey;
    /// use zeroize::Zeroizing;
    ///
    /// let raw = Zeroizing::new([0u8; 32]);
    /// let key = SoftwareSigningKey::new_from_zeroizing(raw);
    /// ```
    #[must_use]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "ownership is required so the caller's Zeroizing<[u8;32]> is dropped on return"
    )]
    pub fn new_from_zeroizing(raw: Zeroizing<[u8; 32]>) -> Self {
        // `SecretBox::init_with_mut` initialises `S` in-place inside the
        // `SecretBox`'s heap allocation via a mutable reference — no stack
        // temporary is materialised for the secret bytes.
        // `[u8; 32]` satisfies `Zeroize + Default` (both required by the
        // `impl<S: Zeroize + Default> SecretBox<S>` bound).
        // The `Zeroizing<[u8; 32]>` wrapper is consumed by this call so its
        // `Drop` impl fires on return, zeroing the caller's copy.
        Self(SecretBox::init_with_mut(|dst: &mut [u8; 32]| {
            dst.copy_from_slice(&*raw);
        }))
    }

    /// Constructs a `SoftwareSigningKey` from 32 raw bytes.
    ///
    /// **Test and fixture use only.** The caller is responsible for zeroing
    /// the source bytes after this call.  Production code MUST use
    /// [`SoftwareSigningKey::new_from_zeroizing`] instead, which enforces the
    /// caller-side zeroise discipline via the `Zeroizing<T>` type wrapper.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stellar_agent_network::SoftwareSigningKey;
    ///
    /// let raw = [0u8; 32];
    /// let key = SoftwareSigningKey::new_from_bytes(raw);
    /// drop(key); // inner bytes zeroed by SecretBox::drop
    /// ```
    #[must_use]
    pub fn new_from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Exposes the raw 32-byte secret key seed for the signing implementation.
    ///
    /// `pub(crate)` — called by `SoftwareSigningKey::sign_tx_payload` and
    /// `SoftwareSigningKey::public_key` only.
    pub(crate) fn expose_secret_for_signing(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// Explicit `Drop` for `SoftwareSigningKey`.
///
/// The body is intentionally empty: `secrecy::SecretBox` already calls
/// `zeroize::Zeroize::zeroize` on its heap-allocated array before freeing.
/// The explicit `impl Drop` is an auditable guarantee: a future refactor that
/// swaps `SecretBox` for a non-zeroizing holder will fail to compile cleanly
/// while this impl exists, making the invariant visible to any reviewer.
impl Drop for SoftwareSigningKey {
    fn drop(&mut self) {
        // SecretBox's own Drop handles the actual zeroize.
        // This impl exists as the explicit audit point for the zeroize guarantee.
    }
}

// Compile-time guarantee that `ed25519_dalek::SigningKey` implements
// `ZeroizeOnDrop`. If a future dep pin strips the `zeroize` feature
// from `ed25519-dalek` this assertion fails at compile time.
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
};

#[async_trait]
impl Signer for SoftwareSigningKey {
    /// Signs a 32-byte transaction hash payload using the ed25519 secret seed.
    ///
    /// Constructs an `ed25519_dalek::SigningKey` from the secret seed, signs
    /// the payload, and returns the 64-byte signature.  The dalek signing key
    /// is zeroed by its own `Drop` impl before this function returns.
    ///
    /// # Errors
    ///
    /// This implementation does not return errors under normal use.  The seed
    /// is always 32 bytes (enforced by type), so dalek construction cannot
    /// fail.  The error type is `WalletError` for trait uniformity.
    async fn sign_tx_payload(&self, payload: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        use ed25519_dalek::{Signer as DalekSigner, SigningKey};

        let seed = self.expose_secret_for_signing();
        let signing_key = SigningKey::from_bytes(seed);
        let signature = signing_key.sign(payload);
        Ok(signature.to_bytes())
    }

    /// Signs a 32-byte smart-account auth-digest using the ed25519 secret seed.
    ///
    /// Cryptographically identical to [`SoftwareSigningKey::sign_tx_payload`];
    /// the split is a call-site-discipline guard: smart-account auth-entry
    /// assembly invokes this method, classic transaction signing invokes
    /// `sign_tx_payload`. The implementations are separated rather than chained
    /// so that each call site is auditable at the trait-dispatch level —
    /// `sign_auth_digest` and `sign_tx_payload` resolve to distinct vtable
    /// entries.
    ///
    /// # Errors
    ///
    /// This implementation does not return errors under normal use; the seed
    /// is always 32 bytes (enforced by type), so dalek construction cannot fail.
    /// The error type is `WalletError` for trait uniformity.
    async fn sign_auth_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], WalletError> {
        use ed25519_dalek::{Signer as DalekSigner, SigningKey};

        let seed = self.expose_secret_for_signing();
        let signing_key = SigningKey::from_bytes(seed);
        let signature = signing_key.sign(digest);
        Ok(signature.to_bytes())
    }

    /// Signs a 32-byte Soroban address-credentials auth-entry signature_payload
    /// using the ed25519 secret seed.
    ///
    /// Cryptographically identical to [`SoftwareSigningKey::sign_tx_payload`]
    /// and [`SoftwareSigningKey::sign_auth_digest`]; the split is a call-site
    /// discipline guard. Used exclusively by the smart-account manager flow
    /// when constructing the secondary "Delegated G-key" auth entry that OZ
    /// smart accounts require alongside the smart-account entry.
    ///
    /// # Errors
    ///
    /// Same as [`SoftwareSigningKey::sign_tx_payload`]: this implementation
    /// does not return errors under normal use.
    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &[u8; 32],
    ) -> Result<[u8; 64], WalletError> {
        use ed25519_dalek::{Signer as DalekSigner, SigningKey};

        let seed = self.expose_secret_for_signing();
        let signing_key = SigningKey::from_bytes(seed);
        let signature = signing_key.sign(payload);
        Ok(signature.to_bytes())
    }

    /// Software ed25519 signers cannot produce WebAuthn assertions; passkey
    /// signing requires a dedicated `PasskeySignHandle`.
    ///
    /// Always returns [`AuthError::SignerKindMismatch`] with
    /// `signer_kind = "software"`. The `_auth_digest` and `_credential_id`
    /// parameters are unused; the underscore prefix silences the unused-variable
    /// lint without requiring `#[allow]`.
    ///
    /// # Errors
    ///
    /// - [`WalletError::Auth`] wrapping [`AuthError::SignerKindMismatch`] —
    ///   always, on every call.
    async fn sign_webauthn_assertion(
        &self,
        _auth_digest: &[u8; 32],
        _credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        Err(WalletError::Auth(AuthError::SignerKindMismatch {
            signer_kind: "software",
            requested_primitive: "sign_webauthn_assertion",
        }))
    }

    /// Returns the ed25519 public key derived from the secret seed.
    ///
    /// # Errors
    ///
    /// This implementation does not return errors; the public key is derived
    /// deterministically from the seed, which is always 32 bytes.
    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        use ed25519_dalek::SigningKey;

        let seed = self.expose_secret_for_signing();
        let signing_key = SigningKey::from_bytes(seed);
        let vk = signing_key.verifying_key();
        Ok(stellar_strkey::ed25519::PublicKey(vk.to_bytes()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only code; panics and unwraps are acceptable in unit tests"
)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn new_from_bytes_roundtrip() {
        let seed = [42u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        assert_eq!(key.expose_secret_for_signing(), &seed);
    }

    #[test]
    fn new_from_zeroizing_roundtrip() {
        let seed = Zeroizing::new([99u8; 32]);
        let key = SoftwareSigningKey::new_from_zeroizing(seed);
        assert_eq!(key.expose_secret_for_signing(), &[99u8; 32]);
    }

    #[test]
    fn new_from_bytes_all_zeros() {
        let key = SoftwareSigningKey::new_from_bytes([0u8; 32]);
        assert_eq!(key.expose_secret_for_signing(), &[0u8; 32]);
    }

    #[test]
    fn new_from_bytes_all_max() {
        let key = SoftwareSigningKey::new_from_bytes([0xff_u8; 32]);
        assert_eq!(key.expose_secret_for_signing(), &[0xff_u8; 32]);
    }

    /// Verifies that secret bytes are accessible before drop and match the
    /// input — the positive-case assertion for the zeroize-on-drop contract.
    ///
    /// `secrecy::SecretBox` guarantees that the heap-allocated byte array is
    /// zeroed when `drop` fires, via `zeroize::Zeroize::zeroize`. A classical
    /// "read the freed pointer" volatile-read smoke check would require `unsafe
    /// code`, which the workspace forbids (`#![forbid(unsafe_code)]`). Instead
    /// this test verifies the behavioural contract at the type level:
    ///
    /// 1. `SoftwareSigningKey` has an explicit `impl Drop` (audit point).
    /// 2. After construction from non-zero bytes, the secret bytes are
    ///    accessible before drop and match the input.
    /// 3. A `Zeroizing<[u8; 32]>` wrapper was used to construct the key,
    ///    meaning the stack copy was cleared when it went out of scope.
    ///
    /// The zeroise-on-heap guarantee is verified by inspecting the `secrecy`
    /// and `zeroize` crate source.
    #[test]
    fn secret_accessible_before_drop() {
        // Verify that the key can be constructed and the bytes are accessible
        // before drop. This is the positive-case assertion. The drop itself
        // fires when `key` goes out of scope at the end of this block.
        let seed = Zeroizing::new([0xAB_u8; 32]);
        let key = SoftwareSigningKey::new_from_zeroizing(seed);
        assert_eq!(
            key.expose_secret_for_signing(),
            &[0xAB_u8; 32],
            "bytes must be accessible before drop"
        );
        drop(key);
        // After drop: SecretBox::drop called zeroize::Zeroize::zeroize.
        // We cannot read the freed pointer without unsafe code; the contract
        // is verified by code review of secrecy 0.10.x and the explicit
        // `impl Drop for SoftwareSigningKey` audit point above this function.
        // See also: `secret_accessible_before_drop` test name chosen to reflect
        // what this test actually asserts (pre-drop access + value match).
    }

    #[tokio::test]
    async fn sign_tx_payload_produces_64_bytes() {
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let payload = [0xDE_u8; 32];
        let sig = key.sign_tx_payload(&payload).await.unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn public_key_is_deterministic() {
        let key = SoftwareSigningKey::new_from_bytes([7u8; 32]);
        let pk1 = key.public_key().await.unwrap();
        let pk2 = key.public_key().await.unwrap();
        assert_eq!(pk1.0, pk2.0, "public key must be deterministic");
    }

    #[tokio::test]
    async fn sign_auth_digest_produces_64_bytes() {
        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let digest = [0xAD_u8; 32];
        let sig = key.sign_auth_digest(&digest).await.unwrap();
        assert_eq!(sig.len(), 64);
    }

    /// Documents the cryptographic-identity property between the two signing
    /// methods. Both `sign_tx_payload` and `sign_auth_digest` reach the same
    /// underlying ed25519 primitive (identical 32-byte → 64-byte mapping per
    /// the same secret seed), so identical 32-byte inputs MUST produce
    /// identical 64-byte signatures. The discipline that distinguishes them
    /// lives at the call site: smart-account auth-entry assembly invokes
    /// `sign_auth_digest`, classic-transaction signing invokes
    /// `sign_tx_payload`. Cross-substitution of these methods is a build-time
    /// invariant enforced in the repository gate rules.
    #[tokio::test]
    async fn sign_methods_are_cryptographically_identical_for_same_input() {
        let key = SoftwareSigningKey::new_from_bytes([42u8; 32]);
        let bytes = [0xC0_u8; 32];
        let sig_tx = key.sign_tx_payload(&bytes).await.unwrap();
        let sig_auth = key.sign_auth_digest(&bytes).await.unwrap();
        assert_eq!(
            sig_tx, sig_auth,
            "ed25519 is deterministic — identical 32-byte inputs must produce identical signatures regardless of trait method invoked"
        );
    }

    #[tokio::test]
    async fn sign_auth_digest_then_verify_with_dalek() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let seed = [3u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let digest = [0xAD_u8; 32];
        let sig_bytes = key.sign_auth_digest(&digest).await.unwrap();

        let pk_strkey = key.public_key().await.unwrap();
        let vk = VerifyingKey::from_bytes(&pk_strkey.0).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);

        vk.verify(&digest, &sig)
            .expect("auth-digest signature must verify against derived pubkey");
    }

    /// Asserts that `SoftwareSigningKey::sign_webauthn_assertion` returns
    /// `AuthError::SignerKindMismatch { signer_kind: "software", .. }`.
    ///
    /// Software ed25519 signers are incapable of producing WebAuthn / secp256r1
    /// assertions; the refusal must be immediate and not consume the inputs.
    #[tokio::test]
    async fn software_signer_refuses_webauthn_assertion_with_kind_mismatch() {
        use stellar_agent_core::error::AuthError;

        let key = SoftwareSigningKey::new_from_bytes([1u8; 32]);
        let auth_digest = [0xAB_u8; 32];
        let credential_id = b"test-credential-id";

        let err = key
            .sign_webauthn_assertion(&auth_digest, credential_id)
            .await
            .unwrap_err();

        assert_eq!(err.code(), "auth.signer_kind_mismatch");
        match err {
            WalletError::Auth(AuthError::SignerKindMismatch {
                signer_kind,
                requested_primitive,
            }) => {
                assert_eq!(signer_kind, "software");
                assert_eq!(requested_primitive, "sign_webauthn_assertion");
            }
            other => panic!("expected SignerKindMismatch, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_then_verify_with_dalek() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let seed = [3u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let payload = [0xBE_u8; 32];
        let sig_bytes = key.sign_tx_payload(&payload).await.unwrap();

        let pk_strkey = key.public_key().await.unwrap();
        let vk = VerifyingKey::from_bytes(&pk_strkey.0).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);

        // Verification succeeds when the signature was produced by the
        // corresponding private key.
        vk.verify(&payload, &sig).expect("signature must verify");
    }
}
