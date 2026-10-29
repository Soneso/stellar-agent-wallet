//! Software ed25519 signing with a zeroize-on-drop seed home.
//!
//! Keyring and fixture constructors use `secrecy::SecretBox`. Wallet signers
//! take ownership of a `LockedSeed` and read its stable home directly.
//! Both homes zeroize before freeing; a locked home also unlocks after zeroizing.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretBox};
use stellar_agent_core::error::{AuthError, WalletError};
use stellar_agent_core::wallet::LockedSeed;
use zeroize::Zeroizing;

use crate::signing::{
    MessagePayload, Signer, SmartAccountAuthDigest, SorobanAuthPayload, TxSigningPayload,
    WebAuthnAssertion,
};

/// A zeroize-on-drop wrapper around a 32-byte ed25519 secret seed.
///
/// Holds either a boxed secret or the locked home transferred by a wallet.
/// Callers pass `&SoftwareSigningKey` or `&dyn Signer` to signing functions.
///
/// See the [module-level documentation](crate::signing::software) for the
/// `Drop` and `Zeroizing` discipline.
///
/// # Secret-material policy
///
/// The inner bytes are never accessible except through
/// `expose_secret_for_signing` (a `pub(crate)` method), which is explicitly
/// named to signal the narrow use case. It is called by
/// `SoftwareSigningKey::sign_raw` and `SoftwareSigningKey::public_key` only.
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
/// The private seed home keeps construction behind the named constructors.
///
/// The raw signing primitive is crate-private:
///
/// ```compile_fail,E0624
/// use stellar_agent_network::SoftwareSigningKey;
/// let key = SoftwareSigningKey::new_from_bytes([7; 32]);
/// let _ = key.sign_raw(&[0; 32]);
/// ```
pub struct SoftwareSigningKey(SeedHome);

enum SeedHome {
    Boxed(SecretBox<[u8; 32]>),
    Locked(LockedSeed),
}

impl SoftwareSigningKey {
    /// Constructs a `SoftwareSigningKey` from a `Zeroizing<[u8; 32]>` container.
    ///
    /// Copies into a heap-allocated `SecretBox`. The `raw` parameter zeroizes
    /// when this function returns; the box zeroizes when the signing key drops.
    /// Wallet signers transfer their locked home through `signer_from_wallet`.
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
        reason = "the owned Zeroizing parameter zeroizes on return"
    )]
    pub fn new_from_zeroizing(raw: Zeroizing<[u8; 32]>) -> Self {
        // Initialize the boxed seed in place from the zeroizing input.
        Self(SeedHome::Boxed(SecretBox::init_with_mut(
            |dst: &mut [u8; 32]| {
                dst.copy_from_slice(&*raw);
            },
        )))
    }

    /// Constructs a `SoftwareSigningKey` from 32 raw bytes.
    ///
    /// **Test and fixture use only.** The caller is responsible for zeroing
    /// the source bytes after this call. Production code uses
    /// [`SoftwareSigningKey::new_from_zeroizing`] or transfers a locked wallet home.
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
        Self(SeedHome::Boxed(SecretBox::new(Box::new(bytes))))
    }

    /// Take ownership of a wallet's stable seed home without copying its bytes.
    pub(crate) fn from_locked_seed(seed: LockedSeed) -> Self {
        Self(SeedHome::Locked(seed))
    }

    /// Exposes the raw 32-byte secret key seed for the signing implementation.
    ///
    /// `pub(crate)`: called by `SoftwareSigningKey::sign_raw` and
    /// `SoftwareSigningKey::public_key` only.
    pub(crate) fn expose_secret_for_signing(&self) -> &[u8; 32] {
        match &self.0 {
            SeedHome::Boxed(seed) => seed.expose_secret(),
            SeedHome::Locked(seed) => seed.seed(),
        }
    }

    /// Signs 32 bytes with the ed25519 secret seed: the primitive under every
    /// typed signing method.
    ///
    /// Reads the seed in place from its home, boxed or locked, and builds the
    /// dalek signing key from it; the dalek key zeroizes when it drops at the
    /// end of the call. Crate-private: outside this crate a signature is made
    /// only over a typed payload.
    pub(crate) fn sign_raw(&self, bytes: &[u8; 32]) -> [u8; 64] {
        use ed25519_dalek::{Signer as DalekSigner, SigningKey};

        let signing_key = SigningKey::from_bytes(self.expose_secret_for_signing());
        signing_key.sign(bytes).to_bytes()
    }
}

/// Both seed homes zeroize through their field's drop implementation.
impl Drop for SoftwareSigningKey {
    fn drop(&mut self) {
        // SecretBox zeroizes before freeing; LockedSeed zeroizes before unlocking.
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
    /// Signs a SEP-23 transaction payload with the ed25519 secret seed.
    ///
    /// # Errors
    ///
    /// `network.mainnet_authorization_refused` when the mainnet binding
    /// names another signer key.
    async fn sign_tx_payload(&self, payload: &TxSigningPayload) -> Result<[u8; 64], WalletError> {
        payload.check_mainnet_binding(self).await?;
        Ok(self.sign_raw(payload.as_bytes()))
    }

    /// Signs a smart-account auth digest with the ed25519 secret seed.
    ///
    /// # Errors
    ///
    /// This implementation does not return errors under normal use; the seed
    /// is always 32 bytes (enforced by type), so dalek construction cannot fail.
    /// The error type is `WalletError` for trait uniformity.
    async fn sign_auth_digest(
        &self,
        digest: &SmartAccountAuthDigest,
    ) -> Result<[u8; 64], WalletError> {
        Ok(self.sign_raw(digest.as_bytes()))
    }

    /// Signs a Soroban address-credentials auth-entry payload with the
    /// ed25519 secret seed.
    ///
    /// # Errors
    ///
    /// `network.mainnet_authorization_refused` when the mainnet binding
    /// names another signer key.
    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &SorobanAuthPayload,
    ) -> Result<[u8; 64], WalletError> {
        payload.check_mainnet_binding(self).await?;
        Ok(self.sign_raw(payload.as_bytes()))
    }

    /// Signs a SEP-53 message digest with the ed25519 secret seed.
    ///
    /// # Errors
    ///
    /// This implementation does not return errors under normal use.
    async fn sign_message(&self, payload: &MessagePayload) -> Result<[u8; 64], WalletError> {
        Ok(self.sign_raw(payload.as_bytes()))
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
        _auth_digest: &SmartAccountAuthDigest,
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

    #[tokio::test]
    async fn soroban_mainnet_binding_refuses_another_key() {
        let key = SoftwareSigningKey::new_from_bytes([7; 32]);
        let own_key = key.public_key().await.unwrap().0;
        let bytes = [0x3c; 32];
        let wrong = SorobanAuthPayload::bound_for_test(bytes, [0; 32]);
        let error = key
            .sign_soroban_address_auth_payload(&wrong)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "network.mainnet_authorization_refused");
        for payload in [
            SorobanAuthPayload::from_bytes_for_test(bytes),
            SorobanAuthPayload::bound_for_test(bytes, own_key),
        ] {
            let signature = key
                .sign_soroban_address_auth_payload(&payload)
                .await
                .unwrap();
            assert_eq!(signature, key.sign_raw(&bytes));
        }
    }

    #[tokio::test]
    async fn transaction_mainnet_binding_refuses_another_key() {
        let key = SoftwareSigningKey::new_from_bytes([7; 32]);
        let own_key = key.public_key().await.unwrap().0;
        let bytes = [0x3c; 32];
        let wrong = TxSigningPayload::bound_for_test(bytes, [0; 32]);
        let error = key.sign_tx_payload(&wrong).await.unwrap_err();
        assert_eq!(error.code(), "network.mainnet_authorization_refused");
        for payload in [
            TxSigningPayload::from_bytes_for_test(bytes),
            TxSigningPayload::bound_for_test(bytes, own_key),
        ] {
            let signature = key.sign_tx_payload(&payload).await.unwrap();
            assert_eq!(signature, key.sign_raw(&bytes));
        }
    }

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
        let payload = TxSigningPayload::from_bytes_for_test([0xDE_u8; 32]);
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
        let digest = SmartAccountAuthDigest::from_bytes_for_test([0xAD_u8; 32]);
        let sig = key.sign_auth_digest(&digest).await.unwrap();
        assert_eq!(sig.len(), 64);
    }

    /// Every typed method signs its payload's bytes with the one ed25519
    /// primitive: identical bytes under one seed produce identical
    /// signatures, whichever domain type carries them. The types, not the
    /// bytes, keep the domains apart.
    #[tokio::test]
    async fn sign_methods_are_cryptographically_identical_for_same_input() {
        let key = SoftwareSigningKey::new_from_bytes([42u8; 32]);
        let bytes = [0xC0_u8; 32];
        let raw = key.sign_raw(&bytes);
        assert_eq!(
            key.sign_tx_payload(&TxSigningPayload::from_bytes_for_test(bytes))
                .await
                .unwrap(),
            raw
        );
        assert_eq!(
            key.sign_auth_digest(&SmartAccountAuthDigest::from_bytes_for_test(bytes))
                .await
                .unwrap(),
            raw
        );
        assert_eq!(
            key.sign_soroban_address_auth_payload(&SorobanAuthPayload::from_bytes_for_test(bytes))
                .await
                .unwrap(),
            raw
        );
    }

    /// A message signature verifies against the SEP-53 digest of the message
    /// under the key's public key.
    #[tokio::test]
    async fn sign_message_verifies_against_the_sep53_digest() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use sha2::{Digest as _, Sha256};

        let key = SoftwareSigningKey::new_from_bytes([5u8; 32]);
        let message = b"sign me";
        let sig_bytes = key
            .sign_message(&MessagePayload::sep53(message))
            .await
            .unwrap();

        let mut preimage = b"Stellar Signed Message:\n".to_vec();
        preimage.extend_from_slice(message);
        let digest: [u8; 32] = Sha256::digest(&preimage).into();
        let vk = VerifyingKey::from_bytes(&key.public_key().await.unwrap().0).unwrap();
        vk.verify(&digest, &Signature::from_bytes(&sig_bytes))
            .expect("the message signature verifies against the SEP-53 digest");
    }

    #[tokio::test]
    async fn sign_auth_digest_then_verify_with_dalek() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let seed = [3u8; 32];
        let key = SoftwareSigningKey::new_from_bytes(seed);
        let digest = [0xAD_u8; 32];
        let sig_bytes = key
            .sign_auth_digest(&SmartAccountAuthDigest::from_bytes_for_test(digest))
            .await
            .unwrap();

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
        let auth_digest = SmartAccountAuthDigest::from_bytes_for_test([0xAB_u8; 32]);
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
        let sig_bytes = key
            .sign_tx_payload(&TxSigningPayload::from_bytes_for_test(payload))
            .await
            .unwrap();

        let pk_strkey = key.public_key().await.unwrap();
        let vk = VerifyingKey::from_bytes(&pk_strkey.0).unwrap();
        let sig = Signature::from_bytes(&sig_bytes);

        // Verification succeeds when the signature was produced by the
        // corresponding private key.
        vk.verify(&payload, &sig).expect("signature must verify");
    }
}
