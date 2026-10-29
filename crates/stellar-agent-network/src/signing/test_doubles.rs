//! A signer double for signing-boundary tests that counts every key access.
//!
//! "Before any key access" is asserted as zero calls of every method: a
//! `public_key` call counts because a software key derives it from its seed,
//! and every `sign_*` call counts as a signing.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use stellar_agent_core::error::WalletError;

use super::{
    MessagePayload, Signer, SmartAccountAuthDigest, SoftwareSigningKey, SorobanAuthPayload,
    TxSigningPayload, WebAuthnAssertion,
};

/// Wraps a software key and counts each call of each [`Signer`] method.
/// Clones share their key and counters.
#[derive(Clone)]
pub struct CountingSigner {
    key: Arc<SoftwareSigningKey>,
    #[cfg(feature = "mainnet-write")]
    key_bytes: [u8; 32],
    corrupt: bool,
    public_keys: Arc<AtomicUsize>,
    signs: Arc<AtomicUsize>,
}

impl CountingSigner {
    /// A signer over the key with `seed`.
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            key: Arc::new(SoftwareSigningKey::new_from_bytes(seed)),
            #[cfg(feature = "mainnet-write")]
            key_bytes: ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes(),
            corrupt: false,
            public_keys: Arc::new(AtomicUsize::new(0)),
            signs: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A signer over the key with `seed` whose every signature has its first
    /// byte flipped, so it no longer verifies.
    #[cfg(feature = "mainnet-write")]
    pub fn corrupting(seed: [u8; 32]) -> Self {
        Self {
            corrupt: true,
            ..Self::new(seed)
        }
    }

    /// The key's public key bytes, read without counting.
    #[cfg(feature = "mainnet-write")]
    pub fn key_bytes(&self) -> [u8; 32] {
        self.key_bytes
    }

    /// Calls of [`Signer::public_key`].
    pub fn public_key_calls(&self) -> usize {
        self.public_keys.load(Ordering::SeqCst)
    }

    /// Calls of every signing method together.
    pub fn sign_calls(&self) -> usize {
        self.signs.load(Ordering::SeqCst)
    }

    /// Every key access together.
    pub fn key_accesses(&self) -> usize {
        self.public_key_calls() + self.sign_calls()
    }

    fn finish(&self, signature: Result<[u8; 64], WalletError>) -> Result<[u8; 64], WalletError> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        signature.map(|mut bytes| {
            if self.corrupt {
                bytes[0] ^= 0x01;
            }
            bytes
        })
    }
}

#[async_trait]
impl Signer for CountingSigner {
    async fn sign_tx_payload(&self, payload: &TxSigningPayload) -> Result<[u8; 64], WalletError> {
        self.finish(self.key.sign_tx_payload(payload).await)
    }

    async fn sign_auth_digest(
        &self,
        digest: &SmartAccountAuthDigest,
    ) -> Result<[u8; 64], WalletError> {
        self.finish(self.key.sign_auth_digest(digest).await)
    }

    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &SorobanAuthPayload,
    ) -> Result<[u8; 64], WalletError> {
        self.finish(self.key.sign_soroban_address_auth_payload(payload).await)
    }

    async fn sign_message(&self, payload: &MessagePayload) -> Result<[u8; 64], WalletError> {
        self.finish(self.key.sign_message(payload).await)
    }

    async fn sign_webauthn_assertion(
        &self,
        auth_digest: &SmartAccountAuthDigest,
        credential_id: &[u8],
    ) -> Result<WebAuthnAssertion, WalletError> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        self.key
            .sign_webauthn_assertion(auth_digest, credential_id)
            .await
    }

    async fn public_key(&self) -> Result<stellar_strkey::ed25519::PublicKey, WalletError> {
        self.public_keys.fetch_add(1, Ordering::SeqCst);
        self.key.public_key().await
    }
}
