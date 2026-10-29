//! Wallet-backed signer resolution with a stable seed home.
//!
//! [`signer_from_wallet`] consumes an unlocked wallet and transfers its
//! `LockedSeed` into [`SoftwareSigningKey`]. The signer reads the same bytes
//! at the same address, retaining the configured memory lock until drop.
//! Drop zeroizes before unlocking and freeing, including during panic unwind.
//!
//! The wallet's clock checks the TTL at transfer. The signer then owns the
//! seed for its own lifetime. Mainnet environment signing transfers once per
//! signature; testnet commands can retain their signer beyond the unlock TTL.
//! The caller verifies the signer's public key against the expected account.

use stellar_agent_core::{
    error::{AuthError, WalletError},
    wallet::Wallet,
};

use super::software::SoftwareSigningKey;

/// Transfer an active wallet's seed home into a signing key.
///
/// The transfer preserves the seed's address and lock. The signer zeroizes
/// the seed before unlocking its page on drop.
///
/// # Errors
///
/// Returns [`AuthError::KeyringLocked`] when the wallet refuses access because
/// it is disposed, its TTL expires, or its clock fails.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_core::wallet::{Wallet, MlockRequired};
/// use stellar_agent_network::signing::wallet::signer_from_wallet;
/// use stellar_agent_network::signing::envelope_signing::attach_signature;
/// use zeroize::Zeroizing;
///
/// # async fn example(unsigned_xdr: &str) -> Result<(), Box<dyn std::error::Error>> {
/// let seed = Zeroizing::new([0u8; 32]);
/// let wallet = Wallet::unlock("my-profile".to_owned(), &seed, 30, MlockRequired::False)?;
/// let signer = signer_from_wallet(wallet)?;
/// let passphrase = "Test SDF Network ; September 2015";
/// let signed_xdr = attach_signature(unsigned_xdr, &signer, passphrase).await?;
/// drop(signer);
/// # Ok(())
/// # }
/// ```
pub fn signer_from_wallet(wallet: Wallet) -> Result<SoftwareSigningKey, WalletError> {
    let locked = wallet
        .into_locked_seed()
        .map_err(|_| WalletError::Auth(AuthError::KeyringLocked))?;
    Ok(SoftwareSigningKey::from_locked_seed(locked))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in unit tests"
)]
mod tests {
    use stellar_agent_core::{
        error::ErrorCategory,
        wallet::{MlockRequired, Wallet},
    };

    use crate::signing::Signer;

    use super::*;
    use zeroize::Zeroizing;

    const TEST_SEED: [u8; 32] = [0x42u8; 32];
    /// The ed25519 public key of [`TEST_SEED`], as a G-strkey.
    const TEST_SEED_PUBLIC_KEY: &str = "GAQVF6GRTN4R2JCFGJBOCXZOVNWLPT72PNVF5UYAS6LA4BUYQHNRET46";

    // ── signer_from_wallet happy path ─────────────────────────────────────────

    #[tokio::test]
    async fn signer_from_wallet_returns_signer_for_active_wallet() {
        let wallet = Wallet::unlock(
            "test-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();

        let signer = signer_from_wallet(wallet).expect("active wallet must produce signer");

        // The returned signer must produce the correct public key.
        let pk = signer.public_key().await.expect("public key derivation");
        let pk_g = pk.to_string().to_string();
        // Verify the public key is non-empty and looks like a G-strkey.
        assert!(
            pk_g.starts_with('G'),
            "public key must be a G-strkey; got: {pk_g}"
        );
    }

    #[tokio::test]
    async fn signer_from_wallet_produces_valid_signature() {
        let wallet = Wallet::unlock(
            "test-sign-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();

        let signer = signer_from_wallet(wallet).expect("active wallet must produce signer");
        let payload = [0xABu8; 32];
        let sig = signer
            .sign_tx_payload(&payload)
            .await
            .expect("signing must succeed");

        assert_eq!(sig.len(), 64, "ed25519 signature must be 64 bytes");
    }

    // ── signer_from_wallet error path ─────────────────────────────────────────

    #[tokio::test]
    async fn signer_from_wallet_returns_keyring_locked_after_dispose() {
        let mut wallet = Wallet::unlock(
            "disposed-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();

        wallet.dispose();

        // `SoftwareSigningKey` deliberately omits `Debug` to prevent secret
        // leakage through log/assert formatting.  `expect_err` / `unwrap_err`
        // both require `T: Debug`; use a `match` to extract the error variant
        // without requiring that bound.
        let err = match signer_from_wallet(wallet) {
            Ok(_) => panic!("disposed wallet must fail"),
            Err(e) => e,
        };
        assert_eq!(
            err.category(),
            ErrorCategory::Auth,
            "error must be in auth category"
        );
        assert_eq!(
            err.code(),
            "auth.keyring_locked",
            "disposed wallet must map to KeyringLocked"
        );
    }

    #[tokio::test]
    async fn signer_from_wallet_returns_keyring_locked_after_ttl_expiry() {
        let now = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1000));
        let clock_now = std::sync::Arc::clone(&now);
        let clock = std::sync::Arc::new(stellar_agent_core::timefmt::MockClock::new(move || {
            Ok(clock_now.load(std::sync::atomic::Ordering::SeqCst))
        }));
        let wallet = Wallet::unlock_with_clock(
            "ttl-expired-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            1,
            MlockRequired::False,
            clock,
        )
        .unwrap();
        now.store(2000, std::sync::atomic::Ordering::SeqCst);
        let err = match signer_from_wallet(wallet) {
            Ok(_) => panic!("an expired wallet must fail"),
            Err(e) => e,
        };
        assert_eq!(
            err.code(),
            "auth.keyring_locked",
            "an expired wallet must map to KeyringLocked"
        );
    }

    // ── Single keyring access per commit-path call ────────────────────────────

    /// Ownership transfer and repeated signing use the supplied seed.
    #[tokio::test]
    async fn signer_from_wallet_does_not_access_keyring() {
        // No keyring mock installed; any keyring access would panic under
        // keyring_core::NoDefaultStore (no default store registered).
        // The test passes only if signer_from_wallet never touches the keyring.
        let wallet = Wallet::unlock(
            "no-keyring-access-profile".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();

        // Reuse the transferred home for both operations.
        let signer_a = signer_from_wallet(wallet).expect("first call");

        let pk_a = signer_a.public_key().await.expect("pk_a");
        let pk_b = signer_a.public_key().await.expect("pk_b");

        assert_eq!(
            pk_a.to_string().to_string(),
            TEST_SEED_PUBLIC_KEY,
            "the first call derives TEST_SEED's key"
        );
        assert_eq!(
            pk_b.to_string().to_string(),
            TEST_SEED_PUBLIC_KEY,
            "the second call derives TEST_SEED's key"
        );
    }

    /// Verifies that `signer_from_wallet` on an already-disposed wallet
    /// returns the AuthError::KeyringLocked without attempting any keyring
    /// access (no panic from NoDefaultStore).
    #[tokio::test]
    async fn signer_from_disposed_wallet_returns_error_without_keyring_access() {
        let mut wallet = Wallet::unlock(
            "disposed-no-keyring".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .unwrap();
        wallet.dispose();

        // Must return Err without touching keyring (no mock installed).
        // `SoftwareSigningKey` deliberately omits `Debug`; extract error via
        // match to avoid the `T: Debug` bound on `unwrap_err`.
        let err = match signer_from_wallet(wallet) {
            Ok(_) => panic!("disposed wallet must error"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "auth.keyring_locked");
    }

    #[test]
    fn the_signer_reads_the_locked_bytes() {
        let wallet = Wallet::unlock(
            "test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::Warn,
        )
        .unwrap();
        let address = wallet.seed().unwrap().as_ptr();
        let signer = signer_from_wallet(wallet).unwrap();
        assert_eq!(signer.expose_secret_for_signing().as_ptr(), address);
    }

    #[tokio::test]
    async fn a_locked_home_signs_like_a_boxed_home() {
        let wallet = Wallet::unlock(
            "test".to_owned(),
            &Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::Warn,
        )
        .unwrap();
        let locked = signer_from_wallet(wallet).unwrap();
        let boxed = SoftwareSigningKey::new_from_zeroizing(Zeroizing::new(TEST_SEED));
        assert_eq!(
            locked.public_key().await.unwrap(),
            boxed.public_key().await.unwrap()
        );
        let payload = [0xA7; 32];
        assert_eq!(
            locked.sign_tx_payload(&payload).await.unwrap(),
            boxed.sign_tx_payload(&payload).await.unwrap()
        );
    }
}
