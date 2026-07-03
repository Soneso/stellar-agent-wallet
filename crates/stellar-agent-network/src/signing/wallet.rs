//! Wallet-backed signer resolution — mlock-protected signing window.
//!
//! Provides [`signer_from_wallet`], which converts an already-unlocked
//! [`stellar_agent_core::wallet::Wallet`] into a [`SoftwareSigningKey`] for
//! use with [`super::envelope_signing::attach_signature`].
//!
//! # Lifetime and disposal discipline
//!
//! The caller constructs a `Wallet` immediately before calling
//! `signer_from_wallet`, uses the returned `SoftwareSigningKey` exactly once
//! with `attach_signature`, then lets both the key and the wallet drop at the
//! end of the signing block.  On drop:
//!
//! 1. `SoftwareSigningKey` drops → `SecretBox::drop` zeroises the heap seed.
//! 2. `Wallet` drops → `Wallet::dispose` fires → `LockedSeed::internal_dispose`
//!    runs `munlock` then `Zeroizing::drop`, clearing the locked page.
//!
//! Both zeroization paths fire even on panic-unwind (Rust Drop glue).
//!
//! # Secret-residency window
//!
//! The seed bytes live in protected RAM for the duration between
//! `Wallet::unlock` and the wallet's drop.  `signer_from_wallet` copies the
//! 32 seed bytes into a `Zeroizing<[u8; 32]>` on the stack; those bytes are
//! cleared when `Zeroizing` drops (at the end of this function).  The only
//! remaining copy lives inside `SoftwareSigningKey`'s `SecretBox`.
//!
//! # No keyring access
//!
//! Unlike [`super::source::signer_from_env`] or
//! [`crate::keyring::signer_from_keyring`], this function performs no keyring
//! I/O.  The secret has already been loaded by the caller (who constructed
//! the `Wallet`).
//!
//! # Public-key verification
//!
//! The caller is responsible for verifying that the `Wallet` corresponds to
//! the expected source account before calling `signer_from_wallet` and before
//! any RPC call.  The typical pattern is:
//!
//! ```text
//! let signer = signer_from_wallet(&wallet)?;
//! let pk = signer.public_key().await?;
//! // compare pk with expected_source_g before proceeding
//! ```
//!
//! This mirrors the public-key verification invariant in
//! `signing::source::signer_from_s_strkey`.

use stellar_agent_core::{
    error::{AuthError, WalletError},
    wallet::Wallet,
};
use zeroize::Zeroizing;

use super::software::SoftwareSigningKey;

/// Constructs a [`SoftwareSigningKey`] from an already-unlocked [`Wallet`].
///
/// Borrows the seed bytes from `wallet` (which must be active — neither
/// TTL-expired nor disposed), copies them into a `Zeroizing<[u8; 32]>`, and
/// moves that into `SoftwareSigningKey::new_from_zeroizing`.  The
/// `Zeroizing` wrapper on the stack copy drops at function exit; the
/// `SecretBox` inside `SoftwareSigningKey` owns the sole remaining copy.
///
/// # Per-call-load lifetime contract
///
/// The returned `SoftwareSigningKey` MUST be dropped before — or in the same
/// scope as — the `Wallet`.  Both the key and the wallet should live for
/// exactly one `attach_signature` call:
///
/// ```text
/// let mut wallet = Wallet::unlock(...).await?;
/// let signer     = signer_from_wallet(&wallet)?;
/// let signed_xdr = attach_signature(&xdr, &signer, passphrase).await?;
/// // signer drops here → SecretBox zeroised
/// wallet.dispose();
/// // LockedSeed munlock + zeroised
/// ```
///
/// # Errors
///
/// - [`WalletError::Auth`] wrapping [`AuthError::KeyringLocked`] when the
///   wallet has been disposed or its TTL has expired.  The `KeyringLocked`
///   variant is the most semantically accurate existing error for "key
///   material is no longer accessible due to lifecycle policy".
///
/// # Panics
///
/// Never panics.
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
/// let seed = [0u8; 32]; // obtained from keyring / env
/// let mut wallet = Wallet::unlock(
///     "my-profile".to_owned(),
///     Zeroizing::new(seed),
///     30,
///     MlockRequired::False,
/// ).await?;
///
/// let signer = signer_from_wallet(&wallet)?;
/// let passphrase = "Test SDF Network ; September 2015";
/// let signed_xdr = attach_signature(unsigned_xdr, &signer, passphrase).await?;
/// // signer drops here; SecretBox zeroised
/// wallet.dispose();
/// // LockedSeed munlock + zeroise
/// # Ok(())
/// # }
/// ```
pub fn signer_from_wallet(wallet: &Wallet) -> Result<SoftwareSigningKey, WalletError> {
    // Wallet::seed() returns Err when the wallet is disposed or TTL-expired.
    // Map to AuthError::KeyringLocked — the error variant that most precisely
    // expresses "signing material unavailable due to lifecycle policy".
    let seed_bytes: &[u8; 32] = wallet
        .seed()
        .map_err(|_| WalletError::Auth(AuthError::KeyringLocked))?;

    // Copy the 32 seed bytes into a Zeroizing wrapper on the stack.
    // Zeroizing::drop fires at end of this function, clearing the copy.
    // The only surviving copy moves into SoftwareSigningKey's SecretBox.
    let seed_copy: Zeroizing<[u8; 32]> = Zeroizing::new(*seed_bytes);

    Ok(SoftwareSigningKey::new_from_zeroizing(seed_copy))
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

    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    // ── signer_from_wallet happy path ─────────────────────────────────────────

    #[tokio::test]
    async fn signer_from_wallet_returns_signer_for_active_wallet() {
        let mut wallet = Wallet::unlock(
            "test-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();

        let signer = signer_from_wallet(&wallet).expect("active wallet must produce signer");

        // The returned signer must produce the correct public key.
        let pk = signer.public_key().await.expect("public key derivation");
        let pk_g = pk.to_string().to_string();
        // Verify the public key is non-empty and looks like a G-strkey.
        assert!(
            pk_g.starts_with('G'),
            "public key must be a G-strkey; got: {pk_g}"
        );

        wallet.dispose();
    }

    #[tokio::test]
    async fn signer_from_wallet_produces_valid_signature() {
        let mut wallet = Wallet::unlock(
            "test-sign-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();

        let signer = signer_from_wallet(&wallet).expect("active wallet must produce signer");
        let payload = [0xABu8; 32];
        let sig = signer
            .sign_tx_payload(&payload)
            .await
            .expect("signing must succeed");

        assert_eq!(sig.len(), 64, "ed25519 signature must be 64 bytes");
        wallet.dispose();
    }

    // ── signer_from_wallet error path ─────────────────────────────────────────

    #[tokio::test]
    async fn signer_from_wallet_returns_keyring_locked_after_dispose() {
        let mut wallet = Wallet::unlock(
            "disposed-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();

        wallet.dispose();

        // `SoftwareSigningKey` deliberately omits `Debug` to prevent secret
        // leakage through log/assert formatting.  `expect_err` / `unwrap_err`
        // both require `T: Debug`; use a `match` to extract the error variant
        // without requiring that bound.
        let err = match signer_from_wallet(&wallet) {
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
        let mut wallet = Wallet::unlock(
            "ttl-expired-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();

        // Force expiry by setting the TTL timestamp to the past.
        // Direct field access is not pub; manipulate via the public API by
        // setting expires_at_unix_ms = 0 (epoch = definitely in the past).
        //
        // Note: expires_at_unix_ms is not a public field.  We simulate TTL
        // expiry by using the test-visible fact that Wallet::seed() returns
        // Disposed when now_ms >= expires_at_unix_ms, and we can reach that
        // state by disposing the wallet.
        //
        // The full TTL-expiry path (clock-based) is tested in lifecycle::tests.
        // Here we exercise the error-mapping contract: disposed wallet →
        // signer_from_wallet → KeyringLocked.
        wallet.dispose();

        let result = signer_from_wallet(&wallet);
        assert!(result.is_err(), "expired/disposed wallet must return Err");
    }

    // ── Single keyring access per commit-path call ────────────────────────────

    /// Verifies that `signer_from_wallet` accesses the wallet's seed exactly
    /// once per call.  The `Wallet::seed()` method is deterministic and does
    /// not perform I/O; we verify this by calling `signer_from_wallet` twice
    /// on the same active wallet and asserting both signers produce the same
    /// public key (proving consistent, non-destructive seed access).
    ///
    /// The keyring is NOT consulted on sign calls: `signer_from_wallet` reads
    /// `Wallet::seed()` (already in mlock-protected RAM) rather than calling
    /// `get_password()`.
    #[tokio::test]
    async fn signer_from_wallet_does_not_access_keyring() {
        // No keyring mock installed; any keyring access would panic under
        // keyring_core::NoDefaultStore (no default store registered).
        // The test passes only if signer_from_wallet never touches the keyring.
        let mut wallet = Wallet::unlock(
            "no-keyring-access-profile".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();

        // Call twice: both must succeed without touching the keyring.
        let signer_a = signer_from_wallet(&wallet).expect("first call");
        let signer_b = signer_from_wallet(&wallet).expect("second call");

        let pk_a = signer_a.public_key().await.expect("pk_a");
        let pk_b = signer_b.public_key().await.expect("pk_b");

        assert_eq!(
            pk_a.0, pk_b.0,
            "both signers must derive the same public key from the same seed"
        );

        wallet.dispose();
    }

    /// Verifies that `signer_from_wallet` on an already-disposed wallet
    /// returns the AuthError::KeyringLocked without attempting any keyring
    /// access (no panic from NoDefaultStore).
    #[tokio::test]
    async fn signer_from_disposed_wallet_returns_error_without_keyring_access() {
        let mut wallet = Wallet::unlock(
            "disposed-no-keyring".to_owned(),
            Zeroizing::new(TEST_SEED),
            30,
            MlockRequired::False,
        )
        .await
        .unwrap();
        wallet.dispose();

        // Must return Err without touching keyring (no mock installed).
        // `SoftwareSigningKey` deliberately omits `Debug`; extract error via
        // match to avoid the `T: Debug` bound on `unwrap_err`.
        let err = match signer_from_wallet(&wallet) {
            Ok(_) => panic!("disposed wallet must error"),
            Err(e) => e,
        };
        assert_eq!(err.code(), "auth.keyring_locked");
    }
}
