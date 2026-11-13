//! The shared owner-seed ceremony keeps the seed and its signing key in one
//! page, locked when the configured lock succeeds. The parsing buffer is cleared
//! before the signing operation runs.

use stellar_agent_core::wallet::{MlockRequired, Wallet};
use zeroize::Zeroizing;

/// A seed failure carries neither a variable name nor a secret value.
#[derive(Debug)]
pub(super) enum OwnerSeedError {
    NotSet,
    Invalid,
    Unlock(String),
}

#[cfg(not(test))]
type StagingSeed = Zeroizing<[u8; 32]>;

#[cfg(test)]
struct StagingSeed(Zeroizing<[u8; 32]>);

#[cfg(test)]
impl std::ops::Deref for StagingSeed {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl Drop for StagingSeed {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
        STAGING_SEED_CLEARED.set(self.0.iter().all(|byte| *byte == 0));
    }
}

#[cfg(test)]
thread_local! {
    static STAGING_SEED_CLEARED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static STAGING_TEXT_CLEARED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LOCKED_RANGE: std::cell::Cell<Option<(usize, usize)>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
struct StagingText(Zeroizing<String>);

#[cfg(test)]
impl std::ops::Deref for StagingText {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl Drop for StagingText {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
        STAGING_TEXT_CLEARED.set(self.0.is_empty());
    }
}

fn seed_from_env(var_name: &str) -> Result<Zeroizing<String>, OwnerSeedError> {
    std::env::var(var_name)
        .map(Zeroizing::new)
        .map_err(|_| OwnerSeedError::NotSet)
}

/// Clears the text and the parser's copied bytes before the ceremony.
fn seed_from_text(s_strkey: Zeroizing<String>) -> Result<StagingSeed, OwnerSeedError> {
    #[cfg(test)]
    let s_strkey = StagingText(s_strkey);
    let mut private_key = stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey)
        .map_err(|_| OwnerSeedError::Invalid)?;
    drop(s_strkey);
    let seed = Zeroizing::new(private_key.0);
    zeroize::Zeroize::zeroize(&mut private_key.0);
    #[cfg(test)]
    let seed = StagingSeed(seed);
    Ok(seed)
}

/// Runs an operation with the seed and its signing key in the wallet's page.
/// The page is locked when the configured lock succeeds. The parsing buffer
/// clears before the operation runs; disposal zeroizes the key and seed before
/// unlocking their page.
pub(super) async fn with_owner_seed<T, E: From<OwnerSeedError>>(
    var_name: &str,
    wallet_label: &str,
    mlock_required: MlockRequired,
    ttl_seconds: u32,
    operation: impl AsyncFnOnce(&ed25519_dalek::SigningKey) -> Result<T, E>,
) -> Result<T, E> {
    with_owner_seed_text(
        seed_from_env(var_name)?,
        wallet_label,
        mlock_required,
        ttl_seconds,
        operation,
    )
    .await
}

/// Clears the supplied text before operating with the wallet's locked key.
pub(super) async fn with_owner_seed_text<T, E: From<OwnerSeedError>>(
    seed: Zeroizing<String>,
    wallet_label: &str,
    mlock_required: MlockRequired,
    ttl_seconds: u32,
    operation: impl AsyncFnOnce(&ed25519_dalek::SigningKey) -> Result<T, E>,
) -> Result<T, E> {
    let mut wallet = {
        let seed = seed_from_text(seed)?;
        Wallet::unlock(wallet_label.to_owned(), &seed, ttl_seconds, mlock_required)
            .map_err(|e| OwnerSeedError::Unlock(e.to_string()))?
    };
    #[cfg(test)]
    LOCKED_RANGE.set(wallet.locked_range_for_test());
    let key = wallet
        .signing_key()
        .map_err(|e| OwnerSeedError::Unlock(e.to_string()));
    let result = match key {
        Ok(key) => operation(key).await,
        Err(error) => Err(error.into()),
    };
    wallet.dispose();
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test-only assertions")]
mod tests {
    use super::*;
    use serial_test::serial;
    use stellar_agent_core::wallet::mlock::force_lock_failure_for_test;

    const VAR: &str = "OWNER_SEED_LOCKED_PAGE_TEST";

    #[tokio::test]
    async fn seed_text_is_cleared_before_operation() {
        STAGING_TEXT_CLEARED.set(false);
        let seed = Zeroizing::new(
            stellar_strkey::ed25519::PrivateKey([42; 32])
                .as_unredacted()
                .to_string()
                .to_string(),
        );
        with_owner_seed_text(seed, "test", MlockRequired::Warn, 30, async |key| {
            assert!(STAGING_TEXT_CLEARED.get());
            assert_eq!(key.to_bytes(), [42; 32]);
            Ok::<_, OwnerSeedError>(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn seed_text_is_cleared_on_failure() {
        STAGING_TEXT_CLEARED.set(false);
        let ran = std::cell::Cell::new(false);
        let result = with_owner_seed_text(
            Zeroizing::new("invalid".into()),
            "test",
            MlockRequired::Warn,
            30,
            async |_| {
                ran.set(true);
                Ok::<_, OwnerSeedError>(())
            },
        )
        .await;
        assert!(matches!(result, Err(OwnerSeedError::Invalid)));
        assert!(STAGING_TEXT_CLEARED.get());
        assert!(!ran.get());
    }

    #[tokio::test]
    #[serial]
    async fn with_owner_seed_keeps_env_behavior() {
        assert!(matches!(
            seed_from_env("OWNER_SEED_MISSING_TEST"),
            Err(OwnerSeedError::NotSet)
        ));
        let _env = SeedEnv::new();
        with_owner_seed(VAR, "test", MlockRequired::Warn, 30, async |key| {
            assert_eq!(key.to_bytes(), [42; 32]);
            Ok::<_, OwnerSeedError>(())
        })
        .await
        .unwrap();
        let _invalid = SeedEnv::with_value("invalid");
        let result = with_owner_seed(VAR, "test", MlockRequired::Warn, 30, async |_| {
            Ok::<_, OwnerSeedError>(())
        })
        .await;
        assert!(matches!(result, Err(OwnerSeedError::Invalid)));
    }
    struct SeedEnv;
    impl SeedEnv {
        fn new() -> Self {
            Self::with_value(
                stellar_strkey::ed25519::PrivateKey([42; 32])
                    .as_unredacted()
                    .to_string()
                    .as_ref(),
            )
        }
        #[allow(
            unsafe_code,
            reason = "test-only environment mutation serialized by serial"
        )]
        fn with_value(value: &str) -> Self {
            // SAFETY: all users of this test variable hold the serial test lock.
            unsafe {
                std::env::set_var(VAR, value);
            }
            Self
        }
    }
    impl Drop for SeedEnv {
        #[allow(
            unsafe_code,
            reason = "test-only environment cleanup serialized by serial"
        )]
        fn drop(&mut self) {
            // SAFETY: the serial test lock covers the guard's lifetime.
            unsafe {
                std::env::remove_var(VAR);
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn the_staging_seed_is_cleared_before_the_operation() {
        let _env = SeedEnv::new();
        STAGING_SEED_CLEARED.set(false);
        with_owner_seed(VAR, "test", MlockRequired::Warn, 30, async |_| {
            assert!(STAGING_SEED_CLEARED.get());
            Ok::<_, OwnerSeedError>(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn the_operation_receives_the_key_from_the_locked_page() {
        let _env = SeedEnv::new();
        LOCKED_RANGE.set(None);
        with_owner_seed(VAR, "test", MlockRequired::Warn, 30, async |key| {
            let (start, len) = LOCKED_RANGE.get().unwrap();
            let address = std::ptr::from_ref(key) as usize;
            assert!(address >= start && address + std::mem::size_of_val(key) <= start + len);
            assert_eq!(key.to_bytes(), [42; 32]);
            Ok::<_, OwnerSeedError>(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn a_required_lock_failure_never_runs_the_operation() {
        let _env = SeedEnv::new();
        let ran = std::cell::Cell::new(false);
        force_lock_failure_for_test(true);
        let result = with_owner_seed(VAR, "test", MlockRequired::True, 30, async |_| {
            ran.set(true);
            Ok::<_, OwnerSeedError>(())
        })
        .await;
        assert!(matches!(result, Err(OwnerSeedError::Unlock(_))));
        assert!(!ran.get());
    }
}
