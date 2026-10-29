//! The shared mlock-protected owner-seed ceremony.

use stellar_agent_core::wallet::{MlockRequired, Wallet};
use zeroize::Zeroizing;

/// A seed failure that carries the variable name, never its value.
#[derive(Debug)]
pub(super) enum OwnerSeedError {
    NotSet { var: String },
    Invalid { var: String },
    Unlock(String),
}

/// Reads a zeroizing seed and clears the parser's copied bytes.
fn seed_from_env(var_name: &str) -> Result<Zeroizing<[u8; 32]>, OwnerSeedError> {
    let s_strkey = Zeroizing::new(std::env::var(var_name).map_err(|_| OwnerSeedError::NotSet {
        var: var_name.to_owned(),
    })?);
    let mut private_key =
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).map_err(|_| {
            OwnerSeedError::Invalid {
                var: var_name.to_owned(),
            }
        })?;
    let seed = Zeroizing::new(private_key.0);
    zeroize::Zeroize::zeroize(&mut private_key.0);
    Ok(seed)
}

/// Runs an operation with a pinned seed and disposes the wallet on every path.
pub(super) async fn with_owner_seed<T, E: From<OwnerSeedError>>(
    var_name: &str,
    wallet_label: &str,
    mlock_required: MlockRequired,
    ttl_seconds: u32,
    operation: impl AsyncFnOnce(&ed25519_dalek::SigningKey) -> Result<T, E>,
) -> Result<T, E> {
    let seed = seed_from_env(var_name)?;
    let mut wallet = Wallet::unlock(wallet_label.to_owned(), seed, ttl_seconds, mlock_required)
        .await
        .map_err(|e| OwnerSeedError::Unlock(e.to_string()))?;
    let key = wallet
        .seed()
        .map(ed25519_dalek::SigningKey::from_bytes)
        .map_err(|e| OwnerSeedError::Unlock(e.to_string()));
    let result = match key {
        Ok(key) => operation(&key).await,
        Err(error) => Err(error.into()),
    };
    wallet.dispose();
    result
}
