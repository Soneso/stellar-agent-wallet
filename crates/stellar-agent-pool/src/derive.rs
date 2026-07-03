//! Channel keypair re-derivation from the pool master seed.
//!
//! Channel secrets are NEVER persisted; they are re-derived on demand from the
//! pool master BIP-39 seed held in the OS keyring.  This module provides both
//! the raw derivation step and a keyring-read helper that ensures both the
//! base64 password string and the decoded seed bytes are wrapped in `Zeroizing`
//! so they are zeroed on drop.
//!
//! # Secret lifecycle
//!
//! 1. Load the 64-byte BIP-39 seed from the keyring via
//!    [`load_pool_master_seed_from_keyring`] (this module) OR load manually and
//!    pass to [`derive_channel_signer`].
//! 2. Use the returned [`SoftwareSigningKey`] for one signing operation.
//! 3. Drop the `SoftwareSigningKey` immediately — the `SecretBox` inside
//!    zeroizes on drop.
//!
//! # Byte-layout citations
//!
//! The derivation path `m/44'/148'/index'` is SLIP-0010 ed25519 hardened CKD
//! over a BIP-39 seed.  Channel indices start at 1; index 0 is reserved for
//! the wallet's primary account.
//!
//! Cited from `stellar-agent-derive` which cites SLIP-0010 §"Hardened child
//! key derivation" + SEP-5 §"Multi-Account Hierarchy for Deterministic Wallets".

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use keyring_core::Entry as KeyringEntry;
use secrecy::ExposeSecret;
use stellar_agent_derive::Sep5Wallet;
use stellar_agent_network::SoftwareSigningKey;
use zeroize::Zeroizing;

use crate::error::PoolError;

/// Loads the pool master 64-byte BIP-39 seed from the OS keyring, with both
/// the base64 password string and the decoded bytes wrapped in [`Zeroizing`].
///
/// This is the canonical keyring-read path for the pool master.  It ensures:
///
/// - `get_password()` result is immediately wrapped in `Zeroizing<String>` so
///   the base64 representation is zeroed when the function returns.
/// - The base64 decode output is wrapped in `Zeroizing<Vec<u8>>` so the
///   intermediate byte buffer is zeroed before the caller's `[u8; 64]` copy
///   is returned.
/// - The error arm on decode failure carries NO secret-derived bytes.
///
/// The caller receives a `Zeroizing<[u8; 64]>` sized to exactly 64 bytes.
/// The seed is read ONCE; call [`derive_channel_signer`] in a loop to derive
/// multiple channels from the result rather than re-reading the keyring per
/// channel, to minimise the live window.
///
/// # Errors
///
/// Returns [`PoolError::InitFailed`] if the keyring entry cannot be opened or
/// read, or if the base64 decode fails.
///
/// # Panics
///
/// Never panics.  A decoded length other than 64 bytes returns `PoolError::InitFailed`.
pub fn load_pool_master_seed_from_keyring(
    service: &str,
    account: &str,
) -> Result<Zeroizing<[u8; 64]>, PoolError> {
    let entry = KeyringEntry::new(service, account).map_err(|e| PoolError::InitFailed {
        detail: format!("keyring entry open failed for pool master ({service}/{account}): {e}"),
    })?;

    // Wrap the returned password string immediately to ensure it zeroizes on drop.
    let pw = Zeroizing::new(entry.get_password().map_err(|_| PoolError::InitFailed {
        detail: format!("keyring get_password failed for pool master ({service}/{account})"),
    })?);

    // Decode into a Zeroizing<Vec<u8>> so the intermediate buffer is zeroed
    // before we copy into the fixed-size array.
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(pw.as_bytes()).map_err(|_| {
        PoolError::InitFailed {
            // Do NOT include any derived bytes in the error message.
            detail: format!("pool master seed base64-decode failed ({service}/{account})"),
        }
    })?);

    // Copy into a fixed-size Zeroizing array.
    let mut seed = Zeroizing::new([0u8; 64]);
    if decoded.len() != 64 {
        return Err(PoolError::InitFailed {
            detail: format!(
                "pool master seed length mismatch: expected 64 bytes, got {} \
                 ({service}/{account})",
                decoded.len()
            ),
        });
    }
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

/// Re-derives the channel keypair at `m/44'/148'/index'` from a 64-byte BIP-39
/// pool master seed.
///
/// The returned [`SoftwareSigningKey`] is ready for use with
/// `ClassicOpBuilder::build_and_sign_multi` (via `&dyn Signer`).  Drop it
/// as soon as signing is complete.
///
/// # Errors
///
/// Returns [`PoolError::DeriveFailed`] if `Sep5Wallet::derive_account` fails
/// (e.g. `index >= 2^31`).
///
/// # Secret discipline
///
/// - `seed` is consumed by value into a `Zeroizing` wrapper so the caller's
///   copy is zeroed on entry.
/// - The intermediate `DerivedAccount` extracts its `SecretBox<[u8; 32]>` into
///   a `Zeroizing<[u8; 32]>` for the `SoftwareSigningKey` constructor.
/// - After this function returns, the only live copy of the secret is inside
///   the `SoftwareSigningKey`'s `SecretBox`; it is zeroed when the key is
///   dropped.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_pool::derive::derive_channel_signer;
/// use zeroize::Zeroizing;
///
/// // In production: load from keyring.
/// let seed = Zeroizing::new([0u8; 64]);
/// let signer = derive_channel_signer(seed, 1).unwrap();
/// // Use signer for one signing operation, then drop it.
/// ```
#[allow(
    clippy::needless_pass_by_value,
    reason = "ownership of `seed` is required so its Zeroizing<> Drop fires when this \
              function returns, clearing the caller's stack copy"
)]
pub fn derive_channel_signer(
    seed: Zeroizing<[u8; 64]>,
    index: u32,
) -> Result<SoftwareSigningKey, PoolError> {
    // from_bip39_seed_zeroizing consumes the Zeroizing<[u8;64]> by value so no
    // bare [u8;64] stack temporary forms (prevents the master-seed copy escaping
    // zeroize).  `seed` is moved into the wallet's internal Zeroizing storage;
    // the wallet zeroizes it on drop at the end of this function.
    let wallet = Sep5Wallet::from_bip39_seed_zeroizing(seed);
    // seed has been consumed; the wallet holds the only live copy.
    let account = wallet.derive_account(index)?;

    // Extract the secret seed from the DerivedAccount's SecretBox into a
    // Zeroizing buffer for the SoftwareSigningKey constructor.
    // `expose_secret()` is the only way to access the inner [u8; 32].
    // The Zeroizing wrapper ensures the intermediate stack copy is cleared.
    let raw: Zeroizing<[u8; 32]> = Zeroizing::new(*account.secret_seed().expose_secret());

    // `new_from_zeroizing` moves `raw` into a SecretBox and zeroes the source.
    Ok(SoftwareSigningKey::new_from_zeroizing(raw))
}
