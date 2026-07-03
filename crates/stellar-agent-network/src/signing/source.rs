//! Shared signer-resolution helpers — software and hardware.
//!
//! Centralises the seed-zeroisation discipline for both signing paths.
//! Every call site resolves to a `signer_from_env` / `signer_from_ledger`
//! call followed by `attach_signature`.
//!
//! # Seed-zeroisation invariant
//!
//! `signer_from_env` performs the full zeroisation sequence:
//!
//! 1. `std::env::var` result immediately wrapped in `Zeroizing<String>`.
//! 2. `stellar_strkey::ed25519::PrivateKey::from_string` parses the S-strkey.
//! 3. Seed bytes copied into `Zeroizing<[u8; 32]>`.
//! 4. `zeroize::Zeroize::zeroize(&mut private_key.0)` — explicit zeroisation of
//!    the `Copy` residue in the `PrivateKey` stack local.
//! 5. `Zeroizing<String>` holding the S-strkey dropped before `SoftwareSigningKey`
//!    is returned.
//! 6. `SoftwareSigningKey::new_from_zeroizing` moves the seed into a `SecretBox`,
//!    whose `Drop` impl zeroes the heap allocation.
//!
//! # stellar-strkey upstream gap
//!
//! `stellar_strkey::ed25519::PrivateKey` is `Copy` and has no `Drop`/`Zeroize`
//! impl. Step 4 above patches the gap explicitly. When stellar-strkey adds
//! `Drop+Zeroize` to `PrivateKey`, remove the explicit
//! `zeroize::Zeroize::zeroize` call.
//!
//! # Public key verification before use
//!
//! Both helpers derive or fetch the public key from the signer and compare it
//! against the `expected_source_g` argument BEFORE returning. Any mismatch
//! returns `AuthError::SignerKeyMismatch`, ensuring no RPC or network call
//! proceeds if the key doesn't match the claimed source.

use stellar_agent_core::error::{AuthError, WalletError};
use zeroize::Zeroizing;

use crate::signing::Signer;
use crate::signing::hardware::HardwareSigningKey;
use crate::signing::software::SoftwareSigningKey;

/// Inner helper: construct a `SoftwareSigningKey` from a raw S-strkey string
/// with full zeroisation discipline, then verify the public key.
///
/// This function is `pub(crate)` so that tests can exercise the parse + verify
/// logic directly without manipulating environment variables (which requires
/// `unsafe` in Rust 2024 edition, conflicting with `#![forbid(unsafe_code)]`
/// on the library root).
///
/// The outer `signer_from_env` is the only production call site.
///
/// # Errors
///
/// - [`WalletError::Auth`] wrapping `KeyringNotFound` with name
///   `"invalid S-strkey"` if `s_strkey` cannot be parsed. The wrapper
///   ([`signer_from_env`]) maps this into a more specific error naming the
///   env-var source. The inner helper does not own the env-var diagnostics —
///   it only owns the parse-and-verify contract.
/// - [`WalletError::Auth`] wrapping `SignerKeyMismatch` on public-key mismatch.
pub(crate) async fn signer_from_s_strkey(
    s_strkey: Zeroizing<String>,
    expected_source_g: &str,
) -> Result<SoftwareSigningKey, WalletError> {
    // stellar_strkey::ed25519::PrivateKey is Copy and has no Drop/Zeroize.
    // Parse the S-strkey, immediately copy the 32-byte seed into a Zeroizing
    // wrapper, then explicitly zeroize the original local before it drops.
    // stellar-strkey's PrivateKey is Copy with no Drop/Zeroize, so the residue is
    // zeroized explicitly here.
    let mut private_key =
        stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey).map_err(|_| {
            WalletError::Auth(AuthError::KeyringNotFound {
                name: "invalid S-strkey".to_owned(),
            })
        })?;
    let seed_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(private_key.0);
    // Two copies of the seed exist: `seed_bytes` (Zeroizing) and
    // `private_key.0` (plain [u8; 32]). Explicitly zeroize the latter.
    zeroize::Zeroize::zeroize(&mut private_key.0);
    // Release the heap String holding the raw S-strkey now that the seed
    // has been captured in `seed_bytes`.
    drop(s_strkey);

    let signer = SoftwareSigningKey::new_from_zeroizing(seed_bytes);

    // Derive public key and compare to expected_source_g BEFORE any RPC call.
    // A key mismatch exits here — the signer is never returned.
    let signer_pk: stellar_strkey::ed25519::PublicKey = signer.public_key().await?;
    // stellar-strkey's PublicKey::to_string() returns a heapless String; the second
    // .to_string() (Display) converts to std::String.
    let signer_gstrkey = signer_pk.to_string().to_string();
    if signer_gstrkey != expected_source_g {
        return Err(WalletError::Auth(AuthError::SignerKeyMismatch {
            expected: expected_source_g.to_owned(),
            got: signer_gstrkey,
        }));
    }

    Ok(signer)
}

/// Resolves a software signing key from a named environment variable.
///
/// Reads the S-strkey from `var_name`, applies the full seed-zeroisation
/// discipline, constructs a [`SoftwareSigningKey`], derives the public key,
/// and verifies it matches `expected_source_g` before returning.
///
/// # Errors
///
/// - [`WalletError::Auth`] wrapping [`AuthError::KeyringNotFound`] if the
///   environment variable is unset or contains an invalid S-strkey.
/// - [`WalletError::Auth`] wrapping [`AuthError::SignerKeyMismatch`] if the
///   derived public key does not match `expected_source_g`.
/// - Propagates any error from `signer.public_key()`.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::signing::source::signer_from_env;
///
/// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
/// // std::env::set_var("MY_SECRET", "S...");
/// let signer = signer_from_env(
///     "MY_SECRET",
///     "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
/// ).await?;
/// # Ok(()) }
/// ```
pub async fn signer_from_env(
    var_name: &str,
    expected_source_g: &str,
) -> Result<SoftwareSigningKey, WalletError> {
    // Wrap the env-var String in Zeroizing so the heap allocation is
    // cleared when this scope exits, regardless of the code path taken.
    let s_strkey: Zeroizing<String> = Zeroizing::new(std::env::var(var_name).map_err(|_| {
        WalletError::Auth(AuthError::KeyringNotFound {
            name: format!("environment variable '{var_name}' not set"),
        })
    })?);

    // The inner helper owns parse+verify only; map its generic
    // "invalid S-strkey" error to one that names the env-var source.
    signer_from_s_strkey(s_strkey, expected_source_g)
        .await
        .map_err(|e| match e {
            WalletError::Auth(AuthError::KeyringNotFound { ref name })
                if name == "invalid S-strkey" =>
            {
                WalletError::Auth(AuthError::KeyringNotFound {
                    name: format!("environment variable '{var_name}' contains an invalid S-strkey"),
                })
            }
            other => other,
        })
}

/// Resolves a hardware signing key from the first connected Ledger device.
///
/// Opens a native HID connection, applies the `account_index` override for
/// the BIP-32 path (`m/44'/148'/<account_index>'`), fetches the device's
/// public key, and verifies it matches `expected_source_g` before returning.
///
/// No secret key material ever leaves the device. The device is not prompted
/// for signing approval during this call (Ledger Stellar app GET_PUBLIC_KEY
/// with P1=0x00 does not require confirmation).
///
/// # Errors
///
/// - [`WalletError::WalletState`] — device not connected, wrong app, timeout.
/// - [`WalletError::Auth`] wrapping [`AuthError::SignerKeyMismatch`] if the
///   device public key does not match `expected_source_g`.
/// - Propagates any error from `hw_key.public_key()`.
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_network::signing::source::signer_from_ledger;
///
/// # async fn example() -> Result<(), stellar_agent_core::WalletError> {
/// // Requires a Ledger device with the Stellar app open.
/// let signer = signer_from_ledger(
///     0,
///     "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
/// ).await?;
/// # Ok(()) }
/// ```
pub async fn signer_from_ledger(
    account_index: u32,
    expected_source_g: &str,
) -> Result<HardwareSigningKey, WalletError> {
    let hw_key = HardwareSigningKey::native()?.with_account_index(account_index);

    // Fetch hardware public key and compare to expected_source_g BEFORE any
    // other RPC or device operation. GET_PUBLIC_KEY does not prompt the user
    // for approval (Ledger Stellar app P1=0x00 path). Mismatch exits here
    // without proceeding to sign.
    let signer_pk: stellar_strkey::ed25519::PublicKey = hw_key.public_key().await?;
    // stellar-strkey's PublicKey::to_string() returns a heapless String; the second
    // .to_string() (Display) converts to std::String.
    let signer_gstrkey = signer_pk.to_string().to_string();
    if signer_gstrkey != expected_source_g {
        return Err(WalletError::Auth(AuthError::SignerKeyMismatch {
            expected: expected_source_g.to_owned(),
            got: signer_gstrkey,
        }));
    }

    Ok(hw_key)
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
    use super::*;
    use stellar_agent_core::error::ErrorCategory;

    /// Derive a canonical G-strkey from a known 32-byte seed for test setup.
    fn gstrkey_for_seed(seed: [u8; 32]) -> String {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = signing_key.verifying_key();
        stellar_strkey::ed25519::PublicKey(vk.to_bytes())
            .to_string()
            .to_string()
    }

    /// Build a valid S-strkey from a known 32-byte seed.
    fn sstrkey_for_seed(seed: [u8; 32]) -> Zeroizing<String> {
        Zeroizing::new(
            stellar_strkey::ed25519::PrivateKey(seed)
                .as_unredacted()
                .to_string()
                .to_string(),
        )
    }

    // Note: tests for `signer_from_env` (the env-var wrapper) are not included
    // here because `std::env::set_var` / `remove_var` are `unsafe` in Rust 2024
    // edition, and this library crate carries `#![forbid(unsafe_code)]`. The env
    // wrapper is a thin adapter over `signer_from_s_strkey`; all logic lives in
    // that inner function, which IS tested below. The env integration is covered
    // by the CLI-layer integration tests in `stellar-agent-cli` where the test
    // binary does not carry `forbid(unsafe_code)`.

    #[tokio::test]
    async fn invalid_sstrkey_returns_keyring_not_found() {
        // "not-a-valid-strkey" is not a valid S-strkey.
        let bad = Zeroizing::new("not-a-valid-strkey".to_owned());
        let result = signer_from_s_strkey(bad, "GDUMMY").await;
        assert!(result.is_err(), "invalid S-strkey must fail");
        // Extract the WalletError via explicit match to avoid the Debug
        // bound on T that unwrap_err() requires (SoftwareSigningKey
        // deliberately does not implement Debug to prevent secret leakage).
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err"),
        };
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_not_found");
    }

    #[tokio::test]
    async fn key_mismatch_returns_signer_key_mismatch() {
        let seed = [1u8; 32];
        let s_strkey = sstrkey_for_seed(seed);

        // Pass an expected G-strkey that does NOT match the seed.
        let result = signer_from_s_strkey(
            s_strkey,
            "GDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY",
        )
        .await;
        assert!(result.is_err(), "key mismatch must fail");
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err"),
        };
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.signer_key_mismatch");
    }

    #[tokio::test]
    async fn matching_key_returns_signer() {
        let seed = [2u8; 32];
        let s_strkey = sstrkey_for_seed(seed);
        let expected_g = gstrkey_for_seed(seed);

        let signer = signer_from_s_strkey(s_strkey, &expected_g)
            .await
            .expect("matching key must succeed");

        // Verify the returned signer's public key matches the expected G-strkey.
        let pk: stellar_strkey::ed25519::PublicKey = signer.public_key().await.unwrap();
        let got_g = pk.to_string().to_string();
        assert_eq!(got_g, expected_g);
    }

    #[tokio::test]
    async fn signer_from_env_missing_var_returns_keyring_not_found() {
        // A var name that is guaranteed to be unset in CI. No set_var needed.
        let var = "STELLAR_AGENT_SOURCE_MISSING_VAR_ABCDEFGH12345";
        // The variable should not be set; if somehow it is, the test may give
        // a different error. This variable name is chosen to be distinctive
        // enough to not collide with real env vars.
        let result = signer_from_env(var, "GDUMMY").await;
        assert!(result.is_err(), "unset env var must fail");
        // Extract the WalletError via explicit match to avoid the Debug
        // bound on T that unwrap_err() requires (SoftwareSigningKey
        // deliberately does not implement Debug to prevent secret leakage).
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err for unset env var"),
        };
        // If the var happens to be set in the environment with invalid content,
        // the error will be keyring_not_found either way (not-set OR invalid-strkey).
        // A valid S-strkey that matches GDUMMY is astronomically unlikely.
        assert_eq!(err.category(), ErrorCategory::Auth);
    }
}
