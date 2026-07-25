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

use stellar_agent_core::error::{AuthError, ValidationError, WalletError};
use zeroize::Zeroizing;

use crate::signing::Signer;
use crate::signing::hardware::HardwareSigningKey;
use crate::signing::software::SoftwareSigningKey;

/// Identifies where a to-be-parsed S-strkey originates, so a parse failure is
/// classified into its true failure domain instead of a generic
/// keyring-not-found.
///
/// The two production callers of [`signer_from_s_strkey`] read the secret from
/// different places and require different failure codes: an unset-or-malformed
/// environment variable is an input-validation failure, while a keyring entry
/// holding an unparseable value is a genuine keyring-content condition. This
/// descriptor lets the inner helper construct the correct typed error directly,
/// removing the fragile "match on a magic error string" rewrap each caller used
/// to apply.
pub(crate) enum SecretStrkeySource<'a> {
    /// The S-strkey was read from the named environment variable. A parse
    /// failure classifies as [`ValidationError::SecretEnvInvalid`].
    EnvVar(&'a str),
    /// The S-strkey was read from the named keyring entry (service alias). A
    /// parse failure classifies as [`AuthError::KeyringNotFound`] naming the
    /// entry — the keyring stored an unparseable value.
    KeyringEntry(&'a str),
}

impl SecretStrkeySource<'_> {
    /// Builds the classification error for an S-strkey that failed to parse,
    /// naming only the source coordinate (variable name or keyring service
    /// alias) — never the value.
    fn invalid_strkey_error(&self) -> WalletError {
        match self {
            Self::EnvVar(var) => WalletError::Validation(ValidationError::SecretEnvInvalid {
                var: (*var).to_owned(),
            }),
            Self::KeyringEntry(service) => WalletError::Auth(AuthError::KeyringNotFound {
                name: format!("keyring entry '{service}' contains an invalid S-strkey"),
            }),
        }
    }
}

/// Inner helper: construct a `SoftwareSigningKey` from a raw S-strkey string
/// with full zeroisation discipline, then verify the public key.
///
/// This function is `pub(crate)` so that tests can exercise the parse + verify
/// logic directly without manipulating environment variables (which requires
/// `unsafe` in Rust 2024 edition, conflicting with `#![forbid(unsafe_code)]`
/// on the library root).
///
/// `source` identifies where `s_strkey` came from so a parse failure is
/// classified into the correct failure domain. Its two production callers are
/// [`signer_from_env`] (environment variable) and
/// [`crate::keyring::signer_from_keyring`] (keyring entry).
///
/// # Errors
///
/// - [`WalletError::Validation`] wrapping [`ValidationError::SecretEnvInvalid`]
///   when `source` is [`SecretStrkeySource::EnvVar`] and `s_strkey` cannot be
///   parsed; [`WalletError::Auth`] wrapping [`AuthError::KeyringNotFound`] when
///   `source` is [`SecretStrkeySource::KeyringEntry`]. In either case the error
///   names only the source coordinate, never the value.
/// - [`WalletError::Auth`] wrapping [`AuthError::SignerKeyMismatch`] on
///   public-key mismatch.
pub(crate) async fn signer_from_s_strkey(
    s_strkey: Zeroizing<String>,
    expected_source_g: &str,
    source: SecretStrkeySource<'_>,
) -> Result<SoftwareSigningKey, WalletError> {
    // stellar_strkey::ed25519::PrivateKey is Copy and has no Drop/Zeroize.
    // Parse the S-strkey, immediately copy the 32-byte seed into a Zeroizing
    // wrapper, then explicitly zeroize the original local before it drops.
    // stellar-strkey's PrivateKey is Copy with no Drop/Zeroize, so the residue is
    // zeroized explicitly here.
    let mut private_key = stellar_strkey::ed25519::PrivateKey::from_string(&s_strkey)
        .map_err(|_| source.invalid_strkey_error())?;
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
/// - [`WalletError::Validation`] wrapping [`ValidationError::SecretEnvNotSet`]
///   if the environment variable is not set, or
///   [`ValidationError::SecretEnvInvalid`] if it holds a value that is not a
///   valid S-strkey. Both name only the variable, never its value.
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
        WalletError::Validation(ValidationError::SecretEnvNotSet {
            var: var_name.to_owned(),
        })
    })?);

    signer_from_s_strkey(
        s_strkey,
        expected_source_g,
        SecretStrkeySource::EnvVar(var_name),
    )
    .await
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
    async fn env_source_invalid_sstrkey_returns_secret_env_invalid() {
        // "not-a-valid-strkey" is not a valid S-strkey. With the env-var source,
        // the parse failure classifies directly as the typed
        // validation.secret_env_invalid — no magic-string rewrap in the caller.
        let bad = Zeroizing::new("not-a-valid-strkey".to_owned());
        let result =
            signer_from_s_strkey(bad, "GDUMMY", SecretStrkeySource::EnvVar("SOURCE_TEST_VAR"))
                .await;
        assert!(result.is_err(), "invalid S-strkey must fail");
        // Extract the WalletError via explicit match to avoid the Debug
        // bound on T that unwrap_err() requires (SoftwareSigningKey
        // deliberately does not implement Debug to prevent secret leakage).
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err"),
        };
        assert_eq!(err.category(), ErrorCategory::Validation);
        assert_eq!(err.code(), "validation.secret_env_invalid");
        // The variable name appears; the (malformed) value must never be echoed.
        assert!(err.message().contains("SOURCE_TEST_VAR"));
        assert!(!err.message().contains("not-a-valid-strkey"));
    }

    #[tokio::test]
    async fn keyring_source_invalid_sstrkey_returns_keyring_not_found() {
        // With the keyring-entry source, the same parse failure classifies as a
        // genuine keyring-content condition naming the service alias.
        let bad = Zeroizing::new("not-a-valid-strkey".to_owned());
        let result = signer_from_s_strkey(
            bad,
            "GDUMMY",
            SecretStrkeySource::KeyringEntry("stellar-agent-signer"),
        )
        .await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("expected Err"),
        };
        assert_eq!(err.category(), ErrorCategory::Auth);
        assert_eq!(err.code(), "auth.keyring_not_found");
        assert!(err.message().contains("stellar-agent-signer"));
    }

    #[tokio::test]
    async fn key_mismatch_returns_signer_key_mismatch() {
        let seed = [1u8; 32];
        let s_strkey = sstrkey_for_seed(seed);

        // Pass an expected G-strkey that does NOT match the seed.
        let result = signer_from_s_strkey(
            s_strkey,
            "GDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY",
            SecretStrkeySource::EnvVar("SOURCE_TEST_VAR"),
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

        let signer = signer_from_s_strkey(
            s_strkey,
            &expected_g,
            SecretStrkeySource::EnvVar("SOURCE_TEST_VAR"),
        )
        .await
        .expect("matching key must succeed");

        // Verify the returned signer's public key matches the expected G-strkey.
        let pk: stellar_strkey::ed25519::PublicKey = signer.public_key().await.unwrap();
        let got_g = pk.to_string().to_string();
        assert_eq!(got_g, expected_g);
    }

    #[tokio::test]
    async fn signer_from_env_missing_var_returns_secret_env_not_set() {
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
        // the error is a validation.secret_env_* code either way (not-set OR
        // invalid-strkey).
        // A valid S-strkey that matches GDUMMY is astronomically unlikely.
        assert_eq!(err.category(), ErrorCategory::Validation);
    }
}
