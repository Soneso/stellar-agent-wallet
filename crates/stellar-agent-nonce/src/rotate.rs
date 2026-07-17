//! Nonce-key rotation — generates a fresh 32-byte HMAC key and stores it in
//! the platform keyring entry identified by the profile's
//! `mcp_nonce_key_alias`.
//!
//! # When to rotate
//!
//! - At first wallet deployment (no key entry exists yet).
//! - Periodically at audit-log key-rotation events.
//! - On operator demand (e.g. after a suspected credential disclosure).
//!
//! # Impact on outstanding nonces
//!
//! Rotation changes the HMAC key.  Any nonce minted with the old key fails
//! HMAC verification immediately after rotation — the in-memory
//! [`crate::ReplayWindow`] does not need explicit invalidation.  Outstanding
//! agent simulations must be re-simulated after a rotation.
//!
//! # Key encoding
//!
//! Keys are stored as URL-safe base64 (no padding) — the same encoding used
//! by [`crate::NonceMint`]'s `load_key` method.  See the crate `//!` header
//! for the encoding rationale.
//!
//! # Self-custodial key residency
//!
//! Key generation and keyring storage are delegated to
//! [`stellar_agent_network::keyring::rotate_keyring_secret_32`], which keeps
//! the raw bytes and encoded string local to that helper and zeroizes them on
//! drop.  Neither the raw bytes nor the encoded string is returned, logged, or
//! stored outside the keyring.

use stellar_agent_core::{error::WalletError, profile::schema::Profile};
use stellar_agent_network::keyring::rotate_keyring_secret_32;

/// Generates a fresh 32-byte HMAC nonce key and atomically replaces the
/// keyring entry for `profile.mcp_nonce_key_alias`.
///
/// The new key is generated via `OsRng::fill_bytes` (CSPRNG) and encoded as
/// URL-safe base64 (no padding) before storage.  The function is idempotent:
/// calling it when no entry exists (first-run case) succeeds by creating the
/// entry.  Calling it when an entry exists replaces the value atomically via
/// `set_password` (the keyring backend handles atomicity; on macOS Keychain a
/// `set_password` on an existing entry is an atomic update).
///
/// After rotation, the caller SHOULD log a tracing event at `info!` level
/// naming the profile and the rotation outcome so the operator knows
/// when rotation occurred.
///
/// # Errors
///
/// - [`WalletError::Auth`] with the keyring failure classified by
///   [`stellar_agent_network::keyring::classify_keyring_error`]:
///   `KeyringInteractiveSessionRequired` when the Windows Credential Manager
///   is unreachable from a non-interactive session,
///   `KeyringPlatformError` for other backend failures, and
///   `KeyringNotFound` when the platform keyring is unavailable (not
///   initialised or unsupported OS).
///
/// # Panics
///
/// Never panics.
///
/// # Examples
///
/// ```no_run
/// use stellar_agent_core::profile::schema::Profile;
/// use stellar_agent_nonce::rotate_nonce_key;
/// use stellar_agent_test_support::keyring_mock;
///
/// # fn make_profile() -> Profile {
/// #     Profile::builder_testnet("s", "a", "n", "b").build()
/// # }
/// keyring_mock::install().expect("mock store");
/// let profile = make_profile();
/// rotate_nonce_key(&profile).expect("rotation ok");
/// ```
pub fn rotate_nonce_key(profile: &Profile) -> Result<(), WalletError> {
    let entry_ref = &profile.mcp_nonce_key_alias;
    // The shared helper classifies keyring failures (interactive-session,
    // platform, not-found) — surface its error unchanged so environmental
    // causes keep their typed code instead of collapsing into "not found".
    rotate_keyring_secret_32(&entry_ref.service, &entry_ref.account).inspect_err(|e| {
        tracing::debug!(error = %e, "rotate_nonce_key: shared rotation failed");
    })?;
    tracing::info!(
        profile.nonce_service = entry_ref.service,
        "nonce key rotated; outstanding nonces invalidated"
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;
    use serial_test::serial;
    use stellar_agent_test_support::keyring_mock;

    use super::*;

    fn test_profile(suffix: &str) -> Profile {
        Profile::builder_testnet(
            "stellar-agent-signer",
            suffix,
            format!("stellar-agent-nonce-{suffix}"),
            suffix,
        )
        .build()
    }

    #[test]
    #[serial]
    fn rotate_creates_new_key() {
        keyring_mock::install().expect("mock store");
        let profile = test_profile("rotate-creates");

        rotate_nonce_key(&profile).expect("rotation ok");

        // Verify the key was stored and is valid base64 decoding to ≥ 32 bytes.
        let entry_ref = &profile.mcp_nonce_key_alias;
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        let stored = entry.get_password().expect("key stored");
        let decoded = URL_SAFE_NO_PAD.decode(stored.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 32, "key must be exactly 32 bytes");
    }

    #[test]
    #[serial]
    fn rotate_overwrites_existing_key() {
        keyring_mock::install().expect("mock store");
        let profile = test_profile("rotate-overwrite");

        rotate_nonce_key(&profile).expect("first rotation");
        let entry_ref = &profile.mcp_nonce_key_alias;
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        let first = entry.get_password().expect("first key stored");

        rotate_nonce_key(&profile).expect("second rotation");
        let second = entry.get_password().expect("second key stored");

        // With overwhelming probability the two 32-byte random keys differ.
        // There is a 1 in 2^256 chance they match.
        assert_ne!(first, second, "rotation must generate a fresh key");
    }

    /// The classified keyring failure must pass through unchanged: a
    /// non-interactive Windows session (`ERROR_NO_SUCH_LOGON_SESSION` on the
    /// `set_password` write) surfaces as
    /// `auth.keyring_interactive_session_required`, not as a generic
    /// `auth.keyring_not_found` claiming the entry is missing.
    #[test]
    #[serial]
    fn rotate_surfaces_interactive_session_required_on_windows_write_failure() {
        keyring_mock::install().expect("mock store");
        let profile = test_profile("rotate-no-logon");
        let entry_ref = &profile.mcp_nonce_key_alias;
        keyring_mock::inject_no_logon_session(&entry_ref.service, &entry_ref.account)
            .expect("inject");

        let err = rotate_nonce_key(&profile).expect_err("rotation must fail");
        assert_eq!(err.code(), "auth.keyring_interactive_session_required");
        assert!(
            err.message().contains("STELLAR_AGENT_KEYRING_BACKEND"),
            "the message must name the headless escape hatch: {}",
            err.message()
        );
    }

    #[test]
    #[serial]
    fn rotated_key_is_base64_encoded() {
        keyring_mock::install().expect("mock store");
        let profile = test_profile("rotate-b64");

        rotate_nonce_key(&profile).expect("rotation ok");

        let entry_ref = &profile.mcp_nonce_key_alias;
        let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).unwrap();
        let stored = entry.get_password().unwrap();

        // Must decode without error.
        let bytes = URL_SAFE_NO_PAD
            .decode(stored.as_bytes())
            .expect("valid URL-safe base64");
        assert_eq!(bytes.len(), 32);
    }
}
