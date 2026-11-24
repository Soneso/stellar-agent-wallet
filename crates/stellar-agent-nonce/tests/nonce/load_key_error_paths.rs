//! Tests for error paths in `NonceMint::load_key` and `rotate_nonce_key`.
//!
//! Covered paths:
//!
//! - `load_key` → `get_password` failure: keyring entry missing (no key seeded)
//!   returns `NonceError::KeyringError`.
//! - `load_key` → `get_password` failure: mock `set_error` sentinel fires
//!   and the error propagates as `NonceError::KeyringError` with the failure
//!   classified (a backend `NoStorageAccess` is `KeyringPlatformError`, not
//!   "not found").
//! - `load_key` → base64 decode failure: keyring entry contains invalid base64,
//!   propagated as `NonceError::SerialiseFailed`.
//! - `rotate_nonce_key` → `set_password` failure: mock `set_error` sentinel on
//!   the nonce entry causes `rotate_keyring_secret_32` to fail;
//!   `rotate_nonce_key` surfaces the classified error unchanged.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use keyring_core::mock;
use serial_test::serial;
use stellar_agent_core::error::{AuthError, WalletError};
use stellar_agent_nonce::{NonceError, NonceMint, rotate_nonce_key};
use stellar_agent_test_support::rejected_value::assert_no_marker;

use crate::helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
};

// ─── load_key: missing entry ──────────────────────────────────────────────────

/// `load_key` returns `NonceError::KeyringError` when no key has been seeded
/// for the profile (entry does not exist in the mock store → `Error::NoEntry`
/// from `get_password`).
///
/// This is the "first time `mint` is called before `rotate_nonce_key`" path.
#[test]
#[serial]
fn load_key_returns_keyring_error_when_entry_missing() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    init_mock();

    // Intentionally do NOT seed any key.
    let profile = make_profile("load-key-missing");
    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);

    let err = mint
        .mint(
            &cat,
            b"xdr",
            now_before_expiry(),
            far_future_expiry(),
            "stellar_pay",
            "stellar:testnet",
        )
        .expect_err("missing keyring entry must return KeyringError");

    assert!(
        matches!(err, NonceError::KeyringError(_)),
        "expected KeyringError, got: {err:?}"
    );
}

// ─── load_key: get_password sentinel ─────────────────────────────────────────

/// `load_key` returns `NonceError::KeyringError` when the mock keyring's
/// `get_password` call returns `Error::NoStorageAccess` (keyring locked).
///
/// Mechanism: the entry exists in the mock store (key was seeded), then
/// `set_error(Error::NoStorageAccess)` is armed before `mint` is called.
/// The next `get_password` call fires the sentinel and returns an error.
#[test]
#[serial]
fn load_key_returns_keyring_error_on_get_password_no_storage_access() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use keyring_core::Entry as KeyringEntry;

    init_mock();

    let profile = make_profile("load-key-no-storage");
    let key = [0xB1u8; 32];
    let entry_ref = &profile.mcp_nonce_key_alias;
    let encoded = URL_SAFE_NO_PAD.encode(key);
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).expect("entry creation");
    entry.set_password(&encoded).expect("seed key");

    // Arm the sentinel: the next get_password on this entry returns the error.
    let cred: &mock::Cred = entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("credential must downcast to mock::Cred when mock store is active");
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(
        std::io::Error::other("keyring locked in test"),
    )));

    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);

    let err = mint
        .mint(
            &cat,
            b"xdr",
            now_before_expiry(),
            far_future_expiry(),
            "stellar_pay",
            "stellar:testnet",
        )
        .expect_err("NoStorageAccess sentinel must return KeyringError");

    assert!(
        matches!(
            err,
            NonceError::KeyringError(AuthError::KeyringPlatformError { .. })
        ),
        "a backend NoStorageAccess must classify as KeyringPlatformError, \
         not collapse into not-found; got: {err:?}"
    );
}

// ─── load_key: invalid base64 in keyring ─────────────────────────────────────

/// `load_key` returns `NonceError::SerialiseFailed` when the keyring entry
/// contains a value that is not valid URL-safe base64.
///
/// This can occur if the keyring entry was corrupted or written by a
/// non-conforming tool.  The production `load_key` path catches the
/// base64-decode error and maps it to `SerialiseFailed`.
#[test]
#[serial]
fn load_key_returns_serialise_failed_on_invalid_base64() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use keyring_core::Entry as KeyringEntry;

    init_mock();

    let profile = make_profile("load-key-bad-b64");
    let entry_ref = &profile.mcp_nonce_key_alias;
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).expect("entry creation");

    // Store a string that is not valid base64 (contains chars outside the alphabet).
    entry
        .set_password("!!!not-valid-base64!!!")
        .expect("seed bad value");

    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);

    let err = mint
        .mint(
            &cat,
            b"xdr",
            now_before_expiry(),
            far_future_expiry(),
            "stellar_pay",
            "stellar:testnet",
        )
        .expect_err("invalid base64 in keyring must return SerialiseFailed");

    assert!(
        matches!(err, NonceError::SerialiseFailed { .. }),
        "expected SerialiseFailed, got: {err:?}"
    );
}

// ─── rotate_nonce_key: set_password failure ───────────────────────────────────

/// `rotate_nonce_key` surfaces the CLASSIFIED keyring failure when the
/// underlying `rotate_keyring_secret_32` → `set_password` call fails: a
/// backend `NoStorageAccess` is `KeyringPlatformError`, not a "not found"
/// claim about an entry that was never missing.
///
/// Mechanism: the mock entry is seeded so it exists, then
/// `set_error(Error::NoStorageAccess)` is armed so the next write (the
/// `set_password` call inside `rotate_keyring_secret_32`) fires the sentinel.
/// `rotate_keyring_secret_32` maps the error through `map_keyring_operation_error`;
/// `rotate_nonce_key` passes the classified error through unchanged.
#[test]
#[serial]
fn rotate_nonce_key_returns_wallet_error_on_set_password_failure() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use keyring_core::Entry as KeyringEntry;

    init_mock();

    let profile = make_profile("rotate-set-pw-fail");
    let entry_ref = &profile.mcp_nonce_key_alias;

    // Create the entry in the mock store so the sentinel can be armed.
    // `rotate_keyring_secret_32` calls `open_entry` (which calls `Entry::new`)
    // then `set_password`.  The sentinel fires on `set_password`.
    let entry = KeyringEntry::new(&entry_ref.service, &entry_ref.account).expect("entry creation");

    // Seed an initial value so the entry object exists and can be armed.
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    entry
        .set_password(&URL_SAFE_NO_PAD.encode([0u8; 32]))
        .expect("seed initial key");

    // Arm the sentinel: the next call on this entry (set_password by rotate)
    // returns the error.
    let cred: &mock::Cred = entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("credential must downcast to mock::Cred when mock store is active");
    cred.set_error(keyring_core::Error::NoStorageAccess(Box::new(
        std::io::Error::other("keyring locked during rotation test"),
    )));

    let result = rotate_nonce_key(&profile);

    assert!(
        result.is_err(),
        "rotate_nonce_key must return Err when set_password fails"
    );

    let err = result.expect_err("already asserted is_err");
    assert!(
        matches!(
            err,
            WalletError::Auth(AuthError::KeyringPlatformError { .. })
        ),
        "a backend NoStorageAccess on the write must classify as \
         KeyringPlatformError, not collapse into not-found; got: {err:?}"
    );
}

// ─── load_key: rejected coordinates ──────────────────────────────────────────

/// A keyring read refusal names neither coordinate field, in the error, its
/// `Debug` form or the log, for a missing entry and for an absent store.
#[test]
#[serial]
fn keyring_refusals_hold_no_coordinate() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    const MISSING: &str = "keyring error: the configured keyring entry must exist; provision or \
                           select the required entry.";
    const NO_STORE: &str = "keyring error: a platform keychain must be available for this \
                            session; start and unlock macOS Keychain, GNOME Keyring, KWallet, or \
                            Windows Credential Manager.";
    init_mock();
    let profile = make_profile("credmarker7");
    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let mint_once = || {
        mint.mint(
            &cat,
            b"xdr",
            now_before_expiry(),
            far_future_expiry(),
            "stellar_pay",
            "stellar:testnet",
        )
        .expect_err("the read refuses")
    };

    let mut missing = None;
    let logs = stellar_agent_test_support::with_captured_logs(|| missing = Some(mint_once()));
    let missing = missing.expect("the mint ran");
    assert_eq!(missing.to_string(), MISSING);
    assert_no_marker(&missing, "credmarker7");
    assert!(!logs.contains("credmarker7"), "{logs}");

    seed_key(&profile, &[0xA7; 32]);
    let coordinate = &profile.mcp_nonce_key_alias;
    let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap();
    entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("mock credential")
        .set_error(keyring_core::Error::NoDefaultStore);
    let mut absent = None;
    let logs = stellar_agent_test_support::with_captured_logs(|| absent = Some(mint_once()));
    let absent = absent.expect("the mint ran");
    assert_eq!(absent.to_string(), NO_STORE);
    assert_no_marker(&absent, "credmarker7");
    assert!(!logs.contains("credmarker7"), "{logs}");
}
