//! Verifies that `signer_from_ledger` resolves through the hardware layer.
//!
//! # Design
//!
//! The mock keyring store holds an entry at the canonical signer service name.
//! `keyring_core::mock::Cred::set_error` arms its next `get_password` call with
//! an `Error::Invalid` sentinel. The classifier maps that sentinel to
//! `auth.keyring_platform_error`.
//!
//! `signer_from_ledger` returns a `WalletState` error when CI has no device.
//! A live device can return a signer or an identity mismatch. The test rejects
//! missing-entry errors and the sentinel's platform-error code.
//!
//! # Mechanism
//!
//! - `entry.as_any()` is the `keyring_core::CredentialApi::as_any` hook that
//!   allows downcasting the opaque `Credential` trait object to the concrete
//!   `mock::Cred` type.
//! - `mock::Cred::set_error(Error::Invalid(...))` programs the sentinel so
//!   the next `get_password` call on this entry returns the error.
//!
//! # Test serialisation
//!
//! This test shares the process-global default keyring store with the keyring
//! integration tests.  `#[serial]` serialises execution to prevent races.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in integration tests"
)]

use keyring_core::mock;
use serial_test::serial;
use stellar_agent_network::signing::source::signer_from_ledger;
use stellar_agent_test_support::keyring_mock;
use stellar_strkey::ed25519::PrivateKey;

/// The Ledger path resolves a signer through the hardware layer.
///
/// A mock `get_password` call returns the armed `Error::Invalid` sentinel,
/// which `map_keyring_operation_error` classifies as `auth.keyring_platform_error`.
/// The test rejects this code and `auth.keyring_not_found`.
///
/// CI without a device reports `WalletState`. A live device can return a
/// signer or `SignerKeyMismatch`.
#[tokio::test]
#[serial]
async fn ledger_path_does_not_invoke_keyring_get_password() {
    // 1. Install the mock store to observe keyring access.
    keyring_mock::install().expect("mock store init");

    // 2. Create an entry at the canonical signer service name and arm it with
    //    an error sentinel via mock::Cred::set_error.  Any call to get_password
    //    on this entry returns the sentinel, which map_keyring_operation_error maps to
    //    auth.keyring_platform_error.
    let dummy_entry =
        keyring_core::Entry::new("stellar-agent-signer", "ledger-path-test").expect("mock entry");

    // Disposable test seed; not a real key.
    let disposable = PrivateKey([0x01_u8; 32])
        .as_unredacted()
        .to_string()
        .to_string();

    // Set a password first so the entry exists in the store.
    dummy_entry
        .set_password(disposable.as_str())
        .expect("set dummy entry");

    // Arm the sentinel: downcast the Entry's inner credential to mock::Cred via
    // Entry::as_any(), then call set_error so the next get_password call on
    // this entry returns the sentinel error.
    // mock::Cred is the concrete type when the mock store is active.
    let mock_cred = dummy_entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("credential must downcast to mock::Cred when mock store is active");
    mock_cred.set_error(keyring_core::Error::Invalid(
        "sentinel: ledger-path keyring-not-invoked probe".to_owned(),
        "get_password must not be called on the hardware path".to_owned(),
    ));

    // 3. Call the hardware path.
    //    CI without hardware returns a WalletState error.
    let result = signer_from_ledger(
        0,
        "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
    )
    .await;

    // 4. Accept hardware errors and live-device identity mismatches.
    let err = match result {
        Err(e) => e,
        Ok(_) => {
            // A live Ledger derives the expected G-strkey.
            return;
        }
    };
    let code = err.code();

    // Missing-entry and sentinel codes identify keyring access.
    assert_ne!(
        code, "auth.keyring_not_found",
        "hardware signing must not read a missing keyring entry"
    );
    assert_ne!(
        code, "auth.keyring_platform_error",
        "hardware path must not produce a keyring_platform_error; got code={code}; \
         this means signer_from_ledger unexpectedly called get_password on the mock store"
    );
}
