//! Verifies that `signer_from_ledger` does NOT invoke the keyring on the
//! hardware-signer path.
//!
//! # Design
//!
//! The mock keyring store is installed and an entry at the canonical signer
//! service name is armed via `keyring_core::mock::Cred::set_error`.  If any
//! code calls `get_password` on that entry, it receives a
//! `keyring_core::Error::Invalid` sentinel, which propagates through
//! `map_keyring_error` as `auth.keyring_not_found`.
//!
//! `signer_from_ledger` is then called.  In CI (no device attached) it returns
//! a `WalletState` error from the hardware layer.  The test asserts the error
//! code is NOT `auth.keyring_not_found` — that code would indicate an
//! accidental keyring lookup on the hardware path.
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

/// Asserts that `signer_from_ledger` does NOT call `get_password` on the keyring.
///
/// The mock store entry is armed with a `set_error` sentinel (`Error::Invalid`)
/// so any `get_password` call returns a recognisable error.  After calling
/// `signer_from_ledger`, the assertion verifies the error code is NOT
/// `auth.keyring_not_found` — which would be the sentinel's signature
/// propagated through `map_keyring_error`.
///
/// In CI (no device): expected `WalletState` (device not found / timeout).
/// With a live device that derives the expected G-strkey: returns `Ok` and the
/// test passes (the important assertion — no keyring call — is still satisfied).
#[tokio::test]
#[serial]
async fn ledger_path_does_not_invoke_keyring_get_password() {
    // 1. Install the mock store so any accidental keyring lookup is observable.
    keyring_mock::install().expect("mock store init");

    // 2. Create an entry at the canonical signer service name and arm it with
    //    an error sentinel via mock::Cred::set_error.  Any call to get_password
    //    on this entry returns the sentinel, which map_keyring_error maps to
    //    auth.keyring_not_found.
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
    // If the hardware path touches get_password, the test sees
    // auth.keyring_not_found (from the sentinel) and the assertion below fails.
    let mock_cred = dummy_entry
        .as_any()
        .downcast_ref::<mock::Cred>()
        .expect("credential must downcast to mock::Cred when mock store is active");
    mock_cred.set_error(keyring_core::Error::Invalid(
        "sentinel — ledger-path keyring-not-invoked probe".to_owned(),
        "get_password must not be called on the hardware path".to_owned(),
    ));

    // 3. Call the hardware path.
    //    This will return a WalletState error in CI (no hardware attached).
    //    It must NOT return an Auth error from a keyring lookup.
    let result = signer_from_ledger(
        0,
        "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
    )
    .await;

    // 4. Assert the error is NOT from keyring access.
    //    In CI: expected WalletState (device not found).
    //    With a live device: expected either success or SignerKeyMismatch (Auth).
    //    Either way, the error must NOT be KeyringNotFound (the sentinel).
    let err = match result {
        Err(e) => e,
        Ok(_) => {
            // Unlikely in CI but possible with a live Ledger whose BIP-32 path
            // happens to derive the dummy G-strkey above.  The important assertion
            // (no keyring invocation) is still satisfied if we get here.
            return;
        }
    };
    let code = err.code();

    // The error must come from the hardware layer, NOT from the keyring.
    // Allowed: WalletState (device not found), Auth::SignerKeyMismatch (live device).
    // Forbidden: Auth::KeyringNotFound — that would mean the hardware path
    //            accidentally triggered the mock sentinel via get_password.
    assert_ne!(
        code, "auth.keyring_not_found",
        "hardware path MUST NOT produce a keyring_not_found error — got code={code}; \
         this means signer_from_ledger unexpectedly called get_password on the mock store"
    );
}
