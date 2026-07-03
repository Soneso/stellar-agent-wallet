//! Verify that an unregistered tool name returns `InvalidTool` WITHOUT engaging
//! key state.
//!
//! Uses `RejectAllCatalogue` (returns `false` from `is_registered` for every
//! tool name) to drive the rejection path.  The structural proof that key
//! state is not engaged: seed NO key in the keyring for the profile.  If
//! `mint` engaged key state before tool validation, the call would fail with
//! `KeyringError`; the test asserts `InvalidTool` instead — so the order
//! (validation BEFORE key load) is verified end-to-end through the public API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint};

use helpers::{RejectAllCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry};

#[test]
#[serial]
fn unregistered_tool_rejected_before_key_state() {
    init_mock();

    // Intentionally do NOT seed a key — if key state were engaged, the call
    // would return KeyringError (entry not found), NOT InvalidTool.
    let profile = make_profile("unregistered-tool");

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = RejectAllCatalogue;

    let err = mint
        .mint(
            &cat,
            b"xdr",
            now_before_expiry(),
            far_future_expiry(),
            "unregistered_tool",
            "stellar:testnet",
        )
        .expect_err("unregistered tool must be rejected");

    // If this is InvalidTool, key state was never engaged (correct).
    // If this is KeyringError, key was loaded before validation (bug).
    assert!(
        matches!(err, NonceError::InvalidTool { ref tool } if tool == "unregistered_tool"),
        "expected InvalidTool, got: {err:?}"
    );
}
