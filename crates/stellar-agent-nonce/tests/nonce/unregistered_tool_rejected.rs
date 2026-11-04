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

use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint};
use stellar_agent_test_support::rejected_value::{assert_refusal_text, capture_refusal};

use crate::helpers::{
    RejectAllCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry,
};

#[test]
#[serial]
fn unregistered_tool_rejected_before_key_state() {
    init_mock();

    // Intentionally do NOT seed a key — if key state were engaged, the call
    // would return KeyringError (entry not found), NOT InvalidTool.
    let profile = make_profile("unregistered-tool");

    let mint = NonceMint::from_profile(&profile, "nonce-test").expect("from_profile");
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
        matches!(err, NonceError::InvalidTool),
        "expected InvalidTool, got: {err:?}"
    );
}

#[test]
#[serial]
fn rejected_input_nonce_tool() {
    capture_refusal(|| {
        let profile = make_profile("refusal-marker");
        let mint = NonceMint::from_profile(&profile, "nonce-test").expect("mint configuration");
        let error = mint
            .mint(
                &RejectAllCatalogue,
                b"xdr",
                now_before_expiry(),
                far_future_expiry(),
                "CREDMARKER7",
                "stellar:testnet",
            )
            .expect_err("unknown tool");
        assert_eq!(error.wire_code(), "tool.unknown");
        assert_refusal_text(&error, "tool_name must name a registered tool");
    });
}
