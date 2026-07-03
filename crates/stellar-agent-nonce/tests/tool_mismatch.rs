//! Verify that presenting a different tool_name at verify time returns HmacMismatch.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint, ReplayWindow};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
    verify_request,
};

#[test]
#[serial]
fn tool_mismatch_returns_hmac_mismatch() {
    init_mock();
    let key = [0x22u8; 32];
    let profile = make_profile("tool-mismatch");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay", "stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"some_xdr";

    // Mint for stellar_pay.
    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    let mut window = ReplayWindow::new();
    // Verify for stellar_balances — different tool → HmacMismatch.
    let err = mint
        .verify(verify_request(
            &mut window,
            &nonce,
            envelope,
            expiry,
            "stellar_balances", // different tool
            "stellar:testnet",
            now,
        ))
        .expect_err("tool mismatch must fail");

    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch, got: {err:?}"
    );
}
