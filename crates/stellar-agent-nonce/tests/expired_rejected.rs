//! Verify that a nonce with a past expiry returns Expired.

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
fn expired_rejected() {
    init_mock();
    let key = [0xDDu8; 32];
    let profile = make_profile("expired-rejected");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"envelope";

    let nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_balances",
            "stellar:testnet",
        )
        .expect("mint ok");

    let mut window = ReplayWindow::new();

    // now_unix_ms > expiry → Expired.
    let now_past_expiry = expiry + 1;
    let err = mint
        .verify(verify_request(
            &mut window,
            &nonce,
            envelope,
            expiry,
            "stellar_balances",
            "stellar:testnet",
            now_past_expiry,
        ))
        .expect_err("expired nonce must be rejected");

    assert!(
        matches!(err, NonceError::Expired),
        "expected Expired, got: {err:?}"
    );
}
