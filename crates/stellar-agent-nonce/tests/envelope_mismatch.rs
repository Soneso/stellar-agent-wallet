//! Verify that presenting a different envelope_xdr at verify time returns HmacMismatch.

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
fn envelope_mismatch_returns_hmac_mismatch() {
    init_mock();
    let key = [0x11u8; 32];
    let profile = make_profile("envelope-mismatch");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope_mint = b"original_envelope";
    let envelope_verify = b"tampered_envelope";

    let nonce = mint
        .mint(
            &cat,
            envelope_mint,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    let mut window = ReplayWindow::new();
    let err = mint
        .verify(verify_request(
            &mut window,
            &nonce,
            envelope_verify, // different envelope
            expiry,
            "stellar_pay",
            "stellar:testnet",
            now,
        ))
        .expect_err("envelope mismatch must fail");

    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch, got: {err:?}"
    );
}
