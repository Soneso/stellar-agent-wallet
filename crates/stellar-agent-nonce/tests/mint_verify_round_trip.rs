//! Round-trip test: mint a nonce then verify it on the same NonceMint.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceMint, ReplayWindow};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
    verify_request,
};

#[test]
#[serial]
fn mint_verify_round_trip_happy_path() {
    init_mock();
    let key = [0xABu8; 32];
    let profile = make_profile("round-trip");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"some_xdr_bytes";

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
    mint.verify(verify_request(
        &mut window,
        &nonce,
        envelope,
        expiry,
        "stellar_balances",
        "stellar:testnet",
        now,
    ))
    .expect("verify ok");
}

#[test]
#[serial]
fn nonce_base64_encoding_survives_round_trip() {
    init_mock();
    let key = [0x55u8; 32];
    let profile = make_profile("b64-round-trip");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"xdr_payload";

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

    // Transmit as base64 string and reconstruct.
    let b64 = nonce.to_base64();
    let reconstructed =
        stellar_agent_nonce::mint::Nonce::from_base64(&b64).expect("from_base64 ok");

    let mut window = ReplayWindow::new();
    mint.verify(verify_request(
        &mut window,
        &reconstructed,
        envelope,
        expiry,
        "stellar_pay",
        "stellar:testnet",
        now,
    ))
    .expect("verify after base64 round trip ok");
}
