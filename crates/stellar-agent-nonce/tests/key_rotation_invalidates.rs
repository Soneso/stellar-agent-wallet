//! Verify that rotating the nonce key invalidates outstanding nonces.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint, ReplayWindow, rotate_nonce_key};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
    verify_request,
};

#[test]
#[serial]
fn key_rotation_invalidates_old_nonce() {
    init_mock();
    let key = [0x55u8; 32];
    let profile = make_profile("key-rotation-invalidates");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"pre_rotation_xdr";

    // Mint nonce before rotation.
    let old_nonce = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:testnet",
        )
        .expect("mint ok");

    // Rotate the nonce key.
    rotate_nonce_key(&profile).expect("rotation ok");

    // The existing `mint` still has the process boot_nonce and the OLD key in
    // the keyring has been REPLACED.  A new verify attempt loads the new key →
    // HMAC mismatch.
    let mut window = ReplayWindow::new();
    let err = mint
        .verify(verify_request(
            &mut window,
            &old_nonce,
            envelope,
            expiry,
            "stellar_pay",
            "stellar:testnet",
            now,
        ))
        .expect_err("old nonce after rotation must fail");

    // After key rotation the old tag was computed with the old key; recomputed
    // with the new key → HmacMismatch.
    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch after rotation, got: {err:?}"
    );
}
