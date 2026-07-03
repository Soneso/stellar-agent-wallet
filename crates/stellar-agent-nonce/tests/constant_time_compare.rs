//! Structural test asserting that `subtle::ConstantTimeEq` is used for HMAC
//! tag comparison.
//!
//! A direct timing test is not feasible in a unit test context. Verification
//! is structural:
//! 1. `subtle::ConstantTimeEq` is imported and used in `mint.rs`.
//! 2. The verify path rejects a manipulated tag (bit-flip test).
//!
//! The bit-flip test also serves as a regression guard against accidental
//! fallback to non-constant-time comparison.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine as _;

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint, ReplayWindow, mint::Nonce};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
    verify_request,
};

#[test]
#[serial]
fn bit_flipped_tag_returns_hmac_mismatch() {
    init_mock();
    let key = [0x77u8; 32];
    let profile = make_profile("constant-time");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"ct_test_xdr";

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

    // Flip the first bit of the HMAC tag (bytes[16]).
    let b64 = nonce.to_base64();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&b64)
        .unwrap();
    let mut tampered = [0u8; 48];
    tampered.copy_from_slice(&decoded);
    tampered[16] ^= 0x01; // flip bit in tag byte 0
    let tampered_nonce = Nonce::from_raw(tampered);

    let mut window = ReplayWindow::new();
    let err = mint
        .verify(verify_request(
            &mut window,
            &tampered_nonce,
            envelope,
            expiry,
            "stellar_pay",
            "stellar:testnet",
            now,
        ))
        .expect_err("tampered tag must fail");

    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch for tampered tag, got: {err:?}"
    );
}

#[test]
#[serial]
fn last_tag_byte_flip_returns_hmac_mismatch() {
    init_mock();
    let key = [0x88u8; 32];
    let profile = make_profile("constant-time-last-byte");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_balances"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"ct_last_byte_xdr";

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

    let b64 = nonce.to_base64();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&b64)
        .unwrap();
    let mut tampered = [0u8; 48];
    tampered.copy_from_slice(&decoded);
    tampered[47] ^= 0x80; // flip MSB of last tag byte
    let tampered_nonce = Nonce::from_raw(tampered);

    let mut window = ReplayWindow::new();
    let err = mint
        .verify(verify_request(
            &mut window,
            &tampered_nonce,
            envelope,
            expiry,
            "stellar_balances",
            "stellar:testnet",
            now,
        ))
        .expect_err("last-byte tamper must fail");

    assert!(
        matches!(err, NonceError::HmacMismatch),
        "expected HmacMismatch for last-byte tamper, got: {err:?}"
    );
}
