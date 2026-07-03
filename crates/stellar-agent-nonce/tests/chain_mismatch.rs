//! Verify chain_id enforcement at both mint and verify time.
//!
//! Both `mint` and `verify` enforce the chain_id binding:
//! - `mint` returns `ChainMismatch` when the caller-supplied chain_id
//!   differs from the profile's chain.
//! - `verify` returns `ChainMismatch` when the chain_id passed to verify
//!   differs from the profile's chain.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint, ReplayWindow};

use helpers::{
    StaticCatalogue, far_future_expiry, init_mock, make_profile, now_before_expiry, seed_key,
    verify_request,
};

/// `mint` returns `ChainMismatch` when the caller passes a chain_id that
/// differs from the profile's configured CAIP-2 chain.
///
/// The profile is built via `Profile::builder_testnet` which sets
/// `chain_id = "stellar:testnet"`.  Passing `"stellar:mainnet"` triggers
/// `ChainMismatch` before key state is engaged.
#[test]
#[serial]
fn mint_rejects_wrong_chain_id() {
    init_mock();
    let key = [0x33u8; 32];
    let profile = make_profile("chain-mismatch-mint");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"xdr_bytes";

    let err = mint
        .mint(
            &cat,
            envelope,
            now,
            expiry,
            "stellar_pay",
            "stellar:mainnet", // profile is testnet → mismatch
        )
        .expect_err("wrong chain_id must be rejected at mint");

    assert!(
        matches!(err, NonceError::ChainMismatch { .. }),
        "expected ChainMismatch, got: {err:?}"
    );
}

/// `verify` returns `ChainMismatch` when the caller passes a chain_id that
/// differs from the profile's configured CAIP-2 chain.
#[test]
#[serial]
fn verify_rejects_wrong_chain_id() {
    init_mock();
    let key = [0x33u8; 32];
    let profile = make_profile("chain-mismatch-verify");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let expiry = far_future_expiry();
    let now = now_before_expiry();
    let envelope = b"xdr_bytes";

    // Mint correctly for testnet.
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
    // Verify with wrong chain → ChainMismatch (checked before HMAC).
    let err = mint
        .verify(verify_request(
            &mut window,
            &nonce,
            envelope,
            expiry,
            "stellar_pay",
            "stellar:mainnet", // different chain
            now,
        ))
        .expect_err("chain mismatch must fail at verify");

    assert!(
        matches!(err, NonceError::ChainMismatch { .. }),
        "expected ChainMismatch, got: {err:?}"
    );
}
