//! Verify TTL range enforcement at mint time.
//!
//! `NonceMint::mint` validates that the TTL (`expiry - now`) is within
//! `[MIN_TTL_MS, max_ttl_ms]`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod helpers;

use serial_test::serial;
use stellar_agent_nonce::{NonceError, NonceMint};

use helpers::{StaticCatalogue, init_mock, make_profile, seed_key};

const MIN_TTL_MS: u64 = NonceMint::MIN_TTL_MS;
const MAX_TTL_MS: u64 = NonceMint::MAX_TTL_MS;

/// `mint` returns `TtlExceeded` when the requested TTL exceeds the profile max.
#[test]
#[serial]
fn mint_rejects_ttl_exceeded() {
    init_mock();
    let key = [0xA1u8; 32];
    let profile = make_profile("ttl-exceeded");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let now = 1_000_000u64;
    // Request TTL slightly above MAX_TTL_MS (5 minutes + 1 ms).
    let expiry = now + MAX_TTL_MS + 1;

    let err = mint
        .mint(&cat, b"xdr", now, expiry, "stellar_pay", "stellar:testnet")
        .expect_err("TTL exceeding max must be rejected");

    assert!(
        matches!(
            err,
            NonceError::TtlExceeded {
                max_ms: MAX_TTL_MS,
                requested_ms: _
            }
        ),
        "expected TtlExceeded, got: {err:?}"
    );
}

/// `mint` returns `TtlTooShort` when the requested TTL is below MIN_TTL_MS.
#[test]
#[serial]
fn mint_rejects_ttl_too_short() {
    init_mock();
    let key = [0xA2u8; 32];
    let profile = make_profile("ttl-too-short");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let now = 1_000_000u64;
    // Request TTL 1 ms below the minimum floor (30 seconds - 1 ms).
    let expiry = now + MIN_TTL_MS - 1;

    let err = mint
        .mint(&cat, b"xdr", now, expiry, "stellar_pay", "stellar:testnet")
        .expect_err("TTL below minimum must be rejected");

    assert!(
        matches!(
            err,
            NonceError::TtlTooShort {
                min_ms: MIN_TTL_MS,
                requested_ms: _
            }
        ),
        "expected TtlTooShort, got: {err:?}"
    );
}

/// `mint` accepts a TTL exactly at the minimum floor.
#[test]
#[serial]
fn mint_accepts_min_ttl() {
    init_mock();
    let key = [0xA3u8; 32];
    let profile = make_profile("ttl-min");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let now = 1_000_000u64;
    let expiry = now + MIN_TTL_MS;

    mint.mint(&cat, b"xdr", now, expiry, "stellar_pay", "stellar:testnet")
        .expect("TTL exactly at min must be accepted");
}

/// `mint` accepts a TTL exactly at the maximum.
#[test]
#[serial]
fn mint_accepts_max_ttl() {
    init_mock();
    let key = [0xA4u8; 32];
    let profile = make_profile("ttl-max");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let now = 1_000_000u64;
    let expiry = now + MAX_TTL_MS;

    mint.mint(&cat, b"xdr", now, expiry, "stellar_pay", "stellar:testnet")
        .expect("TTL exactly at max must be accepted");
}

/// `mint` returns `Expired` when `expiry <= now` (underflow case).
#[test]
#[serial]
fn mint_rejects_already_expired() {
    init_mock();
    let key = [0xA5u8; 32];
    let profile = make_profile("ttl-already-expired");
    seed_key(&profile, &key);

    let mint = NonceMint::from_profile(&profile).expect("from_profile");
    let cat = StaticCatalogue(&["stellar_pay"]);
    let now = 1_000_000u64;
    let expiry = now - 1; // already expired

    let err = mint
        .mint(&cat, b"xdr", now, expiry, "stellar_pay", "stellar:testnet")
        .expect_err("already-expired must be rejected");

    assert!(
        matches!(err, NonceError::Expired),
        "expected Expired for already-expired, got: {err:?}"
    );
}
