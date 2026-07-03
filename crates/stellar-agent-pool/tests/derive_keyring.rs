//! Tests for `derive::load_pool_master_seed_from_keyring`.
//!
//! Uses the in-memory mock keyring from `stellar_agent_test_support::keyring_mock`
//! so no OS keychain prompts are issued.
//!
//! # Process-global store
//!
//! `keyring_core::set_default_store` is process-global.  All four sub-cases
//! (happy path, missing entry, invalid base64, wrong length) are exercised inside
//! a SINGLE test function with `#[serial]` to prevent concurrent tests from racing
//! on the shared store.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serial_test::serial;

use stellar_agent_pool::PoolError;
use stellar_agent_pool::derive::load_pool_master_seed_from_keyring;
use stellar_agent_test_support::keyring_mock;

const SERVICE: &str = "pool-test-svc";
const ACCOUNT: &str = "pool-test-account";

/// Exercises all four branches of `load_pool_master_seed_from_keyring`
/// in sequence within a single serialised test.
///
/// 1. Happy path: correct 64-byte seed stored as URL-safe-no-pad base64.
/// 2. Missing entry: nothing stored → `PoolError::InitFailed`.
/// 3. Malformed base64: stored value is not valid base64 → `PoolError::InitFailed`.
/// 4. Wrong length: valid base64 but not 64 bytes → `PoolError::InitFailed`.
#[test]
#[serial]
fn load_pool_master_seed_all_branches() {
    // ── Case 1: happy path ────────────────────────────────────────────────────
    keyring_mock::install().expect("mock keyring install");

    let expected_seed: [u8; 64] = {
        let mut s = [0u8; 64];
        for (i, b) in s.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(7);
        }
        s
    };
    let encoded = URL_SAFE_NO_PAD.encode(expected_seed);

    let entry = keyring_core::Entry::new(SERVICE, ACCOUNT)
        .expect("keyring entry creation must succeed under mock store");
    entry
        .set_password(&encoded)
        .expect("set_password must succeed");

    let seed = load_pool_master_seed_from_keyring(SERVICE, ACCOUNT)
        .expect("load must succeed for correctly-stored seed");
    assert_eq!(
        seed.as_ref(),
        &expected_seed,
        "loaded seed must match the stored 64-byte value"
    );

    // ── Case 2: missing entry (fresh store, no password set) ─────────────────
    keyring_mock::install().expect("reinstall fresh store");
    // No password set → get_password will fail → InitFailed.
    let result = load_pool_master_seed_from_keyring(SERVICE, ACCOUNT);
    match result {
        Err(PoolError::InitFailed { detail }) => {
            assert!(
                detail.contains("keyring get_password failed"),
                "error detail must mention keyring failure; got: {detail}"
            );
        }
        other => panic!("expected InitFailed for missing entry, got: {other:?}"),
    }

    // ── Case 3: stored value is not valid base64 ──────────────────────────────
    keyring_mock::install().expect("reinstall fresh store");
    let entry =
        keyring_core::Entry::new(SERVICE, ACCOUNT).expect("keyring entry creation must succeed");
    entry
        .set_password("!!not-valid-base64!!")
        .expect("set_password must succeed");

    let result = load_pool_master_seed_from_keyring(SERVICE, ACCOUNT);
    match result {
        Err(PoolError::InitFailed { detail }) => {
            assert!(
                detail.contains("base64-decode failed"),
                "error detail must mention base64 failure; got: {detail}"
            );
        }
        other => panic!("expected InitFailed for invalid base64, got: {other:?}"),
    }

    // ── Case 4: valid base64 but wrong length (not 64 bytes) ─────────────────
    keyring_mock::install().expect("reinstall fresh store");
    let short_bytes = [0u8; 32];
    let short_encoded = URL_SAFE_NO_PAD.encode(short_bytes);
    let entry =
        keyring_core::Entry::new(SERVICE, ACCOUNT).expect("keyring entry creation must succeed");
    entry
        .set_password(&short_encoded)
        .expect("set_password must succeed");

    let result = load_pool_master_seed_from_keyring(SERVICE, ACCOUNT);
    match result {
        Err(PoolError::InitFailed { detail }) => {
            assert!(
                detail.contains("seed length mismatch"),
                "error detail must mention length mismatch; got: {detail}"
            );
        }
        other => panic!("expected InitFailed for wrong-length seed, got: {other:?}"),
    }
}
