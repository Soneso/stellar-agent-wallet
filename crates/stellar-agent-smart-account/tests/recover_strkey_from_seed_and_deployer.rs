//! In-process verification — recovering the same C-strkey from the same
//! `(deployer, salt, passphrase)` triple.
//!
//! This is the pure-host equivalent of the testnet recovery test at
//! `tests/deploy_c_testnet_acceptance.rs`. No network access.
//!
//! Steps:
//!
//! 1. Use a pinned salt (deterministic CI — no OsRng dependency needed here).
//! 2. Invoke `derive_smart_account_address(deployer, salt, passphrase)` → c1.
//! 3. Invoke again with the same args → c2.
//! 4. Assert `c1 == c2`.
//! 5. Invoke with `interop_deployer_pubkey()` instead → c3.
//! 6. Assert `c3` is a valid C-strkey AND deterministic across invocations.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]

use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_smart_account::deployment::{
    derive_smart_account_address, interop_deployer_pubkey,
};

const TESTNET: &str = "Test SDF Network ; September 2015";
const MAINNET: &str = "Public Global Stellar Network ; September 2015";

/// A stable test deployer G-strkey (all-zeros ed25519 public key).
const TEST_DEPLOYER_1: &str = SIMULATE_SENTINEL_G;

/// Acceptance #3 core verification: the same `(deployer, salt, passphrase)` triple
/// always re-derives the same C-strkey.
#[test]
fn same_inputs_always_produce_same_c_strkey() {
    // Pinned salt — deterministic CI; no OsRng needed here.
    let salt = [0x11u8; 32];

    let c1 = derive_smart_account_address(TEST_DEPLOYER_1, &salt, TESTNET)
        .expect("derivation must succeed for valid inputs");
    let c2 = derive_smart_account_address(TEST_DEPLOYER_1, &salt, TESTNET)
        .expect("derivation must succeed for valid inputs (second invocation)");

    assert_eq!(
        c1, c2,
        "two invocations with identical (deployer, salt, passphrase) must produce the same C-strkey"
    );
    assert!(
        c1.starts_with('C'),
        "derived address must start with 'C': {c1}"
    );
    assert_eq!(c1.len(), 56, "C-strkey must be 56 characters: {c1}");
}

/// Asserts the well-known interop deployer path is deterministic across multiple invocations.
///
/// Acceptance criterion: a wallet that did not deploy the account can still locate
/// it by re-deriving the same C-strkey from the same `(interop_deployer, salt, passphrase)`.
#[test]
fn interop_deployer_produces_deterministic_c_strkeys() {
    let interop_dep = interop_deployer_pubkey();

    // Fixed salt for determinism (zero-salt is a valid input).
    let salt = [0u8; 32];

    let c1 = derive_smart_account_address(&interop_dep, &salt, TESTNET)
        .expect("interop deployer path must succeed");
    let c2 = derive_smart_account_address(&interop_dep, &salt, TESTNET)
        .expect("interop deployer path must succeed (second invocation)");
    let c3 = derive_smart_account_address(&interop_dep, &salt, TESTNET)
        .expect("interop deployer path must succeed (third invocation)");

    assert_eq!(c1, c2, "interop deployer derivation must be deterministic");
    assert_eq!(c2, c3, "interop deployer derivation must be deterministic");
    assert!(
        c1.starts_with('C'),
        "interop deployer derived address must start with 'C': {c1}"
    );
    assert_eq!(
        c1.len(),
        56,
        "interop deployer C-strkey must be 56 characters: {c1}"
    );

    // Can be decoded back to 32 bytes.
    let decoded = stellar_strkey::Contract::from_string(&c1)
        .expect("interop deployer C-strkey must decode without error");
    assert_eq!(decoded.0.len(), 32, "decoded contract ID must be 32 bytes");
}

/// Asserts that different salts produce different C-strkeys (address isolation).
#[test]
fn different_salts_produce_different_c_strkeys() {
    let deployer = interop_deployer_pubkey();

    // Pinned salts — deterministic CI; no OsRng needed here.
    let salt_a = [0x11u8; 32];
    let salt_b = [0x22u8; 32];

    let ca = derive_smart_account_address(&deployer, &salt_a, TESTNET).unwrap();
    let cb = derive_smart_account_address(&deployer, &salt_b, TESTNET).unwrap();

    assert_ne!(ca, cb, "different salts must produce different C-strkeys");
}

/// Asserts that the same `(deployer, salt)` on testnet vs mainnet produces different C-strkeys.
///
/// Network isolation is required so testnet-derived addresses cannot collide with
/// mainnet-deployed accounts.
#[test]
fn testnet_vs_mainnet_produce_different_c_strkeys() {
    let interop_dep = interop_deployer_pubkey();
    let salt = [0x42u8; 32];

    let c_testnet = derive_smart_account_address(&interop_dep, &salt, TESTNET)
        .expect("testnet derivation must succeed");
    let c_mainnet = derive_smart_account_address(&interop_dep, &salt, MAINNET)
        .expect("mainnet derivation must succeed");

    assert_ne!(
        c_testnet, c_mainnet,
        "same (deployer, salt) must produce different C-strkeys on testnet vs mainnet"
    );
}

/// Asserts that different deployers produce different C-strkeys.
///
/// The deployer's public key is part of the contract-id preimage; deployer isolation
/// ensures one operator's deployed accounts cannot collide with another's.
#[test]
fn different_deployers_produce_different_c_strkeys() {
    let interop_dep = interop_deployer_pubkey();
    let salt = [0x55u8; 32];

    let c_interop = derive_smart_account_address(&interop_dep, &salt, TESTNET)
        .expect("interop deployer path must succeed");
    let c_test1 = derive_smart_account_address(TEST_DEPLOYER_1, &salt, TESTNET)
        .expect("test deployer 1 path must succeed");

    assert_ne!(
        c_interop, c_test1,
        "different deployers must produce different C-strkeys for the same salt"
    );
}
