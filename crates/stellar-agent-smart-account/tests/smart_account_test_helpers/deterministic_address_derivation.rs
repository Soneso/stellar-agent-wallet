//! Integration tests for the deterministic smart-account address derivation algorithm.
//!
//! Loads `tests/fixtures/address_derivation_vectors.json` and asserts
//! byte-equality of `derive_smart_account_address` for each vector.
//!
//! The canonical algorithm computes `salt = SHA256(credentialId)` then uses
//! `derive_smart_account_address(deployer, salt, passphrase)`. The fixture
//! file carries the pre-computed salt (the Rust function's direct input) so
//! this test exercises the Rust implementation at the same layer the canonical
//! reference does.
//!
//! # Interop verification
//!
//! This is the interop-verification layer: byte-equality against canonical
//! reference vectors confirms the Rust derivation is byte-identical to the
//! reference.
//!
//! # Coverage
//!
//! Interop verification: byte-equality of the Rust derivation against canonical reference vectors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use stellar_agent_core::hex::decode_hex32 as core_decode_hex32;
use stellar_agent_smart_account::deployment::derive_smart_account_address;

/// Minimum vector count for interop verification (at least 3 vectors required).
const MIN_VECTOR_COUNT: usize = 3;

/// The fixture file, loaded relative to the workspace root at test time.
fn fixture_path() -> std::path::PathBuf {
    // `env!("CARGO_MANIFEST_DIR")` is the crate root at compile time.
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("tests")
        .join("fixtures")
        .join("address_derivation_vectors.json")
}

/// Decodes a 64-char hex string into exactly 32 bytes.
///
/// Delegates to `stellar_agent_core::hex::decode_hex32`.
fn decode_hex32(hex: &str) -> [u8; 32] {
    core_decode_hex32(hex).unwrap_or_else(|e| panic!("invalid salt_hex in fixture: {e}"))
}

/// Asserts byte-equality of `derive_smart_account_address` against all canonical reference vectors.
///
/// Vectors are loaded from `tests/fixtures/address_derivation_vectors.json`.
/// At least `MIN_VECTOR_COUNT` (3) vectors must be present.
///
/// Each vector:
/// - `deployer_pubkey` — G-strkey of the deployer.
/// - `salt_hex` — 64-char hex of the 32-byte salt (= SHA256(credentialId)).
/// - `network_passphrase` — Stellar network passphrase string.
/// - `expected_smart_account` — Expected C-strkey output.
///
/// Interop verification layer: byte-equality against canonical reference vectors.
#[test]
fn derive_smart_account_address_matches_kmp_vectors() {
    let path = fixture_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read fixture at {}: {e}", path.display()));
    let json: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse fixture JSON at {}: {e}", path.display()));

    let vectors = json["vectors"]
        .as_array()
        .unwrap_or_else(|| panic!("fixture missing 'vectors' array"));

    assert!(
        vectors.len() >= MIN_VECTOR_COUNT,
        "fixture must have at least {MIN_VECTOR_COUNT} vectors; found {}",
        vectors.len()
    );

    for (idx, vector) in vectors.iter().enumerate() {
        let deployer_pubkey = vector["deployer_pubkey"]
            .as_str()
            .unwrap_or_else(|| panic!("vector {idx} missing deployer_pubkey"));
        let salt_hex = vector["salt_hex"]
            .as_str()
            .unwrap_or_else(|| panic!("vector {idx} missing salt_hex"));
        let network_passphrase = vector["network_passphrase"]
            .as_str()
            .unwrap_or_else(|| panic!("vector {idx} missing network_passphrase"));
        let expected = vector["expected_smart_account"]
            .as_str()
            .unwrap_or_else(|| panic!("vector {idx} missing expected_smart_account"));
        let source = vector["source"].as_str().unwrap_or("(no source)");

        let salt = decode_hex32(salt_hex);

        let actual = derive_smart_account_address(deployer_pubkey, &salt, network_passphrase)
            .unwrap_or_else(|e| {
                panic!("vector {idx} ({source}): derive_smart_account_address failed: {e}")
            });

        assert_eq!(
            actual, expected,
            "vector {idx} ({source}): C-strkey mismatch.\n\
             deployer_pubkey: {deployer_pubkey}\n\
             salt_hex:        {salt_hex}\n\
             network:         {network_passphrase}\n\
             expected:        {expected}\n\
             actual:          {actual}"
        );
    }
}

/// Asserts the fixture covers both testnet and mainnet passphrases.
///
/// Cross-network isolation: the same (deployer, salt) pair MUST produce
/// different C-strkeys on testnet vs mainnet.
#[test]
fn fixture_covers_multiple_networks() {
    let path = fixture_path();
    let raw = std::fs::read_to_string(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let vectors = json["vectors"].as_array().unwrap();

    let testnet_passphrases = vectors
        .iter()
        .filter(|v| v["network_passphrase"].as_str() == Some("Test SDF Network ; September 2015"))
        .count();

    let mainnet_passphrases = vectors
        .iter()
        .filter(|v| {
            v["network_passphrase"].as_str()
                == Some("Public Global Stellar Network ; September 2015")
        })
        .count();

    assert!(
        testnet_passphrases >= 1,
        "fixture must include at least one testnet vector; found {testnet_passphrases}"
    );
    assert!(
        mainnet_passphrases >= 1,
        "fixture must include at least one mainnet vector; found {mainnet_passphrases}"
    );
}

/// Asserts the interop deployer vector is present and produces a valid C-strkey.
///
/// The well-known interop deployer `GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N`
/// must appear in the fixture so the interop-verification path is covered.
#[test]
fn fixture_covers_interop_deployer() {
    const INTEROP_DEPLOYER: &str = "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N";

    let path = fixture_path();
    let raw = std::fs::read_to_string(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let vectors = json["vectors"].as_array().unwrap();

    let interop_vector = vectors
        .iter()
        .find(|v| v["deployer_pubkey"].as_str() == Some(INTEROP_DEPLOYER))
        .unwrap_or_else(|| {
            panic!("fixture must include a vector for the interop deployer {INTEROP_DEPLOYER}")
        });

    let expected = interop_vector["expected_smart_account"].as_str().unwrap();
    let salt_hex = interop_vector["salt_hex"].as_str().unwrap();
    let passphrase = interop_vector["network_passphrase"].as_str().unwrap();
    let salt = decode_hex32(salt_hex);

    // Also verify that interop_deployer_pubkey() returns this G-strkey.
    let derived_deployer = stellar_agent_smart_account::deployment::interop_deployer_pubkey();
    assert_eq!(
        derived_deployer, INTEROP_DEPLOYER,
        "interop_deployer_pubkey() must equal the fixture deployer"
    );

    let actual = derive_smart_account_address(INTEROP_DEPLOYER, &salt, passphrase).unwrap();
    assert_eq!(
        actual, expected,
        "interop deployer vector must match expected C-strkey"
    );
}
