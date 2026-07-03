//! Test vector verification for the toolset-sig-v1 preimage layout.
//!
//! This test verifies that `build_preimage` produces the exact byte layout
//! documented in `tests/vectors/toolset-sig-v1.json`.
//!
//! The vector uses a FIXED EPHEMERAL test key.  No `S...` strkey is committed.
//! The test key is generated deterministically from a fixed seed for
//! reproducibility.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; panics acceptable in integration tests"
)]

use ed25519_dalek::{Signer, SigningKey};
use stellar_agent_toolsets_install::{DOMAIN_TAG, ToolsetInstallError};

/// Fixed test seed for the ephemeral test key.
///
/// This seed is TEST-ONLY and must never be used for real keys.
/// It is NOT a Stellar `S...` strkey.
const TEST_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

// Test vector fields from tests/vectors/toolset-sig-v1.json.
const TV_PACKAGE: &str = "test-toolset";
const TV_VERSION: &str = "1.0.0";
const TV_SHASUM: &str = "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469224bca68a674e5262";

/// Committed public key hex from the test vector (locks the key derivation).
///
/// ed25519 is deterministic given a fixed seed; if this constant changes,
/// the TEST_SEED or the strkey library changed.
const TV_PUBLIC_KEY_HEX: &str = "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

/// Committed signature hex from the test vector (locks preimage layout + determinism).
///
/// ed25519 signatures over the same message with the same key are deterministic
/// (RFC 8032 §5.1.6).  A change here means either the preimage layout or the
/// key derivation changed.
const TV_SIGNATURE_HEX: &str = "49386d482ca76418ed69242a761011fc2ea1b1b10071b8f19083ee7455ae27eb\
     4b18458a0ce2b5baa89f312b89012e9008b0381af32ecf543c23eefdf348a107";

/// The expected preimage bytes (DOMAIN_TAG || len(pkg) || pkg || len(ver) || ver || len(sha) || sha).
///
/// This is the authoritative byte-layout source for the publisher preimage.
fn expected_preimage() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(DOMAIN_TAG); // 28 bytes: "stellar-agent-toolset-sig:v1"

    let pkg = TV_PACKAGE.as_bytes();
    let ver = TV_VERSION.as_bytes();
    let sha = TV_SHASUM.as_bytes();

    v.extend_from_slice(&(pkg.len() as u32).to_be_bytes());
    v.extend_from_slice(pkg);
    v.extend_from_slice(&(ver.len() as u32).to_be_bytes());
    v.extend_from_slice(ver);
    v.extend_from_slice(&(sha.len() as u32).to_be_bytes());
    v.extend_from_slice(sha);
    v
}

#[test]
fn domain_tag_is_exact_28_bytes() {
    assert_eq!(DOMAIN_TAG, b"stellar-agent-toolset-sig:v1");
    assert_eq!(DOMAIN_TAG.len(), 28);
}

#[test]
fn preimage_layout_matches_test_vector() {
    use stellar_agent_toolsets_install::signature::build_preimage;

    let computed = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    let expected = expected_preimage();

    assert_eq!(
        computed, expected,
        "preimage does not match the test vector layout"
    );
}

#[test]
fn sign_and_verify_against_test_vector() {
    use stellar_agent_toolsets_install::signature::{build_preimage, verify_signature};

    let sk = SigningKey::from_bytes(&TEST_SEED);
    let pk = sk.verifying_key().to_bytes();

    let preimage = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    let sig: [u8; 64] = sk.sign(&preimage).to_bytes();

    // Verification must succeed.
    verify_signature(TV_PACKAGE, TV_VERSION, TV_SHASUM, &sig, &pk)
        .expect("signature must verify against the test vector");
}

#[test]
fn test_vector_signature_is_stable() {
    // This test verifies that the same inputs always produce a verifiable
    // signature (deterministic keys, deterministic preimage).
    use stellar_agent_toolsets_install::signature::{build_preimage, verify_signature};

    let sk = SigningKey::from_bytes(&TEST_SEED);
    let pk = sk.verifying_key().to_bytes();

    let preimage = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    let sig1: [u8; 64] = sk.sign(&preimage).to_bytes();
    let sig2: [u8; 64] = sk.sign(&preimage).to_bytes();

    // ed25519 signatures are deterministic for the same key + message.
    assert_eq!(sig1, sig2, "ed25519 signatures must be deterministic");
    verify_signature(TV_PACKAGE, TV_VERSION, TV_SHASUM, &sig1, &pk).unwrap();
}

/// Verifies that the test-time computed public key and signature EQUAL the
/// committed constants in `tests/vectors/toolset-sig-v1.json`.
///
/// ed25519 is deterministic (RFC 8032 §5.1.6): the same seed always produces
/// the same key, and the same key + message always produces the same signature.
/// This test LOCKS the preimage layout and key derivation against future drift.
///
/// If this test fails after a refactor, it means either:
/// - the preimage byte layout changed (update the test vector JSON), or
/// - the seed derivation or ed25519-dalek API changed.
#[test]
fn committed_constants_match_computed_values() {
    use stellar_agent_toolsets_install::signature::build_preimage;

    let sk = SigningKey::from_bytes(&TEST_SEED);
    let pk = sk.verifying_key().to_bytes();
    let preimage = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    let sig: [u8; 64] = sk.sign(&preimage).to_bytes();

    let computed_pk_hex = hex::encode(pk);
    let computed_sig_hex = hex::encode(sig);

    // Remove any internal whitespace from the constant (the constant wraps
    // across two string literals for readability; Rust joins them at compile
    // time with no whitespace, but we normalise just in case).
    let expected_sig = TV_SIGNATURE_HEX.replace(char::is_whitespace, "");

    assert_eq!(
        computed_pk_hex, TV_PUBLIC_KEY_HEX,
        "public key hex diverged from committed test vector; \
         update TV_PUBLIC_KEY_HEX and tests/vectors/toolset-sig-v1.json"
    );
    assert_eq!(
        computed_sig_hex, expected_sig,
        "signature hex diverged from committed test vector; \
         update TV_SIGNATURE_HEX and tests/vectors/toolset-sig-v1.json (preimage layout changed?)"
    );
}

#[test]
fn mutated_package_name_fails_verification() {
    use stellar_agent_toolsets_install::signature::{build_preimage, verify_signature};

    let sk = SigningKey::from_bytes(&TEST_SEED);
    let pk = sk.verifying_key().to_bytes();

    let preimage = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    let sig: [u8; 64] = sk.sign(&preimage).to_bytes();

    // Different package name → different preimage → verification fails.
    let err = verify_signature("other-toolset", TV_VERSION, TV_SHASUM, &sig, &pk).unwrap_err();
    assert!(
        matches!(err, ToolsetInstallError::SignatureInvalid),
        "expected SignatureInvalid, got: {err:?}"
    );
}

#[test]
fn mutated_version_fails_verification() {
    use stellar_agent_toolsets_install::signature::{build_preimage, verify_signature};

    let sk = SigningKey::from_bytes(&TEST_SEED);
    let pk = sk.verifying_key().to_bytes();

    let preimage = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    let sig: [u8; 64] = sk.sign(&preimage).to_bytes();

    let err = verify_signature(TV_PACKAGE, "2.0.0", TV_SHASUM, &sig, &pk).unwrap_err();
    assert!(matches!(err, ToolsetInstallError::SignatureInvalid));
}

#[test]
fn injective_encoding_newline_collision_impossible() {
    // Verify the length-prefix scheme prevents the newline-delimiter collision
    // that a delimiter-based design would permit:
    // package="a\nb" with version="c" ≠ package="a" with version="b\nc"
    use stellar_agent_toolsets_install::signature::build_preimage;

    let shasum = "a".repeat(64);
    let p1 = build_preimage("a\nb", "c", &shasum);
    let p2 = build_preimage("a", "b\nc", &shasum);
    assert_ne!(
        p1, p2,
        "length-prefix encoding must prevent tuple-collision via embedded separators"
    );
}
