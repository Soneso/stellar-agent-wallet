//! Test vector verification and integration tests for the attestation gate.
//!
//! This file covers:
//!
//! - KAT: preimage layout locked against `tests/vectors/toolset-attestation-v1.json`
//!   (single capability) and `tests/vectors/toolset-attestation-v1-multicap.json`
//!   (multi-capability, locking token join order).  Both JSON files are loaded and
//!   their committed `preimage_hex`, `auditor_public_key_hex`, and `signature_hex`
//!   values are asserted equal to the values computed at test time.
//! - Cross-protocol inequality: attestation preimage ≠ publisher preimage.
//! - Trust-set: absent/empty auditor trust set → `TrustSetEmpty`.
//! - Install gate integration tests (key-touching, attestation, override, mismatch).
//! - Override does not weaken runtime (capabilities persist inert in pin).
//! - Redaction: no key/sig bytes in `Debug`, `Display`, or error output.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use stellar_agent_toolsets::parse_capability_value_pub;
use stellar_agent_toolsets_install::attestation::{
    ATTESTATION_DOMAIN_TAG, ToolsetAttestation, build_attestation_preimage, check_auditor_trusted,
    verify_attestation_signature,
};
use stellar_agent_toolsets_install::signature::{DOMAIN_TAG, build_preimage};
use stellar_agent_toolsets_install::{InstallOptions, ToolsetInstallError, install_toolset};
use stellar_strkey::ed25519::PublicKey as StrPublicKey;
use tempfile::TempDir;

// ── JSON vector loading helper ────────────────────────────────────────────────

/// Parses the spaced-hex encoding used in the JSON vector files
/// (`"aa bb cc ..."`) into a byte vector.
fn parse_spaced_hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|tok| u8::from_str_radix(tok, 16).expect("valid hex byte in vector"))
        .collect()
}

// ── Test seeds ────────────────────────────────────────────────────────────────

/// Auditor ed25519 test seed (NEVER a mainnet key).
///
/// Distinct from the publisher `TEST_SEED` (0x01..0x20) in `signature_vector.rs`.
const AUDITOR_TEST_SEED: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

/// Publisher ed25519 test seed (matches `signature_vector.rs` `TEST_SEED`).
const PUBLISHER_TEST_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

// ── Test vector constants ─────────────────────────────────────────────────────

/// KAT package name.
const TV_PACKAGE: &str = "test-toolset";
/// KAT version.
const TV_VERSION: &str = "1.0.0";
/// KAT shasum (same as in `toolset-sig-v1.json`).
const TV_SHASUM: &str = "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469224bca68a674e5262";
/// KAT capabilities joined (sorted single token).
const TV_CAPS_JOINED: &str = "sign-payment";

/// Committed auditor public key hex (locks key derivation from `AUDITOR_TEST_SEED`).
const TV_AUDITOR_PUBLIC_KEY_HEX: &str =
    "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0";

/// Committed attestation signature hex (locks preimage layout + determinism).
const TV_SIGNATURE_HEX: &str = "289af14acc7027f0ad515988a701d9dcc8dd538703a086e8d146cc9dd8273f18\
     4dd06e4e52675d24393e7004f273951cbc3fd56dbd727499b8c60d455c55f30d";

// ── Multi-capability KAT constants ────────────────────────────────────────────
// Capabilities: read-balance + sign-payment, joined in Capability Ord order
// (enum declaration order): "read-balance,sign-payment".

/// Multi-cap KAT capability tokens joined in Capability Ord order, as emitted
/// into the attestation preimage (comma-separated).
const TV_MULTI_CAPS_JOINED: &str = "read-balance,sign-payment";

/// Multi-cap KAT capabilities in the TOOLSET.md manifest form (space-separated),
/// the input to `parse_capability_value_pub`.  `build_attestation_preimage`
/// re-joins them with commas into the canonical [`TV_MULTI_CAPS_JOINED`] form.
const TV_MULTI_CAPS_SPACED: &str = "read-balance sign-payment";

/// Multi-cap KAT attestation signature hex.
///
/// Locked against `tests/vectors/toolset-attestation-v1-multicap.json`.
const TV_MULTI_SIGNATURE_HEX: &str = "a3daf8a30f088f234f10b0e05bc8749ce9b9d90643f9869621a2613b1481649d\
     0c1f5dc923f2dae766877f20daf935d4c7529079eed89ed49ddc95308c3e4404";

// ── Build helpers ─────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Builds a minimal `TOOLSET.md` that declares `sign-payment` (key-touching).
fn toolset_md_with_sign_payment(name: &str) -> String {
    format!(
        "---\nname: {name}\ndescription: A test toolset for attestation gate tests.\nmetadata:\n  stellar-agent-capabilities: sign-payment\n---\n\nAttestation gate test toolset body.\n"
    )
}

/// Builds a minimal `TOOLSET.md` with NO capabilities (non-key-touching control).
fn minimal_toolset_md_no_caps(name: &str) -> String {
    format!("---\nname: {name}\ndescription: A non-key-touching test toolset.\n---\n\nBody.\n")
}

/// Builds a `.tar.gz` archive with a single `TOOLSET.md` entry under `<name>/`.
fn make_toolset_tar_gz(package_name: &str, toolset_md_content: &str) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());

    // Directory entry.
    let mut dir_header = tar::Header::new_gnu();
    dir_header.set_entry_type(tar::EntryType::Directory);
    dir_header.set_path(format!("{package_name}/")).unwrap();
    dir_header.set_size(0);
    dir_header.set_mode(0o755);
    dir_header.set_cksum();
    ar.append(&dir_header, &[][..]).unwrap();

    // TOOLSET.md entry.
    let content = toolset_md_content.as_bytes();
    let mut file_header = tar::Header::new_gnu();
    file_header.set_entry_type(tar::EntryType::Regular);
    file_header
        .set_path(format!("{package_name}/TOOLSET.md"))
        .unwrap();
    file_header.set_size(content.len() as u64);
    file_header.set_mode(0o644);
    file_header.set_cksum();
    ar.append(&file_header, content).unwrap();

    let tar_bytes = ar.into_inner().unwrap();
    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

/// Signs a package with the given publisher key and returns (signature, shasum).
fn sign_package_publisher(
    package: &str,
    version: &str,
    data: &[u8],
    publisher_sk: &SigningKey,
) -> ([u8; 64], String) {
    let shasum = sha256_hex(data);
    let preimage = build_preimage(package, version, &shasum);
    let sig: [u8; 64] = publisher_sk.sign(&preimage).to_bytes();
    (sig, shasum)
}

/// Creates an auditor attestation for the given parameters.
fn make_attestation(
    auditor_sk: &SigningKey,
    auditor_pk: [u8; 32],
    package: &str,
    version: &str,
    shasum: &str,
    caps_joined: &str,
) -> ToolsetAttestation {
    let caps = parse_capability_value_pub(caps_joined).unwrap();
    let preimage = build_attestation_preimage(package, version, shasum, &caps);
    let sig: [u8; 64] = auditor_sk.sign(&preimage).to_bytes();
    ToolsetAttestation {
        package: package.to_owned(),
        version: version.to_owned(),
        shasum: shasum.to_owned(),
        capabilities: caps,
        auditor_pubkey: auditor_pk,
        signature: sig,
    }
}

/// Sets up a publisher trust file and an auditor trust file in `dir`.
fn write_trust_files(
    dir: &Path,
    publisher_pk: [u8; 32],
    auditor_pk: [u8; 32],
) -> (std::path::PathBuf, std::path::PathBuf) {
    let publisher_strkey = StrPublicKey(publisher_pk).to_string();
    let publisher_strkey_s: String = publisher_strkey.as_str().to_owned();
    let trust_path = dir.join("trust.txt");
    std::fs::write(&trust_path, format!("{publisher_strkey_s}\n")).unwrap();

    let auditor_strkey = StrPublicKey(auditor_pk).to_string();
    let auditor_strkey_s: String = auditor_strkey.as_str().to_owned();
    let auditor_trust_path = dir.join("auditor-trust.txt");
    std::fs::write(&auditor_trust_path, format!("{auditor_strkey_s}\n")).unwrap();

    (trust_path, auditor_trust_path)
}

// ── KAT: preimage layout locked ───────────────────────────────────────────────

#[test]
fn attestation_domain_tag_is_exact_36_bytes() {
    assert_eq!(
        ATTESTATION_DOMAIN_TAG,
        b"stellar-agent-toolset-attestation:v1"
    );
    assert_eq!(ATTESTATION_DOMAIN_TAG.len(), 36);
}

#[test]
fn attestation_preimage_layout_matches_test_vector() {
    let caps = parse_capability_value_pub(TV_CAPS_JOINED).unwrap();
    let computed = build_attestation_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM, &caps);

    // Reconstruct the expected preimage from the TV_* constants.
    let mut expected = Vec::new();
    expected.extend_from_slice(ATTESTATION_DOMAIN_TAG);
    let pkg = TV_PACKAGE.as_bytes();
    expected.extend_from_slice(&(pkg.len() as u32).to_be_bytes());
    expected.extend_from_slice(pkg);
    let ver = TV_VERSION.as_bytes();
    expected.extend_from_slice(&(ver.len() as u32).to_be_bytes());
    expected.extend_from_slice(ver);
    let sha = TV_SHASUM.as_bytes();
    expected.extend_from_slice(&(sha.len() as u32).to_be_bytes());
    expected.extend_from_slice(sha);
    let caps_b = TV_CAPS_JOINED.as_bytes();
    expected.extend_from_slice(&(caps_b.len() as u32).to_be_bytes());
    expected.extend_from_slice(caps_b);

    assert_eq!(
        computed, expected,
        "attestation preimage does not match the test vector layout"
    );

    // Also assert the computed preimage matches the committed JSON oracle.
    let json_raw = include_str!("vectors/toolset-attestation-v1.json");
    let json: serde_json::Value = serde_json::from_str(json_raw).unwrap();
    let json_preimage = parse_spaced_hex(json["preimage_hex"].as_str().unwrap());
    assert_eq!(
        computed, json_preimage,
        "computed preimage diverged from the committed JSON oracle \
         (tests/vectors/toolset-attestation-v1.json preimage_hex)"
    );
}

#[test]
fn committed_constants_match_computed_attestation_values() {
    // ed25519 is deterministic (RFC 8032 §5.1.6): same seed → same key → same sig.
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let computed_pk_hex = hex::encode(auditor_pk);
    assert_eq!(
        computed_pk_hex, TV_AUDITOR_PUBLIC_KEY_HEX,
        "auditor public key hex diverged from committed test vector; \
         update TV_AUDITOR_PUBLIC_KEY_HEX and tests/vectors/toolset-attestation-v1.json"
    );

    let caps = parse_capability_value_pub(TV_CAPS_JOINED).unwrap();
    let preimage = build_attestation_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM, &caps);
    let sig: [u8; 64] = auditor_sk.sign(&preimage).to_bytes();
    let computed_sig_hex = hex::encode(sig);

    let expected_sig = TV_SIGNATURE_HEX.replace(char::is_whitespace, "");
    assert_eq!(
        computed_sig_hex, expected_sig,
        "attestation signature hex diverged from committed test vector; \
         update TV_SIGNATURE_HEX and tests/vectors/toolset-attestation-v1.json (preimage layout changed?)"
    );

    // Load and verify against the JSON oracle.
    let json_raw = include_str!("vectors/toolset-attestation-v1.json");
    let json: serde_json::Value = serde_json::from_str(json_raw).unwrap();

    let json_pk_hex = json["auditor_public_key_hex"].as_str().unwrap();
    assert_eq!(
        computed_pk_hex, json_pk_hex,
        "computed auditor public key diverged from JSON oracle \
         (tests/vectors/toolset-attestation-v1.json auditor_public_key_hex)"
    );

    let json_sig_hex = json["signature_hex"]
        .as_str()
        .unwrap()
        .replace(char::is_whitespace, "");
    assert_eq!(
        computed_sig_hex, json_sig_hex,
        "computed attestation signature diverged from JSON oracle \
         (tests/vectors/toolset-attestation-v1.json signature_hex)"
    );
}

// ── KAT: multi-capability token join order locked ────────────────────────────

#[test]
fn multi_capability_kat_locked_against_json_oracle() {
    // Loads tests/vectors/toolset-attestation-v1-multicap.json and asserts that
    // the preimage_hex, auditor_public_key_hex, and signature_hex EQUAL the
    // values computed at test time.  This locks the two-token join order
    // ("read-balance,sign-payment" in Capability Ord order) against drift.
    let json_raw = include_str!("vectors/toolset-attestation-v1-multicap.json");
    let json: serde_json::Value = serde_json::from_str(json_raw).unwrap();

    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    // Compute from TV_* inputs + multi-cap set.  Parse the space-separated
    // manifest form; the builder re-joins tokens with commas into the canonical
    // TV_MULTI_CAPS_JOINED order, which the preimage_hex assertion below locks.
    let caps = parse_capability_value_pub(TV_MULTI_CAPS_SPACED).unwrap();
    assert_eq!(
        json["capabilities_joined"].as_str().unwrap(),
        TV_MULTI_CAPS_JOINED,
        "multi-cap KAT: JSON capabilities_joined must be the comma-joined Ord order"
    );
    let computed_preimage = build_attestation_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM, &caps);
    let sig: [u8; 64] = auditor_sk.sign(&computed_preimage).to_bytes();

    // Assert public key matches committed constant and JSON oracle.
    let computed_pk_hex = hex::encode(auditor_pk);
    assert_eq!(
        computed_pk_hex, TV_AUDITOR_PUBLIC_KEY_HEX,
        "multi-cap KAT: auditor public key must match TV_AUDITOR_PUBLIC_KEY_HEX"
    );
    assert_eq!(
        computed_pk_hex,
        json["auditor_public_key_hex"].as_str().unwrap(),
        "multi-cap KAT: computed public key diverged from JSON oracle"
    );

    // Assert preimage matches JSON oracle.
    let json_preimage = parse_spaced_hex(json["preimage_hex"].as_str().unwrap());
    assert_eq!(
        computed_preimage, json_preimage,
        "multi-cap KAT: computed preimage diverged from JSON oracle \
         (tests/vectors/toolset-attestation-v1-multicap.json preimage_hex)"
    );

    // Assert signature matches committed constant and JSON oracle.
    let computed_sig_hex = hex::encode(sig);
    let expected_sig = TV_MULTI_SIGNATURE_HEX.replace(char::is_whitespace, "");
    assert_eq!(
        computed_sig_hex, expected_sig,
        "multi-cap KAT: computed signature diverged from TV_MULTI_SIGNATURE_HEX \
         (preimage layout or join order changed?)"
    );
    let json_sig_hex = json["signature_hex"]
        .as_str()
        .unwrap()
        .replace(char::is_whitespace, "");
    assert_eq!(
        computed_sig_hex, json_sig_hex,
        "multi-cap KAT: computed signature diverged from JSON oracle \
         (tests/vectors/toolset-attestation-v1-multicap.json signature_hex)"
    );
}

#[test]
fn capability_token_join_order_is_canonical() {
    // Two capability sets with the same capabilities in different insertion
    // order must produce the SAME preimage.  Tokens are emitted in Capability
    // Ord order (enum declaration order), comma-joined — insertion order is irrelevant.
    let caps1 = parse_capability_value_pub("sign-payment read-balance").unwrap();
    let caps2 = parse_capability_value_pub("read-balance sign-payment").unwrap();
    let p1 = build_attestation_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM, &caps1);
    let p2 = build_attestation_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM, &caps2);
    assert_eq!(
        p1, p2,
        "capability tokens must be joined in a canonical order regardless of insertion order"
    );
}

// ── Cross-protocol inequality ─────────────────────────────────────────────────
// Attestation and publisher preimages differ: different domain tags and
// capability field in attestation preimage prevents cross-protocol replay.

#[test]
fn attestation_preimage_ne_publisher_preimage() {
    let caps = parse_capability_value_pub(TV_CAPS_JOINED).unwrap();
    let att_pre = build_attestation_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM, &caps);
    let sig_pre = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    assert_ne!(
        att_pre, sig_pre,
        "attestation preimage must differ from publisher preimage \
         (cross-protocol replay protection)"
    );
}

#[test]
fn attestation_domain_tag_ne_publisher_domain_tag() {
    assert_ne!(ATTESTATION_DOMAIN_TAG, DOMAIN_TAG);
    assert_ne!(ATTESTATION_DOMAIN_TAG.len(), DOMAIN_TAG.len());
}

#[test]
fn publisher_sig_rejected_as_attestation_sig_via_verify() {
    // A valid publisher signature over the publisher preimage must be REFUSED
    // when presented as an attestation signature (cross-protocol replay immunity).
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let caps = parse_capability_value_pub(TV_CAPS_JOINED).unwrap();

    // Sign over the publisher preimage.
    let publisher_preimage = build_preimage(TV_PACKAGE, TV_VERSION, TV_SHASUM);
    let publisher_sig: [u8; 64] = auditor_sk.sign(&publisher_preimage).to_bytes();

    // Present as an attestation — verify must fail.
    let att = ToolsetAttestation {
        package: TV_PACKAGE.to_owned(),
        version: TV_VERSION.to_owned(),
        shasum: TV_SHASUM.to_owned(),
        capabilities: caps.clone(),
        auditor_pubkey: auditor_pk,
        signature: publisher_sig,
    };
    let err = verify_attestation_signature(&att, &caps).unwrap_err();
    assert!(
        matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
        "publisher sig presented as attestation must be AttestationInvalid; got: {err:?}"
    );
}

// ── Trust-set: absent/empty → TrustSetEmpty ───────────────────────────────────

#[test]
fn absent_auditor_trust_set_returns_trust_set_empty() {
    use stellar_agent_toolsets_install::attestation::load_auditor_trust_set;

    let tmp = TempDir::new().unwrap();
    let nonexistent = tmp.path().join("auditor-trust.txt");
    // File does not exist → TrustSetEmpty.
    let err = load_auditor_trust_set(&nonexistent).unwrap_err();
    assert!(
        matches!(err, ToolsetInstallError::TrustSetEmpty),
        "absent auditor trust set must return TrustSetEmpty; got: {err:?}"
    );
}

#[test]
fn empty_auditor_trust_set_returns_trust_set_empty() {
    use stellar_agent_toolsets_install::attestation::load_auditor_trust_set;

    let tmp = TempDir::new().unwrap();
    let trust_path = tmp.path().join("auditor-trust.txt");
    std::fs::write(&trust_path, b"# no keys\n").unwrap();
    let err = load_auditor_trust_set(&trust_path).unwrap_err();
    assert!(
        matches!(err, ToolsetInstallError::TrustSetEmpty),
        "empty auditor trust set must return TrustSetEmpty; got: {err:?}"
    );
}

// ── Key-touching, no attestation → AttestationRequired ───────────────────────

#[test]
fn key_touching_no_attestation_required() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        None, // no attestation
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::AttestationRequired { .. }),
        "expected AttestationRequired for key-touching toolset with no attestation, got: {err:?}"
    );

    // Verify no partial install.
    assert!(
        !toolsets_root.join("sign-toolset").exists(),
        "no partial install must remain after AttestationRequired"
    );
}

// ── Valid attestation from trusted auditor → success ─────────────────────────

#[test]
fn valid_attestation_trusted_auditor_succeeds() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    let att = make_attestation(
        &auditor_sk,
        auditor_pk,
        "sign-toolset",
        "1.0.0",
        &shasum,
        "sign-payment",
    );

    install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .expect("valid attestation from trusted auditor must succeed");

    // Verify the pin was written.
    assert!(
        toolsets_root
            .join("sign-toolset")
            .join(".stellar-agent-toolset-pin.json")
            .exists(),
        "pin record must be written after attested install"
    );
}

// ── override_attestation=true → outcome Overridden, warn emitted ─────────────

#[test]
fn override_attestation_succeeds_with_warn() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    let opts = InstallOptions {
        override_attestation: true,
        ..InstallOptions::default()
    };

    install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        None, // no attestation — override bypasses the gate
        &auditor_trust_path,
        &opts,
    )
    .expect("override_attestation must succeed even with no attestation");

    // Verify pin exists.
    assert!(
        toolsets_root
            .join("sign-toolset")
            .join(".stellar-agent-toolset-pin.json")
            .exists(),
        "pin must be written after overridden install"
    );
}

// ── Untrusted auditor → AuditorUntrusted ─────────────────────────────────────

#[test]
fn untrusted_auditor_refused() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    // A DIFFERENT auditor that is NOT in the trust file.
    let untrusted_seed = [0xeeu8; 32];
    let untrusted_sk = SigningKey::from_bytes(&untrusted_seed);
    let untrusted_pk = untrusted_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    // Only `auditor_pk` is in the trust file — `untrusted_pk` is NOT.
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    // Attestation signed by the untrusted key.
    let att = make_attestation(
        &untrusted_sk,
        untrusted_pk,
        "sign-toolset",
        "1.0.0",
        &shasum,
        "sign-payment",
    );

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    assert!(
        matches!(err, ToolsetInstallError::AuditorUntrusted { .. }),
        "expected AuditorUntrusted for key not in auditor trust set, got: {err:?}"
    );
}

// ── Field mismatch in attestation → AttestationFieldMismatch ─────────────────

#[test]
fn attestation_package_mismatch_refused() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    // Attestation for a DIFFERENT package name.
    let att = make_attestation(
        &auditor_sk,
        auditor_pk,
        "other-toolset", // wrong package
        "1.0.0",
        &shasum,
        "sign-payment",
    );

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            ToolsetInstallError::AttestationFieldMismatch { field: "package" }
        ),
        "expected AttestationFieldMismatch{{field:package}} for wrong package name, got: {err:?}"
    );
}

#[test]
fn attestation_version_mismatch_refused() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    // Attestation for a DIFFERENT version.
    let att = make_attestation(
        &auditor_sk,
        auditor_pk,
        "sign-toolset",
        "2.0.0", // wrong version
        &shasum,
        "sign-payment",
    );

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            ToolsetInstallError::AttestationFieldMismatch { field: "version" }
        ),
        "expected AttestationFieldMismatch{{field:version}} for wrong version, got: {err:?}"
    );
}

#[test]
fn attestation_shasum_mismatch_refused() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    // Attestation for a DIFFERENT shasum (different artefact).
    let wrong_shasum = "b".repeat(64);
    let att = make_attestation(
        &auditor_sk,
        auditor_pk,
        "sign-toolset",
        "1.0.0",
        &wrong_shasum, // wrong shasum
        "sign-payment",
    );

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            ToolsetInstallError::AttestationFieldMismatch { field: "shasum" }
        ),
        "expected AttestationFieldMismatch{{field:shasum}} for wrong shasum, got: {err:?}"
    );
}

#[test]
fn attestation_capabilities_mismatch_refused() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    // Attestation with DIFFERENT capabilities (empty instead of sign-payment).
    let wrong_caps = parse_capability_value_pub("").unwrap();
    let preimage_wrong = build_attestation_preimage("sign-toolset", "1.0.0", &shasum, &wrong_caps);
    let sig_att: [u8; 64] = auditor_sk.sign(&preimage_wrong).to_bytes();
    let att = ToolsetAttestation {
        package: "sign-toolset".to_owned(),
        version: "1.0.0".to_owned(),
        shasum: shasum.clone(),
        capabilities: wrong_caps,
        auditor_pubkey: auditor_pk,
        signature: sig_att,
    };

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            ToolsetInstallError::AttestationFieldMismatch {
                field: "capabilities"
            }
        ),
        "expected AttestationFieldMismatch{{field:capabilities}} for wrong capabilities, got: {err:?}"
    );
}

// ── Non-key-touching toolset → no attestation required ─────────────────────────

#[test]
fn non_key_touching_no_attestation_needed() {
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let trust_path = tmp.path().join("trust.txt");
    let publisher_strkey = StrPublicKey(publisher_pk).to_string();
    let publisher_strkey_s: String = publisher_strkey.as_str().to_owned();
    std::fs::write(&trust_path, format!("{publisher_strkey_s}\n")).unwrap();

    // No-caps toolset — attestation gate must NOT fire.
    let pkg_bytes =
        make_toolset_tar_gz("read-toolset", &minimal_toolset_md_no_caps("read-toolset"));
    let (sig, shasum) = sign_package_publisher("read-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    // Non-existent auditor trust path — would return TrustSetEmpty if opened,
    // but must NOT be opened for a non-key-touching toolset.
    let auditor_trust_path = tmp.path().join("auditor-trust.txt");

    install_toolset(
        "read-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        None,
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .expect("non-key-touching toolset must install without attestation");
}

// ── Membership check and verify use the same auditor_pubkey bytes ────────────

#[test]
fn membership_and_verify_use_same_key_bytes() {
    // The gate checks trust-set membership and signature verify against
    // att.auditor_pubkey (single key source).  Swapping auditor_pubkey to a
    // trusted-but-different key after signing must fail signature verification.
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    // A SECOND auditor that IS in the trust set.
    let second_auditor_seed = [0xddu8; 32];
    let second_auditor_sk = SigningKey::from_bytes(&second_auditor_seed);
    let second_auditor_pk = second_auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    // Write BOTH auditor keys to the trust file.
    let publisher_strkey = StrPublicKey(publisher_pk).to_string();
    let ps: String = publisher_strkey.as_str().to_owned();
    let strkey1 = StrPublicKey(auditor_pk).to_string();
    let s1: String = strkey1.as_str().to_owned();
    let strkey2 = StrPublicKey(second_auditor_pk).to_string();
    let s2: String = strkey2.as_str().to_owned();
    let trust_path = tmp.path().join("trust.txt");
    std::fs::write(&trust_path, format!("{ps}\n")).unwrap();
    let auditor_trust_path = tmp.path().join("auditor-trust.txt");
    std::fs::write(&auditor_trust_path, format!("{s1}\n{s2}\n")).unwrap();

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    // Sign over the attestation preimage with `auditor_sk`, but present
    // `second_auditor_pk` as the auditor_pubkey in the struct.
    // Both keys are trusted, but the signature was made with auditor_sk,
    // so verify must fail because the key in the struct (second_auditor_pk)
    // differs from the signing key (auditor_sk).
    let caps = parse_capability_value_pub("sign-payment").unwrap();
    let preimage = build_attestation_preimage("sign-toolset", "1.0.0", &shasum, &caps);
    let att_sig: [u8; 64] = auditor_sk.sign(&preimage).to_bytes();

    let att = ToolsetAttestation {
        package: "sign-toolset".to_owned(),
        version: "1.0.0".to_owned(),
        shasum: shasum.clone(),
        capabilities: caps,
        // Key carried in struct is second_auditor_pk, but sig was made with auditor_sk.
        auditor_pubkey: second_auditor_pk,
        signature: att_sig,
    };

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    // The gate uses att.auditor_pubkey (second_auditor_pk) for both membership and verify.
    // Because the signature was made with auditor_sk (not second_auditor_sk), verify fails.
    assert!(
        matches!(err, ToolsetInstallError::AttestationInvalid { .. }),
        "mismatched sign key vs struct key must give AttestationInvalid; got: {err:?}"
    );
}

// ── Identity confusion — attestation.package=A, TOOLSET.md name=B ──────────────

#[test]
fn identity_confusion_attested_for_wrong_name_refused() {
    // A tarball whose TOOLSET.md declares name="other-toolset" (key-touching)
    // is presented as "sign-toolset" with an attestation for "sign-toolset".
    // The identity cross-check fires first and returns IdentityMismatch.
    // This proves the attestation gate runs AFTER the identity cross-check.
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    // TOOLSET.md says name="other-toolset" but is signed+attested as "sign-toolset".
    // parse_toolset checks the TOOLSET.md name against the staging directory name
    // ("sign-toolset"), so it returns NameDirMismatch (wrapped as ToolsetFormat)
    // before the identity cross-check at the identity verification step.  Either
    // ToolsetFormat or IdentityMismatch proves the install was refused before the
    // attestation gate reached an unconfirmed identity.
    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("other-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    let att = make_attestation(
        &auditor_sk,
        auditor_pk,
        "sign-toolset",
        "1.0.0",
        &shasum,
        "sign-payment",
    );

    let err = install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        Some(&att),
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .unwrap_err();

    // Accepts ToolsetFormat (NameDirMismatch at Step 8) or IdentityMismatch (Step 9).
    // Both prove the gate never ran against an unconfirmed identity.
    assert!(
        matches!(err, ToolsetInstallError::IdentityMismatch { .. })
            || matches!(err, ToolsetInstallError::ToolsetFormat(..)),
        "identity confusion must be refused at parse/identity-check; got: {err:?}"
    );

    // No partial install.
    assert!(
        !toolsets_root.join("sign-toolset").exists(),
        "no partial install must remain after identity confusion refusal"
    );
}

// ── Why a pure Step-9 IdentityMismatch is unconstructible ────────────────────
//
// The extractor, parse_toolset, and Step 9 all enforce the same invariant:
// the top-level tar directory name EQUALS the package argument.  A tarball that
// passes the extractor (Step 7) and parse_toolset (Step 8) therefore always
// passes Step 9 as well — there is no constructible input that reaches Step 9
// with a name mismatch via the public API.  The identity_confusion test above
// (which hits Step-8 ToolsetFormat) is the strongest achievable proof that the
// attestation gate fires AFTER identity is confirmed.

// ── Override does not weaken runtime (sign-payment persisted inert) ───────────

#[test]
fn override_still_persists_sign_payment_in_pin() {
    // A toolset installed under override_attestation must still have sign-payment
    // in the pin record.  The toolsets-runtime reads capabilities from the pin;
    // the capability is inert (not exercisable at dispatch) until an attested
    // reinstall occurs.  This test verifies the pin reflects the declared
    // capability even when the install gate was bypassed.
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();
    let (trust_path, auditor_trust_path) = write_trust_files(tmp.path(), publisher_pk, auditor_pk);

    let pkg_bytes = make_toolset_tar_gz(
        "sign-toolset",
        &toolset_md_with_sign_payment("sign-toolset"),
    );
    let (sig, shasum) = sign_package_publisher("sign-toolset", "1.0.0", &pkg_bytes, &publisher_sk);

    let opts = InstallOptions {
        override_attestation: true,
        ..InstallOptions::default()
    };

    install_toolset(
        "sign-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        None,
        &auditor_trust_path,
        &opts,
    )
    .expect("override install must succeed");

    // Read the pin and verify sign-payment is persisted (inert) in the pin.
    let pin_path = toolsets_root
        .join("sign-toolset")
        .join(".stellar-agent-toolset-pin.json");
    let pin: stellar_agent_toolsets_install::ToolsetPinRecord =
        serde_json::from_str(&std::fs::read_to_string(&pin_path).unwrap()).unwrap();

    assert!(
        pin.capabilities
            .contains(stellar_agent_toolsets::Capability::SignPayment),
        "sign-payment must be persisted in pin even after override install; pin: {pin:?}"
    );
}

// ── Capability-source invariant: pin is source of truth ───────────────────────

#[test]
fn sec_on_disk_tamper_pin_is_source_of_truth() {
    // A toolset installed with NO capabilities (no key-touching).
    // After install, the on-disk TOOLSET.md is tampered to add sign-payment.
    // The pin record (written at install time from the verified parse) must NOT
    // reflect the tampered content — only the original empty capability set.
    //
    // This test verifies the capability-source invariant at the install-crate level:
    // the pin is written from the signature-verified parse, not from the disk.
    //
    // Full runtime enforcement (dispatch reading pin vs file) is tested in
    // stellar-agent-toolsets-runtime; here we verify the PIN CONTENTS.
    let publisher_sk = SigningKey::from_bytes(&PUBLISHER_TEST_SEED);
    let publisher_pk = publisher_sk.verifying_key().to_bytes();

    let tmp = TempDir::new().unwrap();
    let toolsets_root = tmp.path().join("toolsets");
    std::fs::create_dir_all(&toolsets_root).unwrap();

    let trust_path = tmp.path().join("trust.txt");
    let publisher_strkey = StrPublicKey(publisher_pk).to_string();
    let ps: String = publisher_strkey.as_str().to_owned();
    std::fs::write(&trust_path, format!("{ps}\n")).unwrap();

    // Install a non-key-touching toolset.
    let pkg_bytes =
        make_toolset_tar_gz("read-toolset", &minimal_toolset_md_no_caps("read-toolset"));
    let (sig, shasum) = sign_package_publisher("read-toolset", "1.0.0", &pkg_bytes, &publisher_sk);
    let auditor_trust_path = tmp.path().join("auditor-trust.txt");

    install_toolset(
        "read-toolset",
        "1.0.0",
        &pkg_bytes,
        &shasum,
        &sig,
        &publisher_pk,
        &toolsets_root,
        &trust_path,
        None,
        &auditor_trust_path,
        &InstallOptions::default(),
    )
    .expect("non-key-touching install must succeed");

    // Read the pin — must have NO capabilities (empty set).
    let pin_path = toolsets_root
        .join("read-toolset")
        .join(".stellar-agent-toolset-pin.json");
    let pin_before: stellar_agent_toolsets_install::ToolsetPinRecord =
        serde_json::from_str(&std::fs::read_to_string(&pin_path).unwrap()).unwrap();
    assert!(
        pin_before.capabilities.is_empty(),
        "pin must have empty capabilities after non-key-touching install; got: {:?}",
        pin_before.capabilities
    );

    // Tamper the on-disk TOOLSET.md to add sign-payment.
    let tampered_md = toolset_md_with_sign_payment("read-toolset");
    std::fs::write(
        toolsets_root.join("read-toolset").join("TOOLSET.md"),
        tampered_md,
    )
    .unwrap();

    // Read the pin again — must STILL have no capabilities.
    // The pin was written from the signature-verified parse; the disk tamper
    // changes the file but NOT the pin.
    let pin_after: stellar_agent_toolsets_install::ToolsetPinRecord =
        serde_json::from_str(&std::fs::read_to_string(&pin_path).unwrap()).unwrap();
    assert!(
        pin_after.capabilities.is_empty(),
        "pin must still have empty capabilities after on-disk tamper of TOOLSET.md; \
         the pin is the source of truth for capability decisions; got: {:?}",
        pin_after.capabilities
    );

    // Verify the tampered TOOLSET.md would now parse as key-touching.
    let tampered_dir = toolsets_root.join("read-toolset");
    let parsed = stellar_agent_toolsets::parse_toolset(&tampered_dir).unwrap();
    assert!(
        parsed
            .capabilities
            .contains(stellar_agent_toolsets::Capability::SignPayment),
        "tampered TOOLSET.md must parse as having sign-payment (to confirm tamper worked)"
    );

    // Confirm: the pin does NOT match the tampered file.
    assert_ne!(
        pin_after.capabilities, parsed.capabilities,
        "pin must differ from tampered TOOLSET.md (pin is source of truth for capability decisions)"
    );
}

// ── Redaction: no key/sig bytes in Debug, Display, error output ───────────────

#[test]
fn redaction_no_key_bytes_in_debug_output() {
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    let att = make_attestation(
        &auditor_sk,
        auditor_pk,
        "test-toolset",
        "1.0.0",
        TV_SHASUM,
        "sign-payment",
    );

    let debug_str = format!("{att:?}");

    // Raw pubkey hex must not appear.
    let pk_hex = hex::encode(auditor_pk);
    assert!(
        !debug_str.contains(&pk_hex),
        "Debug must not contain raw auditor pubkey hex; got: {debug_str}"
    );

    // Raw signature hex must not appear.
    let sig_hex = hex::encode(att.signature);
    assert!(
        !debug_str.contains(&sig_hex),
        "Debug must not contain raw signature hex; got: {debug_str}"
    );

    // [REDACTED] sentinel must be present.
    assert!(
        debug_str.contains("[REDACTED]"),
        "Debug must contain [REDACTED] for signature; got: {debug_str}"
    );
}

#[test]
fn redaction_error_display_no_key_bytes() {
    let auditor_sk = SigningKey::from_bytes(&AUDITOR_TEST_SEED);
    let auditor_pk = auditor_sk.verifying_key().to_bytes();

    // AuditorUntrusted display should use a redacted key, not raw bytes.
    let mut empty_set = BTreeSet::new();
    let err = check_auditor_trusted(&auditor_pk, &empty_set).unwrap_err();
    let display = err.to_string();

    // Raw pubkey hex must not appear in Display.
    let pk_hex = hex::encode(auditor_pk);
    assert!(
        !display.contains(&pk_hex),
        "AuditorUntrusted Display must not contain raw key hex; got: {display}"
    );

    // AttestationInvalid display must not contain variant detail beyond the static string.
    let invalid_err = ToolsetInstallError::AttestationInvalid {
        detail: "ed25519 verify_strict failed for attestation signature",
    };
    let invalid_display = invalid_err.to_string();
    // Must not be empty.
    assert!(!invalid_display.is_empty());
    // Must not leak bytes.
    assert!(
        !invalid_display.contains("0x"),
        "AttestationInvalid Display must not contain hex-style bytes; got: {invalid_display}"
    );

    // Suppress unused warning on empty_set.
    empty_set.insert([0u8; 32]);
}
