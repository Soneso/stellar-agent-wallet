//! Binds every embedded Wasm constant, every pinned Wasm digest, and every
//! Wasm allowlist entry of this crate to one specific vendored file.
//!
//! [`VENDORED`] lists the vendored Wasm files by their path relative to the
//! crate root, the form the `vendored-wasm` workflow's manifest uses. Each
//! entry reads its bytes through a direct `include_bytes!` of that path, never
//! through an embedded constant, and every digest these tests compare with is
//! the sha256 of those direct bytes. The `vendored-wasm` workflow ties rebuildable
//! files to their pinned sources; these tests tie the code's bytes and digests to
//! specific files. The integration test in `tests/vendored_wasm_release_cfg.rs`
//! checks the library compiled without `cfg(test)`. The tree check constrains
//! source spellings as defense in depth.
//!
//! Package verification does not compile `cfg(test)` code, so this module may
//! include the v0.7.1 files that the package excludes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::path::Path;
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use crate::deployment::deploy::{
    DeploymentArgs, ResolvedFeePerOp, deploy_smart_account, interop_deployer,
};
use crate::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES;
use crate::weighted_threshold_policy::WEIGHTED_THRESHOLD_POLICY_WASM_HASHES;
use crate::{VERIFIER_ALLOWLIST, VerifierAllowlistEntry, VerifierAuditStatus};

/// One vendored Wasm file: its path relative to the crate root and its bytes.
struct VendoredFile {
    path: &'static str,
    bytes: &'static [u8],
}

const ACCOUNTS_V072: &str = "vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm";
const MULTISIG_V072: &str = "vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm";
const WEBAUTHN_V072: &str =
    "vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm";
const TIMELOCK_V072: &str = "vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm";
const THRESHOLD_V072: &str =
    "vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm";
const ED25519_V072: &str =
    "vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm";
const SPENDING_LIMIT_V072: &str =
    "vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm";
const WEIGHTED_THRESHOLD_V072: &str =
    "vendor/oz-weighted-threshold-policy/v0.7.2/multisig_weighted_threshold_policy_example.wasm";
const ACCOUNTS_V071: &str = "vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm";
const MULTISIG_V071: &str = "vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm";
const WEBAUTHN_V071: &str =
    "vendor/oz-webauthn-verifier/v0.7.1/multisig_webauthn_verifier_example.wasm";
const TIMELOCK_V071: &str = "vendor/oz-timelock-controller/v0.7.1/timelock_controller_example.wasm";
const THRESHOLD_V071: &str =
    "vendor/oz-threshold-policy/v0.7.1/multisig_threshold_policy_example.wasm";
const CAP85_BEACON: &str = "vendor/cap85-beacon/v0.1.0/cap85_beacon.wasm";
const MULTICALL: &str = "vendor/multicall/v0.1.0/multicall.wasm";

/// The 15 vendored Wasm files, each with its bytes from a direct
/// `include_bytes!` of its path.
const VENDORED: &[VendoredFile] = &[
    VendoredFile {
        path: ACCOUNTS_V072,
        bytes: include_bytes!("../vendor/oz-stellar-accounts/v0.7.2/stellar_accounts.wasm"),
    },
    VendoredFile {
        path: MULTISIG_V072,
        bytes: include_bytes!(
            "../vendor/oz-smart-account-multisig/v0.7.2/multisig_account_example.wasm"
        ),
    },
    VendoredFile {
        path: WEBAUTHN_V072,
        bytes: include_bytes!(
            "../vendor/oz-webauthn-verifier/v0.7.2/multisig_webauthn_verifier_example.wasm"
        ),
    },
    VendoredFile {
        path: TIMELOCK_V072,
        bytes: include_bytes!(
            "../vendor/oz-timelock-controller/v0.7.2/timelock_controller_example.wasm"
        ),
    },
    VendoredFile {
        path: THRESHOLD_V072,
        bytes: include_bytes!(
            "../vendor/oz-threshold-policy/v0.7.2/multisig_threshold_policy_example.wasm"
        ),
    },
    VendoredFile {
        path: ED25519_V072,
        bytes: include_bytes!(
            "../vendor/oz-ed25519-verifier/v0.7.2/multisig_ed25519_verifier_example.wasm"
        ),
    },
    VendoredFile {
        path: SPENDING_LIMIT_V072,
        bytes: include_bytes!(
            "../vendor/oz-spending-limit-policy/v0.7.2/multisig_spending_limit_policy_example.wasm"
        ),
    },
    VendoredFile {
        path: WEIGHTED_THRESHOLD_V072,
        bytes: include_bytes!(
            "../vendor/oz-weighted-threshold-policy/v0.7.2/multisig_weighted_threshold_policy_example.wasm"
        ),
    },
    VendoredFile {
        path: ACCOUNTS_V071,
        bytes: include_bytes!("../vendor/oz-stellar-accounts/v0.7.1/stellar_accounts.wasm"),
    },
    VendoredFile {
        path: MULTISIG_V071,
        bytes: include_bytes!(
            "../vendor/oz-smart-account-multisig/v0.7.1/multisig_account_example.wasm"
        ),
    },
    VendoredFile {
        path: WEBAUTHN_V071,
        bytes: include_bytes!(
            "../vendor/oz-webauthn-verifier/v0.7.1/multisig_webauthn_verifier_example.wasm"
        ),
    },
    VendoredFile {
        path: TIMELOCK_V071,
        bytes: include_bytes!(
            "../vendor/oz-timelock-controller/v0.7.1/timelock_controller_example.wasm"
        ),
    },
    VendoredFile {
        path: THRESHOLD_V071,
        bytes: include_bytes!(
            "../vendor/oz-threshold-policy/v0.7.1/multisig_threshold_policy_example.wasm"
        ),
    },
    VendoredFile {
        path: CAP85_BEACON,
        bytes: include_bytes!("../vendor/cap85-beacon/v0.1.0/cap85_beacon.wasm"),
    },
    VendoredFile {
        path: MULTICALL,
        bytes: include_bytes!("../vendor/multicall/v0.1.0/multicall.wasm"),
    },
];

/// The test-only fixture entry of `VERIFIER_ALLOWLIST`, compiled only under
/// `cfg(any(test, feature = "test-helpers"))`.
const TEST_ONLY_VERIFIER_FIXTURE: [u8; 32] = [0xee; 32];

/// The direct bytes of the vendored file at `path`.
fn vendored(path: &str) -> &'static [u8] {
    VENDORED
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.bytes)
        .unwrap_or_else(|| panic!("{path} is not in VENDORED"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

/// Each entry names a distinct Wasm file, and its bytes are the file at its
/// path, so a path and an `include_bytes!` literal that disagree fail here.
#[test]
fn vendored_table_entries_are_the_files_at_their_paths() {
    assert_eq!(VENDORED.len(), 15, "VENDORED lists 15 vendored Wasm files");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (index, file) in VENDORED.iter().enumerate() {
        assert!(
            VENDORED[..index]
                .iter()
                .all(|other| other.path != file.path),
            "{} is listed twice",
            file.path
        );
        assert_eq!(
            &file.bytes[..4],
            b"\0asm",
            "{} does not start with the Wasm magic bytes",
            file.path
        );
        let on_disk = std::fs::read(root.join(file.path))
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", file.path));
        assert!(
            on_disk == file.bytes,
            "the bytes listed for {} are not that file",
            file.path
        );
    }
}

/// Each embedded Wasm constant equals the vendored file its rustdoc names.
#[test]
fn embedded_wasm_constants_are_their_vendored_files() {
    let constants: &[(&str, &[u8], &str)] = &[
        ("bindings::WASM", crate::bindings::WASM, ACCOUNTS_V072),
        (
            "MULTISIG_ACCOUNT_WASM",
            crate::deployment::deploy::MULTISIG_ACCOUNT_WASM,
            MULTISIG_V072,
        ),
        (
            "WEBAUTHN_VERIFIER_WASM",
            crate::webauthn_verifier::WEBAUTHN_VERIFIER_WASM,
            WEBAUTHN_V072,
        ),
        (
            "VERIFIER_WASM_FIXTURE",
            crate::signers::verifier_identification::VERIFIER_WASM_FIXTURE,
            WEBAUTHN_V072,
        ),
        (
            "TIMELOCK_CONTROLLER_WASM",
            crate::deployment::deploy_timelock_controller::TIMELOCK_CONTROLLER_WASM,
            TIMELOCK_V072,
        ),
        (
            "THRESHOLD_POLICY_WASM",
            crate::signers::policy_identification::THRESHOLD_POLICY_WASM,
            THRESHOLD_V072,
        ),
        (
            "ED25519_VERIFIER_WASM",
            crate::ed25519_verifier::ED25519_VERIFIER_WASM,
            ED25519_V072,
        ),
        (
            "SPENDING_LIMIT_POLICY_WASM",
            crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM,
            SPENDING_LIMIT_V072,
        ),
        (
            "WEIGHTED_THRESHOLD_POLICY_WASM",
            crate::weighted_threshold_policy::WEIGHTED_THRESHOLD_POLICY_WASM,
            WEIGHTED_THRESHOLD_V072,
        ),
        (
            "cap85_beacon::CAP85_BEACON_WASM",
            crate::cap85_beacon::CAP85_BEACON_WASM,
            CAP85_BEACON,
        ),
        (
            "MULTICALL_WASM",
            crate::multicall::MULTICALL_WASM,
            MULTICALL,
        ),
    ];
    let differing: Vec<String> = constants
        .iter()
        .filter(|(_, bytes, path)| *bytes != vendored(path))
        .map(|(name, _, path)| format!("{name} is not {path}"))
        .collect();
    assert!(
        differing.is_empty(),
        "embedded Wasm constants that differ from their vendored file: {differing:?}"
    );
}

/// Each Wasm digest constant is the sha256 of its own vendored file.
#[test]
fn digest_constants_are_the_sha256_of_their_vendored_files() {
    let digests: &[(&str, &str, &str)] = &[
        (
            "bindings::WASM_SHA256",
            crate::bindings::WASM_SHA256,
            ACCOUNTS_V072,
        ),
        (
            "MULTISIG_ACCOUNT_WASM_SHA256",
            crate::deployment::deploy::MULTISIG_ACCOUNT_WASM_SHA256,
            MULTISIG_V072,
        ),
        (
            "WEBAUTHN_VERIFIER_WASM_SHA256",
            crate::webauthn_verifier::WEBAUTHN_VERIFIER_WASM_SHA256,
            WEBAUTHN_V072,
        ),
        (
            "MULTICALL_WASM_SHA256",
            crate::multicall::MULTICALL_WASM_SHA256,
            MULTICALL,
        ),
        (
            "TIMELOCK_CONTROLLER_WASM_SHA256",
            crate::deployment::deploy_timelock_controller::TIMELOCK_CONTROLLER_WASM_SHA256,
            TIMELOCK_V072,
        ),
        (
            "SPENDING_LIMIT_POLICY_WASM_SHA256",
            crate::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256,
            SPENDING_LIMIT_V072,
        ),
        (
            "ED25519_VERIFIER_WASM_SHA256",
            crate::ed25519_verifier::ED25519_VERIFIER_WASM_SHA256,
            ED25519_V072,
        ),
        (
            "WEIGHTED_THRESHOLD_POLICY_WASM_SHA256",
            crate::weighted_threshold_policy::WEIGHTED_THRESHOLD_POLICY_WASM_SHA256,
            WEIGHTED_THRESHOLD_V072,
        ),
        (
            "cap85_beacon::CAP85_BEACON_WASM_SHA256",
            crate::cap85_beacon::CAP85_BEACON_WASM_SHA256,
            CAP85_BEACON,
        ),
    ];
    let differing: Vec<String> = digests
        .iter()
        .filter(|(_, digest, path)| *digest != sha256_hex(vendored(path)))
        .map(|(name, digest, path)| {
            format!(
                "{name} is {digest}, the sha256 of {path} is {}",
                sha256_hex(vendored(path))
            )
        })
        .collect();
    assert!(
        differing.is_empty(),
        "digest constants that differ from their vendored file: {differing:?}"
    );
}

/// The production entries of `VERIFIER_ALLOWLIST` are exactly the v0.7.2
/// WebAuthn, v0.7.1 WebAuthn, and v0.7.2 Ed25519 verifier files, in that
/// order. The test-only fixture is filtered by its exact value, so an
/// appended production entry of any audit status is counted.
#[test]
fn verifier_allowlist_production_entries_are_the_vendored_verifiers() {
    let production: Vec<String> = VERIFIER_ALLOWLIST
        .iter()
        .map(|entry| entry.wasm_hash)
        .filter(|hash| *hash != TEST_ONLY_VERIFIER_FIXTURE)
        .map(hex::encode)
        .collect();
    assert_eq!(
        production,
        vec![
            sha256_hex(vendored(WEBAUTHN_V072)),
            sha256_hex(vendored(WEBAUTHN_V071)),
            sha256_hex(vendored(ED25519_V072)),
        ],
        "VERIFIER_ALLOWLIST production entries must be the v0.7.2 WebAuthn, v0.7.1 WebAuthn, \
         and v0.7.2 Ed25519 verifier digests"
    );
}

/// `VERIFIER_ALLOWLIST` holds the test-only fixture exactly once, with a
/// revoked status. The tree check requires that entry under its own attribute,
/// and this test refuses a second copy by value.
#[test]
fn verifier_allowlist_holds_the_revoked_fixture_once() {
    let fixtures: Vec<&VerifierAllowlistEntry> = VERIFIER_ALLOWLIST
        .iter()
        .filter(|entry| entry.wasm_hash == TEST_ONLY_VERIFIER_FIXTURE)
        .collect();
    assert_eq!(
        fixtures.len(),
        1,
        "VERIFIER_ALLOWLIST must hold the test-only fixture exactly once"
    );
    assert!(
        matches!(
            fixtures[0].audit_status,
            VerifierAuditStatus::Revoked { .. }
        ),
        "the test-only fixture must be revoked, not {:?}",
        fixtures[0].audit_status
    );
}

/// `THRESHOLD_POLICY_WASM_HASHES` is exactly the v0.7.2 and v0.7.1 threshold
/// policy files, in that order.
#[test]
fn threshold_policy_hashes_are_the_vendored_threshold_policies() {
    assert_eq!(
        THRESHOLD_POLICY_WASM_HASHES
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        vec![
            sha256_hex(vendored(THRESHOLD_V072)),
            sha256_hex(vendored(THRESHOLD_V071)),
        ],
        "THRESHOLD_POLICY_WASM_HASHES must be the v0.7.2 and v0.7.1 threshold-policy digests"
    );
}

/// `WEIGHTED_THRESHOLD_POLICY_WASM_HASHES` is exactly the v0.7.2 weighted
/// threshold policy file.
#[test]
fn weighted_threshold_policy_hashes_are_the_vendored_weighted_policy() {
    assert_eq!(
        WEIGHTED_THRESHOLD_POLICY_WASM_HASHES
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>(),
        vec![sha256_hex(vendored(WEIGHTED_THRESHOLD_V072))],
        "WEIGHTED_THRESHOLD_POLICY_WASM_HASHES must be the v0.7.2 weighted-policy digest"
    );
}

/// A dry run through the public `deploy_smart_account` reports the digest of
/// the vendored v0.7.2 multisig file, which binds the constants the wrapper
/// passes to its body.
#[tokio::test]
async fn deploy_smart_account_dry_run_reports_the_vendored_multisig_digest() {
    let args = DeploymentArgs {
        deployer: interop_deployer(),
        initial_signer: "GAAH4OT36RRCCAGKARGPN2HLHT2NOBVFHO4GUHA6CF7UKQ4MMV24WQ4N".to_owned(),
        salt: [0x5bu8; 32],
        network_passphrase: stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE.to_owned(),
        rpc_url: "http://127.0.0.1:9".to_owned(),
        timeout: Duration::from_secs(1),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: true,
        genesis_signer_scval_override: None,
    };

    let result = deploy_smart_account(args, None)
        .await
        .expect("a dry run with the embedded Wasm succeeds");

    assert_eq!(result.wasm_hash, sha256_hex(vendored(MULTISIG_V072)));
}
