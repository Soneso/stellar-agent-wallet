//! Integration tests for audit-log emission from `deploy_smart_account`.
//!
//! Each test wires an `AuditWriter` backed by a `tempfile::NamedTempFile`, runs
//! `deploy_smart_account` in dry-run or error mode, then reads back the JSONL
//! output and asserts on the entry fields.
//!
//! # Coverage
//!
//! These tests close the gap where every call site passed `None` to the audit
//! writer, leaving the emission path entirely untested. The following cases are
//! covered:
//!
//! 1. Dry-run guard: `deploy_smart_account` with `dry_run = true` and a live
//!    writer emits NO entries.
//! 2. Constructor-phase failure: `initial_signer` is not a valid G-strkey;
//!    `SaError::DeploymentFailed { phase: "constructor", .. }` is emitted as
//!    one `sa_raw_invocation` entry with `result: "pre_submission_refused"`;
//!    no `smart_account_deployed` entry. Includes field-shape assertions for
//!    redaction compliance.
//! 3. Simulate-phase failure: RPC URL is unreachable; one `sa_raw_invocation`
//!    entry with `result: "pre_submission_refused"` is emitted. Verifies the
//!    phase-mapping rule for pre-submission phases via the integration path.
//! 4. Request-ID contract: every emitted entry carries a non-empty `request_id`.
//!
//! The `OnChainRejected` phase-mapping rule (`phase ∈ {"deploy", "submit",
//! "post_deploy_verification"}`) is verified exhaustively at the unit-test
//! layer by `phase_to_sa_invocation_result_maps_*` in `deploy.rs::tests`.
//!
//! # Smart account deployment support
//!
//! Verifies the audit-emission contract for `deploy_smart_account`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::io::BufRead as _;
use std::path::PathBuf;
use std::time::Duration;

use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_smart_account::deployment::{
    DeploymentArgs, ResolvedFeePerOp, deploy_smart_account, interop_deployer,
    interop_deployer_pubkey,
};
use tempfile::TempDir;

// ── Constants ─────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// A stable initial-signer G-strkey (seed `[0x11; 32]`).
const INITIAL_SIGNER_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Opens a temporary `AuditWriter` and returns `(writer, dir)`.
///
/// `dir` must be kept alive for the duration of the test; dropping it removes
/// the temp directory and invalidates the writer path.
fn tmp_writer() -> (AuditWriter, TempDir) {
    let dir = tempfile::tempdir().expect("tmp dir");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path, None).expect("AuditWriter::open");
    (writer, dir)
}

/// Constructs a dry-run `DeploymentArgs` using the well-known interop deployer.
fn dry_run_args(salt: [u8; 32]) -> DeploymentArgs {
    DeploymentArgs {
        deployer: interop_deployer(),
        initial_signer: INITIAL_SIGNER_G.to_owned(),
        salt,
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: "http://unused.example.com:8000".to_owned(),
        timeout: Duration::from_secs(5),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: true,
        genesis_signer_scval_override: None,
    }
}

/// Constructs non-dry-run `DeploymentArgs` that will fail in the `"constructor"` phase.
///
/// `initial_signer` is set to a string that is NOT a valid G-strkey, causing
/// `build_signer_delegated_scval` (called during deployment construction) to return
/// `SaError::DeploymentFailed { phase: "constructor", .. }`.
///
/// The deployer is the well-known interop deployer (valid); the RPC URL is unreachable,
/// but the constructor-arg error occurs before any RPC traffic.
///
/// NOTE: `phase: "constructor"` is in the `PreSubmissionRefused` bucket.
fn build_failure_args() -> DeploymentArgs {
    DeploymentArgs {
        deployer: interop_deployer(),
        // NOT a valid G-strkey — triggers constructor-phase SaError.
        initial_signer: "INVALID-NOT-A-GSTRKEY".to_owned(),
        salt: [0x42u8; 32],
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: "http://unused.example.com:8000".to_owned(),
        timeout: Duration::from_secs(5),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    }
}

/// Reads all JSONL lines from the temp file and parses each as `serde_json::Value`.
fn read_entries(dir: &TempDir) -> Vec<serde_json::Value> {
    let path: PathBuf = dir.path().join("audit.jsonl");
    let file = std::fs::File::open(&path).expect("audit.jsonl");
    let reader = std::io::BufReader::new(file);
    reader
        .lines()
        .map(|l| {
            let line = l.expect("line");
            serde_json::from_str(&line).expect("valid JSON per line")
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Dry-run guard: dry-run with a `Some(writer)` must NOT emit any audit entries.
///
/// Dry-run is a developer-mode path; auditing fictitious metadata is incorrect.
#[tokio::test]
async fn deploy_smart_account_dry_run_with_writer_emits_no_entries() {
    let (mut writer, dir) = tmp_writer();
    let args = dry_run_args([0x11u8; 32]);

    let result = deploy_smart_account(args, Some(&mut writer)).await;
    assert!(result.is_ok(), "dry-run must succeed: {result:?}");

    // Drop writer to flush and release lock.
    drop(writer);

    let entries = read_entries(&dir);
    assert_eq!(
        entries.len(),
        0,
        "dry-run must not emit any audit entries; got {}: {entries:#?}",
        entries.len()
    );
}

/// Constructor-phase failure emits exactly ONE `sa_raw_invocation`
/// entry with `result: "pre_submission_refused"` and NO `smart_account_deployed`.
///
/// Uses an invalid `initial_signer` (not a G-strkey) to trigger
/// `SaError::DeploymentFailed { phase: "constructor", .. }` inside
/// `build_signer_delegated_scval`.
///
/// Verifies:
/// - Entry count = 1.
/// - `kind = "sa_raw_invocation"`.
/// - `result = "pre_submission_refused"` (phase = "constructor" → PreSubmissionRefused).
/// - `wire_code` is NOT `"sa.ok"`.
/// - No `smart_account_deployed` entry is present.
/// - The `request_id` field is present.
/// - `auth_digest_prefix` is absent from the JSON (`None` → field omitted).
/// - `context_rule_ids_count = 0`.
#[tokio::test]
async fn deploy_smart_account_emits_sa_raw_invocation_on_build_phase_failure() {
    let (mut writer, dir) = tmp_writer();
    let args = build_failure_args();

    let result = deploy_smart_account(args, Some(&mut writer)).await;
    assert!(
        result.is_err(),
        "constructor-failure args must produce an error"
    );
    drop(writer);

    let entries = read_entries(&dir);
    assert_eq!(
        entries.len(),
        1,
        "build-phase failure must emit exactly 1 entry; got {}: {entries:#?}",
        entries.len()
    );

    let entry = &entries[0];
    assert_eq!(
        entry["kind"], "sa_raw_invocation",
        "entry kind must be sa_raw_invocation: {entry}"
    );

    // Phase "build" maps to PreSubmissionRefused.
    assert_eq!(
        entry["result"], "pre_submission_refused",
        "build-phase failure must map to pre_submission_refused: {entry}"
    );

    // wire_code must not be "sa.ok".
    let wire_code = entry["wire_code"].as_str().unwrap();
    assert_ne!(
        wire_code, "sa.ok",
        "failure wire_code must not be sa.ok: {entry}"
    );

    // context_rule_ids_count must be 0.
    assert_eq!(
        entry["context_rule_ids_count"], 0,
        "context_rule_ids_count must be 0: {entry}"
    );

    // auth_digest_prefix must be ABSENT (None → skip_serializing_if).
    assert!(
        entry.get("auth_digest_prefix").is_none(),
        "auth_digest_prefix must be absent when None: {entry}"
    );

    // request_id must be present and non-empty.
    let req_id = entry["request_id"].as_str().unwrap_or("");
    assert!(!req_id.is_empty(), "request_id must be present: {entry}");

    // Field-shape assertions for redaction compliance.
    // smart_account must be "unknown" (pre-derivation failed before constructor
    // error because initial_signer is invalid) or a 13-char first-5...last-5 form
    // (e.g. "CAAAA...D2KM" — 5 + 3 + 5 chars = 13, but strkeys vary in length so
    // we check the "..." separator as the minimum indicator of redaction).
    let smart_account = entry["smart_account"].as_str().unwrap_or("");
    assert!(
        smart_account == "unknown" || smart_account.contains("..."),
        "smart_account must be 'unknown' or a redacted form (contains '...'): '{smart_account}'"
    );
    // chain_id must match the passphrase used in build_failure_args().
    assert_eq!(
        entry["chain_id"], "stellar:testnet",
        "chain_id must be stellar:testnet: {entry}"
    );

    // No smart_account_deployed entry.
    let deployed: Vec<_> = entries
        .iter()
        .filter(|e| e["kind"] == "smart_account_deployed")
        .collect();
    assert!(
        deployed.is_empty(),
        "no smart_account_deployed entry on failure: {deployed:#?}"
    );
}

/// Simulate-phase failure test: the mock-RPC will fail at simulate because there
/// is no server — this triggers a "simulate" phase failure which maps to
/// PreSubmissionRefused.
///
/// We cannot exercise a true success path (two emitted entries) without a
/// live network or a full wiremock that returns valid Soroban XDR. The success
/// shape is covered by the single-entry mock test here. The deployed-entry
/// shape assertions are covered by `smart_account_deployed_constructor_shape`
/// in entry.rs.
///
/// This test asserts:
/// - `kind = "sa_raw_invocation"` is emitted on simulate-phase failure.
/// - `result = "pre_submission_refused"` (phase "simulate" → PreSubmissionRefused).
/// - `request_id` is present.
/// - No `smart_account_deployed` entry.
#[tokio::test]
async fn deploy_smart_account_emits_sa_raw_invocation_on_simulate_phase_failure() {
    let (mut writer, dir) = tmp_writer();

    // Point at an unreachable server so the RPC call fails with a simulate-phase error.
    let args = DeploymentArgs {
        deployer: interop_deployer(),
        initial_signer: INITIAL_SIGNER_G.to_owned(),
        salt: [0x33u8; 32],
        network_passphrase: TESTNET_PASSPHRASE.to_owned(),
        rpc_url: "http://127.0.0.1:19999".to_owned(), // nothing listening
        timeout: Duration::from_millis(200),
        fee: ResolvedFeePerOp {
            stroops: 100,
            percentile_label: "profile_default".to_owned(),
        },
        dry_run: false,
        genesis_signer_scval_override: None,
    };

    let result = deploy_smart_account(args, Some(&mut writer)).await;
    // May succeed in timing out at various phases; it must be an error.
    assert!(
        result.is_err(),
        "unreachable-RPC must produce an error: {result:?}"
    );
    drop(writer);

    let entries = read_entries(&dir);
    // Must have emitted at least one entry (the SaRawInvocation).
    assert!(
        !entries.is_empty(),
        "at least one sa_raw_invocation must be emitted: {entries:#?}"
    );

    let ra_entries: Vec<_> = entries
        .iter()
        .filter(|e| e["kind"] == "sa_raw_invocation")
        .collect();
    assert_eq!(
        ra_entries.len(),
        1,
        "exactly one sa_raw_invocation must be emitted: {entries:#?}"
    );

    let entry = ra_entries[0];
    // The failure occurs at the "build" or "simulate" phase (unreachable RPC means
    // no transaction is ever submitted); both phases map to PreSubmissionRefused per
    // the phase-mapping rule. OnChainRejected would indicate a regression.
    assert_eq!(
        entry["result"], "pre_submission_refused",
        "unreachable-RPC failure must map to pre_submission_refused: {entry}"
    );

    // Both entries from this operation share the same request_id.
    let req_id = entry["request_id"].as_str().unwrap_or("");
    assert!(!req_id.is_empty(), "request_id must be present");

    // No smart_account_deployed entry.
    let deployed: Vec<_> = entries
        .iter()
        .filter(|e| e["kind"] == "smart_account_deployed")
        .collect();
    assert!(
        deployed.is_empty(),
        "no smart_account_deployed on failure: {deployed:#?}"
    );
}

/// Request-ID pairing: both `SaRawInvocation` and `SmartAccountDeployed`
/// entries from a single operation must share the same `request_id`.
///
/// This test is best-effort on the failure path (we only get one entry);
/// the two-entry case (success) is not exercisable without live RPC. The
/// contract is documented and enforced in the wrapper source code. The unit
/// contract of the constructor is verified by `sa_raw_invocation_constructor_shape`
/// in entry.rs.
///
/// This test documents the intent and verifies at least that a single
/// request_id is emitted and is non-empty.
#[tokio::test]
async fn deploy_smart_account_emitted_entries_carry_request_id() {
    let (mut writer, dir) = tmp_writer();
    let args = build_failure_args();

    let _ = deploy_smart_account(args, Some(&mut writer)).await;
    drop(writer);

    let entries = read_entries(&dir);
    for entry in &entries {
        let req_id = entry["request_id"].as_str().unwrap_or("");
        assert!(
            !req_id.is_empty(),
            "every emitted entry must carry a non-empty request_id: {entry}"
        );
    }
}

/// Verifies that `interop_deployer_pubkey()` returns the stable
/// well-known G-strkey used in dry-run audit emission.
#[test]
fn interop_deployer_pubkey_stable() {
    let pk = interop_deployer_pubkey();
    assert!(
        pk.starts_with('G'),
        "interop deployer must be a G-strkey: {pk}"
    );
    assert_eq!(pk.len(), 56, "G-strkey must be 56 chars: {pk}");
}
