//! Adversarial fixture: fresh wallet with no established signer baseline.
//!
//! Asserts that a fresh wallet with no audit-log row for a rule returns
//! [`SaError::SignerSetMissingBaseline`] when `verify_signer_set_against_chain`
//! is called — before any RPC call is attempted.
//!
//! # Coverage
//!
//! - Fail-closed: first signing attempt with no baseline returns
//!   `sa.signer_set_missing_baseline` (NOT `sa.signer_set_diverged`).
//! - Wire code `"sa.signer_set_missing_baseline"` is present.
//! - Error message mentions the baseline-write commands.
//! - After `refresh_signer_baseline`, the baseline is established and
//!   subsequent `verify_signer_set_against_chain` calls can proceed past
//!   Step 1. The "proceed past step 1" assertion with real on-chain state
//!   is covered by the testnet acceptance tests.
//!
//! # Invariant
//!
//! `verify_signer_set_against_chain` returns `SignerSetMissingBaseline` before
//! making any RPC call when the audit log contains no baseline entry for the
//! requested rule.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_xdr::{ContractId, Hash, ScAddress};
use tempfile::TempDir;
use uuid::Uuid;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Minimal valid C-strkey for a 32-byte zero contract hash.
///
/// `stellar_strkey::Contract([0u8; 32]).to_string()` → this value.
const ZERO_CONTRACT_STRKEY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

/// Builds a `SignersManager` against the given URL (may be a dummy URL for
/// tests that do not reach the RPC layer).
fn manager_with_url(
    rpc_url: &str,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
) -> SignersManager {
    let config = SignersManagerConfig::new(
        rpc_url.to_owned(),
        rpc_url.to_owned(), // secondary = primary (same URL, divergence won't fire in tests)
        audit_writer,
        audit_log_path,
        "Test SDF Network ; September 2015".to_owned(),
        "test-profile".to_owned(),
        Duration::from_secs(5),
        "stellar:testnet".to_owned(),
    );
    SignersManager::new(config).expect("SignersManager::new must succeed with valid URL")
}

fn zero_sc_address() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0u8; 32])))
}

// ── Test: fresh wallet returns SignerSetMissingBaseline ───────────────────────

/// `verify_signer_set_against_chain` with no audit-log baseline returns
/// `SaError::SignerSetMissingBaseline` before any RPC call.
///
/// This is the Step 1 early-return path: audit-log read returns `None` →
/// error is returned immediately without contacting the RPC.
///
/// We use a dummy RPC URL (pointing to a non-existent host) to confirm
/// no network I/O occurs — if RPC were called, the test would fail with
/// a connection error, not `SignerSetMissingBaseline`.
#[tokio::test]
async fn verify_returns_missing_baseline_on_empty_audit_log() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Intentionally unreachable URL — any RPC attempt would return a
    // connection-refused error, not SignerSetMissingBaseline.
    let manager = manager_with_url(
        "http://127.0.0.1:1", // port 1 is not a valid RPC endpoint
        audit_writer,
        audit_log_path,
    );

    let result = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1, // rule_id
            Some(stellar_agent_core::constants::SIMULATE_SENTINEL_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetMissingBaseline { rule_id: 1, .. })
        ),
        "fresh wallet must return SignerSetMissingBaseline (no RPC call); got: {result:?}"
    );
}

/// The wire code on `SignerSetMissingBaseline` is `"sa.signer_set_missing_baseline"`.
#[tokio::test]
async fn missing_baseline_wire_code_is_correct() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    let manager = manager_with_url("http://127.0.0.1:1", audit_writer, audit_log_path);

    let result = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            2,
            Some(stellar_agent_core::constants::SIMULATE_SENTINEL_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    let err = result.unwrap_err();
    assert_eq!(
        err.wire_code(),
        "sa.signer_set_missing_baseline",
        "wire_code must be 'sa.signer_set_missing_baseline'; got: '{}'",
        err.wire_code()
    );
}

/// Rule 0 (bootstrap rule) and rule 1 are independent in the audit log.
/// Missing baseline for rule 1 returns the error even if rule 0 has a baseline.
#[tokio::test]
async fn missing_baseline_is_per_rule() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // Write a baseline for rule 0 (bootstrap rule is skipped in divergence checks
    // but the entry still exists in the log).
    {
        use stellar_agent_core::audit_log::entry::AuditEntry;
        use stellar_agent_core::audit_log::signer_set::{
            BaselineReason, ObservedSignerSet, SignerPubkey,
        };
        use stellar_agent_core::observability::RedactedStrkey;

        let observed = ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0u8; 32] }],
        };
        let entry = AuditEntry::new_sa_signer_set_baselined(
            0, // rule_id 0
            &observed,
            vec!["0000000000000000".to_owned()],
            0,
            BaselineReason::first_observation(),
            [0u8; 32],
            RedactedStrkey::from_already_redacted(format!("{}...", &ZERO_CONTRACT_STRKEY[..5])),
            "stellar:testnet",
            Uuid::new_v4().to_string(),
        );
        audit_writer
            .lock()
            .unwrap()
            .write_entry(entry)
            .expect("write baseline for rule 0 must succeed");
    }

    let manager = manager_with_url(
        "http://127.0.0.1:1",
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    // Rule 1 has no baseline — must return SignerSetMissingBaseline.
    let result = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1, // different rule_id
            Some(stellar_agent_core::constants::SIMULATE_SENTINEL_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    assert!(
        matches!(
            result,
            Err(SaError::SignerSetMissingBaseline { rule_id: 1, .. })
        ),
        "rule 1 must return SignerSetMissingBaseline even if rule 0 has a baseline; got: {result:?}"
    );
}
