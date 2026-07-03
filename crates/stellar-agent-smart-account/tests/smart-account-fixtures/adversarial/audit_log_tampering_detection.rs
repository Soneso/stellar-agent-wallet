//! Adversarial fixture: audit log tampering detection.
//!
//! Synthesises an audit log with the most-recent `SaSignerSetBaselined` row's
//! payload tampered (e.g. `resulting_threshold` flipped) WITHOUT regenerating the
//! hash chain. Asserts that `verify_signer_set_against_chain` returns
//! `AuditLogIntegrityError` BEFORE `read_audit_log_baseline` can return a
//! poisoned `ObservedSignerSet`.
//!
//! The audit log is a load-bearing substrate: the path MUST NOT swallow the
//! integrity error and fall through to the on-chain comparison step.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::signer_set::{BaselineReason, ObservedSignerSet, SignerPubkey};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::RedactedStrkey;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_xdr::{ContractId, Hash, ScAddress};
use tempfile::TempDir;
use uuid::Uuid;

// ── Shared helpers ────────────────────────────────────────────────────────────

fn tmp_audit_writer() -> (Arc<Mutex<AuditWriter>>, PathBuf, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir must succeed");
    let path = dir.path().join("audit.jsonl");
    let writer = AuditWriter::open(path.clone(), None).expect("AuditWriter::open must succeed");
    (Arc::new(Mutex::new(writer)), path, dir)
}

fn manager_with_url(
    rpc_url: &str,
    audit_writer: Arc<Mutex<AuditWriter>>,
    audit_log_path: PathBuf,
) -> SignersManager {
    let config = SignersManagerConfig::new(
        rpc_url.to_owned(),
        rpc_url.to_owned(),
        audit_writer,
        audit_log_path,
        "Test SDF Network ; September 2015".to_owned(),
        "test-profile".to_owned(),
        Duration::from_secs(5),
        "stellar:testnet".to_owned(),
    );
    SignersManager::new(config).expect("SignersManager::new must succeed")
}

fn zero_sc_address() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0u8; 32])))
}

fn signer_set_1_of_1() -> ObservedSignerSet {
    ObservedSignerSet {
        signer_count: 1,
        threshold: 1,
        signer_ids: vec![0],
        signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [1u8; 32] }],
    }
}

// ── Test: tampered payload causes integrity error ─────────────────────────────

/// Write a valid `SaSignerSetBaselined` audit entry, then directly corrupt
/// the JSONL file by flipping the `observed_threshold` field from 1 to 99
/// (without re-computing the hash chain). Assert that
/// `verify_signer_set_against_chain` returns `SaError::AuditLog(...)` wrapping
/// an `AuditLogIntegrityError`, not `SignerSetMissingBaseline` or any other
/// variant.
///
/// This validates the audit-log integrity gate is active on the divergence-check
/// code path (audit-log integrity risk).
#[tokio::test]
async fn tampered_payload_returns_audit_log_integrity_error() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let observed = signer_set_1_of_1();

    // Step 1: Write row 1 — the legitimate baseline entry.
    {
        let prev_chain_tip = {
            let writer = audit_writer.lock().unwrap();
            writer.current_chain_tip()
        };
        let entry = AuditEntry::new_sa_signer_set_baselined(
            1,
            &observed,
            vec!["0101010101010101".to_owned()],
            0,
            BaselineReason::first_observation(),
            prev_chain_tip,
            RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
            "stellar:testnet",
            Uuid::new_v4().to_string(),
        );
        audit_writer
            .lock()
            .unwrap()
            .write_entry(entry)
            .expect("legitimate baseline write must succeed");
    }

    // Step 1b: Write row 2 — a witness entry whose `previous_entry_hash`
    // commits to the ORIGINAL hash of row 1.  Without this second row the
    // single-row chain has no downstream commitment to the body of row 1, so
    // body tampering is undetectable by the chain-link check alone.  Row 2's
    // `previous_entry_hash` stores SHA-256(row1_canonical_body ‖ prev_bytes),
    // so any modification to row 1's body will cause a chain-hash mismatch
    // when the reader recomputes that hash and compares it against what row 2
    // stores.
    {
        // Use the writer to emit the second entry — it automatically sets
        // `previous_entry_hash` to the current chain tip (= hash of row 1).
        let prev_chain_tip = {
            let writer = audit_writer.lock().unwrap();
            writer.current_chain_tip()
        };
        let witness = AuditEntry::new_sa_signer_set_baselined(
            1,
            &observed,
            vec!["0101010101010101".to_owned()],
            0,
            BaselineReason::first_observation(),
            prev_chain_tip,
            RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
            "stellar:testnet",
            Uuid::new_v4().to_string(),
        );
        audit_writer
            .lock()
            .unwrap()
            .write_entry(witness)
            .expect("witness entry write must succeed");
    }

    // Step 2: Corrupt row 1's payload by flipping `observed_threshold` from 1
    // to 99 WITHOUT regenerating the hash chain.  The reader will detect the
    // mismatch when it recomputes `H(row1_body)` and finds it does not equal
    // `row2.previous_entry_hash`.
    {
        let contents =
            std::fs::read_to_string(&audit_log_path).expect("audit log JSONL must be readable");
        // Replace only the FIRST occurrence (row 1) by splitting into lines.
        let original_lines: Vec<&str> = contents.lines().collect();
        assert!(
            original_lines.len() >= 2,
            "log must have at least 2 rows after witness write"
        );
        let corrupted_row1 =
            original_lines[0].replacen("\"observed_threshold\":1", "\"observed_threshold\":99", 1);
        assert_ne!(
            original_lines[0],
            corrupted_row1.as_str(),
            "tamper replacement must change row 1 content"
        );
        // Reassemble: corrupted row 1 + all remaining rows + trailing newline.
        let remaining = original_lines[1..].join("\n");
        let reassembled = format!("{corrupted_row1}\n{remaining}\n");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&audit_log_path)
            .expect("must be able to open audit log for write");
        file.write_all(reassembled.as_bytes())
            .expect("corrupted content write must succeed");
        file.flush().expect("flush must succeed");
    }

    // Step 3: Construct a fresh manager pointing at the same corrupted log.
    // Use an unreachable RPC URL — the integrity check fires at audit-log
    // read (Step 1 of verify_signer_set_against_chain) BEFORE any RPC call.
    let manager = manager_with_url(
        "http://127.0.0.1:1",
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let result = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(stellar_agent_core::constants::SIMULATE_SENTINEL_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    // The tampered row's hash chain check must fire BEFORE returning
    // a poisoned ObservedSignerSet to the caller.
    assert!(
        matches!(result, Err(SaError::AuditLog(_))),
        "tampered audit log must return SaError::AuditLog, not {:?}",
        result
    );

    let err = result.unwrap_err();
    assert_eq!(
        err.wire_code(),
        "sa.audit_log",
        "wire_code must be 'sa.audit_log'; got: '{}'",
        err.wire_code()
    );
}

/// Tear-off (truncated last line) of the audit log JSONL is detected as
/// an integrity error, not silently treated as "no baseline".
///
/// A torn row, parse error, or chain-hash mismatch propagates
/// `AuditLogIntegrityError` — MUST NOT reinterpret as `Ok(None)`.
#[tokio::test]
async fn torn_tail_returns_integrity_error_not_none() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let observed = signer_set_1_of_1();

    // Write a legitimate baseline entry.
    {
        let prev_tip = audit_writer.lock().unwrap().current_chain_tip();
        let entry = AuditEntry::new_sa_signer_set_baselined(
            1,
            &observed,
            vec!["0101010101010101".to_owned()],
            0,
            BaselineReason::first_observation(),
            prev_tip,
            RedactedStrkey::from_already_redacted("CAAAA...ABSC4"),
            "stellar:testnet",
            Uuid::new_v4().to_string(),
        );
        audit_writer
            .lock()
            .unwrap()
            .write_entry(entry)
            .expect("baseline write must succeed");
    }

    // Truncate the last 10 bytes of the JSONL file to simulate a torn tail.
    {
        let metadata = std::fs::metadata(&audit_log_path).expect("metadata must succeed");
        let len = metadata.len();
        let new_len = len.saturating_sub(10);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&audit_log_path)
            .expect("must open file for truncation");
        file.set_len(new_len).expect("truncation must succeed");
    }

    let manager = manager_with_url(
        "http://127.0.0.1:1",
        Arc::clone(&audit_writer),
        audit_log_path,
    );

    let result = manager
        .verify_signer_set_against_chain(
            zero_sc_address(),
            1,
            Some(stellar_agent_core::constants::SIMULATE_SENTINEL_G),
            Uuid::new_v4().to_string(),
        )
        .await;

    // A torn tail is either a parse error or a chain-hash mismatch.
    // Both map to SaError::AuditLog, not SignerSetMissingBaseline.
    assert!(
        matches!(result, Err(SaError::AuditLog(_))),
        "torn tail must return SaError::AuditLog, not {:?}",
        result
    );
}
