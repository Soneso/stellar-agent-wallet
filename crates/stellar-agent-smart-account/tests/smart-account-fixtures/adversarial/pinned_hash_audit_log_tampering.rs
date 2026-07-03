//! Adversarial fixture: pinned-hash audit-log tampering is detected first.
//!
//! A `SaContextRuleCreated` row is tampered after a later row has already
//! committed to its hash-chain link. Reading pinned hashes must surface
//! `SaError::AuditLog` before any verifier/policy pin is trusted.
//!
//! # Verifier-pinning invariant
//!
//! Pinned hashes are derived from the audit log; a tampered log must cause
//! `SaError::AuditLog` before any verifier pin is trusted.

#![cfg(feature = "test-helpers")]

use std::io::Write as _;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::verifiers::test_helpers;
use uuid::Uuid;

use super::rpc_mock_helpers::{ZERO_CONTRACT_REDACTED, manager_one_url, tmp_audit_writer};

#[test]
fn pinned_hash_tampering_returns_audit_log_error_before_pin_extraction() {
    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let rule_id = 1;

    let created = AuditEntry::new_sa_context_rule_created(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        Uuid::new_v4().to_string(),
        vec!["0101010101010101".to_owned()],
        vec![],
        false,
        false,
    );
    let witness = AuditEntry::new_sa_context_rule_created(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        Uuid::new_v4().to_string(),
        vec!["0101010101010101".to_owned()],
        vec![],
        false,
        false,
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(created)
            .expect("created row write must succeed");
        writer
            .write_entry(witness)
            .expect("witness row write must succeed");
    }

    let original = std::fs::read_to_string(&audit_log_path).expect("audit log must be readable");
    let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
    assert_eq!(
        lines.len(),
        2,
        "fixture writes exactly created + witness rows"
    );
    let tampered = lines[0].replacen("0101010101010101", "ffffffffffffffff", 1);
    assert_ne!(lines[0], tampered, "tamper must mutate row 1");
    lines[0] = tampered;
    let rewritten = format!("{}\n", lines.join("\n"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&audit_log_path)
        .expect("audit log must be writable");
    file.write_all(rewritten.as_bytes())
        .expect("tampered log write must succeed");
    file.flush().expect("flush must succeed");

    let manager = manager_one_url("http://127.0.0.1:1", audit_writer, audit_log_path.clone());
    let result =
        test_helpers::read_pinned_hashes_for_rule(&manager, rule_id, ZERO_CONTRACT_REDACTED);

    assert!(
        matches!(result, Err(SaError::AuditLog(_))),
        "tampered pinned hashes must return SaError::AuditLog; got {result:?}"
    );
    assert_eq!(result.unwrap_err().wire_code(), "sa.audit_log");
}
