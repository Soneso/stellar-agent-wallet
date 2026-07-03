//! Adversarial fixture: `verifier_wasm_drift_detection`.
//!
//! Scenario: a rule was installed with a verifier whose wasm hash was pinned
//! at install time.  At signing time the mock RPC returns a different wasm
//! hash for that verifier (simulating an on-chain WASM upgrade).
//! `verify_pinned_verifier_against_chain` MUST return
//! `SaError::VerifierHashDrift` with `wire_code = "sa.verifier_hash_drift"`.
//!
//! # Design
//!
//! 1. Write a `SaContextRuleCreated` audit entry whose
//!    `pinned_verifier_wasm_hashes_first8` is `["0101010101010101"]` (a
//!    sentinel that will not match the mock RPC's response).
//! 2. Mount a mock RPC that returns a contract instance with wasm hash
//!    `VERIFIER_ALLOWLIST[0].wasm_hash` (first-8: `"67800690..."`) — different from
//!    the audit-pinned `"0101010101010101"`.
//! 3. Call `verify_pinned_verifier_against_chain` (exposed via
//!    `managers::verifiers::test_helpers` under `--features test-helpers`).
//! 4. Assert `SaError::VerifierHashDrift` is returned AND a `SaVerifierHashDrift`
//!    audit row is emitted with matching `request_id`.
//!
//! # Implements
//!
//! Verifier-pinning drift detection: on-chain WASM hash change at sign time must be caught.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_smart_account::VERIFIER_ALLOWLIST;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::verifiers::test_helpers;
use stellar_xdr::{ContractId, Hash, ScAddress};
use uuid::Uuid;
use wiremock::{
    Mock, MockServer,
    matchers::{method, path},
};

use super::combined_rpc_responder::JsonRpcResultResponder;
use super::rpc_mock_helpers::{
    ZERO_CONTRACT_REDACTED, build_ledger_entries_contract_instance, manager_one_url,
    tmp_audit_writer,
};

// ── Address helpers ───────────────────────────────────────────────────────────

/// Verifier contract address (`[0x20; 32]`).
fn verifier_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x20u8; 32])))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Reads all non-empty JSONL lines from the audit log file.
fn read_audit_entries(log_path: &std::path::Path) -> Vec<AuditEntry> {
    let file = std::fs::File::open(log_path).expect("audit log must be readable");
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(trimmed) {
            entries.push(entry);
        }
    }
    entries
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// When the pinned verifier wasm hash in the audit log does not match the live
/// on-chain hash returned by the mock RPC, `verify_pinned_verifier_against_chain`
/// returns `SaError::VerifierHashDrift` and emits a `SaVerifierHashDrift` audit row.
#[tokio::test]
async fn verifier_wasm_hash_drift_detected_and_audit_row_emitted() {
    let verifier = verifier_addr();

    // ── Step 1: Set up a mock RPC that serves VERIFIER_ALLOWLIST[0].wasm_hash ──
    // first-8 hex: "67800690..."
    let live_wasm_hash = VERIFIER_ALLOWLIST[0].wasm_hash;
    let ledger_entries = build_ledger_entries_contract_instance(&verifier, live_wasm_hash);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(ledger_entries))
        .mount(&server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_one_url(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    // ── Step 2: Write a fake SaContextRuleCreated row with a DIFFERENT pinned hash
    // Pinned sentinel: "0101010101010101" — will not match live_wasm_hash's first-8.
    let fake_pinned_first8 = "0101010101010101".to_owned();
    let rule_id: u32 = 1;
    let request_id = Uuid::new_v4().to_string();

    let fake_entry = AuditEntry::new_sa_context_rule_created(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        0,
        None,
        "stellar:testnet",
        &request_id,
        vec![fake_pinned_first8.clone()],
        vec![],
        false,
        false,
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(fake_entry)
            .expect("write_entry must succeed");
    }

    // ── Step 3: Call verify_pinned_verifier_against_chain ────────────────────
    let mut cache: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();

    let result = test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier.clone(),
        rule_id,
        ZERO_CONTRACT_REDACTED,
        &request_id,
        &mut cache,
    )
    .await;

    // ── Step 4: Assertions ────────────────────────────────────────────────────
    assert!(
        matches!(result, Err(SaError::VerifierHashDrift { .. })),
        "wasm-hash drift must return SaError::VerifierHashDrift; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.verifier_hash_drift",
        "wire_code must be 'sa.verifier_hash_drift'"
    );

    // The SaVerifierHashDrift audit row must be emitted.
    let entries = read_audit_entries(&audit_log_path);
    let drift_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaVerifierHashDrift { rule_id: rid, .. } if *rid == rule_id
        )
    });
    assert!(
        drift_row.is_some(),
        "SaVerifierHashDrift audit row must be emitted after drift detection"
    );

    // Verify the drift row carries the same request_id.
    let drift_entry = drift_row.unwrap();
    assert_eq!(
        drift_entry.request_id, request_id,
        "SaVerifierHashDrift row must carry the same request_id as the verify call"
    );
}
