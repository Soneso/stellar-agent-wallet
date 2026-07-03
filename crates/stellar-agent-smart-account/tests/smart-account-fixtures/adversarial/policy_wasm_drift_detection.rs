//! Adversarial fixture: `policy_wasm_drift_detection`.
//!
//! Scenario: a rule was installed with a policy whose wasm hash was pinned
//! at install time.  At signing time the mock RPC returns a different wasm
//! hash for that policy (simulating an on-chain WASM upgrade).
//! `verify_pinned_policy_against_chain` MUST return
//! `SaError::PolicyHashDrift` with `wire_code = "sa.policy_hash_drift"`.
//!
//! # Design
//!
//! 1. Write a `SaContextRuleCreated` audit entry whose
//!    `pinned_policy_wasm_hashes_first8` is `["0202020202020202"]` (a
//!    sentinel that will not match the mock RPC's response).
//! 2. Mount a mock RPC that returns a contract instance with wasm hash
//!    `THRESHOLD_POLICY_WASM_HASHES[0]` — different from the audit-pinned
//!    sentinel.
//! 3. Call `verify_pinned_policy_against_chain` (exposed via
//!    `managers::verifiers::test_helpers` under `--features test-helpers`).
//! 4. Assert `SaError::PolicyHashDrift` is returned AND a `SaPolicyHashDrift`
//!    audit row is emitted with matching `request_id`.
//!
//! Verifies the verifier-pinning requirement: on-chain WASM hash drift is
//! detected at signing time and returned as `SaError::PolicyHashDrift`.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::verifiers::test_helpers;
use stellar_agent_smart_account::signers::policy_identification::THRESHOLD_POLICY_WASM_HASHES;
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

/// Policy contract address (`[0x21; 32]`).
fn policy_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x21u8; 32])))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/// When the pinned policy wasm hash in the audit log does not match the live
/// on-chain hash returned by the mock RPC, `verify_pinned_policy_against_chain`
/// returns `SaError::PolicyHashDrift` and emits a `SaPolicyHashDrift` audit row.
///
/// Verifies that a pinned policy WASM hash mismatch is detected at sign time.
#[tokio::test]
async fn policy_wasm_hash_drift_detected_and_audit_row_emitted() {
    let policy = policy_addr();

    // ── Step 1: Mock RPC serves THRESHOLD_POLICY_WASM_HASHES[0] ─────────────
    let live_wasm_hash = THRESHOLD_POLICY_WASM_HASHES[0];
    let ledger_entries = build_ledger_entries_contract_instance(&policy, live_wasm_hash);

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

    // ── Step 2: Write fake SaContextRuleCreated with a DIFFERENT pinned policy hash
    let fake_pinned_first8 = "0202020202020202".to_owned();
    let rule_id: u32 = 1;
    let request_id = Uuid::new_v4().to_string();

    let fake_entry = AuditEntry::new_sa_context_rule_created(
        ZERO_CONTRACT_REDACTED,
        rule_id,
        "default",
        1,
        1,
        None,
        "stellar:testnet",
        &request_id,
        vec![],
        vec![fake_pinned_first8.clone()],
        false,
        false,
    );
    {
        let mut writer = audit_writer.lock().expect("audit writer poisoned");
        writer
            .write_entry(fake_entry)
            .expect("write_entry must succeed");
    }

    // ── Step 3: Call verify_pinned_policy_against_chain ──────────────────────
    let mut cache: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();

    let result = test_helpers::verify_pinned_policy_against_chain(
        &manager,
        policy.clone(),
        rule_id,
        ZERO_CONTRACT_REDACTED,
        &request_id,
        &mut cache,
    )
    .await;

    // ── Step 4: Assertions ────────────────────────────────────────────────────
    assert!(
        matches!(result, Err(SaError::PolicyHashDrift { .. })),
        "wasm-hash drift must return SaError::PolicyHashDrift; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "sa.policy_hash_drift",
        "wire_code must be 'sa.policy_hash_drift'"
    );

    // The SaPolicyHashDrift audit row must be emitted.
    let entries = read_audit_entries(&audit_log_path);
    let drift_row = entries.iter().find(|e| {
        matches!(
            &e.event_kind,
            EventKind::SaPolicyHashDrift { rule_id: rid, .. } if *rid == rule_id
        )
    });
    assert!(
        drift_row.is_some(),
        "SaPolicyHashDrift audit row must be emitted after drift detection"
    );

    let drift_entry = drift_row.unwrap();
    assert_eq!(
        drift_entry.request_id, request_id,
        "SaPolicyHashDrift row must carry the same request_id as the verify call"
    );
}
