//! Adversarial fixture: `verifier_drift_rpc_suppression`.
//!
//! Scenario: primary RPC returns the pinned verifier wasm hash (appearing
//! unchanged); secondary RPC returns a DIFFERENT hash (the actual upgraded
//! wasm).  Two-RPC consultation fires `NetworkRpcDivergence` BEFORE the
//! drift comparison, preventing a compromised primary from masking an upgrade.
//!
//! # Design
//!
//! 1. Write a `SaContextRuleCreated` audit entry with pinned hash `"67800690..."`
//!    (i.e., `VERIFIER_ALLOWLIST[0].wasm_hash` first-8).
//! 2. Primary RPC serves `VERIFIER_ALLOWLIST[0].wasm_hash` (matches pin).
//! 3. Secondary RPC serves `UNKNOWN_WASM_HASH` (does NOT match primary).
//! 4. Call `verify_pinned_verifier_against_chain`.
//! 5. Assert `SaError::NetworkRpcDivergence` is returned — divergence fires
//!    BEFORE the drift check, ensuring a compromised primary cannot suppress an upgrade.

#![cfg(feature = "test-helpers")]

use std::collections::HashMap;
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
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
    UNKNOWN_WASM_HASH, ZERO_CONTRACT_REDACTED, build_ledger_entries_contract_instance,
    manager_two_url, tmp_audit_writer,
};

// ── Address helpers ───────────────────────────────────────────────────────────

/// Verifier contract address (`[0x22; 32]`).
fn verifier_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x22u8; 32])))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Primary RPC returns the pinned hash (no drift visible); secondary returns a
/// different hash (simulating an upgrade visible only to the secondary).
/// Two-RPC consultation fires `NetworkRpcDivergence` BEFORE the drift check,
/// ensuring a compromised primary cannot suppress upgrade detection.
#[tokio::test]
async fn rpc_suppression_fires_divergence_before_drift_check() {
    let verifier = verifier_addr();

    // Primary: serves VERIFIER_ALLOWLIST[0].wasm_hash (matches the pinned hash).
    let primary_entries =
        build_ledger_entries_contract_instance(&verifier, VERIFIER_ALLOWLIST[0].wasm_hash);
    // Secondary: serves UNKNOWN_WASM_HASH (different — divergence fires).
    let secondary_entries = build_ledger_entries_contract_instance(&verifier, UNKNOWN_WASM_HASH);

    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(primary_entries))
        .mount(&primary_server)
        .await;

    let secondary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(JsonRpcResultResponder(secondary_entries))
        .mount(&secondary_server)
        .await;

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();
    let manager = manager_two_url(
        &primary_server.uri(),
        &secondary_server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    );

    // Write a SaContextRuleCreated row with the pinned hash matching VERIFIER_ALLOWLIST[0].wasm_hash.
    let pinned_first8 = VERIFIER_ALLOWLIST[0].wasm_hash[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
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
        vec![pinned_first8],
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

    // Call verify_pinned_verifier_against_chain — should fire divergence before drift.
    let mut cache: HashMap<Vec<u8>, [u8; 32]> = HashMap::new();

    let result = test_helpers::verify_pinned_verifier_against_chain(
        &manager,
        verifier,
        rule_id,
        ZERO_CONTRACT_REDACTED,
        &request_id,
        &mut cache,
    )
    .await;

    assert!(
        matches!(result, Err(SaError::NetworkRpcDivergence { .. })),
        "RPC suppression must yield NetworkRpcDivergence before drift check; got: {result:?}"
    );
    assert_eq!(
        result.unwrap_err().wire_code(),
        "network.rpc_divergence",
        "wire_code must be 'network.rpc_divergence'"
    );
}
