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
//! 1. Write a `SaContextRuleCreatedV2` audit entry whose
//!    `pinned_policy_wasm_hashes` is `[[0x02; 32]]` (a sentinel that will
//!    not match the mock RPC's response).
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
use std::sync::Arc;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, WasmHashPin};
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::signers::ObservedExecutable;
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
    ZERO_CONTRACT_REDACTED, assert_refusal_holds_no_marker, build_ledger_entries_contract_instance,
    manager_one_url, mcp_error_envelope, tmp_audit_writer, wallet_traced,
};

// ── Address helpers ───────────────────────────────────────────────────────────

/// Policy contract address (`[0x21; 32]`).
fn policy_addr() -> ScAddress {
    ScAddress::Contract(ContractId(Hash([0x21u8; 32])))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// When the pinned policy wasm hash in the audit log does not match the live
/// on-chain hash returned by the mock RPC, `verify_pinned_policy_against_chain`
/// returns `SaError::PolicyHashDrift` and emits a `SaPolicyHashDrift` audit row.
///
/// The refusal holds no form of the observed hash, whole or as its first
/// eight bytes, nor its executable summary, in its Display, Debug and source
/// chain, its serialized form, the MCP error envelope or the wallet's logs,
/// which hold the drift warning. The drift row keeps the observed hash's
/// first eight bytes and the executable summary.
#[test]
fn policy_wasm_hash_drift_detected_and_audit_row_emitted() {
    let live_wasm_hash = THRESHOLD_POLICY_WASM_HASHES[0];
    let observed_full = hex::encode(live_wasm_hash);
    let observed_first8 = WasmHashPin::new(live_wasm_hash).first8_display();
    assert!(observed_full.starts_with(&observed_first8));

    let (audit_writer, audit_log_path, _dir) = tmp_audit_writer();

    // A pin record whose policy hash differs from the live one.
    let fake_pinned = WasmHashPin::new([0x02; 32]);
    let rule_id: u32 = 1;
    let request_id = Uuid::new_v4().to_string();
    audit_writer
        .lock()
        .expect("audit writer poisoned")
        .write_entry(AuditEntry::new_sa_context_rule_created_v2(
            ZERO_CONTRACT_REDACTED,
            rule_id,
            "default",
            1,
            1,
            None,
            "stellar:testnet",
            &request_id,
            vec![],
            vec![fake_pinned],
            false,
            false,
            vec![],
            vec![],
        ))
        .expect("write_entry must succeed");

    let (result, logs) = wallet_traced({
        let audit_writer = Arc::clone(&audit_writer);
        let request_id = request_id.clone();
        async move {
            // The mock RPC serves THRESHOLD_POLICY_WASM_HASHES[0].
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/"))
                .respond_with(JsonRpcResultResponder(
                    build_ledger_entries_contract_instance(&policy_addr(), live_wasm_hash),
                ))
                .mount(&server)
                .await;
            let manager = manager_one_url(&server.uri(), audit_writer, audit_log_path);
            let mut cache: HashMap<Vec<u8>, ObservedExecutable> = HashMap::new();
            test_helpers::verify_pinned_policy_against_chain(
                &manager,
                policy_addr(),
                rule_id,
                ZERO_CONTRACT_REDACTED,
                &request_id,
                &mut cache,
            )
            .await
        }
    });

    let err = result.expect_err("wasm-hash drift must refuse");
    let SaError::PolicyHashDrift { pinned_hash, .. } = &err else {
        panic!("wasm-hash drift must return SaError::PolicyHashDrift; got: {err:?}");
    };
    assert_eq!(*pinned_hash, fake_pinned);
    assert_eq!(
        err.wire_code(),
        "sa.policy_hash_drift",
        "wire_code must be 'sa.policy_hash_drift'"
    );
    assert_eq!(
        err.to_string(),
        format!(
            "policy executable must match the pinned executable for rule 1: pinned={}",
            fake_pinned.to_hex()
        )
    );
    assert!(
        logs.contains(
            "verify_pinned_policy_against_chain: policy executable must match the pinned"
        ),
        "the drift warning is captured: {logs}"
    );
    assert!(
        mcp_error_envelope(&err).contains("\"sa.policy_hash_drift\""),
        "the MCP envelope carries the wire code"
    );
    assert_refusal_holds_no_marker(&err, &logs, &[&observed_full, &observed_first8], &["wasm"]);

    // The SaPolicyHashDrift audit row is emitted with the call's request id
    // and keeps the observed hash's first eight bytes and executable.
    let entries = verified_audit_entries(&audit_writer);
    let rows: Vec<&EventKind> = entries
        .iter()
        .filter(|entry| entry.request_id == request_id)
        .map(|entry| &entry.event_kind)
        .filter(|kind| matches!(kind, EventKind::SaPolicyHashDrift { .. }))
        .collect();
    let [
        EventKind::SaPolicyHashDrift {
            rule_id: row_rule_id,
            pinned_hash_first8,
            observed_hash_first8,
            observed_executable,
            ..
        },
    ] = rows.as_slice()
    else {
        panic!("one SaPolicyHashDrift row with the call's request id: {rows:?}");
    };
    assert_eq!(*row_rule_id, rule_id);
    assert_eq!(pinned_hash_first8, &fake_pinned.first8_display());
    assert_eq!(observed_hash_first8, &observed_first8);
    assert_eq!(observed_executable.as_deref(), Some("wasm"));
}

/// A live policy whose hash shares the pinned hash's first eight bytes
/// refuses as drift although neither hash is in the policy allowlist; the
/// exact pinned hash passes. The error names the full pin; the drift audit
/// row keeps the observed hash and executable.
#[tokio::test]
async fn an_equal_prefix_policy_twin_refuses_as_drift_outside_the_allowlist() {
    let pinned = [0x42u8; 32];
    let mut twin = pinned;
    twin[8..].fill(0x43);
    for (live, drift) in [(twin, true), (pinned, false)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(JsonRpcResultResponder(
                build_ledger_entries_contract_instance(&policy_addr(), live),
            ))
            .mount(&server)
            .await;
        let (audit, path, _dir) = tmp_audit_writer();
        let manager = manager_one_url(&server.uri(), Arc::clone(&audit), path);
        audit
            .lock()
            .unwrap()
            .write_entry(AuditEntry::new_sa_context_rule_created_v2(
                ZERO_CONTRACT_REDACTED,
                1,
                "default",
                1,
                1,
                None,
                "stellar:testnet",
                "policy-twin",
                vec![],
                vec![WasmHashPin::new(pinned)],
                false,
                true,
                vec![],
                vec![],
            ))
            .unwrap();
        let outcome = test_helpers::verify_pinned_policy_against_chain(
            &manager,
            policy_addr(),
            1,
            ZERO_CONTRACT_REDACTED,
            "policy-twin",
            &mut HashMap::new(),
        )
        .await;
        if drift {
            match &outcome {
                Err(err @ SaError::PolicyHashDrift { pinned_hash, .. }) => {
                    assert_eq!(*pinned_hash, WasmHashPin::new(pinned));
                    let rendered =
                        format!("{err}\n{err:?}\n{}", serde_json::to_string(err).unwrap());
                    assert!(!rendered.contains(&hex::encode(twin)), "{rendered}");
                }
                other => panic!("expected PolicyHashDrift, got {other:?}"),
            }
            assert!(
                verified_audit_entries(&audit)
                    .iter()
                    .any(|entry| matches!(entry.event_kind, EventKind::SaPolicyHashDrift { .. }))
            );
        } else {
            assert!(outcome.is_ok(), "{outcome:?}");
        }
    }
}
