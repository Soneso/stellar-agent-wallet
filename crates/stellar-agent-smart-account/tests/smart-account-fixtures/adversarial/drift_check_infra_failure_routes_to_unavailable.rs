//! Adversarial fixture: drift-check infrastructure failure routes to unavailable.
//!
//! The signing path must not report `WasmHashDrift` unless a concrete
//! verifier/policy drift row was emitted. This fixture makes the policy
//! drift re-fetch hit two-RPC divergence after the signer-set divergence check
//! has passed.
//!
//! # Invariant
//!
//! When the policy drift re-fetch hits a cross-RPC divergence error, the signing
//! path must route to `DriftCheckUnavailable` rather than reporting `WasmHashDrift`,
//! because no concrete drift row was emitted.

#![cfg(feature = "test-helpers")]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_xdr::{LedgerKey, Limits, ReadXdr};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

use super::combined_rpc_responder::SequencedSimulate;
use super::rpc_mock_helpers::{
    KNOWN_WASM_HASH, UNKNOWN_WASM_HASH, build_context_rule_scval_xdr, build_ledger_entries_account,
    build_ledger_entries_contract_instance, build_simulate_response, build_threshold_scval_xdr,
    policy_sc_address, signer_set_n_of_n, tmp_audit_writer, write_baseline,
};

const RULE_ID: u32 = 1;

struct SequencedLedgerResponder {
    source_g: &'static str,
    policy_hashes: Vec<[u8; 32]>,
    ledger_call: AtomicUsize,
    simulate: SequencedSimulate,
}

impl SequencedLedgerResponder {
    fn new(policy_hashes: Vec<[u8; 32]>, simulate: Vec<serde_json::Value>) -> Self {
        Self {
            source_g: SIMULATE_SENTINEL_G,
            policy_hashes,
            ledger_call: AtomicUsize::new(0),
            simulate: SequencedSimulate::new(simulate),
        }
    }
}

impl Respond for SequencedLedgerResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::json!({}));
        let req_id = body.get("id").cloned().unwrap_or(serde_json::json!(1));
        let method_name = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let result = match method_name {
            "simulateTransaction" => self.simulate.next(),
            "getLedgerEntries" => {
                let key = body
                    .get("params")
                    .and_then(|p| p.get("keys"))
                    .and_then(|k| k.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|k| k.as_str())
                    .unwrap_or("");
                if LedgerKey::from_xdr_base64(key, Limits::none())
                    .map(|k| matches!(k, LedgerKey::Account(_)))
                    .unwrap_or(false)
                {
                    build_ledger_entries_account(self.source_g)
                } else {
                    let idx = self.ledger_call.fetch_add(1, Ordering::Relaxed);
                    assert!(
                        idx < self.policy_hashes.len(),
                        "fixture out of range: policy hash index {idx} >= {}",
                        self.policy_hashes.len()
                    );
                    build_ledger_entries_contract_instance(
                        &policy_sc_address(),
                        self.policy_hashes[idx],
                    )
                }
            }
            _ => serde_json::json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result
            }))
            .insert_header("content-type", "application/json")
    }
}

fn read_audit_entries(log_path: &Path) -> Vec<AuditEntry> {
    std::fs::read_to_string(log_path)
        .expect("audit log must be readable")
        .lines()
        .filter_map(|line| serde_json::from_str::<AuditEntry>(line).ok())
        .collect()
}

#[tokio::test]
async fn policy_rpc_divergence_routes_to_drift_check_unavailable() {
    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
    let smart_account_strkey = format!("{}", stellar_strkey::Contract([0u8; 32]));
    let smart_account_redacted = redact_strkey_first5_last5(&smart_account_strkey);
    let policy = policy_sc_address();
    let signer_set = signer_set_n_of_n(1);
    // Lock-ordering verification: seed the baseline before constructing the
    // signers manager and before the signing path can acquire the shared writer,
    // keeping this fixture out of the runtime drift-check lock sequence.
    write_baseline(&audit_writer, RULE_ID, &smart_account_redacted, &signer_set);

    let pinned_policy_first8 = KNOWN_WASM_HASH[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    {
        let entry = AuditEntry::new_sa_context_rule_created(
            &smart_account_redacted,
            RULE_ID,
            "default",
            1,
            1,
            None,
            "stellar:testnet",
            uuid::Uuid::new_v4().to_string(),
            vec![],
            vec![pinned_policy_first8],
            false,
            false,
        );
        audit_writer
            .lock()
            .expect("audit writer poisoned")
            .write_entry(entry)
            .expect("context-rule-created row must write");
    }

    let context_rule_xdr =
        build_context_rule_scval_xdr(RULE_ID, &signer_set, std::slice::from_ref(&policy));
    let threshold_xdr = build_threshold_scval_xdr(1);
    let context_rule_response = build_simulate_response(&context_rule_xdr);
    let threshold_response = build_simulate_response(&threshold_xdr);

    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SequencedLedgerResponder::new(
            vec![KNOWN_WASM_HASH, KNOWN_WASM_HASH],
            vec![
                context_rule_response.clone(),
                context_rule_response.clone(),
                threshold_response.clone(),
                context_rule_response.clone(),
            ],
        ))
        .mount(&primary)
        .await;

    let secondary = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SequencedLedgerResponder::new(
            vec![KNOWN_WASM_HASH, UNKNOWN_WASM_HASH],
            vec![context_rule_response.clone(), threshold_response],
        ))
        .mount(&secondary)
        .await;

    let signers_manager = Arc::new(super::rpc_mock_helpers::manager_two_url(
        &primary.uri(),
        &secondary.uri(),
        Arc::clone(&audit_writer),
        audit_log_path.clone(),
    ));
    let manager =
        CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);

    let result = manager
        .sign_with_passkey_rule(
            "missing-before-show",
            &smart_account_strkey,
            &[0u8; 32],
            vec![RULE_ID],
            Some(signers_manager),
            "127.0.0.1:0".parse().expect("socket addr parses"),
            Duration::from_millis(10),
            |_| {},
            true, // accept_single_verifier: bypass diversification (fixture tests drift infra)
        )
        .await;

    assert!(
        matches!(result, Err(CredentialsError::DriftCheckUnavailable { .. })),
        "non-drift inner SaError must route to DriftCheckUnavailable; got {result:?}"
    );

    let entries = read_audit_entries(&audit_log_path);
    assert!(
        !entries.iter().any(|entry| matches!(
            entry.event_kind,
            EventKind::SaVerifierHashDrift { .. } | EventKind::SaPolicyHashDrift { .. }
        )),
        "infrastructure failure must not emit verifier/policy drift rows"
    );
    assert!(
        entries.iter().any(|entry| matches!(
            &entry.event_kind,
            EventKind::PasskeyAssertion { result, .. } if result == "failure:drift_check_unavailable"
        )),
        "PasskeyAssertion(failure:drift_check_unavailable) row must be emitted"
    );
}
