//! A verifier status refusal precedes every passkey bridge request.

#![cfg(feature = "test-helpers")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::schema::{EventKind, WasmHashPin};
use stellar_agent_core::audit_log::test_helpers::verified_audit_entries;
use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_smart_account::managers::auth_entry::PartialSorobanAuthorizationEntry;
use stellar_agent_smart_account::managers::auth_entry::test_helpers::partial_authorization_entry;
use stellar_agent_smart_account::managers::credentials::{CredentialsError, CredentialsManager};
use stellar_xdr::{ContractId, Hash, LedgerKey, Limits, ReadXdr, ScAddress, ScVal, WriteXdr};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

use super::combined_rpc_responder::SequencedSimulate;
use super::rpc_mock_helpers::{
    build_context_rule_scval_xdr, build_ledger_entries_account,
    build_ledger_entries_contract_instance, build_simulate_response, policy_sc_address,
    signer_set_n_of_n, tmp_audit_writer, write_baseline,
};

const RULE_ID: u32 = 1;

fn testnet_entry() -> PartialSorobanAuthorizationEntry {
    partial_authorization_entry(
        ScAddress::Contract(ContractId(Hash([0u8; 32]))),
        TESTNET_PASSPHRASE,
        vec![ContextRuleId::new(RULE_ID)],
    )
    .expect("fixture auth entry builds")
}

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

#[tokio::test]
async fn passkey_signing_refuses_a_revoked_verifier_before_bridge_io() {
    let (audit_writer, audit_log_path, dir) = tmp_audit_writer();
    let smart_account_redacted =
        redact_strkey_first5_last5(&stellar_strkey::Contract([0; 32]).to_string());
    let signer_set = signer_set_n_of_n(1);
    write_baseline(&audit_writer, RULE_ID, &smart_account_redacted, &signer_set);
    audit_writer
        .lock()
        .unwrap()
        .write_entry(AuditEntry::new_sa_context_rule_created_v2(
            &smart_account_redacted,
            RULE_ID,
            "default",
            1,
            0,
            None,
            "stellar:testnet",
            "revoked-passkey",
            vec![WasmHashPin::new([0xee; 32])],
            vec![],
            false,
            false,
            vec![],
            vec![],
        ))
        .unwrap();
    let xdr = build_context_rule_scval_xdr(RULE_ID, &signer_set, &[]);
    let ScVal::Map(Some(map)) = ScVal::from_xdr_base64(xdr, Limits::none()).unwrap() else {
        panic!("rule map")
    };
    let mut fields = map.0.to_vec();
    let signer = stellar_agent_smart_account::managers::signers::build_external_signer_scval(
        policy_sc_address(),
        &[0x11; 32],
    )
    .unwrap();
    for field in &mut fields {
        if field.key == ScVal::Symbol("signers".try_into().unwrap()) {
            field.val = ScVal::Vec(Some(vec![signer.clone()].try_into().unwrap()));
        }
    }
    let rule = ScVal::Map(Some(fields.try_into().unwrap()))
        .to_xdr_base64(Limits::none())
        .unwrap();
    // Both endpoints share this server. The drift check reads the rule, then
    // the verifier's instance from each endpoint; the live hash matches the
    // pin, so the status gate on the match path refuses. A ledger read past
    // those two fails the responder's range assertion.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(SequencedLedgerResponder::new(
            vec![[0xee; 32]; 2],
            vec![build_simulate_response(&rule)],
        ))
        .mount(&server)
        .await;
    let signers = Arc::new(super::rpc_mock_helpers::manager_one_url(
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    ));
    let bridge = MockServer::start().await;
    let bridge_addr = bridge.uri().trim_start_matches("http://").parse().unwrap();
    let manager =
        CredentialsManager::new(dir.path().join("passkeys"), "default", "localhost", None);
    let result = manager
        .sign_with_passkey_rule(
            "missing-before-show",
            &testnet_entry(),
            signers,
            bridge_addr,
            Duration::from_millis(100),
            |_| panic!("bridge callback must not run"),
            true,
        )
        .await;
    assert!(
        matches!(result, Err(CredentialsError::VerifierStatusRefused { ref source })
        if matches!(source.as_ref(), stellar_agent_smart_account::SaError::VerifierWasmRevoked { rule_id: Some(1), .. })),
        "{result:?}"
    );
    let entries = verified_audit_entries(&audit_writer);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| matches!(&entry.event_kind,
        EventKind::PasskeyAssertion { result, .. } if result == "failure:verifier_status_refused"))
            .count(),
        1
    );
    assert!(
        !entries
            .iter()
            .any(|entry| matches!(entry.event_kind, EventKind::SaVerifierHashDrift { .. }))
    );
    assert!(bridge.received_requests().await.unwrap().is_empty());
}
