//! Mock-driven path tests for `ContextRuleManager::verify_rule_wasm_pins`.
//!
//! All tests hold the serial lock because the RPC client's proxy cache and
//! HTTP-proxy environment variables are process-global state.

use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;

use stellar_agent_core::audit_log::AuditEntry;
use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_core::observability::redact_strkey_first5_last5;

use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, PinStatus, parse_c_strkey_to_smart_account,
};
use stellar_agent_smart_account::managers::signers::build_external_signer_scval;
use stellar_agent_test_support::xdr_fixtures::{
    account_entry_xdr_with_seq, contract_instance_ledger_entries_json,
};
use stellar_xdr::{
    LedgerKey, Limits, ReadXdr, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec, WriteXdr,
};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

use crate::combined_rpc_responder;
use crate::rpc_mock_helpers;

use combined_rpc_responder::{CombinedRpcResponder, SequencedSimulate};
use rpc_mock_helpers::{
    SOURCE_G, build_context_rule_scval_xdr, build_simulate_response, manager_one_url,
    manager_two_url, policy_sc_address, signer_set_n_of_n, tmp_audit_writer, zero_sc_address,
};

const ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
const NETWORK_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";

#[allow(
    clippy::expect_used,
    reason = "test helper asserts fixture construction invariants"
)]
async fn manager_with_rule(
    rule_id: u32,
    policies: Vec<stellar_xdr::ScAddress>,
) -> (ContextRuleManager, tempfile::TempDir) {
    let (audit_writer, audit_log_path, tmp_dir) = tmp_audit_writer();
    let signers = signer_set_n_of_n(0);
    let rule_xdr = build_context_rule_scval_xdr(rule_id, &signers, &policies);
    let simulate = SequencedSimulate::new(vec![build_simulate_response(&rule_xdr)]);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(CombinedRpcResponder::new_no_policies(SOURCE_G, simulate))
        .mount(&server)
        .await;

    let signers_manager = Arc::new(manager_two_url(
        &server.uri(),
        &server.uri(),
        Arc::clone(&audit_writer),
        audit_log_path,
    ));

    let manager = ContextRuleManager::new(
        ContextRuleManagerConfig::new(
            server.uri(),
            NETWORK_PASSPHRASE.to_owned(),
            Duration::from_secs(5),
            CHAIN_ID.to_owned(),
        )
        .with_signers_manager(signers_manager)
        .with_audit_writer(audit_writer),
    )
    .expect("ContextRuleManager::new must succeed");
    // Return `tmp_dir` so the caller keeps it in scope for the test's lifetime;
    // when the test scope ends, `TempDir::Drop` cleans the directory naturally
    // (avoids the previous `std::mem::forget` leak).
    (manager, tmp_dir)
}

#[tokio::test]
#[serial]
#[allow(clippy::expect_used, reason = "test asserts successful fixture path")]
async fn verify_rule_wasm_pins_returns_no_contracts_when_rule_has_no_external_contracts() {
    let rule_id = 31;
    let (manager, _tmp_dir) = manager_with_rule(rule_id, vec![]).await;

    let result = manager
        .verify_rule_wasm_pins(zero_sc_address(), rule_id, SOURCE_G, "req-no-contracts")
        .await
        .expect("verify_rule_wasm_pins must return a result");

    assert_eq!(result.verifier_pin_status, PinStatus::NoContracts);
    assert_eq!(result.policy_pin_status, PinStatus::NoContracts);
    assert!(result.pinned_verifier_first8.is_empty());
    assert!(result.pinned_policy_first8.is_empty());
}

#[tokio::test]
#[serial]
#[allow(clippy::expect_used, reason = "test asserts successful fixture path")]
async fn verify_rule_wasm_pins_returns_no_pin_when_contracts_exist_without_audit_pin() {
    let rule_id = 32;
    let (manager, _tmp_dir) = manager_with_rule(rule_id, vec![policy_sc_address()]).await;

    let result = manager
        .verify_rule_wasm_pins(zero_sc_address(), rule_id, SOURCE_G, "req-no-pin")
        .await
        .expect("verify_rule_wasm_pins must return a result");

    assert_eq!(result.verifier_pin_status, PinStatus::NoPin);
    assert_eq!(result.policy_pin_status, PinStatus::NoPin);
    assert!(result.pinned_verifier_first8.is_empty());
    assert!(result.pinned_policy_first8.is_empty());
}

struct MixedPinsResponder {
    rule: ScVal,
    available: serde_json::Value,
    unavailable_key: LedgerKey,
}

#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixture construction and assertions"
)]
impl Respond for MixedPinsResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let mut response = serde_json::json!({"jsonrpc": "2.0", "id": body["id"]});
        match body["method"].as_str().unwrap() {
            "simulateTransaction" => {
                response["result"] = serde_json::json!({
                    "results": [{"auth": [], "xdr": self.rule.to_xdr_base64(Limits::none()).unwrap()}],
                    "latestLedger": 1000,
                });
            }
            "getLedgerEntries" => {
                let keys = body["params"]["keys"].as_array().unwrap();
                assert_eq!(keys.len(), 1);
                let key =
                    LedgerKey::from_xdr_base64(keys[0].as_str().unwrap(), Limits::none()).unwrap();
                if matches!(key, LedgerKey::Account(_)) {
                    response["result"] = serde_json::json!({
                        "entries": [{"key": keys[0], "xdr": account_entry_xdr_with_seq(SIMULATE_SENTINEL_G, 100_000_000, 0, 100), "lastModifiedLedgerSeq": 100}],
                        "latestLedger": 1000,
                    });
                } else if key == self.unavailable_key {
                    response["error"] =
                        serde_json::json!({"code": -32603, "message": "pin probe unavailable"});
                } else {
                    assert_eq!(keys[0], self.available["entries"][0]["key"]);
                    response["result"] = self.available.clone();
                }
            }
            other => panic!("unexpected RPC method: {other}"),
        }
        ResponseTemplate::new(200).set_body_json(response)
    }
}

/// A drifted pin remains drift beside an unavailable pin, in either kind.
/// The report carries the unavailable probe's wire code; the unavailable kind's observed list is empty.
#[tokio::test]
#[serial]
#[allow(
    clippy::unwrap_used,
    reason = "test fixture construction and assertions"
)]
async fn verify_pins_mixed_drift_and_unavailable_preserves_both_statuses_and_code() {
    let verifier = stellar_strkey::Contract([0x41; 32]).to_string();
    let policy = stellar_strkey::Contract([0x42; 32]).to_string();
    let vector = |items: Vec<ScVal>| ScVal::Vec(Some(ScVec(items.try_into().unwrap())));
    let field = |key: &str, val| ScMapEntry {
        key: ScVal::Symbol(ScSymbol(key.try_into().unwrap())),
        val,
    };
    let rule = ScVal::Map(Some(ScMap(
        vec![
            field("id", ScVal::U32(7)),
            field(
                "policies",
                vector(vec![ScVal::Address(
                    parse_c_strkey_to_smart_account(&policy).unwrap(),
                )]),
            ),
            field("signer_ids", vector(vec![ScVal::U32(0)])),
            field(
                "signers",
                vector(vec![
                    build_external_signer_scval(
                        parse_c_strkey_to_smart_account(&verifier).unwrap(),
                        &[0x11; 32],
                    )
                    .unwrap(),
                ]),
            ),
        ]
        .try_into()
        .unwrap(),
    )));

    for verifier_drifts in [true, false] {
        let (audit, audit_log_path, _tmp_dir) = tmp_audit_writer();
        audit
            .lock()
            .unwrap()
            .write_entry(AuditEntry::new_sa_context_rule_created(
                redact_strkey_first5_last5(ACCOUNT),
                7,
                "default",
                1,
                1,
                None,
                CHAIN_ID,
                "pins",
                vec!["1111111111111111".to_owned()],
                vec!["2222222222222222".to_owned()],
                false,
                false,
                vec![],
                vec![],
            ))
            .unwrap();
        let (available, unavailable) = if verifier_drifts {
            (&verifier, &policy)
        } else {
            (&policy, &verifier)
        };
        let available: serde_json::Value = serde_json::from_str(
            &contract_instance_ledger_entries_json(available, [0xab; 32]),
        )
        .unwrap();
        let unavailable: serde_json::Value = serde_json::from_str(
            &contract_instance_ledger_entries_json(unavailable, [0xcd; 32]),
        )
        .unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(MixedPinsResponder {
                rule: rule.clone(),
                available: available["result"].clone(),
                unavailable_key: LedgerKey::from_xdr_base64(
                    unavailable["result"]["entries"][0]["key"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap(),
            })
            .mount(&server)
            .await;
        let signers = Arc::new(manager_one_url(
            &server.uri(),
            Arc::clone(&audit),
            audit_log_path,
        ));
        let manager = ContextRuleManager::new(
            ContextRuleManagerConfig::new(
                server.uri(),
                NETWORK_PASSPHRASE.to_owned(),
                Duration::from_secs(5),
                CHAIN_ID.to_owned(),
            )
            .with_signers_manager(signers)
            .with_audit_writer(audit),
        )
        .unwrap();
        let result = manager
            .verify_rule_wasm_pins(
                parse_c_strkey_to_smart_account(ACCOUNT).unwrap(),
                7,
                SIMULATE_SENTINEL_G,
                "mixed-pins",
            )
            .await
            .unwrap();
        let (verifier_status, policy_status) = if verifier_drifts {
            (PinStatus::Drift, PinStatus::Unavailable)
        } else {
            (PinStatus::Unavailable, PinStatus::Drift)
        };
        assert_eq!(result.smart_account, ACCOUNT);
        assert_eq!(result.rule_id, 7);
        assert_eq!(
            result.verifier_pin_status, verifier_status,
            "verifier_drifts={verifier_drifts}"
        );
        assert_eq!(
            result.policy_pin_status, policy_status,
            "verifier_drifts={verifier_drifts}"
        );
        assert_eq!(result.unavailable_wire_code, Some("sa.deployment_failed"));
        assert_eq!(result.pinned_verifier_first8, ["1111111111111111"]);
        assert_eq!(result.pinned_policy_first8, ["2222222222222222"]);
        let (drifted, unavailable) = if verifier_drifts {
            (
                &result.observed_verifier_first8,
                &result.observed_policy_first8,
            )
        } else {
            (
                &result.observed_policy_first8,
                &result.observed_verifier_first8,
            )
        };
        assert_eq!(drifted, &["abababababababab"]);
        assert!(unavailable.is_empty());
        let report = serde_json::to_value(&result).unwrap();
        assert_eq!(
            report["verifier_pin_status"],
            if verifier_drifts {
                "drift"
            } else {
                "unavailable"
            }
        );
        assert_eq!(
            report["policy_pin_status"],
            if verifier_drifts {
                "unavailable"
            } else {
                "drift"
            }
        );
        assert_eq!(report["unavailable_wire_code"], "sa.deployment_failed");
    }
}
