//! Multicall rule coverage is checked against the simulated invocation tree.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "mock fixture construction and assertions"
)]

use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256;
use stellar_agent_smart_account::{
    SaError,
    submit::{MulticallCheck, SubmitInvokeArgs, submit_signed_invoke},
};
use stellar_agent_test_support::signed_envelope::{
    account_id_for_seed, get_network_result, send_transaction_hash_hex,
};
use stellar_xdr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, Limits, OperationBody, ReadXdr, ScAddress,
    ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    TransactionEnvelope, WriteXdr,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_helpers;

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const SEED: [u8; 32] = [0x53; 32];

struct Rpc(Arc<AtomicUsize>);

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(PASSPHRASE),
            "getLatestLedger" => {
                json!({"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27})
            }
            "getLedgerEntries" => {
                rpc_helpers::build_ledger_entries_account(&account_id_for_seed(SEED))
            }
            "simulateTransaction" => {
                let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap() else {
                    panic!("v1 envelope")
                };
                let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                    panic!("invoke operation")
                };
                let HostFunction::InvokeContract(invoke) = &op.host_function else {
                    panic!("contract function")
                };
                let mut result = rpc_helpers::build_simulate_response(
                    &ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),
                );
                let auth = if op.auth.is_empty() {
                    vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: invoke.contract_address.clone(),
                            nonce: 7,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: SorobanAuthorizedInvocation {
                            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                            sub_invocations: vec![SorobanAuthorizedInvocation {
                                function: SorobanAuthorizedFunction::ContractFn(
                                    InvokeContractArgs {
                                        contract_address: ScAddress::Contract(ContractId(Hash(
                                            [0x55; 32],
                                        ))),
                                        function_name: ScSymbol("nested".try_into().unwrap()),
                                        args: Default::default(),
                                    },
                                ),
                                sub_invocations: Default::default(),
                            }]
                            .try_into()
                            .unwrap(),
                        },
                    }]
                } else {
                    op.auth.to_vec()
                };
                result["results"][0]["auth"] = json!(
                    auth.iter()
                        .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
                        .collect::<Vec<_>>()
                );
                result
            }
            "sendTransaction" => {
                self.0.fetch_add(1, Ordering::SeqCst);
                json!({"status": "PENDING", "hash": send_transaction_hash_hex(&body, PASSPHRASE), "latestLedger": 1000, "latestLedgerCloseTime": "1234567890"})
            }
            "getTransaction" => {
                json!({"status": "SUCCESS", "ledger": 1001, "latestLedger": 1001, "oldestLedger": 1})
            }
            other => panic!("unexpected RPC method: {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

async fn submit(
    rule_count: usize,
) -> (
    Result<stellar_agent_smart_account::submit::SubmitInvokeResult, SaError>,
    usize,
) {
    let mock = MockServer::start().await;
    let sends = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .respond_with(Rpc(Arc::clone(&sends)))
        .mount(&mock)
        .await;
    let target = stellar_strkey::Contract([0x54; 32]).to_string().to_string();
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let ids = vec![ContextRuleId::new(0); rule_count];
    let result = submit_signed_invoke(
        SubmitInvokeArgs::builder()
            .target_contract(&target)
            .auth_rule_ids(&ids)
            .host_function(HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([0x54; 32]))),
                function_name: ScSymbol("exec".try_into().unwrap()),
                args: Default::default(),
            }))
            .signer(&signer)
            .primary_rpc_url(&mock.uri())
            .network_passphrase(PASSPHRASE)
            .chain_id("stellar:testnet")
            .timeout(Duration::from_secs(2))
            .op_label("multicall_rule_count")
            .required_checks(&["multicall"])
            .multicall_check(MulticallCheck {
                registry_entry_address: target.clone(),
                registry_entry_wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
                network_passphrase: PASSPHRASE.to_owned(),
            })
            .build(),
    )
    .await;
    (result, sends.load(Ordering::SeqCst))
}

#[tokio::test]
async fn three_rules_for_two_contexts_are_refused_before_send() {
    let (result, sends) = submit(3).await;
    assert_eq!(sends, 0);
    match result {
        Err(SaError::MulticallFailed {
            phase,
            redacted_reason,
            ..
        }) => {
            assert_eq!(phase, "build");
            assert!(
                redacted_reason.contains("rule count 3"),
                "{redacted_reason}"
            );
            assert!(
                redacted_reason.contains("2 invocation contexts"),
                "{redacted_reason}"
            );
        }
        other => panic!("expected early multicall refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn one_rule_expands_across_two_contexts_and_reaches_send() {
    let (result, sends) = submit(1).await;
    assert_eq!(sends, 1, "single rule must reach send: {result:?}");
}

#[tokio::test]
async fn two_rules_cover_two_contexts_and_reach_send() {
    let (result, sends) = submit(2).await;
    assert_eq!(sends, 1, "exact coverage must reach send: {result:?}");
}
