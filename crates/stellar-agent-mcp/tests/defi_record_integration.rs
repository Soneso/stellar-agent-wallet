//! DeFi sends retain durable receipts, audit rows, and spending reservations.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration fixture construction and assertions"
)]

use base64::Engine as _;
use serde_json::{Value, json};
use serial_test::serial;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::policy::{
    Decision,
    v1::{
        PolicyEngineV1,
        criteria::per_period_cap::{PerPeriodCapCriterion, Window},
        loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId},
    },
};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_defindex::pins::DEFINDEX_VAULT_WASM_HASH;
use stellar_agent_dex::pins::{SOROSWAP_ROUTER_ADDRESS_TESTNET, SOROSWAP_ROUTER_WASM_HASH_TESTNET};
use stellar_agent_mcp::server::{
    DexTradeArgs, StellarTransactionStatusArgs, VaultDepositMcpArgs, VaultWithdrawMcpArgs,
    WalletServer,
};
use stellar_agent_network::{envelope_hash_hex, policy_state::PersistedWindowStore};
use stellar_agent_test_support::{
    keyring_mock,
    signed_envelope::{account_id_for_seed, send_transaction_hash_hex},
};
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
    Hash, HostFunction, Int128Parts, LedgerEntryData, Limits, OperationBody, ReadXdr, ScAddress,
    ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, TransactionEnvelope, WriteXdr,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};

mod common;
#[path = "../../stellar-agent-smart-account/tests/smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_helpers;

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const WALLET: u8 = 0x64;
const VAULT: u8 = 0x65;
const TOKEN: u8 = 0x66;
const QUANTITY: i128 = 30;

fn contract(byte: u8) -> String {
    stellar_strkey::Contract([byte; 32]).to_string().to_string()
}

fn address(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

fn symbol(value: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(value.try_into().unwrap()))
}

fn vector(values: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(values.try_into().unwrap()))
}

fn map(entries: Vec<(ScVal, ScVal)>) -> ScMap {
    let mut entries: Vec<_> = entries
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect();
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    ScMap(entries.try_into().unwrap())
}

fn vault_entry() -> (String, String) {
    let mut storage = vec![
        (vector(vec![symbol("Upgradable")]), ScVal::Bool(false)),
        (vector(vec![symbol("TotalAssets")]), ScVal::U32(1)),
        (
            vector(vec![symbol("AssetStrategySet"), ScVal::U32(0)]),
            ScVal::Map(Some(map(vec![
                (symbol("address"), ScVal::Address(address(TOKEN))),
                (symbol("strategies"), vector(vec![])),
            ]))),
        ),
    ];
    for role in [
        "Manager",
        "EmergencyManager",
        "RebalanceManager",
        "VaultFeeReceiver",
    ] {
        storage.push((vector(vec![symbol(role)]), ScVal::Address(address(WALLET))));
    }
    let entry = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: address(VAULT),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(DEFINDEX_VAULT_WASM_HASH)),
            storage: Some(map(storage)),
        }),
    });
    (
        rpc_helpers::contract_instance_key_xdr(&address(VAULT)),
        entry.to_xdr_base64(Limits::none()).unwrap(),
    )
}

struct Rpc {
    entries: Vec<(String, String)>,
    confirming: Arc<AtomicBool>,
    sent: Arc<Mutex<Vec<(String, String)>>>,
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let mut delegate = common::TimeoutRpc::new(self.entries.clone());
        if self.confirming.load(Ordering::SeqCst) {
            delegate = delegate.confirming_in(1001);
        }
        match body["method"].as_str().unwrap() {
            "getLatestLedger" => return ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": body["id"], "result": {"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27}
            })),
            "simulateTransaction" => {
                let TransactionEnvelope::Tx(tx) = TransactionEnvelope::from_xdr_base64(body["params"]["transaction"].as_str().unwrap(), Limits::none()).unwrap() else { panic!("v1 envelope") };
                let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else { panic!("invoke operation") };
                let HostFunction::InvokeContract(invoke) = &op.host_function else { panic!("contract function") };
                let function = invoke.function_name.0.to_utf8_string().unwrap();
                let quote = function == "router_get_amounts_out";
                assert!(quote || matches!(function.as_str(), "swap_exact_tokens_for_tokens" | "deposit" | "withdraw"), "unexpected simulated function: {function}");
                let value = if quote { vector(vec![ScVal::I128(Int128Parts { hi: 0, lo: 30 }), ScVal::I128(Int128Parts { hi: 0, lo: 30 })]) } else { ScVal::Void };
                let mut simulation = rpc_helpers::build_simulate_response(&value.to_xdr_base64(Limits::none()).unwrap());
                let auth = if quote { vec![] } else if !op.auth.is_empty() { op.auth.to_vec() } else {
                    vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: address(WALLET), nonce: 7, signature_expiration_ledger: 0, signature: ScVal::Void,
                        }),
                        root_invocation: SorobanAuthorizedInvocation {
                            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()), sub_invocations: Default::default(),
                        },
                    }]
                };
                simulation["results"][0]["auth"] = json!(auth.iter().map(|entry| entry.to_xdr_base64(Limits::none()).unwrap()).collect::<Vec<_>>());
                delegate = delegate.with_simulate(simulation);
            }
            "sendTransaction" => {
                let envelope = body["params"]["transaction"].as_str().unwrap();
                self.sent.lock().unwrap().push((send_transaction_hash_hex(&body, PASSPHRASE), envelope_hash_hex(envelope)));
            }
            "getNetwork" | "getFeeStats" | "getLedgerEntries" | "getTransaction" => {}
            other => panic!("unexpected RPC method: {other}"),
        }
        delegate.respond(request)
    }
}

#[derive(Clone, Copy)]
enum Tool {
    Trade,
    Deposit,
    Withdraw,
}

impl Tool {
    fn seed(self, confirmed: bool) -> [u8; 32] {
        [match self {
            Self::Trade => 0x71,
            Self::Deposit => 0x73,
            Self::Withdraw => 0x75,
        } + u8::from(confirmed); 32]
    }

    fn name(self) -> &'static str {
        match self {
            Self::Trade => "stellar_dex_trade",
            Self::Deposit => "stellar_defindex_vault_deposit",
            Self::Withdraw => "stellar_defindex_vault_withdraw",
        }
    }

    async fn call(self, server: &WalletServer) -> rmcp::model::CallToolResult {
        let result = match self {
            Self::Trade => {
                server
                    .call_stellar_dex_trade(DexTradeArgs {
                        chain_id: "stellar:testnet".to_owned(),
                        from_address: contract(WALLET),
                        qty_in: QUANTITY.to_string(),
                        qty_out_min: "20".to_owned(),
                        path: vec![contract(TOKEN), contract(TOKEN + 1)],
                        deadline: None,
                        secondary_rpc_url: None,
                    })
                    .await
            }
            Self::Deposit => {
                server
                    .call_stellar_defindex_vault_deposit(VaultDepositMcpArgs {
                        chain_id: "stellar:testnet".to_owned(),
                        vault_address: contract(VAULT),
                        from_address: contract(WALLET),
                        amounts_desired: vec![QUANTITY.to_string()],
                        amounts_min: vec!["20".to_owned()],
                        invest: false,
                        override_upgradable: false,
                        secondary_rpc_url: None,
                    })
                    .await
            }
            Self::Withdraw => {
                server
                    .call_stellar_defindex_vault_withdraw(VaultWithdrawMcpArgs {
                        chain_id: "stellar:testnet".to_owned(),
                        vault_address: contract(VAULT),
                        from_address: contract(WALLET),
                        withdraw_shares: QUANTITY.to_string(),
                        min_amounts_out: vec!["20".to_owned()],
                        override_upgradable: false,
                        secondary_rpc_url: None,
                    })
                    .await
            }
        };
        result.unwrap()
    }
}

fn result_json(result: &rmcp::model::CallToolResult) -> Value {
    serde_json::from_str(&result.content.first().unwrap().as_text().unwrap().text).unwrap()
}

fn install_test_nonce_key() {
    keyring_core::Entry::new("n-svc", "n-acct")
        .unwrap()
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]))
        .unwrap();
}

fn assert_window_total(
    window: &PersistedWindowStore,
    profile: &Profile,
    profile_name: &str,
    tool: Tool,
) {
    let state = PolicyStateStore::new();
    window.load_into(profile_name, profile, &state).unwrap();
    let key = StateKey::new(
        profile_name,
        1,
        &stellar_agent_core::policy::v1::value::asset_normalise(&contract(TOKEN)),
        86_400,
    );
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let expected = if matches!(tool, Tool::Withdraw) {
        (0, 0)
    } else {
        (QUANTITY, 1)
    };
    assert_eq!(
        state.query_window(&key, now).unwrap(),
        expected,
        "the persisted cap accounts for this submission exactly once"
    );
}

async fn exercise(tool: Tool, initially_confirmed: bool) {
    let _root = common::isolated_data_root();
    keyring_mock::install().unwrap();
    install_test_nonce_key();
    let seed = tool.seed(initially_confirmed);
    let source = account_id_for_seed(seed);
    let signer_seed = stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string();
    keyring_core::Entry::new("svc", &source)
        .unwrap()
        .set_password(&signer_seed)
        .unwrap();
    let mock = MockServer::start().await;
    let confirming = Arc::new(AtomicBool::new(initially_confirmed));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let router = ScAddress::Contract(ContractId(Hash(
        stellar_strkey::Contract::from_string(SOROSWAP_ROUTER_ADDRESS_TESTNET)
            .unwrap()
            .0,
    )));
    Mock::given(method("POST"))
        .respond_with(Rpc {
            entries: vec![
                (
                    rpc_helpers::account_key_xdr(&source),
                    rpc_helpers::account_entry_xdr(&source, 42),
                ),
                (
                    rpc_helpers::contract_instance_key_xdr(&router),
                    rpc_helpers::contract_instance_entry_xdr(
                        &router,
                        SOROSWAP_ROUTER_WASM_HASH_TESTNET,
                    ),
                ),
                vault_entry(),
            ],
            confirming: Arc::clone(&confirming),
            sent: Arc::clone(&sent),
        })
        .mount(&mock)
        .await;
    let profile = common::timeout_profile(&mock.uri(), &source);
    let mut server = WalletServer::new(profile.clone()).unwrap();
    let profile_name = server.profile_name_for_approval();
    server.set_policy_engine_for_test(Arc::new(PolicyEngineV1::new(
        PolicyDocument {
            version: 1,
            scope: ScopeId::AllProfiles,
            signature: None,
            rules: vec![PolicyRule {
                r#match: RuleMatch {
                    tool: "*".to_owned(),
                    chain: "*".to_owned(),
                },
                criteria: vec![Box::new(PerPeriodCapCriterion::new(
                    contract(TOKEN),
                    Window::parse("1d").unwrap(),
                    1000,
                ))],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }],
        },
        profile_name.clone(),
    )));
    let result = tool.call(&server).await;
    let response = result_json(&result);
    let sent = sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "{} must send once: {response}", tool.name());
    let (tx_hash, envelope_hash) = &sent[0];
    let receipts = ReceiptStore::open(&profile_name).unwrap();
    let window = PersistedWindowStore::for_profile(&profile_name);
    if !initially_confirmed {
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            response["error"]["code"], "submission.tx_timeout",
            "{response}"
        );
        let details = &response["error"]["details"];
        assert_eq!(details["tx_hash"], *tx_hash);
        assert_eq!(tx_hash.len(), 64);
        assert!(tx_hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(details["envelope_hash"], *envelope_hash);
        assert_eq!(details["outcome"], "unknown");
        assert_eq!(details["reconcile_with"], "stellar_transaction_status");
        assert!(
            !response["error"]["message"]
                .as_str()
                .unwrap()
                .contains(tx_hash)
        );
        let receipt = receipts
            .get(envelope_hash)
            .unwrap()
            .expect("pending receipt");
        assert_eq!(receipt.status, ReceiptStatus::Pending);
        assert!(receipt.submitted);
        let rows = common::audit_rows(&profile);
        assert_eq!(common::rows_of_kind(&rows, "value_action_pending").len(), 1);
        assert!(common::rows_of_kind(&rows, "value_action_submitted").is_empty());
        let pending = window.pending_reservations(&profile).unwrap();
        if matches!(tool, Tool::Withdraw) {
            // Withdrawal carries a non-debit leg, so this spending cap reserves nothing.
            assert!(pending.is_empty());
        } else {
            assert_eq!(pending.len(), 1, "the debit reserves its spending window");
            assert_eq!(pending[0].id, *envelope_hash);
            assert_eq!(pending[0].tx_hash, *tx_hash);
        }
        assert_window_total(&window, &profile, &profile_name, tool);
        confirming.store(true, Ordering::SeqCst);
    } else {
        assert_ne!(result.is_error, Some(true), "{response}");
        assert_eq!(
            receipts.get(envelope_hash).unwrap().unwrap().status,
            ReceiptStatus::Success
        );
        assert!(window.pending_reservations(&profile).unwrap().is_empty());
        assert_eq!(
            common::rows_of_kind(&common::audit_rows(&profile), "value_action_submitted").len(),
            1
        );
    }
    for _ in 0..2 {
        let status = server
            .call_stellar_transaction_status(StellarTransactionStatusArgs {
                chain_id: "stellar:testnet".to_owned(),
                tx_hash: tx_hash.clone(),
            })
            .await
            .unwrap();
        let status_json = result_json(&status);
        assert_ne!(status.is_error, Some(true), "{status_json}");
        assert_eq!(
            status_json["data"]["record"]["envelope_hash"],
            *envelope_hash
        );
        assert_eq!(status_json["data"]["record"]["status"], "success");
        assert_eq!(status_json["data"]["record"]["reservation_open"], false);
        assert_eq!(
            receipts.get(envelope_hash).unwrap().unwrap().status,
            ReceiptStatus::Success
        );
        assert!(window.pending_reservations(&profile).unwrap().is_empty());
        assert_window_total(&window, &profile, &profile_name, tool);
        let rows = common::audit_rows(&profile);
        assert_eq!(common::rows_of_kind(&rows, "value_action_pending").len(), 1);
        assert_eq!(
            common::rows_of_kind(&rows, "value_action_submitted").len(),
            1,
            "settlement is idempotent"
        );
    }
}

#[tokio::test]
#[serial]
async fn trade_timeout_retains_and_settles_record() {
    exercise(Tool::Trade, false).await;
}
#[tokio::test]
#[serial]
async fn deposit_timeout_retains_and_settles_record() {
    exercise(Tool::Deposit, false).await;
}
#[tokio::test]
#[serial]
async fn withdraw_timeout_retains_and_settles_record() {
    exercise(Tool::Withdraw, false).await;
}
#[tokio::test]
#[serial]
async fn trade_confirmation_settles_record() {
    exercise(Tool::Trade, true).await;
}
#[tokio::test]
#[serial]
async fn deposit_confirmation_settles_record() {
    exercise(Tool::Deposit, true).await;
}
#[tokio::test]
#[serial]
async fn withdraw_confirmation_settles_record() {
    exercise(Tool::Withdraw, true).await;
}
