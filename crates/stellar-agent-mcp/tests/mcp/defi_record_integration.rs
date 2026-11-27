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
    atomic::{AtomicBool, AtomicUsize, Ordering},
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
    timing::{ClockHold, drive_call, wait_until},
};
use stellar_xdr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, ExtensionPoint,
    Hash, HostFunction, Int128Parts, LedgerEntryData, Limits, OperationBody, ReadXdr, ScAddress,
    ScContractInstance, ScMap, ScMapEntry, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, TransactionEnvelope, WriteXdr,
};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers::method};
#[path = "../../../stellar-agent-smart-account/tests/smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
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

fn symbol(case: &str, value: &str) -> ScVal {
    ScVal::Symbol(ScSymbol(value.try_into().unwrap_or_else(|e| {
        panic!("case {case}: ScSymbol encode failed: {e}")
    })))
}

fn vector(case: &str, values: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(values.try_into().unwrap_or_else(|e| {
        panic!("case {case}: ScVal Vec encode failed: {e}")
    })))
}

fn map(case: &str, entries: Vec<(ScVal, ScVal)>) -> ScMap {
    let mut entries: Vec<_> = entries
        .into_iter()
        .map(|(key, val)| ScMapEntry { key, val })
        .collect();
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    ScMap(
        entries
            .try_into()
            .unwrap_or_else(|e| panic!("case {case}: ScMap encode failed: {e}")),
    )
}

fn vault_entry(case: &str) -> (String, String) {
    let mut storage = vec![
        (
            vector(case, vec![symbol(case, "Upgradable")]),
            ScVal::Bool(false),
        ),
        (
            vector(case, vec![symbol(case, "TotalAssets")]),
            ScVal::U32(1),
        ),
        (
            vector(case, vec![symbol(case, "AssetStrategySet"), ScVal::U32(0)]),
            ScVal::Map(Some(map(
                case,
                vec![
                    (symbol(case, "address"), ScVal::Address(address(TOKEN))),
                    (symbol(case, "strategies"), vector(case, vec![])),
                ],
            ))),
        ),
    ];
    for role in [
        "Manager",
        "EmergencyManager",
        "RebalanceManager",
        "VaultFeeReceiver",
    ] {
        storage.push((
            vector(case, vec![symbol(case, role)]),
            ScVal::Address(address(WALLET)),
        ));
    }
    let entry = LedgerEntryData::ContractData(ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: address(VAULT),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(DEFINDEX_VAULT_WASM_HASH)),
            storage: Some(map(case, storage)),
        }),
    });
    (
        rpc_helpers::contract_instance_key_xdr(&address(VAULT)),
        entry
            .to_xdr_base64(Limits::none())
            .unwrap_or_else(|e| panic!("case {case}: vault entry XDR encode failed: {e}")),
    )
}

struct Rpc {
    case: &'static str,
    entries: Vec<(String, String)>,
    confirming: Arc<AtomicBool>,
    sent: Arc<Mutex<Vec<(String, String)>>>,
    /// The number of confirmation polls received.
    polls: Arc<AtomicUsize>,
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let case = self.case;
        let body: Value = serde_json::from_slice(&request.body)
            .unwrap_or_else(|e| panic!("case {case}: RPC request body must be JSON: {e}"));
        let mut delegate = crate::common::TimeoutRpc::new(self.entries.clone());
        if self.confirming.load(Ordering::SeqCst) {
            delegate = delegate.confirming_in(1001);
        }
        match body["method"]
            .as_str()
            .unwrap_or_else(|| panic!("case {case}: RPC request missing method: {body}"))
        {
            "getLatestLedger" => {
                return ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0", "id": body["id"], "result": {"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27}
                }));
            }
            "simulateTransaction" => {
                let tx_b64 = body["params"]["transaction"]
                    .as_str()
                    .unwrap_or_else(|| panic!("case {case}: simulate missing transaction: {body}"));
                let TransactionEnvelope::Tx(tx) =
                    TransactionEnvelope::from_xdr_base64(tx_b64, Limits::none()).unwrap_or_else(
                        |e| panic!("case {case}: simulate envelope decode failed: {e}"),
                    )
                else {
                    panic!("case {case}: expected v1 envelope");
                };
                let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                    panic!("case {case}: expected invoke operation");
                };
                let HostFunction::InvokeContract(invoke) = &op.host_function else {
                    panic!("case {case}: expected contract function");
                };
                let function = invoke
                    .function_name
                    .0
                    .to_utf8_string()
                    .unwrap_or_else(|e| panic!("case {case}: function name UTF-8: {e}"));
                let quote = function == "router_get_amounts_out";
                assert!(
                    quote
                        || matches!(
                            function.as_str(),
                            "swap_exact_tokens_for_tokens" | "deposit" | "withdraw"
                        ),
                    "case {case}: unexpected simulated function: {function}"
                );
                let value = if quote {
                    vector(
                        case,
                        vec![
                            ScVal::I128(Int128Parts { hi: 0, lo: 30 }),
                            ScVal::I128(Int128Parts { hi: 0, lo: 30 }),
                        ],
                    )
                } else {
                    ScVal::Void
                };
                let mut simulation = rpc_helpers::build_simulate_response(
                    &value
                        .to_xdr_base64(Limits::none())
                        .unwrap_or_else(|e| panic!("case {case}: ScVal encode failed: {e}")),
                );
                let auth = if quote {
                    vec![]
                } else if !op.auth.is_empty() {
                    op.auth.to_vec()
                } else {
                    vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: address(WALLET),
                            nonce: 7,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: SorobanAuthorizedInvocation {
                            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                            sub_invocations: Default::default(),
                        },
                    }]
                };
                simulation["results"][0]["auth"] = json!(
                    auth.iter()
                        .map(
                            |entry| entry.to_xdr_base64(Limits::none()).unwrap_or_else(|e| {
                                panic!("case {case}: auth entry encode failed: {e}")
                            })
                        )
                        .collect::<Vec<_>>()
                );
                delegate = delegate.with_simulate(simulation);
            }
            "sendTransaction" => {
                let envelope = body["params"]["transaction"]
                    .as_str()
                    .unwrap_or_else(|| panic!("case {case}: sendTransaction missing transaction"));
                self.sent
                    .lock()
                    .unwrap_or_else(|e| panic!("case {case}: sent lock poisoned: {e}"))
                    .push((
                        send_transaction_hash_hex(&body, PASSPHRASE),
                        envelope_hash_hex(envelope),
                    ));
            }
            "getTransaction" => {
                self.polls.fetch_add(1, Ordering::SeqCst);
            }
            "getNetwork" | "getFeeStats" | "getLedgerEntries" => {}
            other => panic!("case {case}: unexpected RPC method: {other}"),
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
    /// The signer seed. Its signer account is the keyring account name, and
    /// `install_test_audit_key` names the audit log after it. That name and log
    /// path must stay distinct from every other test in the process. The audit
    /// writer registry holds one log path and key per profile name.
    fn seed(self, confirmed: bool) -> [u8; 32] {
        [match self {
            Self::Trade => 0x91,
            Self::Deposit => 0x93,
            Self::Withdraw => 0x95,
        } + u8::from(confirmed); 32]
    }

    fn name(self) -> &'static str {
        match self {
            Self::Trade => "stellar_dex_trade",
            Self::Deposit => "stellar_defindex_vault_deposit",
            Self::Withdraw => "stellar_defindex_vault_withdraw",
        }
    }

    async fn call(self, case: &str, server: &WalletServer) -> rmcp::model::CallToolResult {
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
        result.unwrap_or_else(|e| panic!("case {case}: {} call failed: {e}", self.name()))
    }
}

fn result_json(case: &str, result: &rmcp::model::CallToolResult) -> Value {
    let text = &result
        .content
        .first()
        .unwrap_or_else(|| panic!("case {case}: result missing content block"))
        .as_text()
        .unwrap_or_else(|| panic!("case {case}: result content block is not text"))
        .text;
    serde_json::from_str(text)
        .unwrap_or_else(|e| panic!("case {case}: result content is not JSON: {e}: {text}"))
}

fn install_test_nonce_key(case: &str) {
    keyring_core::Entry::new("n-svc", "n-acct")
        .unwrap_or_else(|e| panic!("case {case}: nonce Entry::new failed: {e}"))
        .set_password(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]))
        .unwrap_or_else(|e| panic!("case {case}: nonce set_password failed: {e}"));
}

fn assert_window_total(
    case: &str,
    window: &PersistedWindowStore,
    profile: &Profile,
    profile_name: &str,
    tool: Tool,
) {
    let state = PolicyStateStore::new();
    window
        .load_into(profile_name, profile, &state)
        .unwrap_or_else(|e| panic!("case {case}: window load_into failed: {e}"));
    let key = StateKey::new(
        profile_name,
        1,
        &stellar_agent_core::policy::v1::value::asset_normalise(&contract(TOKEN)),
        86_400,
    );
    let now = stellar_agent_core::timefmt::now_unix_ms()
        .unwrap_or_else(|e| panic!("case {case}: now_unix_ms failed: {e}"));
    let expected = if matches!(tool, Tool::Withdraw) {
        (0, 0)
    } else {
        (QUANTITY, 1)
    };
    assert_eq!(
        state
            .query_window(&key, now)
            .unwrap_or_else(|e| panic!("case {case}: query_window failed: {e}")),
        expected,
        "case {case}: the persisted cap accounts for this submission exactly once"
    );
}

/// A signer-load failure a case puts at the profile's signer coordinate.
#[derive(Clone, Copy)]
enum SignerFault {
    /// No entry at the coordinate.
    Missing,
    /// The entry holds the seed of another account.
    OtherKey,
    /// The credential store fails the read with backend text of its own.
    StoreFailure,
}

impl SignerFault {
    /// Added to the tool's seed byte. Each fault gets its own signer account,
    /// so its audit log name stays distinct from every other case in the
    /// process.
    fn seed_offset(self) -> u8 {
        match self {
            Self::Missing => 6,
            Self::OtherKey => 7,
            Self::StoreFailure => 13,
        }
    }
}

/// Backend text the injected store failure carries; no envelope may echo it.
const BACKEND_TEXT: &str = "backend-sentinel-never-render";

/// The seed of the account whose secret the `OtherKey` fault stores.
const OTHER_SEED: [u8; 32] = [0x2f; 32];

fn secret_strkey(seed: [u8; 32]) -> String {
    stellar_strkey::ed25519::PrivateKey(seed)
        .as_unredacted()
        .to_string()
        .to_string()
}

/// Runs `tool` against the fixture endpoint and checks its record.
///
/// The settling tests run on a paused clock that this holds still, so the
/// pre-submit deadline and the confirmation deadline both start at the
/// instant the call starts, however long the reads, simulations, and
/// signatures take in real time. A timeout case moves the clock by the submit
/// timeout only once the send and the first confirmation poll have reached
/// the endpoint.
#[allow(
    clippy::too_many_lines,
    reason = "one scenario helper exercises every DeFi settlement and signer-fault case"
)]
async fn exercise(
    case: &'static str,
    tool: Tool,
    initially_confirmed: bool,
    fault: Option<SignerFault>,
) {
    let _hold = ClockHold::new();
    let _root = crate::common::isolated_data_root_for(case);
    keyring_mock::install()
        .unwrap_or_else(|e| panic!("case {case}: keyring_mock::install failed: {e}"));
    install_test_nonce_key(case);
    let seed = match fault {
        None => tool.seed(initially_confirmed),
        Some(fault) => [tool.seed(initially_confirmed)[0] + fault.seed_offset(); 32],
    };
    let source = account_id_for_seed(seed);
    let signer_seed = secret_strkey(seed);
    let stored_seed = match fault {
        None | Some(SignerFault::StoreFailure) => Some(signer_seed.clone()),
        Some(SignerFault::OtherKey) => Some(secret_strkey(OTHER_SEED)),
        Some(SignerFault::Missing) => None,
    };
    if let Some(stored_seed) = &stored_seed {
        keyring_core::Entry::new("svc", &source)
            .unwrap_or_else(|e| panic!("case {case}: signer Entry::new failed: {e}"))
            .set_password(stored_seed)
            .unwrap_or_else(|e| panic!("case {case}: signer set_password failed: {e}"));
    }
    crate::common::store_signer_identity_for("svc", &source, seed, case);
    if matches!(fault, Some(SignerFault::StoreFailure)) {
        keyring_mock::inject_error(
            "svc",
            &source,
            keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(BACKEND_TEXT))),
        )
        .unwrap_or_else(|e| panic!("case {case}: inject_error failed: {e}"));
    }
    let mock = MockServer::start().await;
    let confirming = Arc::new(AtomicBool::new(initially_confirmed));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let polls = Arc::new(AtomicUsize::new(0));
    let router = ScAddress::Contract(ContractId(Hash(
        stellar_strkey::Contract::from_string(SOROSWAP_ROUTER_ADDRESS_TESTNET)
            .unwrap_or_else(|e| panic!("case {case}: router strkey decode failed: {e}"))
            .0,
    )));
    Mock::given(method("POST"))
        .respond_with(Rpc {
            case,
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
                vault_entry(case),
            ],
            confirming: Arc::clone(&confirming),
            sent: Arc::clone(&sent),
            polls: Arc::clone(&polls),
        })
        .mount(&mock)
        .await;
    let mut profile = crate::common::timeout_profile_for(&mock.uri(), &source, case);
    profile.secondary_rpc_url = Some(stellar_agent_test_support::second_loopback_host(
        &mock.uri(),
    ));
    let mut server = WalletServer::new(profile.clone())
        .unwrap_or_else(|e| panic!("case {case}: WalletServer::new failed: {e}"));
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
                    Window::parse("1d")
                        .unwrap_or_else(|e| panic!("case {case}: Window::parse failed: {e}")),
                    1000,
                ))],
                decision: Decision::Allow,
                allow_opaque_signing: false,
            }],
        },
        profile_name.clone(),
    )));
    let result = if initially_confirmed || fault.is_some() {
        tool.call(case, &server).await
    } else {
        let submit_timeout = profile.submit_timeout();
        // The joined run is bounded in real time, so a deadline the advance
        // does not reach fails rather than leaving the call pending.
        drive_call(tool.call(case, &server), |_probe| async {
            let label = format!("case {case}: the send and the first confirmation poll");
            wait_until(&label, || {
                !sent
                    .lock()
                    .unwrap_or_else(|e| panic!("case {case}: sent lock poisoned: {e}"))
                    .is_empty()
                    && polls.load(Ordering::SeqCst) > 0
            })
            .await;
            tokio::time::advance(submit_timeout).await;
        })
        .await
    };
    let response = result_json(case, &result);
    let sent = sent
        .lock()
        .unwrap_or_else(|e| panic!("case {case}: sent lock poisoned: {e}"))
        .clone();
    if let Some(fault) = fault {
        let (code, message, text) = crate::common::assert_business_envelope_for(&result, case);
        let (expected_code, expected_message) = match fault {
            SignerFault::Missing => (
                "auth.keyring_not_found",
                "the configured keyring entry must exist; provision or select the required \
                 entry."
                    .to_owned(),
            ),
            SignerFault::OtherKey => (
                "auth.signer_key_mismatch",
                format!(
                    "signing key public key '{}' does not match the expected signing account '{source}'",
                    account_id_for_seed(OTHER_SEED)
                ),
            ),
            SignerFault::StoreFailure => (
                "auth.keyring_platform_error",
                "keyring operation failed: read unknown credential store: \
                 credential store operation failed"
                    .to_owned(),
            ),
        };
        assert_eq!(code, expected_code, "case {case} ({}): {text}", tool.name());
        assert_eq!(
            message,
            expected_message,
            "case {case} ({}): {text}",
            tool.name()
        );
        assert!(
            response["error"].get("details").is_none(),
            "case {case}: {text}"
        );
        if !matches!(fault, SignerFault::OtherKey) {
            assert!(!text.contains(&source), "case {case}: {text}");
        }
        assert!(!text.contains(&signer_seed), "case {case}: {text}");
        if let Some(stored_seed) = &stored_seed {
            assert!(!text.contains(stored_seed.as_str()), "case {case}: {text}");
        }
        assert!(!text.contains(BACKEND_TEXT), "case {case}: {text}");
        assert!(
            sent.is_empty(),
            "case {case}: {} must not submit",
            tool.name()
        );
        // The vault tools read the pinned vault before the gate; nothing is
        // simulated or sent once the signer fails to load.
        let methods: Vec<String> = mock
            .received_requests()
            .await
            .unwrap_or_else(|| panic!("case {case}: mock request recording disabled"))
            .iter()
            .map(|request| {
                let body: Value = serde_json::from_slice(&request.body)
                    .unwrap_or_else(|e| panic!("case {case}: recorded RPC body JSON: {e}"));
                body["method"]
                    .as_str()
                    .unwrap_or_else(|| panic!("case {case}: recorded RPC missing method: {body}"))
                    .to_owned()
            })
            .collect();
        let reads_vault = !matches!(tool, Tool::Trade);
        assert_eq!(
            !methods.is_empty(),
            reads_vault,
            "case {case} ({}): {methods:?}",
            tool.name()
        );
        assert!(
            methods.iter().all(|method| method == "getLedgerEntries"),
            "case {case} ({}): {methods:?}",
            tool.name()
        );
        return;
    }
    assert_eq!(
        sent.len(),
        1,
        "case {case}: {} must send once: {response}",
        tool.name()
    );
    let (tx_hash, envelope_hash) = &sent[0];
    let receipts = ReceiptStore::open(&profile_name)
        .unwrap_or_else(|e| panic!("case {case}: ReceiptStore::open failed: {e}"));
    let window = PersistedWindowStore::for_profile(&profile_name);
    if !initially_confirmed {
        assert_eq!(result.is_error, Some(true), "case {case}");
        assert_eq!(
            response["error"]["code"], "submission.tx_timeout",
            "case {case}: {response}"
        );
        let details = &response["error"]["details"];
        assert_eq!(details["tx_hash"], *tx_hash, "case {case}");
        assert_eq!(tx_hash.len(), 64, "case {case}");
        assert!(
            tx_hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "case {case}"
        );
        assert_eq!(details["envelope_hash"], *envelope_hash, "case {case}");
        assert_eq!(details["outcome"], "unknown", "case {case}");
        assert_eq!(
            details["reconcile_with"], "stellar_transaction_status",
            "case {case}"
        );
        assert!(
            !response["error"]["message"]
                .as_str()
                .unwrap_or_else(|| panic!("case {case}: missing error.message: {response}"))
                .contains(tx_hash),
            "case {case}"
        );
        let receipt = receipts
            .get(envelope_hash)
            .unwrap_or_else(|e| panic!("case {case}: receipts.get failed: {e}"))
            .unwrap_or_else(|| panic!("case {case}: missing pending receipt"));
        assert_eq!(receipt.status, ReceiptStatus::Pending, "case {case}");
        assert!(receipt.submitted, "case {case}");
        let rows = crate::common::audit_rows_for(&profile, case);
        assert_eq!(
            crate::common::rows_of_kind(&rows, "value_action_pending").len(),
            1,
            "case {case}"
        );
        assert!(
            crate::common::rows_of_kind(&rows, "value_action_submitted").is_empty(),
            "case {case}"
        );
        let pending = window
            .pending_reservations(&profile)
            .unwrap_or_else(|e| panic!("case {case}: pending_reservations failed: {e}"));
        if matches!(tool, Tool::Withdraw) {
            // Withdrawal carries a non-debit leg, so this spending cap reserves nothing.
            assert!(pending.is_empty(), "case {case}");
        } else {
            assert_eq!(
                pending.len(),
                1,
                "case {case}: the debit reserves its spending window"
            );
            assert_eq!(pending[0].id, *envelope_hash, "case {case}");
            assert_eq!(pending[0].tx_hash, *tx_hash, "case {case}");
        }
        assert_window_total(case, &window, &profile, &profile_name, tool);
        confirming.store(true, Ordering::SeqCst);
    } else {
        assert_ne!(result.is_error, Some(true), "case {case}: {response}");
        assert_eq!(
            receipts
                .get(envelope_hash)
                .unwrap_or_else(|e| panic!("case {case}: receipts.get failed: {e}"))
                .unwrap_or_else(|| panic!("case {case}: missing confirmed receipt"))
                .status,
            ReceiptStatus::Success,
            "case {case}"
        );
        assert_eq!(
            window
                .pending_reservations(&profile)
                .unwrap_or_else(|e| panic!("case {case}: pending_reservations failed: {e}"))
                .is_empty(),
            matches!(tool, Tool::Withdraw),
            "case {case}"
        );
        assert_eq!(
            crate::common::rows_of_kind(
                &crate::common::audit_rows_for(&profile, case),
                "value_action_submitted"
            )
            .len(),
            0,
            "case {case}"
        );
    }
    for _ in 0..2 {
        let status = server
            .call_stellar_transaction_status(StellarTransactionStatusArgs {
                chain_id: "stellar:testnet".to_owned(),
                tx_hash: Some(tx_hash.clone()),
                business_id: None,
                retry_recovery: false,
            })
            .await
            .unwrap_or_else(|e| panic!("case {case}: call_stellar_transaction_status failed: {e}"));
        let status_json = result_json(case, &status);
        assert_ne!(status.is_error, Some(true), "case {case}: {status_json}");
        assert_eq!(
            status_json["data"]["record"]["envelope_hash"], *envelope_hash,
            "case {case}"
        );
        assert_eq!(
            status_json["data"]["record"]["status"], "success",
            "case {case}"
        );
        assert_eq!(
            status_json["data"]["record"]["reservation_open"],
            !matches!(tool, Tool::Withdraw),
            "case {case}"
        );
        assert_eq!(
            receipts
                .get(envelope_hash)
                .unwrap_or_else(|e| panic!("case {case}: settled receipts.get failed: {e}"))
                .unwrap_or_else(|| panic!("case {case}: missing settled receipt"))
                .status,
            ReceiptStatus::Success,
            "case {case}"
        );
        assert_eq!(
            window
                .pending_reservations(&profile)
                .unwrap_or_else(|e| panic!("case {case}: settled pending_reservations failed: {e}"))
                .is_empty(),
            matches!(tool, Tool::Withdraw),
            "case {case}"
        );
        assert_window_total(case, &window, &profile, &profile_name, tool);
        let rows = crate::common::audit_rows_for(&profile, case);
        assert_eq!(
            crate::common::rows_of_kind(&rows, "value_action_pending").len(),
            1,
            "case {case}"
        );
        assert_eq!(
            crate::common::rows_of_kind(&rows, "value_action_submitted").len(),
            0,
            "case {case}: settlement is idempotent"
        );
    }
}

/// Trade, deposit, and withdraw submissions retain durable receipts, audit
/// rows, and spending reservations across both timeout and immediate
/// confirmation paths.
#[test]
#[serial]
fn defi_settlement_retains_and_settles_record() {
    const CASES: [(&str, Tool, bool); 6] = [
        ("trade_timeout", Tool::Trade, false),
        ("deposit_timeout", Tool::Deposit, false),
        ("withdraw_timeout", Tool::Withdraw, false),
        ("trade_confirmed", Tool::Trade, true),
        ("deposit_confirmed", Tool::Deposit, true),
        ("withdraw_confirmed", Tool::Withdraw, true),
    ];

    for (case, tool, initially_confirmed) in CASES {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap_or_else(|e| panic!("case {case}: paused runtime build failed: {e}"));
        runtime.block_on(exercise(case, tool, initially_confirmed, None));
    }
}

/// Trade, deposit, and withdraw report auth error codes without submitting or
/// leaking secrets when the signer entry is missing, mismatched, or failing.
#[tokio::test]
#[serial]
async fn defi_signer_faults_preserve_auth_errors() {
    const CASES: [(&str, Tool, SignerFault); 9] = [
        ("trade_missing_signer", Tool::Trade, SignerFault::Missing),
        (
            "deposit_missing_signer",
            Tool::Deposit,
            SignerFault::Missing,
        ),
        (
            "withdraw_missing_signer",
            Tool::Withdraw,
            SignerFault::Missing,
        ),
        (
            "trade_signer_key_mismatch",
            Tool::Trade,
            SignerFault::OtherKey,
        ),
        (
            "trade_keyring_platform_error",
            Tool::Trade,
            SignerFault::StoreFailure,
        ),
        (
            "deposit_signer_key_mismatch",
            Tool::Deposit,
            SignerFault::OtherKey,
        ),
        (
            "deposit_keyring_platform_error",
            Tool::Deposit,
            SignerFault::StoreFailure,
        ),
        (
            "withdraw_signer_key_mismatch",
            Tool::Withdraw,
            SignerFault::OtherKey,
        ),
        (
            "withdraw_keyring_platform_error",
            Tool::Withdraw,
            SignerFault::StoreFailure,
        ),
    ];

    for (case, tool, fault) in CASES {
        exercise(case, tool, false, Some(fault)).await;
    }
}
