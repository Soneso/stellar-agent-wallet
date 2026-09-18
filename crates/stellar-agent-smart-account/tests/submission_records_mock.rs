//! Durable records for policy-sized bundles and timelock executions.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixture construction and assertions"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::policy::Decision;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_network::policy_state::PersistedWindowStore;
use stellar_agent_network::submission_record::WalletSubmissionRecorder;
use stellar_agent_smart_account::SaError;
use stellar_agent_smart_account::multicall::{
    MULTICALL_WASM_SHA256, MulticallInvocation, MulticallRegistry, MulticallRegistryEntry,
    MulticallSubmitArgs, submit_multicall_bundle,
};
use stellar_agent_smart_account::submit::ResolvedFeePerOp;
use stellar_agent_test_support::signed_envelope::{
    account_id_for_seed, get_network_result, send_transaction_hash_hex,
};
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
use stellar_xdr::{
    ContractId, Hash, HostFunction, Limits, OperationBody, ReadXdr, ScAddress, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, VecM, WriteXdr,
};
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_helpers;

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const PROFILE: &str = "submission-records-mock";
const SEED: [u8; 32] = [0x43; 32];

fn contract(byte: u8) -> String {
    stellar_strkey::Contract([byte; 32]).to_string().to_string()
}

struct Rpc {
    poll_status: &'static str,
    sends: Arc<AtomicUsize>,
    sent_hash: Arc<Mutex<String>>,
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(PASSPHRASE),
            "getLatestLedger" => {
                json!({"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27})
            }
            "getLedgerEntries" => {
                let source = account_id_for_seed(SEED);
                if body["params"]["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|key| key.as_str() == Some(rpc_helpers::account_key_xdr(&source).as_str()))
                {
                    rpc_helpers::build_ledger_entries_account(&source)
                } else {
                    let hash: [u8; 32] = hex::decode(MULTICALL_WASM_SHA256)
                        .unwrap()
                        .try_into()
                        .unwrap();
                    rpc_helpers::build_ledger_entries_contract_instance(
                        &ScAddress::Contract(ContractId(Hash([0x45; 32]))),
                        hash,
                    )
                }
            }
            "simulateTransaction" => {
                let envelope = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let TransactionEnvelope::Tx(tx) = envelope else {
                    panic!("expected v1 envelope")
                };
                let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                    panic!("expected invocation")
                };
                let HostFunction::InvokeContract(invoke) = &op.host_function else {
                    panic!("expected contract function")
                };
                let function = invoke.function_name.0.to_utf8_string().unwrap();
                let value = match function.as_str() {
                    "get_operation_ledger" => ScVal::U32(500),
                    "hash_operation" => ScVal::Bytes(vec![0x46; 32].try_into().unwrap()),
                    "exec" => ScVal::Vec(Some(vec![ScVal::Void, ScVal::Void].try_into().unwrap())),
                    _ => ScVal::Void,
                };
                let mut result = rpc_helpers::build_simulate_response(
                    &value.to_xdr_base64(Limits::none()).unwrap(),
                );
                let auth = if !op.auth.is_empty() {
                    op.auth.to_vec()
                } else if function == "exec" {
                    vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: ScAddress::Contract(ContractId(Hash([0x44; 32]))),
                            nonce: 7,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: SorobanAuthorizedInvocation {
                            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                            sub_invocations: VecM::default(),
                        },
                    }]
                } else {
                    Vec::new()
                };
                result["results"][0]["auth"] = json!(
                    auth.iter()
                        .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
                        .collect::<Vec<_>>()
                );
                result
            }
            "sendTransaction" => {
                self.sends.fetch_add(1, Ordering::SeqCst);
                let hash = send_transaction_hash_hex(&body, PASSPHRASE);
                *self.sent_hash.lock().unwrap() = hash.clone();
                json!({"status": "PENDING", "hash": hash, "latestLedger": 1000, "latestLedgerCloseTime": "1234567890"})
            }
            "getTransaction" => json!({
                "status": self.poll_status, "latestLedger": 1001, "oldestLedger": 1,
                "ledger": if self.poll_status == "SUCCESS" { Some(1001) } else { None },
                "createdAt": if self.poll_status == "SUCCESS" {
                    Some((stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000).to_string())
                } else { None },
            }),
            other => panic!("unexpected RPC method: {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

struct Fixture {
    _root: TempDir,
    _home: StellarAgentHomeGuard,
    profile: Profile,
    audit: Arc<Mutex<AuditWriter>>,
    registry: MulticallRegistry,
}

impl Fixture {
    fn new() -> Self {
        keyring_mock::install().unwrap();
        let root = TempDir::new().unwrap();
        let home = StellarAgentHomeGuard::new(root.path());
        let mut profile = Profile::builder_testnet("svc", PROFILE, "nonce", PROFILE)
            .with_profile_name(PROFILE)
            .build();
        profile.audit_log_path = root.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        let mut registry = MulticallRegistry::load(&root.path().join("networks.toml")).unwrap();
        registry
            .register(MulticallRegistryEntry {
                network_passphrase: PASSPHRASE.to_owned(),
                address: contract(0x45),
                wasm_sha256: MULTICALL_WASM_SHA256.to_owned(),
            })
            .unwrap();
        Self {
            _root: root,
            _home: home,
            profile,
            audit,
            registry,
        }
    }

    fn engine(&self) -> Arc<PolicyEngineV1> {
        let engine = PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "wallet_multicall".to_owned(),
                        chain: "*".to_owned(),
                    },
                    criteria: vec![Box::new(BundlePerPeriodCapCriterion::new(
                        contract(0x47),
                        Window::parse("1d").unwrap(),
                        100,
                    ))],
                    decision: Decision::Allow,
                    allow_opaque_signing: false,
                }],
                signature: None,
            },
            PROFILE.to_owned(),
        );
        PersistedWindowStore::for_profile(PROFILE)
            .load_into(PROFILE, &self.profile, engine.state_store())
            .unwrap();
        Arc::new(engine)
    }

    fn bundle(&self) -> Vec<MulticallInvocation> {
        (0..2)
            .map(|_| MulticallInvocation {
                target_contract: contract(0x47),
                fn_name: "transfer".to_owned(),
                args_json: json!([
                    account_id_for_seed(SEED),
                    account_id_for_seed([0x48; 32]),
                    "30"
                ]),
            })
            .collect()
    }

    #[allow(
        clippy::result_large_err,
        reason = "preserve the submission API's typed error for assertions"
    )]
    async fn multicall(
        &self,
        url: &str,
    ) -> Result<stellar_agent_smart_account::multicall::MulticallResult, SaError> {
        let signer = SoftwareSigningKey::new_from_bytes(SEED);
        submit_multicall_bundle(
            MulticallSubmitArgs {
                smart_account: &contract(0x44),
                rule_id: 0,
                bundle: self.bundle(),
                signer: &signer,
                primary_rpc_url: url,
                secondary_rpc_url: url,
                network_passphrase: PASSPHRASE,
                policy_engine: self.engine(),
                profile: &self.profile,
                audit_writer: Some(Arc::clone(&self.audit)),
                timeout: Duration::from_secs(2),
                fee: ResolvedFeePerOp::default(),
                chain_id: "stellar:testnet",
                request_id: "multicall-record",
            },
            &self.registry,
        )
        .await
    }

    fn rows(&self, kind: &str) -> Vec<Value> {
        std::fs::read_to_string(&self.profile.audit_log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|row| row["kind"] == kind)
            .collect()
    }

    fn total(&self) -> (i128, u32) {
        let state = PolicyStateStore::new();
        PersistedWindowStore::for_profile(PROFILE)
            .load_into(PROFILE, &self.profile, &state)
            .unwrap();
        state
            .query_window(
                &StateKey::new(PROFILE, 1, &contract(0x47), 86_400),
                stellar_agent_core::timefmt::now_unix_ms().unwrap(),
            )
            .unwrap()
    }
}

async fn rpc(status: &'static str) -> (MockServer, Arc<AtomicUsize>, Arc<Mutex<String>>) {
    let server = MockServer::start().await;
    let sends = Arc::new(AtomicUsize::new(0));
    let sent_hash = Arc::new(Mutex::new(String::new()));
    Mock::given(method("POST"))
        .respond_with(Rpc {
            poll_status: status,
            sends: Arc::clone(&sends),
            sent_hash: Arc::clone(&sent_hash),
        })
        .mount(&server)
        .await;
    (server, sends, sent_hash)
}

#[tokio::test]
#[serial]
async fn timed_out_multicall_reserves_sized_legs_and_denies_a_second_bundle() {
    let fixture = Fixture::new();
    let (server, sends, sent_hash) = rpc("NOT_FOUND").await;
    let err = fixture.multicall(&server.uri()).await.unwrap_err();
    assert_eq!(err.wire_code(), "submission.tx_timeout", "{err:?}");
    let SaError::SubmissionUnresolved {
        tx_hash: Some(tx_hash),
        envelope_hash: Some(envelope_hash),
        ..
    } = err
    else {
        panic!("timeout must retain submission identity")
    };
    assert_eq!(tx_hash, *sent_hash.lock().unwrap());
    assert_eq!(tx_hash.len(), 64);
    let receipt = ReceiptStore::open(PROFILE)
        .unwrap()
        .get(&envelope_hash)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert!(receipt.submitted);
    assert_eq!(
        PersistedWindowStore::for_profile(PROFILE)
            .pending_reservations(&fixture.profile)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(fixture.total(), (60, 2));
    let rows = fixture.rows("value_action_pending");
    assert_eq!(rows.len(), 1);
    let legs = rows[0]["legs"].as_array().unwrap();
    assert_eq!(legs.len(), 2);
    for leg in legs {
        assert_eq!(leg["amount"], "30");
        assert_eq!(leg["asset"], contract(0x47));
    }
    let second = fixture.multicall(&server.uri()).await.unwrap_err();
    assert!(
        matches!(
            second,
            SaError::MulticallFailed {
                phase: "policy_gate",
                ..
            }
        ),
        "{second:?}"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 1);
}

/// The applying ledger's close time dates each confirmed leg, so a complete
/// success answer closes the holds and preserves each debit exactly once.
#[tokio::test]
#[serial]
async fn confirmed_multicall_counts_each_leg_once() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    fixture.multicall(&server.uri()).await.unwrap();
    assert_eq!(fixture.total(), (60, 2));
    assert!(
        PersistedWindowStore::for_profile(PROFILE)
            .pending_reservations(&fixture.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fixture.rows("value_action_pending").len(), 1);
    assert_eq!(fixture.rows("value_action_submitted").len(), 1);
    assert_eq!(sends.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[serial]
async fn timed_out_timelock_execute_keeps_receipt_and_pending_row() {
    let fixture = Fixture::new();
    let (server, sends, sent_hash) = rpc("UNKNOWN").await;
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let recorder = WalletSubmissionRecorder::new(
        &fixture.profile,
        PROFILE,
        "stellar_smart_account_timelock_execute",
        Some("stellar:testnet".to_owned()),
        Vec::new(),
        Vec::new(),
        ReceiptStore::open(PROFILE).unwrap(),
        PersistedWindowStore::for_profile(PROFILE),
        Some(Arc::clone(&fixture.audit)),
        None,
        "timelock-record",
        stellar_agent_core::timefmt::now_unix_ms().unwrap(),
    );
    let operation =
        stellar_agent_smart_account::timelock::TimelockOperationId::from_bytes([0x46; 32]);
    let result = stellar_agent_smart_account::timelock::execute(
        stellar_agent_smart_account::timelock::TimelockExecuteArgs::builder()
            .timelock_contract_strkey(&contract(0x49))
            .target_strkey(&contract(0x47))
            .function("transfer")
            .salt([0x50; 32])
            .signer(&signer)
            .primary_rpc_url(&server.uri())
            .secondary_rpc_url(&server.uri())
            .network_passphrase(PASSPHRASE)
            .audit_writer(&fixture.audit)
            .request_id("timelock-record")
            .expected_operation_id(&operation)
            .submission_recorder(&recorder)
            .build(),
    )
    .await;
    let error = result.unwrap_err();
    assert_eq!(error.wire_code(), "submission.tx_timeout", "{error:?}");
    let hash = sent_hash.lock().unwrap().clone();
    let receipt = ReceiptStore::open(PROFILE)
        .unwrap()
        .find_by_tx_hash(&hash)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
    assert!(receipt.submitted);
    assert_eq!(fixture.rows("value_action_pending").len(), 1);
    assert!(fixture.rows("value_action_submitted").is_empty());
    assert_eq!(sends.load(Ordering::SeqCst), 1);
}
