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
use stellar_agent_core::audit_log::test_helpers::verified_audit_lines;
use stellar_agent_core::policy::Decision;
use stellar_agent_core::policy::v1::PolicyEngineV1;
use stellar_agent_core::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
use stellar_agent_core::policy::v1::criteria::state_store::{
    PolicyStateStore, StateKey, WindowEntry, WindowLimit,
};
use stellar_agent_core::policy::v1::loader::{PolicyDocument, PolicyRule, RuleMatch, ScopeId};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_network::policy_state::{PersistedWindowStore, SubmissionHold};
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
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock, second_loopback_host};
use stellar_xdr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, Limits, OperationBody, ReadXdr, ScAddress,
    ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, VecM, WriteXdr,
};
use tempfile::TempDir;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::rpc_mock_helpers as rpc_helpers;

#[path = "../common/pin_check_manager.rs"]
mod pin_check_manager;

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const PROFILE: &str = "submission-records-mock";
const SEED: [u8; 32] = [0x43; 32];

fn contract(byte: u8) -> String {
    stellar_strkey::Contract([byte; 32]).to_string().to_string()
}

/// The `{"scval": ...}` multicall argument of the address `strkey`, a G- or
/// C-strkey, encoded as a standard-base64 `ScVal::Address`.
fn scval_address(strkey: &str) -> Value {
    let address = match stellar_strkey::Strkey::from_string(strkey).unwrap() {
        stellar_strkey::Strkey::PublicKeyEd25519(key) => {
            ScAddress::Account(stellar_xdr::AccountId(
                stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(key.0)),
            ))
        }
        stellar_strkey::Strkey::Contract(contract) => {
            ScAddress::Contract(ContractId(Hash(contract.0)))
        }
        _ => panic!("not an address strkey"),
    };
    json!({"scval": ScVal::Address(address).to_xdr_base64(Limits::none()).unwrap()})
}

/// Runs once inside the mock RPC, on the first simulation.
type SimulateHook = Box<dyn FnOnce() + Send>;

struct Rpc {
    poll_status: &'static str,
    nonce: i64,
    sends: Arc<AtomicUsize>,
    sent_hash: Arc<Mutex<String>>,
    /// Runs once, on the first simulation: the point after the bundle gate
    /// has admitted the call and before its reservation is written.
    before_simulate: Arc<Mutex<Option<SimulateHook>>>,
    /// Whether the unsigned `exec` simulation authorizes one sub-invocation
    /// per inner call beneath the router's root invocation.
    exec_subtree: bool,
    extra_transfer: bool,
    fail_signed: bool,
    source_only: bool,
    on_signed_or_send: Option<Arc<dyn Fn() + Send + Sync>>,
    /// The envelopes this endpoint saw, in order.
    seen: Arc<Mutex<SeenEnvelopes>>,
}

/// The envelopes a mock endpoint received.
#[derive(Default)]
struct SeenEnvelopes {
    /// Each simulation that carried signed authorization entries.
    signed_simulations: Vec<TransactionEnvelope>,
    /// Each envelope sent with `sendTransaction`.
    sent: Vec<TransactionEnvelope>,
}

/// One authorized sub-invocation per inner call of the router's `exec`
/// arguments, in bundle order.
fn exec_subtree(invoke: &InvokeContractArgs) -> Vec<SorobanAuthorizedInvocation> {
    let Some(ScVal::Vec(Some(inners))) = invoke.args.get(1) else {
        return Vec::new();
    };
    inners
        .iter()
        .filter_map(|inner| {
            let ScVal::Vec(Some(parts)) = inner else {
                return None;
            };
            let (ScVal::Address(contract_address), ScVal::Symbol(function_name), ScVal::Vec(args)) =
                (parts.first()?, parts.get(1)?, parts.get(2)?)
            else {
                return None;
            };
            Some(SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: contract_address.clone(),
                    function_name: function_name.clone(),
                    args: args.clone().map(|args| args.0).unwrap_or_default(),
                }),
                sub_invocations: VecM::default(),
            })
        })
        .collect()
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
                if let Some(hook) = self.before_simulate.lock().unwrap().take() {
                    hook();
                }
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
                    "exec" => ScVal::Vec(Some(
                        vec![ScVal::Void; exec_subtree(invoke).len()]
                            .try_into()
                            .unwrap(),
                    )),
                    _ => ScVal::Void,
                };
                let mut result = rpc_helpers::build_simulate_response(
                    &value.to_xdr_base64(Limits::none()).unwrap(),
                );
                let auth = if !op.auth.is_empty() {
                    if let Some(hook) = &self.on_signed_or_send {
                        hook();
                    }
                    self.seen
                        .lock()
                        .unwrap()
                        .signed_simulations
                        .push(TransactionEnvelope::Tx(tx.clone()));
                    if self.fail_signed {
                        return ResponseTemplate::new(200).set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": {"error": "signed simulation refuses"}}));
                    }
                    op.auth.to_vec()
                } else if function == "exec" {
                    let sub_invocations = if self.exec_subtree {
                        let mut calls = exec_subtree(invoke);
                        if self.extra_transfer {
                            calls.push(SorobanAuthorizedInvocation {
                                function: SorobanAuthorizedFunction::ContractFn(
                                    InvokeContractArgs {
                                        contract_address: ScAddress::Contract(ContractId(Hash(
                                            [0x50; 32],
                                        ))),
                                        function_name: "transfer".try_into().unwrap(),
                                        args: vec![
                                            ScVal::Address(ScAddress::Contract(ContractId(Hash(
                                                [0x44; 32],
                                            )))),
                                            ScVal::Address(ScAddress::Contract(ContractId(Hash(
                                                [0x51; 32],
                                            )))),
                                            ScVal::I128(stellar_xdr::Int128Parts {
                                                hi: 0,
                                                lo: 1000,
                                            }),
                                        ]
                                        .try_into()
                                        .unwrap(),
                                    },
                                ),
                                sub_invocations: VecM::default(),
                            });
                        }
                        calls.try_into().unwrap()
                    } else {
                        VecM::default()
                    };
                    vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                            address: ScAddress::Contract(ContractId(Hash([0x44; 32]))),
                            nonce: self.nonce,
                            signature_expiration_ledger: 0,
                            signature: ScVal::Void,
                        }),
                        root_invocation: SorobanAuthorizedInvocation {
                            function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                            sub_invocations,
                        },
                    }]
                } else if self.source_only && value == ScVal::Void {
                    vec![SorobanAuthorizationEntry {
                        credentials: SorobanCredentials::SourceAccount,
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
                if let Some(hook) = &self.on_signed_or_send {
                    hook();
                }
                self.sends.fetch_add(1, Ordering::SeqCst);
                self.seen.lock().unwrap().sent.push(
                    TransactionEnvelope::from_xdr_base64(
                        body["params"]["transaction"].as_str().unwrap(),
                        Limits::none(),
                    )
                    .unwrap(),
                );
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

struct SpySigner {
    inner: stellar_agent_network::signing::test_doubles::CountingSigner,
    hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl SpySigner {
    fn sign_calls(&self) -> usize {
        self.inner.sign_calls()
    }
    fn observe(&self) {
        if let Some(hook) = self.hook.lock().unwrap().as_ref() {
            hook();
        }
    }
}

#[async_trait::async_trait]
impl stellar_agent_network::Signer for SpySigner {
    async fn public_key(
        &self,
    ) -> Result<stellar_strkey::ed25519::PublicKey, stellar_agent_core::WalletError> {
        self.inner.public_key().await
    }
    async fn sign_auth_digest(
        &self,
        payload: &stellar_agent_network::SmartAccountAuthDigest,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        self.observe();
        self.inner.sign_auth_digest(payload).await
    }
    async fn sign_tx_payload(
        &self,
        payload: &stellar_agent_network::TxSigningPayload,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        self.observe();
        self.inner.sign_tx_payload(payload).await
    }
    async fn sign_soroban_address_auth_payload(
        &self,
        payload: &stellar_agent_network::SorobanAuthPayload,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        self.observe();
        self.inner.sign_soroban_address_auth_payload(payload).await
    }
    async fn sign_message(
        &self,
        payload: &stellar_agent_network::MessagePayload,
    ) -> Result<[u8; 64], stellar_agent_core::WalletError> {
        self.inner.sign_message(payload).await
    }
    async fn sign_webauthn_assertion(
        &self,
        payload: &stellar_agent_network::SmartAccountAuthDigest,
        id: &[u8],
    ) -> Result<stellar_agent_network::WebAuthnAssertion, stellar_agent_core::WalletError> {
        self.observe();
        self.inner.sign_webauthn_assertion(payload, id).await
    }
}

struct Fixture {
    _root: TempDir,
    _home: StellarAgentHomeGuard,
    profile: Profile,
    audit: Arc<Mutex<AuditWriter>>,
    registry: MulticallRegistry,
    signer: SpySigner,
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
            signer: SpySigner {
                inner: stellar_agent_network::signing::test_doubles::CountingSigner::new(SEED),
                hook: Mutex::new(None),
            },
        }
    }

    fn restart(self) -> Self {
        let Self {
            _root: root,
            _home: home,
            profile,
            audit,
            registry,
            signer,
        } = self;
        drop((audit, registry, signer));
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(profile.audit_log_path.clone(), None).unwrap(),
        ));
        let mut registry = MulticallRegistry::load(&root.path().join("networks.toml")).unwrap();
        registry
            .register(MulticallRegistryEntry {
                network_passphrase: PASSPHRASE.into(),
                address: contract(0x45),
                wasm_sha256: MULTICALL_WASM_SHA256.into(),
            })
            .unwrap();
        Self {
            _root: root,
            _home: home,
            profile,
            audit,
            registry,
            signer: SpySigner {
                inner: stellar_agent_network::signing::test_doubles::CountingSigner::new(SEED),
                hook: Mutex::new(None),
            },
        }
    }

    fn engine(&self) -> Arc<PolicyEngineV1> {
        self.engine_for_chain("*")
    }

    fn engine_for_chain(&self, chain: &str) -> Arc<PolicyEngineV1> {
        let engine = PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules: vec![
                    PolicyRule {
                        r#match: RuleMatch {
                            tool: "wallet_multicall".to_owned(),
                            chain: chain.to_owned(),
                        },
                        criteria: vec![Box::new(BundlePerPeriodCapCriterion::new(
                            contract(0x47),
                            Window::parse("1d").expect("bundle cap window"),
                            100,
                        ))],
                        decision: Decision::Allow,
                        allow_opaque_signing: false,
                    },
                    PolicyRule {
                        r#match: RuleMatch {
                            tool: "*".to_owned(),
                            chain: "*".to_owned(),
                        },
                        criteria: Vec::new(),
                        decision: Decision::Allow,
                        allow_opaque_signing: false,
                    },
                ],
                signature: None,
            },
            PROFILE.to_owned(),
        );
        PersistedWindowStore::for_profile(PROFILE)
            .load_into(PROFILE, &self.profile, engine.state_store())
            .unwrap();
        Arc::new(engine)
    }

    fn per_call_engine(&self, cap: i128, allow_opaque_signing: bool) -> Arc<PolicyEngineV1> {
        use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
        Arc::new(PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                signature: None,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: "wallet_multicall".to_owned(),
                        chain: "stellar:testnet".to_owned(),
                    },
                    criteria: vec![Box::new(PerTxCapCriterion::new(contract(0x47), cap))],
                    decision: Decision::Allow,
                    allow_opaque_signing,
                }],
            },
            PROFILE.to_owned(),
        ))
    }

    fn bundle(&self) -> Vec<MulticallInvocation> {
        (0..2)
            .map(|_| MulticallInvocation {
                target_contract: contract(0x47),
                fn_name: "transfer".to_owned(),
                args_json: json!([
                    scval_address(&contract(0x44)),
                    scval_address(&account_id_for_seed([0x48; 32])),
                    30
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
        self.multicall_with_policy(url, self.bundle(), self.engine())
            .await
    }

    #[allow(
        clippy::result_large_err,
        reason = "preserve the submission API's typed error for assertions"
    )]
    async fn multicall_with_policy(
        &self,
        url: &str,
        bundle: Vec<MulticallInvocation>,
        engine: Arc<PolicyEngineV1>,
    ) -> Result<stellar_agent_smart_account::multicall::MulticallResult, SaError> {
        self.multicall_on_chain(url, bundle, engine, self.profile.chain_id.caip2_str())
            .await
    }

    #[allow(
        clippy::result_large_err,
        reason = "preserve the submission API's typed error for assertions"
    )]
    async fn multicall_on_chain(
        &self,
        url: &str,
        bundle: Vec<MulticallInvocation>,
        engine: Arc<PolicyEngineV1>,
        chain_id: &str,
    ) -> Result<stellar_agent_smart_account::multicall::MulticallResult, SaError> {
        self.multicall_with_secondary(url, &second_loopback_host(url), bundle, engine, chain_id)
            .await
    }

    #[allow(
        clippy::result_large_err,
        reason = "preserve the submission API's typed error for assertions"
    )]
    #[allow(
        clippy::significant_drop_tightening,
        reason = "the signer and manager live for the whole submission"
    )]
    async fn multicall_with_secondary(
        &self,
        url: &str,
        secondary_url: &str,
        bundle: Vec<MulticallInvocation>,
        engine: Arc<PolicyEngineV1>,
        chain_id: &str,
    ) -> Result<stellar_agent_smart_account::multicall::MulticallResult, SaError> {
        let signer = &self.signer;
        // The bundle signs under rule 0, which the pinned-hash drift check
        // never fetches or reads.
        let signers_manager =
            pin_check_manager::pin_check_manager(url, secondary_url, PROFILE, self._root.path());
        submit_multicall_bundle(
            MulticallSubmitArgs {
                smart_account: &contract(0x44),
                rule_id: 0,
                bundle,
                signer,
                primary_rpc_url: url,
                secondary_rpc_url: secondary_url,
                network_passphrase: PASSPHRASE,
                policy_engine: engine,
                profile: &self.profile,
                audit_writer: Some(Arc::clone(&self.audit)),
                timeout: Duration::from_secs(2),
                fee: ResolvedFeePerOp::default(),
                chain_id,
                request_id: "multicall-record",
                signers_manager: &signers_manager,
            },
            &self.registry,
        )
        .await
    }

    fn rows(&self, kind: &str) -> Vec<Value> {
        verified_audit_lines(&self.audit)
            .into_iter()
            .map(|line| serde_json::from_str::<Value>(&line).expect("audit row must parse"))
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
    rpc_with_hook(status, None).await
}

async fn rpc_with_hook(
    status: &'static str,
    before_simulate: Option<SimulateHook>,
) -> (MockServer, Arc<AtomicUsize>, Arc<Mutex<String>>) {
    let server = MockServer::start().await;
    let sends = Arc::new(AtomicUsize::new(0));
    let sent_hash = Arc::new(Mutex::new(String::new()));
    Mock::given(method("POST"))
        .respond_with(Rpc {
            poll_status: status,
            nonce: 7,
            sends: Arc::clone(&sends),
            sent_hash: Arc::clone(&sent_hash),
            before_simulate: Arc::new(Mutex::new(before_simulate)),
            exec_subtree: false,
            extra_transfer: false,
            fail_signed: false,
            source_only: false,
            on_signed_or_send: None,
            seen: Arc::default(),
        })
        .mount(&server)
        .await;
    (server, sends, sent_hash)
}

/// A confirming endpoint whose `exec` simulation authorizes a sub-invocation
/// per inner call, with the envelopes it received.
async fn rpc_with_exec_subtree() -> (MockServer, Arc<AtomicUsize>, Arc<Mutex<SeenEnvelopes>>) {
    rpc_with_tree(false).await
}

async fn rpc_with_tree(
    extra_transfer: bool,
) -> (MockServer, Arc<AtomicUsize>, Arc<Mutex<SeenEnvelopes>>) {
    rpc_with_tree_failure(extra_transfer, false).await
}

async fn rpc_with_tree_failure(
    extra_transfer: bool,
    fail_signed: bool,
) -> (MockServer, Arc<AtomicUsize>, Arc<Mutex<SeenEnvelopes>>) {
    rpc_with_tree_failure_nonce(extra_transfer, fail_signed, 7).await
}

async fn rpc_with_tree_failure_nonce(
    extra_transfer: bool,
    fail_signed: bool,
    nonce: i64,
) -> (MockServer, Arc<AtomicUsize>, Arc<Mutex<SeenEnvelopes>>) {
    let server = MockServer::start().await;
    let sends = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(SeenEnvelopes::default()));
    Mock::given(method("POST"))
        .respond_with(Rpc {
            poll_status: "SUCCESS",
            nonce,
            sends: Arc::clone(&sends),
            sent_hash: Arc::default(),
            before_simulate: Arc::default(),
            exec_subtree: true,
            extra_transfer,
            fail_signed,
            source_only: false,
            on_signed_or_send: None,
            seen: Arc::clone(&seen),
        })
        .mount(&server)
        .await;
    (server, sends, seen)
}

/// The single host-function operation of a v1 envelope: its contract
/// invocation and its authorization entries.
fn invocation_of(
    envelope: &TransactionEnvelope,
) -> (InvokeContractArgs, Vec<SorobanAuthorizationEntry>) {
    let TransactionEnvelope::Tx(tx) = envelope else {
        panic!("expected a v1 envelope")
    };
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        panic!("expected a host-function invocation")
    };
    let HostFunction::InvokeContract(invoke) = &op.host_function else {
        panic!("expected a contract invocation")
    };
    (invoke.clone(), op.auth.to_vec())
}

/// A bundle the gate admits against an empty window is refused at its
/// reservation when a competing reservation lands in between, and the
/// refusal reaches the caller as the gate's own denial: no multicall wrapper,
/// no send, and the policy-gate row carries the policy code.
#[tokio::test]
#[serial]
async fn a_reservation_refused_at_admission_surfaces_as_the_gate_denial() {
    let fixture = Fixture::new();
    let profile = fixture.profile.clone();
    let competing = Box::new(move || {
        let asset = stellar_agent_core::policy::v1::value::asset_normalise(&contract(0x47));
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let entry = WindowEntry::new(
            StateKey::new(PROFILE, 1, &asset, 86_400),
            now,
            60,
            WindowLimit::Amount {
                asset: contract(0x47),
                window: "1d".to_owned(),
                max_stroops: 100,
            },
        );
        PersistedWindowStore::for_profile(PROFILE)
            .record_pending(
                &profile,
                &[entry],
                &SubmissionHold {
                    chain_scope: stellar_agent_network::policy_state::ChainScope::for_chain(
                        profile.chain_id,
                    ),
                    id: "c".repeat(64),
                    tx_hash: "d".repeat(64),
                    source: "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY".to_owned(),
                    sequence: 9,
                    max_time: 0,
                    pending_since_ms: now,
                    submission_ledger: 1_000,
                    submission_anchor: None,
                    operator_required: false,
                },
            )
            .unwrap();
    });
    let (server, sends, _) = rpc_with_hook("SUCCESS", Some(competing)).await;
    let (witness, _, _) = rpc("SUCCESS").await;
    let result = fixture
        .multicall_with_secondary(
            &server.uri(),
            &second_loopback_host(&witness.uri()),
            fixture.bundle(),
            fixture.engine(),
            "stellar:testnet",
        )
        .await;
    assert_eq!(fixture.signer.sign_calls(), 0);
    let err = result.unwrap_err();
    assert_eq!(
        err.wire_code(),
        "policy.deny.per_period_cap_exceeded",
        "{err:?}"
    );
    assert!(
        matches!(err, SaError::PolicyDenied { .. }),
        "the refusal passes through unwrapped: {err:?}"
    );
    assert_eq!(
        sends.load(Ordering::SeqCst),
        0,
        "a refused reservation sends nothing"
    );
    assert_eq!(
        PersistedWindowStore::for_profile(PROFILE)
            .pending_reservations(&fixture.profile)
            .unwrap()
            .len(),
        1,
        "only the competing reservation stands"
    );
    assert_eq!(fixture.signer.sign_calls(), 0);
    assert!(
        PersistedWindowStore::for_profile(PROFILE)
            .signed_intents(PROFILE, &fixture.profile)
            .unwrap()
            .is_empty()
    );
    assert!(fixture.rows("value_action_pending").is_empty());
    assert!(fixture.rows("value_action_failed").is_empty());
    let denied = fixture.rows("sa_multicall_bundle_denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["refusal_phase"], "policy_gate");
    assert_eq!(
        denied[0]["deny_wire_code"],
        "multicall.policy.deny.per_period_cap_exceeded"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(
                |request| serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                    == "simulateTransaction"
            )
            .count(),
        1
    );

    assert!(fixture.rows("value_action_submitted").is_empty());
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

/// A success report retains exposure and preserves each debit exactly once.
#[tokio::test]
#[serial]
async fn confirmed_multicall_counts_each_leg_once() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    fixture.multicall(&server.uri()).await.unwrap();
    assert_eq!(fixture.total(), (60, 2));
    assert!(
        !PersistedWindowStore::for_profile(PROFILE)
            .pending_reservations(&fixture.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fixture.rows("value_action_pending").len(), 1);
    assert!(fixture.rows("value_action_submitted").is_empty());
    assert_eq!(sends.load(Ordering::SeqCst), 1);
}

/// An invalid bundle function name is refused with the check before any
/// request, in the character and the length case alike, and holds the name
/// in no rendered form.
#[tokio::test]
#[serial]
async fn an_invalid_function_name_stays_out_of_the_bundle_refusal() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    for fn_name in ["credmarker7!".to_owned(), "credmarker7".repeat(3)] {
        let mut bundle = fixture.bundle();
        bundle[0].fn_name = fn_name;
        let error = fixture
            .multicall_with_policy(&server.uri(), bundle, fixture.engine())
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "multicall bundle failed at phase 'build': fn_name must be a non-empty Soroban \
             symbol of at most 32 bytes using only [A-Za-z0-9_]; correct the bundle function \
             name."
        );
        stellar_agent_test_support::rejected_value::assert_no_marker(&error, "credmarker7");
        let json = serde_json::to_string(&error).unwrap();
        assert!(!json.contains("credmarker7"), "{json}");
    }
    assert_eq!(sends.load(Ordering::SeqCst), 0);
}

/// A confirmed bundle's transaction invokes the registered router's `exec`
/// with the wallet as its caller, and carries the wallet's authorization over
/// the simulated tree, sub-invocations included, through the signed
/// re-simulation and the submission.
#[tokio::test]
#[serial]
async fn confirmed_multicall_submits_the_router_exec_under_wallet_authorization() {
    let fixture = Fixture::new();
    let (server, sends, seen) = rpc_with_exec_subtree().await;
    fixture.multicall(&server.uri()).await.unwrap();
    assert_eq!(fixture.total(), (60, 2));
    assert!(
        !PersistedWindowStore::for_profile(PROFILE)
            .pending_reservations(&fixture.profile)
            .unwrap()
            .is_empty()
    );
    assert_eq!(fixture.rows("value_action_pending").len(), 1);
    assert!(fixture.rows("value_action_submitted").is_empty());
    assert_eq!(sends.load(Ordering::SeqCst), 1);

    let router = ScAddress::Contract(ContractId(Hash([0x45; 32])));
    let wallet = ScAddress::Contract(ContractId(Hash([0x44; 32])));
    let seen = seen.lock().unwrap();
    let [sent] = seen.sent.as_slice() else {
        panic!("one envelope is sent")
    };
    let (invoke, auth) = invocation_of(sent);
    assert_eq!(
        invoke.contract_address, router,
        "the submitted transaction invokes the registered router"
    );
    assert_eq!(invoke.function_name.0.as_slice(), b"exec");
    assert_eq!(
        invoke.args.first(),
        Some(&ScVal::Address(wallet.clone())),
        "the router's caller argument is the wallet"
    );

    let subtree = exec_subtree(&invoke);
    assert_eq!(subtree.len(), 2, "one sub-invocation per inner call");
    let wallet_entries: Vec<&SorobanAuthorizationEntry> = auth
        .iter()
        .filter(|entry| {
            matches!(&entry.credentials, SorobanCredentials::Address(credentials)
                if credentials.address == wallet)
        })
        .collect();
    let [entry] = wallet_entries.as_slice() else {
        panic!("the wallet authorizes the bundle with one entry: {auth:?}")
    };
    assert_eq!(
        entry.root_invocation.function,
        SorobanAuthorizedFunction::ContractFn(invoke.clone()),
        "the authorized root is the submitted router invocation"
    );
    assert_eq!(
        entry.root_invocation.sub_invocations.as_slice(),
        subtree.as_slice(),
        "the submission keeps the simulated subtree"
    );

    let [resimulated] = seen.signed_simulations.as_slice() else {
        panic!("one signed re-simulation")
    };
    let (resimulated_invoke, resimulated_auth) = invocation_of(resimulated);
    assert_eq!(
        resimulated_invoke, invoke,
        "the re-simulation invokes the router"
    );
    assert_eq!(
        resimulated_auth.as_slice(),
        auth.as_slice(),
        "the re-simulation carries the submitted authorization"
    );
}

#[tokio::test]
#[serial]
async fn profile_chain_multicall_cap_precedes_wildcard_and_persists_accounting() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    let mut over_cap = fixture.bundle();
    for invocation in &mut over_cap {
        invocation.args_json[2] = json!(60);
    }
    let error = fixture
        .multicall_with_policy(
            &server.uri(),
            over_cap,
            fixture.engine_for_chain("stellar:testnet"),
        )
        .await
        .expect_err("120 exceeds the exact-chain bundle cap of 100");
    assert!(matches!(
        error,
        SaError::MulticallFailed {
            phase: "policy_gate",
            ..
        }
    ));
    assert_eq!(error.wire_code(), "sa.multicall_failed");
    let denied = fixture.rows("sa_multicall_bundle_denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(
        denied[0]["deny_wire_code"],
        "multicall.per_period_cap_exceeded"
    );
    assert_eq!(denied[0]["denied_inner_index"], 1);
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.total(), (0, 0));

    fixture
        .multicall_with_policy(
            &server.uri(),
            fixture.bundle(),
            fixture.engine_for_chain("stellar:testnet"),
        )
        .await
        .expect("60 fits the exact-chain bundle cap of 100");
    assert_eq!(fixture.total(), (60, 2));
    assert!(
        !PersistedWindowStore::for_profile(PROFILE)
            .pending_reservations(&fixture.profile)
            .expect("persisted reservations")
            .is_empty()
    );
    assert!(fixture.rows("value_action_submitted").is_empty());
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
        stellar_agent_core::audit_log::PolicyDecision::Allow,
        Vec::new(),
        Vec::new(),
        ReceiptStore::open(PROFILE).unwrap(),
        PersistedWindowStore::for_profile(PROFILE),
        Some(Arc::clone(&fixture.audit)),
        None,
        "timelock-record",
        stellar_agent_core::timefmt::now_unix_ms().unwrap(),
    )
    .with_signing_sizing(
        stellar_agent_core::policy::v1::CheckedSizing::for_test(
            stellar_agent_core::policy::v1::SizingBasis::NoApplicableLimit,
            Vec::new(),
        )
        .unwrap(),
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
            .secondary_rpc_url(&second_loopback_host(&server.uri()))
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

type TreeSnapshot = std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>>;

/// Records directory existence and file contents, including receipts and reservations.
fn snapshot_tree(root: &std::path::Path) -> std::io::Result<TreeSnapshot> {
    fn visit(
        root: &std::path::Path,
        path: &std::path::Path,
        snapshot: &mut TreeSnapshot,
    ) -> std::io::Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_owned();
            if entry.file_type()?.is_dir() {
                snapshot.insert(relative, None);
                visit(root, &path, snapshot)?;
            } else {
                snapshot.insert(relative, Some(std::fs::read(&path)?));
            }
        }
        Ok(())
    }
    let mut snapshot = std::collections::BTreeMap::new();
    visit(root, root, &mut snapshot)?;
    Ok(snapshot)
}

fn assert_multicall_chain_mismatch(error: &SaError) {
    assert_eq!(error.wire_code(), "sa.multicall_failed");
    assert!(
        matches!(error, SaError::MulticallFailed { phase: "policy_gate", redacted_reason, post_submit_kind: None }
        if redacted_reason == "chain_id does not match the profile chain"),
        "{error:?}"
    );
}

/// A bundle whose witness is on the primary's host refuses with the witness
/// code, writes its denied row and reserves nothing.
#[tokio::test]
#[serial]
async fn multicall_on_one_host_refuses_with_the_witness_code() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    let error = fixture
        .multicall_with_secondary(
            &server.uri(),
            &server.uri(),
            fixture.bundle(),
            fixture.engine(),
            fixture.profile.chain_id.caip2_str(),
        )
        .await
        .expect_err("one host is no witness");
    assert_eq!(
        error.wire_code(),
        "smart_account.ledger_witness_unavailable"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.total(), (0, 0));
    let denied = fixture.rows("sa_multicall_bundle_denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(
        denied[0]["deny_wire_code"],
        "multicall.smart_account.ledger_witness_unavailable"
    );
}

/// A bundle on one host refuses before the policy gate weighs it: four
/// 30-unit transfers exceed the bundle cap of 100, yet the one denied row
/// carries the witness code, not the cap's.
#[tokio::test]
#[serial]
async fn multicall_on_one_host_refuses_before_the_policy_gate() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    let mut over_cap = fixture.bundle();
    over_cap.extend(fixture.bundle());
    assert_eq!(over_cap.len(), 4);
    let error = fixture
        .multicall_with_secondary(
            &server.uri(),
            &server.uri(),
            over_cap,
            fixture.engine(),
            fixture.profile.chain_id.caip2_str(),
        )
        .await
        .expect_err("one host is no witness");
    assert_eq!(
        error.wire_code(),
        "smart_account.ledger_witness_unavailable",
        "{error:?}"
    );
    let denied = fixture.rows("sa_multicall_bundle_denied");
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert_eq!(
        denied[0]["deny_wire_code"],
        "multicall.smart_account.ledger_witness_unavailable"
    );
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.total(), (0, 0));
}

/// A bundle whose endpoints disagree on the ledger keeps the skew code through
/// the multicall surface and sends nothing.
#[tokio::test]
#[serial]
async fn multicall_with_skewed_endpoints_refuses_with_the_skew_code() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    let witness = MockServer::start().await;
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getNetwork"}),
        ))
        .respond_with(stellar_agent_test_support::EchoIdResponder::new(
            get_network_result(PASSPHRASE),
        ))
        .mount(&witness)
        .await;
    Mock::given(method("POST"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getLatestLedger"}),
        ))
        .respond_with(stellar_agent_test_support::EchoIdResponder::new(
            json!({"id": "ab".repeat(32), "sequence": 1003, "protocolVersion": 27}),
        ))
        .mount(&witness)
        .await;
    let error = fixture
        .multicall_with_secondary(
            &server.uri(),
            &second_loopback_host(&witness.uri()),
            fixture.bundle(),
            fixture.engine(),
            fixture.profile.chain_id.caip2_str(),
        )
        .await
        .expect_err("a three-ledger skew refuses");
    assert_eq!(error.wire_code(), "simulation.divergence.ledger_skew");
    assert_eq!(sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[serial]
async fn multicall_chain_mismatch_has_no_side_effects() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new();
    let (server, _, _) = rpc("SUCCESS").await;
    // The manager creates fixture files so the snapshot isolates the submission's effects.
    drop(pin_check_manager::pin_check_manager(
        &server.uri(),
        &second_loopback_host(&server.uri()),
        PROFILE,
        fixture._root.path(),
    ));
    let before = snapshot_tree(fixture._root.path())?;
    let result = fixture
        .multicall_on_chain(
            &server.uri(),
            fixture.bundle(),
            fixture.engine(),
            "stellar:mainnet",
        )
        .await;
    let requests = server
        .received_requests()
        .await
        .ok_or("request recording disabled")?;
    assert!(requests.is_empty(), "received requests: {requests:?}");
    assert_eq!(snapshot_tree(fixture._root.path())?, before);
    let error = result.err().ok_or("chain mismatch must refuse")?;
    assert_multicall_chain_mismatch(&error);
    Ok(())
}

#[tokio::test]
#[serial]
async fn multicall_chain_mismatch_precedes_empty_bundle_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new();
    let (server, _, _) = rpc("SUCCESS").await;
    let error = fixture
        .multicall_on_chain(
            &server.uri(),
            Vec::new(),
            fixture.engine(),
            "stellar:mainnet",
        )
        .await
        .err()
        .ok_or("chain mismatch must refuse")?;
    assert_multicall_chain_mismatch(&error);
    Ok(())
}

#[tokio::test]
#[serial]
async fn a_bundle_of_string_transfers_is_not_valued() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    let mut bundle = fixture.bundle();
    for invocation in &mut bundle {
        invocation.args_json = json!([
            account_id_for_seed(SEED),
            account_id_for_seed([0x48; 32]),
            "30"
        ]);
    }
    let error = fixture
        .multicall_with_policy(&server.uri(), bundle, fixture.engine())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SaError::MulticallFailed {
                phase: "policy_gate",
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        fixture.rows("sa_multicall_bundle_denied")[0]["deny_wire_code"],
        "multicall.bundle_contains_generic_kind"
    );
    assert_eq!(fixture.total(), (0, 0));
    assert_eq!(sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[serial]
async fn a_wallet_transfer_over_the_per_call_cap_is_refused() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    let error = fixture
        .multicall_with_policy(
            &server.uri(),
            fixture.bundle(),
            fixture.per_call_engine(20, false),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SaError::MulticallFailed {
                phase: "policy_gate",
                ..
            }
        ),
        "{error:?}"
    );
    let rows = fixture.rows("sa_multicall_bundle_denied");
    assert_eq!(rows[0]["deny_wire_code"], "multicall.per_tx_cap_exceeded");
    assert_eq!(rows[0]["denied_inner_index"], 0);
    assert_eq!(sends.load(Ordering::SeqCst), 0);
}

fn with_unvalued_call(mut bundle: Vec<MulticallInvocation>) -> Vec<MulticallInvocation> {
    bundle.push(MulticallInvocation {
        target_contract: contract(0x49),
        fn_name: "approve".to_owned(),
        args_json: json!([]),
    });
    bundle
}

#[tokio::test]
#[serial]
async fn a_per_call_value_rule_refuses_an_unvalued_call() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    let error = fixture
        .multicall_with_policy(
            &server.uri(),
            with_unvalued_call(fixture.bundle()),
            fixture.per_call_engine(100, false),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            SaError::MulticallFailed {
                phase: "policy_gate",
                ..
            }
        ),
        "{error:?}"
    );
    let rows = fixture.rows("sa_multicall_bundle_denied");
    assert_eq!(
        rows[0]["deny_wire_code"],
        "multicall.unsizable_value_effect"
    );
    assert_eq!(rows[0]["denied_inner_index"], 2);
    assert_eq!(sends.load(Ordering::SeqCst), 0);
}

#[tokio::test]
#[serial]
async fn allow_opaque_signing_admits_an_unvalued_call() {
    let fixture = Fixture::new();
    let (server, sends, _) = rpc("SUCCESS").await;
    fixture
        .multicall_with_policy(
            &server.uri(),
            with_unvalued_call(fixture.bundle()),
            fixture.per_call_engine(100, true),
        )
        .await
        .unwrap();
    let rows = fixture.rows("value_action_pending");
    let legs = rows[0]["legs"].as_array().unwrap();
    assert_eq!(legs.len(), 2);
    for leg in legs {
        assert_eq!(leg["amount"], "30");
        assert_eq!(leg["asset"], contract(0x47));
    }
    assert_eq!(sends.load(Ordering::SeqCst), 1);
}

/// A simulated `exec` subtree that carries a transfer after the declared
/// calls is refused by the declared sub-invocation check before anything is
/// signed: the bundle reports the divergence at phase `sign` and writes the
/// denied row naming it.
#[tokio::test]
#[serial]
async fn a_simulated_transfer_outside_the_bundle_is_refused() {
    let fixture = Fixture::new();
    let (server, sends, seen) = rpc_with_tree(true).await;
    let error = fixture.multicall(&server.uri()).await.unwrap_err();
    assert!(
        matches!(
            &error,
            SaError::MulticallFailed {
                phase: "sign",
                redacted_reason,
                post_submit_kind: None,
            } if redacted_reason == "submit error: simulation.divergence.auth_contexts"
        ),
        "{error:?}"
    );
    let rows = fixture.rows("sa_multicall_bundle_denied");
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["deny_wire_code"],
        "multicall.simulation.divergence.auth_contexts"
    );
    assert_eq!(rows[0]["refusal_phase"], "sign");
    assert_eq!(sends.load(Ordering::SeqCst), 0);
    assert!(seen.lock().unwrap().signed_simulations.is_empty());
}

#[tokio::test]
#[serial]
async fn repeated_signed_resimulation_failure_cannot_exceed_cap() {
    let fixture = Fixture::new();
    let (server, sends, seen) = rpc_with_tree_failure_nonce(false, true, 7).await;
    let first = fixture.multicall(&server.uri()).await.unwrap_err();
    assert_eq!(first.wire_code(), "sa.multicall_failed", "{first:?}");
    assert_eq!(seen.lock().unwrap().signed_simulations.len(), 1);
    assert!(fixture.signer.sign_calls() > 0);
    let intents = PersistedWindowStore::for_profile(PROFILE)
        .signed_intents(PROFILE, &fixture.profile)
        .unwrap();
    let retained_total = fixture.total();
    let fixture = fixture.restart();
    let (second_server, second_sends, second_seen) =
        rpc_with_tree_failure_nonce(false, true, 8).await;
    let second = fixture
        .multicall_with_policy(&second_server.uri(), fixture.bundle(), fixture.engine())
        .await;
    assert_eq!(
        fixture.signer.sign_calls(),
        0,
        "the retained charge refuses the fresh nonce before signing"
    );
    let second = second.unwrap_err();
    assert_eq!(second.wire_code(), "sa.multicall_failed", "{second:?}");
    assert_eq!(intents.len(), 1);
    assert_eq!(
        intents[0].status,
        "authorization exposed, submission unknown"
    );
    assert_eq!(intents[0].legs.len(), 2);
    assert_eq!(retained_total, (60, 2));
    assert_eq!(
        seen.lock().unwrap().signed_simulations.len()
            + second_seen.lock().unwrap().signed_simulations.len(),
        1
    );
    assert_eq!(
        sends.load(Ordering::SeqCst) + second_sends.load(Ordering::SeqCst),
        0
    );
    assert_eq!(fixture.total(), (60, 2));
}

#[cfg(feature = "test-hooks")]
#[tokio::test]
#[serial]
async fn the_entry_guard_is_free_at_every_signer_rpc_and_writer_call() {
    use stellar_agent_core::policy::state_lock::WindowStoreLock;
    let fixture = Fixture::new();
    let path = PersistedWindowStore::for_profile(PROFILE).path().to_owned();
    let key = fixture.profile.policy_window_state_key_id.clone();
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let rpc_calls = Arc::new(AtomicUsize::new(0));
    let writer_calls = Arc::new(AtomicUsize::new(0));
    let observer = |count: Arc<AtomicUsize>| {
        let path = path.clone();
        let key = key.clone();
        Arc::new(move || {
            let _guard = WindowStoreLock::acquire_for(&path, &key).unwrap();
            count.fetch_add(1, Ordering::SeqCst);
        }) as Arc<dyn Fn() + Send + Sync>
    };
    *fixture.signer.hook.lock().unwrap() = Some(observer(Arc::clone(&signer_calls)));
    let seen = Arc::new(Mutex::new(SeenEnvelopes::default()));
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Rpc {
            poll_status: "SUCCESS",
            nonce: 7,
            sends: Arc::default(),
            sent_hash: Arc::default(),
            before_simulate: Arc::default(),
            exec_subtree: true,
            extra_transfer: false,
            fail_signed: false,
            source_only: false,
            on_signed_or_send: Some(observer(Arc::clone(&rpc_calls))),
            seen,
        })
        .mount(&server)
        .await;
    let observed = Arc::clone(&writer_calls);
    let _hook = stellar_agent_network::submission_record::observe_pending_writer_for_test(
        Arc::new(move |profile, store| {
            let _guard =
                WindowStoreLock::acquire_for(store.path(), &profile.policy_window_state_key_id)
                    .unwrap();
            observed.fetch_add(1, Ordering::SeqCst);
        }),
    );
    fixture.multicall(&server.uri()).await.unwrap();
    assert_eq!(signer_calls.load(Ordering::SeqCst), 3);
    assert_eq!(rpc_calls.load(Ordering::SeqCst), 2);
    assert_eq!(writer_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[serial]
async fn cap_refusal_precedes_any_signed_authorization() {
    use stellar_agent_core::policy::v1::criteria::rate_limit::RateLimitCriterion;
    use stellar_agent_core::policy::{
        McpToolRegistration, PolicyEngine, ToolDescriptor, ToolValueKind,
    };
    for case in [
        "schedule",
        "execute",
        "cancel",
        "missing_sizing",
        "value_schedule",
    ] {
        let fixture = Fixture::new();
        let server = MockServer::start().await;
        let sends = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(SeenEnvelopes::default()));
        Mock::given(method("POST"))
            .respond_with(Rpc {
                poll_status: "SUCCESS",
                nonce: 7,
                sends: Arc::clone(&sends),
                sent_hash: Arc::default(),
                before_simulate: Arc::default(),
                exec_subtree: false,
                extra_transfer: false,
                fail_signed: false,
                source_only: true,
                on_signed_or_send: None,
                seen: Arc::clone(&seen),
            })
            .mount(&server)
            .await;
        let tool = if case == "cancel" {
            "stellar_smart_account_timelock_cancel"
        } else if case == "execute" {
            "stellar_smart_account_timelock_execute"
        } else {
            "stellar_smart_account_timelock_schedule"
        };
        let criterion: Box<dyn stellar_agent_core::policy::v1::criteria::Criterion> = if case
            == "value_schedule"
        {
            Box::new(stellar_agent_core::policy::v1::criteria::per_period_cap::PerPeriodCapCriterion::new("native".into(), Window::parse("1m").unwrap(), 1))
        } else {
            Box::new(RateLimitCriterion::new(Window::parse("1m").unwrap(), 1))
        };
        let engine = PolicyEngineV1::new(
            PolicyDocument {
                version: 1,
                scope: ScopeId::AllProfiles,
                rules: vec![PolicyRule {
                    r#match: RuleMatch {
                        tool: tool.into(),
                        chain: "*".into(),
                    },
                    criteria: vec![criterion],
                    decision: Decision::Allow,
                    allow_opaque_signing: false,
                }],
                signature: None,
            },
            PROFILE.into(),
        );
        let descriptor = ToolDescriptor::from_registration(&McpToolRegistration {
            name: tool,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::ReadOnly,
        });
        let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
        let window = PersistedWindowStore::for_profile(PROFILE);
        let count = engine
            .size_no_value(&descriptor, &fixture.profile, now)
            .unwrap();
        if case != "value_schedule" {
            window
                .record_and_persist(&fixture.profile, count.entries())
                .unwrap();
        }
        let before = std::fs::read(window.path()).ok();
        let result = if case == "value_schedule" {
            match engine
                .size_unvalued_call(
                    &descriptor,
                    &fixture.profile,
                    stellar_agent_core::policy::v1::OpaqueReason::UnvaluedContractCall,
                    now,
                )
                .unwrap()
            {
                stellar_agent_core::policy::v1::SizingOutcome::Refused(reason) => {
                    Err(SaError::PolicyDenied {
                        reason: Box::new(reason),
                    })
                }
                _ => panic!("a value rule must refuse scheduling without value evidence"),
            }
        } else if case == "cancel" {
            let admission = stellar_agent_network::NoValueAdmission::new(
                fixture.profile.clone(),
                PROFILE,
                count,
            )
            .unwrap();
            stellar_agent_smart_account::timelock::cancel(
                stellar_agent_smart_account::timelock::TimelockCancelArgs::builder()
                    .timelock_contract_strkey(&contract(0x49))
                    .operation_id(
                        &stellar_agent_smart_account::timelock::TimelockOperationId::from_bytes(
                            [0x46; 32],
                        ),
                    )
                    .signer(&fixture.signer)
                    .primary_rpc_url(&server.uri())
                    .secondary_rpc_url(&second_loopback_host(&server.uri()))
                    .network_passphrase(PASSPHRASE)
                    .audit_writer(&fixture.audit)
                    .request_id("cap-cancel")
                    .intent_admission(&admission)
                    .build(),
            )
            .await
            .map(|_| ())
        } else {
            let entries = if case == "missing_sizing" {
                vec![]
            } else {
                count.entries().to_vec()
            };
            let recorder = WalletSubmissionRecorder::new(
                &fixture.profile,
                PROFILE,
                tool,
                Some("stellar:testnet".into()),
                stellar_agent_core::audit_log::PolicyDecision::Allow,
                vec![],
                entries,
                ReceiptStore::open(PROFILE).unwrap(),
                window.clone(),
                Some(Arc::clone(&fixture.audit)),
                None,
                "cap-schedule",
                now,
            );
            let recorder = if case == "missing_sizing" {
                recorder
            } else {
                recorder.with_signing_sizing(count)
            };
            if case == "execute" {
                stellar_agent_smart_account::timelock::execute(
                    stellar_agent_smart_account::timelock::TimelockExecuteArgs::builder()
                        .timelock_contract_strkey(&contract(0x49))
                        .target_strkey(&contract(0x47))
                        .function("transfer")
                        .salt([0x50; 32])
                        .signer(&fixture.signer)
                        .primary_rpc_url(&server.uri())
                        .secondary_rpc_url(&second_loopback_host(&server.uri()))
                        .network_passphrase(PASSPHRASE)
                        .audit_writer(&fixture.audit)
                        .request_id("cap-execute")
                        .expected_operation_id(
                            &stellar_agent_smart_account::timelock::TimelockOperationId::from_bytes(
                                [0x46; 32],
                            ),
                        )
                        .submission_recorder(&recorder)
                        .build(),
                )
                .await
                .map(|_| ())
            } else {
                stellar_agent_smart_account::timelock::schedule_upgrade(
                    stellar_agent_smart_account::timelock::TimelockScheduleArgs::builder()
                        .timelock_contract_strkey(&contract(0x49))
                        .target_strkey(&contract(0x47))
                        .function("transfer")
                        .delay_ledgers(10)
                        .signer(&fixture.signer)
                        .primary_rpc_url(&server.uri())
                        .secondary_rpc_url(&second_loopback_host(&server.uri()))
                        .network_passphrase(PASSPHRASE)
                        .audit_writer(&fixture.audit)
                        .request_id("cap-schedule")
                        .submission_recorder(&recorder)
                        .build(),
                )
                .await
                .map(|_| ())
            }
        };
        let error = result.unwrap_err();
        assert_eq!(
            error.wire_code(),
            match case {
                "missing_sizing" => "submission.intent_record_unavailable",
                "value_schedule" => "policy.deny.unsizable_value_effect",
                _ => "policy.deny.rate_limit_exceeded",
            },
            "{case}: {error:?}"
        );
        assert_eq!(fixture.signer.sign_calls(), 0, "{case}");
        assert_eq!(sends.load(Ordering::SeqCst), 0, "{case}");
        assert!(
            seen.lock()
                .unwrap()
                .signed_simulations
                .iter()
                .all(|envelope| invocation_of(envelope)
                    .1
                    .iter()
                    .all(|entry| matches!(entry.credentials, SorobanCredentials::SourceAccount))),
            "{case}"
        );
        assert_eq!(std::fs::read(window.path()).ok(), before, "{case}");
        assert!(
            window
                .signed_intents(PROFILE, &fixture.profile)
                .unwrap()
                .is_empty()
        );
    }
}
