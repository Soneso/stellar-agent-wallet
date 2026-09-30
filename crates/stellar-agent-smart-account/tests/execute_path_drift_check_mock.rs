//! The pinned-hash drift check `submit_signed_invoke` runs before signing,
//! and the pin record the wallet's own verifier-set mutations keep in step,
//! against a mock Soroban RPC.
//!
//! The mock serves one smart account: its context rules through
//! `get_context_rule`, contract instances and executable-tag entries through
//! `getLedgerEntries`, the signed invocation through `simulateTransaction`,
//! `sendTransaction` and `getTransaction`. Every request is recorded, so a
//! test can assert that a refused submission never simulated its invocation
//! and never sent anything.
//!
//! ```text
//! cargo test -p stellar-agent-smart-account --features test-helpers \
//!   --test execute_path_drift_check_mock
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test fixture construction and assertions"
)]
#![allow(
    clippy::result_large_err,
    reason = "the helpers return the submission API's typed error for assertions"
)]

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::reader::AuditLogIntegrityError;
use stellar_agent_core::audit_log::schema::{EventKind, ExecutableRefPin, PinsUpdateReason};
use stellar_agent_core::audit_log::signer_set::{
    BaselineReason, SignerEntryV2, SignerIdentityV2, SignerPubkey, SignerSetSnapshotV2,
    account_digest,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::redact_strkey_first5_last5;
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::migration::{
    MigrationPlan, RuleMigration, SignerMigrationStep,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, PinStatus,
};
use stellar_agent_smart_account::managers::signers::{SignersManager, SignersManagerConfig};
use stellar_agent_smart_account::submit::{
    PinCheck, SubmitInvokeArgs, SubmitInvokeResult, submit_signed_invoke,
};
use stellar_agent_smart_account::verifier_allowlist::{VERIFIER_ALLOWLIST, VerifierAuditStatus};
use stellar_agent_test_support::signed_envelope::{
    account_id_for_seed, get_network_result, send_transaction_hash_hex,
};
use stellar_agent_test_support::xdr_fixtures;
use stellar_xdr::{
    AccountId, BytesM, ContractId, Hash, HostFunction, InvokeContractArgs, LedgerKey, Limits,
    OperationBody, PublicKey, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry, ScString, ScSymbol,
    ScVal, ScVec, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TransactionEnvelope, Uint256, VecM, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[path = "smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use rpc_mock_helpers::{KNOWN_WASM_HASH, signer_set_n_of_n, write_baseline};

const PASSPHRASE: &str = "Test SDF Network ; September 2015";
const CHAIN_ID: &str = "stellar:testnet";
const SEED: [u8; 32] = [0x51; 32];

/// The G-strkey owning an external-reference executable in these fixtures.
const OWNER_G: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
const TAG: &[u8] = b"verifier";

/// A URL no test may dial: the refusals below happen before network I/O.
const UNROUTABLE_RPC: &str = "http://pin-check-must-not-be-dialed.invalid";

// ── Addresses and hashes ──────────────────────────────────────────────────────

fn contract(byte: u8) -> ScAddress {
    ScAddress::Contract(ContractId(Hash([byte; 32])))
}

fn strkey(addr: &ScAddress) -> String {
    stellar_agent_core::sc_address::scaddress_to_strkey(addr).expect("contract strkey")
}

fn smart_account() -> ScAddress {
    contract(0x44)
}

fn verifier_v() -> ScAddress {
    contract(0x20)
}

fn verifier_w() -> ScAddress {
    contract(0x21)
}

fn policy_p() -> ScAddress {
    contract(0x30)
}

fn first8(hash: &[u8; 32]) -> String {
    hex::encode(&hash[..8])
}

/// The allowlisted WebAuthn v0.7.2 verifier hash.
fn webauthn_hash() -> [u8; 32] {
    VERIFIER_ALLOWLIST[0].wasm_hash
}

/// The allowlisted Ed25519 verifier hash.
fn ed25519_hash() -> [u8; 32] {
    VERIFIER_ALLOWLIST[2].wasm_hash
}

/// A first-8 no live contract in these fixtures has.
const FOREIGN_FIRST8: &str = "0101010101010101";

fn smart_account_redacted() -> String {
    redact_strkey_first5_last5(&strkey(&smart_account()))
}

// ── Ledger entries ────────────────────────────────────────────────────────────

fn wasm_instance(addr: &ScAddress, hash: [u8; 32]) -> Value {
    xdr_fixtures::ledger_entry_from_response_json(
        &xdr_fixtures::contract_instance_ledger_entries_json(&strkey(addr), hash),
    )
}

fn external_ref_instance(addr: &ScAddress) -> Value {
    xdr_fixtures::ledger_entry_from_response_json(
        &xdr_fixtures::external_ref_instance_ledger_entries_json(&strkey(addr), OWNER_G, TAG),
    )
}

fn tag_entry(hash: [u8; 32]) -> Value {
    xdr_fixtures::ledger_entry_from_response_json(
        &xdr_fixtures::executable_tag_ledger_entries_json(OWNER_G, TAG, hash),
    )
}

fn owner_scaddress() -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        stellar_strkey::ed25519::PublicKey::from_string(OWNER_G)
            .expect("owner G-strkey")
            .0,
    ))))
}

fn reference_pin(resolved: [u8; 32]) -> ExecutableRefPin {
    ExecutableRefPin::new(
        &owner_scaddress(),
        &ScString(TAG.to_vec().try_into().expect("tag fits")),
        &resolved,
    )
    .expect("pin builds")
}

/// An instance entry under the instance key of `addr` whose data does not
/// decode as `LedgerEntryData`.
fn undecodable_instance(addr: &ScAddress) -> Value {
    json!({
        "key": rpc_mock_helpers::contract_instance_key_xdr(addr),
        "xdr": "bm90dmFsaWR4ZHI=",
        "lastModifiedLedgerSeq": 100
    })
}

/// The kinds of the rows written under `request_id`, in log order, each
/// override row with its rule id.
fn row_kinds(rows: &[AuditEntry], request_id: &str) -> Vec<String> {
    rows.iter()
        .filter(|e| e.request_id == request_id)
        .map(|e| match &e.event_kind {
            EventKind::SaUnknownContractOverride { rule_id, .. } => {
                format!("unknown_override(rule {rule_id:?})")
            }
            EventKind::SaMutableContractOverride { rule_id, .. } => {
                format!("mutable_override(rule {rule_id:?})")
            }
            other => serde_json::to_value(other).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_owned(),
        })
        .collect()
}

// ── Context rules ─────────────────────────────────────────────────────────────

fn symbol(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol::try_from(s).expect("symbol fits"))
}

fn scvec(items: Vec<ScVal>) -> ScVal {
    ScVal::Vec(Some(ScVec(items.try_into().expect("vec fits"))))
}

fn external_signer(verifier: &ScAddress, key: &[u8]) -> ScVal {
    let key: BytesM = key.to_vec().try_into().expect("key fits");
    scvec(vec![
        symbol("External"),
        ScVal::Address(verifier.clone()),
        ScVal::Bytes(ScBytes(key)),
    ])
}

fn delegated_signer() -> ScVal {
    let g = account_id_for_seed(SEED);
    let pk = stellar_strkey::ed25519::PublicKey::from_string(&g).expect("G-strkey");
    scvec(vec![
        symbol("Delegated"),
        ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256(pk.0)),
        ))),
    ])
}

/// A Default-context rule with `signers` and `policies`; signer and policy
/// ids count from 0.
fn rule(rule_id: u32, signers: Vec<ScVal>, policies: Vec<ScAddress>) -> ScVal {
    let signer_ids = (0..u32::try_from(signers.len()).unwrap())
        .map(ScVal::U32)
        .collect();
    let policy_ids = (0..u32::try_from(policies.len()).unwrap())
        .map(ScVal::U32)
        .collect();
    let entry = |key: &str, val: ScVal| ScMapEntry {
        key: symbol(key),
        val,
    };
    let entries: VecM<ScMapEntry> = vec![
        entry("context_type", scvec(vec![symbol("Default")])),
        entry("id", ScVal::U32(rule_id)),
        entry(
            "name",
            ScVal::String(ScString(
                format!("rule-{rule_id}").into_bytes().try_into().unwrap(),
            )),
        ),
        entry(
            "policies",
            scvec(policies.into_iter().map(ScVal::Address).collect()),
        ),
        entry("policy_ids", scvec(policy_ids)),
        entry("signer_ids", scvec(signer_ids)),
        entry("signers", scvec(signers)),
        entry("valid_until", ScVal::Void),
    ]
    .try_into()
    .expect("map fits");
    ScVal::Map(Some(ScMap(entries)))
}

// ── Mock RPC ──────────────────────────────────────────────────────────────────

/// The live state the mock serves.
#[derive(Default)]
struct Chain {
    rules: HashMap<u32, ScVal>,
    entries: HashMap<String, Value>,
    /// `getLedgerEntries` requests naming one of these keys answer with a
    /// JSON-RPC error.
    failing_keys: HashSet<String>,
    /// The rule a confirmed submission leaves on-chain, applied at
    /// `sendTransaction`.
    after_send: Option<(u32, ScVal)>,
}

impl Chain {
    fn with_rule(mut self, rule_id: u32, value: ScVal) -> Self {
        self.rules.insert(rule_id, value);
        self
    }

    fn with_entry(mut self, entry: Value) -> Self {
        let key = entry["key"].as_str().expect("entry key").to_owned();
        self.entries.insert(key, entry);
        self
    }
}

/// What one endpoint saw.
#[derive(Default)]
struct Log {
    ledger_keys: Mutex<Vec<String>>,
    simulated: Mutex<Vec<String>>,
    sends: AtomicUsize,
}

struct Rpc {
    chain: Arc<Mutex<Chain>>,
    log: Arc<Log>,
}

fn simulate_result(value: &ScVal, auth: &[SorobanAuthorizationEntry]) -> Value {
    let mut result =
        rpc_mock_helpers::build_simulate_response(&value.to_xdr_base64(Limits::none()).unwrap());
    result["results"][0]["auth"] = json!(
        auth.iter()
            .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
            .collect::<Vec<_>>()
    );
    result
}

/// The authorized sub-invocations the mock reports for `function`: `pair`
/// authorizes a second call, so its tree has two contexts and takes two
/// rule ids; every other function authorizes itself alone.
fn sub_invocations(function: &str) -> VecM<SorobanAuthorizedInvocation> {
    if function != "pair" {
        return VecM::default();
    }
    vec![SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: smart_account(),
            function_name: ScSymbol::try_from("noop").unwrap(),
            args: VecM::default(),
        }),
        sub_invocations: VecM::default(),
    }]
    .try_into()
    .unwrap()
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let reply = |result: Value| {
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
        };
        match body["method"].as_str().unwrap() {
            "getLedgerEntries" => {
                let keys: Vec<String> = body["params"]["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|k| k.as_str().unwrap().to_owned())
                    .collect();
                self.log
                    .ledger_keys
                    .lock()
                    .unwrap()
                    .extend(keys.iter().cloned());
                let chain = self.chain.lock().unwrap();
                if keys.iter().any(|k| chain.failing_keys.contains(k)) {
                    return ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "error": {"code": -32603, "message": "mock ledger read failure"}
                    }));
                }
                let entries: Vec<Value> = keys
                    .iter()
                    .filter_map(|key| {
                        if let LedgerKey::Account(account) =
                            LedgerKey::from_xdr_base64(key, Limits::none()).unwrap()
                        {
                            let PublicKey::PublicKeyTypeEd25519(Uint256(pk)) = account.account_id.0;
                            let g = stellar_strkey::ed25519::PublicKey(pk).to_string();
                            return Some(json!({
                                "key": key,
                                "xdr": rpc_mock_helpers::account_entry_xdr(g.as_str(), 100),
                                "lastModifiedLedgerSeq": 100
                            }));
                        }
                        chain.entries.get(key).cloned()
                    })
                    .collect();
                reply(json!({"entries": entries, "latestLedger": 1000}))
            }
            "simulateTransaction" => {
                let envelope = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let TransactionEnvelope::Tx(tx) = envelope else {
                    panic!("expected a v1 envelope")
                };
                let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                    panic!("expected an invocation")
                };
                let HostFunction::InvokeContract(invoke) = &op.host_function else {
                    panic!("expected a contract invocation")
                };
                let function = invoke.function_name.0.to_utf8_string().unwrap();
                self.log.simulated.lock().unwrap().push(function.clone());
                let chain = self.chain.lock().unwrap();
                match function.as_str() {
                    "get_context_rule" => {
                        let ScVal::U32(rule_id) = invoke.args[0] else {
                            panic!("get_context_rule takes a u32")
                        };
                        let value = chain
                            .rules
                            .get(&rule_id)
                            .unwrap_or_else(|| panic!("rule {rule_id} is not on the mock chain"));
                        reply(simulate_result(value, &[]))
                    }
                    "get_threshold" => reply(simulate_result(&ScVal::U32(1), &[])),
                    _ => {
                        let value = match function.as_str() {
                            "add_signer" | "add_policy" => ScVal::U32(7),
                            _ => ScVal::Void,
                        };
                        let auth = if op.auth.is_empty() {
                            vec![SorobanAuthorizationEntry {
                                credentials: SorobanCredentials::Address(
                                    SorobanAddressCredentials {
                                        address: smart_account(),
                                        nonce: 11,
                                        signature_expiration_ledger: 0,
                                        signature: ScVal::Void,
                                    },
                                ),
                                root_invocation: SorobanAuthorizedInvocation {
                                    function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                                    sub_invocations: sub_invocations(&function),
                                },
                            }]
                        } else {
                            op.auth.to_vec()
                        };
                        reply(simulate_result(&value, &auth))
                    }
                }
            }
            "sendTransaction" => {
                self.log.sends.fetch_add(1, Ordering::SeqCst);
                let mut chain = self.chain.lock().unwrap();
                if let Some((rule_id, value)) = chain.after_send.take() {
                    chain.rules.insert(rule_id, value);
                }
                let hash = send_transaction_hash_hex(&body, PASSPHRASE);
                reply(json!({
                    "status": "PENDING", "hash": hash,
                    "latestLedger": 1000, "latestLedgerCloseTime": "1234567890"
                }))
            }
            "getTransaction" => reply(json!({
                "status": "SUCCESS", "latestLedger": 1001, "oldestLedger": 1, "ledger": 1001,
                "createdAt": (stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000).to_string(),
            })),
            "getNetwork" => reply(get_network_result(PASSPHRASE)),
            "getLatestLedger" => {
                reply(json!({"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 27}))
            }
            other => panic!("unexpected RPC method: {other}"),
        }
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

/// A smart account served by a primary and a secondary endpoint over one
/// chain, a signers manager over both, and its audit log.
struct Harness {
    primary: MockServer,
    chain: Arc<Mutex<Chain>>,
    primary_log: Arc<Log>,
    secondary_log: Arc<Log>,
    audit: Arc<Mutex<AuditWriter>>,
    log_path: PathBuf,
    manager: Arc<SignersManager>,
    _dir: tempfile::TempDir,
    _secondary: MockServer,
}

impl Harness {
    async fn new(chain: Chain) -> Self {
        let chain = Arc::new(Mutex::new(chain));
        let primary_log = Arc::new(Log::default());
        let secondary_log = Arc::new(Log::default());
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        for (server, log) in [(&primary, &primary_log), (&secondary, &secondary_log)] {
            Mock::given(method("POST"))
                .respond_with(Rpc {
                    chain: Arc::clone(&chain),
                    log: Arc::clone(log),
                })
                .mount(server)
                .await;
        }
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let audit = Arc::new(Mutex::new(
            AuditWriter::open(log_path.clone(), None).unwrap(),
        ));
        let manager = Arc::new(
            SignersManager::new(SignersManagerConfig::new(
                primary.uri(),
                secondary.uri(),
                Arc::clone(&audit),
                log_path.clone(),
                PASSPHRASE.to_owned(),
                "pin-check-mock".to_owned(),
                Duration::from_secs(10),
                CHAIN_ID.to_owned(),
            ))
            .unwrap(),
        );
        Self {
            primary,
            chain,
            primary_log,
            secondary_log,
            audit,
            log_path,
            manager,
            _dir: dir,
            _secondary: secondary,
        }
    }

    /// A rule manager over the primary endpoint with this harness's signers
    /// manager and audit writer, the production configuration.
    fn rule_manager(&self) -> ContextRuleManager {
        ContextRuleManager::new(
            ContextRuleManagerConfig::new(
                self.primary.uri(),
                PASSPHRASE.to_owned(),
                Duration::from_secs(10),
                CHAIN_ID.to_owned(),
            )
            .with_signers_manager(Arc::clone(&self.manager))
            .with_audit_writer(Arc::clone(&self.audit)),
        )
        .unwrap()
    }

    /// Replaces the ledger entry with the key of `entry`.
    fn set_entry(&self, entry: Value) {
        let key = entry["key"].as_str().expect("entry key").to_owned();
        self.chain.lock().unwrap().entries.insert(key, entry);
    }

    /// Sets the rule a confirmed submission leaves on-chain.
    fn after_send(&self, rule_id: u32, value: ScVal) {
        self.chain.lock().unwrap().after_send = Some((rule_id, value));
    }

    fn write(&self, entry: AuditEntry) {
        self.audit.lock().unwrap().write_entry(entry).unwrap();
    }

    /// Writes the `SaContextRuleCreated` pin record of `rule_id`.
    fn pin_created(
        &self,
        rule_id: u32,
        verifier_first8: Vec<String>,
        policy_first8: Vec<String>,
        verifier_refs: Vec<Option<ExecutableRefPin>>,
        policy_refs: Vec<Option<ExecutableRefPin>>,
    ) {
        self.write(AuditEntry::new_sa_context_rule_created(
            smart_account_redacted(),
            rule_id,
            "default",
            1,
            u32::try_from(policy_first8.len()).unwrap(),
            None,
            CHAIN_ID,
            "req-install",
            verifier_first8,
            policy_first8,
            false,
            false,
            verifier_refs,
            policy_refs,
        ));
    }

    fn rows(&self) -> Vec<AuditEntry> {
        std::fs::read_to_string(&self.log_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn pins_updated_rows(&self) -> Vec<AuditEntry> {
        self.rows()
            .into_iter()
            .filter(|e| matches!(e.event_kind, EventKind::SaContextRulePinsUpdated { .. }))
            .collect()
    }

    fn sends(&self) -> usize {
        self.primary_log.sends.load(Ordering::SeqCst)
    }

    fn simulated(&self, function: &str) -> bool {
        self.primary_log
            .simulated
            .lock()
            .unwrap()
            .iter()
            .any(|f| f == function)
    }

    /// Requests for the instance key of `addr` the primary endpoint saw.
    fn primary_instance_reads(&self, addr: &ScAddress) -> usize {
        let key = rpc_mock_helpers::contract_instance_key_xdr(addr);
        self.primary_log
            .ledger_keys
            .lock()
            .unwrap()
            .iter()
            .filter(|k| **k == key)
            .count()
    }

    fn fail_reads_of(&self, addr: &ScAddress) {
        self.chain
            .lock()
            .unwrap()
            .failing_keys
            .insert(rpc_mock_helpers::contract_instance_key_xdr(addr));
    }

    /// Submits `noop()` on the smart account under `rule_ids`, with the
    /// drift check through this harness's manager when `request_id` is set.
    async fn submit(
        &self,
        rule_ids: &[u32],
        request_id: Option<&str>,
    ) -> Result<SubmitInvokeResult, SaError> {
        self.submit_invocation("noop", rule_ids, request_id).await
    }

    /// Submits `function()` on the smart account; see [`Self::submit`].
    async fn submit_invocation(
        &self,
        function: &str,
        rule_ids: &[u32],
        request_id: Option<&str>,
    ) -> Result<SubmitInvokeResult, SaError> {
        let signer = SoftwareSigningKey::new_from_bytes(SEED);
        let rule_ids: Vec<ContextRuleId> =
            rule_ids.iter().copied().map(ContextRuleId::new).collect();
        let smart_account = strkey(&smart_account());
        let uri = self.primary.uri();
        submit_signed_invoke(
            SubmitInvokeArgs::builder()
                .target_contract(&smart_account)
                .auth_rule_ids(&rule_ids)
                .host_function(invocation(function))
                .signer(&signer)
                .primary_rpc_url(&uri)
                .network_passphrase(PASSPHRASE)
                .chain_id(CHAIN_ID)
                .timeout(Duration::from_secs(10))
                .op_label("pin_check_mock")
                .maybe_pin_check(request_id.map(|request_id| PinCheck {
                    signers_manager: &self.manager,
                    request_id,
                    migrating_rule: None,
                }))
                .build(),
        )
        .await
    }
}

fn invocation(function: &str) -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: smart_account(),
        function_name: ScSymbol::try_from(function).unwrap(),
        args: VecM::default(),
    })
}

fn noop() -> HostFunction {
    invocation("noop")
}

/// Rule 1: an External signer on verifier V and policy P.
fn rule_one_verifier_and_policy() -> ScVal {
    rule(
        1,
        vec![external_signer(&verifier_v(), &[0x11; 32])],
        vec![policy_p()],
    )
}

fn chain_with_rule_one(verifier_hash: [u8; 32]) -> Chain {
    Chain::default()
        .with_rule(1, rule_one_verifier_and_policy())
        .with_entry(wasm_instance(&verifier_v(), verifier_hash))
        .with_entry(wasm_instance(&policy_p(), KNOWN_WASM_HASH))
}

// ── Drift refusals ────────────────────────────────────────────────────────────

/// A live verifier that differs from the rule's pin refuses the submission
/// before its invocation is simulated, and the drift row carries the
/// caller's request id.
#[tokio::test]
async fn verifier_drift_refuses_before_simulation_with_the_callers_request_id() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.pin_created(
        1,
        vec![FOREIGN_FIRST8.to_owned()],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );

    let err = h
        .submit(&[1], Some("req-verifier-drift"))
        .await
        .unwrap_err();
    match &err {
        SaError::VerifierHashDrift {
            rule_id,
            pinned_hash_first8,
            observed_hash_first8,
            request_id,
            ..
        } => {
            assert_eq!(*rule_id, 1);
            assert_eq!(pinned_hash_first8, FOREIGN_FIRST8);
            assert_eq!(observed_hash_first8, &first8(&webauthn_hash()));
            assert_eq!(request_id, "req-verifier-drift");
        }
        other => panic!("expected VerifierHashDrift; got {other:?}"),
    }
    let drift_rows: Vec<AuditEntry> = h
        .rows()
        .into_iter()
        .filter(|e| {
            matches!(
                e.event_kind,
                EventKind::SaVerifierHashDrift { rule_id: 1, .. }
            )
        })
        .collect();
    assert_eq!(drift_rows.len(), 1);
    assert_eq!(drift_rows[0].request_id, "req-verifier-drift");
    assert!(!h.simulated("noop"), "nothing may be simulated after drift");
    assert_eq!(h.sends(), 0);
}

/// A live policy that differs from the rule's pin refuses the same way.
#[tokio::test]
async fn policy_drift_refuses_before_simulation_with_the_callers_request_id() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![FOREIGN_FIRST8.to_owned()],
        vec![],
        vec![],
    );

    let err = h.submit(&[1], Some("req-policy-drift")).await.unwrap_err();
    match &err {
        SaError::PolicyHashDrift {
            rule_id,
            pinned_hash_first8,
            observed_hash_first8,
            request_id,
            ..
        } => {
            assert_eq!(*rule_id, 1);
            assert_eq!(pinned_hash_first8, FOREIGN_FIRST8);
            assert_eq!(observed_hash_first8, &first8(&KNOWN_WASM_HASH));
            assert_eq!(request_id, "req-policy-drift");
        }
        other => panic!("expected PolicyHashDrift; got {other:?}"),
    }
    let drift_rows: Vec<AuditEntry> = h
        .rows()
        .into_iter()
        .filter(|e| {
            matches!(
                e.event_kind,
                EventKind::SaPolicyHashDrift { rule_id: 1, .. }
            )
        })
        .collect();
    assert_eq!(drift_rows.len(), 1);
    assert_eq!(drift_rows[0].request_id, "req-policy-drift");
    assert!(!h.simulated("noop"));
    assert_eq!(h.sends(), 0);
}

/// A pinned external reference whose tag now resolves to another hash
/// refuses with the observed executable named.
#[tokio::test]
async fn a_repointed_external_reference_refuses_with_the_observed_executable() {
    let chain = Chain::default()
        .with_rule(
            1,
            rule(1, vec![external_signer(&verifier_v(), &[0x11; 32])], vec![]),
        )
        .with_entry(external_ref_instance(&verifier_v()))
        .with_entry(tag_entry(ed25519_hash()));
    let h = Harness::new(chain).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![],
        vec![Some(reference_pin(webauthn_hash()))],
        vec![],
    );

    let err = h.submit(&[1], Some("req-ref-drift")).await.unwrap_err();
    match &err {
        SaError::VerifierHashDrift {
            pinned_hash_first8,
            observed_hash_first8,
            observed_executable: Some(observed_executable),
            ..
        } => {
            assert_eq!(pinned_hash_first8, &first8(&webauthn_hash()));
            assert_eq!(observed_hash_first8, &first8(&ed25519_hash()));
            assert!(
                observed_executable.starts_with("external reference owner ")
                    && observed_executable.contains(&format!(
                        "tag \"verifier\" resolved {}",
                        first8(&ed25519_hash())
                    )),
                "{observed_executable}"
            );
        }
        other => {
            panic!("expected VerifierHashDrift {{ observed_executable: Some(..) }}; got {other:?}")
        }
    }
    assert_eq!(h.sends(), 0);
}

// ── Checks that cannot run ────────────────────────────────────────────────────

/// An RPC failure while observing a pinned contract refuses as unavailable,
/// naming the inner code, and nothing is simulated or sent.
#[tokio::test]
async fn an_rpc_failure_during_the_check_refuses_and_sends_nothing() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.fail_reads_of(&verifier_v());

    let err = h.submit(&[1], Some("req-rpc-failure")).await.unwrap_err();
    match &err {
        SaError::PinCheckUnavailable {
            rule_id,
            smart_account_redacted: redacted,
            reason,
            request_id,
        } => {
            assert_eq!(*rule_id, 1);
            assert_eq!(redacted.as_str(), smart_account_redacted());
            assert!(reason.starts_with("sa.deployment_failed: "), "{reason}");
            assert_eq!(request_id, "req-rpc-failure");
        }
        other => panic!("expected PinCheckUnavailable; got {other:?}"),
    }
    assert!(!h.simulated("noop"));
    assert_eq!(h.sends(), 0);
}

/// A pin record with two verifier pins, and an audit log that fails its
/// integrity check, each refuse as unavailable carrying the inner code.
#[tokio::test]
async fn multiple_pins_and_an_audit_integrity_error_refuse_as_unavailable() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash()), first8(&ed25519_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let err = h.submit(&[1], Some("req-multi")).await.unwrap_err();
    match &err {
        SaError::PinCheckUnavailable { reason, .. } => assert!(
            reason.starts_with("sa.multiple_pinned_hashes_unsupported: "),
            "{reason}"
        ),
        other => panic!("expected PinCheckUnavailable; got {other:?}"),
    }

    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&h.log_path)
        .unwrap()
        .write_all(b"not an audit row\n")
        .unwrap();
    let err = h.submit(&[1], Some("req-integrity")).await.unwrap_err();
    match &err {
        SaError::PinCheckUnavailable { reason, .. } => {
            assert!(reason.starts_with("sa.audit_log: "), "{reason}");
        }
        other => panic!("expected PinCheckUnavailable; got {other:?}"),
    }
    assert_eq!(h.sends(), 0);
}

// ── Checks that pass ──────────────────────────────────────────────────────────

/// A rule without a pin record signs: the check fetches the rule and passes.
#[tokio::test]
async fn a_rule_without_a_pin_record_signs() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    let result = h.submit(&[1], Some("req-unpinned")).await.unwrap();
    assert!(!result.tx_hash.is_empty());
    assert!(
        h.simulated("get_context_rule"),
        "the check fetched the rule"
    );
    assert_eq!(h.sends(), 1);
}

/// Rule 0 alone signs without a check, and the check never runs for it.
#[tokio::test]
async fn rule_zero_only_signs_without_a_check() {
    let h = Harness::new(Chain::default()).await;
    h.submit(&[0], None).await.unwrap();
    assert!(!h.simulated("get_context_rule"));
    assert_eq!(h.sends(), 1);
}

/// A pins-updated row newer than the created row is the record the check
/// reads: the live verifier matches it and the submission signs.
#[tokio::test]
async fn a_newer_pins_updated_row_is_the_record_the_check_reads() {
    let h = Harness::new(chain_with_rule_one(ed25519_hash())).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.write(AuditEntry::new_sa_context_rule_pins_updated(
        smart_account_redacted(),
        1,
        PinsUpdateReason::VerifierMigrated,
        CHAIN_ID,
        "req-migration",
        vec![first8(&ed25519_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        false,
        false,
        vec![],
        vec![],
    ));
    h.submit(&[1], Some("req-after-update")).await.unwrap();
    assert_eq!(h.sends(), 1);
}

/// One observation per contract per call: a verifier shared by two checked
/// rules is read once from the primary endpoint.
#[tokio::test]
async fn a_verifier_shared_by_two_rules_is_observed_once() {
    let chain = Chain::default()
        .with_rule(
            1,
            rule(1, vec![external_signer(&verifier_v(), &[0x11; 32])], vec![]),
        )
        .with_rule(
            2,
            rule(2, vec![external_signer(&verifier_v(), &[0x12; 32])], vec![]),
        )
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()));
    let h = Harness::new(chain).await;
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.pin_created(2, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);

    h.submit_invocation("pair", &[1, 2], Some("req-shared"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
    assert_eq!(h.primary_instance_reads(&verifier_v()), 1);
    assert_eq!(
        h.secondary_log
            .ledger_keys
            .lock()
            .unwrap()
            .iter()
            .filter(|k| **k == rpc_mock_helpers::contract_instance_key_xdr(&verifier_v()))
            .count(),
        1
    );
}

// ── Argument guards ───────────────────────────────────────────────────────────

fn unroutable_args<'a>(
    rule_ids: &'a [ContextRuleId],
    signer: &'a SoftwareSigningKey,
    pin_check: Option<PinCheck<'a>>,
) -> SubmitInvokeArgs<'a> {
    SubmitInvokeArgs::builder()
        .target_contract("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM")
        .auth_rule_ids(rule_ids)
        .host_function(noop())
        .signer(signer)
        .primary_rpc_url(UNROUTABLE_RPC)
        .network_passphrase(PASSPHRASE)
        .chain_id(CHAIN_ID)
        .timeout(Duration::from_secs(10))
        .op_label("pin_check_guard")
        .maybe_pin_check(pin_check)
        .build()
}

fn stage_of(err: &SaError) -> &'static str {
    match err {
        SaError::AuthEntryConstructionFailed { stage, .. } => stage,
        other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
    }
}

/// A non-zero rule without a check is refused before any network I/O.
#[tokio::test]
async fn a_non_zero_rule_without_a_check_is_refused_before_io() {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    for ids in [vec![3], vec![0, 3], vec![3, 0]] {
        let rule_ids: Vec<ContextRuleId> = ids.into_iter().map(ContextRuleId::new).collect();
        let err = submit_signed_invoke(unroutable_args(&rule_ids, &signer, None))
            .await
            .unwrap_err();
        assert_eq!(stage_of(&err), "pin_check_required", "{err}");
    }
}

/// The migrating-rule exemption is accepted only when the migrating rule is
/// the only authorizing rule.
#[tokio::test]
async fn a_migrating_rule_must_be_the_only_authorizing_rule() {
    let h = Harness::new(Chain::default()).await;
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    for ids in [vec![2, 3], vec![3], vec![2, 2], vec![]] {
        let rule_ids: Vec<ContextRuleId> = ids.into_iter().map(ContextRuleId::new).collect();
        let pin_check = PinCheck {
            signers_manager: &h.manager,
            request_id: "req-guard",
            migrating_rule: Some(2),
        };
        let err = submit_signed_invoke(unroutable_args(&rule_ids, &signer, Some(pin_check)))
            .await
            .unwrap_err();
        assert_eq!(stage_of(&err), "migrating_rule_mismatch", "{err}");
    }
    assert!(h.primary_log.simulated.lock().unwrap().is_empty());
}

// ── Pin record kept in step by signer adds ────────────────────────────────────

/// Rule 1 before the add: a Delegated signer, an External signer on
/// verifier V, and policy P.
fn signer_add_rule_before() -> ScVal {
    rule(
        1,
        vec![
            delegated_signer(),
            external_signer(&verifier_v(), &[0x11; 32]),
        ],
        vec![policy_p()],
    )
}

async fn signer_add_harness(pinned: bool) -> Harness {
    let chain = Chain::default()
        .with_rule(1, signer_add_rule_before())
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()))
        .with_entry(wasm_instance(&verifier_w(), ed25519_hash()))
        .with_entry(wasm_instance(&contract(0x22), [0xdd; 32]))
        .with_entry(wasm_instance(&policy_p(), KNOWN_WASM_HASH));
    let h = Harness::new(chain).await;
    write_baseline(
        &h.audit,
        1,
        &smart_account_redacted(),
        &signer_set_n_of_n(2),
    );
    if pinned {
        h.pin_created(
            1,
            vec![first8(&webauthn_hash())],
            vec![first8(&KNOWN_WASM_HASH)],
            vec![],
            vec![],
        );
    }
    h
}

fn external_pubkey(verifier: &ScAddress) -> SignerPubkey {
    SignerPubkey::External {
        verifier_contract: strkey(verifier),
        key_data_first16: [0x33; 16],
    }
}

async fn add_external_signer(
    h: &Harness,
    verifier: &ScAddress,
    request_id: &str,
    accept_unknown_verifier: bool,
) -> Result<u32, SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.manager
        .add_signer(
            smart_account(),
            1,
            external_signer(verifier, &[0x33; 32]),
            external_pubkey(verifier),
            &signer,
            request_id.to_owned(),
            false,
            accept_unknown_verifier,
        )
        .await
}

fn pins_updated_fields(entry: &AuditEntry) -> (Vec<String>, Vec<String>, bool, PinsUpdateReason) {
    match &entry.event_kind {
        EventKind::SaContextRulePinsUpdated {
            rule_id: 1,
            pinned_verifier_wasm_hashes_first8,
            pinned_policy_wasm_hashes_first8,
            unknown_override,
            reason,
            ..
        } => (
            pinned_verifier_wasm_hashes_first8.clone(),
            pinned_policy_wasm_hashes_first8.clone(),
            *unknown_override,
            *reason,
        ),
        other => panic!("expected SaContextRulePinsUpdated for rule 1; got {other:?}"),
    }
}

/// An External signer added on the rule's existing verifier leaves the
/// verifier pins unchanged and writes the pins-updated row.
#[tokio::test]
async fn a_signer_on_the_existing_verifier_keeps_the_pins_and_writes_the_row() {
    let h = signer_add_harness(true).await;
    add_external_signer(&h, &verifier_v(), "req-add-same", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-add-same");
    let (verifiers, policies, unknown_override, reason) = pins_updated_fields(&rows[0]);
    assert_eq!(verifiers, vec![first8(&webauthn_hash())]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert!(!unknown_override);
    assert_eq!(reason, PinsUpdateReason::SignerAdded);
}

/// An External signer added on a second distinct verifier writes a two-pin
/// record, and the next checked signing verb refuses it as unavailable.
#[tokio::test]
async fn a_signer_on_a_second_verifier_writes_two_pins_and_the_next_verb_refuses() {
    let h = signer_add_harness(true).await;
    h.chain.lock().unwrap().after_send = Some((
        1,
        rule(
            1,
            vec![
                delegated_signer(),
                external_signer(&verifier_v(), &[0x11; 32]),
                external_signer(&verifier_w(), &[0x33; 32]),
            ],
            vec![policy_p()],
        ),
    ));
    add_external_signer(&h, &verifier_w(), "req-add-second", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    let (verifiers, policies, _, reason) = pins_updated_fields(&rows[0]);
    assert_eq!(
        verifiers,
        vec![first8(&webauthn_hash()), first8(&ed25519_hash())]
    );
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::SignerAdded);

    let err = h.submit(&[1], Some("req-after-second")).await.unwrap_err();
    match &err {
        SaError::PinCheckUnavailable { reason, .. } => assert!(
            reason.starts_with("sa.multiple_pinned_hashes_unsupported: "),
            "{reason}"
        ),
        other => panic!("expected PinCheckUnavailable; got {other:?}"),
    }
}

/// A new verifier outside the allowlist is refused before submission unless
/// the unknown-hash override is set; with it, the add proceeds, the override
/// row names the rule, and the record carries the override flag.
#[tokio::test]
async fn an_unknown_new_verifier_needs_the_override() {
    let h = signer_add_harness(true).await;
    let err = add_external_signer(&h, &contract(0x22), "req-add-unknown", false)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::VerifierWasmNotInAllowlist {
                rule_id: Some(1),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(h.sends(), 0);
    assert!(h.pins_updated_rows().is_empty());

    add_external_signer(&h, &contract(0x22), "req-add-unknown-ok", true)
        .await
        .unwrap();
    let overrides: Vec<AuditEntry> = h
        .rows()
        .into_iter()
        .filter(|e| {
            matches!(
                e.event_kind,
                EventKind::SaUnknownContractOverride {
                    rule_id: Some(1),
                    ..
                }
            )
        })
        .collect();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].request_id, "req-add-unknown-ok");
    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    let (verifiers, _, unknown_override, _) = pins_updated_fields(&rows[0]);
    assert_eq!(
        verifiers,
        vec![first8(&webauthn_hash()), first8(&[0xdd; 32])]
    );
    assert!(unknown_override);
}

/// A signer add on a rule without a pin record writes no pins-updated row and
/// observes no new verifier.
#[tokio::test]
async fn a_signer_add_on_an_unpinned_rule_writes_no_row() {
    let h = signer_add_harness(false).await;
    add_external_signer(&h, &verifier_w(), "req-add-unpinned", false)
        .await
        .unwrap();
    assert!(h.pins_updated_rows().is_empty());
    assert_eq!(h.sends(), 1);
}

/// A confirmed signer add on an unknown verifier under the override writes
/// `SaSignerAdded`, then the override row naming the rule, then the
/// pins-updated row.
#[tokio::test]
async fn a_signer_add_writes_the_override_row_between_the_add_and_the_pins() {
    let h = signer_add_harness(true).await;
    add_external_signer(&h, &contract(0x22), "req-add-order", true)
        .await
        .unwrap();

    assert_eq!(
        row_kinds(&h.rows(), "req-add-order"),
        vec![
            "sa_signer_added",
            "unknown_override(rule Some(1))",
            "sa_context_rule_pins_updated",
        ]
    );
}

/// A signer add on a rule whose newest state row is version 2 refuses with
/// the audit-log error naming that row, before any RPC and without writing a
/// row: this build compares version-1 baselines only, and a version-2 row is
/// never read as a missing baseline.
#[tokio::test]
async fn a_signer_add_over_a_version_2_state_row_refuses_before_any_rpc() {
    let h = signer_add_harness(true).await;
    let snapshot = SignerSetSnapshotV2 {
        signers: vec![
            SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0x01; 32] },
            },
            SignerEntryV2 {
                id: 1,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0x02; 32] },
            },
        ],
        threshold: None,
    };
    {
        let mut writer = h.audit.lock().unwrap();
        let tip = writer.current_chain_tip();
        writer
            .write_entry(AuditEntry::new_sa_signer_set_baselined_v2(
                1,
                &snapshot,
                1_234,
                1_700_000_000_000,
                BaselineReason::confirmed_install(),
                tip,
                account_digest(PASSPHRASE, &strkey(&smart_account())),
                stellar_agent_core::observability::RedactedStrkey::from_already_redacted(
                    smart_account_redacted(),
                ),
                CHAIN_ID,
                "req-v2-baseline",
            ))
            .unwrap();
    }
    let rows_before = h.rows().len();

    let err = add_external_signer(&h, &verifier_v(), "req-add-over-v2", false)
        .await
        .unwrap_err();

    assert_eq!(err.wire_code(), "sa.audit_log", "{err:?}");
    match &err {
        SaError::AuditLog(AuditLogIntegrityError::ParseError { line, detail }) => {
            assert_eq!(*line, rows_before, "the v2 row is the last row");
            assert_eq!(
                detail,
                &format!(
                    "signer-set state row audit.jsonl:{rows_before} is version 2; \
                     this build compares version 1 rows only"
                )
            );
        }
        other => panic!("expected the version-2 refusal; got {other:?}"),
    }
    for log in [&h.primary_log, &h.secondary_log] {
        assert!(log.ledger_keys.lock().unwrap().is_empty());
        assert!(log.simulated.lock().unwrap().is_empty());
        assert_eq!(log.sends.load(Ordering::SeqCst), 0);
    }
    assert_eq!(h.rows().len(), rows_before, "the refusal writes no row");
}

/// A batch whose first new verifier is admitted under the unknown-hash
/// override and whose second is undecodable refuses before submission, and
/// the override applied to the first is written nowhere.
#[tokio::test]
async fn a_refused_batch_writes_no_override_row_for_an_admitted_verifier() {
    let h = signer_add_harness(true).await;
    let undecodable = contract(0x23);
    h.set_entry(undecodable_instance(&undecodable));
    let signer = SoftwareSigningKey::new_from_bytes(SEED);

    let err = h
        .manager
        .batch_add_signers(
            smart_account(),
            1,
            vec![
                (
                    external_signer(&contract(0x22), &[0x33; 32]),
                    external_pubkey(&contract(0x22)),
                ),
                (
                    external_signer(&undecodable, &[0x34; 32]),
                    external_pubkey(&undecodable),
                ),
            ],
            &signer,
            "req-batch-refused".to_owned(),
            false,
            true,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(
            err,
            SaError::ContractInstanceUnsupported {
                rule_id: Some(1),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(h.sends(), 0);
    assert!(
        !h.rows().iter().any(|e| matches!(
            e.event_kind,
            EventKind::SaUnknownContractOverride { .. }
                | EventKind::SaMutableContractOverride { .. }
        )),
        "a refused batch writes no override row"
    );
    assert!(h.pins_updated_rows().is_empty());
}

// ── Verifier migration ────────────────────────────────────────────────────────

fn migration_plan(from: [u8; 32], to: [u8; 32]) -> MigrationPlan {
    let step = SignerMigrationStep::new_for_test(
        1,
        first8(&from),
        HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: smart_account(),
            function_name: ScSymbol::try_from("remove_signer").unwrap(),
            args: vec![ScVal::U32(1), ScVal::U32(1)].try_into().unwrap(),
        }),
        HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: smart_account(),
            function_name: ScSymbol::try_from("add_signer").unwrap(),
            args: vec![ScVal::U32(1), external_signer(&verifier_w(), &[0x11; 32])]
                .try_into()
                .unwrap(),
        }),
    );
    MigrationPlan::new_for_test(
        smart_account(),
        from,
        to,
        verifier_w(),
        vec![RuleMigration::new_for_test(1, first8(&from), vec![step])],
        VerifierAuditStatus::Unaudited,
        "req-migration-plan",
    )
}

/// The migration steps sign under the migrating rule with its verifier
/// check skipped: a verifier that differs from the pin does not stop
/// the migration away from it, and the confirmed pair writes the record
/// naming the destination.
#[tokio::test]
async fn a_migration_skips_the_verifier_check_of_the_migrating_rule() {
    let h = signer_add_harness(false).await;
    h.pin_created(
        1,
        vec![FOREIGN_FIRST8.to_owned()],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let result = migration_plan(webauthn_hash(), ed25519_hash())
        .submit(&signer, &h.manager, "req-migrate")
        .await;
    assert!(
        result.failed_step_error.is_none(),
        "{:?}",
        result.failed_step_error
    );
    assert_eq!(h.sends(), 2, "remove and add both confirmed");
    assert!(
        !h.rows()
            .iter()
            .any(|e| matches!(e.event_kind, EventKind::SaVerifierHashDrift { .. })),
        "the migrating rule's verifier is not checked"
    );
    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-migrate");
    let (verifiers, policies, _, reason) = pins_updated_fields(&rows[0]);
    assert_eq!(verifiers, vec![first8(&ed25519_hash())]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::VerifierMigrated);
}

/// The migrating rule's policies are still checked: a policy that differs
/// from the pin refuses the first step with its own code, unwrapped.
#[tokio::test]
async fn a_migration_still_checks_the_migrating_rules_policies() {
    let h = signer_add_harness(false).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![FOREIGN_FIRST8.to_owned()],
        vec![],
        vec![],
    );
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let result = migration_plan(webauthn_hash(), ed25519_hash())
        .submit(&signer, &h.manager, "req-migrate-policy")
        .await;
    assert_eq!(result.failed_step_index, Some(0));
    assert!(
        matches!(
            result.failed_step_error,
            Some(SaError::PolicyHashDrift { rule_id: 1, .. })
        ),
        "{:?}",
        result.failed_step_error
    );
    assert_eq!(h.sends(), 0);
    assert!(h.pins_updated_rows().is_empty());
}

/// A migration on a rule without a pin record writes no pins-updated row.
#[tokio::test]
async fn a_migration_on_an_unpinned_rule_writes_no_row() {
    let h = signer_add_harness(false).await;
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let result = migration_plan(webauthn_hash(), ed25519_hash())
        .submit(&signer, &h.manager, "req-migrate-unpinned")
        .await;
    assert!(
        result.failed_step_error.is_none(),
        "{:?}",
        result.failed_step_error
    );
    assert!(h.pins_updated_rows().is_empty());
}

// ── Rule manager without a signers manager ────────────────────────────────────

/// A rule manager built without a signers manager refuses a mutation
/// authorized by any rule other than 0 before any network I/O: it has no
/// manager to run the drift check through.
#[tokio::test]
async fn a_rule_manager_without_a_signers_manager_refuses_a_non_zero_rule() {
    use stellar_agent_smart_account::managers::rules::{
        ContextRuleManager, ContextRuleManagerConfig,
    };

    let manager = ContextRuleManager::new(ContextRuleManagerConfig::new(
        UNROUTABLE_RPC.to_owned(),
        PASSPHRASE.to_owned(),
        Duration::from_secs(10),
        CHAIN_ID.to_owned(),
    ))
    .unwrap();
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let err = manager
        .update_name(
            smart_account(),
            5,
            "renamed".to_owned(),
            vec![ContextRuleId::new(0), ContextRuleId::new(5)],
            &signer,
            None,
            "req-no-manager".to_owned(),
        )
        .await
        .unwrap_err();
    match err {
        SaError::SignersManagerNotConfigured {
            rule_id,
            smart_account_redacted: ref redacted,
            ref request_id,
        } => {
            assert_eq!(rule_id, 5);
            assert_eq!(redacted.as_str(), smart_account_redacted());
            assert_eq!(request_id, "req-no-manager");
        }
        other => panic!("expected SignersManagerNotConfigured; got {other:?}"),
    }
}

// ── Pin record kept in step by policy adds and removals ───────────────────────

fn policy_q() -> ScAddress {
    contract(0x31)
}

fn policy_r() -> ScAddress {
    contract(0x32)
}

/// The vendored spending-limit policy hash.
fn spending_limit_hash() -> [u8; 32] {
    hex::decode(
        stellar_agent_smart_account::spending_limit_policy::SPENDING_LIMIT_POLICY_WASM_SHA256,
    )
    .unwrap()
    .try_into()
    .unwrap()
}

/// Rule 1 with an External signer on verifier V and `policies`.
fn rule_one_with_policies(policies: Vec<ScAddress>) -> ScVal {
    rule(
        1,
        vec![external_signer(&verifier_v(), &[0x11; 32])],
        policies,
    )
}

/// A chain serving rule 1 with `policies`, verifier V, and the policies P
/// (threshold), Q (spending-limit) and R (unknown hash).
async fn policy_harness(policies: Vec<ScAddress>) -> Harness {
    let chain = Chain::default()
        .with_rule(1, rule_one_with_policies(policies))
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()))
        .with_entry(wasm_instance(&policy_p(), KNOWN_WASM_HASH))
        .with_entry(wasm_instance(&policy_q(), spending_limit_hash()))
        .with_entry(wasm_instance(&policy_r(), [0xdd; 32]));
    Harness::new(chain).await
}

async fn add_policy(
    h: &Harness,
    policy: &ScAddress,
    request_id: &str,
    accept_unknown_verifier: bool,
) -> Result<u32, SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.rule_manager()
        .add_policy(
            smart_account(),
            1,
            policy.clone(),
            ScVal::Void,
            vec![ContextRuleId::new(0)],
            &signer,
            None,
            request_id.to_owned(),
            false,
            accept_unknown_verifier,
        )
        .await
}

/// Removes the policy with on-chain id `policy_id` from rule 1, authorized
/// under rule 0.
async fn remove_policy(h: &Harness, policy_id: u32, request_id: &str) -> Result<(), SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.rule_manager()
        .remove_policy(
            smart_account(),
            1,
            policy_id,
            vec![ContextRuleId::new(0)],
            &signer,
            None,
            request_id.to_owned(),
        )
        .await
}

fn policy_pins_of(entry: &AuditEntry) -> (Vec<String>, bool, PinsUpdateReason) {
    match &entry.event_kind {
        EventKind::SaContextRulePinsUpdated {
            rule_id: 1,
            pinned_policy_wasm_hashes_first8,
            unknown_override,
            reason,
            ..
        } => (
            pinned_policy_wasm_hashes_first8.clone(),
            *unknown_override,
            *reason,
        ),
        other => panic!("expected SaContextRulePinsUpdated for rule 1; got {other:?}"),
    }
}

/// A policy attached to a pinned rule with no policy pin is pinned: the
/// record gains its pin, and the next checked verb compares the live policy
/// with it.
#[tokio::test]
async fn a_policy_added_to_a_pinned_rule_is_pinned_and_checked() {
    let h = policy_harness(vec![]).await;
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.after_send(1, rule_one_with_policies(vec![policy_p()]));
    add_policy(&h, &policy_p(), "req-policy-add", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-policy-add");
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::PolicyAdded);

    h.set_entry(wasm_instance(&policy_p(), [0xab; 32]));
    let err = h
        .submit(&[1], Some("req-after-policy-add"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SaError::PolicyHashDrift { rule_id: 1, .. }),
        "{err:?}"
    );
}

/// A second policy with another hash yields a two-pin record, which the
/// next checked verb refuses as unavailable.
#[tokio::test]
async fn a_second_policy_writes_two_pins_and_the_next_verb_refuses() {
    let h = policy_harness(vec![policy_p()]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![policy_p(), policy_q()]));
    add_policy(&h, &policy_q(), "req-policy-second", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert_eq!(
        policies,
        vec![first8(&KNOWN_WASM_HASH), first8(&spending_limit_hash())]
    );
    assert_eq!(reason, PinsUpdateReason::PolicyAdded);

    let err = h
        .submit(&[1], Some("req-after-second-policy"))
        .await
        .unwrap_err();
    match &err {
        SaError::PinCheckUnavailable { reason, .. } => assert!(
            reason.starts_with("sa.multiple_pinned_hashes_unsupported: "),
            "{reason}"
        ),
        other => panic!("expected PinCheckUnavailable; got {other:?}"),
    }
}

/// A policy outside the policy allowlist is refused before submission unless
/// the unknown-hash override is set; with it, the add proceeds, the override
/// row names the rule and the record carries the override flag.
#[tokio::test]
async fn an_unknown_new_policy_needs_the_override() {
    let h = policy_harness(vec![]).await;
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    let err = add_policy(&h, &policy_r(), "req-policy-unknown", false)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::PolicyWasmNotInAllowlist {
                rule_id: Some(1),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(h.sends(), 0);
    assert!(h.pins_updated_rows().is_empty());

    h.after_send(1, rule_one_with_policies(vec![policy_r()]));
    add_policy(&h, &policy_r(), "req-policy-unknown-ok", true)
        .await
        .unwrap();
    let overrides: Vec<AuditEntry> = h
        .rows()
        .into_iter()
        .filter(|e| {
            matches!(
                e.event_kind,
                EventKind::SaUnknownContractOverride {
                    rule_id: Some(1),
                    ..
                }
            )
        })
        .collect();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0].request_id, "req-policy-unknown-ok");
    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    let (policies, unknown_override, _) = policy_pins_of(&rows[0]);
    assert_eq!(policies, vec![first8(&[0xdd; 32])]);
    assert!(unknown_override);
}

/// A policy add on a rule without a pin record writes no pins-updated row.
#[tokio::test]
async fn a_policy_add_on_an_unpinned_rule_writes_no_row() {
    let h = policy_harness(vec![]).await;
    add_policy(&h, &policy_r(), "req-policy-unpinned", false)
        .await
        .unwrap();
    assert!(h.pins_updated_rows().is_empty());
    assert_eq!(h.sends(), 1);
}

/// A confirmed policy add of an unknown policy under the override writes
/// `SaPolicyAdded`, the raw-invocation row, then the override row naming the
/// rule, then the pins-updated row.
#[tokio::test]
async fn a_policy_add_writes_the_override_row_after_the_raw_invocation() {
    let h = policy_harness(vec![]).await;
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.after_send(1, rule_one_with_policies(vec![policy_r()]));
    add_policy(&h, &policy_r(), "req-policy-order", true)
        .await
        .unwrap();

    assert_eq!(
        row_kinds(&h.rows(), "req-policy-order"),
        vec![
            "sa_policy_added",
            "sa_raw_invocation",
            "unknown_override(rule Some(1))",
            "sa_context_rule_pins_updated",
        ]
    );
}

/// Removing the pinned policy clears its pin, and a later add of a policy
/// with another hash writes a fresh one-pin record the next verb accepts.
#[tokio::test]
async fn removing_the_pinned_policy_clears_its_pin() {
    let h = policy_harness(vec![policy_p()]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![]));
    remove_policy(&h, 0, "req-policy-remove").await.unwrap();
    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-policy-remove");
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert!(policies.is_empty(), "{policies:?}");
    assert_eq!(reason, PinsUpdateReason::PolicyRemoved);

    h.after_send(1, rule_one_with_policies(vec![policy_q()]));
    add_policy(&h, &policy_q(), "req-policy-replace", false)
        .await
        .unwrap();
    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 2);
    let (policies, _, reason) = policy_pins_of(&rows[1]);
    assert_eq!(policies, vec![first8(&spending_limit_hash())]);
    assert_eq!(reason, PinsUpdateReason::PolicyAdded);

    h.submit(&[1], Some("req-after-replace")).await.unwrap();
}

/// The single pin of a rule's only policy is dropped on removal even when
/// the policy differs from its pin, so a replacement policy gets a one-pin
/// record the next verb accepts.
#[tokio::test]
async fn removing_a_drifted_only_policy_drops_its_pin() {
    let h = policy_harness(vec![policy_p()]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.set_entry(wasm_instance(&policy_p(), [0xab; 32]));
    h.after_send(1, rule_one_with_policies(vec![]));
    remove_policy(&h, 0, "req-drifted-remove").await.unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-drifted-remove");
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert!(policies.is_empty(), "{policies:?}");
    assert_eq!(reason, PinsUpdateReason::PolicyRemoved);

    h.after_send(1, rule_one_with_policies(vec![policy_q()]));
    add_policy(&h, &policy_q(), "req-drifted-replace", false)
        .await
        .unwrap();
    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 2);
    let (policies, _, reason) = policy_pins_of(&rows[1]);
    assert_eq!(policies, vec![first8(&spending_limit_hash())]);
    assert_eq!(reason, PinsUpdateReason::PolicyAdded);

    h.submit(&[1], Some("req-after-drifted-replace"))
        .await
        .unwrap();
}

/// A rule's only policy that cannot be read is still removed, and its
/// single pin is dropped with it.
#[tokio::test]
async fn removing_an_unreadable_only_policy_confirms_and_drops_its_pin() {
    let h = policy_harness(vec![policy_p()]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.fail_reads_of(&policy_p());
    h.after_send(1, rule_one_with_policies(vec![]));
    remove_policy(&h, 0, "req-unreadable-remove").await.unwrap();
    assert_eq!(h.sends(), 1);

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-unreadable-remove");
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert!(policies.is_empty(), "{policies:?}");
    assert_eq!(reason, PinsUpdateReason::PolicyRemoved);
}

/// With two policy pins, the removal drops the pin equal to the removed
/// policy's hash, not the first one, and the next verb checks the policy
/// that stays.
#[tokio::test]
async fn removing_one_of_two_policies_drops_the_pin_of_its_hash() {
    let h = policy_harness(vec![policy_p(), policy_q()]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH), first8(&spending_limit_hash())],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![policy_p()]));
    remove_policy(&h, 1, "req-remove-second").await.unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-remove-second");
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::PolicyRemoved);

    h.submit(&[1], Some("req-after-remove-second"))
        .await
        .unwrap();
}

/// Removing a policy no pin covers, from a rule that keeps a pinned policy,
/// leaves the record alone, so the policy that stays is still checked.
#[tokio::test]
async fn removing_an_unpinned_policy_beside_a_pinned_one_keeps_the_pin() {
    let h = policy_harness(vec![policy_p(), policy_r()]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![policy_p()]));
    remove_policy(&h, 1, "req-remove-unpinned").await.unwrap();
    assert!(h.pins_updated_rows().is_empty());

    h.set_entry(wasm_instance(&policy_p(), [0xab; 32]));
    let err = h
        .submit(&[1], Some("req-after-remove-unpinned"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SaError::PolicyHashDrift { rule_id: 1, .. }),
        "{err:?}"
    );
}

/// A record with two policy pins, neither equal to the removed policy's
/// hash, is left as it is even when the policy is the rule's only one: the
/// removal confirms and writes no row, and the next verb refuses the rule,
/// which holds two policy pins and no policy.
#[tokio::test]
async fn removing_a_policy_no_pin_of_two_matches_writes_no_row() {
    let h = policy_harness(vec![policy_r()]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH), first8(&spending_limit_hash())],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![]));
    remove_policy(&h, 0, "req-remove-under-two-pins")
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
    assert!(h.pins_updated_rows().is_empty());

    let err = h
        .submit(&[1], Some("req-after-remove-under-two-pins"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::PinnedPolicyAbsent {
                rule_id: 1,
                pinned_count: 2,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(h.sends(), 1);
}

// ── Policy pins with no policy on chain ───────────────────────────────────────

/// A record pinning a policy on a rule with no policy on chain refuses the
/// submission with the caller's request id before its invocation is
/// simulated; nothing is sent and no drift row is written.
#[tokio::test]
async fn a_policy_pin_with_no_live_policy_refuses_and_sends_nothing() {
    let h = policy_harness(vec![]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let err = h.submit(&[1], Some("req-policy-absent")).await.unwrap_err();
    match &err {
        SaError::PinnedPolicyAbsent {
            rule_id: 1,
            pinned_count: 1,
            smart_account_redacted: redacted,
            request_id,
        } => {
            assert_eq!(redacted.as_str(), smart_account_redacted());
            assert_eq!(request_id, "req-policy-absent");
        }
        other => panic!("expected PinnedPolicyAbsent; got {other:?}"),
    }
    assert_eq!(err.wire_code(), "sa.pinned_policy_absent");
    assert_eq!(h.sends(), 0);
    assert!(!h.simulated("noop"));
    assert!(!h.rows().iter().any(|e| matches!(
        e.event_kind,
        EventKind::SaPolicyHashDrift { .. } | EventKind::SaVerifierHashDrift { .. }
    )));
}

/// A record without policy pins on a rule with no policy on chain signs.
#[tokio::test]
async fn a_rule_without_policies_or_policy_pins_signs() {
    let h = policy_harness(vec![]).await;
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.submit(&[1], Some("req-no-policy")).await.unwrap();
    assert_eq!(h.sends(), 1);
}

/// A policy added to a rule with no policy on chain replaces the record's
/// stale policy pin with its own, and the next verb signs.
#[tokio::test]
async fn a_policy_added_with_no_live_policy_replaces_a_stale_pin() {
    let h = policy_harness(vec![]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![policy_q()]));
    add_policy(&h, &policy_q(), "req-repin", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-repin");
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert_eq!(policies, vec![first8(&spending_limit_hash())]);
    assert_eq!(reason, PinsUpdateReason::PolicyAdded);
    assert_eq!(h.sends(), 1);

    h.submit(&[1], Some("req-after-repin")).await.unwrap();
    assert_eq!(h.sends(), 2);
}

/// The same repair from the two-pin record a removal of the last policy
/// leaves: the add pins exactly the added policy, and the next verb signs.
#[tokio::test]
async fn a_policy_added_after_the_last_of_two_pinned_policies_replaces_both_pins() {
    let h = policy_harness(vec![]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH), first8(&spending_limit_hash())],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![policy_p()]));
    add_policy(&h, &policy_p(), "req-repin-two", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    let (policies, _, reason) = policy_pins_of(&rows[0]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::PolicyAdded);

    h.submit(&[1], Some("req-after-repin-two")).await.unwrap();
    assert_eq!(h.sends(), 2);
}

/// A policy added to a rule with no policy on chain drops the stale policy
/// pin's executable reference with it: a Wasm policy replacing a pinned
/// external reference leaves the reference list empty, and the next verb
/// signs.
#[tokio::test]
async fn a_policy_added_with_no_live_policy_drops_a_stale_reference_pin() {
    let h = policy_harness(vec![]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![Some(reference_pin(KNOWN_WASM_HASH))],
    );
    h.after_send(1, rule_one_with_policies(vec![policy_q()]));
    add_policy(&h, &policy_q(), "req-repin-reference", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    match &rows[0].event_kind {
        EventKind::SaContextRulePinsUpdated {
            rule_id: 1,
            pinned_policy_wasm_hashes_first8,
            pinned_policy_executable_refs,
            reason,
            ..
        } => {
            assert_eq!(
                pinned_policy_wasm_hashes_first8,
                &vec![first8(&spending_limit_hash())]
            );
            assert!(
                pinned_policy_executable_refs.is_empty(),
                "{pinned_policy_executable_refs:?}"
            );
            assert_eq!(*reason, PinsUpdateReason::PolicyAdded);
        }
        other => panic!("expected SaContextRulePinsUpdated for rule 1; got {other:?}"),
    }

    h.submit(&[1], Some("req-after-repin-reference"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 2);
}

/// `verify-pins` reports a verifier that cannot be read as unavailable and a
/// drifted policy as drift, and names the verifier's failure code although
/// a policy failure is recorded after it: the first failure code, verifiers
/// before policies, whatever each kind's final status.
#[tokio::test]
async fn verify_pins_names_the_verifier_failure_beside_a_drifted_policy() {
    let undecodable_policy = contract(0x33);
    let h = policy_harness(vec![undecodable_policy.clone(), policy_p()]).await;
    h.set_entry(undecodable_instance(&undecodable_policy));
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![FOREIGN_FIRST8.to_owned()],
        vec![],
        vec![],
    );
    h.fail_reads_of(&verifier_v());

    let result = h
        .rule_manager()
        .verify_rule_wasm_pins(
            smart_account(),
            1,
            &account_id_for_seed(SEED),
            "req-verify-merge",
        )
        .await
        .unwrap();
    assert_eq!(result.verifier_pin_status, PinStatus::Unavailable);
    assert_eq!(result.policy_pin_status, PinStatus::Drift);
    assert!(result.observed_verifier_first8.is_empty());
    assert_eq!(
        result.observed_policy_first8,
        vec![first8(&KNOWN_WASM_HASH)]
    );
    assert_eq!(result.unavailable_wire_code, Some("sa.deployment_failed"));
    assert_eq!(h.sends(), 0);
}

/// `verify-pins` reports a pinned policy with no policy on chain as policy
/// drift with no observed policy, beside the matching verifier.
#[tokio::test]
async fn verify_pins_reports_drift_for_a_policy_pin_with_no_live_policy() {
    let h = policy_harness(vec![]).await;
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let result = h
        .rule_manager()
        .verify_rule_wasm_pins(
            smart_account(),
            1,
            &account_id_for_seed(SEED),
            "req-verify-absent",
        )
        .await
        .unwrap();
    assert_eq!(result.verifier_pin_status, PinStatus::Match);
    assert_eq!(result.policy_pin_status, PinStatus::Drift);
    assert!(result.observed_policy_first8.is_empty());
    assert!(result.observed_policy_executable.is_empty());
    assert_eq!(result.pinned_policy_first8, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(result.unavailable_wire_code, None);
    assert_eq!(h.sends(), 0);
}

/// A migration checks the migrating rule's policy pins for presence: a
/// record pinning a policy on a rule with no policy on chain refuses the
/// first step with its own code, unwrapped.
#[tokio::test]
async fn a_migration_refuses_a_rule_whose_pinned_policy_is_absent() {
    let chain = Chain::default()
        .with_rule(
            1,
            rule(
                1,
                vec![
                    delegated_signer(),
                    external_signer(&verifier_v(), &[0x11; 32]),
                ],
                vec![],
            ),
        )
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()))
        .with_entry(wasm_instance(&verifier_w(), ed25519_hash()));
    let h = Harness::new(chain).await;
    write_baseline(
        &h.audit,
        1,
        &smart_account_redacted(),
        &signer_set_n_of_n(2),
    );
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let result = migration_plan(webauthn_hash(), ed25519_hash())
        .submit(&signer, &h.manager, "req-migrate-absent")
        .await;
    assert_eq!(result.failed_step_index, Some(0));
    assert!(
        matches!(
            result.failed_step_error,
            Some(SaError::PinnedPolicyAbsent {
                rule_id: 1,
                pinned_count: 1,
                ..
            })
        ),
        "{:?}",
        result.failed_step_error
    );
    assert_eq!(h.sends(), 0);
    assert!(h.pins_updated_rows().is_empty());
}
