//! The pinned-hash drift check `submit_signed_invoke` runs before signing,
//! the pin record the wallet's own verifier-set mutations keep in step, and
//! the signer-set comparison and state rows of the signers manager, against
//! a mock Soroban RPC.
//!
//! The mock serves one smart account: its context rules through
//! `get_context_rule`, the simple-threshold values through `get_threshold`,
//! contract instances and executable-tag entries through `getLedgerEntries`,
//! the signed invocation through `simulateTransaction`, `sendTransaction` and
//! `getTransaction`. The two endpoints serve one chain unless a test gives
//! the secondary its own; a send applies the post-send state a test sets to
//! both, and each endpoint's simulations report `latestLedger` 1000 before a
//! send and 1001 after it unless a test holds that endpoint behind, in which
//! case its reads serve the state before the send. Every request is
//! recorded, so a test can assert that a refused submission never simulated
//! its invocation and never sent anything.
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

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::reader::AuditReader;
use stellar_agent_core::audit_log::schema::{EventKind, ExecutableRefPin, PinsUpdateReason};
use stellar_agent_core::audit_log::signer_set::{
    BaselineReason, ObservedSignerSet, SignerEntryV2, SignerIdentityV2, SignerPubkey,
    SignerSetSnapshotV2, SignerSetView, ThresholdObservation, account_digest,
};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::{RedactedStrkey, redact_strkey_first5_last5};
use stellar_agent_core::smart_account::rule_id::ContextRuleId;
use stellar_agent_network::SoftwareSigningKey;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::migration::{
    MigrationPlan, RuleMigration, SignerMigrationStep,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleManager, ContextRuleManagerConfig, PinStatus,
};
use stellar_agent_smart_account::managers::signers::{
    PreviousBaseline, SignersManager, SignersManagerConfig,
};
use stellar_agent_smart_account::signers::THRESHOLD_POLICY_WASM_HASHES;
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

/// A signer delegated to the ed25519 account `[byte; 32]`.
fn delegated_account(byte: u8) -> ScVal {
    scvec(vec![
        symbol("Delegated"),
        ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([byte; 32])),
        ))),
    ])
}

/// A signer delegated to the contract `addr`.
fn contract_delegate(addr: &ScAddress) -> ScVal {
    scvec(vec![symbol("Delegated"), ScVal::Address(addr.clone())])
}

/// A Default-context rule with `signers` and `policies`; signer and policy
/// ids count from 0.
fn rule(rule_id: u32, signers: Vec<ScVal>, policies: Vec<ScAddress>) -> ScVal {
    rule_with_ids(
        rule_id,
        (0..).zip(signers).collect::<Vec<(u32, ScVal)>>(),
        policies,
    )
}

/// A Default-context rule whose signers carry the given ids; policy ids
/// count from 0.
fn rule_with_ids(rule_id: u32, signers: Vec<(u32, ScVal)>, policies: Vec<ScAddress>) -> ScVal {
    let (signer_ids, signers): (Vec<ScVal>, Vec<ScVal>) = signers
        .into_iter()
        .map(|(id, signer)| (ScVal::U32(id), signer))
        .unzip();
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

/// The ledger every simulation reports before a submission is sent.
const PRE_SEND_LEDGER: u32 = 1000;

/// The ledger a sent submission confirms at, and the ledger every simulation
/// reports after the send unless a test holds an endpoint behind.
const CONFIRMATION_LEDGER: u32 = 1001;

/// The state a confirmed submission leaves on chain, applied at
/// `sendTransaction`.
#[derive(Clone, Default)]
struct AfterSend {
    rules: Vec<(u32, ScVal)>,
    /// `(policy strkey, rule id, threshold)` entries of the threshold table.
    thresholds: Vec<(String, u32, u32)>,
}

/// A chain's rules by id and its threshold table.
type RulesAndThresholds = (HashMap<u32, ScVal>, HashMap<(String, u32), u32>);

/// The live state one endpoint serves.
#[derive(Clone, Default)]
struct Chain {
    rules: HashMap<u32, ScVal>,
    entries: HashMap<String, Value>,
    /// `getLedgerEntries` requests naming one of these keys answer with a
    /// JSON-RPC error.
    failing_keys: HashSet<String>,
    /// What `get_threshold(rule_id, smart_account)` of a policy returns, by
    /// `(policy strkey, rule id)`; a pair without an entry returns `Void`.
    thresholds: HashMap<(String, u32), u32>,
    /// The executable hash of each contract served with [`Chain::with_wasm`],
    /// by strkey; the baseline helpers identify simple-threshold policies by it.
    wasm: HashMap<String, [u8; 32]>,
    after_send: Option<AfterSend>,
    /// The rules and thresholds before the last send, which a simulation
    /// reporting a ledger behind the confirmation serves.
    before_send: Option<RulesAndThresholds>,
    /// A state change that lands while an endpoint is behind, applied once a
    /// read behind the confirmation is served, and where it lands.
    after_behind_read: Option<(AfterSend, Landing)>,
    /// What a simulated `add_signer` or `add_policy` returns; `U32(7)` when
    /// unset.
    add_return: Option<ScVal>,
}

/// Where a [`Chain::after_behind_read`] change lands.
#[derive(Clone, Copy)]
enum Landing {
    /// On every endpoint's chain, as a change both endpoints later serve.
    EveryEndpoint,
    /// On the chain of the endpoint whose read was behind, as a change only
    /// that endpoint serves.
    LaggingEndpoint,
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

    /// Serves `addr` as a Wasm contract with `hash`.
    fn with_wasm(mut self, addr: &ScAddress, hash: [u8; 32]) -> Self {
        self.wasm.insert(strkey(addr), hash);
        self.with_entry(wasm_instance(addr, hash))
    }

    /// Makes `get_threshold(rule_id, ..)` of `policy` return `threshold`.
    fn with_threshold(mut self, policy: &ScAddress, rule_id: u32, threshold: u32) -> Self {
        self.thresholds.insert((strkey(policy), rule_id), threshold);
        self
    }

    /// Applies a send: keeps the current rules and thresholds for reads
    /// behind the confirmation, then applies the pending post-send state.
    fn apply_send(&mut self) {
        self.before_send = Some((self.rules.clone(), self.thresholds.clone()));
        if let Some(after) = self.after_send.take() {
            self.apply(&after);
        }
    }

    /// Replaces the rules and thresholds `state` names.
    fn apply(&mut self, state: &AfterSend) {
        for (rule_id, value) in &state.rules {
            self.rules.insert(*rule_id, value.clone());
        }
        for (policy, rule_id, threshold) in &state.thresholds {
            self.thresholds
                .insert((policy.clone(), *rule_id), *threshold);
        }
    }
}

/// What one endpoint saw.
#[derive(Default)]
struct Log {
    ledger_keys: Mutex<Vec<String>>,
    simulated: Mutex<Vec<String>>,
    sends: AtomicUsize,
}

impl Log {
    fn simulated(&self) -> Vec<String> {
        self.simulated.lock().unwrap().clone()
    }

    /// Whether the endpoint saw no request at all.
    fn is_untouched(&self) -> bool {
        self.ledger_keys.lock().unwrap().is_empty()
            && self.simulated.lock().unwrap().is_empty()
            && self.sends.load(Ordering::SeqCst) == 0
    }
}

/// The `latestLedger` one endpoint's simulations report, and how late they
/// answer after a send.
#[derive(Default)]
struct Ledgers {
    /// Ledgers the first simulations before the send report, in order;
    /// [`PRE_SEND_LEDGER`] once empty.
    before_send: Mutex<VecDeque<u32>>,
    /// Ledgers the next simulations after the send report, in order.
    queued: Mutex<VecDeque<u32>>,
    /// The ledger every later simulation after the send reports; the
    /// confirmation ledger when unset.
    after_send: Mutex<Option<u32>>,
    /// How long every simulation after the send takes to answer; at once
    /// when unset.
    delay_after_send: Mutex<Option<Duration>>,
}

impl Ledgers {
    fn next_before_send(&self) -> u32 {
        self.before_send
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(PRE_SEND_LEDGER)
    }

    fn next_after_send(&self) -> u32 {
        self.queued
            .lock()
            .unwrap()
            .pop_front()
            .or(*self.after_send.lock().unwrap())
            .unwrap_or(CONFIRMATION_LEDGER)
    }
}

/// Poisons the audit writer's mutex when the endpoint receives `at` (a
/// JSON-RPC method or a simulated function name), once.
struct Poison {
    at: &'static str,
    audit: Arc<Mutex<AuditWriter>>,
}

impl Poison {
    /// Panics inside a thread that holds the writer lock, which poisons it.
    fn fire(self) {
        let audit = self.audit;
        let joined = std::thread::spawn(move || {
            let _guard = audit.lock().unwrap();
            panic!("poisoning the audit writer from the mock RPC");
        })
        .join();
        assert!(joined.is_err(), "the poisoning thread panicked");
    }
}

struct Rpc {
    /// The chain this endpoint serves.
    chain: Arc<Mutex<Chain>>,
    /// Every endpoint's chain; a send on this endpoint applies to each.
    chains: Vec<Arc<Mutex<Chain>>>,
    log: Arc<Log>,
    ledgers: Arc<Ledgers>,
    /// Whether a submission was sent, shared by both endpoints.
    sent: Arc<AtomicBool>,
    poison: Arc<Mutex<Option<Poison>>>,
}

impl Rpc {
    /// Applies this endpoint's pending [`Chain::after_behind_read`] change
    /// where its [`Landing`] names. The read that triggers it is served from
    /// the state before the send, so the change reaches only later reads.
    fn land_after_behind_read(&self) {
        let pending = self.chain.lock().unwrap().after_behind_read.take();
        match pending {
            Some((change, Landing::EveryEndpoint)) => {
                for chain in &self.chains {
                    let mut chain = chain.lock().unwrap();
                    chain.after_behind_read = None;
                    chain.apply(&change);
                }
            }
            Some((change, Landing::LaggingEndpoint)) => {
                self.chain.lock().unwrap().apply(&change);
            }
            None => {}
        }
    }

    fn poison_at(&self, name: &str) {
        let poison = self.poison.lock().unwrap().take_if(|p| p.at == name);
        if let Some(poison) = poison {
            poison.fire();
        }
    }
}

fn simulate_result(value: &ScVal, auth: &[SorobanAuthorizationEntry], ledger: u32) -> Value {
    let mut result =
        rpc_mock_helpers::build_simulate_response(&value.to_xdr_base64(Limits::none()).unwrap());
    result["results"][0]["auth"] = json!(
        auth.iter()
            .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
            .collect::<Vec<_>>()
    );
    result["latestLedger"] = json!(ledger);
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
        let method = body["method"].as_str().unwrap();
        self.poison_at(method);
        match method {
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
                reply(json!({"entries": entries, "latestLedger": PRE_SEND_LEDGER}))
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
                self.poison_at(&function);
                let sent = self.sent.load(Ordering::SeqCst);
                let ledger = if sent {
                    self.ledgers.next_after_send()
                } else {
                    self.ledgers.next_before_send()
                };
                if sent && ledger < CONFIRMATION_LEDGER {
                    self.land_after_behind_read();
                }
                let chain = self.chain.lock().unwrap();
                // A read behind the confirmation ledger serves the state
                // before the send.
                let (rules, thresholds) = match &chain.before_send {
                    Some((rules, thresholds)) if ledger < CONFIRMATION_LEDGER => {
                        (rules, thresholds)
                    }
                    _ => (&chain.rules, &chain.thresholds),
                };
                let response = match function.as_str() {
                    "get_context_rule" => {
                        let ScVal::U32(rule_id) = invoke.args[0] else {
                            panic!("get_context_rule takes a u32")
                        };
                        let value = rules
                            .get(&rule_id)
                            .unwrap_or_else(|| panic!("rule {rule_id} is not on the mock chain"));
                        reply(simulate_result(value, &[], ledger))
                    }
                    "get_threshold" => {
                        let ScVal::U32(rule_id) = invoke.args[0] else {
                            panic!("get_threshold takes a u32 rule id")
                        };
                        let value = thresholds
                            .get(&(strkey(&invoke.contract_address), rule_id))
                            .map_or(ScVal::Void, |threshold| ScVal::U32(*threshold));
                        reply(simulate_result(&value, &[], ledger))
                    }
                    _ => {
                        let value = match function.as_str() {
                            "add_signer" | "add_policy" => {
                                chain.add_return.clone().unwrap_or(ScVal::U32(7))
                            }
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
                        reply(simulate_result(&value, &auth, ledger))
                    }
                };
                match *self.ledgers.delay_after_send.lock().unwrap() {
                    Some(delay) if sent => response.set_delay(delay),
                    _ => response,
                }
            }
            "sendTransaction" => {
                self.log.sends.fetch_add(1, Ordering::SeqCst);
                for (index, chain) in self.chains.iter().enumerate() {
                    // Both endpoints may serve one chain; apply the send once.
                    if self.chains[..index].iter().any(|c| Arc::ptr_eq(c, chain)) {
                        continue;
                    }
                    chain.lock().unwrap().apply_send();
                }
                self.sent.store(true, Ordering::SeqCst);
                let hash = send_transaction_hash_hex(&body, PASSPHRASE);
                reply(json!({
                    "status": "PENDING", "hash": hash,
                    "latestLedger": PRE_SEND_LEDGER, "latestLedgerCloseTime": "1234567890"
                }))
            }
            "getTransaction" => reply(json!({
                "status": "SUCCESS", "latestLedger": CONFIRMATION_LEDGER, "oldestLedger": 1,
                "ledger": CONFIRMATION_LEDGER,
                "createdAt": (stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000).to_string(),
            })),
            "getNetwork" => reply(get_network_result(PASSPHRASE)),
            "getLatestLedger" => reply(
                json!({"id": "ab".repeat(32), "sequence": PRE_SEND_LEDGER, "protocolVersion": 27}),
            ),
            other => panic!("unexpected RPC method: {other}"),
        }
    }
}

// ── Harness ───────────────────────────────────────────────────────────────────

/// A smart account served by a primary and a secondary endpoint, a signers
/// manager over both, and its audit log.
///
/// Both endpoints serve one chain unless the harness is built with a
/// secondary chain of its own.
struct Harness {
    primary: MockServer,
    chain: Arc<Mutex<Chain>>,
    secondary_chain: Arc<Mutex<Chain>>,
    primary_log: Arc<Log>,
    secondary_log: Arc<Log>,
    primary_ledgers: Arc<Ledgers>,
    secondary_ledgers: Arc<Ledgers>,
    primary_poison: Arc<Mutex<Option<Poison>>>,
    audit: Arc<Mutex<AuditWriter>>,
    log_path: PathBuf,
    manager: Arc<SignersManager>,
    _dir: tempfile::TempDir,
    _secondary: MockServer,
}

impl Harness {
    async fn new(chain: Chain) -> Self {
        Self::build(chain, None, Duration::from_secs(10)).await
    }

    /// A harness whose secondary endpoint serves `secondary` instead of the
    /// primary's chain.
    async fn with_secondary(chain: Chain, secondary: Chain) -> Self {
        Self::build(chain, Some(secondary), Duration::from_secs(10)).await
    }

    /// A harness whose manager has `timeout`, the `confirmation_recording`
    /// budget of its signer verbs.
    async fn with_timeout(chain: Chain, timeout: Duration) -> Self {
        Self::build(chain, None, timeout).await
    }

    async fn build(chain: Chain, secondary: Option<Chain>, timeout: Duration) -> Self {
        let chain = Arc::new(Mutex::new(chain));
        let secondary_chain = secondary.map_or_else(
            || Arc::clone(&chain),
            |secondary| Arc::new(Mutex::new(secondary)),
        );
        let chains = vec![Arc::clone(&chain), Arc::clone(&secondary_chain)];
        let primary_log = Arc::new(Log::default());
        let secondary_log = Arc::new(Log::default());
        let primary_ledgers = Arc::new(Ledgers::default());
        let secondary_ledgers = Arc::new(Ledgers::default());
        let primary_poison = Arc::new(Mutex::new(None));
        let sent = Arc::new(AtomicBool::new(false));
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        for (server, served, log, ledgers, poison) in [
            (
                &primary,
                &chain,
                &primary_log,
                &primary_ledgers,
                Arc::clone(&primary_poison),
            ),
            (
                &secondary,
                &secondary_chain,
                &secondary_log,
                &secondary_ledgers,
                Arc::new(Mutex::new(None)),
            ),
        ] {
            Mock::given(method("POST"))
                .respond_with(Rpc {
                    chain: Arc::clone(served),
                    chains: chains.clone(),
                    log: Arc::clone(log),
                    ledgers: Arc::clone(ledgers),
                    sent: Arc::clone(&sent),
                    poison,
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
                timeout,
                CHAIN_ID.to_owned(),
            ))
            .unwrap(),
        );
        Self {
            primary,
            chain,
            secondary_chain,
            primary_log,
            secondary_log,
            primary_ledgers,
            secondary_ledgers,
            primary_poison,
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

    /// Replaces rule `rule_id` on every endpoint's chain, as a change made
    /// outside the wallet.
    fn set_rule(&self, rule_id: u32, value: &ScVal) {
        for chain in [&self.chain, &self.secondary_chain] {
            chain.lock().unwrap().rules.insert(rule_id, value.clone());
        }
    }

    /// Replaces the threshold of `policy` for `rule_id` on every endpoint's
    /// chain, as a change made outside the wallet.
    fn set_threshold(&self, policy: &ScAddress, rule_id: u32, threshold: u32) {
        for chain in [&self.chain, &self.secondary_chain] {
            chain
                .lock()
                .unwrap()
                .thresholds
                .insert((strkey(policy), rule_id), threshold);
        }
    }

    /// Sets the rule a confirmed submission leaves on every endpoint's chain.
    fn after_send(&self, rule_id: u32, value: ScVal) {
        self.after_send_state(&AfterSend {
            rules: vec![(rule_id, value)],
            thresholds: vec![],
        });
    }

    /// Sets the state a confirmed submission leaves on every endpoint's chain.
    fn after_send_state(&self, after: &AfterSend) {
        for chain in [&self.chain, &self.secondary_chain] {
            chain.lock().unwrap().after_send = Some(after.clone());
        }
    }

    /// Sets a state change that lands on every endpoint's chain once a read
    /// behind the confirmation is served, as a transaction confirmed while
    /// the endpoints lag.
    fn after_behind_read(&self, change: &AfterSend) {
        self.set_after_behind_read(change, Landing::EveryEndpoint);
    }

    /// Sets a state change that lands only on the chain of the endpoint
    /// whose read is behind the confirmation, once that read is served: an
    /// endpoint that serves a state the other never does. The harness must
    /// give the secondary its own chain.
    fn after_behind_read_on_the_lagging_endpoint(&self, change: &AfterSend) {
        self.set_after_behind_read(change, Landing::LaggingEndpoint);
    }

    fn set_after_behind_read(&self, change: &AfterSend, landing: Landing) {
        for chain in [&self.chain, &self.secondary_chain] {
            chain.lock().unwrap().after_behind_read = Some((change.clone(), landing));
        }
    }

    /// Makes the primary's simulated `add_signer` and `add_policy` return
    /// `value`.
    fn set_simulated_add_return(&self, value: ScVal) {
        self.chain.lock().unwrap().add_return = Some(value);
    }

    /// Poisons the audit writer when the primary endpoint receives `at`.
    fn poison_audit_writer_at(&self, at: &'static str) {
        *self.primary_poison.lock().unwrap() = Some(Poison {
            at,
            audit: Arc::clone(&self.audit),
        });
    }

    fn write(&self, entry: AuditEntry) {
        self.audit.lock().unwrap().write_entry(entry).unwrap();
    }

    /// The rule `rule_id` the primary endpoint serves now.
    fn served_rule(&self, rule_id: u32) -> ScVal {
        self.chain.lock().unwrap().rules[&rule_id].clone()
    }

    /// The version-2 snapshot of rule `rule_id` the signer-set observation
    /// builds from the primary's chain: every signer's full identity in
    /// ascending id order and, when exactly one attached policy runs a
    /// simple-threshold executable, its threshold.
    fn snapshot_of(&self, rule_id: u32) -> SignerSetSnapshotV2 {
        let chain = self.chain.lock().unwrap();
        let (ids, signers, policies) = rule_parts(&chain.rules[&rule_id]);
        let mut entries: Vec<SignerEntryV2> = ids
            .into_iter()
            .zip(&signers)
            .map(|(id, signer)| SignerEntryV2 {
                id,
                identity: identity_of(signer),
            })
            .collect();
        entries.sort_by_key(|entry| entry.id);
        let mut simple_threshold: Vec<&ScAddress> = policies
            .iter()
            .filter(|policy| {
                chain
                    .wasm
                    .get(&strkey(policy))
                    .is_some_and(|hash| THRESHOLD_POLICY_WASM_HASHES.contains(hash))
            })
            .collect();
        simple_threshold.dedup();
        let threshold = match simple_threshold.as_slice() {
            [policy] => Some(ThresholdObservation {
                policy: contract_id(policy),
                threshold: chain.thresholds[&(strkey(policy), rule_id)],
            }),
            _ => None,
        };
        SignerSetSnapshotV2 {
            signers: entries,
            threshold,
        }
    }

    /// Writes a version-2 baseline of rule `rule_id` recording the chain as
    /// the observation reads it.
    fn baseline_v2(&self, rule_id: u32) {
        let snapshot = self.snapshot_of(rule_id);
        self.write_v2_baseline(rule_id, &snapshot);
    }

    fn write_v2_baseline(&self, rule_id: u32, snapshot: &SignerSetSnapshotV2) {
        let mut writer = self.audit.lock().unwrap();
        let tip = writer.current_chain_tip();
        writer
            .write_entry(AuditEntry::new_sa_signer_set_baselined_v2(
                rule_id,
                snapshot,
                PRE_SEND_LEDGER,
                1_700_000_000_000,
                BaselineReason::first_observation(),
                tip,
                account_digest(PASSPHRASE, &strkey(&smart_account())),
                RedactedStrkey::from_already_redacted(smart_account_redacted()),
                CHAIN_ID,
                "req-baseline",
            ))
            .unwrap();
    }

    /// Writes a version-1 baseline of rule `rule_id` from the primary's
    /// chain: the version-1 form of each signer in the rule's order and the
    /// simple-threshold value.
    fn baseline_v1(&self, rule_id: u32) {
        let snapshot = self.snapshot_of(rule_id);
        let (ids, signers, _) = rule_parts(&self.served_rule(rule_id));
        let threshold = snapshot
            .threshold
            .expect("a version-1 baseline records a threshold")
            .threshold;
        self.write_v1_baseline(
            rule_id,
            &ObservedSignerSet {
                signer_count: u32::try_from(ids.len()).unwrap(),
                threshold,
                signer_ids: ids,
                signer_pubkeys: signers
                    .iter()
                    .map(|signer| pubkey_v1_of(signer).expect("a version-1 signer"))
                    .collect(),
            },
        );
    }

    fn write_v1_baseline(&self, rule_id: u32, observed: &ObservedSignerSet) {
        let mut writer = self.audit.lock().unwrap();
        let tip = writer.current_chain_tip();
        writer
            .write_entry(AuditEntry::new_sa_signer_set_baselined(
                rule_id,
                observed,
                vec!["0101010101010101".to_owned(); observed.signer_pubkeys.len()],
                1_700_000_000_000,
                BaselineReason::first_observation(),
                tip,
                RedactedStrkey::from_already_redacted(smart_account_redacted()),
                CHAIN_ID,
                "req-baseline-v1",
            ))
            .unwrap();
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

/// The `signer_ids`, `signers` and `policies` of a rule value.
fn rule_parts(rule: &ScVal) -> (Vec<u32>, Vec<ScVal>, Vec<ScAddress>) {
    let ScVal::Map(Some(map)) = rule else {
        panic!("a rule is a map")
    };
    let field = |name: &str| -> Vec<ScVal> {
        map.iter()
            .find(|entry| entry.key == symbol(name))
            .map(|entry| match &entry.val {
                ScVal::Vec(Some(items)) => items.to_vec(),
                ScVal::Vec(None) => vec![],
                other => panic!("{name} is not a Vec: {other:?}"),
            })
            .unwrap_or_default()
    };
    let ids = field("signer_ids")
        .into_iter()
        .map(|id| match id {
            ScVal::U32(id) => id,
            other => panic!("a signer id is a u32: {other:?}"),
        })
        .collect();
    let policies = field("policies")
        .into_iter()
        .map(|policy| match policy {
            ScVal::Address(address) => address,
            other => panic!("a policy is an address: {other:?}"),
        })
        .collect();
    (ids, field("signers"), policies)
}

/// The contract id of a contract address.
fn contract_id(addr: &ScAddress) -> [u8; 32] {
    match addr {
        ScAddress::Contract(ContractId(Hash(id))) => *id,
        other => panic!("not a contract address: {other:?}"),
    }
}

/// The items of a signer value: its tag and its payload.
fn signer_items(signer: &ScVal) -> Vec<ScVal> {
    match signer {
        ScVal::Vec(Some(items)) => items.to_vec(),
        other => panic!("a signer is a Vec: {other:?}"),
    }
}

/// The full version-2 identity of a signer value built by this file's
/// signer builders.
fn identity_of(signer: &ScVal) -> SignerIdentityV2 {
    let items = signer_items(signer);
    match (&items[0], &items[1]) {
        (
            tag,
            ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                Uint256(pubkey),
            )))),
        ) if *tag == symbol("Delegated") => SignerIdentityV2::Ed25519 { pubkey: *pubkey },
        (tag, ScVal::Address(ScAddress::Contract(ContractId(Hash(contract)))))
            if *tag == symbol("Delegated") =>
        {
            SignerIdentityV2::DelegatedContract {
                contract: *contract,
            }
        }
        (tag, ScVal::Address(verifier)) if *tag == symbol("External") => {
            let ScVal::Bytes(ScBytes(key)) = &items[2] else {
                panic!("External key data is Bytes")
            };
            SignerIdentityV2::External {
                verifier: contract_id(verifier),
                key_data_sha256: Sha256::digest(key.as_slice()).into(),
                key_data_len: u32::try_from(key.len()).unwrap(),
            }
        }
        other => panic!("not a signer this file builds: {other:?}"),
    }
}

/// The version-1 form of a signer value, `None` for a contract delegate.
fn pubkey_v1_of(signer: &ScVal) -> Option<SignerPubkey> {
    let items = signer_items(signer);
    match (&items[0], &items[1]) {
        (
            tag,
            ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(
                Uint256(pubkey),
            )))),
        ) if *tag == symbol("Delegated") => Some(SignerPubkey::Ed25519 { pubkey: *pubkey }),
        (tag, ScVal::Address(ScAddress::Contract(_))) if *tag == symbol("Delegated") => None,
        (tag, ScVal::Address(verifier)) if *tag == symbol("External") => {
            let ScVal::Bytes(ScBytes(key)) = &items[2] else {
                panic!("External key data is Bytes")
            };
            let mut key_data_first16 = [0u8; 16];
            let len = key.len().min(16);
            key_data_first16[..len].copy_from_slice(&key[..len]);
            Some(SignerPubkey::External {
                verifier_contract: strkey(verifier),
                key_data_first16,
            })
        }
        other => panic!("not a signer this file builds: {other:?}"),
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

/// The signers of rule 1 before an add: a Delegated signer (id 0) and an
/// External signer on verifier V (id 1).
fn signers_before_add() -> Vec<(u32, ScVal)> {
    vec![
        (0, delegated_signer()),
        (1, external_signer(&verifier_v(), &[0x11; 32])),
    ]
}

/// Rule 1 before the add: [`signers_before_add`] and policy P.
fn signer_add_rule_before() -> ScVal {
    rule_with_ids(1, signers_before_add(), vec![policy_p()])
}

/// Rule 1 after `added` signers joined [`signers_before_add`], policy P kept.
fn signer_add_rule_after(added: Vec<(u32, ScVal)>) -> ScVal {
    let mut signers = signers_before_add();
    signers.extend(added);
    rule_with_ids(1, signers, vec![policy_p()])
}

/// The id the mock's `add_signer` simulation returns.
const SIMULATED_SIGNER_ID: u32 = 7;

/// Rule 1 served with [`signer_add_rule_before`], simple-threshold policy P
/// at threshold 1, and the verifiers the add tests use; its version-2
/// baseline recorded from the served chain, and a pin record when `pinned`.
async fn signer_add_harness(pinned: bool) -> Harness {
    let chain = Chain::default()
        .with_rule(1, signer_add_rule_before())
        .with_wasm(&verifier_v(), webauthn_hash())
        .with_wasm(&verifier_w(), ed25519_hash())
        .with_wasm(&contract(0x22), [0xdd; 32])
        .with_wasm(&passkey_verifier(), webauthn_hash())
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 1);
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
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

/// A WebAuthn verifier contract distinct from verifier V.
fn passkey_verifier() -> ScAddress {
    contract(0x24)
}

/// A passkey signer: an External signer on [`passkey_verifier`] whose key
/// data is a 65-byte uncompressed P-256 point and a 16-byte credential id.
fn passkey_signer() -> ScVal {
    let mut key_data = vec![0x04];
    key_data.extend_from_slice(&[0x5a; 64]);
    key_data.extend_from_slice(&[0xc1; 16]);
    external_signer(&passkey_verifier(), &key_data)
}

/// Adds an External signer on `verifier` with 32 bytes of key data to rule
/// 1; the confirmed add leaves the signer on chain under the id the
/// simulation returned.
async fn add_external_signer(
    h: &Harness,
    verifier: &ScAddress,
    request_id: &str,
    accept_unknown_verifier: bool,
) -> Result<u32, SaError> {
    add_signer_value(
        h,
        external_signer(verifier, &[0x33; 32]),
        request_id,
        accept_unknown_verifier,
    )
    .await
}

/// Adds `new_signer` to rule 1; the confirmed add leaves it on chain under
/// the id the simulation returned.
async fn add_signer_value(
    h: &Harness,
    new_signer: ScVal,
    request_id: &str,
    accept_unknown_verifier: bool,
) -> Result<u32, SaError> {
    h.after_send(
        1,
        signer_add_rule_after(vec![(SIMULATED_SIGNER_ID, new_signer.clone())]),
    );
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.manager
        .add_signer(
            smart_account(),
            1,
            new_signer,
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

/// A passkey signer (an External signer on a WebAuthn verifier) added to a
/// pinned rule pins its verifier like any other new verifier: the record
/// gains the WebAuthn verifier's pin.
#[tokio::test]
async fn a_passkey_signer_added_to_a_pinned_rule_pins_its_verifier() {
    let h = signer_add_harness(true).await;
    add_signer_value(&h, passkey_signer(), "req-add-passkey", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-add-passkey");
    let (verifiers, _, _, reason) = pins_updated_fields(&rows[0]);
    assert_eq!(
        verifiers,
        vec![first8(&webauthn_hash()), first8(&webauthn_hash())],
        "the passkey's verifier is pinned beside verifier V"
    );
    assert_eq!(reason, PinsUpdateReason::SignerAdded);
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
    assert_eq!(h.primary_instance_reads(&verifier_w()), 0);
}

/// A confirmed signer add on an unknown verifier under the override writes
/// `SaSignerAddedV2`, then the override row naming the rule, then the
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
            "sa_signer_added_v2",
            "unknown_override(rule Some(1))",
            "sa_context_rule_pins_updated",
        ]
    );
}

/// A signer add over a version-2 baseline compares the chain with it through
/// both endpoints in version 2, submits, observes the confirmed rule at the
/// confirmation ledger, and records a `SaSignerAddedV2` row carrying the new
/// id and the full resulting set.
#[tokio::test]
async fn a_signer_add_over_a_version_2_baseline_records_the_confirmed_set() {
    let h = signer_add_harness(true).await;
    let id = add_external_signer(&h, &verifier_v(), "req-add-v2", false)
        .await
        .unwrap();
    assert_eq!(id, SIMULATED_SIGNER_ID);

    let resulting = h.snapshot_of(1);
    assert_eq!(resulting.signer_count(), 3);
    let added: Vec<AuditEntry> = h
        .rows()
        .into_iter()
        .filter(|e| e.request_id == "req-add-v2")
        .filter(|e| matches!(e.event_kind, EventKind::SaSignerAddedV2 { .. }))
        .collect();
    assert_eq!(added.len(), 1);
    match &added[0].event_kind {
        EventKind::SaSignerAddedV2 {
            rule_id,
            signer_id,
            snapshot,
            account_digest: digest,
            ..
        } => {
            assert_eq!(*rule_id, 1);
            assert_eq!(*signer_id, SIMULATED_SIGNER_ID);
            assert_eq!(snapshot, &resulting);
            assert_eq!(
                digest,
                &account_digest(PASSPHRASE, &strkey(&smart_account()))
            );
        }
        other => panic!("expected SaSignerAddedV2; got {other:?}"),
    }
    // The secondary serves only the signer-set observations: one before
    // the send and one after it. The primary also serves the drift check's
    // rule read.
    assert_eq!(
        h.secondary_log.simulated(),
        vec![
            "get_context_rule",
            "get_threshold",
            "get_context_rule",
            "get_threshold"
        ]
    );
    assert_eq!(
        h.primary_log
            .simulated()
            .iter()
            .filter(|f| *f == "get_threshold")
            .count(),
        2
    );
    assert_eq!(h.sends(), 1);
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
                external_signer(&contract(0x22), &[0x33; 32]),
                external_signer(&undecodable, &[0x34; 32]),
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

// ── Signer-set comparison and state rows of the signer verbs ──────────────────

/// Rule 1's signers in the verb tests: three delegated accounts, ids 0 to 2.
fn verb_signers() -> Vec<(u32, ScVal)> {
    vec![
        (0, delegated_account(0x10)),
        (1, delegated_account(0x11)),
        (2, delegated_account(0x12)),
    ]
}

/// Rule 1 with `signers` and simple-threshold policy P.
fn verb_rule(signers: Vec<(u32, ScVal)>) -> ScVal {
    rule_with_ids(1, signers, vec![policy_p()])
}

/// A chain serving rule 1 with [`verb_signers`] and policy P at threshold 2.
fn verb_chain() -> Chain {
    Chain::default()
        .with_rule(1, verb_rule(verb_signers()))
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 2)
}

/// A [`verb_chain`] harness with rule 1's version-2 baseline recorded from
/// the served chain.
async fn verb_harness() -> Harness {
    let h = Harness::new(verb_chain()).await;
    h.baseline_v2(1);
    h
}

/// The four signer verbs.
#[derive(Clone, Copy, Debug)]
enum Verb {
    Add,
    Remove,
    SetThreshold,
    BatchAdd,
}

const VERBS: [Verb; 4] = [Verb::Add, Verb::Remove, Verb::SetThreshold, Verb::BatchAdd];

impl Verb {
    /// The state row kinds the confirmed verb writes, in order.
    fn state_rows(self) -> Vec<&'static str> {
        match self {
            Verb::Add => vec!["sa_signer_added_v2"],
            Verb::Remove => vec!["sa_signer_removed_v2"],
            Verb::SetThreshold => vec!["sa_threshold_changed_v2"],
            Verb::BatchAdd => vec!["sa_signer_added_v2", "sa_signer_added_v2"],
        }
    }

    /// The post-send state of the intended change on [`verb_chain`]: the add
    /// assigns the simulated id 7, the batch ids 8 and 9 in input order.
    fn intended(self) -> AfterSend {
        let mut signers = verb_signers();
        let mut thresholds = vec![];
        match self {
            Verb::Add => signers.push((SIMULATED_SIGNER_ID, delegated_account(0x20))),
            Verb::Remove => signers.retain(|(id, _)| *id != 2),
            Verb::SetThreshold => thresholds.push((strkey(&policy_p()), 1, 3)),
            Verb::BatchAdd => {
                signers.extend([(8, delegated_account(0x20)), (9, delegated_account(0x21))])
            }
        }
        AfterSend {
            rules: vec![(1, verb_rule(signers))],
            thresholds,
        }
    }

    /// A post-send state that is not the intended change: the add also
    /// raises the threshold, the removal takes another signer, the threshold
    /// change lands on another value, the batch adds one signer of two.
    fn unintended(self) -> AfterSend {
        let mut signers = verb_signers();
        let mut thresholds = vec![];
        match self {
            Verb::Add => {
                signers.push((SIMULATED_SIGNER_ID, delegated_account(0x20)));
                thresholds.push((strkey(&policy_p()), 1, 3));
            }
            Verb::Remove => signers.retain(|(id, _)| *id != 1),
            Verb::SetThreshold => thresholds.push((strkey(&policy_p()), 1, 1)),
            Verb::BatchAdd => signers.push((8, delegated_account(0x20))),
        }
        AfterSend {
            rules: vec![(1, verb_rule(signers))],
            thresholds,
        }
    }

    /// Runs the verb on rule 1: add account 0x20, remove signer 2, set the
    /// threshold to 3, or batch-add accounts 0x20 and 0x21.
    async fn run(self, h: &Harness, request_id: &str) -> Result<(), SaError> {
        let signer = SoftwareSigningKey::new_from_bytes(SEED);
        let request_id = request_id.to_owned();
        match self {
            Verb::Add => h
                .manager
                .add_signer(
                    smart_account(),
                    1,
                    delegated_account(0x20),
                    &signer,
                    request_id,
                    false,
                    false,
                )
                .await
                .map(|_| ()),
            Verb::Remove => {
                h.manager
                    .remove_signer(smart_account(), 1, 2, &signer, request_id)
                    .await
            }
            Verb::SetThreshold => {
                h.manager
                    .set_threshold(smart_account(), 1, 3, &signer, request_id)
                    .await
            }
            Verb::BatchAdd => h
                .manager
                .batch_add_signers(
                    smart_account(),
                    1,
                    vec![delegated_account(0x20), delegated_account(0x21)],
                    &signer,
                    request_id,
                    false,
                    false,
                )
                .await
                .map(|_| ()),
        }
    }
}

/// The version-2 snapshot of the state a row of kind `sa_signer_*_v2` or
/// `sa_threshold_changed_v2` records.
fn state_row_snapshot(entry: &AuditEntry) -> &SignerSetSnapshotV2 {
    match &entry.event_kind {
        EventKind::SaSignerAddedV2 { snapshot, .. }
        | EventKind::SaSignerRemovedV2 { snapshot, .. }
        | EventKind::SaThresholdChangedV2 { snapshot, .. }
        | EventKind::SaSignerSetBaselinedV2 { snapshot, .. } => snapshot,
        other => panic!("expected a version-2 state row; got {other:?}"),
    }
}

/// The rows written under `request_id`.
fn rows_of(h: &Harness, request_id: &str) -> Vec<AuditEntry> {
    h.rows()
        .into_iter()
        .filter(|e| e.request_id == request_id)
        .collect()
}

/// A rule whose newest state row is version 1 refuses every signer verb
/// with `sa.signer_set_baseline_legacy` before any RPC, and writes nothing.
#[tokio::test]
async fn a_version_1_baseline_refuses_each_signer_verb_before_any_rpc() {
    for verb in VERBS {
        let h = Harness::new(verb_chain()).await;
        h.baseline_v1(1);
        let rows_before = h.rows().len();
        let err = verb.run(&h, "req-legacy").await.unwrap_err();
        assert_eq!(
            err.wire_code(),
            "sa.signer_set_baseline_legacy",
            "{verb:?}: {err:?}"
        );
        assert!(
            err.to_string()
                .contains("'smart-account signers refresh --rule-id 1'"),
            "{verb:?}: {err}"
        );
        assert!(h.primary_log.is_untouched(), "{verb:?}: no RPC");
        assert!(h.secondary_log.is_untouched(), "{verb:?}: no RPC");
        assert_eq!(h.rows().len(), rows_before, "{verb:?}: no row");
    }
}

/// A chain changed outside the wallet since the version-2 baseline refuses
/// every signer verb with `sa.signer_set_diverged` without a transaction
/// hash: the divergence row is written and nothing is sent.
#[tokio::test]
async fn a_chain_change_before_submission_refuses_each_signer_verb() {
    for verb in VERBS {
        let h = verb_harness().await;
        let mut changed = verb_signers();
        changed.push((3, delegated_account(0x13)));
        h.set_rule(1, &verb_rule(changed));

        let err = verb.run(&h, "req-changed").await.unwrap_err();
        match &err {
            SaError::SignerSetDiverged {
                rule_id: 1,
                tx_hash: None,
                expected,
                observed,
                ..
            } => {
                assert_eq!(expected.signer_count(), 3, "{verb:?}");
                assert_eq!(observed.signer_count(), 4, "{verb:?}");
                assert_eq!(expected.version(), 2, "{verb:?}");
            }
            other => panic!("{verb:?}: expected SignerSetDiverged; got {other:?}"),
        }
        assert_eq!(err.wire_code(), "sa.signer_set_diverged");
        assert_eq!(
            row_kinds(&h.rows(), "req-changed"),
            vec!["sa_signer_set_diverged"],
            "{verb:?}"
        );
        assert_eq!(h.sends(), 0, "{verb:?}");
        assert!(
            !h.simulated("add_signer") && !h.simulated("execute"),
            "{verb:?}"
        );
    }
}

/// Each signer verb whose confirmed state is the intended change records it
/// as its version-2 state row, carrying the full resulting set.
#[tokio::test]
async fn each_confirmed_signer_verb_records_its_version_2_state_row() {
    for verb in VERBS {
        let h = verb_harness().await;
        h.after_send_state(&verb.intended());
        verb.run(&h, "req-confirmed")
            .await
            .unwrap_or_else(|e| panic!("{verb:?}: the intended change must be recorded: {e:?}"));

        let rows = rows_of(&h, "req-confirmed");
        assert_eq!(
            row_kinds(&rows, "req-confirmed"),
            verb.state_rows(),
            "{verb:?}"
        );
        let resulting = h.snapshot_of(1);
        for row in &rows {
            assert_eq!(state_row_snapshot(row), &resulting, "{verb:?}");
        }
        match (&verb, &rows[0].event_kind) {
            (Verb::Add, EventKind::SaSignerAddedV2 { signer_id, .. }) => {
                assert_eq!(*signer_id, SIMULATED_SIGNER_ID);
            }
            (Verb::Remove, EventKind::SaSignerRemovedV2 { signer_id, .. }) => {
                assert_eq!(*signer_id, 2);
            }
            (
                Verb::SetThreshold,
                EventKind::SaThresholdChangedV2 {
                    previous_threshold, ..
                },
            ) => assert_eq!(
                previous_threshold,
                &Some(ThresholdObservation {
                    policy: contract_id(&policy_p()),
                    threshold: 2
                })
            ),
            (Verb::BatchAdd, EventKind::SaSignerAddedV2 { signer_id, .. }) => {
                assert_eq!(*signer_id, 8);
            }
            (verb, other) => panic!("{verb:?}: unexpected row {other:?}"),
        }
        assert_eq!(h.sends(), 1, "{verb:?}");
    }
}

/// A confirmed state that is not the intended change refuses every signer
/// verb with `sa.signer_set_diverged` carrying the transaction hash; the
/// divergence row is written and no state row.
#[tokio::test]
async fn a_confirmed_state_that_is_not_the_intended_change_refuses_each_signer_verb() {
    for verb in VERBS {
        let h = verb_harness().await;
        h.after_send_state(&verb.unintended());
        let err = verb.run(&h, "req-wrong-delta").await.unwrap_err();
        match &err {
            SaError::SignerSetDiverged {
                rule_id: 1,
                tx_hash: Some(hash),
                observed,
                ..
            } => {
                assert_eq!(hash.len(), 64, "{verb:?}");
                assert_eq!(observed, &SignerSetView::V2(h.snapshot_of(1)), "{verb:?}");
                assert!(
                    err.to_string()
                        .contains(&format!("after transaction {hash}"))
                );
            }
            other => panic!("{verb:?}: expected SignerSetDiverged with a hash; got {other:?}"),
        }
        assert_eq!(
            row_kinds(&h.rows(), "req-wrong-delta"),
            vec!["sa_signer_set_diverged"],
            "{verb:?}"
        );
        assert_eq!(h.sends(), 1, "{verb:?}");
    }
}

/// An add whose confirmed rule holds the new signer under an id other than
/// the one the simulation returned refuses with the transaction hash and
/// records no state row: the reported id must be the chain's.
#[tokio::test]
async fn an_add_the_chain_assigns_another_id_refuses_with_the_hash() {
    let h = verb_harness().await;
    let mut signers = verb_signers();
    signers.push((8, delegated_account(0x20)));
    h.after_send(1, verb_rule(signers));

    let err = Verb::Add.run(&h, "req-other-id").await.unwrap_err();
    match &err {
        SaError::SignerSetDiverged {
            tx_hash: Some(_),
            expected: SignerSetView::V2(expected),
            observed: SignerSetView::V2(observed),
            ..
        } => {
            assert!(expected.signers.iter().any(|e| e.id == SIMULATED_SIGNER_ID));
            assert!(observed.signers.iter().any(|e| e.id == 8));
        }
        other => panic!("expected SignerSetDiverged with a hash; got {other:?}"),
    }
    assert_eq!(
        row_kinds(&h.rows(), "req-other-id"),
        vec!["sa_signer_set_diverged"]
    );
}

/// A batch returns the id the chain assigned to each signer in input order,
/// whatever order the chain assigned the ids in, and writes one row per
/// signer in that order.
#[tokio::test]
async fn a_batch_returns_the_observed_ids_in_input_order() {
    let h = verb_harness().await;
    let mut signers = verb_signers();
    signers.extend([(8, delegated_account(0x21)), (9, delegated_account(0x20))]);
    h.after_send(1, verb_rule(signers));
    let signer = SoftwareSigningKey::new_from_bytes(SEED);

    let ids = h
        .manager
        .batch_add_signers(
            smart_account(),
            1,
            vec![delegated_account(0x20), delegated_account(0x21)],
            &signer,
            "req-batch-order".to_owned(),
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(ids, vec![9, 8]);
    let row_ids: Vec<u32> = rows_of(&h, "req-batch-order")
        .iter()
        .map(|e| match &e.event_kind {
            EventKind::SaSignerAddedV2 { signer_id, .. } => *signer_id,
            other => panic!("expected SaSignerAddedV2; got {other:?}"),
        })
        .collect();
    assert_eq!(row_ids, vec![9, 8]);
}

/// A secondary endpoint one ledger behind the confirmation for one read is
/// read again after a pause, and the confirmed state is recorded.
#[tokio::test]
async fn a_secondary_behind_for_one_read_is_read_again_and_the_row_is_written() {
    let h = verb_harness().await;
    h.after_send_state(&Verb::Add.intended());
    h.secondary_ledgers
        .queued
        .lock()
        .unwrap()
        .push_back(PRE_SEND_LEDGER);

    Verb::Add.run(&h, "req-lagging").await.unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-lagging"),
        vec!["sa_signer_added_v2"]
    );
    assert_eq!(
        h.secondary_log.simulated(),
        vec![
            "get_context_rule",
            "get_threshold",
            "get_context_rule",
            "get_context_rule",
            "get_threshold"
        ],
        "the behind rule read is repeated"
    );
}

/// A secondary endpoint that stays behind the confirmation ledger for the
/// whole `confirmation_recording` budget fails the recording at stage
/// `observe` with the transaction hash, naming the endpoint; no state row
/// is written.
#[tokio::test]
async fn a_secondary_that_stays_behind_fails_at_stage_observe() {
    let h = Harness::with_timeout(verb_chain(), Duration::from_secs(2)).await;
    h.baseline_v2(1);
    h.after_send_state(&Verb::Add.intended());
    *h.secondary_ledgers.after_send.lock().unwrap() = Some(PRE_SEND_LEDGER);

    let err = Verb::Add.run(&h, "req-behind").await.unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            rule_id: 1,
            tx_hash: Some(hash),
            stage,
            reason,
            ..
        } => {
            assert_eq!(*stage, "observe");
            assert_eq!(hash.len(), 64);
            assert!(
                reason.starts_with("sa.deployment_failed: ") && reason.contains("(secondary)"),
                "{reason}"
            );
        }
        other => panic!("expected BaselineWriteFailed at stage observe; got {other:?}"),
    }
    assert_eq!(err.wire_code(), "sa.baseline_write_failed");
    assert!(row_kinds(&h.rows(), "req-behind").is_empty());
    assert_eq!(h.sends(), 1);
}

/// A secondary that stays behind and answers slowly after the send is
/// named in the refusal when the `confirmation_recording` budget ends while
/// one of its reads is outstanding.
#[tokio::test]
async fn a_slow_secondary_behind_the_confirmation_is_named_when_the_budget_ends() {
    let h = Harness::with_timeout(verb_chain(), Duration::from_secs(3)).await;
    h.baseline_v2(1);
    h.after_send_state(&Verb::Add.intended());
    *h.secondary_ledgers.after_send.lock().unwrap() = Some(PRE_SEND_LEDGER);
    *h.secondary_ledgers.delay_after_send.lock().unwrap() = Some(Duration::from_millis(1200));

    let err = Verb::Add.run(&h, "req-slow-behind").await.unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            tx_hash: Some(_),
            stage,
            reason,
            ..
        } => {
            assert_eq!(*stage, "observe");
            assert!(
                reason.contains("get_context_rule (secondary)")
                    && reason.contains("latestLedger 1000"),
                "{reason}"
            );
        }
        other => panic!("expected BaselineWriteFailed at stage observe; got {other:?}"),
    }
    assert!(row_kinds(&h.rows(), "req-slow-behind").is_empty());
}

/// A secondary whose rule read after the send is current and whose
/// threshold read is behind repeats its whole observation, rule and
/// threshold, and the confirmed threshold is recorded.
#[tokio::test]
async fn a_secondary_threshold_read_behind_repeats_its_observation() {
    let h = verb_harness().await;
    h.after_send_state(&Verb::SetThreshold.intended());
    h.secondary_ledgers
        .queued
        .lock()
        .unwrap()
        .extend([CONFIRMATION_LEDGER, PRE_SEND_LEDGER]);

    Verb::SetThreshold
        .run(&h, "req-threshold-behind")
        .await
        .unwrap();
    let rows = rows_of(&h, "req-threshold-behind");
    assert_eq!(
        row_kinds(&rows, "req-threshold-behind"),
        vec!["sa_threshold_changed_v2"]
    );
    assert_eq!(
        state_row_snapshot(&rows[0]).threshold,
        Some(ThresholdObservation {
            policy: contract_id(&policy_p()),
            threshold: 3
        })
    );
    assert_eq!(
        h.secondary_log.simulated(),
        vec![
            // The comparison before the send.
            "get_context_rule",
            "get_threshold",
            // After the send: the behind threshold read repeats both reads.
            "get_context_rule",
            "get_threshold",
            "get_context_rule",
            "get_threshold",
        ]
    );
}

/// A policy list that changes between the endpoints' first rule reads and
/// the repeat of their observations refuses the recording at stage
/// `observe`: the threshold policy was identified from the earlier list.
#[tokio::test]
async fn a_policy_list_changed_during_a_repeated_observation_refuses_at_stage_observe() {
    let h = verb_harness().await;
    h.after_send_state(&Verb::SetThreshold.intended());
    for ledgers in [&h.primary_ledgers, &h.secondary_ledgers] {
        ledgers
            .queued
            .lock()
            .unwrap()
            .extend([CONFIRMATION_LEDGER, PRE_SEND_LEDGER]);
    }
    // Policy P is detached while both endpoints lag.
    h.after_behind_read(&AfterSend {
        rules: vec![(1, rule_with_ids(1, verb_signers(), vec![]))],
        thresholds: vec![],
    });

    let err = Verb::SetThreshold
        .run(&h, "req-policy-list")
        .await
        .unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            tx_hash: Some(_),
            stage,
            reason,
            ..
        } => {
            assert_eq!(*stage, "observe");
            assert!(reason.contains("policy list changed"), "{reason}");
        }
        other => panic!("expected BaselineWriteFailed at stage observe; got {other:?}"),
    }
    assert!(row_kinds(&h.rows(), "req-policy-list").is_empty());
    assert_eq!(h.sends(), 1);
}

/// Endpoints that agree after the send until one of them repeats its
/// observation and then serves another rule refuse the recording at stage
/// `observe` with `network.rpc_divergence`: the repeated reads are compared
/// across the endpoints again, and no state row is written.
#[tokio::test]
async fn endpoints_that_disagree_after_a_repeated_observation_refuse_at_stage_observe() {
    let h = Harness::with_secondary(verb_chain(), verb_chain()).await;
    h.baseline_v2(1);
    h.after_send_state(&Verb::SetThreshold.intended());
    h.primary_ledgers
        .queued
        .lock()
        .unwrap()
        .extend([CONFIRMATION_LEDGER, PRE_SEND_LEDGER]);
    // A signer joins on the primary's chain alone while it lags.
    let mut signers = verb_signers();
    signers.push((3, delegated_account(0x13)));
    h.after_behind_read_on_the_lagging_endpoint(&AfterSend {
        rules: vec![(1, verb_rule(signers))],
        thresholds: vec![],
    });

    let err = Verb::SetThreshold
        .run(&h, "req-repeated-disagree")
        .await
        .unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            tx_hash: Some(_),
            stage,
            reason,
            ..
        } => {
            assert_eq!(*stage, "observe");
            assert!(reason.starts_with("network.rpc_divergence: "), "{reason}");
        }
        other => panic!("expected BaselineWriteFailed at stage observe; got {other:?}"),
    }
    assert!(
        h.primary_log.simulated().ends_with(&[
            "get_context_rule".to_owned(),
            "get_threshold".to_owned(),
            "get_context_rule".to_owned(),
            "get_threshold".to_owned(),
        ]),
        "the primary's behind threshold read repeated its observation: {:?}",
        h.primary_log.simulated()
    );
    assert!(row_kinds(&h.rows(), "req-repeated-disagree").is_empty());
    assert_eq!(h.sends(), 1);
}

/// Rule 1 with one delegated signer and simple-threshold policy P at
/// threshold 1, its version-2 baseline and a pin record that holds no
/// verifier pin, under a two-second `confirmation_recording` budget.
async fn verifierless_pinned_rule() -> Harness {
    let chain = Chain::default()
        .with_rule(
            1,
            rule_with_ids(1, vec![(0, delegated_signer())], vec![policy_p()]),
        )
        .with_wasm(&passkey_verifier(), webauthn_hash())
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 1);
    let h = Harness::with_timeout(chain, Duration::from_secs(2)).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);
    h
}

/// A [`verifierless_pinned_rule`] harness whose secondary stays behind every
/// read after the send.
async fn verifierless_pinned_harness() -> Harness {
    let h = verifierless_pinned_rule().await;
    *h.secondary_ledgers.after_send.lock().unwrap() = Some(PRE_SEND_LEDGER);
    h
}

/// Rule 1 of [`verifierless_pinned_rule`] after the passkey signer joined
/// under the simulated id.
fn verifierless_rule_with_the_passkey() -> ScVal {
    rule_with_ids(
        1,
        vec![
            (0, delegated_signer()),
            (SIMULATED_SIGNER_ID, passkey_signer()),
        ],
        vec![policy_p()],
    )
}

/// A passkey add whose simulated return is not a `u32` confirms without an
/// id the wallet can report: it fails at stage `observe` with the
/// transaction hash, and the pin rows of the confirmed add are written.
#[tokio::test]
async fn an_add_whose_simulated_return_is_not_a_u32_fails_at_stage_observe_and_pins() {
    let h = verifierless_pinned_rule().await;
    h.set_simulated_add_return(ScVal::Void);
    h.after_send(1, verifierless_rule_with_the_passkey());
    let signer = SoftwareSigningKey::new_from_bytes(SEED);

    let err = h
        .manager
        .add_signer(
            smart_account(),
            1,
            passkey_signer(),
            &signer,
            "req-void-return".to_owned(),
            false,
            false,
        )
        .await
        .unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            tx_hash: Some(hash),
            stage,
            reason,
            ..
        } => {
            assert_eq!(*stage, "observe");
            assert_eq!(hash.len(), 64);
            assert!(
                reason.starts_with("sa.deployment_failed: ")
                    && reason.contains("add_signer: expected ScVal::U32 return, got Void"),
                "{reason}"
            );
        }
        other => panic!("expected BaselineWriteFailed at stage observe; got {other:?}"),
    }
    assert_eq!(h.sends(), 1);
    assert_eq!(
        row_kinds(&h.rows(), "req-void-return"),
        vec!["sa_context_rule_pins_updated"]
    );
    let (verifiers, _, _, reason) = pins_updated_fields(&h.pins_updated_rows()[0]);
    assert_eq!(verifiers, vec![first8(&webauthn_hash())]);
    assert_eq!(reason, PinsUpdateReason::SignerAdded);
}

/// A passkey add, single or batched, on a rule whose pin record holds no
/// verifier pin writes the passkey verifier's pin once the add confirms,
/// although the confirmed state is never observed. A later change of that
/// verifier's executable is then refused by the drift check.
#[tokio::test]
async fn a_confirmed_passkey_add_that_fails_to_record_still_pins_its_verifier() {
    for batch in [false, true] {
        let h = verifierless_pinned_harness().await;
        h.after_send(1, verifierless_rule_with_the_passkey());
        let signer = SoftwareSigningKey::new_from_bytes(SEED);
        let request_id = format!("req-pin-after-confirmation-{batch}");
        let added = if batch {
            h.manager
                .batch_add_signers(
                    smart_account(),
                    1,
                    vec![passkey_signer()],
                    &signer,
                    request_id.clone(),
                    false,
                    false,
                )
                .await
                .map(|_| ())
        } else {
            h.manager
                .add_signer(
                    smart_account(),
                    1,
                    passkey_signer(),
                    &signer,
                    request_id.clone(),
                    false,
                    false,
                )
                .await
                .map(|_| ())
        };
        match &added {
            Err(SaError::BaselineWriteFailed {
                tx_hash: Some(_),
                stage,
                ..
            }) => assert_eq!(*stage, "observe", "batch {batch}"),
            other => panic!("batch {batch}: expected stage observe; got {other:?}"),
        }
        assert_eq!(h.sends(), 1, "batch {batch}");
        assert_eq!(
            row_kinds(&h.rows(), &request_id),
            vec!["sa_context_rule_pins_updated"],
            "batch {batch}"
        );
        let rows = h.pins_updated_rows();
        assert_eq!(rows.len(), 1, "batch {batch}");
        let (verifiers, policies, _, reason) = pins_updated_fields(&rows[0]);
        assert_eq!(verifiers, vec![first8(&webauthn_hash())], "batch {batch}");
        assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)], "batch {batch}");
        assert_eq!(reason, PinsUpdateReason::SignerAdded, "batch {batch}");

        h.submit(&[1], Some("req-pinned-verifier-matches"))
            .await
            .unwrap_or_else(|e| panic!("batch {batch}: the pinned verifier matches: {e:?}"));

        h.set_entry(wasm_instance(&passkey_verifier(), ed25519_hash()));
        let err = h
            .submit(&[1], Some("req-pinned-verifier-drift"))
            .await
            .unwrap_err();
        match &err {
            SaError::VerifierHashDrift {
                pinned_hash_first8,
                observed_hash_first8,
                ..
            } => {
                assert_eq!(pinned_hash_first8, &first8(&webauthn_hash()));
                assert_eq!(observed_hash_first8, &first8(&ed25519_hash()));
            }
            other => panic!("batch {batch}: expected VerifierHashDrift; got {other:?}"),
        }
        assert_eq!(err.wire_code(), "sa.verifier_hash_drift");
    }
}

/// The signer-set comparison over a version-2 state row freezes the
/// observed version-2 view, the smallest `latestLedger` any of its reads
/// reported, and the hash of the matched row.
#[tokio::test]
async fn a_signer_set_check_over_a_version_2_row_freezes_the_view_ledger_and_row() {
    let h = verb_harness().await;
    // Rule read, then threshold read, per endpoint; the secondary's
    // threshold read reports the smallest ledger.
    h.primary_ledgers
        .before_send
        .lock()
        .unwrap()
        .extend([1005, 1004]);
    h.secondary_ledgers
        .before_send
        .lock()
        .unwrap()
        .extend([1006, 1003]);

    let frozen = h
        .manager
        .verify_signer_set_against_chain(smart_account(), 1, None, "req-frozen".to_owned())
        .await
        .unwrap();
    assert_eq!(frozen.rule_id(), 1);
    assert_eq!(
        frozen.observed_chain_state(),
        &SignerSetView::V2(h.snapshot_of(1))
    );
    assert_eq!(frozen.simulation_ledger().0, 1003);
    let newest = AuditReader::new(Arc::clone(&h.audit), None)
        .find_latest_signer_set_view(
            1,
            &smart_account_redacted(),
            &account_digest(PASSPHRASE, &strkey(&smart_account())),
        )
        .unwrap()
        .expect("the version-2 baseline");
    assert_eq!(newest.view().version(), 2);
    assert_eq!(frozen.expected_audit_row_hash(), newest.row_hash());
}

/// A signer add whose state row the audit log refuses (the writer poisoned
/// after the send) fails at stage `write` with the hash, marks the writer
/// degraded, and records no state row.
#[tokio::test]
async fn a_signer_add_whose_row_is_refused_fails_at_stage_write() {
    let h = verb_harness().await;
    h.after_send_state(&Verb::Add.intended());
    h.poison_audit_writer_at("sendTransaction");

    let err = Verb::Add.run(&h, "req-poisoned-add").await.unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            tx_hash: Some(hash),
            stage,
            ..
        } => {
            assert_eq!(*stage, "write");
            assert_eq!(hash.len(), 64);
        }
        other => panic!("expected BaselineWriteFailed at stage write; got {other:?}"),
    }
    assert!(h.manager.audit_writer_degraded());
    assert!(row_kinds(&h.rows(), "req-poisoned-add").is_empty());
    assert_eq!(h.sends(), 1);
}

/// A first `signers list` whose baseline row the audit log refuses (the
/// writer poisoned after the state read) fails at stage `write` without a
/// transaction hash.
#[tokio::test]
async fn a_list_whose_baseline_row_is_refused_fails_at_stage_write() {
    let h = Harness::new(verb_chain()).await;
    h.poison_audit_writer_at("get_context_rule");

    let err = h
        .manager
        .list_signers(smart_account(), 1, None, "req-poisoned-list".to_owned())
        .await
        .unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            tx_hash: None,
            stage,
            ..
        } => assert_eq!(*stage, "write"),
        other => panic!("expected BaselineWriteFailed at stage write; got {other:?}"),
    }
    assert!(h.manager.audit_writer_degraded());
    assert!(row_kinds(&h.rows(), "req-poisoned-list").is_empty());
}

/// A rule whose only policy is not a simple-threshold policy observes no
/// threshold, and a removal refuses before submission: another policy
/// decides which signers suffice.
#[tokio::test]
async fn a_removal_on_a_weighted_only_rule_refuses_before_submission() {
    let weighted = contract(0x35);
    let chain = Chain::default()
        .with_rule(1, rule_with_ids(1, verb_signers(), vec![weighted.clone()]))
        .with_wasm(
            &weighted,
            stellar_agent_smart_account::weighted_threshold_policy::WEIGHTED_THRESHOLD_POLICY_WASM_HASHES[0],
        );
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    assert_eq!(h.snapshot_of(1).threshold, None);
    let rows_before = h.rows().len();

    let err = Verb::Remove.run(&h, "req-weighted").await.unwrap_err();
    assert_eq!(
        err.wire_code(),
        "sa.threshold_policy_identification_failed",
        "{err:?}"
    );
    assert_eq!(h.sends(), 0);
    assert!(!h.simulated("remove_signer"));
    assert!(!h.simulated("get_threshold"));
    assert_eq!(h.rows().len(), rows_before);
}

/// A rule without any policy has no threshold to check: a removal proceeds
/// and records its state row, and a threshold change refuses before
/// submission.
#[tokio::test]
async fn a_policyless_rule_accepts_a_removal_and_refuses_a_threshold_change() {
    let policyless = || Chain::default().with_rule(1, rule_with_ids(1, verb_signers(), vec![]));
    let h = Harness::new(policyless()).await;
    h.baseline_v2(1);
    let mut after = verb_signers();
    after.retain(|(id, _)| *id != 2);
    h.after_send(1, rule_with_ids(1, after, vec![]));
    Verb::Remove.run(&h, "req-policyless-remove").await.unwrap();
    let rows = rows_of(&h, "req-policyless-remove");
    assert_eq!(
        row_kinds(&rows, "req-policyless-remove"),
        vec!["sa_signer_removed_v2"]
    );
    assert_eq!(state_row_snapshot(&rows[0]), &h.snapshot_of(1));
    assert_eq!(state_row_snapshot(&rows[0]).threshold, None);

    let h = Harness::new(policyless()).await;
    h.baseline_v2(1);
    let err = Verb::SetThreshold
        .run(&h, "req-policyless-threshold")
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.threshold_policy_not_installed");
    assert_eq!(h.sends(), 0);
}

/// `signers list` on a policyless rule records a version-2 baseline with no
/// threshold, at the ledger the rule reads reported.
#[tokio::test]
async fn a_list_on_a_policyless_rule_writes_a_version_2_baseline_without_a_threshold() {
    let h =
        Harness::new(Chain::default().with_rule(1, rule_with_ids(1, verb_signers(), vec![]))).await;
    let outcome = h
        .manager
        .list_signers(smart_account(), 1, None, "req-list-policyless".to_owned())
        .await
        .unwrap();
    assert_eq!(outcome.baseline, PreviousBaseline::None);
    assert_eq!(outcome.view, SignerSetView::V2(h.snapshot_of(1)));

    let rows = rows_of(&h, "req-list-policyless");
    assert_eq!(rows.len(), 1);
    match &rows[0].event_kind {
        EventKind::SaSignerSetBaselinedV2 {
            rule_id: 1,
            snapshot,
            observed_at_ledger_seq,
            baseline_reason,
            account_digest: digest,
            ..
        } => {
            assert_eq!(snapshot, &h.snapshot_of(1));
            assert_eq!(snapshot.threshold, None);
            assert_eq!(*observed_at_ledger_seq, PRE_SEND_LEDGER);
            assert_eq!(*baseline_reason, BaselineReason::first_observation());
            assert_eq!(
                digest,
                &account_digest(PASSPHRASE, &strkey(&smart_account()))
            );
        }
        other => panic!("expected SaSignerSetBaselinedV2; got {other:?}"),
    }
}

/// `signers list` over an existing state row reports how the chain compares
/// with it and writes nothing.
#[tokio::test]
async fn a_list_over_an_existing_row_reports_the_comparison_and_writes_nothing() {
    let list = |h: &Harness| {
        let manager = Arc::clone(&h.manager);
        async move {
            manager
                .list_signers(smart_account(), 1, None, "req-list-compare".to_owned())
                .await
                .unwrap()
        }
    };

    let h = verb_harness().await;
    let rows_before = h.rows().len();
    assert_eq!(list(&h).await.baseline, PreviousBaseline::Matched);
    let mut changed = verb_signers();
    changed.push((3, delegated_account(0x13)));
    h.set_rule(1, &verb_rule(changed));
    assert_eq!(list(&h).await.baseline, PreviousBaseline::Diverged);
    assert_eq!(
        h.rows().len(),
        rows_before,
        "list writes no row over a baseline"
    );

    let h =
        Harness::new(Chain::default().with_rule(1, rule_with_ids(1, verb_signers(), vec![]))).await;
    h.write_v1_baseline(
        1,
        &ObservedSignerSet {
            signer_count: 3,
            threshold: 2,
            signer_ids: vec![0, 1, 2],
            signer_pubkeys: [0x10, 0x11, 0x12]
                .into_iter()
                .map(|byte| SignerPubkey::Ed25519 { pubkey: [byte; 32] })
                .collect(),
        },
    );
    let rows_before = h.rows().len();
    assert_eq!(list(&h).await.baseline, PreviousBaseline::NotComparable);
    assert_eq!(h.rows().len(), rows_before);
}

/// `signers refresh` over a version-1 baseline the chain matches records the
/// version-2 baseline and reports `matched`.
#[tokio::test]
async fn a_refresh_over_a_matching_version_1_baseline_records_version_2() {
    let h = Harness::new(verb_chain()).await;
    h.baseline_v1(1);
    let outcome = h
        .manager
        .refresh_signer_baseline(smart_account(), 1, None, false, "req-upgrade".to_owned())
        .await
        .unwrap();
    assert_eq!(outcome.previous_baseline, PreviousBaseline::Matched);
    assert_eq!(outcome.view, SignerSetView::V2(h.snapshot_of(1)));
    let rows = rows_of(&h, "req-upgrade");
    assert_eq!(
        row_kinds(&rows, "req-upgrade"),
        vec!["sa_signer_set_baselined_v2"]
    );
    match &rows[0].event_kind {
        EventKind::SaSignerSetBaselinedV2 {
            baseline_reason, ..
        } => assert_eq!(*baseline_reason, BaselineReason::explicit_refresh()),
        other => panic!("expected SaSignerSetBaselinedV2; got {other:?}"),
    }
}

/// `signers refresh` over a version-1 baseline the chain differs from writes
/// the divergence row and refuses without `accept_divergence`; with it, the
/// divergence row is written, then the version-2 baseline.
#[tokio::test]
async fn a_refresh_over_a_diverged_version_1_baseline_needs_the_flag() {
    let h = Harness::new(verb_chain()).await;
    h.baseline_v1(1);
    h.set_threshold(&policy_p(), 1, 3);

    let err = h
        .manager
        .refresh_signer_baseline(smart_account(), 1, None, false, "req-refresh-no".to_owned())
        .await
        .unwrap_err();
    match &err {
        SaError::SignerSetDiverged {
            tx_hash: None,
            expected: SignerSetView::V1(expected),
            observed: SignerSetView::V1(observed),
            ..
        } => {
            assert_eq!(expected.threshold, 2);
            assert_eq!(observed.threshold, 3);
        }
        other => panic!("expected a version-1 SignerSetDiverged; got {other:?}"),
    }
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-no"),
        vec!["sa_signer_set_diverged"]
    );

    let outcome = h
        .manager
        .refresh_signer_baseline(smart_account(), 1, None, true, "req-refresh-yes".to_owned())
        .await
        .unwrap();
    assert_eq!(outcome.previous_baseline, PreviousBaseline::Diverged);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-yes"),
        vec!["sa_signer_set_diverged", "sa_signer_set_baselined_v2"]
    );
}

/// A signer delegated to a contract address is readable in version 2, and a
/// version-1 baseline cannot be compared with a rule holding one: `list`
/// reports `not_comparable`, `refresh` refuses without the flag writing no
/// row, and with it records the version-2 baseline only.
#[tokio::test]
async fn a_contract_delegate_reads_in_version_2_and_is_not_comparable_with_version_1() {
    let delegate = contract(0x55);
    let chain = || {
        Chain::default()
            .with_rule(
                1,
                rule_with_ids(
                    1,
                    vec![
                        (0, delegated_account(0x10)),
                        (1, contract_delegate(&delegate)),
                    ],
                    vec![policy_p()],
                ),
            )
            .with_wasm(&policy_p(), KNOWN_WASM_HASH)
            .with_threshold(&policy_p(), 1, 1)
    };

    let h = Harness::new(chain()).await;
    let outcome = h
        .manager
        .list_signers(smart_account(), 1, None, "req-contract-list".to_owned())
        .await
        .unwrap();
    assert_eq!(outcome.baseline, PreviousBaseline::None);
    let SignerSetView::V2(snapshot) = &outcome.view else {
        panic!("list observes in version 2")
    };
    assert_eq!(
        snapshot.signers[1].identity,
        SignerIdentityV2::DelegatedContract {
            contract: contract_id(&delegate)
        }
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-contract-list"),
        vec!["sa_signer_set_baselined_v2"]
    );

    let h = Harness::new(chain()).await;
    h.write_v1_baseline(
        1,
        &ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0x10; 32] }],
        },
    );
    let rows_before = h.rows().len();
    let outcome = h
        .manager
        .list_signers(smart_account(), 1, None, "req-contract-v1".to_owned())
        .await
        .unwrap();
    assert_eq!(outcome.baseline, PreviousBaseline::NotComparable);

    let err = h
        .manager
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            false,
            "req-contract-no".to_owned(),
        )
        .await
        .unwrap_err();
    match &err {
        SaError::SignerSetDiverged {
            tx_hash: None,
            expected: SignerSetView::V1(_),
            observed: SignerSetView::V2(_),
            ..
        } => {}
        other => panic!("expected a version-1 against version-2 refusal; got {other:?}"),
    }
    assert_eq!(h.rows().len(), rows_before, "the refusal writes no row");

    let outcome = h
        .manager
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            true,
            "req-contract-yes".to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(outcome.previous_baseline, PreviousBaseline::NotComparable);
    assert_eq!(
        row_kinds(&h.rows(), "req-contract-yes"),
        vec!["sa_signer_set_baselined_v2"]
    );
}

/// Two attached policies that both run a simple-threshold executable refuse
/// the observation: the wallet cannot tell which threshold applies.
#[tokio::test]
async fn two_allowlisted_threshold_policies_refuse_the_observation() {
    let p2 = contract(0x36);
    let chain = Chain::default()
        .with_rule(
            1,
            rule_with_ids(1, verb_signers(), vec![policy_p(), p2.clone()]),
        )
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_wasm(&p2, KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 2)
        .with_threshold(&p2, 1, 2);
    let h = Harness::new(chain).await;
    let err = h
        .manager
        .list_signers(smart_account(), 1, None, "req-two-thresholds".to_owned())
        .await
        .unwrap_err();
    match &err {
        SaError::ThresholdPolicyIdentificationFailed {
            observed_wasm_hashes_summary,
            ..
        } => assert_eq!(observed_wasm_hashes_summary.count, 2),
        other => panic!("expected ThresholdPolicyIdentificationFailed; got {other:?}"),
    }
    assert!(!h.simulated("get_threshold"));
    assert!(h.rows().is_empty());
}

/// A policy whose instance is absent is readable and is not the
/// simple-threshold policy; the rule's simple-threshold policy beside it is
/// observed.
#[tokio::test]
async fn a_policy_without_an_instance_is_readable_and_not_the_threshold_policy() {
    let absent = contract(0x37);
    let chain = Chain::default()
        .with_rule(
            1,
            rule_with_ids(1, verb_signers(), vec![absent.clone(), policy_p()]),
        )
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 2);
    let h = Harness::new(chain).await;
    let outcome = h
        .manager
        .list_signers(smart_account(), 1, None, "req-absent-policy".to_owned())
        .await
        .unwrap();
    let SignerSetView::V2(snapshot) = &outcome.view else {
        panic!("list observes in version 2")
    };
    assert_eq!(
        snapshot.threshold,
        Some(ThresholdObservation {
            policy: contract_id(&policy_p()),
            threshold: 2
        })
    );
    assert_eq!(h.primary_instance_reads(&absent), 1);
}

/// Endpoints that agree on the rule and disagree on the simple-threshold
/// value refuse with `network.rpc_divergence` before submission, and a
/// first `signers list` records no baseline.
#[tokio::test]
async fn the_endpoints_disagreeing_on_the_threshold_refuse_with_rpc_divergence() {
    let secondary = || verb_chain().with_threshold(&policy_p(), 1, 3);
    let h = Harness::with_secondary(verb_chain(), secondary()).await;
    h.baseline_v2(1);
    let removed = Verb::Remove.run(&h, "req-threshold-rpc").await;
    let listing = Harness::with_secondary(verb_chain(), secondary()).await;
    let listed = listing
        .manager
        .list_signers(smart_account(), 1, None, "req-threshold-list".to_owned())
        .await;
    // Both legs run before any assertion, so a failure reports both.
    assert_eq!(
        (
            removed.as_ref().err().map(SaError::wire_code),
            listed.as_ref().err().map(SaError::wire_code),
        ),
        (
            Some("network.rpc_divergence"),
            Some("network.rpc_divergence")
        ),
    );

    assert!(matches!(
        removed,
        Err(SaError::NetworkRpcDivergence {
            rule_id: Some(1),
            ..
        })
    ));
    assert_eq!(
        h.secondary_log.simulated(),
        vec!["get_context_rule", "get_threshold"],
        "the endpoints agreed on the rule and both read the threshold"
    );
    assert_eq!(h.sends(), 0);
    assert!(row_kinds(&h.rows(), "req-threshold-rpc").is_empty());
    assert!(listing.rows().is_empty(), "no baseline is recorded");
}

/// The two endpoints disagreeing on the rule's policy list refuse the
/// observation with `network.rpc_divergence` before any threshold read.
#[tokio::test]
async fn the_endpoints_disagreeing_on_the_policy_list_refuse_with_rpc_divergence() {
    let q = contract(0x31);
    let secondary = verb_chain()
        .with_rule(
            1,
            rule_with_ids(1, verb_signers(), vec![policy_p(), q.clone()]),
        )
        .with_wasm(&q, [0xdd; 32]);
    let h = Harness::with_secondary(verb_chain(), secondary).await;
    let err = h
        .manager
        .list_signers(smart_account(), 1, None, "req-policy-lists".to_owned())
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "network.rpc_divergence", "{err:?}");
    assert!(matches!(
        err,
        SaError::NetworkRpcDivergence {
            rule_id: Some(1),
            ..
        }
    ));
    assert!(!h.simulated("get_threshold"));
    assert!(
        h.secondary_log
            .simulated()
            .iter()
            .all(|f| f == "get_context_rule")
    );
    assert!(h.rows().is_empty());
}
