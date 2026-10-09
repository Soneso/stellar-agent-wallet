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
//!   --test smart_account_test_helpers execute_path_drift_check_mock
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
use stellar_agent_network::SubmissionRecorder;
use stellar_agent_smart_account::PendingAddStep;
use stellar_agent_smart_account::error::SaError;
use stellar_agent_smart_account::managers::migration::{
    MigrationPlan, RuleMigration, SignerMigrationStep,
};
use stellar_agent_smart_account::managers::rules::{
    ContextRuleDefinition, ContextRuleManager, ContextRuleManagerConfig, ContextRulePolicy,
    ContextRuleSignerInput, PinStatus, RuleContext,
};
use stellar_agent_smart_account::managers::signers::{
    PreviousBaseline, RefreshOptions, SignersManager, SignersManagerConfig,
};
use stellar_agent_smart_account::signers::THRESHOLD_POLICY_WASM_HASHES;
use stellar_agent_smart_account::submit::{
    MigratingRule, PinCheck, SubmitInvokeArgs, SubmitInvokeResult, submit_signed_invoke,
};
use stellar_agent_smart_account::verifier_allowlist::{VERIFIER_ALLOWLIST, VerifierAuditStatus};
use stellar_agent_test_support::signed_envelope::{
    account_id_for_seed, get_network_result, send_transaction_hash_hex,
};
use stellar_agent_test_support::xdr_fixtures;
use stellar_xdr::{
    AccountId, BytesM, ContractId, Hash, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, LedgerKey, Limits, OperationBody, PublicKey, ReadXdr, ScAddress, ScBytes,
    ScMap, ScMapEntry, ScString, ScSymbol, ScVal, ScVec, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, TransactionEnvelope, Uint256, VecM, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[path = "../smart-account-fixtures/adversarial/rpc_mock_helpers.rs"]
mod rpc_mock_helpers;

use rpc_mock_helpers::KNOWN_WASM_HASH;

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
    /// What a simulated function returns, by function name, in send order.
    /// The front value serves every simulation until a send of the function
    /// advances the queue; the last value serves every later simulation.
    /// Unset, a simulated `add_signer` or `add_policy` returns `U32(7)`, an
    /// `add_context_rule` the map `{ id: U32(next rule id) }`, and any other
    /// invocation `Void`.
    returns: HashMap<&'static str, VecDeque<ScVal>>,
    /// An entry that replaces the one under its key once the key has been
    /// read the given number of times, by key.
    entries_after_reads: HashMap<String, (usize, Value)>,
    /// How many times each ledger-entry key has been read.
    entry_reads: HashMap<String, usize>,
    /// A rule value that replaces the rule once it has been read through
    /// `get_context_rule` the given number of times, by rule id.
    rules_after_reads: HashMap<u32, (usize, ScVal)>,
    /// How many times each rule has been read through `get_context_rule`.
    rule_reads: HashMap<u32, usize>,
    /// The changes the sends of each function make to the chain as it stands
    /// at the send, by function name, in send order; each applies once.
    effects: HashMap<String, VecDeque<SendEffect>>,
}

/// The change a confirmed submission of one function makes to the rule it
/// targets, applied to the chain as it stands at the send. Two verbs in
/// flight therefore each change the state the other's send left, in either
/// order.
#[derive(Clone)]
enum SendEffect {
    /// Appends the signer `signer` under `signer_id` to rule `rule_id`.
    AddSigner {
        rule_id: u32,
        signer_id: u32,
        signer: ScVal,
    },
    /// Removes `policy` and its id from rule `rule_id`; the remaining
    /// policies' ids count from 0, as this file's rule builders number them.
    RemovePolicy { rule_id: u32, policy: ScAddress },
    /// Removes the signer `signer_id` from rule `rule_id`.
    RemoveSigner { rule_id: u32, signer_id: u32 },
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

    /// Serves `entry` under `key` once `n` reads of `key` have been answered,
    /// so a contract's executable can change between two observations. Both
    /// endpoints of a [`Harness::new`] harness share the count.
    fn entry_after_reads(mut self, key: String, n: usize, entry: Value) -> Self {
        self.entries_after_reads.insert(key, (n, entry));
        self
    }

    /// The entry a read of `key` serves, counting the read.
    fn read_entry(&mut self, key: &str) -> Option<Value> {
        let reads = self.entry_reads.entry(key.to_owned()).or_insert(0);
        let served_before = *reads;
        *reads += 1;
        match self.entries_after_reads.get(key) {
            Some((n, entry)) if served_before >= *n => Some(entry.clone()),
            _ => self.entries.get(key).cloned(),
        }
    }

    /// Counts a `get_context_rule` read of rule `rule_id`, and replaces the
    /// rule with the value [`Chain::rules_after_reads`] registers for it
    /// once the reads before this one reach the registered count.
    fn count_rule_read(&mut self, rule_id: u32) {
        let reads = self.rule_reads.entry(rule_id).or_insert(0);
        let served_before = *reads;
        *reads += 1;
        if let Some((n, _)) = self.rules_after_reads.get(&rule_id)
            && served_before >= *n
        {
            let (_, value) = self.rules_after_reads.remove(&rule_id).unwrap();
            self.rules.insert(rule_id, value);
        }
    }

    /// The value a simulation of `function` returns, if a test set one.
    fn simulated_return(&self, function: &str) -> Option<ScVal> {
        self.returns
            .get(function)
            .and_then(|queue| queue.front().cloned())
    }

    /// Applies a send of `function`. Keeps the current rules and thresholds
    /// for reads behind the confirmation, then applies the pending post-send
    /// state and the next effect registered for `function`. Advances
    /// `function`'s return queue past the value this send's step was
    /// simulated with.
    fn apply_send(&mut self, function: &str) {
        self.before_send = Some((self.rules.clone(), self.thresholds.clone()));
        if let Some(after) = self.after_send.take() {
            self.apply(&after);
        }
        if let Some(effect) = self.effects.get_mut(function).and_then(VecDeque::pop_front) {
            self.apply_effect(effect);
        }
        if let Some(queue) = self.returns.get_mut(function)
            && queue.len() > 1
        {
            queue.pop_front();
        }
    }

    /// Applies `effect` to the rule it names, as the rule stands now.
    fn apply_effect(&mut self, effect: SendEffect) {
        let (rule_id, signers, policies) = match effect {
            SendEffect::AddSigner {
                rule_id,
                signer_id,
                signer,
            } => {
                let (ids, signers, policies) = rule_parts(&self.rules[&rule_id]);
                let mut signers: Vec<(u32, ScVal)> = ids.into_iter().zip(signers).collect();
                signers.push((signer_id, signer));
                (rule_id, signers, policies)
            }
            SendEffect::RemovePolicy { rule_id, policy } => {
                let (ids, signers, policies) = rule_parts(&self.rules[&rule_id]);
                let policies = policies.into_iter().filter(|p| *p != policy).collect();
                (rule_id, ids.into_iter().zip(signers).collect(), policies)
            }
            SendEffect::RemoveSigner { rule_id, signer_id } => {
                let (ids, signers, policies) = rule_parts(&self.rules[&rule_id]);
                let signers = ids
                    .into_iter()
                    .zip(signers)
                    .filter(|(id, _)| *id != signer_id)
                    .collect();
                (rule_id, signers, policies)
            }
        };
        self.rules
            .insert(rule_id, rule_with_ids(rule_id, signers, policies));
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
    /// How many `getLedgerEntries` requests named each key, by key; a request
    /// naming a key more than once counts once.
    entry_requests: Mutex<HashMap<String, usize>>,
    simulated: Mutex<Vec<String>>,
    /// The rule id of each `get_context_rule` simulation, in order.
    rule_reads: Mutex<Vec<u32>>,
    sends: AtomicUsize,
}

impl Log {
    fn simulated(&self) -> Vec<String> {
        self.simulated.lock().unwrap().clone()
    }

    fn rule_reads(&self) -> Vec<u32> {
        self.rule_reads.lock().unwrap().clone()
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
    /// How long a simulation of a function takes to answer, by function
    /// name, before and after the send; at once for a function without an
    /// entry.
    delay_simulated: Mutex<HashMap<&'static str, Duration>>,
    /// How long `getTransaction` takes to answer; at once when unset.
    delay_poll: Mutex<Option<Duration>>,
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

/// Whether `getTransaction` confirms the sent transactions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Unconfirmed {
    /// Every `getTransaction` answers `SUCCESS`.
    #[default]
    Off,
    /// The next send switches to [`Unconfirmed::Blocking`].
    NextSend,
    /// Every `getTransaction` answers `NOT_FOUND`, so a confirmation poll
    /// runs until its timeout.
    Blocking,
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
    /// Whether `getTransaction` withholds the confirmation, shared by both
    /// endpoints.
    unconfirmed: Arc<Mutex<Unconfirmed>>,
    poison: Arc<Mutex<Option<Poison>>>,
    /// How late this endpoint answers the `nth` `getLedgerEntries` request
    /// naming a key, by `(key, nth)`.
    entry_delays: EntryDelays,
}

/// Answer delays of one endpoint's `getLedgerEntries` requests, by the key a
/// request names and the request's position among those naming that key.
type EntryDelays = Arc<Mutex<HashMap<(String, usize), Duration>>>;

impl Rpc {
    /// Counts one request naming each distinct key of `keys` on this
    /// endpoint, and returns the longest delay registered for a key at its
    /// new count.
    fn count_entry_request(&self, keys: &[String]) -> Option<Duration> {
        let mut requests = self.log.entry_requests.lock().unwrap();
        let delays = self.entry_delays.lock().unwrap();
        let mut counted: Vec<&String> = Vec::with_capacity(keys.len());
        let mut delay: Option<Duration> = None;
        for key in keys {
            if counted.contains(&key) {
                continue;
            }
            counted.push(key);
            let count = requests.entry(key.clone()).or_insert(0);
            *count += 1;
            if let Some(registered) = delays.get(&(key.clone(), *count)) {
                delay = delay.max(Some(*registered));
            }
        }
        delay
    }
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

/// The `ContextRule` return value of a simulated `add_context_rule`, reduced
/// to the `id` field the wallet reads.
fn context_rule_return(rule_id: u32) -> ScVal {
    ScVal::Map(Some(ScMap(
        vec![ScMapEntry {
            key: symbol("id"),
            val: ScVal::U32(rule_id),
        }]
        .try_into()
        .unwrap(),
    )))
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

/// The invocation operation of a transaction envelope and the contract call
/// it makes.
fn envelope_invocation(envelope_xdr: &str) -> (InvokeHostFunctionOp, InvokeContractArgs) {
    let envelope = TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none()).unwrap();
    let TransactionEnvelope::Tx(tx) = envelope else {
        panic!("expected a v1 envelope")
    };
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        panic!("expected an invocation")
    };
    let HostFunction::InvokeContract(invoke) = &op.host_function else {
        panic!("expected a contract invocation")
    };
    (op.clone(), invoke.clone())
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
                // wiremock awaits the delay after this responder returned, so
                // the endpoint keeps answering other requests meanwhile.
                let delay = self.count_entry_request(&keys);
                let delayed = |response: ResponseTemplate| match delay {
                    Some(delay) => response.set_delay(delay),
                    None => response,
                };
                let mut chain = self.chain.lock().unwrap();
                if keys.iter().any(|k| chain.failing_keys.contains(k)) {
                    return delayed(ResponseTemplate::new(200).set_body_json(json!({
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "error": {"code": -32603, "message": "mock ledger read failure"}
                    })));
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
                        chain.read_entry(key)
                    })
                    .collect();
                delayed(reply(
                    json!({"entries": entries, "latestLedger": PRE_SEND_LEDGER}),
                ))
            }
            "simulateTransaction" => {
                let (op, invoke) =
                    envelope_invocation(body["params"]["transaction"].as_str().unwrap());
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
                let mut chain = self.chain.lock().unwrap();
                if function == "get_context_rule" {
                    let ScVal::U32(rule_id) = invoke.args[0] else {
                        panic!("get_context_rule takes a u32")
                    };
                    chain.count_rule_read(rule_id);
                }
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
                        self.log.rule_reads.lock().unwrap().push(rule_id);
                        match rules.get(&rule_id) {
                            Some(value) => reply(simulate_result(value, &[], ledger)),
                            // The contract's `ContextRuleNotFound` panic.
                            None => reply(json!({
                                "error": "HostError: Error(Contract, #3000)",
                                "latestLedger": ledger,
                            })),
                        }
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
                        let value =
                            chain
                                .simulated_return(function.as_str())
                                .unwrap_or_else(|| match function.as_str() {
                                    "add_signer" | "add_policy" => ScVal::U32(7),
                                    "add_context_rule" => context_rule_return(
                                        rules.keys().max().map_or(0, |rule_id| rule_id + 1),
                                    ),
                                    _ => ScVal::Void,
                                });
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
                let response = match self
                    .ledgers
                    .delay_simulated
                    .lock()
                    .unwrap()
                    .get(function.as_str())
                {
                    Some(delay) => response.set_delay(*delay),
                    None => response,
                };
                match *self.ledgers.delay_after_send.lock().unwrap() {
                    Some(delay) if sent => response.set_delay(delay),
                    _ => response,
                }
            }
            "sendTransaction" => {
                self.log.sends.fetch_add(1, Ordering::SeqCst);
                let (_, invoke) =
                    envelope_invocation(body["params"]["transaction"].as_str().unwrap());
                let function = invoke.function_name.0.to_utf8_string().unwrap();
                for (index, chain) in self.chains.iter().enumerate() {
                    // Both endpoints may serve one chain; apply the send once.
                    if self.chains[..index].iter().any(|c| Arc::ptr_eq(c, chain)) {
                        continue;
                    }
                    chain.lock().unwrap().apply_send(&function);
                }
                self.sent.store(true, Ordering::SeqCst);
                {
                    let mut unconfirmed = self.unconfirmed.lock().unwrap();
                    if *unconfirmed == Unconfirmed::NextSend {
                        *unconfirmed = Unconfirmed::Blocking;
                    }
                }
                let hash = send_transaction_hash_hex(&body, PASSPHRASE);
                reply(json!({
                    "status": "PENDING", "hash": hash,
                    "latestLedger": PRE_SEND_LEDGER, "latestLedgerCloseTime": "1234567890"
                }))
            }
            "getTransaction" => {
                let response = if *self.unconfirmed.lock().unwrap() == Unconfirmed::Blocking {
                    reply(json!({
                        "status": "NOT_FOUND", "latestLedger": CONFIRMATION_LEDGER,
                        "oldestLedger": 1,
                    }))
                } else {
                    reply(json!({
                        "status": "SUCCESS", "latestLedger": CONFIRMATION_LEDGER,
                        "oldestLedger": 1, "ledger": CONFIRMATION_LEDGER,
                        "createdAt": (stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000)
                            .to_string(),
                    }))
                };
                match *self.ledgers.delay_poll.lock().unwrap() {
                    Some(delay) => response.set_delay(delay),
                    None => response,
                }
            }
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
    primary_entry_delays: EntryDelays,
    unconfirmed: Arc<Mutex<Unconfirmed>>,
    audit: Arc<Mutex<AuditWriter>>,
    log_path: PathBuf,
    manager: Arc<SignersManager>,
    timeouts: Timeouts,
    _dir: tempfile::TempDir,
    _secondary: MockServer,
}

/// The two timeouts of a [`Harness`].
#[derive(Clone, Copy)]
struct Timeouts {
    /// The pre-submit budget of the free function's submissions and the
    /// timeout of the rule manager, whose submissions take it as theirs.
    budget: Duration,
    /// The signers manager's timeout: the timeout of each of its RPC reads,
    /// the lock wait of its verbs and their `confirmation_recording` budget.
    client: Duration,
}

/// The timeout of a harness that sets none.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

impl Harness {
    async fn new(chain: Chain) -> Self {
        Self::build(
            chain,
            None,
            Timeouts {
                budget: DEFAULT_TIMEOUT,
                client: DEFAULT_TIMEOUT,
            },
        )
        .await
    }

    /// A harness whose secondary endpoint serves `secondary` instead of the
    /// primary's chain.
    async fn with_secondary(chain: Chain, secondary: Chain) -> Self {
        Self::build(
            chain,
            Some(secondary),
            Timeouts {
                budget: DEFAULT_TIMEOUT,
                client: DEFAULT_TIMEOUT,
            },
        )
        .await
    }

    /// A harness whose pre-submit budget and signers-manager timeout are
    /// both `timeout`.
    async fn with_timeout(chain: Chain, timeout: Duration) -> Self {
        Self::build(
            chain,
            None,
            Timeouts {
                budget: timeout,
                client: timeout,
            },
        )
        .await
    }

    /// A harness whose pre-submit budget is `budget` and whose signers
    /// manager keeps the default timeout, so an RPC read's own timeout never
    /// ends before the budget does.
    async fn with_budget(chain: Chain, budget: Duration) -> Self {
        Self::build(
            chain,
            None,
            Timeouts {
                budget,
                client: DEFAULT_TIMEOUT,
            },
        )
        .await
    }

    async fn build(chain: Chain, secondary: Option<Chain>, timeouts: Timeouts) -> Self {
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
        let primary_entry_delays = EntryDelays::default();
        let sent = Arc::new(AtomicBool::new(false));
        let unconfirmed = Arc::new(Mutex::new(Unconfirmed::Off));
        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        for (server, served, log, ledgers, poison, entry_delays) in [
            (
                &primary,
                &chain,
                &primary_log,
                &primary_ledgers,
                Arc::clone(&primary_poison),
                Arc::clone(&primary_entry_delays),
            ),
            (
                &secondary,
                &secondary_chain,
                &secondary_log,
                &secondary_ledgers,
                Arc::new(Mutex::new(None)),
                EntryDelays::default(),
            ),
        ] {
            Mock::given(method("POST"))
                .respond_with(Rpc {
                    chain: Arc::clone(served),
                    chains: chains.clone(),
                    log: Arc::clone(log),
                    ledgers: Arc::clone(ledgers),
                    sent: Arc::clone(&sent),
                    unconfirmed: Arc::clone(&unconfirmed),
                    poison,
                    entry_delays,
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
                timeouts.client,
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
            primary_entry_delays,
            unconfirmed,
            audit,
            log_path,
            manager,
            timeouts,
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
                self.timeouts.budget,
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

    /// Makes the next send of `function` without an effect apply `effect`
    /// to every endpoint's chain as it stands at that send, once. Effects
    /// registered for one function apply in registration order, one per
    /// send. Both endpoints of a [`Harness::new`] harness serve one chain,
    /// which a send changes once.
    fn on_send(&self, function: &'static str, effect: SendEffect) {
        if !Arc::ptr_eq(&self.chain, &self.secondary_chain) {
            self.secondary_chain
                .lock()
                .unwrap()
                .effects
                .entry(function.to_owned())
                .or_default()
                .push_back(effect.clone());
        }
        self.chain
            .lock()
            .unwrap()
            .effects
            .entry(function.to_owned())
            .or_default()
            .push_back(effect);
    }

    /// Replaces rule `rule_id` with `value` on the primary's chain once `n`
    /// `get_context_rule` reads of the rule have been answered. Read `n + 1`
    /// and every later read serve `value`, a change made outside the wallet
    /// between two reads. Both endpoints of a [`Harness::new`]
    /// harness share the count.
    fn replace_rule_after_reads(&self, rule_id: u32, n: usize, value: ScVal) {
        self.chain
            .lock()
            .unwrap()
            .rules_after_reads
            .insert(rule_id, (n, value));
    }

    /// Makes every `getTransaction` after the next send answer `NOT_FOUND`,
    /// so that send's confirmation poll ends at its timeout with the
    /// outcome unknown.
    fn never_confirm_next_send(&self) {
        *self.unconfirmed.lock().unwrap() = Unconfirmed::NextSend;
    }

    /// Delays the primary's answer to its `nth` `getLedgerEntries` request
    /// naming `key` by `delay`. The primary keeps answering other requests
    /// during the delay.
    fn delay_entry_read(&self, key: &str, nth: usize, delay: Duration) {
        self.primary_entry_delays
            .lock()
            .unwrap()
            .insert((key.to_owned(), nth), delay);
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

    /// Makes the primary's simulated `function` return `value`.
    fn set_simulated_return(&self, function: &'static str, value: ScVal) {
        self.set_simulated_returns(function, vec![value]);
    }

    /// Makes the primary's simulated `function` return `values` in order:
    /// each value serves the simulations of one submission, a send of
    /// `function` advances to the next, and the last value serves every
    /// later simulation.
    fn set_simulated_returns(&self, function: &'static str, values: Vec<ScVal>) {
        self.chain
            .lock()
            .unwrap()
            .returns
            .insert(function, values.into());
    }

    /// Poisons the audit writer now, before the next submission.
    fn poison_audit_writer_now(&self) {
        Poison {
            at: "now",
            audit: Arc::clone(&self.audit),
        }
        .fire();
    }

    /// Delays every simulation of `function` on both endpoints by `delay`.
    /// The delay applies once the function name is decoded, so other
    /// functions answer at once.
    fn delay_simulated(&self, function: &'static str, delay: Duration) {
        for ledgers in [&self.primary_ledgers, &self.secondary_ledgers] {
            ledgers
                .delay_simulated
                .lock()
                .unwrap()
                .insert(function, delay);
        }
    }

    /// Delays the primary's `getTransaction` answers by `delay`, so a sent
    /// submission stalls in its confirmation poll.
    fn delay_poll(&self, delay: Duration) {
        *self.primary_ledgers.delay_poll.lock().unwrap() = Some(delay);
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
    /// rule checks through this harness's manager when `request_id` is set.
    async fn submit(
        &self,
        rule_ids: &[u32],
        request_id: Option<&str>,
    ) -> Result<SubmitInvokeResult, SaError> {
        self.submit_invocation("noop", rule_ids, request_id, None)
            .await
    }

    /// Submits `noop()` under `rule_id` alone with `rule_id` as the migrating
    /// rule, as a verifier migration's step does.
    async fn submit_as_migrating_rule(
        &self,
        rule_id: u32,
        request_id: &str,
    ) -> Result<SubmitInvokeResult, SaError> {
        let signer = SoftwareSigningKey::new_from_bytes(SEED);
        let rule_ids = [ContextRuleId::new(rule_id)];
        let smart_account = strkey(&smart_account());
        let uri = self.primary.uri();
        submit_signed_invoke(
            SubmitInvokeArgs::builder()
                .target_contract(&smart_account)
                .auth_rule_ids(&rule_ids)
                .host_function(noop())
                .signer(&signer)
                .primary_rpc_url(&uri)
                .network_passphrase(PASSPHRASE)
                .chain_id(CHAIN_ID)
                .timeout(self.timeouts.budget)
                .op_label("pin_check_mock")
                .pin_check(PinCheck {
                    signers_manager: &self.manager,
                    request_id,
                    migrating_rule: Some(MigratingRule::for_tests(rule_id)),
                })
                .build(),
        )
        .await
    }

    /// Submits `function()` on the smart account, recording the submission
    /// through `recorder` when one is given; see [`Self::submit`].
    async fn submit_invocation(
        &self,
        function: &str,
        rule_ids: &[u32],
        request_id: Option<&str>,
        recorder: Option<&dyn SubmissionRecorder>,
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
                .timeout(self.timeouts.budget)
                .op_label("pin_check_mock")
                .maybe_submission_recorder(recorder)
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

/// Rule 1 of [`rule_one_verifier_and_policy`] with verifier V running
/// `verifier_hash` and P the simple-threshold policy at threshold 1.
fn chain_with_rule_one(verifier_hash: [u8; 32]) -> Chain {
    Chain::default()
        .with_rule(1, rule_one_verifier_and_policy())
        .with_entry(wasm_instance(&verifier_v(), verifier_hash))
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 1)
}

// ── Drift refusals ────────────────────────────────────────────────────────────

/// A live verifier that differs from the rule's pin refuses the submission
/// before its invocation is simulated, and the drift row carries the
/// caller's request id. The rule's baseline is present, so the refusal is
/// the pin check's, and the signer-set comparison after it never runs: the
/// only simulation is the pin check's primary rule read.
#[tokio::test]
async fn verifier_drift_refuses_before_simulation_with_the_callers_request_id() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.baseline_v2(1);
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
    assert_eq!(h.primary_log.simulated(), vec!["get_context_rule"]);
    assert!(
        h.secondary_log.simulated().is_empty(),
        "the comparison's two-endpoint reads never ran"
    );
    assert!(!h.simulated("get_threshold"));
    assert_eq!(h.sends(), 0);
}

/// A live policy that differs from the rule's pin refuses the same way,
/// after the baseline read and before the comparison.
#[tokio::test]
async fn policy_drift_refuses_before_simulation_with_the_callers_request_id() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.baseline_v2(1);
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
    assert_eq!(h.primary_log.simulated(), vec!["get_context_rule"]);
    assert!(
        h.secondary_log.simulated().is_empty(),
        "the comparison's two-endpoint reads never ran"
    );
    assert!(!h.simulated("get_threshold"));
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
    h.baseline_v2(1);
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
    h.baseline_v2(1);
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

/// A pin record with two verifier pins refuses as unavailable carrying the
/// inner code.
///
/// An audit log that fails its integrity check refuses with `sa.audit_log`
/// at the baseline read, which scans the log before the pin check does; the
/// rule is never fetched. The migrating rule's baseline is read like any
/// rule's, so the error is `sa.audit_log` under it too.
#[tokio::test]
async fn multiple_pins_and_an_audit_integrity_error_refuse_as_unavailable() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.baseline_v2(1);
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
    h.baseline_v2(1);
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
    assert!(matches!(err, SaError::AuditLog(_)), "{err:?}");
    assert_eq!(err.wire_code(), "sa.audit_log");
    assert!(
        !h.simulated("get_context_rule"),
        "the baseline read refuses before the pin check fetches the rule"
    );

    let err = h
        .submit_as_migrating_rule(1, "req-integrity-migrating")
        .await
        .unwrap_err();
    assert!(matches!(err, SaError::AuditLog(_)), "{err:?}");
    assert_eq!(err.wire_code(), "sa.audit_log");
    assert_eq!(h.sends(), 0);
}

// ── Checks that pass ──────────────────────────────────────────────────────────

/// A rule without a pin record signs: the check fetches the rule and passes.
#[tokio::test]
async fn a_rule_without_a_pin_record_signs() {
    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.baseline_v2(1);
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
    h.baseline_v2(1);
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
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.pin_created(2, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);

    h.submit_invocation("pair", &[1, 2], Some("req-shared"), None)
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
            migrating_rule: Some(MigratingRule::for_tests(2)),
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
/// at threshold 1, and the verifiers the add tests use.
fn signer_add_chain() -> Chain {
    Chain::default()
        .with_rule(1, signer_add_rule_before())
        .with_wasm(&verifier_v(), webauthn_hash())
        .with_wasm(&verifier_w(), ed25519_hash())
        .with_wasm(&contract(0x22), [0xdd; 32])
        .with_wasm(&passkey_verifier(), webauthn_hash())
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 1)
}

/// A [`signer_add_chain`] harness with rule 1's version-2 baseline recorded
/// from the served chain, and a pin record when `pinned`.
async fn signer_add_harness(pinned: bool) -> Harness {
    let h = Harness::new(signer_add_chain()).await;
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
/// pinned rule pins its verifier like any other new verifier. Its verifier
/// runs the hash the record already pins for verifier V, with no executable
/// reference, so the pin is the recorded one. The list stays unchanged, the
/// pins row is written, and the rule signs.
#[tokio::test]
async fn a_passkey_signer_added_to_a_pinned_rule_pins_its_verifier() {
    let h = signer_add_harness(true).await;
    add_signer_value(&h, passkey_signer(), "req-add-passkey", false)
        .await
        .unwrap();

    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_id, "req-add-passkey");
    let (verifiers, policies, _, reason) = pins_updated_fields(&rows[0]);
    assert_eq!(
        verifiers,
        vec![first8(&webauthn_hash())],
        "the passkey's verifier has the pin verifier V has"
    );
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::SignerAdded);
    assert!(verifier_refs_of(&rows[0]).is_empty());

    h.submit(&[1], Some("req-after-passkey")).await.unwrap();
    assert_eq!(h.sends(), 2);
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

/// The `remove_signer(1, signer_id)` host function of a migration step.
fn remove_signer_call(signer_id: u32) -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: smart_account(),
        function_name: ScSymbol::try_from("remove_signer").unwrap(),
        args: vec![ScVal::U32(1), ScVal::U32(signer_id)]
            .try_into()
            .unwrap(),
    })
}

/// The `add_signer(1, signer)` host function of a migration step.
fn add_signer_call(signer: ScVal) -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: smart_account(),
        function_name: ScSymbol::try_from("add_signer").unwrap(),
        args: vec![ScVal::U32(1), signer].try_into().unwrap(),
    })
}

/// The step migrating signer `signer_id` of rule 1: its removal, then the
/// add of `key` on `add_verifier`.
fn migration_step(
    signer_id: u32,
    from: [u8; 32],
    add_verifier: &ScAddress,
    key: &[u8],
) -> SignerMigrationStep {
    SignerMigrationStep::new_for_test(
        signer_id,
        first8(&from),
        remove_signer_call(signer_id),
        add_signer_call(external_signer(add_verifier, key)),
    )
}

/// A plan migrating `steps` of rule 1 from `from` to `to` on verifier W.
fn plan_of(from: [u8; 32], to: [u8; 32], steps: Vec<SignerMigrationStep>) -> MigrationPlan {
    MigrationPlan::new_for_test(
        smart_account(),
        from,
        to,
        verifier_w(),
        vec![RuleMigration::new_for_test(1, first8(&from), steps)],
        VerifierAuditStatus::Unaudited,
        "req-migration-plan",
    )
}

/// The plan migrating signer 1 of [`signers_before_add`] (key `0x11` on
/// verifier V) to verifier W.
fn migration_plan(from: [u8; 32], to: [u8; 32]) -> MigrationPlan {
    plan_of(
        from,
        to,
        vec![migration_step(1, from, &verifier_w(), &[0x11; 32])],
    )
}

/// Adds a second External signer on verifier V (id 2, key `0x12`) to rule 1
/// of the served chain and records rule 1's version-2 baseline again.
/// Returns the plan migrating signers 1 and 2, the second add naming
/// `second_add_verifier`.
fn migration_plan_two_signers(h: &Harness, second_add_verifier: &ScAddress) -> MigrationPlan {
    let mut signers = signers_before_add();
    signers.push((2, external_signer(&verifier_v(), &[0x12; 32])));
    h.set_rule(1, &rule_with_ids(1, signers, vec![policy_p()]));
    h.baseline_v2(1);
    plan_of(
        webauthn_hash(),
        ed25519_hash(),
        vec![
            migration_step(1, webauthn_hash(), &verifier_w(), &[0x11; 32]),
            migration_step(2, webauthn_hash(), second_add_verifier, &[0x12; 32]),
        ],
    )
}

/// Makes the one-pair plan's sends change the chain: the removal takes
/// signer 1 off rule 1, and the add puts its key on verifier W under the
/// simulated id.
fn on_send_one_pair(h: &Harness) {
    h.on_send(
        "remove_signer",
        SendEffect::RemoveSigner {
            rule_id: 1,
            signer_id: 1,
        },
    );
    h.on_send(
        "add_signer",
        SendEffect::AddSigner {
            rule_id: 1,
            signer_id: SIMULATED_SIGNER_ID,
            signer: external_signer(&verifier_w(), &[0x11; 32]),
        },
    );
}

/// Submits `plan` through the harness's manager under `request_id`.
async fn migrate(
    h: &Harness,
    plan: &MigrationPlan,
    request_id: &str,
) -> stellar_agent_smart_account::MigrationSubmitResult {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    plan.submit(&signer, &h.manager, request_id).await
}

/// The identity of an External signer holding `key` on `verifier`.
fn external_identity(verifier: &ScAddress, key: &[u8]) -> SignerIdentityV2 {
    SignerIdentityV2::External {
        verifier: contract_id(verifier),
        key_data_sha256: Sha256::digest(key).into(),
        key_data_len: u32::try_from(key.len()).unwrap(),
    }
}

/// The row of `kind` written under `request_id`; exactly one must exist.
fn the_row(h: &Harness, request_id: &str, kind: &str) -> AuditEntry {
    let rows: Vec<AuditEntry> = rows_of(h, request_id)
        .into_iter()
        .filter(|e| serde_json::to_value(&e.event_kind).unwrap()["kind"] == kind)
        .collect();
    assert_eq!(rows.len(), 1, "one {kind} row under {request_id}");
    rows.into_iter().next().unwrap()
}

/// The verifier executable-reference pins of a pins-updated row.
fn verifier_refs_of(entry: &AuditEntry) -> Vec<Option<ExecutableRefPin>> {
    match &entry.event_kind {
        EventKind::SaContextRulePinsUpdated {
            pinned_verifier_executable_refs,
            ..
        } => pinned_verifier_executable_refs.clone(),
        other => panic!("expected SaContextRulePinsUpdated; got {other:?}"),
    }
}

/// The rows of a completed pair, in order.
const PAIR_ROWS: [&str; 4] = [
    "sa_signer_removed_v2",
    "sa_context_rule_pins_updated",
    "sa_signer_added_v2",
    "sa_verifier_migrated",
];

/// A pair on a pinned rule records its removal, repoints the pin record to
/// the destination, and records the add under the simulated id and the
/// migrated pair, in that order. It holds the rule's lock from its first
/// comparison to its last row: a `signers list` started after the removal
/// was sent completes after the pair.
#[tokio::test]
async fn a_migration_pair_records_its_rows_in_order_under_the_rule_lock() {
    let h = signer_add_harness(true).await;
    on_send_one_pair(&h);
    h.delay_poll(Duration::from_secs(2));
    let plan = migration_plan(webauthn_hash(), ed25519_hash());

    let migrated = async {
        let result = migrate(&h, &plan, "req-pair").await;
        (result, tokio::time::Instant::now())
    };
    let listed = async {
        while h.sends() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        h.manager
            .list_signers(smart_account(), 1, None, "req-list-during-pair".to_owned())
            .await
            .unwrap();
        tokio::time::Instant::now()
    };
    let ((result, migrated_at), listed_at) = tokio::join!(migrated, listed);
    assert!(
        result.failed_step_error.is_none(),
        "{:?}",
        result.failed_step_error
    );
    assert!(
        listed_at > migrated_at,
        "the list waited for the pair's lock until the pair completed"
    );
    assert_eq!(h.sends(), 2);
    assert_eq!(row_kinds(&h.rows(), "req-pair"), PAIR_ROWS);

    let resulting = h.snapshot_of(1);
    let removed = the_row(&h, "req-pair", "sa_signer_removed_v2");
    let expected_removed = SignerSetSnapshotV2 {
        signers: resulting
            .signers
            .iter()
            .filter(|entry| entry.id != SIMULATED_SIGNER_ID)
            .cloned()
            .collect(),
        threshold: resulting.threshold.clone(),
    };
    assert_eq!(state_row_snapshot(&removed), &expected_removed);
    assert!(
        matches!(
            removed.event_kind,
            EventKind::SaSignerRemovedV2 { signer_id: 1, .. }
        ),
        "{:?}",
        removed.event_kind
    );
    let added = the_row(&h, "req-pair", "sa_signer_added_v2");
    assert_eq!(state_row_snapshot(&added), &resulting);
    assert!(
        resulting.signers.contains(&SignerEntryV2 {
            id: SIMULATED_SIGNER_ID,
            identity: external_identity(&verifier_w(), &[0x11; 32]),
        }),
        "{resulting:?}"
    );
    assert!(
        matches!(
            added.event_kind,
            EventKind::SaSignerAddedV2 {
                signer_id: SIMULATED_SIGNER_ID,
                ..
            }
        ),
        "{:?}",
        added.event_kind
    );

    let pins = the_row(&h, "req-pair", "sa_context_rule_pins_updated");
    let (verifiers, policies, _, reason) = pins_updated_fields(&pins);
    assert_eq!(verifiers, vec![first8(&ed25519_hash())]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::VerifierMigrated);
    assert!(verifier_refs_of(&pins).is_empty());

    assert_eq!(result.successful_steps.len(), 1);
    assert_eq!(result.successful_steps[0].signer_id, 1);
    assert_eq!(
        result.successful_steps[0].new_signer_id,
        SIMULATED_SIGNER_ID
    );
    assert!(result.pending_add.is_none());
}

/// Asserts a migration refused at its first pair before anything was sent:
/// the error's wire code, step 0, no pending add, no send and no state row.
fn assert_first_pair_refused_unsent(
    h: &Harness,
    result: &stellar_agent_smart_account::MigrationSubmitResult,
    wire_code: &str,
    request_id: &str,
) {
    assert_eq!(h.sends(), 0, "{wire_code}: nothing is sent");
    let err = result.failed_step_error.as_ref().expect("the pair refused");
    assert_eq!(err.wire_code(), wire_code, "{err:?}");
    assert_eq!(result.failed_step_index, Some(0));
    assert_eq!(result.total_steps_attempted, 1);
    assert!(result.successful_steps.is_empty());
    assert!(result.pending_add.is_none());
    assert!(result.failed_step_remove_tx_hash.is_none());
    let kinds = row_kinds(&h.rows(), request_id);
    assert!(
        !kinds
            .iter()
            .any(|kind| kind == "sa_signer_removed_v2" || kind == "sa_signer_added_v2"),
        "{wire_code}: {kinds:?}"
    );
}

/// The removal of a pair refuses before anything is sent. A rule without a
/// state row and a rule with a version-1 row refuse before any RPC. A chain
/// changed since the row, a rule whose threshold equals its signer count and
/// a rule with a policy and no simple-threshold policy refuse after the
/// comparison's reads. So do a plan whose add does not restore the removed
/// identity on the destination, and an audit log that fails its integrity
/// check.
#[tokio::test]
async fn a_migration_pair_refuses_before_any_send() {
    let plan = migration_plan(webauthn_hash(), ed25519_hash());

    let h = Harness::new(signer_add_chain()).await;
    let result = migrate(&h, &plan, "req-no-row").await;
    assert_first_pair_refused_unsent(&h, &result, "sa.signer_set_missing_baseline", "req-no-row");
    assert!(h.primary_log.is_untouched(), "no RPC before the refusal");
    assert!(h.secondary_log.is_untouched(), "no RPC before the refusal");

    let h = Harness::new(signer_add_chain()).await;
    h.baseline_v1(1);
    let result = migrate(&h, &plan, "req-legacy").await;
    assert_first_pair_refused_unsent(&h, &result, "sa.signer_set_baseline_legacy", "req-legacy");
    assert!(h.primary_log.is_untouched(), "no RPC before the refusal");
    assert!(h.secondary_log.is_untouched(), "no RPC before the refusal");

    let h = signer_add_harness(false).await;
    let mut changed = signers_before_add();
    changed.push((3, delegated_account(0x13)));
    h.set_rule(1, &rule_with_ids(1, changed, vec![policy_p()]));
    let result = migrate(&h, &plan, "req-changed").await;
    assert_first_pair_refused_unsent(&h, &result, "sa.signer_set_diverged", "req-changed");
    assert!(
        matches!(
            result.failed_step_error,
            Some(SaError::SignerSetDiverged { tx_hash: None, .. })
        ),
        "{:?}",
        result.failed_step_error
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-changed"),
        vec!["sa_signer_set_diverged"]
    );

    let h = Harness::new(signer_add_chain().with_threshold(&policy_p(), 1, 2)).await;
    h.baseline_v2(1);
    let result = migrate(&h, &plan, "req-unreachable").await;
    assert_first_pair_refused_unsent(&h, &result, "sa.threshold_unreachable", "req-unreachable");

    let h = Harness::new(
        signer_add_chain()
            .with_rule(1, rule_with_ids(1, signers_before_add(), vec![policy_q()]))
            .with_wasm(&policy_q(), spending_limit_hash()),
    )
    .await;
    h.baseline_v2(1);
    let result = migrate(&h, &plan, "req-weighted").await;
    assert_first_pair_refused_unsent(
        &h,
        &result,
        "sa.threshold_policy_identification_failed",
        "req-weighted",
    );

    let h = signer_add_harness(false).await;
    let mismatched = plan_of(
        webauthn_hash(),
        ed25519_hash(),
        vec![migration_step(
            1,
            webauthn_hash(),
            &verifier_v(),
            &[0x11; 32],
        )],
    );
    let result = migrate(&h, &mismatched, "req-mismatch").await;
    assert_first_pair_refused_unsent(&h, &result, "sa.verifier_migration_failed", "req-mismatch");
    match &result.failed_step_error {
        Some(SaError::VerifierMigrationFailed { phase, detail, .. }) => {
            assert_eq!(*phase, "plan_build");
            assert_eq!(
                detail,
                "migrate_verifier: the add step of signer 1 does not restore the removed \
                 identity on the destination verifier"
            );
        }
        other => panic!("expected VerifierMigrationFailed; got {other:?}"),
    }

    let h = signer_add_harness(false).await;
    std::fs::OpenOptions::new()
        .append(true)
        .open(&h.log_path)
        .unwrap()
        .write_all(b"not an audit row\n")
        .unwrap();
    let result = migrate(&h, &plan, "req-integrity").await;
    let err = result.failed_step_error.as_ref().expect("the pair refused");
    assert!(matches!(err, SaError::AuditLog(_)), "{err:?}");
    assert_eq!(err.wire_code(), "sa.audit_log");
    assert_eq!(result.failed_step_index, Some(0));
    assert!(result.pending_add.is_none());
    assert_eq!(h.sends(), 0);
}

/// An add refused before signing after the removal confirmed stops the
/// pair with the removal recorded and the record repointed, and returns the
/// pending add. Running it through `signers add` completes the pair, keeps
/// the repointed pin and lets the rule sign.
#[tokio::test]
async fn an_add_refused_after_the_removal_returns_the_pending_add_that_completes_the_pair() {
    let h = signer_add_harness(true).await;
    on_send_one_pair(&h);
    h.set_simulated_return("add_signer", ScVal::Void);
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-add-refused",
    )
    .await;

    match &result.failed_step_error {
        Some(SaError::VerifierMigrationFailed { phase, detail, .. }) => {
            assert_eq!(*phase, "submit_simulate");
            assert!(
                detail.contains("add_signer: expected ScVal::U32 return, got Void"),
                "{detail}"
            );
        }
        other => panic!("expected VerifierMigrationFailed; got {other:?}"),
    }
    assert_eq!(h.sends(), 1, "the add was refused before it was signed");
    assert!(h.simulated("add_signer"));
    let pending = result.pending_add.as_ref().expect("the pending add");
    assert_eq!(pending.remove_tx_hash.len(), 64);
    assert_eq!(
        pending,
        &PendingAddStep::new_for_test(
            1,
            1,
            verifier_w(),
            vec![0x11; 32],
            pending.remove_tx_hash.clone(),
            true,
            None,
        )
    );
    assert_eq!(
        result.failed_step_remove_tx_hash.as_deref(),
        Some(pending.remove_tx_hash.as_str())
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-add-refused"),
        vec!["sa_signer_removed_v2", "sa_context_rule_pins_updated"]
    );

    h.set_simulated_return("add_signer", ScVal::U32(SIMULATED_SIGNER_ID));
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let id = h
        .manager
        .add_signer(
            smart_account(),
            pending.rule_id,
            external_signer(&verifier_w(), &pending.key_data),
            &signer,
            "req-recovery".to_owned(),
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(id, SIMULATED_SIGNER_ID);
    assert_eq!(
        row_kinds(&h.rows(), "req-recovery"),
        vec!["sa_signer_added_v2", "sa_context_rule_pins_updated"]
    );
    let pins = the_row(&h, "req-recovery", "sa_context_rule_pins_updated");
    let (verifiers, policies, _, reason) = pins_updated_fields(&pins);
    assert_eq!(verifiers, vec![first8(&ed25519_hash())]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::SignerAdded);

    h.submit(&[1], Some("req-after-recovery")).await.unwrap();
    assert_eq!(h.sends(), 3);
}

/// A removal whose state row the audit log refuses stops the pair at stage
/// `write` with the removal's hash and the pending add; the add is not
/// submitted.
#[tokio::test]
async fn a_removal_whose_row_is_refused_stops_the_pair_with_the_pending_add() {
    let h = signer_add_harness(false).await;
    on_send_one_pair(&h);
    h.poison_audit_writer_at("sendTransaction");
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-remove-unrecorded",
    )
    .await;

    assert_eq!(h.sends(), 1, "the add was not submitted");
    let pending = result.pending_add.as_ref().expect("the pending add");
    match &result.failed_step_error {
        Some(SaError::BaselineWriteFailed {
            stage,
            tx_hash: Some(hash),
            ..
        }) => {
            assert_eq!(*stage, "write");
            assert_eq!(hash, &pending.remove_tx_hash);
        }
        other => panic!("expected BaselineWriteFailed at stage write; got {other:?}"),
    }
    assert!(pending.remove_confirmed);
    assert!(h.manager.audit_writer_degraded());
}

/// A pair whose removal row and repoint the audit log refused leaves the
/// record on the source verifier. Once the writer is repaired, the printed
/// recovery completes the pair. `signers refresh --accept-divergence`
/// records the removed set and drops the pin no live `External` signer
/// uses, and the pending `signers add` then pins the destination as the
/// rule's only verifier, so the rule signs.
#[tokio::test]
async fn the_refresh_drops_the_dead_source_pin_and_the_recovery_add_signs() {
    let h = signer_add_harness(true).await;
    on_send_one_pair(&h);
    h.poison_audit_writer_at("sendTransaction");
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-pair-unrecorded",
    )
    .await;
    assert!(
        matches!(
            result.failed_step_error,
            Some(SaError::BaselineWriteFailed { stage: "write", .. })
        ),
        "{:?}",
        result.failed_step_error
    );
    let pending = result.pending_add.clone().expect("the pending add");
    assert!(
        row_kinds(&h.rows(), "req-pair-unrecorded").is_empty(),
        "neither the removal row nor the repoint was written"
    );
    h.audit.clear_poison();

    let refreshed = h
        .manager
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            RefreshOptions::new(true),
            "req-refresh-dead-pin".to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.previous_baseline, PreviousBaseline::Diverged);
    assert!(!refreshed.verifier_pinned);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-dead-pin"),
        vec![
            "sa_signer_set_diverged",
            "sa_signer_set_baselined_v2",
            "sa_context_rule_pins_updated",
        ]
    );
    let dropped = the_row(&h, "req-refresh-dead-pin", "sa_context_rule_pins_updated");
    let (verifiers, policies, _, reason) = pins_updated_fields(&dropped);
    assert!(verifiers.is_empty(), "the dead source pin is dropped");
    assert!(verifier_refs_of(&dropped).is_empty());
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::BaselineRefreshed);

    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.manager
        .add_signer(
            smart_account(),
            pending.rule_id,
            external_signer(&verifier_w(), &pending.key_data),
            &signer,
            "req-recovery-after-refresh".to_owned(),
            false,
            false,
        )
        .await
        .unwrap();
    let pinned = the_row(
        &h,
        "req-recovery-after-refresh",
        "sa_context_rule_pins_updated",
    );
    let (verifiers, _, _, reason) = pins_updated_fields(&pinned);
    assert_eq!(
        verifiers,
        vec![first8(&ed25519_hash())],
        "the destination is the rule's only verifier pin"
    );
    assert_eq!(reason, PinsUpdateReason::SignerAdded);

    h.submit(&[1], Some("req-after-dead-pin")).await.unwrap();
    assert_eq!(h.sends(), 3);
}

/// The verifier, policy and override fields of a pins-updated row.
struct PinRecordFields {
    verifiers: Vec<String>,
    verifier_refs: Vec<Option<ExecutableRefPin>>,
    policies: Vec<String>,
    policy_refs: Vec<Option<ExecutableRefPin>>,
    mutable_override: bool,
    unknown_override: bool,
    reason: PinsUpdateReason,
}

fn pin_record_fields(entry: &AuditEntry) -> PinRecordFields {
    match &entry.event_kind {
        EventKind::SaContextRulePinsUpdated {
            pinned_verifier_wasm_hashes_first8,
            pinned_verifier_executable_refs,
            pinned_policy_wasm_hashes_first8,
            pinned_policy_executable_refs,
            mutable_override,
            unknown_override,
            reason,
            ..
        } => PinRecordFields {
            verifiers: pinned_verifier_wasm_hashes_first8.clone(),
            verifier_refs: pinned_verifier_executable_refs.clone(),
            policies: pinned_policy_wasm_hashes_first8.clone(),
            policy_refs: pinned_policy_executable_refs.clone(),
            mutable_override: *mutable_override,
            unknown_override: *unknown_override,
            reason: *reason,
        },
        other => panic!("expected SaContextRulePinsUpdated; got {other:?}"),
    }
}

/// A dead verifier pin dropped by the refresh takes its executable
/// reference with it, and nothing else. The pair runs on a rule whose
/// simple-threshold policy is served through an executable reference. Its
/// record pins the source verifier with a reference, the policy with a
/// reference, and both override flags. After the removal row and the
/// repoint are refused, `signers refresh --accept-divergence` writes a pins
/// row whose verifier pin and verifier reference lists are empty. The
/// policy pin, the policy reference and the two override flags are the
/// seeded ones. A second refresh finds no verifier pin to drop and writes
/// no pins row, and the recovery add pins the destination beside the kept
/// policy reference, so the rule signs.
#[tokio::test]
async fn the_dead_pin_drop_keeps_the_policy_pins_references_and_override_flags() {
    let mut chain = Chain::default()
        .with_rule(1, signer_add_rule_before())
        .with_wasm(&verifier_v(), webauthn_hash())
        .with_wasm(&verifier_w(), ed25519_hash())
        .with_entry(external_ref_instance(&policy_p()))
        .with_entry(tag_entry(KNOWN_WASM_HASH))
        .with_threshold(&policy_p(), 1, 1);
    // The baseline helpers identify the simple-threshold policy by the hash
    // its reference resolves to.
    chain.wasm.insert(strkey(&policy_p()), KNOWN_WASM_HASH);
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    let policy_refs = vec![Some(reference_pin(KNOWN_WASM_HASH))];
    h.write(AuditEntry::new_sa_context_rule_created(
        smart_account_redacted(),
        1,
        "default",
        2,
        1,
        None,
        CHAIN_ID,
        "req-install-references",
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        true,
        true,
        vec![Some(reference_pin(webauthn_hash()))],
        policy_refs.clone(),
    ));
    on_send_one_pair(&h);
    h.poison_audit_writer_at("sendTransaction");
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-pair-references",
    )
    .await;
    assert!(
        matches!(
            result.failed_step_error,
            Some(SaError::BaselineWriteFailed { stage: "write", .. })
        ),
        "{:?}",
        result.failed_step_error
    );
    h.audit.clear_poison();

    let refresh = |request_id: &'static str| {
        h.manager.refresh_signer_baseline(
            smart_account(),
            1,
            None,
            RefreshOptions::new(true),
            request_id.to_owned(),
        )
    };
    refresh("req-refresh-references").await.unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-references"),
        vec![
            "sa_signer_set_diverged",
            "sa_signer_set_baselined_v2",
            "sa_context_rule_pins_updated",
        ]
    );
    let dropped = pin_record_fields(&the_row(
        &h,
        "req-refresh-references",
        "sa_context_rule_pins_updated",
    ));
    assert!(dropped.verifiers.is_empty(), "{:?}", dropped.verifiers);
    assert!(
        dropped.verifier_refs.is_empty(),
        "{:?}",
        dropped.verifier_refs
    );
    assert_eq!(dropped.policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(dropped.policy_refs, policy_refs);
    assert!(
        dropped.mutable_override,
        "the mutable-contract override is kept"
    );
    assert!(
        dropped.unknown_override,
        "the unknown-contract override is kept"
    );
    assert_eq!(dropped.reason, PinsUpdateReason::BaselineRefreshed);

    refresh("req-refresh-again").await.unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-again"),
        vec!["sa_signer_set_baselined_v2"],
        "a record that pins no verifier is not rewritten"
    );

    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.manager
        .add_signer(
            smart_account(),
            1,
            external_signer(&verifier_w(), &[0x11; 32]),
            &signer,
            "req-recovery-references".to_owned(),
            false,
            false,
        )
        .await
        .unwrap();
    let pinned = pin_record_fields(&the_row(
        &h,
        "req-recovery-references",
        "sa_context_rule_pins_updated",
    ));
    assert_eq!(pinned.verifiers, vec![first8(&ed25519_hash())]);
    assert_eq!(pinned.policy_refs, policy_refs);
    h.submit(&[1], Some("req-after-references")).await.unwrap();
    assert_eq!(h.sends(), 3);
}

/// A rule without `External` signers whose record pins two verifier hashes
/// keeps its record through a refresh: only a record with exactly one
/// verifier pin is dropped.
#[tokio::test]
async fn a_refresh_keeps_a_two_verifier_record_of_a_rule_without_external_signers() {
    let chain = Chain::default()
        .with_rule(
            1,
            rule_with_ids(1, vec![(0, delegated_signer())], vec![policy_p()]),
        )
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 1);
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash()), first8(&ed25519_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let refreshed = h
        .manager
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            RefreshOptions::new(false),
            "req-refresh-two-pins".to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.previous_baseline, PreviousBaseline::Matched);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-two-pins"),
        vec!["sa_signer_set_baselined_v2"]
    );
}

/// A rule with an `External` signer keeps its verifier pin through a
/// refresh, even one its live verifier does not match. A pinned verifier
/// that changed is the drift check's finding, and only a rule without
/// `External` signers drops its verifier pin.
#[tokio::test]
async fn a_refresh_keeps_the_verifier_pin_of_a_rule_with_a_live_external_signer() {
    let h = signer_add_harness(false).await;
    h.pin_created(
        1,
        vec![FOREIGN_FIRST8.to_owned()],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let refreshed = h
        .manager
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            RefreshOptions::new(false),
            "req-refresh-live".to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.previous_baseline, PreviousBaseline::Matched);
    assert!(!refreshed.verifier_pinned);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-live"),
        vec!["sa_signer_set_baselined_v2"]
    );
}

/// A confirmed removal whose resulting state is not the intended one stops
/// the pair with the removal's hash and the pending add. The pin record
/// already names the destination: the removal is on chain, so the
/// recovery's `signers add` finds the destination's pin recorded.
#[tokio::test]
async fn a_removal_whose_confirmed_state_is_wrong_stops_with_the_record_repointed() {
    let h = signer_add_harness(true).await;
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-remove-wrong",
    )
    .await;

    assert_eq!(h.sends(), 1, "the add was not submitted");
    let pending = result.pending_add.as_ref().expect("the pending add");
    match &result.failed_step_error {
        Some(SaError::SignerSetDiverged {
            tx_hash: Some(hash),
            ..
        }) => assert_eq!(hash, &pending.remove_tx_hash),
        other => panic!("expected SignerSetDiverged with the removal's hash; got {other:?}"),
    }
    assert!(pending.remove_confirmed);
    assert_eq!(
        result.failed_step_remove_tx_hash.as_deref(),
        Some(pending.remove_tx_hash.as_str())
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-remove-wrong"),
        vec!["sa_signer_set_diverged", "sa_context_rule_pins_updated"]
    );
    let pins = the_row(&h, "req-remove-wrong", "sa_context_rule_pins_updated");
    let (verifiers, _, _, reason) = pins_updated_fields(&pins);
    assert_eq!(verifiers, vec![first8(&ed25519_hash())]);
    assert_eq!(reason, PinsUpdateReason::VerifierMigrated);
}

/// A change made outside the wallet after the removal's observation is
/// found by the add's comparison against the removal's row. The add is not
/// sent, the divergence row follows the removal's row, and the pair returns
/// its pending add.
///
/// Five reads of rule 1 precede the add's comparison: the removal's
/// comparison on both endpoints, the drift check's read on the primary and
/// the removal's observation on both endpoints.
#[tokio::test]
async fn a_change_after_the_removal_refuses_the_add_before_it_is_sent() {
    let h = signer_add_harness(false).await;
    on_send_one_pair(&h);
    h.replace_rule_after_reads(
        1,
        5,
        rule_with_ids(
            1,
            vec![(0, delegated_signer()), (3, delegated_account(0x13))],
            vec![policy_p()],
        ),
    );
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-changed-between",
    )
    .await;

    assert!(
        matches!(
            result.failed_step_error,
            Some(SaError::SignerSetDiverged { tx_hash: None, .. })
        ),
        "{:?}",
        result.failed_step_error
    );
    assert_eq!(h.sends(), 1, "the add was not sent");
    assert!(
        result
            .pending_add
            .as_ref()
            .is_some_and(|p| p.remove_confirmed)
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-changed-between"),
        vec!["sa_signer_removed_v2", "sa_signer_set_diverged"]
    );
    assert_eq!(h.primary_log.rule_reads(), vec![1, 1, 1, 1]);
    assert_eq!(h.secondary_log.rule_reads(), vec![1, 1, 1]);
}

/// An add whose confirmed state is not the restored identity refuses with
/// the add's hash after both sends. The divergence row is written, no added
/// row, and no pending add, since the add confirmed. The error names the
/// refresh.
#[tokio::test]
async fn an_add_whose_confirmed_state_is_wrong_refuses_without_a_pending_add() {
    let h = signer_add_harness(false).await;
    h.on_send(
        "remove_signer",
        SendEffect::RemoveSigner {
            rule_id: 1,
            signer_id: 1,
        },
    );
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-add-wrong",
    )
    .await;

    let err = result.failed_step_error.as_ref().expect("the pair failed");
    match err {
        SaError::SignerSetDiverged {
            tx_hash: Some(hash),
            ..
        } => assert_eq!(hash.len(), 64),
        other => panic!("expected SignerSetDiverged with the add's hash; got {other:?}"),
    }
    assert!(
        err.to_string().contains("--accept-divergence"),
        "the error names the refresh: {err}"
    );
    assert_eq!(h.sends(), 2);
    assert!(result.pending_add.is_none(), "the add confirmed");
    assert!(result.failed_step_remove_tx_hash.is_none());
    assert_eq!(
        row_kinds(&h.rows(), "req-add-wrong"),
        vec!["sa_signer_removed_v2", "sa_signer_set_diverged"]
    );
}

/// Two pairs on one rule run one after the other, the second comparing
/// against the first pair's added row. Both complete, and the final state
/// row holds both restored signers on the destination and no source signer.
/// The pin record is repointed once, by the first pair.
#[tokio::test]
async fn two_pairs_on_one_rule_each_compare_against_the_newest_row() {
    let h = signer_add_harness(true).await;
    let plan = migration_plan_two_signers(&h, &verifier_w());
    for signer_id in [1, 2] {
        h.on_send(
            "remove_signer",
            SendEffect::RemoveSigner {
                rule_id: 1,
                signer_id,
            },
        );
    }
    for (signer_id, key) in [(7, [0x11; 32]), (8, [0x12; 32])] {
        h.on_send(
            "add_signer",
            SendEffect::AddSigner {
                rule_id: 1,
                signer_id,
                signer: external_signer(&verifier_w(), &key),
            },
        );
    }
    h.set_simulated_returns("add_signer", vec![ScVal::U32(7), ScVal::U32(8)]);

    let result = migrate(&h, &plan, "req-two-pairs").await;
    assert!(
        result.failed_step_error.is_none(),
        "{:?}",
        result.failed_step_error
    );
    assert_eq!(h.sends(), 4);
    let new_ids: Vec<u32> = result
        .successful_steps
        .iter()
        .map(|step| step.new_signer_id)
        .collect();
    assert_eq!(new_ids, vec![7, 8]);
    assert_eq!(
        row_kinds(&h.rows(), "req-two-pairs"),
        vec![
            "sa_signer_removed_v2",
            "sa_context_rule_pins_updated",
            "sa_signer_added_v2",
            "sa_verifier_migrated",
            "sa_signer_removed_v2",
            "sa_signer_added_v2",
            "sa_verifier_migrated",
        ]
    );
    let final_row = rows_of(&h, "req-two-pairs")
        .into_iter()
        .rfind(|e| matches!(e.event_kind, EventKind::SaSignerAddedV2 { .. }))
        .unwrap();
    let final_state = state_row_snapshot(&final_row);
    assert_eq!(final_state, &h.snapshot_of(1));
    let ids: Vec<u32> = final_state.signers.iter().map(|entry| entry.id).collect();
    assert_eq!(ids, vec![0, 7, 8]);
    assert_eq!(
        final_state.signers[1].identity,
        external_identity(&verifier_w(), &[0x11; 32])
    );
    assert_eq!(
        final_state.signers[2].identity,
        external_identity(&verifier_w(), &[0x12; 32])
    );
    let pins = the_row(&h, "req-two-pairs", "sa_context_rule_pins_updated");
    let (verifiers, _, _, reason) = pins_updated_fields(&pins);
    assert_eq!(verifiers, vec![first8(&ed25519_hash())]);
    assert_eq!(reason, PinsUpdateReason::VerifierMigrated);
}

/// A second pair whose plan does not restore its signer on the destination
/// stops at its plan check after the first pair completed: step 1, one
/// successful step, no pending add, two sends.
#[tokio::test]
async fn a_second_pair_whose_plan_does_not_match_stops_after_the_first() {
    let h = signer_add_harness(false).await;
    let plan = migration_plan_two_signers(&h, &verifier_v());
    on_send_one_pair(&h);

    let result = migrate(&h, &plan, "req-second-mismatch").await;
    match &result.failed_step_error {
        Some(SaError::VerifierMigrationFailed { phase, .. }) => assert_eq!(*phase, "plan_build"),
        other => panic!("expected VerifierMigrationFailed at plan_build; got {other:?}"),
    }
    assert_eq!(result.failed_step_index, Some(1));
    assert_eq!(result.total_steps_attempted, 2);
    assert_eq!(result.successful_steps.len(), 1);
    assert!(result.pending_add.is_none());
    assert_eq!(h.sends(), 2);
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
    on_send_one_pair(&h);
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-migrate",
    )
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
    assert_eq!(row_kinds(&h.rows(), "req-migrate"), PAIR_ROWS);
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
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-migrate-policy",
    )
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

/// A migration on a rule without a pin record writes no pins-updated row,
/// and records both state rows of the pair.
#[tokio::test]
async fn a_migration_on_an_unpinned_rule_writes_no_row() {
    let h = signer_add_harness(false).await;
    on_send_one_pair(&h);
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-migrate-unpinned",
    )
    .await;
    assert!(
        result.failed_step_error.is_none(),
        "{:?}",
        result.failed_step_error
    );
    assert!(h.pins_updated_rows().is_empty());
    assert_eq!(
        row_kinds(&h.rows(), "req-migrate-unpinned"),
        vec![
            "sa_signer_removed_v2",
            "sa_signer_added_v2",
            "sa_verifier_migrated"
        ]
    );
}

/// A secondary endpoint one ledger behind the removal's confirmation for
/// one read is read again, and the pair completes with its rows.
#[tokio::test]
async fn a_secondary_behind_the_removal_is_read_again_and_the_pair_completes() {
    let h = signer_add_harness(true).await;
    on_send_one_pair(&h);
    h.secondary_ledgers
        .queued
        .lock()
        .unwrap()
        .push_back(PRE_SEND_LEDGER);
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-pair-lagging",
    )
    .await;
    assert!(
        result.failed_step_error.is_none(),
        "{:?}",
        result.failed_step_error
    );
    assert_eq!(row_kinds(&h.rows(), "req-pair-lagging"), PAIR_ROWS);
    assert_eq!(
        h.secondary_log.simulated(),
        vec![
            "get_context_rule",
            "get_threshold",
            "get_context_rule",
            "get_context_rule",
            "get_threshold",
            "get_context_rule",
            "get_threshold",
            "get_context_rule",
            "get_threshold",
        ],
        "the behind rule read after the removal is repeated"
    );
}

/// A removal whose confirmation never arrives stops the pair with the
/// unknown outcome and its hash. The pin record already names the
/// destination, no state row is written, and the pending add carries the
/// hash with the removal unconfirmed.
#[tokio::test]
async fn an_unresolved_removal_repoints_the_record_and_returns_the_pending_add() {
    let h = Harness::with_timeout(signer_add_chain(), Duration::from_secs(2)).await;
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.never_confirm_next_send();
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-remove-unresolved",
    )
    .await;

    let hash = match &result.failed_step_error {
        Some(SaError::SubmissionUnresolved {
            kind: stellar_agent_smart_account::SubmissionUnresolvedKind::Timeout,
            tx_hash: Some(hash),
            ..
        }) => hash.clone(),
        other => panic!("expected SubmissionUnresolved (timeout) with a hash; got {other:?}"),
    };
    assert_eq!(h.sends(), 1);
    assert_eq!(
        result.pending_add,
        Some(PendingAddStep::new_for_test(
            1,
            1,
            verifier_w(),
            vec![0x11; 32],
            hash,
            false,
            None,
        ))
    );
    assert!(result.failed_step_remove_tx_hash.is_none());
    assert_eq!(
        row_kinds(&h.rows(), "req-remove-unresolved"),
        vec!["sa_context_rule_pins_updated"]
    );
    let pins = the_row(&h, "req-remove-unresolved", "sa_context_rule_pins_updated");
    let (verifiers, _, _, reason) = pins_updated_fields(&pins);
    assert_eq!(verifiers, vec![first8(&ed25519_hash())]);
    assert_eq!(reason, PinsUpdateReason::VerifierMigrated);
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
            assert_eq!(rule_id, Some(5));
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
/// (simple-threshold), Q (spending-limit) and R (unknown hash). P is served
/// with [`Chain::with_wasm`], so a baseline written from the chain records
/// its threshold once a test sets one.
async fn policy_harness(policies: Vec<ScAddress>) -> Harness {
    let chain = Chain::default()
        .with_rule(1, rule_one_with_policies(policies))
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()))
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_entry(wasm_instance(&policy_q(), spending_limit_hash()))
        .with_entry(wasm_instance(&policy_r(), [0xdd; 32]));
    Harness::new(chain).await
}

/// The install parameter of the simple-threshold policy with `threshold`.
fn threshold_param(threshold: u32) -> ScVal {
    stellar_agent_smart_account::simple_threshold_policy::build_simple_threshold_install_param(
        threshold,
    )
    .unwrap()
}

/// The install parameter the policy-pin tests attach `policy` with: the
/// simple-threshold parameter with threshold 1 for P, the policy that takes
/// the threshold path, and `Void` for the others.
fn pin_test_param(policy: &ScAddress) -> ScVal {
    if *policy == policy_p() {
        threshold_param(1)
    } else {
        ScVal::Void
    }
}

/// Attaches `policy` to rule 1 with [`pin_test_param`], authorized under
/// rule 0.
async fn add_policy(
    h: &Harness,
    policy: &ScAddress,
    request_id: &str,
    accept_unknown_verifier: bool,
) -> Result<u32, SaError> {
    add_policy_with(
        h,
        policy,
        pin_test_param(policy),
        request_id,
        accept_unknown_verifier,
    )
    .await
}

/// Attaches `policy` to rule 1 with `install_param`, authorized under rule 0.
async fn add_policy_with(
    h: &Harness,
    policy: &ScAddress,
    install_param: ScVal,
    request_id: &str,
    accept_unknown_verifier: bool,
) -> Result<u32, SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.rule_manager()
        .add_policy(
            smart_account(),
            1,
            policy.clone(),
            install_param,
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
    remove_policy_under(h, policy_id, &[0], request_id).await
}

/// Removes the policy with on-chain id `policy_id` from rule 1, authorized
/// under `auth_rule_ids`.
async fn remove_policy_under(
    h: &Harness,
    policy_id: u32,
    auth_rule_ids: &[u32],
    request_id: &str,
) -> Result<(), SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.rule_manager()
        .remove_policy(
            smart_account(),
            1,
            policy_id,
            auth_rule_ids
                .iter()
                .copied()
                .map(ContextRuleId::new)
                .collect(),
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

/// The post-send state of attaching the simple-threshold policy P to rule 1
/// with threshold 1: the rule holds `policies`, and P's threshold is 1.
fn after_threshold_attach(policies: Vec<ScAddress>) -> AfterSend {
    AfterSend {
        rules: vec![(1, rule_one_with_policies(policies))],
        thresholds: vec![(strkey(&policy_p()), 1, 1)],
    }
}

/// A policy attached to a pinned rule with no policy pin is pinned: the
/// record gains its pin, and the next checked verb compares the live policy
/// with it.
#[tokio::test]
async fn a_policy_added_to_a_pinned_rule_is_pinned_and_checked() {
    let h = policy_harness(vec![]).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.after_send_state(&after_threshold_attach(vec![policy_p()]));
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
    h.set_threshold(&policy_p(), 1, 1);
    h.baseline_v2(1);
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
    h.baseline_v2(1);
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
    h.baseline_v2(1);
    add_policy(&h, &policy_r(), "req-policy-unpinned", false)
        .await
        .unwrap();
    assert!(h.pins_updated_rows().is_empty());
    assert_eq!(h.sends(), 1);
}

/// A confirmed policy add of an unknown policy under the override writes,
/// under the rule's lock, the override row naming the rule and the
/// pins-updated row, then `SaPolicyAdded` and the raw-invocation row.
#[tokio::test]
async fn a_policy_add_writes_the_override_row_before_the_policy_row() {
    let h = policy_harness(vec![]).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.after_send(1, rule_one_with_policies(vec![policy_r()]));
    add_policy(&h, &policy_r(), "req-policy-order", true)
        .await
        .unwrap();

    assert_eq!(
        row_kinds(&h.rows(), "req-policy-order"),
        vec![
            "unknown_override(rule Some(1))",
            "sa_context_rule_pins_updated",
            "sa_policy_added",
            "sa_raw_invocation",
        ]
    );
}

/// Removing the pinned policy clears its pin, and a later add of a policy
/// with another hash writes a fresh one-pin record the next verb accepts.
#[tokio::test]
async fn removing_the_pinned_policy_clears_its_pin() {
    let h = policy_harness(vec![policy_p()]).await;
    h.set_threshold(&policy_p(), 1, 1);
    h.baseline_v2(1);
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
    // The served P runs no simple-threshold executable, so the comparison
    // observes no threshold.
    h.set_threshold(&policy_p(), 1, 1);
    h.write_v2_baseline(
        1,
        &SignerSetSnapshotV2 {
            signers: h.snapshot_of(1).signers,
            threshold: None,
        },
    );
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

    h.baseline_v2(1);
    h.submit(&[1], Some("req-after-drifted-replace"))
        .await
        .unwrap();
}

/// A rule's only policy whose executable cannot be read refuses the removal
/// before submission: the removal cannot tell whether the policy is the
/// simple-threshold policy whose threshold change it must record. The pin
/// record and the chain are unchanged.
#[tokio::test]
async fn removing_an_unreadable_only_policy_refuses_before_submission() {
    let h = policy_harness(vec![policy_p()]).await;
    h.set_threshold(&policy_p(), 1, 1);
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.fail_reads_of(&policy_p());
    h.after_send(1, rule_one_with_policies(vec![]));
    let err = remove_policy(&h, 0, "req-unreadable-remove")
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.deployment_failed", "{err:?}");
    assert_eq!(h.sends(), 0);
    assert!(!h.simulated("remove_policy"));
    assert!(h.pins_updated_rows().is_empty());
    assert_eq!(
        row_kinds(&h.rows(), "req-unreadable-remove"),
        vec!["sa_raw_invocation"]
    );
}

/// With two policy pins, the removal drops the pin equal to the removed
/// policy's hash, not the first one, and the next verb checks the policy
/// that stays.
#[tokio::test]
async fn removing_one_of_two_policies_drops_the_pin_of_its_hash() {
    let h = policy_harness(vec![policy_p(), policy_q()]).await;
    h.set_threshold(&policy_p(), 1, 1);
    h.baseline_v2(1);
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
    h.set_threshold(&policy_p(), 1, 1);
    h.baseline_v2(1);
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
    h.baseline_v2(1);
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
    h.baseline_v2(1);
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
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.submit(&[1], Some("req-no-policy")).await.unwrap();
    assert_eq!(h.sends(), 1);
}

/// A policy added to a rule with no policy on chain replaces the record's
/// stale policy pin with its own, and the next verb signs.
#[tokio::test]
async fn a_policy_added_with_no_live_policy_replaces_a_stale_pin() {
    let h = policy_harness(vec![]).await;
    h.baseline_v2(1);
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
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH), first8(&spending_limit_hash())],
        vec![],
        vec![],
    );
    h.after_send_state(&after_threshold_attach(vec![policy_p()]));
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
    h.baseline_v2(1);
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
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let result = migrate(
        &h,
        &migration_plan(webauthn_hash(), ed25519_hash()),
        "req-migrate-absent",
    )
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

/// The deployment failure of a simulated return value that is not the
/// shape the caller reads, refused before signing.
fn assert_return_shape_refusal(err: &SaError, expected_reason: &str) {
    match err {
        SaError::DeploymentFailed {
            phase,
            redacted_reason,
        } => {
            assert_eq!(*phase, "simulate");
            assert_eq!(redacted_reason, expected_reason);
        }
        other => panic!("expected DeploymentFailed at phase simulate; got {other:?}"),
    }
    assert_eq!(err.wire_code(), "sa.deployment_failed");
}

/// A passkey add whose simulated return value is not a `u32` is refused
/// before it is signed: nothing is sent, and no pin or state row is
/// written.
#[tokio::test]
async fn an_add_whose_simulated_return_is_not_a_u32_refuses_before_signing() {
    let h = verifierless_pinned_rule().await;
    h.set_simulated_return("add_signer", ScVal::Void);
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
    assert_return_shape_refusal(&err, "add_signer: expected ScVal::U32 return, got Void");
    assert!(h.simulated("add_signer"));
    assert_eq!(h.sends(), 0);
    assert!(row_kinds(&h.rows(), "req-void-return").is_empty());
}

/// A passkey add, single or batched, on a rule whose pin record holds no
/// verifier pin writes the passkey verifier's pin once the add confirms,
/// although the confirmed state is never observed.
///
/// The unrecorded add leaves the rule's state row behind the chain, so the
/// next submission under the rule refuses at the signer-set comparison and
/// sends nothing. Once `signers refresh` accepts the chain, a submission
/// signs with the passkey verifier matching its pin, and a later change of
/// that verifier's executable is refused by the drift check.
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

        // The secondary catches up; both endpoints now serve the confirmed
        // add, which no state row records.
        *h.secondary_ledgers.after_send.lock().unwrap() = None;
        let err = h
            .submit(&[1], Some("req-unrecorded-add"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                SaError::SignerSetDiverged {
                    rule_id: 1,
                    tx_hash: None,
                    ..
                }
            ),
            "batch {batch}: {err:?}"
        );
        assert_eq!(h.sends(), 1, "batch {batch}");

        h.manager
            .refresh_signer_baseline(
                smart_account(),
                1,
                None,
                RefreshOptions::new(true),
                format!("req-accept-{batch}"),
            )
            .await
            .unwrap_or_else(|e| panic!("batch {batch}: the refresh accepts the chain: {e:?}"));
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
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            RefreshOptions::new(false),
            "req-upgrade".to_owned(),
        )
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
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            RefreshOptions::new(false),
            "req-refresh-no".to_owned(),
        )
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
        .refresh_signer_baseline(
            smart_account(),
            1,
            None,
            RefreshOptions::new(true),
            "req-refresh-yes".to_owned(),
        )
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
            RefreshOptions::new(false),
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
            RefreshOptions::new(true),
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

// ── Rule install: the confirmed-install baseline ──────────────────────────────

/// A second simple-threshold policy, served with the same executable as P.
fn policy_p2() -> ScAddress {
    contract(0x38)
}

/// A third simple-threshold policy, served with the other allowlisted
/// simple-threshold executable.
fn policy_p3() -> ScAddress {
    contract(0x39)
}

/// An `External` signer input on verifier V with `key`.
fn passkey_input(key: &[u8]) -> ContextRuleSignerInput {
    ContextRuleSignerInput::External {
        verifier: verifier_v(),
        pubkey_data: key.to_vec(),
    }
}

/// A `Delegated` signer input for the ed25519 account `[byte; 32]`.
fn account_input(byte: u8) -> ContextRuleSignerInput {
    ContextRuleSignerInput::Delegated {
        address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            [byte; 32],
        )))),
    }
}

fn install_definition(
    signers: Vec<ContextRuleSignerInput>,
    policies: Vec<ContextRulePolicy>,
) -> ContextRuleDefinition {
    ContextRuleDefinition::new(
        RuleContext::Default,
        "installed".to_owned(),
        None,
        signers,
        policies,
    )
}

/// A chain serving rule 0, which authorizes the installs, and the contracts
/// the install tests reference: verifier V, the simple-threshold policies P
/// and P2, and policy R with an unknown hash. The installed rule takes id 1,
/// the next free id.
fn install_chain() -> Chain {
    Chain::default()
        .with_rule(0, rule(0, vec![delegated_signer()], vec![]))
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()))
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_wasm(&policy_p2(), KNOWN_WASM_HASH)
        .with_entry(wasm_instance(&policy_r(), [0xdd; 32]))
}

/// The state an install of rule 1 with `signers` and `policies` leaves, with
/// `thresholds` as `(policy, threshold)` pairs for rule 1.
fn installed(
    signers: Vec<ScVal>,
    policies: Vec<ScAddress>,
    thresholds: &[(ScAddress, u32)],
) -> AfterSend {
    AfterSend {
        rules: vec![(1, rule(1, signers, policies))],
        thresholds: thresholds
            .iter()
            .map(|(policy, threshold)| (strkey(policy), 1, *threshold))
            .collect(),
    }
}

/// Installs `definition` authorized under rule 0.
async fn install(
    h: &Harness,
    definition: ContextRuleDefinition,
    request_id: &str,
    accept_unknown_verifier: bool,
) -> Result<u32, SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.rule_manager()
        .install_rule(
            smart_account(),
            definition,
            vec![ContextRuleId::new(0)],
            &signer,
            None,
            request_id.to_owned(),
            false,
            accept_unknown_verifier,
        )
        .await
        .map(|output| output.rule_id)
}

/// Simulates the install of `definition`.
async fn simulate_install(
    h: &Harness,
    definition: ContextRuleDefinition,
    request_id: &str,
) -> Result<u32, SaError> {
    h.rule_manager()
        .simulate_install_rule(
            smart_account(),
            definition,
            &account_id_for_seed(SEED),
            false,
            false,
            request_id.to_owned(),
        )
        .await
        .map(|output| output.latest_ledger)
}

/// A rule manager over the harness's endpoints with no signers manager.
fn rule_manager_without_signers_manager(h: &Harness) -> ContextRuleManager {
    ContextRuleManager::new(ContextRuleManagerConfig::new(
        h.primary.uri(),
        PASSPHRASE.to_owned(),
        Duration::from_secs(10),
        CHAIN_ID.to_owned(),
    ))
    .unwrap()
}

/// The wire code of the `SaRawInvocation` row written under `request_id`.
fn raw_wire_code(h: &Harness, request_id: &str) -> String {
    let codes: Vec<String> = rows_of(h, request_id)
        .into_iter()
        .filter_map(|entry| match entry.event_kind {
            EventKind::SaRawInvocation { wire_code, .. } => Some(wire_code),
            _ => None,
        })
        .collect();
    assert_eq!(codes.len(), 1, "one raw invocation row: {codes:?}");
    codes[0].clone()
}

/// The `SaSignerSetBaselinedV2` row written under `request_id`.
fn baselined_row(h: &Harness, request_id: &str) -> (SignerSetSnapshotV2, BaselineReason, u32) {
    let rows: Vec<(SignerSetSnapshotV2, BaselineReason, u32)> = rows_of(h, request_id)
        .into_iter()
        .filter_map(|entry| match entry.event_kind {
            EventKind::SaSignerSetBaselinedV2 {
                rule_id: 1,
                snapshot,
                baseline_reason,
                observed_at_ledger_seq,
                ..
            } => Some((snapshot, baseline_reason, observed_at_ledger_seq)),
            _ => None,
        })
        .collect();
    assert_eq!(rows.len(), 1, "one baseline row for rule 1");
    rows.into_iter().next().unwrap()
}

/// The `InstallStateMismatch` fields of `err`, or a panic naming it.
fn install_state_mismatch(err: &SaError) -> (Option<u32>, &str) {
    match err {
        SaError::InstallStateMismatch {
            rule_id, tx_hash, ..
        } => (*rule_id, tx_hash.as_str()),
        other => panic!("expected InstallStateMismatch; got {other:?}"),
    }
}

/// A confirmed install writes the override row, the `SaContextRuleCreated`
/// row, the baseline with reason `confirmed_install` recording the served
/// rule at the confirmation ledger, then `sa.ok`; the next `signers list`
/// matches the baseline.
#[tokio::test]
async fn a_confirmed_install_records_its_baseline_after_the_created_row() {
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(
        vec![
            external_signer(&verifier_v(), &[0x11; 65]),
            delegated_account(0x13),
        ],
        vec![policy_r()],
        &[],
    ));
    let rule_id = install(
        &h,
        install_definition(
            vec![passkey_input(&[0x11; 65]), account_input(0x13)],
            vec![ContextRulePolicy::new(policy_r(), ScVal::Void)],
        ),
        "req-install",
        true,
    )
    .await
    .unwrap();
    assert_eq!(rule_id, 1);
    assert_eq!(
        row_kinds(&h.rows(), "req-install"),
        vec![
            "unknown_override(rule Some(1))",
            "sa_context_rule_created",
            "sa_signer_set_baselined_v2",
            "sa_raw_invocation",
        ]
    );
    assert_eq!(raw_wire_code(&h, "req-install"), "sa.ok");
    let (snapshot, reason, ledger) = baselined_row(&h, "req-install");
    assert_eq!(snapshot, h.snapshot_of(1));
    assert_eq!(snapshot.signers.len(), 2);
    assert_eq!(snapshot.threshold, None);
    assert_eq!(reason, BaselineReason::ConfirmedInstall);
    assert_eq!(ledger, CONFIRMATION_LEDGER);
    assert_eq!(h.sends(), 1);

    let listed = h
        .manager
        .list_signers(smart_account(), 1, None, "req-install-list".to_owned())
        .await
        .unwrap();
    assert_eq!(listed.baseline, PreviousBaseline::Matched);
}

/// An install that attaches the simple-threshold policy baselines the
/// policy with the threshold of its install parameter.
#[tokio::test]
async fn an_install_with_the_simple_threshold_policy_baselines_its_threshold() {
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(
        vec![delegated_account(0x13)],
        vec![policy_p()],
        &[(policy_p(), 2)],
    ));
    install(
        &h,
        install_definition(
            vec![account_input(0x13)],
            vec![ContextRulePolicy::new(policy_p(), threshold_param(2))],
        ),
        "req-install-threshold",
        false,
    )
    .await
    .unwrap();
    let (snapshot, reason, _) = baselined_row(&h, "req-install-threshold");
    assert_eq!(
        snapshot.threshold,
        Some(ThresholdObservation {
            policy: contract_id(&policy_p()),
            threshold: 2
        })
    );
    assert_eq!(reason, BaselineReason::ConfirmedInstall);
}

/// Asserts the outcome of a confirmed install whose served rule is not the
/// definition: `sa.install_state_mismatch` naming rule 1 and the
/// transaction, the created row and the refusal's raw row, no baseline.
fn assert_mismatch_without_baseline(h: &Harness, err: &SaError, request_id: &str) {
    let (rule_id, tx_hash) = install_state_mismatch(err);
    assert_eq!(rule_id, Some(1));
    assert_eq!(tx_hash.len(), 64);
    assert_eq!(err.wire_code(), "sa.install_state_mismatch");
    assert_eq!(
        row_kinds(&h.rows(), request_id),
        vec!["sa_context_rule_created", "sa_raw_invocation"]
    );
    assert_eq!(raw_wire_code(h, request_id), "sa.install_state_mismatch");
    assert_eq!(h.sends(), 1);
}

/// A served threshold value other than the install parameter's refuses with
/// `sa.install_state_mismatch` and writes no baseline.
#[tokio::test]
async fn an_install_whose_served_threshold_differs_refuses_with_the_rule_id() {
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(
        vec![delegated_account(0x13)],
        vec![policy_p()],
        &[(policy_p(), 3)],
    ));
    let err = install(
        &h,
        install_definition(
            vec![account_input(0x13)],
            vec![ContextRulePolicy::new(policy_p(), threshold_param(2))],
        ),
        "req-install-value",
        false,
    )
    .await
    .unwrap_err();
    assert_mismatch_without_baseline(&h, &err, "req-install-value");
}

/// A served simple-threshold policy other than the definition's, at the
/// same threshold value, refuses: the comparison covers the policy, not the
/// value alone.
#[tokio::test]
async fn an_install_whose_served_threshold_policy_differs_refuses() {
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(
        vec![delegated_account(0x13)],
        vec![policy_p2()],
        &[(policy_p2(), 2)],
    ));
    let err = install(
        &h,
        install_definition(
            vec![account_input(0x13)],
            vec![ContextRulePolicy::new(policy_p(), threshold_param(2))],
        ),
        "req-install-policy",
        false,
    )
    .await
    .unwrap_err();
    assert_mismatch_without_baseline(&h, &err, "req-install-policy");
}

/// Served signers that differ from the definition in one identity, at an
/// equal count, refuse: the comparison covers every identity, not the
/// count alone.
#[tokio::test]
async fn an_install_whose_served_signers_differ_in_one_identity_refuses() {
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(
        vec![
            external_signer(&verifier_v(), &[0x11; 65]),
            delegated_account(0x14),
        ],
        vec![],
        &[],
    ));
    let err = install(
        &h,
        install_definition(
            vec![passkey_input(&[0x11; 65]), account_input(0x13)],
            vec![],
        ),
        "req-install-signers",
        false,
    )
    .await
    .unwrap_err();
    assert_mismatch_without_baseline(&h, &err, "req-install-signers");
}

/// An install whose simulated return value carries no rule id is refused
/// before it is signed. Nothing is sent, and the raw row carries the
/// refusal. Neither the override row nor the created row is written, since
/// no rule exists.
#[tokio::test]
async fn an_install_whose_return_carries_no_rule_id_refuses_without_one() {
    let h = Harness::new(install_chain()).await;
    h.set_simulated_return("add_context_rule", ScVal::Void);
    h.after_send_state(&installed(
        vec![delegated_account(0x13)],
        vec![policy_r()],
        &[],
    ));
    let err = install(
        &h,
        install_definition(
            vec![account_input(0x13)],
            vec![ContextRulePolicy::new(policy_r(), ScVal::Void)],
        ),
        "req-install-void",
        true,
    )
    .await
    .unwrap_err();
    assert_return_shape_refusal(&err, "install_rule: expected a map with a u32 id, got Void");
    assert!(h.simulated("add_context_rule"));
    assert_eq!(h.sends(), 0);
    assert_eq!(
        row_kinds(&h.rows(), "req-install-void"),
        vec!["sa_raw_invocation"]
    );
    assert_eq!(
        raw_wire_code(&h, "req-install-void"),
        "sa.deployment_failed"
    );
}

/// A confirmed install whose baseline row the audit log refuses (the
/// writer poisoned after the created row) fails at stage `write` with the
/// transaction hash; the created row stays and no baseline is written.
#[tokio::test]
async fn an_install_whose_baseline_row_is_refused_fails_at_stage_write() {
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(vec![delegated_account(0x13)], vec![], &[]));
    h.poison_audit_writer_at("get_context_rule");
    let err = install(
        &h,
        install_definition(vec![account_input(0x13)], vec![]),
        "req-install-poisoned",
        false,
    )
    .await
    .unwrap_err();
    match &err {
        SaError::BaselineWriteFailed {
            rule_id: 1,
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
    assert_eq!(
        row_kinds(&h.rows(), "req-install-poisoned"),
        vec!["sa_context_rule_created"]
    );
    assert_eq!(h.sends(), 1);
}

/// A secondary that stays behind the confirmation ledger for the whole
/// recording budget fails the install's baseline at stage `observe` with the
/// transaction hash; the created row and the refusal's raw row are written.
#[tokio::test]
async fn an_install_whose_secondary_stays_behind_fails_at_stage_observe() {
    let h = Harness::with_timeout(install_chain(), Duration::from_secs(2)).await;
    h.after_send_state(&installed(vec![delegated_account(0x13)], vec![], &[]));
    *h.secondary_ledgers.after_send.lock().unwrap() = Some(PRE_SEND_LEDGER);
    let err = install(
        &h,
        install_definition(vec![account_input(0x13)], vec![]),
        "req-install-behind",
        false,
    )
    .await
    .unwrap_err();
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
            assert!(reason.contains("(secondary)"), "{reason}");
        }
        other => panic!("expected BaselineWriteFailed at stage observe; got {other:?}"),
    }
    assert_eq!(
        row_kinds(&h.rows(), "req-install-behind"),
        vec!["sa_context_rule_created", "sa_raw_invocation"]
    );
    assert_eq!(
        raw_wire_code(&h, "req-install-behind"),
        "sa.baseline_write_failed"
    );
}

/// Without a signers manager an install and its simulation refuse with
/// `sa.signers_manager_not_configured` and no rule id, before any RPC.
#[tokio::test]
async fn an_install_and_its_simulation_without_a_signers_manager_refuse_before_any_rpc() {
    let h = Harness::new(install_chain()).await;
    let manager = rule_manager_without_signers_manager(&h);
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let installed = manager
        .install_rule(
            smart_account(),
            install_definition(vec![account_input(0x13)], vec![]),
            vec![ContextRuleId::new(0)],
            &signer,
            None,
            "req-install-no-manager".to_owned(),
            false,
            false,
        )
        .await
        .unwrap_err();
    let simulated = manager
        .simulate_install_rule(
            smart_account(),
            install_definition(vec![account_input(0x13)], vec![]),
            &account_id_for_seed(SEED),
            false,
            false,
            "req-simulate-no-manager".to_owned(),
        )
        .await
        .unwrap_err();
    for (err, request) in [
        (&installed, "req-install-no-manager"),
        (&simulated, "req-simulate-no-manager"),
    ] {
        match err {
            SaError::SignersManagerNotConfigured {
                rule_id,
                request_id,
                ..
            } => {
                assert_eq!(*rule_id, None);
                assert_eq!(request_id, request);
            }
            other => panic!("expected SignersManagerNotConfigured; got {other:?}"),
        }
        assert_eq!(err.wire_code(), "sa.signers_manager_not_configured");
    }
    assert!(h.primary_log.is_untouched());
    assert!(h.secondary_log.is_untouched());
}

/// Asserts that `err` is the build-phase refusal with `reason`, and that
/// nothing was simulated as an install or sent.
fn assert_build_refusal(h: &Harness, err: &SaError, reason: &str) {
    match err {
        SaError::DeploymentFailed {
            phase,
            redacted_reason,
        } => {
            assert_eq!(*phase, "build");
            assert_eq!(redacted_reason, reason);
        }
        other => panic!("expected DeploymentFailed at phase build; got {other:?}"),
    }
    assert!(!h.simulated("add_context_rule"));
    assert_eq!(h.sends(), 0);
}

/// A definition that attaches two policies whose executables are the
/// simple-threshold policy refuses an install and its simulation before
/// either is simulated.
#[tokio::test]
async fn two_simple_threshold_policies_refuse_an_install_and_its_simulation() {
    let h = Harness::new(install_chain()).await;
    let definition = || {
        install_definition(
            vec![account_input(0x13)],
            vec![
                ContextRulePolicy::new(policy_p(), threshold_param(1)),
                ContextRulePolicy::new(policy_p2(), threshold_param(1)),
            ],
        )
    };
    let reason = "install: 2 policies identify as the simple-threshold policy; at most one is \
                  allowed";
    let err = install(&h, definition(), "req-install-two", false)
        .await
        .unwrap_err();
    assert_build_refusal(&h, &err, reason);
    assert_eq!(raw_wire_code(&h, "req-install-two"), "sa.deployment_failed");
    let err = simulate_install(&h, definition(), "req-simulate-two")
        .await
        .unwrap_err();
    assert_build_refusal(&h, &err, reason);
}

/// A simple-threshold install parameter that is not the threshold map
/// refuses an install and its simulation before either is simulated.
#[tokio::test]
async fn a_malformed_threshold_parameter_refuses_an_install_and_its_simulation() {
    let h = Harness::new(install_chain()).await;
    let definition = || {
        install_definition(
            vec![account_input(0x13)],
            vec![ContextRulePolicy::new(policy_p(), ScVal::Void)],
        )
    };
    for err in [
        install(&h, definition(), "req-install-malformed", false)
            .await
            .unwrap_err(),
        simulate_install(&h, definition(), "req-simulate-malformed")
            .await
            .unwrap_err(),
    ] {
        assert!(
            matches!(err, SaError::SimpleThresholdInstallRefused { .. }),
            "{err:?}"
        );
    }
    assert!(!h.simulated("add_context_rule"));
    assert_eq!(h.sends(), 0);
}

/// A definition that lists a policy address twice refuses an install and its
/// simulation before either is simulated.
#[tokio::test]
async fn a_policy_address_listed_twice_refuses_an_install_before_submission() {
    let h = Harness::new(install_chain()).await;
    let definition = || {
        install_definition(
            vec![account_input(0x13)],
            vec![
                ContextRulePolicy::new(policy_p(), threshold_param(1)),
                ContextRulePolicy::new(policy_p(), threshold_param(1)),
            ],
        )
    };
    let err = install(&h, definition(), "req-install-twice", false)
        .await
        .unwrap_err();
    assert_build_refusal(&h, &err, "install: policy address listed twice");
    let err = simulate_install(&h, definition(), "req-simulate-twice")
        .await
        .unwrap_err();
    assert_build_refusal(&h, &err, "install: policy address listed twice");
}

/// An `External` signer with empty key data refuses before submission.
#[tokio::test]
async fn an_external_signer_with_empty_key_data_refuses_an_install_before_submission() {
    let h = Harness::new(install_chain()).await;
    let err = install(
        &h,
        install_definition(vec![passkey_input(&[])], vec![]),
        "req-install-empty-key",
        false,
    )
    .await
    .unwrap_err();
    match &err {
        SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } => {
            assert_eq!(*stage, "auth_payload");
            assert_eq!(redacted_reason, "External signer pubkey is empty");
        }
        other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
    }
    assert!(!h.simulated("add_context_rule"));
    assert_eq!(h.sends(), 0);
}

/// A signer delegated to a contract installs, and the baseline records its
/// full contract identity.
#[tokio::test]
async fn a_contract_delegate_installs_and_its_baseline_carries_it() {
    let delegate = contract(0x77);
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(vec![contract_delegate(&delegate)], vec![], &[]));
    install(
        &h,
        install_definition(
            vec![ContextRuleSignerInput::Delegated {
                address: delegate.clone(),
            }],
            vec![],
        ),
        "req-install-contract",
        false,
    )
    .await
    .unwrap();
    let (snapshot, _, _) = baselined_row(&h, "req-install-contract");
    assert_eq!(
        snapshot.signers,
        vec![SignerEntryV2 {
            id: 0,
            identity: SignerIdentityV2::DelegatedContract {
                contract: contract_id(&delegate)
            }
        }]
    );
}

// ── The simple-threshold policy entries ───────────────────────────────────────

/// A chain serving rule 1 with an External signer on verifier V and
/// `policies`, the simple-threshold policies P, P2 and P3, the
/// spending-limit policy Q, and `thresholds` for rule 1.
async fn threshold_policy_harness(
    policies: Vec<ScAddress>,
    thresholds: &[(ScAddress, u32)],
) -> Harness {
    let mut chain = Chain::default()
        .with_rule(1, rule_one_with_policies(policies))
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()))
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_wasm(&policy_p2(), KNOWN_WASM_HASH)
        .with_wasm(&policy_p3(), THRESHOLD_POLICY_WASM_HASHES[1])
        .with_entry(wasm_instance(&policy_q(), spending_limit_hash()));
    for (policy, threshold) in thresholds {
        chain = chain.with_threshold(policy, 1, *threshold);
    }
    Harness::new(chain).await
}

/// The state a policy change leaves on rule 1: the rule holds `policies` and
/// `thresholds` are rule 1's threshold values.
fn rule_one_after(policies: Vec<ScAddress>, thresholds: &[(ScAddress, u32)]) -> AfterSend {
    AfterSend {
        rules: vec![(1, rule_one_with_policies(policies))],
        thresholds: thresholds
            .iter()
            .map(|(policy, threshold)| (strkey(policy), 1, *threshold))
            .collect(),
    }
}

/// The `SaThresholdChangedV2` row written under `request_id`: its previous
/// threshold and resulting snapshot.
fn threshold_row(
    h: &Harness,
    request_id: &str,
) -> (Option<ThresholdObservation>, SignerSetSnapshotV2) {
    let rows: Vec<(Option<ThresholdObservation>, SignerSetSnapshotV2)> = rows_of(h, request_id)
        .into_iter()
        .filter_map(|entry| match entry.event_kind {
            EventKind::SaThresholdChangedV2 {
                rule_id: 1,
                previous_threshold,
                snapshot,
                ..
            } => Some((previous_threshold, snapshot)),
            _ => None,
        })
        .collect();
    assert_eq!(rows.len(), 1, "one threshold row for rule 1");
    rows.into_iter().next().unwrap()
}

fn observation(policy: &ScAddress, threshold: u32) -> Option<ThresholdObservation> {
    Some(ThresholdObservation {
        policy: contract_id(policy),
        threshold,
    })
}

/// Attaching the simple-threshold policy to a baselined rule records the
/// threshold row (no previous threshold, the resulting set with the
/// parameter's threshold on the policy) and the pins row under the rule's
/// lock. The policy row and the raw row follow, and the next `signers list`
/// matches.
#[tokio::test]
async fn a_threshold_attach_records_the_threshold_before_the_policy_row() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.after_send_state(&rule_one_after(vec![policy_p()], &[(policy_p(), 2)]));
    let policy_id = add_policy_with(&h, &policy_p(), threshold_param(2), "req-attach", false)
        .await
        .unwrap();
    assert_eq!(policy_id, 7);
    assert_eq!(
        row_kinds(&h.rows(), "req-attach"),
        vec![
            "sa_threshold_changed_v2",
            "sa_context_rule_pins_updated",
            "sa_policy_added",
            "sa_raw_invocation",
        ]
    );
    assert_eq!(raw_wire_code(&h, "req-attach"), "sa.ok");
    let (previous, resulting) = threshold_row(&h, "req-attach");
    assert_eq!(previous, None);
    assert_eq!(resulting.threshold, observation(&policy_p(), 2));
    assert_eq!(resulting, h.snapshot_of(1));

    let listed = h
        .manager
        .list_signers(smart_account(), 1, None, "req-attach-list".to_owned())
        .await
        .unwrap();
    assert_eq!(listed.baseline, PreviousBaseline::Matched);
}

/// Asserts a refusal before submission: nothing simulated as `function`,
/// nothing sent, and one raw row under `request_id` carrying the refusal.
fn assert_refused_before_submission(h: &Harness, err: &SaError, function: &str, request_id: &str) {
    assert!(!h.simulated(function), "{function} was simulated");
    assert_eq!(h.sends(), 0);
    assert_eq!(raw_wire_code(h, request_id), err.wire_code());
}

/// Attaching the simple-threshold policy to a rule that already has one
/// refuses before submission.
#[tokio::test]
async fn a_threshold_attach_on_a_rule_with_a_threshold_policy_refuses() {
    let h = threshold_policy_harness(vec![policy_p2()], &[(policy_p2(), 1)]).await;
    h.baseline_v2(1);
    let err = add_policy_with(
        &h,
        &policy_p(),
        threshold_param(2),
        "req-attach-second",
        false,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::ThresholdPolicyIdentificationFailed { rule_id: 1, .. }
        ),
        "{err:?}"
    );
    assert_refused_before_submission(&h, &err, "add_policy", "req-attach-second");
}

/// An attach of the simple-threshold policy on a rule whose signers changed
/// since its state row refuses before submission: the comparison writes the
/// diverged row and returns `sa.signer_set_diverged` without a transaction
/// hash.
#[tokio::test]
async fn a_threshold_attach_on_a_rule_whose_signers_changed_refuses() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    h.set_rule(
        1,
        &rule(
            1,
            vec![
                external_signer(&verifier_v(), &[0x11; 32]),
                delegated_account(0x13),
            ],
            vec![],
        ),
    );
    let err = add_policy_with(
        &h,
        &policy_p(),
        threshold_param(2),
        "req-attach-changed",
        false,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::SignerSetDiverged {
                rule_id: 1,
                tx_hash: None,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-attach-changed"),
        vec!["sa_signer_set_diverged", "sa_raw_invocation"]
    );
    assert_refused_before_submission(&h, &err, "add_policy", "req-attach-changed");
}

/// An attach of the simple-threshold policy whose install parameter is not
/// the threshold map refuses before submission.
#[tokio::test]
async fn a_threshold_attach_with_a_malformed_parameter_refuses() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    let err = add_policy_with(&h, &policy_p(), ScVal::Void, "req-attach-malformed", false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SaError::SimpleThresholdInstallRefused { .. }),
        "{err:?}"
    );
    assert_refused_before_submission(&h, &err, "add_policy", "req-attach-malformed");
}

/// A confirmed attach whose served threshold is not the parameter's refuses
/// with `sa.signer_set_diverged` carrying the hash; the pins row and the
/// policy row are still written, and no threshold row.
#[tokio::test]
async fn a_confirmed_threshold_attach_whose_threshold_differs_refuses_with_the_hash() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.after_send_state(&rule_one_after(vec![policy_p()], &[(policy_p(), 3)]));
    let err = add_policy_with(
        &h,
        &policy_p(),
        threshold_param(2),
        "req-attach-differs",
        false,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::SignerSetDiverged {
                rule_id: 1,
                tx_hash: Some(_),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-attach-differs"),
        vec![
            "sa_signer_set_diverged",
            "sa_context_rule_pins_updated",
            "sa_policy_added",
            "sa_raw_invocation",
        ]
    );
    assert_eq!(
        raw_wire_code(&h, "req-attach-differs"),
        "sa.signer_set_diverged"
    );
    assert_eq!(h.sends(), 1);
}

/// An attach of the simple-threshold policy whose simulated return value is
/// not a `u32` is refused before it is signed. Nothing is sent, no pin,
/// policy or threshold row is written, and the raw row carries the refusal.
#[tokio::test]
async fn a_threshold_attach_whose_simulated_return_is_not_a_u32_refuses_before_signing() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.set_simulated_return("add_policy", ScVal::Void);
    h.after_send_state(&rule_one_after(vec![policy_p()], &[(policy_p(), 2)]));
    let err = add_policy_with(
        &h,
        &policy_p(),
        threshold_param(2),
        "req-attach-void",
        false,
    )
    .await
    .unwrap_err();
    assert_return_shape_refusal(&err, "add_policy: expected ScVal::U32 return, got Void");
    assert!(h.simulated("add_policy"));
    assert_eq!(h.sends(), 0);
    assert_eq!(
        row_kinds(&h.rows(), "req-attach-void"),
        vec!["sa_raw_invocation"]
    );
    assert_eq!(raw_wire_code(&h, "req-attach-void"), "sa.deployment_failed");
}

/// An attach of the simple-threshold policy refuses a rule with no state
/// row and a rule whose state row is version 1, before submission.
#[tokio::test]
async fn a_threshold_attach_without_a_version_2_baseline_refuses() {
    let h = threshold_policy_harness(vec![], &[]).await;
    let err = add_policy_with(
        &h,
        &policy_p(),
        threshold_param(2),
        "req-attach-missing",
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.wire_code(), "sa.signer_set_missing_baseline", "{err:?}");
    assert_refused_before_submission(&h, &err, "add_policy", "req-attach-missing");

    let h = threshold_policy_harness(vec![policy_p2()], &[(policy_p2(), 1)]).await;
    h.baseline_v1(1);
    let err = add_policy_with(
        &h,
        &policy_p(),
        threshold_param(2),
        "req-attach-legacy",
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(err.wire_code(), "sa.signer_set_baseline_legacy", "{err:?}");
    assert_refused_before_submission(&h, &err, "add_policy", "req-attach-legacy");
}

/// An attach of a policy other than the simple-threshold policy whose
/// simulated return value is not a `u32` is refused before it is signed.
/// Nothing is sent, no pin or policy row is written, and the raw row
/// carries the refusal.
#[tokio::test]
async fn a_direct_attach_whose_simulated_return_is_not_a_u32_refuses_before_signing() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.set_simulated_return("add_policy", ScVal::Void);
    h.after_send(1, rule_one_with_policies(vec![policy_q()]));
    let err = add_policy_with(&h, &policy_q(), ScVal::Void, "req-direct-void", false)
        .await
        .unwrap_err();
    assert_return_shape_refusal(&err, "add_policy: expected ScVal::U32 return, got Void");
    assert!(h.simulated("add_policy"));
    assert_eq!(h.sends(), 0);
    assert_eq!(
        row_kinds(&h.rows(), "req-direct-void"),
        vec!["sa_raw_invocation"]
    );
    assert_eq!(raw_wire_code(&h, "req-direct-void"), "sa.deployment_failed");
    assert!(h.pins_updated_rows().is_empty());
}

/// A spending-limit attach records no signer-set state row and keeps its
/// pin rows, which precede the policy row.
#[tokio::test]
async fn a_spending_limit_attach_writes_no_state_row_and_keeps_its_pin_rows() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![first8(&webauthn_hash())], vec![], vec![], vec![]);
    h.after_send(1, rule_one_with_policies(vec![policy_q()]));
    add_policy_with(&h, &policy_q(), ScVal::Void, "req-attach-limit", false)
        .await
        .unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-attach-limit"),
        vec![
            "sa_context_rule_pins_updated",
            "sa_policy_added",
            "sa_raw_invocation",
        ]
    );
    assert_eq!(h.sends(), 1);
}

/// Without a signers manager the policy verbs refuse with
/// `sa.signers_manager_not_configured` naming the target rule, before any
/// RPC.
#[tokio::test]
async fn the_policy_verbs_without_a_signers_manager_refuse_before_any_rpc() {
    let h = threshold_policy_harness(vec![policy_p()], &[(policy_p(), 1)]).await;
    let manager = rule_manager_without_signers_manager(&h);
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let added = manager
        .add_policy(
            smart_account(),
            1,
            policy_q(),
            ScVal::Void,
            vec![ContextRuleId::new(0)],
            &signer,
            None,
            "req-add-no-manager".to_owned(),
            false,
            false,
        )
        .await
        .unwrap_err();
    let removed = manager
        .remove_policy(
            smart_account(),
            1,
            0,
            vec![ContextRuleId::new(0)],
            &signer,
            None,
            "req-remove-no-manager".to_owned(),
        )
        .await
        .unwrap_err();
    for err in [&added, &removed] {
        assert!(
            matches!(
                err,
                SaError::SignersManagerNotConfigured {
                    rule_id: Some(1),
                    ..
                }
            ),
            "{err:?}"
        );
    }
    assert!(h.primary_log.is_untouched());
    assert!(h.secondary_log.is_untouched());
}

/// Detaching the observed simple-threshold policy records the threshold row
/// (the observed threshold as previous, none as resulting) and the pins row
/// under the rule's lock. The policy row and the raw row follow, and the
/// next `signers list` matches.
#[tokio::test]
async fn a_threshold_detach_records_the_cleared_threshold_before_the_policy_row() {
    let h = threshold_policy_harness(vec![policy_p()], &[(policy_p(), 2)]).await;
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![]));
    remove_policy(&h, 0, "req-detach").await.unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-detach"),
        vec![
            "sa_threshold_changed_v2",
            "sa_context_rule_pins_updated",
            "sa_policy_removed",
            "sa_raw_invocation",
        ]
    );
    assert_eq!(raw_wire_code(&h, "req-detach"), "sa.ok");
    let (previous, resulting) = threshold_row(&h, "req-detach");
    assert_eq!(previous, observation(&policy_p(), 2));
    assert_eq!(resulting.threshold, None);
    assert_eq!(resulting, h.snapshot_of(1));

    let listed = h
        .manager
        .list_signers(smart_account(), 1, None, "req-detach-list".to_owned())
        .await
        .unwrap();
    assert_eq!(listed.baseline, PreviousBaseline::Matched);
}

/// A confirmed detach whose served state keeps the threshold refuses with
/// `sa.signer_set_diverged` carrying the hash; the pins row and the policy
/// row are written, and no threshold row.
#[tokio::test]
async fn a_confirmed_threshold_detach_whose_threshold_stays_refuses_with_the_hash() {
    let h = threshold_policy_harness(vec![policy_p()], &[(policy_p(), 2)]).await;
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    h.after_send(1, rule_one_with_policies(vec![policy_p()]));
    let err = remove_policy(&h, 0, "req-detach-stays").await.unwrap_err();
    assert!(
        matches!(
            err,
            SaError::SignerSetDiverged {
                rule_id: 1,
                tx_hash: Some(_),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-detach-stays"),
        vec![
            "sa_signer_set_diverged",
            "sa_context_rule_pins_updated",
            "sa_policy_removed",
            "sa_raw_invocation",
        ]
    );
    assert_eq!(h.sends(), 1);
}

/// A removal whose policy identifies as the simple-threshold policy at the
/// path observation and not at the rule's observation before it refuses
/// before submission: the compared rule has no simple-threshold policy to
/// detach. The policy's executable changes after the comparison's two
/// reads, one per endpoint of the shared chain.
#[tokio::test]
async fn a_detach_whose_policy_starts_identifying_after_the_comparison_refuses() {
    let chain = Chain::default()
        .with_rule(1, rule_one_with_policies(vec![policy_p()]))
        .with_entry(wasm_instance(&verifier_v(), webauthn_hash()))
        .with_entry(wasm_instance(&policy_p(), [0xab; 32]))
        .entry_after_reads(
            rpc_mock_helpers::contract_instance_key_xdr(&policy_p()),
            2,
            wasm_instance(&policy_p(), KNOWN_WASM_HASH),
        );
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    let err = remove_policy(&h, 0, "req-detach-identity")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::ThresholdPolicyIdentificationFailed { rule_id: 1, .. }
        ),
        "{err:?}"
    );
    assert_refused_before_submission(&h, &err, "remove_policy", "req-detach-identity");
    assert_eq!(h.primary_instance_reads(&policy_p()), 2);
}

/// A rule with two simple-threshold policies cannot be observed, and the
/// detach of one of them is accepted: the row records no previous threshold
/// and the remaining policy's threshold; the next `signers list` matches.
#[tokio::test]
async fn a_rule_with_two_threshold_policies_detaches_one_of_them() {
    let h = threshold_policy_harness(
        vec![policy_p(), policy_p2()],
        &[(policy_p(), 1), (policy_p2(), 2)],
    )
    .await;
    h.baseline_v2(1);
    let err = h
        .manager
        .list_signers(smart_account(), 1, None, "req-two-list".to_owned())
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.threshold_policy_identification_failed");

    h.after_send(1, rule_one_with_policies(vec![policy_p2()]));
    remove_policy(&h, 0, "req-repair").await.unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-repair"),
        vec![
            "sa_threshold_changed_v2",
            "sa_policy_removed",
            "sa_raw_invocation",
        ]
    );
    let (previous, resulting) = threshold_row(&h, "req-repair");
    assert_eq!(previous, None);
    assert_eq!(resulting.threshold, observation(&policy_p2(), 2));
    assert_eq!(resulting, h.snapshot_of(1));
    assert_eq!(h.sends(), 1);

    let listed = h
        .manager
        .list_signers(smart_account(), 1, None, "req-repair-list".to_owned())
        .await
        .unwrap();
    assert_eq!(listed.baseline, PreviousBaseline::Matched);
}

/// The detach of one of two simple-threshold policies from a rule whose
/// signers changed since its state row refuses before submission with
/// `sa.signer_set_diverged` without a hash, and writes one diverged row.
#[tokio::test]
async fn a_repair_detach_on_a_rule_whose_signers_changed_refuses_before_submission() {
    let h = threshold_policy_harness(
        vec![policy_p(), policy_p2()],
        &[(policy_p(), 1), (policy_p2(), 2)],
    )
    .await;
    h.baseline_v2(1);
    h.set_rule(
        1,
        &rule(
            1,
            vec![
                external_signer(&verifier_v(), &[0x11; 32]),
                delegated_account(0x13),
            ],
            vec![policy_p(), policy_p2()],
        ),
    );
    let err = remove_policy(&h, 0, "req-repair-signers")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::SignerSetDiverged {
                rule_id: 1,
                tx_hash: None,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-repair-signers"),
        vec!["sa_signer_set_diverged", "sa_raw_invocation"]
    );
    assert_refused_before_submission(&h, &err, "remove_policy", "req-repair-signers");
}

/// The detach of one of two simple-threshold policies whose confirmed state
/// is not the remaining policy's threshold refuses with
/// `sa.signer_set_diverged` carrying the hash, and writes no threshold row.
#[tokio::test]
async fn a_repair_detach_whose_confirmed_state_is_not_the_remaining_policy_refuses() {
    let h = threshold_policy_harness(
        vec![policy_p(), policy_p2()],
        &[(policy_p(), 1), (policy_p2(), 2)],
    )
    .await;
    h.baseline_v2(1);
    h.after_send(1, rule_one_with_policies(vec![]));
    let err = remove_policy(&h, 0, "req-repair-wrong").await.unwrap_err();
    assert!(
        matches!(
            err,
            SaError::SignerSetDiverged {
                rule_id: 1,
                tx_hash: Some(_),
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        row_kinds(&h.rows(), "req-repair-wrong"),
        vec![
            "sa_signer_set_diverged",
            "sa_policy_removed",
            "sa_raw_invocation",
        ]
    );
    assert_eq!(h.sends(), 1);
}

/// A rule with three simple-threshold policies refuses the detach of one of
/// them before submission: one detach cannot leave it observable.
#[tokio::test]
async fn three_threshold_policies_refuse_the_detach() {
    let h = threshold_policy_harness(
        vec![policy_p(), policy_p2(), policy_p3()],
        &[(policy_p(), 1), (policy_p2(), 2), (policy_p3(), 3)],
    )
    .await;
    h.baseline_v2(1);
    let err = remove_policy(&h, 0, "req-three").await.unwrap_err();
    match &err {
        SaError::ThresholdPolicyIdentificationFailed {
            rule_id: 1,
            observed_wasm_hashes_summary,
            ..
        } => assert_eq!(observed_wasm_hashes_summary.count, 3),
        other => panic!("expected ThresholdPolicyIdentificationFailed; got {other:?}"),
    }
    assert_refused_before_submission(&h, &err, "remove_policy", "req-three");
}

/// A removal from a rule that has no state row refuses with
/// `sa.signer_set_missing_baseline` before any RPC. A removal of a policy id
/// a baselined rule does not hold refuses after the comparison. Both refuse
/// before submission.
#[tokio::test]
async fn a_missing_rule_and_an_unattached_policy_id_refuse_the_removal() {
    let h = threshold_policy_harness(vec![policy_p()], &[(policy_p(), 1)]).await;
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let missing_rule = h
        .rule_manager()
        .remove_policy(
            smart_account(),
            9,
            0,
            vec![ContextRuleId::new(0)],
            &signer,
            None,
            "req-remove-missing-rule".to_owned(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            missing_rule,
            SaError::SignerSetMissingBaseline { rule_id: 9, .. }
        ),
        "{missing_rule:?}"
    );
    assert_refused_before_submission(
        &h,
        &missing_rule,
        "remove_policy",
        "req-remove-missing-rule",
    );
    assert!(h.primary_log.is_untouched());

    h.baseline_v2(1);
    let missing_policy = remove_policy(&h, 5, "req-remove-missing-policy")
        .await
        .unwrap_err();
    match &missing_policy {
        SaError::DeploymentFailed {
            phase,
            redacted_reason,
        } => {
            assert_eq!(*phase, "simulate");
            assert_eq!(
                redacted_reason,
                "remove_policy: policy 5 is not attached to rule 1"
            );
        }
        other => panic!("expected DeploymentFailed; got {other:?}"),
    }
    assert_refused_before_submission(
        &h,
        &missing_policy,
        "remove_policy",
        "req-remove-missing-policy",
    );
}

/// A secondary one ledger behind for its first read after the install
/// confirms does not hold the new rule yet: the failed read is behind the
/// confirmation, so it is read again after a pause, and the baseline is
/// written from the caught-up reads.
#[tokio::test]
async fn an_install_whose_secondary_lags_one_read_is_baselined() {
    let h = Harness::new(install_chain()).await;
    h.after_send_state(&installed(vec![delegated_account(0x13)], vec![], &[]));
    h.secondary_ledgers
        .queued
        .lock()
        .unwrap()
        .push_back(PRE_SEND_LEDGER);
    install(
        &h,
        install_definition(vec![account_input(0x13)], vec![]),
        "req-install-lag",
        false,
    )
    .await
    .unwrap();
    let (snapshot, reason, ledger) = baselined_row(&h, "req-install-lag");
    assert_eq!(snapshot, h.snapshot_of(1));
    assert_eq!(reason, BaselineReason::ConfirmedInstall);
    assert_eq!(ledger, CONFIRMATION_LEDGER);
    assert_eq!(
        h.secondary_log.simulated(),
        vec!["get_context_rule", "get_context_rule"],
        "the behind read is repeated"
    );
}

/// A secondary whose threshold read after a confirmed attach is one ledger
/// behind does not hold the new threshold yet: the read is behind the
/// confirmation, so the endpoint's observation is repeated after a pause,
/// and the threshold row is written from the caught-up reads.
#[tokio::test]
async fn a_threshold_attach_whose_secondary_threshold_read_lags_is_recorded() {
    let h = threshold_policy_harness(vec![], &[]).await;
    h.baseline_v2(1);
    h.after_send_state(&rule_one_after(vec![policy_p()], &[(policy_p(), 2)]));
    h.secondary_ledgers
        .queued
        .lock()
        .unwrap()
        .extend([CONFIRMATION_LEDGER, PRE_SEND_LEDGER]);
    add_policy_with(&h, &policy_p(), threshold_param(2), "req-attach-lag", false)
        .await
        .unwrap();
    let (previous, resulting) = threshold_row(&h, "req-attach-lag");
    assert_eq!(previous, None);
    assert_eq!(resulting.threshold, observation(&policy_p(), 2));
    let secondary = h.secondary_log.simulated();
    assert_eq!(
        secondary[secondary.len() - 4..],
        [
            "get_context_rule",
            "get_threshold",
            "get_context_rule",
            "get_threshold"
        ],
        "the behind threshold read repeats the endpoint's observation: {secondary:?}"
    );
}

// ── The signer-set check in the submit path ───────────────────────────────────

/// Rule 1 with a delegated signer and rule 2 with an External signer on
/// verifier V, neither with a policy.
fn two_rule_chain() -> Chain {
    Chain::default()
        .with_rule(1, rule(1, vec![delegated_account(0x31)], vec![]))
        .with_rule(
            2,
            rule(2, vec![external_signer(&verifier_v(), &[0x12; 32])], vec![]),
        )
        .with_wasm(&verifier_v(), webauthn_hash())
}

/// Rule 2 of [`two_rule_chain`] with its External signer's key changed, as a
/// change made outside the wallet.
fn rule_two_with_another_key() -> ScVal {
    rule(2, vec![external_signer(&verifier_v(), &[0x99; 32])], vec![])
}

/// The diverged rows written under `request_id`, as `(rule id, request id)`.
fn diverged_rows(h: &Harness, request_id: &str) -> Vec<u32> {
    rows_of(h, request_id)
        .into_iter()
        .filter_map(|entry| match entry.event_kind {
            EventKind::SaSignerSetDiverged { rule_id, .. } => Some(rule_id),
            _ => None,
        })
        .collect()
}

/// Every auth rule of a submission is read and compared, each step in
/// ascending rule order whatever the submission's order: the primary reads
/// each rule for its pin check, then each rule for its comparison; the
/// secondary reads each rule only for its comparison. A divergence on the
/// second rule alone refuses with that rule's diverged row and sends
/// nothing.
#[tokio::test]
async fn every_distinct_auth_rule_is_read_and_compared() {
    let h = Harness::new(two_rule_chain()).await;
    h.baseline_v2(1);
    h.baseline_v2(2);

    h.submit_invocation("pair", &[2, 1], Some("req-two-rules"), None)
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
    assert_eq!(h.primary_log.rule_reads(), vec![1, 2, 1, 2]);
    assert_eq!(h.secondary_log.rule_reads(), vec![1, 2]);

    let h = Harness::new(two_rule_chain()).await;
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.set_rule(2, &rule_two_with_another_key());
    let err = h
        .submit_invocation("pair", &[1, 2], Some("req-rule-two-diverged"), None)
        .await
        .unwrap_err();
    match &err {
        SaError::SignerSetDiverged {
            rule_id,
            tx_hash,
            request_id,
            ..
        } => {
            assert_eq!(*rule_id, 2);
            assert_eq!(*tx_hash, None);
            assert_eq!(request_id, "req-rule-two-diverged");
        }
        other => panic!("expected SignerSetDiverged; got {other:?}"),
    }
    assert_eq!(err.wire_code(), "sa.signer_set_diverged");
    assert_eq!(diverged_rows(&h, "req-rule-two-diverged"), vec![2]);
    assert!(!h.simulated("pair"));
    assert_eq!(h.sends(), 0);
}

/// A rule without a state row refuses with `sa.signer_set_missing_baseline`
/// before any RPC: the rule is never fetched, nothing is simulated or sent,
/// and no baseline row is written.
#[tokio::test]
async fn a_missing_baseline_never_signs_or_baselines() {
    let h = Harness::new(two_rule_chain()).await;
    let err = h.submit(&[1], Some("req-no-baseline")).await.unwrap_err();
    match &err {
        SaError::SignerSetMissingBaseline {
            rule_id,
            request_id,
            ..
        } => {
            assert_eq!(*rule_id, 1);
            assert_eq!(request_id, "req-no-baseline");
        }
        other => panic!("expected SignerSetMissingBaseline; got {other:?}"),
    }
    assert_eq!(err.wire_code(), "sa.signer_set_missing_baseline");
    assert!(h.primary_log.simulated().is_empty());
    assert!(h.secondary_log.is_untouched());
    assert_eq!(h.sends(), 0);
    assert!(
        !h.rows().iter().any(|e| matches!(
            e.event_kind,
            EventKind::SaSignerSetBaselined { .. } | EventKind::SaSignerSetBaselinedV2 { .. }
        )),
        "the refusal records no baseline"
    );
}

/// A version-1 row on an auth rule is compared through the observation's
/// version-1 projection, and the submission signs.
#[tokio::test]
async fn a_version_1_row_on_an_auth_rule_compares_and_signs() {
    let h = Harness::new(verb_chain()).await;
    h.baseline_v1(1);
    h.submit(&[1], Some("req-v1-auth-rule")).await.unwrap();
    assert_eq!(h.sends(), 1);
    assert_eq!(h.secondary_log.rule_reads(), vec![1]);
    assert!(
        h.secondary_log
            .simulated()
            .contains(&"get_threshold".to_owned()),
        "the version-1 comparison reads the threshold"
    );
    assert!(diverged_rows(&h, "req-v1-auth-rule").is_empty());
}

/// A signer whose key changed outside the wallet refuses with
/// `sa.signer_set_diverged`, writes the diverged row under the caller's
/// request id, and sends nothing.
#[tokio::test]
async fn an_identity_change_on_an_auth_rule_refuses_with_the_diverged_row() {
    let h = Harness::new(two_rule_chain()).await;
    h.baseline_v2(2);
    h.set_rule(2, &rule_two_with_another_key());
    let err = h.submit(&[2], Some("req-identity")).await.unwrap_err();
    assert!(
        matches!(
            err,
            SaError::SignerSetDiverged {
                rule_id: 2,
                tx_hash: None,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(diverged_rows(&h, "req-identity"), vec![2]);
    assert_eq!(
        row_kinds(&h.rows(), "req-identity"),
        vec!["sa_signer_set_diverged"]
    );
    assert!(!h.simulated("noop"));
    assert_eq!(h.sends(), 0);
}

/// Endpoints that disagree on an auth rule refuse with
/// `network.rpc_divergence`, and an audit writer poisoned before the
/// submission refuses with `sa.audit_log`; each sends nothing, and the two
/// identities differ.
#[tokio::test]
async fn rpc_disagreement_and_a_poisoned_writer_refuse_distinctly() {
    let mut secondary = two_rule_chain();
    secondary.rules.insert(2, rule_two_with_another_key());
    let h = Harness::with_secondary(two_rule_chain(), secondary).await;
    h.baseline_v2(2);
    let divergence = h.submit(&[2], Some("req-endpoints")).await.unwrap_err();
    assert!(
        matches!(
            divergence,
            SaError::NetworkRpcDivergence {
                rule_id: Some(2),
                ..
            }
        ),
        "{divergence:?}"
    );
    assert_eq!(divergence.wire_code(), "network.rpc_divergence");
    assert!(diverged_rows(&h, "req-endpoints").is_empty());
    assert_eq!(h.sends(), 0);

    let h = Harness::new(two_rule_chain()).await;
    h.baseline_v2(2);
    h.poison_audit_writer_now();
    let corruption = h.submit(&[2], Some("req-poisoned")).await.unwrap_err();
    assert!(matches!(corruption, SaError::AuditLog(_)), "{corruption:?}");
    assert_eq!(corruption.wire_code(), "sa.audit_log");
    assert!(h.primary_log.simulated().is_empty());
    assert_eq!(h.sends(), 0);
    assert_ne!(divergence.wire_code(), corruption.wire_code());
}

/// The comparison shares the pre-submit deadline: a `get_threshold` answer
/// slower than the budget elapses at stage `signer_set_compare`, after the
/// pin check read the rule, and nothing is sent. The read's own timeout (the
/// signers manager's) is longer than its delay, so the budget ends first.
#[tokio::test]
async fn a_slow_comparison_elapses_at_signer_set_compare() {
    let h = Harness::with_budget(verb_chain(), Duration::from_secs(1)).await;
    h.baseline_v2(1);
    h.delay_simulated("get_threshold", Duration::from_secs(5));
    let err = h.submit(&[1], Some("req-slow-compare")).await.unwrap_err();
    match &err {
        SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } => {
            assert_eq!(*stage, "signer_set_compare");
            assert_eq!(
                redacted_reason,
                "signer_set_compare exceeded collective pre-submit budget of 1s"
            );
        }
        other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
    }
    assert_eq!(
        h.primary_log.rule_reads()[0],
        1,
        "the pin check read the rule"
    );
    assert!(!h.simulated("noop"));
    assert_eq!(h.sends(), 0);
}

/// A budget that is spent by the time the baseline read returns elapses at
/// stage `baseline_read`, before any RPC.
#[tokio::test]
async fn a_spent_budget_elapses_at_baseline_read() {
    let h = Harness::with_budget(verb_chain(), Duration::ZERO).await;
    h.baseline_v2(1);
    let err = h.submit(&[1], Some("req-zero-budget")).await.unwrap_err();
    match &err {
        SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } => {
            assert_eq!(*stage, "baseline_read");
            assert_eq!(
                redacted_reason,
                "baseline_read exceeded collective pre-submit budget of 0s"
            );
        }
        other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
    }
    assert!(h.primary_log.simulated().is_empty());
    assert!(h.secondary_log.is_untouched());
    assert_eq!(h.sends(), 0);
}

/// A rule whose lock another holder keeps refuses at stage `rule_lock`
/// once the pre-submit budget ends, before any RPC; once the holder drops
/// the lock, the same submission signs.
#[tokio::test]
async fn a_held_rule_lock_refuses_at_rule_lock_until_it_is_released() {
    let h = Harness::with_budget(two_rule_chain(), Duration::from_secs(1)).await;
    h.baseline_v2(1);
    let holder = stellar_agent_smart_account::test_helpers::hold_rule_lock(
        &h.manager,
        &strkey(&smart_account()),
        1,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let err = h.submit(&[1], Some("req-held-lock")).await.unwrap_err();
    match &err {
        SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } => {
            assert_eq!(*stage, "rule_lock");
            assert_eq!(
                redacted_reason,
                "rule 1: the rule lock was not acquired within its budget"
            );
        }
        other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
    }
    assert!(h.primary_log.simulated().is_empty());
    assert_eq!(h.sends(), 0);

    drop(holder);
    h.submit(&[1], Some("req-released-lock")).await.unwrap();
    assert_eq!(h.sends(), 1);
}

/// The submit path releases the locks it acquired before the send: while a
/// sent submission stalls in its confirmation poll, a `signers list` on the
/// same rule takes the lock and completes first.
#[tokio::test]
async fn the_submit_path_releases_its_locks_before_the_send() {
    let h = Harness::new(two_rule_chain()).await;
    h.baseline_v2(1);
    h.delay_poll(Duration::from_secs(2));

    let submitted = async {
        h.submit(&[1], Some("req-drop-point")).await.unwrap();
        tokio::time::Instant::now()
    };
    let listed = async {
        while h.sends() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        h.manager
            .list_signers(smart_account(), 1, None, "req-list-during-poll".to_owned())
            .await
            .unwrap();
        tokio::time::Instant::now()
    };
    let (submitted_at, listed_at) = tokio::join!(submitted, listed);
    assert!(
        listed_at < submitted_at,
        "the list completed while the submission was still polling"
    );
}

/// When faults coexist, a missing baseline on one rule refuses before a
/// drifted verifier on another, and a drifted verifier on one rule refuses
/// before a signer-set divergence on another.
#[tokio::test]
async fn coexisting_faults_refuse_in_the_check_order() {
    let h = Harness::new(two_rule_chain()).await;
    h.baseline_v2(2);
    h.pin_created(2, vec![FOREIGN_FIRST8.to_owned()], vec![], vec![], vec![]);
    let err = h
        .submit_invocation("pair", &[1, 2], Some("req-baseline-first"), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SaError::SignerSetMissingBaseline { rule_id: 1, .. }),
        "{err:?}"
    );
    assert!(h.primary_log.simulated().is_empty());
    assert!(
        !h.rows()
            .iter()
            .any(|e| matches!(e.event_kind, EventKind::SaVerifierHashDrift { .. }))
    );

    let chain = two_rule_chain().with_rule(
        1,
        rule(1, vec![external_signer(&verifier_v(), &[0x11; 32])], vec![]),
    );
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.pin_created(1, vec![FOREIGN_FIRST8.to_owned()], vec![], vec![], vec![]);
    h.set_rule(2, &rule_two_with_another_key());
    let err = h
        .submit_invocation("pair", &[1, 2], Some("req-drift-first"), None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SaError::VerifierHashDrift { rule_id: 1, .. }),
        "{err:?}"
    );
    assert!(diverged_rows(&h, "req-drift-first").is_empty());
    assert_eq!(h.sends(), 0);
}

/// Rule 0 beside rule 1 is neither locked nor compared: a held lock on rule
/// 0 does not stop the submission, and only rule 1 is read.
#[tokio::test]
async fn rule_zero_beside_rule_one_checks_rule_one_only() {
    let chain = two_rule_chain().with_rule(0, rule(0, vec![delegated_signer()], vec![]));
    let h = Harness::with_timeout(chain, Duration::from_secs(2)).await;
    h.baseline_v2(1);
    let rule_zero = stellar_agent_smart_account::test_helpers::hold_rule_lock(
        &h.manager,
        &strkey(&smart_account()),
        0,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    h.submit_invocation("pair", &[0, 1], Some("req-rule-zero"), None)
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
    assert_eq!(h.primary_log.rule_reads(), vec![1, 1]);
    assert_eq!(h.secondary_log.rule_reads(), vec![1]);
    drop(rule_zero);
}

/// A rule verb submitting through the rule manager meets the same deadline:
/// an expiry update whose auth rule's comparison is slower than the budget
/// elapses at stage `signer_set_compare`, writes its raw row with that code
/// and sends nothing. The read's own timeout is longer than its delay, so
/// the budget ends first.
#[tokio::test]
async fn a_rule_verbs_slow_comparison_elapses_at_signer_set_compare() {
    let h = Harness::with_budget(verb_chain(), Duration::from_secs(1)).await;
    h.baseline_v2(1);
    h.delay_simulated("get_threshold", Duration::from_secs(5));
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let err = h
        .rule_manager()
        .update_valid_until(
            smart_account(),
            1,
            Some(5_000),
            vec![ContextRuleId::new(1)],
            &signer,
            None,
            "req-wrapper-elapse".to_owned(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::AuthEntryConstructionFailed {
                stage: "signer_set_compare",
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(
        raw_wire_code(&h, "req-wrapper-elapse"),
        "sa.auth_entry_construction_failed"
    );
    assert!(!h.simulated("update_context_rule_valid_until"));
    assert_eq!(h.sends(), 0);
}

/// Counts the submissions recorded as sent and settled.
#[derive(Default)]
struct CountingRecorder {
    pre_sends: AtomicUsize,
    outcomes: AtomicUsize,
}

#[async_trait::async_trait]
impl SubmissionRecorder for CountingRecorder {
    async fn pre_send(
        &self,
        _intent: &stellar_agent_network::SubmissionIntent,
    ) -> Result<(), stellar_agent_core::WalletError> {
        self.pre_sends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn outcome(
        &self,
        _intent: &stellar_agent_network::SubmissionIntent,
        _outcome: &stellar_agent_network::SubmissionOutcome,
    ) {
        self.outcomes.fetch_add(1, Ordering::SeqCst);
    }
}

/// A missing-baseline refusal, a divergence refusal and a drift refusal
/// each leave no submission record; a submission that signs leaves one.
#[tokio::test]
async fn a_refused_submission_leaves_no_record_and_a_sent_one_does() {
    let recorder = CountingRecorder::default();

    let h = Harness::new(two_rule_chain()).await;
    let missing = h
        .submit_invocation("noop", &[1], Some("req-record-missing"), Some(&recorder))
        .await
        .unwrap_err();
    assert_eq!(missing.wire_code(), "sa.signer_set_missing_baseline");

    h.baseline_v2(2);
    h.set_rule(2, &rule_two_with_another_key());
    let diverged = h
        .submit_invocation("noop", &[2], Some("req-record-diverged"), Some(&recorder))
        .await
        .unwrap_err();
    assert_eq!(diverged.wire_code(), "sa.signer_set_diverged");

    let h = Harness::new(chain_with_rule_one(webauthn_hash())).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![FOREIGN_FIRST8.to_owned()], vec![], vec![], vec![]);
    let drift = h
        .submit_invocation("noop", &[1], Some("req-record-drift"), Some(&recorder))
        .await
        .unwrap_err();
    assert_eq!(drift.wire_code(), "sa.verifier_hash_drift");
    assert_eq!(recorder.pre_sends.load(Ordering::SeqCst), 0);
    assert_eq!(recorder.outcomes.load(Ordering::SeqCst), 0);

    let h = Harness::new(two_rule_chain()).await;
    h.baseline_v2(1);
    h.submit_invocation("noop", &[1], Some("req-record-sent"), Some(&recorder))
        .await
        .unwrap();
    assert_eq!(recorder.pre_sends.load(Ordering::SeqCst), 1);
    assert_eq!(recorder.outcomes.load(Ordering::SeqCst), 1);
}

// ── Auth rules a holder lends uncompared ──────────────────────────────────────

/// Rules 1 and 2 of [`two_rule_chain`], with P served as the
/// simple-threshold policy for an attach to rule 1.
fn attach_chain() -> Chain {
    two_rule_chain().with_wasm(&policy_p(), KNOWN_WASM_HASH)
}

/// The state a confirmed attach of P to rule 1 of [`attach_chain`] at
/// threshold 1 leaves on chain.
fn after_attach_on_rule_one() -> AfterSend {
    AfterSend {
        rules: vec![(1, rule(1, vec![delegated_account(0x31)], vec![policy_p()]))],
        thresholds: vec![(strkey(&policy_p()), 1, 1)],
    }
}

/// Attaches the simple-threshold policy P to rule 1 at threshold 1,
/// authorized under `auth_rule_ids`.
async fn attach_threshold_under(
    h: &Harness,
    auth_rule_ids: &[u32],
    request_id: &str,
) -> Result<u32, SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.rule_manager()
        .add_policy(
            smart_account(),
            1,
            policy_p(),
            threshold_param(1),
            auth_rule_ids
                .iter()
                .copied()
                .map(ContextRuleId::new)
                .collect(),
            &signer,
            None,
            request_id.to_owned(),
            false,
            false,
        )
        .await
}

/// A threshold attach to rule 1 authorized under rule 2 compares rule 1
/// itself and lends rule 2 to the submission uncompared; the submission
/// reads rule 2's state row, and a rule 2 without one refuses with
/// `sa.signer_set_missing_baseline` naming rule 2. Nothing is sent, and the
/// only rule read is the entry's comparison of rule 1.
#[tokio::test]
async fn an_attach_under_an_unbaselined_auth_rule_refuses_missing_baseline() {
    let h = Harness::new(attach_chain()).await;
    h.baseline_v2(1);
    h.after_send_state(&after_attach_on_rule_one());

    let err = attach_threshold_under(&h, &[2], "req-attach-auth-unbaselined")
        .await
        .unwrap_err();
    match &err {
        SaError::SignerSetMissingBaseline {
            rule_id,
            request_id,
            ..
        } => {
            assert_eq!(*rule_id, 2);
            assert_eq!(request_id, "req-attach-auth-unbaselined");
        }
        other => panic!("expected SignerSetMissingBaseline; got {other:?}"),
    }
    assert_eq!(h.primary_log.rule_reads(), vec![1]);
    assert_eq!(h.secondary_log.rule_reads(), vec![1]);
    assert!(!h.simulated("add_policy"));
    assert_eq!(h.sends(), 0);
}

/// The same attach with rule 2's signers changed since its state row was
/// recorded refuses with `sa.signer_set_diverged` naming rule 2, writes the
/// diverged row under the call's request id, and sends nothing.
#[tokio::test]
async fn an_attach_under_a_diverged_auth_rule_refuses_with_the_diverged_row() {
    let h = Harness::new(attach_chain()).await;
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.set_rule(2, &rule_two_with_another_key());
    h.after_send_state(&after_attach_on_rule_one());

    let err = attach_threshold_under(&h, &[2], "req-attach-auth-diverged")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            SaError::SignerSetDiverged {
                rule_id: 2,
                tx_hash: None,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(diverged_rows(&h, "req-attach-auth-diverged"), vec![2]);
    assert!(!h.simulated("add_policy"));
    assert_eq!(h.sends(), 0);
}

/// With both rules baselined the attach signs: the entry compares rule 1,
/// the submission compares rule 2, and the threshold row records the
/// attach.
#[tokio::test]
async fn an_attach_under_a_baselined_auth_rule_compares_it_and_signs() {
    let h = Harness::new(attach_chain()).await;
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.after_send_state(&after_attach_on_rule_one());

    attach_threshold_under(&h, &[2], "req-attach-auth-signs")
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
    let secondary = h.secondary_log.rule_reads();
    assert!(
        secondary.contains(&1) && secondary.contains(&2),
        "both rules were compared through the secondary: {secondary:?}"
    );
    assert!(
        row_kinds(&h.rows(), "req-attach-auth-signs")
            .contains(&"sa_threshold_changed_v2".to_owned()),
        "{:?}",
        row_kinds(&h.rows(), "req-attach-auth-signs")
    );
}

/// The spending-limit policy's stored data, as `get_spending_limit_data`
/// returns it: `spending_limit`, `period_ledgers`, an empty history and no
/// spend.
fn spending_limit_data(spending_limit: i128, period_ledgers: u32) -> ScVal {
    let i128_val = |value: i128| {
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "canonical i128 split into its high and low 64 bits"
        )]
        ScVal::I128(Int128Parts {
            hi: (value >> 64) as i64,
            lo: value as u64,
        })
    };
    let entry = |key: &str, val: ScVal| ScMapEntry {
        key: symbol(key),
        val,
    };
    ScVal::Map(Some(ScMap(
        vec![
            entry("cached_total_spent", i128_val(0)),
            entry("period_ledgers", ScVal::U32(period_ledgers)),
            entry("spending_history", scvec(vec![])),
            entry("spending_limit", i128_val(spending_limit)),
        ]
        .try_into()
        .unwrap(),
    )))
}

/// Rule 1 holding the spending-limit policy Q beside [`two_rule_chain`]'s
/// rule 2, with Q's stored data served.
fn spending_limit_chain() -> Chain {
    two_rule_chain()
        .with_rule(1, rule(1, vec![delegated_account(0x31)], vec![policy_q()]))
        .with_entry(wasm_instance(&policy_q(), spending_limit_hash()))
}

/// Retunes rule 1's spending limit, authorized under `auth_rule_ids`.
async fn set_spending_limit_under(
    h: &Harness,
    auth_rule_ids: &[u32],
    request_id: &str,
) -> Result<(), SaError> {
    set_spending_limit_of(h, 1, auth_rule_ids, request_id).await
}

/// Retunes the spending limit of rule `target_rule_id`, authorized under
/// `admin_rule_ids`.
async fn set_spending_limit_of(
    h: &Harness,
    target_rule_id: u32,
    admin_rule_ids: &[u32],
    request_id: &str,
) -> Result<(), SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    let admin_rule_ids: Vec<ContextRuleId> = admin_rule_ids
        .iter()
        .copied()
        .map(ContextRuleId::new)
        .collect();
    h.manager
        .set_spending_limit(
            smart_account(),
            target_rule_id,
            &admin_rule_ids,
            2_000,
            &signer,
            request_id.to_owned(),
        )
        .await
}

/// A spending-limit retune of rule 1 authorized under admin rule 2 lends
/// rule 2 to the submission uncompared; a rule 2 without a state row
/// refuses with `sa.signer_set_missing_baseline` naming rule 2, and nothing
/// is sent.
#[tokio::test]
async fn a_spending_limit_retune_under_an_unbaselined_admin_rule_refuses() {
    let h = Harness::new(spending_limit_chain()).await;
    h.set_simulated_return("get_spending_limit_data", spending_limit_data(1_000, 100));

    let err = set_spending_limit_under(&h, &[2], "req-retune-admin-unbaselined")
        .await
        .unwrap_err();
    assert!(
        matches!(err, SaError::SignerSetMissingBaseline { rule_id: 2, .. }),
        "{err:?}"
    );
    assert!(
        !h.primary_log.rule_reads().contains(&2),
        "the admin rule is refused before any read of it"
    );
    assert!(!h.simulated("execute"));
    assert_eq!(h.sends(), 0);
}

/// The retune locks its admin rule beside its target: while another holder
/// keeps rule 2's lock, the retune refuses at stage `rule_lock` naming rule
/// 2 once the manager's timeout ends, before any RPC.
#[tokio::test]
async fn a_spending_limit_retune_waits_for_its_admin_rules_lock() {
    let h = Harness::with_timeout(spending_limit_chain(), Duration::from_millis(300)).await;
    h.set_simulated_return("get_spending_limit_data", spending_limit_data(1_000, 100));
    let holder = stellar_agent_smart_account::test_helpers::hold_rule_lock(
        &h.manager,
        &strkey(&smart_account()),
        2,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let err = set_spending_limit_under(&h, &[2], "req-retune-admin-locked")
        .await
        .unwrap_err();
    match &err {
        SaError::AuthEntryConstructionFailed {
            stage,
            redacted_reason,
        } => {
            assert_eq!(*stage, "rule_lock");
            assert_eq!(
                redacted_reason,
                "rule 2: the rule lock was not acquired within its budget"
            );
        }
        other => panic!("expected AuthEntryConstructionFailed; got {other:?}"),
    }
    assert!(h.primary_log.simulated().is_empty());
    assert_eq!(h.sends(), 0);
    drop(holder);
}

// ── Policy removals racing a signer add on the same rule ──────────────────────

/// The External signer on verifier V a racing add puts on rule 1, which held
/// no signer on a verifier before it.
fn racing_signer() -> ScVal {
    external_signer(&verifier_v(), &[0x11; 32])
}

/// Makes a send of `add_signer` append [`racing_signer`] to rule 1 under the
/// simulated id, as the rule stands at that send.
fn on_racing_add_send(h: &Harness) {
    h.on_send(
        "add_signer",
        SendEffect::AddSigner {
            rule_id: 1,
            signer_id: SIMULATED_SIGNER_ID,
            signer: racing_signer(),
        },
    );
}

/// Adds [`racing_signer`] to rule 1 through the signers manager.
async fn add_racing_signer(h: &Harness, request_id: &str) -> Result<u32, SaError> {
    let signer = SoftwareSigningKey::new_from_bytes(SEED);
    h.manager
        .add_signer(
            smart_account(),
            1,
            racing_signer(),
            &signer,
            request_id.to_owned(),
            false,
            false,
        )
        .await
}

/// The verifier and policy pins of the newest `SaContextRulePinsUpdated` row
/// of rule 1.
fn last_rule_one_pins(h: &Harness) -> (Vec<String>, Vec<String>) {
    let rows = h.pins_updated_rows();
    let last = rows.last().expect("rule 1 has a pins-updated row");
    let (verifiers, policies, _, _) = pins_updated_fields(last);
    (verifiers, policies)
}

/// Asserts that the rows written under each of `request_ids` form one
/// contiguous block of the log, and returns each block's kinds.
fn contiguous_blocks(h: &Harness, request_ids: &[&str]) -> Vec<Vec<String>> {
    let rows = h.rows();
    request_ids
        .iter()
        .map(|request_id| {
            let positions: Vec<usize> = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| row.request_id == *request_id)
                .map(|(position, _)| position)
                .collect();
            let (first, last) = (positions[0], positions[positions.len() - 1]);
            assert_eq!(
                last - first + 1,
                positions.len(),
                "the rows of {request_id} are interleaved with another verb's: {:?}",
                rows.iter()
                    .map(|row| row.request_id.as_str())
                    .collect::<Vec<_>>()
            );
            row_kinds(&rows, request_id)
        })
        .collect()
}

/// The race outcome of a policy removal and a verifier-adding signer add on
/// rule 1. Both confirmed, the newest pin record holds the added verifier's
/// pin and no policy pin, and each verb's rows form one block.
fn assert_the_added_verifier_pin_survives(h: &Harness, removal: &str, add: &str) -> Vec<String> {
    assert_eq!(h.sends(), 2);
    let (verifiers, policies) = last_rule_one_pins(h);
    assert_eq!(
        verifiers,
        vec![first8(&webauthn_hash())],
        "the newest pin record keeps the added verifier's pin"
    );
    assert!(policies.is_empty(), "{policies:?}");
    let mut blocks = contiguous_blocks(h, &[removal, add]);
    assert_eq!(
        blocks[1],
        vec!["sa_signer_added_v2", "sa_context_rule_pins_updated"]
    );
    blocks.swap_remove(0)
}

/// A direct-path removal of the spending-limit policy Q from rule 1,
/// authorized under rule 2, holds rule 1's lock while its comparison's read
/// of Q is delayed. A signer add on rule 1 started meanwhile waits on the
/// lock. The removal plans from the record it reads under the lock and the
/// add plans from the removal's record, so the newest record keeps the
/// add's verifier pin.
#[tokio::test]
async fn a_direct_removal_racing_a_verifier_add_keeps_the_added_pin() {
    let h = Harness::new(spending_limit_chain()).await;
    h.pin_created(
        1,
        vec![],
        vec![first8(&spending_limit_hash())],
        vec![],
        vec![],
    );
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.delay_entry_read(
        &rpc_mock_helpers::contract_instance_key_xdr(&policy_q()),
        1,
        Duration::from_secs(2),
    );
    h.on_send(
        "remove_policy",
        SendEffect::RemovePolicy {
            rule_id: 1,
            policy: policy_q(),
        },
    );
    on_racing_add_send(&h);

    let (removed, added) = tokio::join!(
        remove_policy_under(&h, 0, &[2], "req-race-direct-remove"),
        add_racing_signer(&h, "req-race-direct-add"),
    );
    removed.unwrap();
    added.unwrap();
    let removal_block =
        assert_the_added_verifier_pin_survives(&h, "req-race-direct-remove", "req-race-direct-add");
    assert_eq!(
        removal_block,
        vec![
            "sa_context_rule_pins_updated",
            "sa_policy_removed",
            "sa_raw_invocation",
        ]
    );
}

/// Rule 1 holding the simple-threshold policy P at threshold 1 beside
/// [`two_rule_chain`]'s rule 2.
fn threshold_race_chain() -> Chain {
    two_rule_chain()
        .with_rule(1, rule(1, vec![delegated_account(0x31)], vec![policy_p()]))
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 1)
}

/// The threshold-path twin of
/// [`a_direct_removal_racing_a_verifier_add_keeps_the_added_pin`]. The
/// detach of P holds rule 1's lock through its delayed comparison and
/// records the cleared threshold and its pins row. The add's block lands
/// after the removal's, never inside it.
#[tokio::test]
async fn a_threshold_detach_racing_a_verifier_add_keeps_the_added_pin() {
    let h = Harness::new(threshold_race_chain()).await;
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.delay_entry_read(
        &rpc_mock_helpers::contract_instance_key_xdr(&policy_p()),
        1,
        Duration::from_secs(2),
    );
    h.on_send(
        "remove_policy",
        SendEffect::RemovePolicy {
            rule_id: 1,
            policy: policy_p(),
        },
    );
    on_racing_add_send(&h);

    let (removed, added) = tokio::join!(
        remove_policy_under(&h, 0, &[2], "req-race-threshold-remove"),
        add_racing_signer(&h, "req-race-threshold-add"),
    );
    removed.unwrap();
    added.unwrap();
    let removal_block = assert_the_added_verifier_pin_survives(
        &h,
        "req-race-threshold-remove",
        "req-race-threshold-add",
    );
    assert_eq!(
        removal_block,
        vec![
            "sa_threshold_changed_v2",
            "sa_context_rule_pins_updated",
            "sa_policy_removed",
            "sa_raw_invocation",
        ]
    );
}

/// The reverse start order: the signer add takes rule 1's lock first and
/// holds it while its probe of verifier V is delayed. The removal started
/// meanwhile waits on the lock, then plans from the record that holds the
/// add's pin.
#[tokio::test]
async fn a_signer_add_racing_a_direct_removal_keeps_its_pin() {
    let h = Harness::new(spending_limit_chain()).await;
    h.pin_created(
        1,
        vec![],
        vec![first8(&spending_limit_hash())],
        vec![],
        vec![],
    );
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.delay_entry_read(
        &rpc_mock_helpers::contract_instance_key_xdr(&verifier_v()),
        1,
        Duration::from_secs(2),
    );
    h.on_send(
        "remove_policy",
        SendEffect::RemovePolicy {
            rule_id: 1,
            policy: policy_q(),
        },
    );
    on_racing_add_send(&h);

    let (added, removed) = tokio::join!(
        add_racing_signer(&h, "req-race-reverse-add"),
        remove_policy_under(&h, 0, &[2], "req-race-reverse-remove"),
    );
    added.unwrap();
    removed.unwrap();
    assert_the_added_verifier_pin_survives(&h, "req-race-reverse-remove", "req-race-reverse-add");
    let rows = h.rows();
    let add_end = rows
        .iter()
        .rposition(|row| row.request_id == "req-race-reverse-add")
        .unwrap();
    let removal_start = rows
        .iter()
        .position(|row| row.request_id == "req-race-reverse-remove")
        .unwrap();
    assert!(add_end < removal_start, "the add completes first");
}

/// Rules 1 and 2, each with one delegated signer and the spending-limit
/// policy Q, Q served.
fn crossed_spending_limit_chain() -> Chain {
    Chain::default()
        .with_rule(1, rule(1, vec![delegated_account(0x31)], vec![policy_q()]))
        .with_rule(2, rule(2, vec![delegated_account(0x31)], vec![policy_q()]))
        .with_entry(wasm_instance(&policy_q(), spending_limit_hash()))
}

/// Two retunes with crossed target and admin rules, rule 1 under admin rule
/// 2 and rule 2 under admin rule 1, each acquire the sorted set {1, 2} in
/// one acquisition. With rule 1 held when they start, both queue on rule 1.
/// Once it is released the first takes both locks and completes, then the
/// second: neither holds one lock while it waits on the other.
#[tokio::test]
async fn crossed_retunes_complete_without_a_deadlock() {
    let h = Harness::with_timeout(crossed_spending_limit_chain(), Duration::from_secs(2)).await;
    h.baseline_v2(1);
    h.baseline_v2(2);
    h.set_simulated_return("get_spending_limit_data", spending_limit_data(1_000, 100));
    let held = stellar_agent_smart_account::test_helpers::hold_rule_lock(
        &h.manager,
        &strkey(&smart_account()),
        1,
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let release = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let reads = h.primary_log.rule_reads();
        assert!(
            !reads.contains(&1) && !reads.contains(&2),
            "both retunes wait on a lock before any read: {reads:?}"
        );
        drop(held);
    };
    let (first, second, ()) = tokio::join!(
        set_spending_limit_of(&h, 1, &[2], "req-crossed-1"),
        set_spending_limit_of(&h, 2, &[1], "req-crossed-2"),
        release,
    );
    first.unwrap();
    second.unwrap();
    assert_eq!(h.sends(), 2);
    for request_id in ["req-crossed-1", "req-crossed-2"] {
        assert_eq!(
            row_kinds(&h.rows(), request_id),
            vec!["sa_spending_limit_retuned"],
            "{request_id}"
        );
    }
}

/// A direct attach compares the target rule as a threshold attach does: a
/// rule without a state row refuses with `sa.signer_set_missing_baseline`
/// before submission.
#[tokio::test]
async fn a_direct_attach_without_a_baseline_refuses() {
    let h = policy_harness(vec![]).await;
    let err = add_policy(&h, &policy_q(), "req-direct-missing", false)
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.signer_set_missing_baseline", "{err:?}");
    assert_refused_before_submission(&h, &err, "add_policy", "req-direct-missing");
}

/// A direct attach on a rule whose state row is version 1 refuses with
/// `sa.signer_set_baseline_legacy` before submission, before the policy's
/// install parameter is parsed.
#[tokio::test]
async fn a_direct_attach_over_a_version_1_baseline_refuses() {
    let h = threshold_policy_harness(vec![policy_p2()], &[(policy_p2(), 1)]).await;
    h.baseline_v1(1);
    let err = add_policy_with(&h, &policy_q(), ScVal::Void, "req-direct-legacy", false)
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.signer_set_baseline_legacy", "{err:?}");
    assert_refused_before_submission(&h, &err, "add_policy", "req-direct-legacy");
}

// ── A pinned rule whose record pins no verifier ───────────────────────────────

/// Rule 1 with a delegated signer and an External signer on the passkey
/// verifier, and the simple-threshold policy P at threshold 1.
fn absent_verifier_pin_chain() -> Chain {
    Chain::default()
        .with_rule(
            1,
            rule_with_ids(
                1,
                vec![
                    (0, delegated_signer()),
                    (1, external_signer(&passkey_verifier(), &[0x22; 32])),
                ],
                vec![policy_p()],
            ),
        )
        .with_wasm(&passkey_verifier(), webauthn_hash())
        .with_wasm(&policy_p(), KNOWN_WASM_HASH)
        .with_threshold(&policy_p(), 1, 1)
}

/// An [`absent_verifier_pin_chain`] harness with rule 1's version-2 baseline
/// and a pin record that pins P and no verifier.
async fn absent_verifier_pin_harness() -> Harness {
    let h = Harness::new(absent_verifier_pin_chain()).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);
    h
}

/// Refreshes rule 1's baseline with `options`.
async fn refresh(
    h: &Harness,
    options: RefreshOptions,
    request_id: &str,
) -> Result<stellar_agent_smart_account::managers::signers::RefreshOutcome, SaError> {
    h.manager
        .refresh_signer_baseline(smart_account(), 1, None, options, request_id.to_owned())
        .await
}

/// A rule whose pin record pins no verifier while it holds an External
/// signer refuses the submission with `sa.pinned_verifier_absent` naming the
/// verifier. The refusal follows the pin check's rule read and precedes any
/// simulation. The same rule without a pin record signs.
#[tokio::test]
async fn a_live_verifier_the_record_does_not_pin_refuses_the_submission() {
    let h = absent_verifier_pin_harness().await;
    let err = h
        .submit(&[1], Some("req-verifier-absent"))
        .await
        .unwrap_err();
    match &err {
        SaError::PinnedVerifierAbsent {
            rule_id: 1,
            verifier_redacted,
            smart_account_redacted: redacted,
            request_id,
        } => {
            assert_eq!(
                verifier_redacted.as_str(),
                redact_strkey_first5_last5(&strkey(&passkey_verifier()))
            );
            assert_eq!(redacted.as_str(), smart_account_redacted());
            assert_eq!(request_id, "req-verifier-absent");
        }
        other => panic!("expected PinnedVerifierAbsent; got {other:?}"),
    }
    assert_eq!(err.wire_code(), "sa.pinned_verifier_absent");
    assert!(h.primary_log.rule_reads().contains(&1));
    assert!(!h.simulated("noop"));
    assert_eq!(h.sends(), 0);

    let h = Harness::new(absent_verifier_pin_chain()).await;
    h.baseline_v2(1);
    h.submit(&[1], Some("req-verifier-unpinned-rule"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
}

/// `verify-pins` reports a live verifier the pin record does not pin as
/// verifier drift with no observed hash, beside the matching policy.
#[tokio::test]
async fn verify_pins_reports_drift_for_a_live_verifier_the_record_does_not_pin() {
    let h = absent_verifier_pin_harness().await;
    let result = h
        .rule_manager()
        .verify_rule_wasm_pins(
            smart_account(),
            1,
            &account_id_for_seed(SEED),
            "req-verify-verifier-absent",
        )
        .await
        .unwrap();
    assert_eq!(result.verifier_pin_status, PinStatus::Drift);
    assert!(result.observed_verifier_first8.is_empty());
    assert_eq!(result.policy_pin_status, PinStatus::Match);
    assert_eq!(result.unavailable_wire_code, None);
    assert_eq!(h.sends(), 0);
}

/// `signers refresh` repairs the record: it writes the baseline, then a
/// pins row (reason `baseline_refreshed`) adding the live verifier's pin and
/// keeping the policy pin, reports one verifier pinned, and the next
/// submission signs.
#[tokio::test]
async fn a_refresh_pins_the_live_verifier_of_a_record_that_pins_none() {
    let h = absent_verifier_pin_harness().await;
    let outcome = refresh(&h, RefreshOptions::new(false), "req-repair")
        .await
        .unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-repair"),
        vec!["sa_signer_set_baselined_v2", "sa_context_rule_pins_updated"]
    );
    let (verifiers, policies, _, reason) = pins_updated_fields(&h.pins_updated_rows()[0]);
    assert_eq!(verifiers, vec![first8(&webauthn_hash())]);
    assert_eq!(policies, vec![first8(&KNOWN_WASM_HASH)]);
    assert_eq!(reason, PinsUpdateReason::BaselineRefreshed);
    assert_eq!(outcome.previous_baseline, PreviousBaseline::Matched);
    assert!(outcome.verifier_pinned);

    h.submit(&[1], Some("req-after-repair")).await.unwrap();
    assert_eq!(h.sends(), 1);
}

/// Over a diverged rule the reconciliation follows the divergence handling.
/// Without `accept_divergence` the refresh refuses after the divergence row
/// and writes no pins row. With it the refresh records the chain and pins
/// the live verifier, and the next submission signs.
#[tokio::test]
async fn a_diverged_refresh_pins_the_live_verifier_only_with_the_flag() {
    let h = absent_verifier_pin_harness().await;
    h.set_rule(
        1,
        &rule_with_ids(
            1,
            vec![
                (0, delegated_signer()),
                (1, external_signer(&passkey_verifier(), &[0x22; 32])),
                (2, delegated_account(0x13)),
            ],
            vec![policy_p()],
        ),
    );
    let err = refresh(&h, RefreshOptions::new(false), "req-repair-diverged-no")
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.signer_set_diverged", "{err:?}");
    assert_eq!(
        row_kinds(&h.rows(), "req-repair-diverged-no"),
        vec!["sa_signer_set_diverged"]
    );

    let outcome = refresh(&h, RefreshOptions::new(true), "req-repair-diverged-yes")
        .await
        .unwrap();
    assert_eq!(outcome.previous_baseline, PreviousBaseline::Diverged);
    assert!(outcome.verifier_pinned);
    assert_eq!(
        row_kinds(&h.rows(), "req-repair-diverged-yes"),
        vec![
            "sa_signer_set_diverged",
            "sa_signer_set_baselined_v2",
            "sa_context_rule_pins_updated",
        ]
    );
    let (verifiers, _, _, _) = pins_updated_fields(&h.pins_updated_rows()[0]);
    assert_eq!(verifiers, vec![first8(&webauthn_hash())]);
    h.submit(&[1], Some("req-after-diverged-repair"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
}

/// A record that already pins a verifier is left alone, whether the live
/// verifier matches the pin or not, and a rule without a pin record gets
/// none: each refresh writes the baseline only. A pinned verifier that
/// changed stays the drift check's finding.
#[tokio::test]
async fn a_refresh_leaves_a_record_with_a_verifier_pin_or_no_record_alone() {
    let h = Harness::new(absent_verifier_pin_chain()).await;
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![first8(&webauthn_hash())],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let outcome = refresh(&h, RefreshOptions::new(false), "req-refresh-pinned")
        .await
        .unwrap();
    assert!(!outcome.verifier_pinned);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-pinned"),
        vec!["sa_signer_set_baselined_v2"]
    );

    let h = Harness::new(absent_verifier_pin_chain()).await;
    h.baseline_v2(1);
    h.pin_created(
        1,
        vec![FOREIGN_FIRST8.to_owned()],
        vec![first8(&KNOWN_WASM_HASH)],
        vec![],
        vec![],
    );
    let outcome = refresh(&h, RefreshOptions::new(false), "req-refresh-foreign")
        .await
        .unwrap();
    assert!(!outcome.verifier_pinned);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-foreign"),
        vec!["sa_signer_set_baselined_v2"]
    );
    let err = h
        .submit(&[1], Some("req-after-foreign-refresh"))
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.verifier_hash_drift", "{err:?}");

    let h = Harness::new(absent_verifier_pin_chain()).await;
    h.baseline_v2(1);
    let outcome = refresh(&h, RefreshOptions::new(false), "req-refresh-unpinned")
        .await
        .unwrap();
    assert!(!outcome.verifier_pinned);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-unpinned"),
        vec!["sa_signer_set_baselined_v2"]
    );
    assert!(h.pins_updated_rows().is_empty());
}

/// Two External signers on one verifier address share one pin.
#[tokio::test]
async fn two_signers_on_one_verifier_are_pinned_once() {
    let chain = absent_verifier_pin_chain().with_rule(
        1,
        rule_with_ids(
            1,
            vec![
                (0, delegated_signer()),
                (1, external_signer(&passkey_verifier(), &[0x22; 32])),
                (2, external_signer(&passkey_verifier(), &[0x23; 32])),
            ],
            vec![policy_p()],
        ),
    );
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);
    let outcome = refresh(&h, RefreshOptions::new(false), "req-refresh-shared")
        .await
        .unwrap();
    assert!(outcome.verifier_pinned);
    let rows = h.pins_updated_rows();
    assert_eq!(rows.len(), 1);
    let (verifiers, _, _, _) = pins_updated_fields(&rows[0]);
    assert_eq!(verifiers, vec![first8(&webauthn_hash())]);
    h.submit(&[1], Some("req-after-shared-refresh"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
}

/// Rule 1 of [`absent_verifier_pin_chain`] with its External signer on
/// `verifier` instead, served by `entries`.
fn absent_verifier_pin_chain_on(verifier: &ScAddress, entries: Vec<Value>) -> Chain {
    let mut chain = absent_verifier_pin_chain().with_rule(
        1,
        rule_with_ids(
            1,
            vec![
                (0, delegated_signer()),
                (1, external_signer(verifier, &[0x22; 32])),
            ],
            vec![policy_p()],
        ),
    );
    for entry in entries {
        chain = chain.with_entry(entry);
    }
    chain
}

/// A live verifier whose hash is outside the allowlist is pinned only with
/// the unknown-verifier override. Without it the refresh refuses before any
/// write. With it the override row sits between the baseline row and the
/// pins row, and the next submission signs.
#[tokio::test]
async fn a_refresh_pins_an_unknown_verifier_only_with_its_override() {
    let unknown = [0xdd; 32];
    let h = Harness::new(absent_verifier_pin_chain_on(
        &verifier_w(),
        vec![wasm_instance(&verifier_w(), unknown)],
    ))
    .await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);

    let err = refresh(&h, RefreshOptions::new(false), "req-refresh-unknown-no")
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.verifier_wasm_not_in_allowlist");
    assert!(
        err.to_string().contains("--accept-unknown-verifier"),
        "{err}"
    );
    assert!(row_kinds(&h.rows(), "req-refresh-unknown-no").is_empty());

    let outcome = refresh(
        &h,
        RefreshOptions::new(false).with_accept_unknown_verifier(true),
        "req-refresh-unknown-yes",
    )
    .await
    .unwrap();
    assert!(outcome.verifier_pinned);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-unknown-yes"),
        vec![
            "sa_signer_set_baselined_v2",
            "unknown_override(rule Some(1))",
            "sa_context_rule_pins_updated",
        ]
    );
    let (verifiers, _, unknown_override, _) = pins_updated_fields(&h.pins_updated_rows()[0]);
    assert_eq!(verifiers, vec![first8(&unknown)]);
    assert!(unknown_override);
    h.submit(&[1], Some("req-after-unknown-refresh"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
}

/// A live verifier whose executable is an owner-managed external reference
/// is mutable, and is pinned only with the mutable-verifier override, with
/// its reference pin.
#[tokio::test]
async fn a_refresh_pins_a_mutable_verifier_only_with_its_override() {
    let h = Harness::new(absent_verifier_pin_chain_on(
        &verifier_v(),
        vec![
            external_ref_instance(&verifier_v()),
            tag_entry(webauthn_hash()),
        ],
    ))
    .await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);

    let err = refresh(&h, RefreshOptions::new(false), "req-refresh-mutable-no")
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.verifier_mutable");
    assert!(
        err.to_string().contains("--accept-mutable-verifier"),
        "{err}"
    );
    assert!(row_kinds(&h.rows(), "req-refresh-mutable-no").is_empty());

    refresh(
        &h,
        RefreshOptions::new(false).with_accept_mutable_verifier(true),
        "req-refresh-mutable-yes",
    )
    .await
    .unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-mutable-yes"),
        vec![
            "sa_signer_set_baselined_v2",
            "mutable_override(rule Some(1))",
            "sa_context_rule_pins_updated",
        ]
    );
    match &h.pins_updated_rows()[0].event_kind {
        EventKind::SaContextRulePinsUpdated {
            pinned_verifier_wasm_hashes_first8,
            pinned_verifier_executable_refs,
            mutable_override,
            ..
        } => {
            assert_eq!(
                pinned_verifier_wasm_hashes_first8,
                &vec![first8(&webauthn_hash())]
            );
            assert_eq!(
                pinned_verifier_executable_refs,
                &vec![Some(reference_pin(webauthn_hash()))]
            );
            assert!(*mutable_override);
        }
        other => panic!("expected SaContextRulePinsUpdated; got {other:?}"),
    }
    h.submit(&[1], Some("req-after-mutable-refresh"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
}

/// A Wasm verifier and an external reference resolving to the same hash have
/// different pins, since the signing check compares the executable kind and
/// reference too. The one-pin record cannot hold both, so the refresh
/// refuses before any write. The reference still needs its mutable-verifier
/// override before the comparison of the two pins is reached.
#[tokio::test]
async fn a_refresh_refuses_a_wasm_verifier_and_a_reference_on_one_hash() {
    let chain = absent_verifier_pin_chain()
        .with_rule(
            1,
            rule_with_ids(
                1,
                vec![
                    (0, delegated_signer()),
                    (1, external_signer(&passkey_verifier(), &[0x22; 32])),
                    (2, external_signer(&verifier_v(), &[0x23; 32])),
                ],
                vec![policy_p()],
            ),
        )
        .with_entry(external_ref_instance(&verifier_v()))
        .with_entry(tag_entry(webauthn_hash()));
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);

    let err = refresh(&h, RefreshOptions::new(false), "req-refresh-mixed-pins-no")
        .await
        .unwrap_err();
    assert_eq!(err.wire_code(), "sa.verifier_mutable");
    assert!(row_kinds(&h.rows(), "req-refresh-mixed-pins-no").is_empty());

    let err = refresh(
        &h,
        RefreshOptions::new(false).with_accept_mutable_verifier(true),
        "req-refresh-mixed-pins-yes",
    )
    .await
    .unwrap_err();
    match &err {
        SaError::MultiplePinnedHashesUnsupported {
            kind,
            rule_id,
            count,
            ..
        } => {
            assert_eq!(*kind, "verifier");
            assert_eq!(*rule_id, 1);
            assert_eq!(*count, 2);
        }
        other => panic!("expected MultiplePinnedHashesUnsupported; got {other:?}"),
    }
    assert!(row_kinds(&h.rows(), "req-refresh-mixed-pins-yes").is_empty());
}

/// Two verifier addresses whose pins are equal share one pin. Two external
/// references on one owner and tag resolve to one hash, so the refresh
/// records one reference pin and writes the mutable-contract override row
/// of each address. The next submission signs.
#[tokio::test]
async fn two_references_on_one_tag_share_one_pin_and_record_both_overrides() {
    let chain = absent_verifier_pin_chain()
        .with_rule(
            1,
            rule_with_ids(
                1,
                vec![
                    (0, delegated_signer()),
                    (1, external_signer(&verifier_v(), &[0x22; 32])),
                    (2, external_signer(&verifier_w(), &[0x23; 32])),
                ],
                vec![policy_p()],
            ),
        )
        .with_entry(external_ref_instance(&verifier_v()))
        .with_entry(external_ref_instance(&verifier_w()))
        .with_entry(tag_entry(webauthn_hash()));
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);

    let outcome = refresh(
        &h,
        RefreshOptions::new(false).with_accept_mutable_verifier(true),
        "req-refresh-one-tag",
    )
    .await
    .unwrap();
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-one-tag"),
        vec![
            "sa_signer_set_baselined_v2",
            "mutable_override(rule Some(1))",
            "mutable_override(rule Some(1))",
            "sa_context_rule_pins_updated",
        ]
    );
    match &h.pins_updated_rows()[0].event_kind {
        EventKind::SaContextRulePinsUpdated {
            pinned_verifier_wasm_hashes_first8,
            pinned_verifier_executable_refs,
            mutable_override,
            ..
        } => {
            assert_eq!(
                pinned_verifier_wasm_hashes_first8,
                &vec![first8(&webauthn_hash())]
            );
            assert_eq!(
                pinned_verifier_executable_refs,
                &vec![Some(reference_pin(webauthn_hash()))]
            );
            assert!(*mutable_override);
        }
        other => panic!("expected SaContextRulePinsUpdated; got {other:?}"),
    }
    assert!(outcome.verifier_pinned);
    h.submit(&[1], Some("req-after-one-tag-refresh"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
}

/// Two External signers on one mutable verifier address are one verifier to
/// the refresh: it probes the address once, writes one override row and one
/// pin, and the next submission signs. One probe reads the address's
/// instance as often as the refresh of a rule with one signer on it does.
#[tokio::test]
async fn two_signers_on_one_mutable_verifier_are_probed_once() {
    let entries = || {
        vec![
            external_ref_instance(&verifier_v()),
            tag_entry(webauthn_hash()),
        ]
    };
    let single = Harness::new(absent_verifier_pin_chain_on(&verifier_v(), entries())).await;
    single.baseline_v2(1);
    single.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);
    refresh(
        &single,
        RefreshOptions::new(false).with_accept_mutable_verifier(true),
        "req-refresh-one-signer",
    )
    .await
    .unwrap();
    let one_probe_reads = single.primary_instance_reads(&verifier_v());
    assert!(one_probe_reads > 0);

    let mut chain = absent_verifier_pin_chain().with_rule(
        1,
        rule_with_ids(
            1,
            vec![
                (0, delegated_signer()),
                (1, external_signer(&verifier_v(), &[0x22; 32])),
                (2, external_signer(&verifier_v(), &[0x23; 32])),
            ],
            vec![policy_p()],
        ),
    );
    for entry in entries() {
        chain = chain.with_entry(entry);
    }
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);
    let outcome = refresh(
        &h,
        RefreshOptions::new(false).with_accept_mutable_verifier(true),
        "req-refresh-two-signers-one-address",
    )
    .await
    .unwrap();
    assert_eq!(h.primary_instance_reads(&verifier_v()), one_probe_reads);
    assert_eq!(
        row_kinds(&h.rows(), "req-refresh-two-signers-one-address"),
        vec![
            "sa_signer_set_baselined_v2",
            "mutable_override(rule Some(1))",
            "sa_context_rule_pins_updated",
        ]
    );
    let (verifiers, _, _, _) = pins_updated_fields(&h.pins_updated_rows()[0]);
    assert_eq!(verifiers, vec![first8(&webauthn_hash())]);
    assert!(outcome.verifier_pinned);
    h.submit(&[1], Some("req-after-one-address-refresh"))
        .await
        .unwrap();
    assert_eq!(h.sends(), 1);
}

/// Live verifiers whose hashes differ cannot share the rule's one verifier
/// pin: the refresh refuses before any write, even with the override the
/// second verifier needs.
#[tokio::test]
async fn a_refresh_refuses_live_verifiers_running_two_executables() {
    let chain = absent_verifier_pin_chain()
        .with_rule(
            1,
            rule_with_ids(
                1,
                vec![
                    (0, delegated_signer()),
                    (1, external_signer(&passkey_verifier(), &[0x22; 32])),
                    (2, external_signer(&verifier_w(), &[0x23; 32])),
                ],
                vec![policy_p()],
            ),
        )
        .with_entry(wasm_instance(&verifier_w(), [0xdd; 32]));
    let h = Harness::new(chain).await;
    h.baseline_v2(1);
    h.pin_created(1, vec![], vec![first8(&KNOWN_WASM_HASH)], vec![], vec![]);

    let err = refresh(
        &h,
        RefreshOptions::new(false).with_accept_unknown_verifier(true),
        "req-refresh-two-hashes",
    )
    .await
    .unwrap_err();
    match &err {
        SaError::MultiplePinnedHashesUnsupported {
            kind,
            rule_id,
            count,
            ..
        } => {
            assert_eq!(*kind, "verifier");
            assert_eq!(*rule_id, 1);
            assert_eq!(*count, 2);
        }
        other => panic!("expected MultiplePinnedHashesUnsupported; got {other:?}"),
    }
    assert!(row_kinds(&h.rows(), "req-refresh-two-hashes").is_empty());
}
