//! `smart-account multicall` gates each bundle on the selected profile's
//! signed V1 policy, with persisted window state, through the
//! `stellar-agent` binary.
//!
//! Each test provisions an isolated data root, and most run the whole
//! signed-policy ceremony. The profile points at a mock RPC that accepts the
//! bundle the way a live endpoint would. The mock simulates the router's
//! `exec` with the wallet's authorization entry and serves the router instance
//! with the vendored wasm hash, which the CLI verifies. It then confirms the
//! submission. The mock counts every method, so a test observes whether the
//! bundle was simulated or sent.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256;
use stellar_agent_test_support::signed_envelope::{
    TESTNET_PASSPHRASE, get_network_result, ledger_entries_result_for, send_transaction_hash_hex,
};
use stellar_agent_test_support::xdr_fixtures::{
    account_ledger_key_xdr, contract_instance_ledger_entries_json, ledger_entry_from_response_json,
};
use stellar_xdr::{
    HostFunction, LedgerFootprint, Limits, OperationBody, ReadXdr as _, ScString, ScVal,
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanResources, SorobanTransactionData,
    SorobanTransactionDataExt, TransactionEnvelope, VecM, WriteXdr as _,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::v1_ceremony::{CliRun, IsolatedHome, Keypair, policy_document, policy_rule};

const PROFILE: &str = "multicall-policy";
const SIGNER_SEED: [u8; 32] = [0x11; 32];
const OWNER_SEED: [u8; 32] = [0x22; 32];

/// The variable the multicall child reads the signer secret from.
const MULTICALL_SIGNER_ENV: &str = "MULTICALL_POLICY_SIGNER_SECRET";

/// The bundle's inner invocations: three native-asset `symbol` calls.
const INNER_COUNT: usize = 3;

/// The window and cap of the persisted `bundle_rate_limit` rule: one bundle
/// of [`INNER_COUNT`] inners fills it.
const RATE_LIMIT_WINDOW: &str = "1h";
const RATE_LIMIT_WINDOW_SECS: u64 = 3_600;

fn contract(byte: u8) -> String {
    stellar_strkey::Contract([byte; 32])
        .to_string()
        .as_str()
        .to_owned()
}

/// The smart account executing the bundle.
fn wallet() -> String {
    contract(0x44)
}

/// The registered multicall router.
fn router() -> String {
    contract(0x45)
}

/// The contract each inner invocation calls.
fn inner_target() -> String {
    contract(0x47)
}

fn signer() -> Keypair {
    Keypair::from_seed(SIGNER_SEED)
}

fn owner() -> Keypair {
    Keypair::from_seed(OWNER_SEED)
}

/// A `wallet_multicall` rule on `stellar:testnet`.
fn multicall_rule(criteria: &str, decision: &str) -> String {
    policy_rule("wallet_multicall", "stellar:testnet", criteria, decision)
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock RPC
// ─────────────────────────────────────────────────────────────────────────────

/// An endpoint that accepts a multicall bundle signed by `source`.
struct BundleRpc {
    source: String,
    router_entry: Value,
    calls: Arc<Mutex<Vec<String>>>,
}

impl BundleRpc {
    /// The entries for every requested key this endpoint knows: the source
    /// account and the router instance, which carries the vendored router's
    /// wasm hash.
    fn ledger_entries(&self, body: &Value) -> Value {
        let account_key = account_ledger_key_xdr(&self.source);
        let account_entry =
            ledger_entries_result_for(&[self.source.as_str()])["entries"][0].clone();
        let entries: Vec<Value> = body["params"]["keys"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|key| {
                let key = key.as_str()?;
                if key == account_key {
                    Some(account_entry.clone())
                } else if key == self.router_entry["key"].as_str()? {
                    Some(self.router_entry.clone())
                } else {
                    None
                }
            })
            .collect();
        json!({"entries": entries, "latestLedger": 1000})
    }
}

/// Simulates the transaction in `body`. The router's `exec` returns one
/// native-asset symbol per inner and requires the caller's authorization
/// over the invocation; a signed simulation echoes the signed entries.
fn simulate(body: &Value) -> Value {
    let Some(envelope) = body["params"]["transaction"]
        .as_str()
        .and_then(|xdr| TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).ok())
    else {
        return json!({"error": "undecodable transaction"});
    };
    let TransactionEnvelope::Tx(tx) = envelope else {
        return json!({"error": "expected a v1 envelope"});
    };
    let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
        return json!({"error": "expected a host-function invocation"});
    };
    let HostFunction::InvokeContract(invoke) = &op.host_function else {
        return json!({"error": "expected a contract invocation"});
    };
    let (value, auth) = if invoke.function_name.0.as_slice() == b"exec" {
        let inners = match invoke.args.get(1) {
            Some(ScVal::Vec(Some(inners))) => inners.len(),
            _ => 0,
        };
        let symbol = ScVal::String(ScString("native".try_into().unwrap()));
        let value = ScVal::Vec(Some(vec![symbol; inners].try_into().unwrap()));
        let auth = if op.auth.is_empty() {
            match invoke.args.first() {
                Some(ScVal::Address(caller)) => vec![SorobanAuthorizationEntry {
                    credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                        address: caller.clone(),
                        nonce: 7,
                        signature_expiration_ledger: 0,
                        signature: ScVal::Void,
                    }),
                    root_invocation: SorobanAuthorizedInvocation {
                        function: SorobanAuthorizedFunction::ContractFn(invoke.clone()),
                        sub_invocations: VecM::default(),
                    },
                }],
                _ => Vec::new(),
            }
        } else {
            op.auth.to_vec()
        };
        (value, auth)
    } else {
        (ScVal::Void, Vec::new())
    };
    let transaction_data = SorobanTransactionData {
        ext: SorobanTransactionDataExt::V0,
        resources: SorobanResources {
            footprint: LedgerFootprint {
                read_only: VecM::default(),
                read_write: VecM::default(),
            },
            instructions: 0,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 0,
    };
    json!({
        "transactionData": transaction_data.to_xdr_base64(Limits::none()).unwrap(),
        "minResourceFee": "1000",
        "results": [{
            "auth": auth
                .iter()
                .map(|entry| entry.to_xdr_base64(Limits::none()).unwrap())
                .collect::<Vec<_>>(),
            "xdr": value.to_xdr_base64(Limits::none()).unwrap(),
        }],
        "latestLedger": 1000,
    })
}

impl Respond for BundleRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let method = body["method"].as_str().unwrap_or_default().to_owned();
        self.calls.lock().unwrap().push(method.clone());
        let result = match method.as_str() {
            "getNetwork" => get_network_result(TESTNET_PASSPHRASE),
            "getLatestLedger" => {
                json!({"id": "ab".repeat(32), "sequence": 1000, "protocolVersion": 23})
            }
            "getLedgerEntries" => self.ledger_entries(&body),
            "simulateTransaction" => simulate(&body),
            "sendTransaction" => json!({
                "status": "PENDING",
                "hash": send_transaction_hash_hex(&body, TESTNET_PASSPHRASE),
                "latestLedger": 1000,
                "latestLedgerCloseTime": "1234567890",
            }),
            "getTransaction" => json!({
                "status": "SUCCESS",
                "latestLedger": 1001,
                "oldestLedger": 1,
                "ledger": 1001,
                "createdAt": (stellar_agent_core::timefmt::now_unix_ms().unwrap() / 1_000)
                    .to_string(),
            }),
            _ => {
                return ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32601, "message": format!("unexpected method {method}")},
                }));
            }
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

/// A mock endpoint and the methods it has answered, in order.
struct MockRpc {
    server: MockServer,
    calls: Arc<Mutex<Vec<String>>>,
}

impl MockRpc {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let hash: [u8; 32] = hex::decode(MULTICALL_WASM_SHA256)
            .unwrap()
            .try_into()
            .unwrap();
        Mock::given(method("POST"))
            .respond_with(BundleRpc {
                source: signer().public().to_owned(),
                router_entry: ledger_entry_from_response_json(
                    &contract_instance_ledger_entries_json(&router(), hash),
                ),
                calls: Arc::clone(&calls),
            })
            .mount(&server)
            .await;
        Self { server, calls }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    /// How many times `method` was called.
    fn count(&self, method: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|m| *m == method)
            .count()
    }

    /// Every request the endpoint received.
    async fn requests(&self) -> usize {
        self.server.received_requests().await.unwrap().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixture
// ─────────────────────────────────────────────────────────────────────────────

/// Provisions a V1 profile whose endpoint is `rpc`, with every key enrolled
/// and `rules` signed by the owner.
fn provision(home: &IsolatedHome, rpc: &str, rules: &[String]) {
    home.provision_v1_profile(
        PROFILE,
        &["--rpc-url", rpc],
        &signer(),
        &owner(),
        &policy_document(PROFILE, rules),
    );
}

/// Registers the router through the CLI and returns the envelope's
/// `data.status`.
fn register(home: &IsolatedHome) -> String {
    let envelope = home.run_ok(
        &[
            "smart-account",
            "register-multicall",
            "--profile",
            PROFILE,
            "--network",
            "testnet",
            "--address",
            &router(),
            "--wasm-sha256",
            MULTICALL_WASM_SHA256,
        ],
        &[],
    );
    envelope["data"]["status"].as_str().unwrap().to_owned()
}

/// Submits [`INNER_COUNT`] `symbol` calls under rule 0, with `rpc` as the
/// secondary endpoint and the enrolled signer's secret.
fn multicall(home: &IsolatedHome, rpc: &str) -> CliRun {
    let invocation = format!("{}:symbol:[]", inner_target());
    let wallet = wallet();
    let mut args = vec![
        "smart-account",
        "multicall",
        "--profile",
        PROFILE,
        "--smart-account",
        &wallet,
        "--rule-id",
        "0",
        "--secondary-rpc-url",
        rpc,
        "--signer-secret-env",
        MULTICALL_SIGNER_ENV,
    ];
    for _ in 0..INNER_COUNT {
        args.extend(["--invocation", invocation.as_str()]);
    }
    let signer = signer();
    home.run(&args, &[(MULTICALL_SIGNER_ENV, signer.secret())])
}

/// Asserts the run refused at the policy gate as `sa.multicall_failed`.
fn assert_policy_gate_refusal(run: &CliRun) {
    assert_eq!(run.code, 1, "{} stderr={}", run.envelope, run.stderr);
    assert_eq!(run.error_code(), "sa.multicall_failed", "{}", run.envelope);
    assert!(
        run.error_message().contains("phase 'policy_gate'"),
        "{}",
        run.envelope
    );
}

/// The `deny_wire_code` of every denied-bundle row in the profile's log.
fn denied_codes(home: &IsolatedHome) -> Vec<String> {
    home.audit_rows(PROFILE, "sa_multicall_bundle_denied")
        .iter()
        .map(|row| row["deny_wire_code"].as_str().unwrap().to_owned())
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// A signed `wallet_multicall` allow rule on `stellar:testnet` admits the
/// bundle, which confirms after exactly one send. Registration, removal, and
/// re-registration of the router report their status first.
#[tokio::test]
async fn multicall_allow_rule_submits_the_bundle_once() {
    let rpc = MockRpc::start().await;
    let home = IsolatedHome::new();
    provision(&home, &rpc.uri(), &[multicall_rule("[]", "allow")]);

    assert_eq!(register(&home), "registered");
    let removed = home.run_ok(
        &[
            "smart-account",
            "unregister-multicall",
            "--profile",
            PROFILE,
            "--network",
            "testnet",
        ],
        &[],
    );
    assert_eq!(removed["data"]["status"], "unregistered", "{removed}");
    assert_eq!(register(&home), "registered");

    let run = multicall(&home, &rpc.uri());
    assert_eq!(run.code, 0, "{} stderr={}", run.envelope, run.stderr);
    assert_eq!(
        run.envelope["data"]["inner_count"], INNER_COUNT,
        "{}",
        run.envelope
    );
    assert!(
        run.envelope["data"]["bundle_tx_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty()),
        "{}",
        run.envelope
    );
    assert_eq!(rpc.count("sendTransaction"), 1);
}

/// A matching deny rule refuses at the policy gate with its own audit code
/// and sends nothing.
#[tokio::test]
async fn multicall_deny_rule_refuses_at_the_policy_gate() {
    let rpc = MockRpc::start().await;
    let home = IsolatedHome::new();
    provision(&home, &rpc.uri(), &[multicall_rule("[]", "deny")]);
    home.write_multicall_registry(&router());

    let run = multicall(&home, &rpc.uri());
    assert_policy_gate_refusal(&run);
    assert_eq!(denied_codes(&home), ["multicall.explicit_rule_deny"]);
    assert_eq!(rpc.count("simulateTransaction"), 0);
    assert_eq!(rpc.count("sendTransaction"), 0);
}

/// A Noop profile refuses with `policy.engine_required` before the audit
/// writer is acquired and before any endpoint is contacted. The profile's
/// audit key is unminted, so a later refusal would carry another code.
#[tokio::test]
async fn multicall_noop_profile_refuses_engine_required() {
    let rpc = MockRpc::start().await;
    let home = IsolatedHome::new();
    home.init_profile(PROFILE, &["--engine", "noop", "--rpc-url", &rpc.uri()]);
    home.write_multicall_registry(&router());

    let run = multicall(&home, &rpc.uri());
    assert_eq!(run.code, 1, "{} stderr={}", run.envelope, run.stderr);
    assert_eq!(
        run.error_code(),
        "policy.engine_required",
        "{}",
        run.envelope
    );
    assert!(
        run.error_message().contains("multicall")
            && run.error_message().contains("policy.engine = \"v1\""),
        "{}",
        run.envelope
    );
    assert!(
        !home.load_profile(PROFILE).audit_log_path.exists(),
        "the refusal precedes the audit writer"
    );
    assert_eq!(rpc.requests().await, 0, "no endpoint is contacted");
}

/// A persisted `bundle_rate_limit` admits the first bundle and refuses the
/// next process's bundle before simulation. The window the first process
/// recorded reads back under the loaded profile's window-key coordinates.
#[tokio::test]
#[serial_test::serial]
async fn multicall_persisted_bundle_rate_limit_refuses_the_next_process() {
    let rpc = MockRpc::start().await;
    let home = IsolatedHome::new();
    provision(
        &home,
        &rpc.uri(),
        &[multicall_rule(
            &format!(
                "[{{ kind = \"bundle_rate_limit\", window = \"{RATE_LIMIT_WINDOW}\", max_calls = \
                 {INNER_COUNT} }}]"
            ),
            "allow",
        )],
    );
    home.write_multicall_registry(&router());

    let first = multicall(&home, &rpc.uri());
    assert_eq!(first.code, 0, "{} stderr={}", first.envelope, first.stderr);
    assert_eq!(rpc.count("sendTransaction"), 1);
    let simulations = rpc.count("simulateTransaction");

    let second = multicall(&home, &rpc.uri());
    assert_policy_gate_refusal(&second);
    assert_eq!(denied_codes(&home), ["multicall.rate_limit_exceeded"]);
    assert_eq!(
        rpc.count("simulateTransaction"),
        simulations,
        "the refusal precedes simulation"
    );
    assert_eq!(rpc.count("sendTransaction"), 1);

    let profile = home.load_profile(PROFILE);
    keyring_core::set_default_store(Arc::new(
        stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.keyring_path(),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(home.headless_key()),
            )),
        ),
    ));
    let state = stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore::new();
    stellar_agent_network::policy_state::PersistedWindowStore::at_path(
        home.path().join("policy").join(format!("{PROFILE}.window")),
    )
    .load_into(PROFILE, &profile, &state)
    .unwrap();
    let (_, calls) = state
        .query_window(
            &stellar_agent_core::policy::v1::criteria::state_store::StateKey::new(
                PROFILE,
                1,
                "rate_limit",
                RATE_LIMIT_WINDOW_SECS,
            ),
            stellar_agent_core::timefmt::now_unix_ms().unwrap(),
        )
        .unwrap();
    assert_eq!(
        calls,
        u32::try_from(INNER_COUNT).unwrap(),
        "one call per confirmed inner"
    );
}

/// An approval-required rule refuses at the policy gate: CLI multicall has
/// no approval route, so nothing is sent.
#[tokio::test]
async fn multicall_approval_rule_refuses_without_an_approval_route() {
    let rpc = MockRpc::start().await;
    let home = IsolatedHome::new();
    provision(
        &home,
        &rpc.uri(),
        &[multicall_rule("[]", "require_approval")],
    );
    home.write_multicall_registry(&router());

    let run = multicall(&home, &rpc.uri());
    assert_policy_gate_refusal(&run);
    assert!(
        run.error_message().contains("requires approval")
            && run
                .error_message()
                .contains("this submission path has no approval route"),
        "{}",
        run.envelope
    );
    assert_eq!(denied_codes(&home), ["multicall.approval_required"]);
    assert_eq!(rpc.count("sendTransaction"), 0);
}

/// A V1 profile whose policy file was never signed refuses with
/// `policy.engine_unavailable`, with the audit and owner keys available.
#[tokio::test]
async fn multicall_missing_signed_policy_refuses_engine_unavailable() {
    let rpc = MockRpc::start().await;
    let home = IsolatedHome::new();
    home.init_profile(PROFILE, &["--rpc-url", &rpc.uri()]);
    home.enroll_keys(PROFILE, &signer(), &owner());
    home.write_policy(
        PROFILE,
        &policy_document(PROFILE, &[multicall_rule("[]", "allow")]),
    );
    home.write_multicall_registry(&router());

    let run = multicall(&home, &rpc.uri());
    assert_eq!(run.code, 1, "{} stderr={}", run.envelope, run.stderr);
    assert_eq!(
        run.error_code(),
        "policy.engine_unavailable",
        "{}",
        run.envelope
    );
    assert_eq!(rpc.count("sendTransaction"), 0);
}
