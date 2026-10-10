//! `smart-account rules verify-pins`, `signers list`, and `signers refresh`
//! load no signer and run on any network, driven as subprocesses of the real
//! `stellar-agent` binary.
//!
//! # What each group observes
//!
//! - Mainnet (`mainnet_signer_free_*`): a persisted mainnet profile with a
//!   minted audit key, and neither a signer nor a source flag. Its endpoint is
//!   a [`ConnectionCounter`] that closes every connection, so the first RPC
//!   fails. The refusal names the simulation and not the source-account
//!   fetch. The simulation is the first RPC on the sentinel path, so no
//!   account fetch preceded it. The counter records at least one connection.
//! - Request shape (`signer_free_request_shape_*`): a persisted testnet
//!   profile with a minted audit key, and neither a signer nor a source flag.
//!   A plaintext mock endpoint records every request. Each simulation
//!   envelope carries the sentinel source, sequence number 1, and no
//!   signature. No request looks up an account, and none submits a
//!   transaction. The verbs succeed and record their audit rows.
//! - Explicit source (`explicit_source_*`): the request-shape setup with
//!   `--source-account <G>`. The verbs look up `G` and simulate from it.
//! - Malformed source (`malformed_source_*`): a malformed `--source-account`
//!   on a mainnet profile whose audit key was never minted. The verbs refuse
//!   with `validation.address_invalid`, not `audit.chain_key_unavailable`,
//!   and no connection reaches the endpoint. The validation precedes the
//!   audit writer and every RPC.
//! - Audit key (`audit_key_required_*`): a persisted mainnet profile whose
//!   audit key was never minted, and no source flag. The verbs refuse with
//!   `audit.chain_key_unavailable`, and no connection reaches the endpoint.
//!   The read context opens the fail-closed audit writer, so a persisted
//!   profile never records rows into an unkeyed chain.
//!
//! The mainnet group shows that the verbs reach the endpoint on mainnet. The
//! request-shape group shows what they send, on a testnet endpoint. A mainnet
//! endpoint is `https://`, and the binary's RPC clients verify it with the
//! platform TLS verifier, so no offline test reads a mainnet request body.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` points each child at a temporary data root, and every
//! child runs the headless keyring backend under [`HEADLESS_KEY`]. No run
//! reaches the login keychain or a host profile. Profiles are written
//! in-process through `stellar-agent-core`'s loader. A minted audit key and
//! its binding are written in-process into the headless store the child
//! opens, under the same key. Every test holds the serial lock, because that
//! in-process store is the process-global default.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::audit_log::AuditBinding;
use stellar_agent_core::constants::SIMULATE_SENTINEL_G;
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::KeyringAuditBindingStore;
use stellar_agent_smart_account::managers::signers::build_delegated_signer_scval;
use stellar_agent_test_support::ConnectionCounter;
use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
use stellar_xdr::{
    LedgerKey, Limits, MuxedAccount, ReadXdr, ScMap, ScMapEntry, ScSymbol, ScVal, ScVec,
    TransactionEnvelope, TransactionV1Envelope, Uint256, WriteXdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The headless keyring key of every child and of the in-process store.
const HEADLESS_KEY: [u8; 32] = [0x5a; 32];

/// The smart account every run names.
const ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// The context rule every run names; the fixtures record no row for it.
const RULE_ID: u32 = 1;

/// The profile every fixture writes and every run names.
const PROFILE: &str = "signer-free";

/// The account the explicit-source runs name, distinct from the sentinel.
const EXPLICIT_SOURCE_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// The `Delegated` signer of the mock endpoint's rule.
const DELEGATED_SIGNER_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// A `--source-account` value that is not a G-strkey.
const MALFORMED_SOURCE: &str = "not-a-g-strkey";

/// The three signer-free inspection verbs.
#[derive(Clone, Copy, Debug)]
enum Verb {
    VerifyPins,
    SignersList,
    SignersRefresh,
}

impl Verb {
    /// The subcommand path of the verb.
    fn subcommand(self) -> [&'static str; 3] {
        match self {
            Self::VerifyPins => ["smart-account", "rules", "verify-pins"],
            Self::SignersList => ["smart-account", "signers", "list"],
            Self::SignersRefresh => ["smart-account", "signers", "refresh"],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Child runner
// ─────────────────────────────────────────────────────────────────────────────

/// Output of one child invocation.
struct Run {
    code: i32,
    envelope: Value,
    stdout: String,
    stderr: String,
}

impl Run {
    /// The envelope's error code, if any.
    fn error_code(&self) -> Option<&str> {
        self.envelope["error"]["code"].as_str()
    }

    /// The envelope's error message, or the empty string.
    fn error_message(&self) -> &str {
        self.envelope["error"]["message"]
            .as_str()
            .unwrap_or_default()
    }

    /// The full output, for an assertion message.
    fn describe(&self) -> String {
        format!(
            "exit {}; stdout={}; stderr={}",
            self.code,
            self.stdout.trim(),
            self.stderr.trim()
        )
    }
}

/// Runs `verb` against the fixture profile in `home` with `extra` appended.
///
/// The child reads its data root from `STELLAR_AGENT_HOME` and runs the
/// headless keyring backend under [`HEADLESS_KEY`]; the environment
/// overlays that select another profile or endpoint are removed.
fn run(home: &Path, verb: Verb, extra: &[&str]) -> Run {
    let rule_id = RULE_ID.to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(verb.subcommand())
        .args([
            "--account",
            ACCOUNT,
            "--rule-id",
            rule_id.as_str(),
            "--profile",
            PROFILE,
        ])
        .args(extra)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL")
        .env_remove("STELLAR_AGENT_ORACLE_PROVIDER_URL")
        .env_remove("STELLAR_AGENT_MCP_SIGNER_DEFAULT")
        .output()
        .expect("stellar-agent binary must run");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON envelope; stdout={stdout} stderr={stderr}"));
    Run {
        code: output.status.code().expect("process must exit with a code"),
        envelope: serde_json::from_str(line).expect("the envelope line is JSON"),
        stdout,
        stderr,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// The audit log every fixture profile names.
fn audit_log_path(home: &Path) -> PathBuf {
    home.join("audit").join(format!("{PROFILE}.jsonl"))
}

/// A `noop`-engine testnet profile whose endpoint is `rpc_url`.
fn testnet_profile(home: &Path, rpc_url: &str) -> Profile {
    Profile::builder_testnet_named(PROFILE, "s", "a", "n", "a")
        .rpc_url(rpc_url)
        .audit_log_path(audit_log_path(home))
        .with_noop_engine()
        .build()
}

/// A `noop`-engine mainnet profile whose endpoint is `rpc_url`.
fn mainnet_profile(home: &Path, rpc_url: &str) -> Profile {
    Profile::builder_mainnet_named(PROFILE, rpc_url, "s", "a", "n", "a")
        .audit_log_path(audit_log_path(home))
        .with_noop_engine()
        .build()
}

/// Persists `profile` with its audit key minted and its binding recorded.
///
/// The in-process default store is the headless store at
/// `<home>/headless-keyring/store.keyring` under [`HEADLESS_KEY`], the store
/// the child opens.
fn save_with_audit_key(home: &Path, profile: &Profile) {
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(HEADLESS_KEY),
            )),
        ));
    keyring_core::set_default_store(store);
    let coordinate = &profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&URL_SAFE_NO_PAD.encode([0x2c; 32]))
        .unwrap();
    KeyringAuditBindingStore::for_profile(PROFILE)
        .store(&AuditBinding::for_profile(profile))
        .unwrap();
    save_new_to_dir(PROFILE, profile, &home.join("profiles")).unwrap();
}

/// Persists `profile` without minting its audit key.
fn save_without_audit_key(home: &Path, profile: &Profile) {
    save_new_to_dir(PROFILE, profile, &home.join("profiles")).unwrap();
}

/// The audit rows of the fixture profile's log, in order.
fn audit_rows(home: &Path) -> Vec<Value> {
    std::fs::read_to_string(audit_log_path(home))
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("an audit row is JSON"))
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock endpoint
// ─────────────────────────────────────────────────────────────────────────────

/// The mock endpoint's context rule: one `Delegated` signer and no policies.
fn delegated_rule() -> ScVal {
    let entry = |key: &str, val| ScMapEntry {
        key: ScVal::Symbol(ScSymbol(key.try_into().unwrap())),
        val,
    };
    let vec_of = |items: Vec<ScVal>| ScVal::Vec(Some(ScVec(items.try_into().unwrap())));
    ScVal::Map(Some(ScMap(
        vec![
            entry("id", ScVal::U32(RULE_ID)),
            entry("policies", vec_of(vec![])),
            entry("signer_ids", vec_of(vec![ScVal::U32(0)])),
            entry(
                "signers",
                vec_of(vec![
                    build_delegated_signer_scval(DELEGATED_SIGNER_G).unwrap(),
                ]),
            ),
            entry("valid_until", ScVal::Void),
        ]
        .try_into()
        .unwrap(),
    )))
}

/// Answers every `simulateTransaction` with [`delegated_rule`]. A
/// `getLedgerEntries` request receives the account entry of `account` for
/// that account's key and no entry for any other key. Every other method is
/// answered with a JSON-RPC error.
struct RuleResponder {
    rule_xdr: String,
    account: Option<(String, String)>,
}

impl RuleResponder {
    /// A responder that knows no account.
    fn without_account() -> Self {
        Self {
            rule_xdr: delegated_rule().to_xdr_base64(Limits::none()).unwrap(),
            account: None,
        }
    }

    /// A responder that answers the account lookup of `g`.
    fn with_account(g: &str) -> Self {
        Self {
            account: Some((
                account_ledger_key_xdr(g),
                account_entry_xdr(g, 100_000_000, 0),
            )),
            ..Self::without_account()
        }
    }
}

impl Respond for RuleResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let id = body["id"].clone();
        let reply = match body["method"].as_str().unwrap_or_default() {
            "simulateTransaction" => json!({"jsonrpc": "2.0", "id": id, "result": {
                "results": [{"auth": [], "xdr": self.rule_xdr}],
                "latestLedger": 1000
            }}),
            "getLedgerEntries" => {
                let entries: Vec<Value> = body["params"]["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|key| {
                        let (account_key, entry) = self.account.as_ref()?;
                        (key.as_str() == Some(account_key.as_str())).then(|| {
                            json!({"key": account_key, "xdr": entry, "lastModifiedLedgerSeq": 100})
                        })
                    })
                    .collect();
                json!({"jsonrpc": "2.0", "id": id, "result": {
                    "entries": entries,
                    "latestLedger": 1000
                }})
            }
            other => json!({"jsonrpc": "2.0", "id": id, "error": {
                "code": -32601,
                "message": format!("the fixture does not serve {other}")
            }}),
        };
        ResponseTemplate::new(200).set_body_json(reply)
    }
}

/// Starts a mock endpoint answering with `responder`.
async fn start_mock(responder: RuleResponder) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(responder)
        .mount(&server)
        .await;
    server
}

/// What the mock endpoint received, decoded.
struct Recorded {
    /// Each request's JSON-RPC method, in arrival order.
    methods: Vec<String>,
    /// Every key of every `getLedgerEntries` request, as XDR base64 beside
    /// its decoded form.
    ledger_keys: Vec<(String, LedgerKey)>,
    /// Every `simulateTransaction` envelope.
    simulations: Vec<TransactionV1Envelope>,
}

impl Recorded {
    /// The keys among [`Recorded::ledger_keys`] that name an account, as XDR
    /// base64.
    fn account_lookups(&self) -> Vec<&str> {
        self.ledger_keys
            .iter()
            .filter(|(_, key)| matches!(key, LedgerKey::Account(_)))
            .map(|(encoded, _)| encoded.as_str())
            .collect()
    }
}

/// Decodes every request `server` recorded.
async fn recorded(server: &MockServer) -> Recorded {
    let mut recorded = Recorded {
        methods: Vec::new(),
        ledger_keys: Vec::new(),
        simulations: Vec::new(),
    };
    for request in server
        .received_requests()
        .await
        .expect("the mock server records requests")
    {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let method = body["method"].as_str().unwrap().to_owned();
        match method.as_str() {
            "getLedgerEntries" => {
                for key in body["params"]["keys"].as_array().unwrap() {
                    let encoded = key.as_str().unwrap().to_owned();
                    let decoded = LedgerKey::from_xdr_base64(&encoded, Limits::none())
                        .unwrap_or_else(|e| {
                            panic!("a recorded ledger key decodes: {encoded}: {e}")
                        });
                    recorded.ledger_keys.push((encoded, decoded));
                }
            }
            "simulateTransaction" => {
                let envelope = TransactionEnvelope::from_xdr_base64(
                    body["params"]["transaction"].as_str().unwrap(),
                    Limits::none(),
                )
                .unwrap();
                let TransactionEnvelope::Tx(envelope) = envelope else {
                    panic!("a simulation envelope is a version 1 transaction")
                };
                recorded.simulations.push(envelope);
            }
            _ => {}
        }
        recorded.methods.push(method);
    }
    recorded
}

/// The raw ed25519 bytes of a G-strkey.
fn account_bytes(g: &str) -> [u8; 32] {
    stellar_strkey::ed25519::PublicKey::from_string(g)
        .expect("a valid G-strkey")
        .0
}

/// The source account bytes of a simulation envelope.
fn simulation_source(envelope: &TransactionV1Envelope) -> [u8; 32] {
    let MuxedAccount::Ed25519(Uint256(source)) = &envelope.tx.source_account else {
        panic!("a simulation source is an ed25519 account")
    };
    *source
}

// ─────────────────────────────────────────────────────────────────────────────
// Mainnet: the verbs reach the endpoint
// ─────────────────────────────────────────────────────────────────────────────

/// A mainnet run with neither a signer nor a source flag reaches the
/// endpoint, and its first RPC is the simulation.
fn mainnet_signer_free_case(verb: Verb) {
    let counter = ConnectionCounter::start().expect("loopback connection counter");
    let home = tempfile::tempdir().unwrap();
    save_with_audit_key(
        home.path(),
        &mainnet_profile(home.path(), &counter.https_uri()),
    );

    let run = run(home.path(), verb, &[]);
    let connections = counter.accepted().expect("connection count");

    assert_eq!(
        run.code,
        1,
        "{verb:?}: {connections} connection(s); {}",
        run.describe()
    );
    let message = run.error_message();
    assert!(
        !message.contains("source-account fetch failed"),
        "{verb:?}: no account fetch precedes the simulation: {message}"
    );
    assert_eq!(
        run.error_code(),
        Some("sa.auth_entry_construction_failed"),
        "{verb:?}: {connections} connection(s); {}",
        run.describe()
    );
    assert!(
        message.contains("simulate_transaction_envelope failed"),
        "{verb:?}: the first RPC is the simulation: {message}"
    );
    assert!(
        connections >= 1,
        "{verb:?}: the run reaches the mainnet endpoint"
    );
}

#[test]
#[serial]
fn mainnet_signer_free_verify_pins() {
    mainnet_signer_free_case(Verb::VerifyPins);
}

#[test]
#[serial]
fn mainnet_signer_free_signers_list() {
    mainnet_signer_free_case(Verb::SignersList);
}

#[test]
#[serial]
fn mainnet_signer_free_signers_refresh() {
    mainnet_signer_free_case(Verb::SignersRefresh);
}

// ─────────────────────────────────────────────────────────────────────────────
// Request shape: what the verbs send
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts the success envelope and audit rows of a request-shape or
/// explicit-source run.
fn assert_outcome(home: &Path, verb: Verb, run: &Run) {
    assert_eq!(run.code, 0, "{verb:?}: {}", run.describe());
    assert_eq!(
        run.envelope["ok"],
        true,
        "{verb:?}: a success envelope: {}",
        run.describe()
    );
    let data = &run.envelope["data"];
    let baseline_reason = match verb {
        Verb::VerifyPins => {
            assert_eq!(data["verifier_pin_status"], "no_contracts", "{data}");
            assert_eq!(data["policy_pin_status"], "no_contracts", "{data}");
            None
        }
        Verb::SignersList => {
            assert_eq!(data["baseline"], "none", "{data}");
            Some("first_observation")
        }
        Verb::SignersRefresh => {
            assert_eq!(data["previous_baseline"], "none", "{data}");
            Some("explicit_refresh")
        }
    };
    let baselines: Vec<Value> = audit_rows(home)
        .into_iter()
        .filter(|row| row["kind"] == "sa_signer_set_baselined_v2")
        .collect();
    match baseline_reason {
        None => assert!(
            baselines.is_empty(),
            "{verb:?} records no baseline: {baselines:?}"
        ),
        Some(reason) => {
            assert_eq!(baselines.len(), 1, "{verb:?}: {baselines:?}");
            assert_eq!(baselines[0]["rule_id"], RULE_ID, "{:?}", baselines[0]);
            assert_eq!(
                baselines[0]["baseline_reason"], reason,
                "{verb:?}: {:?}",
                baselines[0]
            );
        }
    }
}

/// A testnet run with neither a signer nor a source flag simulates from the
/// sentinel without an account lookup or a submission, and succeeds.
async fn signer_free_request_shape_case(verb: Verb) {
    let server = start_mock(RuleResponder::without_account()).await;
    let home = tempfile::tempdir().unwrap();
    save_with_audit_key(home.path(), &testnet_profile(home.path(), &server.uri()));

    let run = run(home.path(), verb, &[]);

    let recorded = recorded(&server).await;
    assert!(
        recorded.account_lookups().is_empty(),
        "{verb:?}: no request looks up an account: {:?}; {}",
        recorded.account_lookups(),
        run.describe()
    );
    assert!(
        !recorded.methods.iter().any(|m| m == "sendTransaction"),
        "{verb:?}: nothing is submitted: {:?}",
        recorded.methods
    );
    assert!(
        !recorded.simulations.is_empty(),
        "{verb:?}: the rule read simulates; requests {:?}; {}",
        recorded.methods,
        run.describe()
    );
    let sentinel = account_bytes(SIMULATE_SENTINEL_G);
    for envelope in &recorded.simulations {
        assert_eq!(
            simulation_source(envelope),
            sentinel,
            "{verb:?}: the simulation source is the sentinel"
        );
        assert_eq!(
            envelope.tx.seq_num.0, 1,
            "{verb:?}: the sentinel's synthetic sequence 0 plus one"
        );
        assert!(
            envelope.signatures.is_empty(),
            "{verb:?}: a simulation carries no signature"
        );
    }
    assert_outcome(home.path(), verb, &run);
}

#[tokio::test]
#[serial]
async fn signer_free_request_shape_verify_pins() {
    signer_free_request_shape_case(Verb::VerifyPins).await;
}

#[tokio::test]
#[serial]
async fn signer_free_request_shape_signers_list() {
    signer_free_request_shape_case(Verb::SignersList).await;
}

#[tokio::test]
#[serial]
async fn signer_free_request_shape_signers_refresh() {
    signer_free_request_shape_case(Verb::SignersRefresh).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Explicit source: the named account is looked up and simulated from
// ─────────────────────────────────────────────────────────────────────────────

/// A testnet run with `--source-account <G>` looks up `G`, simulates from
/// it, and succeeds.
async fn explicit_source_case(verb: Verb) {
    let server = start_mock(RuleResponder::with_account(EXPLICIT_SOURCE_G)).await;
    let home = tempfile::tempdir().unwrap();
    save_with_audit_key(home.path(), &testnet_profile(home.path(), &server.uri()));

    let run = run(home.path(), verb, &["--source-account", EXPLICIT_SOURCE_G]);

    let recorded = recorded(&server).await;
    let explicit_key = account_ledger_key_xdr(EXPLICIT_SOURCE_G);
    assert!(
        recorded.account_lookups().contains(&explicit_key.as_str()),
        "{verb:?}: the explicit source is looked up: {:?}; {}",
        recorded.account_lookups(),
        run.describe()
    );
    assert!(
        recorded
            .account_lookups()
            .iter()
            .all(|key| *key == explicit_key),
        "{verb:?}: no other account is looked up: {:?}",
        recorded.account_lookups()
    );
    let explicit = account_bytes(EXPLICIT_SOURCE_G);
    assert!(
        !recorded.simulations.is_empty(),
        "{verb:?}: the rule read simulates"
    );
    assert!(
        recorded
            .simulations
            .iter()
            .all(|envelope| simulation_source(envelope) == explicit),
        "{verb:?}: every simulation runs from the explicit source"
    );
    assert!(
        !recorded.methods.iter().any(|m| m == "sendTransaction"),
        "{verb:?}: nothing is submitted: {:?}",
        recorded.methods
    );
    assert_outcome(home.path(), verb, &run);
}

#[tokio::test]
#[serial]
async fn explicit_source_verify_pins() {
    explicit_source_case(Verb::VerifyPins).await;
}

#[tokio::test]
#[serial]
async fn explicit_source_signers_list() {
    explicit_source_case(Verb::SignersList).await;
}

#[tokio::test]
#[serial]
async fn explicit_source_signers_refresh() {
    explicit_source_case(Verb::SignersRefresh).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Malformed source: refused before the audit writer and every RPC
// ─────────────────────────────────────────────────────────────────────────────

/// A malformed `--source-account` refuses with `validation.address_invalid`
/// on a mainnet profile without a minted audit key, before any connection.
fn malformed_source_case(verb: Verb) {
    let counter = ConnectionCounter::start().expect("loopback connection counter");
    let home = tempfile::tempdir().unwrap();
    save_without_audit_key(
        home.path(),
        &mainnet_profile(home.path(), &counter.https_uri()),
    );

    let run = run(home.path(), verb, &["--source-account", MALFORMED_SOURCE]);

    assert_eq!(run.code, 1, "{verb:?}: {}", run.describe());
    assert_eq!(
        run.error_code(),
        Some("validation.address_invalid"),
        "{verb:?}: the validation precedes the audit writer: {}",
        run.describe()
    );
    assert!(
        run.error_message().contains("--source-account"),
        "{verb:?}: the refusal names the flag: {}",
        run.describe()
    );
    assert_eq!(
        counter.accepted().expect("connection count"),
        0,
        "{verb:?}: no connection reaches the endpoint"
    );
}

#[test]
#[serial]
fn malformed_source_verify_pins() {
    malformed_source_case(Verb::VerifyPins);
}

#[test]
#[serial]
fn malformed_source_signers_list() {
    malformed_source_case(Verb::SignersList);
}

#[test]
#[serial]
fn malformed_source_signers_refresh() {
    malformed_source_case(Verb::SignersRefresh);
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit key: the read context opens the fail-closed audit writer
// ─────────────────────────────────────────────────────────────────────────────

/// A persisted mainnet profile without a minted audit key refuses with
/// `audit.chain_key_unavailable` when no source is given, before any
/// connection.
fn audit_key_required_case(verb: Verb) {
    let counter = ConnectionCounter::start().expect("loopback connection counter");
    let home = tempfile::tempdir().unwrap();
    save_without_audit_key(
        home.path(),
        &mainnet_profile(home.path(), &counter.https_uri()),
    );

    let run = run(home.path(), verb, &[]);
    let connections = counter.accepted().expect("connection count");

    assert_eq!(
        run.code,
        1,
        "{verb:?}: {connections} connection(s); {}",
        run.describe()
    );
    assert_eq!(
        run.error_code(),
        Some("audit.chain_key_unavailable"),
        "{verb:?}: a persisted profile needs its audit key; {connections} connection(s); {}",
        run.describe()
    );
    assert_eq!(
        connections, 0,
        "{verb:?}: no connection reaches the endpoint"
    );
}

#[test]
#[serial]
fn audit_key_required_verify_pins() {
    audit_key_required_case(Verb::VerifyPins);
}

#[test]
#[serial]
fn audit_key_required_signers_list() {
    audit_key_required_case(Verb::SignersList);
}

#[test]
#[serial]
fn audit_key_required_signers_refresh() {
    audit_key_required_case(Verb::SignersRefresh);
}
