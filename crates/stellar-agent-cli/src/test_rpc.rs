//! A mocked Stellar RPC endpoint for the command tests, answering by JSON-RPC
//! method, the observations the endpoint tests make, and the zero-config setup
//! those tests run under.
//!
//! The endpoint reports one network passphrase, which a test can change
//! between calls. It answers `getLedgerEntries` for the accounts and the
//! extra ledger entries it was given, quotes fixed fee statistics, accepts
//! every send with the hash of the transaction it was handed, and confirms
//! every transaction. `getHealth` and `getLedgers` describe a ledger range
//! that covers every submission the tests make.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only fixture; a malformed request panics the calling test"
)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use stellar_agent_core::profile::caip2::TESTNET_PASSPHRASE;
use stellar_agent_core::profile::loader::ProfileLoadError;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_test_support::signed_envelope::{get_network_result, send_transaction_hash_hex};
use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The native balance every account the endpoint reports holds: 10 000 XLM.
const ACCOUNT_BALANCE_STROOPS: i64 = 100_000_000_000;

/// A mocked endpoint for the classic value verbs.
#[derive(Clone)]
pub(crate) struct ClassicRpc {
    network: Arc<Mutex<String>>,
    /// `(ledger key XDR, entry XDR)` per answerable ledger entry.
    entries: Arc<Vec<(String, String)>>,
}

impl ClassicRpc {
    /// An endpoint reporting testnet and answering for each of `accounts`,
    /// funded and signed by its own master key.
    pub(crate) fn testnet(accounts: &[&str]) -> Self {
        Self {
            network: Arc::new(Mutex::new(TESTNET_PASSPHRASE.to_owned())),
            entries: Arc::new(
                accounts
                    .iter()
                    .map(|account| {
                        (
                            account_ledger_key_xdr(account),
                            account_entry_xdr(account, ACCOUNT_BALANCE_STROOPS, 0),
                        )
                    })
                    .collect(),
            ),
        }
    }

    /// Answers `getLedgerEntries` for `key` with `entry` as well.
    pub(crate) fn with_entry(mut self, key: String, entry: String) -> Self {
        Arc::make_mut(&mut self.entries).push((key, entry));
        self
    }

    /// Reports `passphrase` from every later `getNetwork`.
    pub(crate) fn report(&self, passphrase: &str) {
        *self.network.lock().unwrap() = passphrase.to_owned();
    }

    /// Starts a server answering every `POST` with this endpoint.
    pub(crate) async fn serve(&self) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(self.clone())
            .mount(&server)
            .await;
        server
    }

    fn ledger_entries(&self, body: &Value) -> Value {
        let requested: Vec<&str> = body["params"]["keys"]
            .as_array()
            .map(|keys| keys.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let entries: Vec<Value> = self
            .entries
            .iter()
            .filter(|(key, _)| requested.contains(&key.as_str()))
            .map(|(key, entry)| json!({ "key": key, "xdr": entry, "lastModifiedLedgerSeq": 1000 }))
            .collect();
        json!({ "entries": entries, "latestLedger": 1001 })
    }
}

impl Respond for ClassicRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let fees = json!({
            "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
            "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
            "p80": "100", "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "10", "ledgerCount": 5
        });
        let result = match body["method"].as_str().unwrap_or_default() {
            "getNetwork" => get_network_result(&self.network.lock().unwrap()),
            "getLedgerEntries" => self.ledger_entries(&body),
            "getFeeStats" => json!({
                "sorobanInclusionFee": fees, "inclusionFee": fees, "latestLedger": 1001
            }),
            "sendTransaction" => json!({
                "hash": send_transaction_hash_hex(&body, TESTNET_PASSPHRASE),
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1700000000"
            }),
            "getTransaction" => json!({
                "status": "SUCCESS",
                "txHash": body["params"]["hash"],
                "ledger": 1005,
                "createdAt": "1700000005",
                "latestLedger": 1006,
                "oldestLedger": 1
            }),
            "getHealth" => json!({
                "status": "healthy",
                "latestLedger": 2000,
                "oldestLedger": 1,
                "ledgerRetentionWindow": 1999
            }),
            "getLedgers" => json!({
                "latestLedger": 2000,
                "oldestLedger": 1,
                "latestLedgerCloseTime": "1700000100",
                "oldestLedgerCloseTime": "1",
                "cursor": "2000",
                "ledgers": []
            }),
            other => panic!("unexpected RPC method {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({ "jsonrpc": "2.0", "id": body["id"], "result": result }))
    }
}

/// The JSON-RPC methods `server` received, in order.
pub(crate) async fn methods(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("request recording is enabled")
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// How many `getNetwork` requests `methods` holds.
pub(crate) fn network_checks(methods: &[String]) -> usize {
    methods
        .iter()
        .filter(|m| m.as_str() == "getNetwork")
        .count()
}

/// Runs `call` and returns its output with the number of `StellarRpcClient`
/// values it built.
///
/// The command tests run on a current-thread runtime, so every client the
/// call builds is built on the test's thread and counted here.
pub(crate) async fn clients_built_by<F: Future>(call: F) -> (F::Output, usize) {
    let before = stellar_agent_network::client::constructions_on_this_thread();
    let output = call.await;
    let built = stellar_agent_network::client::constructions_on_this_thread() - before;
    (output, built)
}

/// Isolation every zero-config run needs, as one value.
///
/// The synthesized profile is named by the resolved name, which with no flag
/// and no variable is the literal `default`. Its audit log path and its audit
/// chain-root keyring coordinate are therefore the real `default` profile's.
/// Without this value a test would read and write the operator's own audit
/// log. On a host where `stellar-agent-audit-default` exists, it would also
/// acquire a writer instead of exercising the fail-open branch.
///
/// Bundles the redirected data root, the in-memory keyring store, and a
/// cleared `STELLAR_AGENT_PROFILE`. The resolver reads the ambient
/// environment, so an exported value would make the name explicit and the run
/// refuse. Callers are `#[serial]`: all three are process-global.
pub(crate) struct ZeroConfig {
    _home: stellar_agent_test_support::StellarAgentHomeGuard,
    _profile_var: stellar_agent_test_support::ProfileEnvVarGuard,
    _dir: tempfile::TempDir,
}

/// Sets up the isolation of [`ZeroConfig`] for the lifetime of the value.
pub(crate) fn zero_config() -> ZeroConfig {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let home = stellar_agent_test_support::StellarAgentHomeGuard::new(dir.path());
    let profile_var = stellar_agent_test_support::ProfileEnvVarGuard::cleared();
    stellar_agent_test_support::keyring_mock::install().expect("mock keyring store");
    ZeroConfig {
        _home: home,
        _profile_var: profile_var,
        _dir: dir,
    }
}

/// An injected loader reporting that the profile file does not exist.
///
/// Whether that becomes a synthesized profile or a refusal is decided by the
/// caller of the injected closure, keyed on the resolved name's provenance.
pub(crate) fn absent_profile_file(name: &str) -> Result<Profile, ProfileLoadError> {
    Err(ProfileLoadError::NotFound {
        name: name.to_owned(),
        path: std::path::PathBuf::from("/nonexistent"),
    })
}

/// The signer of a zero-config run: the account of `seed`, whose secret sits
/// in the environment variable `var` for the lifetime of the value.
pub(crate) struct EnvSigner {
    /// The signer's G-strkey.
    pub(crate) g: String,
    /// The environment variable that holds the signer's S-strkey.
    pub(crate) var: &'static str,
}

impl EnvSigner {
    /// Puts the secret of `seed` into `var`. The variable name is unique to
    /// its test, and the caller is `#[serial]`.
    #[allow(
        unsafe_code,
        reason = "test-only process environment mutation; serialised by #[serial]"
    )]
    pub(crate) fn new(seed: [u8; 32], var: &'static str) -> Self {
        let secret = stellar_strkey::ed25519::PrivateKey(seed)
            .as_unredacted()
            .to_string()
            .to_string();
        // SAFETY: serialised by #[serial]; the variable name is unique to its
        // test.
        unsafe {
            std::env::set_var(var, secret);
        }
        Self {
            g: stellar_agent_test_support::signed_envelope::account_id_for_seed(seed),
            var,
        }
    }
}

impl Drop for EnvSigner {
    #[allow(unsafe_code, reason = "test-only env cleanup")]
    fn drop(&mut self) {
        // SAFETY: same as `new`.
        unsafe {
            std::env::remove_var(self.var);
        }
    }
}
