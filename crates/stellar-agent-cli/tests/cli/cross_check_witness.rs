//! Offline process tests: the `cross_check` outcome a signing or submitting
//! stage of `pay` reports, in JSON and in text output.
//!
//! Driven as subprocesses of the real `stellar-agent` binary against a
//! persisted profile whose primary and oracle are loopback endpoints, so the
//! printed envelope and the text lines are the ones an operator sees.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::profile::{loader, schema::Profile};
use stellar_agent_test_support::signed_envelope::{
    TESTNET_PASSPHRASE, account_id_for_seed, get_network_result, send_transaction_hash_hex,
};
use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The headless keyring key the child processes use, so no child can reach
/// the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// The payment destination.
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

/// Answers the reads, the send, and the confirmation of the classic verbs
/// for the ledger entries it holds.
#[derive(Clone)]
struct Ledger {
    entries: Vec<(String, String)>,
}

impl Ledger {
    /// Funded accounts, each signed by its own master key, plus `extra`
    /// `(key, entry)` pairs.
    fn new(accounts: &[&str], extra: &[(String, String)]) -> Self {
        let mut entries: Vec<(String, String)> = accounts
            .iter()
            .map(|a| {
                (
                    account_ledger_key_xdr(a),
                    account_entry_xdr(a, 100_000_000_000, 0),
                )
            })
            .collect();
        entries.extend(extra.iter().cloned());
        Self { entries }
    }

    async fn serve(&self) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(self.clone())
            .mount(&server)
            .await;
        server
    }
}

impl Respond for Ledger {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let fees = json!({
            "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
            "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
            "p80": "100", "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "10", "ledgerCount": 5
        });
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(TESTNET_PASSPHRASE),
            "getLedgerEntries" => {
                let keys: Vec<&str> = body["params"]["keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                let entries: Vec<Value> = self
                    .entries
                    .iter()
                    .filter(|(key, _)| keys.contains(&key.as_str()))
                    .map(
                        |(key, xdr)| json!({"key": key, "xdr": xdr, "lastModifiedLedgerSeq": 1000}),
                    )
                    .collect();
                json!({"entries": entries, "latestLedger": 1001})
            }
            "getFeeStats" => json!({
                "sorobanInclusionFee": fees, "inclusionFee": fees, "latestLedger": 1001
            }),
            "sendTransaction" => json!({
                "hash": send_transaction_hash_hex(&body, TESTNET_PASSPHRASE),
                "status": "PENDING", "latestLedger": 1001, "latestLedgerCloseTime": "1700000000"
            }),
            "getTransaction" => json!({
                "status": "SUCCESS", "txHash": body["params"]["hash"], "ledger": 1005,
                "createdAt": "1700000005", "latestLedger": 1006, "oldestLedger": 1
            }),
            "getHealth" => json!({
                "status": "healthy", "latestLedger": 2000, "oldestLedger": 1,
                "ledgerRetentionWindow": 1999
            }),
            "getLedgers" => json!({
                "latestLedger": 2000, "oldestLedger": 1, "latestLedgerCloseTime": "100",
                "oldestLedgerCloseTime": "1", "cursor": "2000", "ledgers": []
            }),
            other => panic!("unexpected RPC method {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    }
}

/// Writes the persisted profile `name` reading through `primary` and
/// witnessing through `oracle`, and mints its audit key.
fn write_profile(home: &Path, name: &str, primary: &str, oracle: &str) {
    let mut wallet = stellar_agent_core::profile::schema::WalletConfig::default();
    wallet.mlock_required = stellar_agent_core::wallet::MlockRequired::Warn;
    let profile = Profile::builder_testnet_named(
        name,
        "stellar-agent-signer",
        name,
        "stellar-agent-nonce",
        name,
    )
    .policy_engine(stellar_agent_core::profile::schema::PolicyEngineKind::Noop)
    .wallet(wallet)
    .rpc_url(primary)
    .oracle_provider_url(Some(url::Url::parse(oracle).unwrap()))
    .audit_log_path(home.join(format!("audit/{name}.jsonl")))
    .build();
    loader::save_to_dir(name, &profile, &home.join("profiles")).unwrap();
    let (code, stdout) = run(home, &["profile", "rotate-audit-key", name], None);
    assert_eq!(code, 0, "{stdout}");
}

/// Runs the binary with `args`, the secret of `signer` in
/// `CROSS_CHECK_SIGNER` when given, and returns `(exit_code, stdout)`.
fn run(home: &Path, args: &[&str], signer: Option<[u8; 32]>) -> (i32, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY);
    if let Some(seed) = signer {
        command.env(
            "CROSS_CHECK_SIGNER",
            stellar_strkey::ed25519::PrivateKey(seed)
                .as_unredacted()
                .to_string()
                .as_str(),
        );
    }
    let output = command.output().unwrap();
    (
        output.status.code().unwrap(),
        String::from_utf8(output.stdout).unwrap(),
    )
}

/// The envelope on the last non-empty stdout line.
fn envelope(stdout: &str) -> Value {
    serde_json::from_str(stdout.lines().rfind(|l| !l.trim().is_empty()).unwrap())
        .unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

fn pay_argv<'a>(
    source: &'a str,
    name: &'a str,
    amount: &'a str,
    output: &'a str,
    extra: &[&'a str],
) -> Vec<&'a str> {
    let mut argv = vec![
        "pay",
        DEST_G,
        amount,
        "--source",
        source,
        "--secret-env",
        "CROSS_CHECK_SIGNER",
        "--profile",
        name,
        "--output",
        output,
    ];
    argv.extend_from_slice(extra);
    argv
}

/// A full payment reports the passed witness in JSON and prints its line in
/// text output; `--build-only` reports none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn pay_reports_the_cross_check_in_json_and_text() {
    const SEED: [u8; 32] = [0x91; 32];
    let source = account_id_for_seed(SEED);
    let ledger = Ledger::new(&[&source, DEST_G], &[]);
    let primary = ledger.serve().await;
    let oracle = ledger.serve().await;
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), "pay-witness", &primary.uri(), &oracle.uri());

    let (code, stdout) = run(
        home.path(),
        &pay_argv(&source, "pay-witness", "1 XLM", "json", &[]),
        Some(SEED),
    );
    assert_eq!(code, 0, "{stdout}");
    let printed = envelope(&stdout);
    assert_eq!(
        printed["data"]["cross_check"],
        json!({"status": "passed", "provider": oracle.uri(), "ledger": 1001}),
        "{printed}"
    );

    let (code, stdout) = run(
        home.path(),
        &pay_argv(&source, "pay-witness", "2 XLM", "table", &[]),
        Some(SEED),
    );
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains(&format!(
            "Cross-check: passed (oracle {}, ledger 1001)",
            oracle.uri()
        )),
        "{stdout}"
    );

    let (code, stdout) = run(
        home.path(),
        &pay_argv(&source, "pay-witness", "3 XLM", "json", &["--build-only"]),
        Some(SEED),
    );
    assert_eq!(code, 0, "{stdout}");
    let printed = envelope(&stdout);
    assert!(printed["data"].get("cross_check").is_none(), "{printed}");
    let (code, stdout) = run(
        home.path(),
        &pay_argv(&source, "pay-witness", "3 XLM", "table", &["--build-only"]),
        Some(SEED),
    );
    assert_eq!(code, 0, "{stdout}");
    assert!(!stdout.contains("Cross-check:"), "{stdout}");
}

/// A sign-only payment prints the witness line beside the signed envelope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn pay_sign_reports_the_cross_check_in_text() {
    const SEED: [u8; 32] = [0x92; 32];
    let source = account_id_for_seed(SEED);
    let ledger = Ledger::new(&[&source, DEST_G], &[]);
    let primary = ledger.serve().await;
    let oracle = ledger.serve().await;
    let home = tempfile::tempdir().unwrap();
    write_profile(
        home.path(),
        "pay-sign-witness",
        &primary.uri(),
        &oracle.uri(),
    );
    let (code, stdout) = run(
        home.path(),
        &pay_argv(
            &source,
            "pay-sign-witness",
            "1 XLM",
            "json",
            &["--build-only"],
        ),
        Some(SEED),
    );
    assert_eq!(code, 0, "{stdout}");
    let built = envelope(&stdout);
    let xdr = built["data"]["envelope_xdr"].as_str().unwrap();
    let (code, stdout) = run(
        home.path(),
        &pay_argv(
            &source,
            "pay-sign-witness",
            "1 XLM",
            "table",
            &["--sign-only", xdr],
        ),
        Some(SEED),
    );
    assert_eq!(code, 0, "{stdout}");
    assert!(
        stdout.contains(&format!(
            "Cross-check: passed (oracle {}, ledger 1001)",
            oracle.uri()
        )),
        "{stdout}"
    );
}
