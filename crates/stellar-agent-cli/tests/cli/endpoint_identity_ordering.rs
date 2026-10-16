//! Offline process tests: `pay`, `claim --submit-only`, and sponsored
//! `accounts create` ask the endpoint which network it serves. They ask in
//! every stage that reads from it, before the first request whose answer they
//! sign or gate on.
//!
//! Driven as subprocesses of the real `stellar-agent` binary so the printed
//! error envelope is the one an operator sees. The mock endpoint reports a
//! third network and answers every read the verbs make: the accounts, the fee
//! statistics, and the reconcile's transaction lookups. A check placed after
//! any of those reads would leave the read in the trace, so a refusal whose
//! trace is exactly `["getNetwork"]` shows the check came first.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_test_support::signed_envelope::{
    TESTNET_PASSPHRASE, account_id_for_seed, get_network_result, ledger_entries_result_for,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

/// The headless keyring key the child processes use, as URL-safe base64 of
/// the bytes 0 to 31, so no child can reach the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// The network the mock endpoint reports when it serves neither testnet nor
/// mainnet.
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// The payment destination; the endpoint answers for it too.
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

// ─────────────────────────────────────────────────────────────────────────────
// Mock RPC
// ─────────────────────────────────────────────────────────────────────────────

/// Reports `network` from `getNetwork` and answers every read the verbs make:
/// the accounts in `accounts`, fee statistics, and a transaction the endpoint
/// has no record of.
#[derive(Clone)]
struct Rpc {
    network: Arc<Mutex<String>>,
    accounts: Vec<String>,
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let fees = json!({
            "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
            "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
            "p80": "100", "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "10", "ledgerCount": 5
        });
        let result = match body["method"].as_str().unwrap() {
            "getNetwork" => get_network_result(&self.network.lock().unwrap()),
            "getLedgerEntries" => {
                let raw = String::from_utf8_lossy(&request.body);
                let present: Vec<&str> = self
                    .accounts
                    .iter()
                    .filter(|account| {
                        raw.contains(
                            &stellar_agent_test_support::xdr_fixtures::account_ledger_key_xdr(
                                account,
                            ),
                        )
                    })
                    .map(String::as_str)
                    .collect();
                ledger_entries_result_for(&present)
            }
            "getFeeStats" => json!({
                "sorobanInclusionFee": fees, "inclusionFee": fees, "latestLedger": 1001
            }),
            "getTransaction" => json!({
                "status": "NOT_FOUND", "latestLedger": 2000, "oldestLedger": 1
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
            .set_body_json(json!({ "jsonrpc": "2.0", "id": body["id"], "result": result }))
    }
}

/// Starts an endpoint reporting `passphrase` and answering for `accounts`.
async fn start(passphrase: &str, accounts: &[&str]) -> (MockServer, Rpc) {
    let rpc = Rpc {
        network: Arc::new(Mutex::new(passphrase.to_owned())),
        accounts: accounts.iter().map(|a| (*a).to_owned()).collect(),
    };
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(rpc.clone())
        .mount(&server)
        .await;
    (server, rpc)
}

/// The JSON-RPC methods `server` received, in order.
async fn methods(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .iter()
        .map(|request| {
            serde_json::from_slice::<Value>(&request.body).unwrap()["method"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI driver
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the binary with `args` against an isolated home and returns
/// `(exit_code, stdout_envelope)`.
fn run_cli(home: &Path, args: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .output()
        .expect("stellar-agent binary must run");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let last = stdout
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("expected an envelope on stdout; stderr={stderr}"));
    let json: Value = serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("stdout line must be JSON ({e}): {last}"));
    (output.status.code().expect("exit code"), json)
}

/// Asserts the run refused with the endpoint-mismatch code, having made the
/// endpoint check and no other request.
async fn assert_refused_before_any_read(
    label: &str,
    code: i32,
    envelope: &Value,
    server: &MockServer,
) {
    assert_eq!(code, 1, "{label} must refuse: {envelope}");
    assert_eq!(
        envelope["error"]["code"], "network.endpoint_network_mismatch",
        "{label} must refuse with the endpoint-mismatch code: {envelope}"
    );
    assert_eq!(
        methods(server).await,
        ["getNetwork"],
        "{label}: the endpoint check precedes every read"
    );
}

/// The arguments of a 1 XLM payment from the account of `seed` through
/// `rpc_url`, with `extra` appended.
fn pay_argv(seed: [u8; 32], rpc_url: &str, extra: &[&str]) -> Vec<String> {
    let mut argv: Vec<String> = [
        "pay",
        DEST_G,
        "1 XLM",
        "--source",
        &account_id_for_seed(seed),
        "--network",
        "testnet",
        "--rpc-url",
        rpc_url,
        "--output",
        "json",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    argv.extend(extra.iter().map(|s| (*s).to_owned()));
    argv
}

fn as_strs(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// pay
// ─────────────────────────────────────────────────────────────────────────────

/// The full pipeline and `--build-only` refuse an endpoint serving another
/// network before the fee, sequence, and destination reads, with the fixed
/// fee and with the automatic fee.
#[tokio::test]
async fn pay_refuses_another_network_before_the_build_reads() {
    const SEED: [u8; 32] = [0x31; 32];
    let source = account_id_for_seed(SEED);
    for (label, extra) in [
        ("full, fixed fee", vec!["--fee", "100"]),
        ("full, automatic fee", vec!["--fee", "auto"]),
        (
            "build-only, fixed fee",
            vec!["--fee", "100", "--build-only"],
        ),
        (
            "build-only, automatic fee",
            vec!["--fee", "auto", "--build-only"],
        ),
    ] {
        let (server, _rpc) = start(FUTURENET_PASSPHRASE, &[&source, DEST_G]).await;
        let home = tempfile::tempdir().unwrap();
        let argv = pay_argv(SEED, &server.uri(), &extra);
        let (code, envelope) = run_cli(home.path(), &as_strs(&argv));
        assert_refused_before_any_read(&format!("pay {label}"), code, &envelope, &server).await;
    }
}

/// `--sign-only` with an envelope it decodes refuses an endpoint serving
/// another network before the account reads its gate takes.
#[tokio::test]
async fn pay_sign_only_refuses_another_network_before_the_gate_reads() {
    let envelope = stellar_agent_test_support::SignedTestEnvelope::for_source([0x32; 32]);
    let (server, _rpc) = start(
        FUTURENET_PASSPHRASE,
        &[envelope.source(), envelope.destination()],
    )
    .await;
    let home = tempfile::tempdir().unwrap();
    let argv = pay_argv(
        [0x32; 32],
        &server.uri(),
        &["--sign-only", envelope.envelope_xdr()],
    );
    let (code, printed) = run_cli(home.path(), &as_strs(&argv));
    assert_refused_before_any_read("pay --sign-only", code, &printed, &server).await;
}

/// The endpoint refusal precedes the source account's absence: with the
/// endpoint on testnet the run ends on the missing account, and with the
/// endpoint on another network it ends on the endpoint check alone.
#[tokio::test]
async fn pay_endpoint_refusal_precedes_a_missing_source_account() {
    const SEED: [u8; 32] = [0x33; 32];
    let (server, rpc) = start(TESTNET_PASSPHRASE, &[DEST_G]).await;
    let home = tempfile::tempdir().unwrap();
    let argv = pay_argv(SEED, &server.uri(), &["--build-only"]);

    let (code, envelope) = run_cli(home.path(), &as_strs(&argv));
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "network.account_not_found",
        "on testnet the run reaches the source read: {envelope}"
    );

    *rpc.network.lock().unwrap() = FUTURENET_PASSPHRASE.to_owned();
    remount(&server, &rpc).await;
    let (code, envelope) = run_cli(home.path(), &as_strs(&argv));
    assert_refused_before_any_read("pay with a missing source", code, &envelope, &server).await;
}

/// The verb arguments, minus the endpoint, of three stages: the full payment
/// pipeline, and `--submit-only` of a payment and of a claim. In each, the
/// reconcile's lookup would be the first request if the endpoint check came
/// later.
fn reconciling_stages(profile: &str) -> Vec<(&'static str, Vec<String>)> {
    let payment = stellar_agent_test_support::SignedTestEnvelope::for_source([0x34; 32]);
    let claim = stellar_agent_test_support::SignedTestEnvelope::builder([0x34; 32])
        .claim_claimable_balance([0xab; 32])
        .build();
    let common = |verb: Vec<&str>| -> Vec<String> {
        verb.into_iter()
            .chain([
                "--profile",
                profile,
                "--network",
                "testnet",
                "--output",
                "json",
            ])
            .map(str::to_owned)
            .collect()
    };
    vec![
        (
            "pay",
            common(vec![
                "pay",
                DEST_G,
                "1 XLM",
                "--source",
                payment.source(),
                "--fee",
                "100",
            ]),
        ),
        (
            "pay --submit-only",
            common(vec![
                "pay",
                payment.destination(),
                "1 XLM",
                "--source",
                payment.source(),
                "--submit-only",
                payment.envelope_xdr(),
            ]),
        ),
        (
            "claim --submit-only",
            common(vec![
                "claim",
                "abababababababababababababababababababababababababababababababab",
                "--source",
                claim.source(),
                "--submit-only",
                claim.envelope_xdr(),
            ]),
        ),
    ]
}

/// Saves a V1 profile named `name` on `rpc_url` under `home`, and records a
/// reservation for `source` old enough to reconcile in the profile's window
/// file, under the keyring store the child processes read.
fn v1_profile_with_due_reservation(home: &Path, name: &str, rpc_url: &str, source: &str) {
    use stellar_agent_core::policy::v1::criteria::state_store::{
        StateKey, WindowEntry, WindowLimit,
    };
    use stellar_agent_core::profile::schema::{PolicyEngineKind, Profile};
    use stellar_agent_headless_keyring::{crypto::ProtectionMode, store::HeadlessStore};
    use stellar_agent_network::policy_state::{PersistedWindowStore, WindowReservation};

    let _home_guard = stellar_agent_test_support::StellarAgentHomeGuard::new(home);
    let profile = Profile::builder_testnet_named(
        name,
        "stellar-agent-signer",
        name,
        "stellar-agent-nonce",
        name,
    )
    .policy_engine(PolicyEngineKind::V1)
    .rpc_url(rpc_url)
    .audit_log_path(home.join(format!("audit/{name}.jsonl")))
    .build();
    stellar_agent_core::profile::loader::save_to_dir(name, &profile, &home.join("profiles"))
        .unwrap();
    keyring_core::set_default_store(Arc::new(HeadlessStore::new(
        home.join("headless-keyring/store.keyring"),
        ProtectionMode::EnvKey(Arc::new(Zeroizing::new(std::array::from_fn(|index| {
            u8::try_from(index).unwrap()
        })))),
    )));
    let now = stellar_agent_core::timefmt::now_unix_ms().unwrap();
    let since = now - 3_600_000;
    PersistedWindowStore::for_profile(name)
        .record_pending(
            &profile,
            &[WindowEntry::new(
                StateKey::new(name, 1, "native", 86_400),
                since,
                10_000_000,
                WindowLimit::Amount {
                    asset: "native".to_owned(),
                    window: "1d".to_owned(),
                    max_stroops: 1_000_000_000,
                },
            )],
            &WindowReservation {
                id: "7".repeat(64),
                tx_hash: "7".repeat(64),
                source: source.to_owned(),
                sequence: 4_242,
                max_time: 0,
                pending_since_ms: since,
                submission_ledger: 1_500,
                operator_required: false,
            },
        )
        .expect("the reservation is recorded");
}

/// Mounts `rpc` on `server` again with an empty request trace.
async fn remount(server: &MockServer, rpc: &Rpc) {
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(rpc.clone())
        .mount(server)
        .await;
}

/// On a V1 profile with a reservation old enough to reconcile, the full
/// payment pipeline and `--submit-only` of a payment and of a claim check the
/// endpoint before the reconcile's transaction lookup.
///
/// The first run of each stage, on testnet, shows the reconcile does look the
/// reservation up right after the endpoint check. The second, on another
/// network, shows the check refuses before it.
#[tokio::test]
#[serial]
async fn the_endpoint_check_precedes_the_reconcile_lookup_of_a_due_reservation() {
    const NAME: &str = "endpoint-v1-reconcile";
    let source = account_id_for_seed([0x34; 32]);
    for (label, argv) in reconciling_stages(NAME) {
        let (server, rpc) = start(TESTNET_PASSPHRASE, &[&source, DEST_G]).await;
        let home = tempfile::tempdir().unwrap();
        v1_profile_with_due_reservation(home.path(), NAME, &server.uri(), &source);
        let mut argv = argv;
        argv.extend(["--rpc-url".to_owned(), server.uri()]);

        let (_code, _envelope) = run_cli(home.path(), &as_strs(&argv));
        let reached = methods(&server).await;
        assert_eq!(
            reached.get(..2),
            Some(["getNetwork".to_owned(), "getTransaction".to_owned()].as_slice()),
            "{label}: on testnet the reconcile looks the due reservation up right after \
             the endpoint check: {reached:?}"
        );

        *rpc.network.lock().unwrap() = FUTURENET_PASSPHRASE.to_owned();
        remount(&server, &rpc).await;
        let (code, envelope) = run_cli(home.path(), &as_strs(&argv));
        assert_refused_before_any_read(
            &format!("{label} on a V1 profile"),
            code,
            &envelope,
            &server,
        )
        .await;
    }
}

/// The full payment pipeline checks the endpoint, then reconciles, then
/// checks `--fee`. On a V1 profile with a due reservation and a malformed
/// `--fee`, an endpoint serving another network ends the run on the mismatch
/// alone. On testnet the reconcile's lookup comes first and the run then
/// refuses on the fee.
#[tokio::test]
#[serial]
async fn a_malformed_fee_follows_the_endpoint_check_and_the_reconcile() {
    const NAME: &str = "endpoint-v1-malformed-fee";
    let source = account_id_for_seed([0x36; 32]);
    let (server, rpc) = start(FUTURENET_PASSPHRASE, &[&source, DEST_G]).await;
    let home = tempfile::tempdir().unwrap();
    v1_profile_with_due_reservation(home.path(), NAME, &server.uri(), &source);
    let uri = server.uri();
    let argv = [
        "pay",
        DEST_G,
        "1 XLM",
        "--source",
        &source,
        "--fee",
        "not-a-fee",
        "--profile",
        NAME,
        "--network",
        "testnet",
        "--rpc-url",
        &uri,
        "--output",
        "json",
    ];

    let (code, envelope) = run_cli(home.path(), &argv);
    assert_refused_before_any_read("pay with a malformed --fee", code, &envelope, &server).await;

    *rpc.network.lock().unwrap() = TESTNET_PASSPHRASE.to_owned();
    remount(&server, &rpc).await;
    let (code, envelope) = run_cli(home.path(), &argv);
    let reached = methods(&server).await;
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "validation.amount_malformed",
        "on testnet the run refuses on the fee: {envelope}"
    );
    assert_eq!(
        reached.get(..2),
        Some(["getNetwork".to_owned(), "getTransaction".to_owned()].as_slice()),
        "the reconcile looks the due reservation up before the fee check: {reached:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// accounts create
// ─────────────────────────────────────────────────────────────────────────────

/// A sponsored creation refuses an endpoint serving another network before
/// the sponsor read, with the fixed fee and with the automatic fee.
#[tokio::test]
async fn sponsored_creation_refuses_another_network_before_the_sponsor_read() {
    let sponsor = account_id_for_seed([0x35; 32]);
    for fee in ["100", "auto"] {
        let (server, _rpc) = start(FUTURENET_PASSPHRASE, &[&sponsor]).await;
        let home = tempfile::tempdir().unwrap();
        let (code, envelope) = run_cli(
            home.path(),
            &[
                "accounts",
                "create",
                DEST_G,
                "--sponsor",
                &sponsor,
                "--starting-balance",
                "1 XLM",
                "--fee",
                fee,
                "--network",
                "testnet",
                "--rpc-url",
                &server.uri(),
                "--output",
                "json",
            ],
        );
        assert_refused_before_any_read(
            &format!("accounts create, fee {fee}"),
            code,
            &envelope,
            &server,
        )
        .await;
    }
}
