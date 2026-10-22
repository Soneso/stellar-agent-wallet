//! RPC provider credentials through the keyring, driven as subprocesses of
//! the real `stellar-agent` binary.
//!
//! `profile enroll-rpc-credential` stores the key and names it in the primary
//! provider record; every verb on the classic path then sends it to the
//! profile's endpoint. The mock endpoint answers only a request carrying the
//! header with the stored value and answers HTTP 401 otherwise, so a verb
//! whose client lost the credential ends on the identity request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PrimaryProviderRecord, Profile, RpcCredentialPlacement,
};
use stellar_agent_test_support::signed_envelope::{
    TESTNET_PASSPHRASE, account_id_for_seed, get_network_result, ledger_entries_result_for,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The headless keyring key the child processes use, so no child can reach
/// the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

const PROFILE: &str = "rpc-credential";

/// The stored credential, sent as the value of [`HEADER`].
const VALUE: &str = "Bearer K3Y-SENTINEL-0123456789";

const HEADER: &str = "X-API-Key";

const SOURCE_SEED: [u8; 32] = [0x41; 32];

const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

const ENVELOPE_HASH: &str = "11111111111111111111111111111111111111111111111111111111111111aa";

const TX_HASH: &str = "22222222222222222222222222222222222222222222222222222222222222bb";

// Mock RPC

/// Answers every read the verbs make for a request carrying [`HEADER`] with
/// [`VALUE`], when `keyed`; answers HTTP 401 to any other request then.
#[derive(Clone)]
struct Rpc {
    keyed: bool,
    accounts: Vec<String>,
}

fn carries_credential(request: &Request) -> bool {
    request
        .headers
        .get(HEADER)
        .is_some_and(|value| value.as_bytes() == VALUE.as_bytes())
}

impl Respond for Rpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if self.keyed && !carries_credential(request) {
            return ResponseTemplate::new(401);
        }
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
                "oldestLedgerCloseTime": 1, "cursor": "2000", "ledgers": []
            }),
            other => panic!("unexpected RPC method {other}"),
        };
        ResponseTemplate::new(200)
            .set_body_json(json!({ "jsonrpc": "2.0", "id": body["id"], "result": result }))
    }
}

async fn start(keyed: bool) -> MockServer {
    let rpc = Rpc {
        keyed,
        accounts: vec![account_id_for_seed(SOURCE_SEED), DEST_G.to_owned()],
    };
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(rpc)
        .mount(&server)
        .await;
    server
}

/// The JSON-RPC methods `server` received, each with whether it carried the
/// credential.
async fn trace(server: &MockServer) -> Vec<(String, bool)> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|request| {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            (
                body["method"].as_str().unwrap().to_owned(),
                carries_credential(request),
            )
        })
        .collect()
}

fn methods(trace: &[(String, bool)]) -> Vec<&str> {
    trace.iter().map(|(method, _)| method.as_str()).collect()
}

// CLI driver and fixtures

struct Run {
    code: i32,
    json: Value,
    stdout: String,
    stderr: String,
}

fn run_cli(home: &Path, args: &[&str], stdin: Option<&[u8]>, env: &[(&str, &str)]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .envs(env.iter().copied())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("stellar-agent binary must run");
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let last = stdout
        .lines()
        .rfind(|line| !line.trim().is_empty())
        .unwrap_or_else(|| panic!("expected an envelope on stdout; stderr={stderr}"));
    let json = serde_json::from_str(last).unwrap_or_else(|e| panic!("{e}: {last}"));
    Run {
        code: output.status.code().unwrap(),
        json,
        stdout,
        stderr,
    }
}

fn assert_no_value(run: &Run) {
    for text in [&run.stdout, &run.stderr] {
        assert!(
            !text.contains("K3Y-SENTINEL"),
            "the value was printed: {text}"
        );
    }
}

/// Saves a noop-engine testnet profile on `rpc_url` with a primary record
/// for `127.0.0.1`, naming the default credential reference when `credential`
/// is set, mints its audit key, and seeds a sent-but-unanswered receipt.
fn write_profile(home: &Path, rpc_url: &str, credential: bool) {
    let mut record = PrimaryProviderRecord::new("Primary RPC", "127.0.0.1");
    if credential {
        record = record.with_credential(
            KeyringEntryRef::default_rpc_credential(
                PROFILE,
                stellar_agent_core::profile::schema::ProviderRole::Primary,
            ),
            RpcCredentialPlacement::Header {
                name: HEADER.to_owned(),
            },
        );
    }
    let mut profile = Profile::builder_testnet_named(
        PROFILE,
        "stellar-agent-signer",
        "default",
        "stellar-agent-nonce",
        "default",
    )
    .rpc_url(rpc_url)
    .primary_provider(record)
    .audit_log_path(home.join(format!("audit/{PROFILE}.jsonl")))
    .with_noop_engine()
    .build();
    profile.pool_master_key_id = Some(KeyringEntryRef::default_pool_master_key(PROFILE));
    profile.pool_config = Some(stellar_agent_core::profile::schema::PoolConfig::new(
        1,
        vec![stellar_agent_core::profile::schema::PoolChannelRecord::new(
            1,
            account_id_for_seed(SOURCE_SEED),
        )],
    ));
    loader::save_to_dir(PROFILE, &profile, &home.join("profiles")).unwrap();
    let run = run_cli(home, &["profile", "rotate-audit-key", PROFILE], None, &[]);
    assert_eq!(run.code, 0, "rotate-audit-key: {}", run.json);
    let receipts = ReceiptStore::open_at(&home.join("receipts"), PROFILE).unwrap();
    receipts
        .begin_submission_with_approval(
            ENVELOPE_HASH,
            TX_HASH,
            &account_id_for_seed(SOURCE_SEED),
            7,
            0,
            1_000,
            None,
        )
        .unwrap();
    receipts.mark_submitted(ENVELOPE_HASH).unwrap();
}

/// Stores [`VALUE`] through the binary, adding the header placement when the
/// record has none.
fn enroll(home: &Path) -> Run {
    let run = run_cli(
        home,
        &[
            "profile",
            "enroll-rpc-credential",
            "--profile",
            PROFILE,
            "--role",
            "primary",
            "--header",
            HEADER,
            "--stdin",
        ],
        Some(format!("{VALUE}\n").as_bytes()),
        &[],
    );
    assert_eq!(run.code, 0, "enroll-rpc-credential: {}", run.json);
    assert_no_value(&run);
    run
}

fn pay_build_only() -> Vec<String> {
    [
        "pay",
        DEST_G,
        "1 XLM",
        "--source",
        &account_id_for_seed(SOURCE_SEED),
        "--profile",
        PROFILE,
        "--fee",
        "100",
        "--build-only",
        "--output",
        "json",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

fn as_strs(argv: &[String]) -> Vec<&str> {
    argv.iter().map(String::as_str).collect()
}

// Tests

/// `--stdin` stores the value without its line end and adds the reference
/// and the placement to the record; `pay --build-only` then passes the
/// endpoint's credential check, so the stored value is exact.
#[tokio::test]
async fn enroll_rpc_credential_stores_value_and_patches_record() {
    let server = start(true).await;
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), &server.uri(), false);

    let run = enroll(home.path());
    assert_eq!(
        run.json["data"],
        json!({
            "profile": PROFILE,
            "role": "primary",
            "keyring_service": "stellar-agent-rpc-rpc-credential",
            "keyring_account": "primary",
            "placement": {"kind": "header", "name": HEADER},
            "replaced": false,
            "record_patched": true
        })
    );
    let stored =
        std::fs::read_to_string(home.path().join(format!("profiles/{PROFILE}.toml"))).unwrap();
    assert!(
        stored.contains("stellar-agent-rpc-rpc-credential"),
        "{stored}"
    );
    assert!(!stored.contains("K3Y-SENTINEL"), "{stored}");

    let run = run_cli(home.path(), &as_strs(&pay_build_only()), None, &[]);
    assert_eq!(run.code, 0, "{}", run.json);
    let seen = trace(&server).await;
    assert_eq!(methods(&seen).first(), Some(&"getNetwork"));
    assert!(seen.iter().all(|(_, keyed)| *keyed), "{seen:?}");

    let shown = run_cli(home.path(), &["profile", "show", PROFILE], None, &[]);
    assert_eq!(shown.code, 0, "{}", shown.json);
    assert_eq!(
        shown.json["data"]["providers"]["primary"]["credential"],
        json!({"service": "stellar-agent-rpc-rpc-credential", "account": "primary"})
    );
    assert_eq!(
        shown.json["data"]["providers"]["primary"]["placement"],
        json!({"kind": "header", "name": HEADER})
    );
    assert_no_value(&shown);
}

/// A refused enrollment prints no part of the value either.
#[test]
fn enroll_rpc_credential_never_prints_the_value() {
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), "http://127.0.0.1:9", false);
    let long = format!("{VALUE}{}\n", "x".repeat(1100));
    for input in [long.as_bytes(), b"K3Y-SENTINEL\x01\n".as_slice()] {
        let run = run_cli(
            home.path(),
            &[
                "profile",
                "enroll-rpc-credential",
                "--profile",
                PROFILE,
                "--role",
                "primary",
                "--header",
                HEADER,
                "--stdin",
            ],
            Some(input),
            &[],
        );
        assert_eq!(run.code, 1);
        assert_eq!(run.json["error"]["code"], "network.rpc_credential_refused");
        assert_no_value(&run);
    }
}

/// The argument vectors of every classic verb that builds its client from
/// the profile, each after the profile's endpoint check.
fn beta_verbs() -> Vec<(&'static str, Vec<String>)> {
    let source = account_id_for_seed(SOURCE_SEED);
    let owned = |argv: &[&str]| argv.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let claim = stellar_agent_test_support::SignedTestEnvelope::builder(SOURCE_SEED)
        .claim_claimable_balance([0xab; 32])
        .build();
    let balance = "abababababababababababababababababababababababababababababababab";
    vec![
        ("pay --build-only", pay_build_only()),
        (
            "claim",
            owned(&[
                "claim",
                balance,
                "--source",
                &source,
                "--profile",
                PROFILE,
                "--fee",
                "100",
                "--output",
                "json",
            ]),
        ),
        (
            "claim --submit-only",
            owned(&[
                "claim",
                balance,
                "--source",
                claim.source(),
                "--profile",
                PROFILE,
                "--submit-only",
                claim.envelope_xdr(),
                "--output",
                "json",
            ]),
        ),
        (
            "claim --build-only",
            owned(&[
                "claim",
                "abababababababababababababababababababababababababababababababab",
                "--source",
                &source,
                "--profile",
                PROFILE,
                "--build-only",
                "--output",
                "json",
            ]),
        ),
        (
            "trustline",
            owned(&[
                "trustline",
                "--from",
                &source,
                "--asset",
                "USDC",
                "--profile",
                PROFILE,
            ]),
        ),
        (
            "accounts create --sponsor",
            owned(&[
                "accounts",
                "create",
                DEST_G,
                "--sponsor",
                &source,
                "--starting-balance",
                "1 XLM",
                "--fee",
                "100",
                "--profile",
                PROFILE,
                "--output",
                "json",
            ]),
        ),
    ]
}

/// Each classic verb sends the primary credential from its first request on;
/// without a credential in the record the endpoint refuses the identity
/// request with HTTP 401 and the verb ends there with the credential code.
#[tokio::test]
async fn classic_verbs_send_the_primary_credential() {
    for (label, argv) in beta_verbs() {
        let server = start(true).await;
        let home = tempfile::tempdir().unwrap();
        write_profile(home.path(), &server.uri(), false);
        enroll(home.path());
        let run = run_cli(home.path(), &as_strs(&argv), None, &[]);
        let seen = trace(&server).await;
        assert_eq!(
            methods(&seen).first(),
            Some(&"getNetwork"),
            "{label}: {seen:?}"
        );
        assert!(
            seen.len() > 1,
            "{label}: the identity request passed: {seen:?} {}",
            run.json
        );
        assert!(seen.iter().all(|(_, keyed)| *keyed), "{label}: {seen:?}");
        assert_ne!(
            run.json["error"]["code"], "network.rpc_credential_refused",
            "{label}"
        );

        let server = start(true).await;
        let home = tempfile::tempdir().unwrap();
        write_profile(home.path(), &server.uri(), false);
        let run = run_cli(home.path(), &as_strs(&argv), None, &[]);
        assert_eq!(run.code, 1, "{label}: {}", run.json);
        assert_eq!(
            run.json["error"]["code"], "network.rpc_credential_refused",
            "{label}: {}",
            run.json
        );
        assert_eq!(methods(&trace(&server).await), ["getNetwork"], "{label}");
    }
}

/// The classic reads that build their client from the profile send the
/// primary credential too. Without it every request goes out bare and the
/// endpoint refuses it: the reads that need the answer fail, and `pool list`
/// reports its channels without a sequence.
#[tokio::test]
async fn classic_reads_send_the_primary_credential() {
    let reads: [(&str, Vec<&str>, &str, i32); 4] = [
        (
            "tx status",
            vec!["tx", "status", TX_HASH, "--profile", PROFILE],
            "getTransaction",
            1,
        ),
        (
            "tx receipt clear",
            vec![
                "tx",
                "receipt",
                "clear",
                ENVELOPE_HASH,
                "--acknowledge",
                "--profile",
                PROFILE,
            ],
            "getTransaction",
            1,
        ),
        (
            "fees stats",
            vec!["fees", "stats", "--profile", PROFILE],
            "getFeeStats",
            1,
        ),
        (
            "pool list",
            vec!["pool", "list", "--profile", PROFILE],
            "getLedgerEntries",
            0,
        ),
    ];
    for (label, argv, read, bare_code) in reads {
        let server = start(true).await;
        let home = tempfile::tempdir().unwrap();
        write_profile(home.path(), &server.uri(), false);
        enroll(home.path());
        let run = run_cli(home.path(), &argv, None, &[]);
        let seen = trace(&server).await;
        assert_eq!(
            methods(&seen).first(),
            Some(&read),
            "{label}: {seen:?} {}",
            run.json
        );
        assert!(seen.iter().all(|(_, keyed)| *keyed), "{label}: {seen:?}");
        assert_eq!(run.code, 0, "{label}: {}", run.json);
        if label == "pool list" {
            assert!(
                run.json["data"]["channels"][0]["sequence_number"].is_number(),
                "{}",
                run.json
            );
        }

        let server = start(true).await;
        let home = tempfile::tempdir().unwrap();
        write_profile(home.path(), &server.uri(), false);
        let run = run_cli(home.path(), &argv, None, &[]);
        assert_eq!(run.code, bare_code, "{label}: {}", run.json);
        if label == "pool list" {
            assert!(
                run.json["data"]["channels"][0]["sequence_number"].is_null(),
                "{}",
                run.json
            );
        }
        let seen = trace(&server).await;
        assert!(!seen.is_empty(), "{label}");
        assert!(
            seen.iter().all(|(method, keyed)| method == read && !keyed),
            "{label}: {seen:?}"
        );
    }
}

/// `--rpc-url` naming another endpoint gets no credential and opens no
/// keyring entry: the record names an entry that was never stored, which a
/// read would report as missing.
#[tokio::test]
async fn an_overriding_rpc_url_gets_no_credential() {
    let profile_server = start(true).await;
    let other = start(false).await;
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), &profile_server.uri(), true);

    let run = run_cli(home.path(), &as_strs(&pay_build_only()), None, &[]);
    assert_eq!(run.code, 1, "{}", run.json);
    assert_eq!(
        run.json["error"]["code"], "auth.keyring_not_found",
        "{}",
        run.json
    );
    assert!(trace(&profile_server).await.is_empty());

    let mut argv = pay_build_only();
    argv.extend(["--rpc-url".to_owned(), other.uri()]);
    let run = run_cli(home.path(), &as_strs(&argv), None, &[]);
    assert_eq!(run.code, 0, "{}", run.json);
    let seen = trace(&other).await;
    assert_eq!(methods(&seen).first(), Some(&"getNetwork"));
    assert!(seen.iter().all(|(_, keyed)| !keyed), "{seen:?}");
    assert!(trace(&profile_server).await.is_empty());
}

/// A testnet environment overlay of `rpc_url` on the record's host keeps the
/// credential: the loader checked the record against the merged URL.
#[tokio::test]
async fn a_testnet_overlay_on_the_same_host_keeps_the_credential() {
    let file_server = start(true).await;
    let overlay_server = start(true).await;
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), &file_server.uri(), false);
    enroll(home.path());

    let overlay = format!("{}/overlay", overlay_server.uri());
    let run = run_cli(
        home.path(),
        &as_strs(&pay_build_only()),
        None,
        &[("STELLAR_AGENT_RPC_URL", overlay.as_str())],
    );
    assert_eq!(run.code, 0, "{}", run.json);
    let seen = trace(&overlay_server).await;
    assert_eq!(methods(&seen).first(), Some(&"getNetwork"));
    assert!(seen.iter().all(|(_, keyed)| *keyed), "{seen:?}");
    assert!(trace(&file_server).await.is_empty());
}
