//! CLI integration tests for `stellar-agent fees stats` endpoint rules.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::path::Path;

use serde_json::{Value, json};
use stellar_agent_core::profile::loader;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, PrimaryProviderRecord, Profile, ProviderRole, RpcCredentialPlacement,
};
use stellar_agent_test_support::rejected_value::{CREDENTIAL_MARKER, assert_no_marker_in_text};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HEADER: &str = "X-API-Key";

#[derive(Clone)]
struct FeeStatsRpc {
    latest_ledger: u64,
}

impl Respond for FeeStatsRpc {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["method"].as_str(), Some("getFeeStats"));
        let fees = json!({
            "max": "100", "min": "100", "mode": "100", "p10": "100", "p20": "100",
            "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
            "p80": "100", "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "10", "ledgerCount": 5
        });
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "sorobanInclusionFee": fees,
                "inclusionFee": fees,
                "latestLedger": self.latest_ledger
            }
        }))
    }
}

async fn start_fee_stats_rpc(latest_ledger: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(FeeStatsRpc { latest_ledger })
        .mount(&server)
        .await;
    server
}

struct Run {
    code: i32,
    json: Value,
    stdout: String,
    stderr: String,
}

fn run_cli(home: &Path, args: &[&str]) -> Run {
    let output = stellar_agent_test_support::cli_child::cli_command(
        env!("CARGO_BIN_EXE_stellar-agent"),
        home,
    )
    .expect("isolated CLI child")
    .args(args)
    .env("STELLAR_AGENT_HOME", home)
    .env_remove("STELLAR_AGENT_PROFILE")
    .env_remove("STELLAR_AGENT_RPC_URL")
    .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
    .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
    .output()
    .expect("stellar-agent binary must run");
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

/// With a testnet profile, `--rpc-url` on any host replaces the profile
/// endpoint under the shared endpoint rules, and the profile's primary
/// credential is not read or sent to the override.
#[tokio::test]
async fn fees_stats_testnet_profile_accepts_any_override_host() {
    let profile_server = start_fee_stats_rpc(1111).await;
    let override_server = start_fee_stats_rpc(2222).await;
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let name = "fees-testnet-override";
    let record = PrimaryProviderRecord::new("Primary RPC", "127.0.0.1").with_credential(
        KeyringEntryRef::default_rpc_credential(name, ProviderRole::Primary),
        RpcCredentialPlacement::Header {
            name: HEADER.to_owned(),
        },
    );
    let profile = Profile::builder_testnet_named(
        name,
        "stellar-agent-signer",
        "default",
        "stellar-agent-nonce",
        "default",
    )
    .rpc_url(profile_server.uri())
    .primary_provider(record)
    .audit_log_path(home.path().join(format!("audit/{name}.jsonl")))
    .with_noop_engine()
    .build();
    loader::save_to_dir(name, &profile, &home.path().join("profiles")).unwrap();

    let override_url = override_server.uri();
    let run = run_cli(
        home.path(),
        &[
            "fees",
            "stats",
            "--profile",
            name,
            "--rpc-url",
            &override_url,
        ],
    );

    assert_eq!(run.code, 0, "override must succeed: {}", run.json);
    assert_eq!(run.json["data"]["latest_ledger"], json!(2222));
    assert!(
        profile_server.received_requests().await.unwrap().is_empty(),
        "profile server must receive no requests when overridden"
    );
    let requests = override_server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].headers.get(HEADER).is_none(),
        "override endpoint must not receive the profile credential"
    );
}

/// Without `--profile`, an `http://` URL refuses with
/// `validation.config_invalid` naming the HTTPS rule. A credentialed URL
/// refuses at argument parsing with `validation.usage_error` naming the flag.
/// Neither echoes the URL or a host list.
#[test]
fn fees_stats_without_profile_refuses_http_naming_the_rule_and_credentials_naming_the_flag() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();

    let http_url = format!("http://custom-rpc.example/{CREDENTIAL_MARKER}");
    let http_run = run_cli(home.path(), &["fees", "stats", "--rpc-url", &http_url]);
    assert_eq!(http_run.code, 1, "{}", http_run.json);
    assert_eq!(http_run.json["error"]["code"], "validation.config_invalid");
    let http_msg = http_run.json["error"]["message"].as_str().unwrap();
    assert!(
        http_msg.contains("https"),
        "must name HTTPS rule: {http_msg}"
    );
    assert!(
        !http_msg.contains("allow-list"),
        "must not name allow-list: {http_msg}"
    );
    assert!(
        !http_msg.contains("custom-rpc.example"),
        "must not echo host: {http_msg}"
    );
    assert_no_marker_in_text(&http_run.stdout, CREDENTIAL_MARKER);
    assert_no_marker_in_text(&http_run.stderr, CREDENTIAL_MARKER);

    let cred_url = format!("https://user:{CREDENTIAL_MARKER}@custom-rpc.example");
    let cred_run = run_cli(home.path(), &["fees", "stats", "--rpc-url", &cred_url]);
    assert_eq!(cred_run.code, 1, "{}", cred_run.json);
    assert_eq!(cred_run.json["error"]["code"], "validation.usage_error");
    let cred_msg = cred_run.json["error"]["message"].as_str().unwrap();
    assert!(
        cred_msg.starts_with("the argument value is not valid: --rpc-url"),
        "must name the refused flag: {cred_msg}"
    );
    assert!(
        !cred_msg.contains("allow-list"),
        "must not name allow-list: {cred_msg}"
    );
    assert!(
        !cred_msg.contains("custom-rpc.example"),
        "must not echo host: {cred_msg}"
    );
    assert_no_marker_in_text(&cred_run.stdout, CREDENTIAL_MARKER);
    assert_no_marker_in_text(&cred_run.stderr, CREDENTIAL_MARKER);
}
