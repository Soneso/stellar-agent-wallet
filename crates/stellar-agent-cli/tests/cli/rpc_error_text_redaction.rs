//! `stellar-agent balances` against an endpoint whose error text echoes the
//! request URL.
//!
//! A loopback endpoint answers HTTP 200 with a JSON-RPC error object whose
//! `message` repeats the `--rpc-url` the operator passed, query token included,
//! and whose `data` carries a second credential-bearing URL with each slash
//! JSON-escaped. The printed envelope must name the failure with its stable
//! code and keep only the host and port of both URLs.
//!
//! Driven as a subprocess of the real binary so the envelope is the one an
//! operator sees. The CLI crate has no `[lib]` target.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend,
/// so no child process can reach the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// The account `balances` asks for.
const ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// The `data` member of the error object: a second credential-bearing URL,
/// written with JSON-escaped slashes.
const ESCAPED_DATA: &str =
    r#"{"url":"https:\/\/user:SECRET@archive.example.com:8443\/rpc?token=SECRET"}"#;

/// Runs the CLI with an isolated data root and returns its exit code and the
/// envelope it printed.
fn run_cli(home: &Path, args: &[&str]) -> (i32, String, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL")
        .output()
        .expect("stellar-agent binary must run");

    let code = output.status.code().expect("process must exit with a code");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let envelope: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must be a single JSON envelope ({e}); stdout={stdout} stderr={stderr}")
    });
    (code, stdout, envelope)
}

/// The envelope names the unreachable endpoint with its stable code, and its
/// message keeps only the host and port of every URL the endpoint echoed.
#[tokio::test]
async fn balances_envelope_keeps_only_host_and_port_of_echoed_urls() {
    let server = MockServer::start().await;
    let rpc_url = format!("{}/?token=CLIENTSECRET", server.uri());
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"upstream rejected {rpc_url} for this caller","data":{ESCAPED_DATA}}}}}"#
    );
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("token", "CLIENTSECRET"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/json"))
        .mount(&server)
        .await;
    let home = tempfile::tempdir().expect("temp home");

    let (code, stdout, envelope) = run_cli(
        home.path(),
        &["balances", "--account", ACCOUNT, "--rpc-url", &rpc_url],
    );

    assert_eq!(
        code, 1,
        "an unreachable endpoint fails the verb: {envelope}"
    );
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("network.rpc_unreachable"),
        "the envelope names the failure: {envelope}"
    );
    let message = envelope["error"]["message"]
        .as_str()
        .expect("the error carries a message");
    let authority = server.uri().strip_prefix("http://").unwrap().to_owned();
    assert!(
        message.contains(&format!("upstream rejected {authority} for this caller")),
        "the echoed request URL keeps its host and port: {message}"
    );
    assert!(
        message.contains(r#"{\"url\":\"archive.example.com:8443\"}"#),
        "the escaped URL in the data keeps its host and port, its quotes escaped: {message}"
    );
    for leaked in ["SECRET", "token=", "user:", "https:", "/rpc"] {
        assert!(
            !message.contains(leaked),
            "{leaked} reached the envelope message: {message}"
        );
        assert!(
            !stdout.contains(leaked),
            "{leaked} reached stdout: {stdout}"
        );
    }
}
