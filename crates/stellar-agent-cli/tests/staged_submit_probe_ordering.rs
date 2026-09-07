//! Offline process tests: `pay --submit-only` and `claim --submit-only` refuse
//! an endpoint serving another network before the staged policy gate and
//! before the audit-key pre-flight.
//!
//! Driven as subprocesses of the real `stellar-agent` binary so the printed
//! error envelope is the one an operator sees. The CLI crate has no `[lib]`
//! target, so an in-process test cannot read that envelope.
//!
//! The mock RPC server answers `getNetwork` with a third network and answers
//! `getLedgerEntries` for both the source and the destination account. Those
//! account bodies are what make the ordering assertions discriminate: with the
//! probe placed after the policy gate, the gate's own account reads would
//! succeed and be recorded, the run would continue to the audit pre-flight,
//! and both the request trace and the error code would differ.
//!
//! Two profile shapes per verb:
//!
//! - the zero-config synthesized profile, where the audit pre-flight is
//!   fail-open, so only the request trace and the code separate a probe
//!   refusal from a gate refusal;
//! - a persisted profile fresh from `profile init`, which has the audit-log
//!   keyring coordinate but no key material. Its pre-flight fails closed with
//!   `audit.chain_key_unavailable`, so that code appearing instead would mean
//!   the probe ran after it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::path::Path;
use std::process::Command;

use serde_json::{Value, json};
use stellar_agent_test_support::signed_envelope::{SignedTestEnvelope, get_network_result};
use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend,
/// so no child process can reach the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// The network the mock endpoint reports, which is neither the declared
/// testnet nor mainnet.
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

const SOURCE_SEED: [u8; 32] = [61u8; 32];

// ─────────────────────────────────────────────────────────────────────────────
// Mock RPC
// ─────────────────────────────────────────────────────────────────────────────

/// Answers `getNetwork` with a foreign network and `getLedgerEntries` with the
/// account entry whose key the request names.
struct StagedGateRpcResponder {
    /// `(ledger key XDR, account entry XDR)` per answerable account.
    accounts: Vec<(String, String)>,
}

impl Respond for StagedGateRpcResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or_else(|_| json!({}));
        let req_id = body.get("id").cloned().unwrap_or_else(|| json!(1));
        let rpc_method = body
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();

        let result = match rpc_method {
            "getNetwork" => get_network_result(FUTURENET_PASSPHRASE),
            "getLedgerEntries" => {
                let raw = String::from_utf8_lossy(&request.body);
                let entries: Vec<Value> = self
                    .accounts
                    .iter()
                    .filter(|(key, _)| raw.contains(key.as_str()))
                    .map(|(key, entry)| {
                        json!({
                            "key": key,
                            "xdr": entry,
                            "lastModifiedLedgerSeq": 1000
                        })
                    })
                    .collect();
                json!({ "entries": entries, "latestLedger": 1001 })
            }
            "getFeeStats" => json!({
                "sorobanInclusionFee": {
                    "max": "200", "min": "100", "mode": "100", "p10": "100", "p20": "100",
                    "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
                    "p80": "100", "p90": "200", "p95": "200", "p99": "200",
                    "transactionCount": "10", "ledgerCount": 5
                },
                "inclusionFee": {
                    "max": "200", "min": "100", "mode": "100", "p10": "100", "p20": "100",
                    "p30": "100", "p40": "100", "p50": "100", "p60": "100", "p70": "100",
                    "p80": "100", "p90": "200", "p95": "200", "p99": "200",
                    "transactionCount": "10", "ledgerCount": 5
                },
                "latestLedger": 1001
            }),
            _ => json!({}),
        };

        ResponseTemplate::new(200)
            .set_body_json(json!({ "jsonrpc": "2.0", "id": req_id, "result": result }))
            .insert_header("content-type", "application/json")
    }
}

/// Starts a mock endpoint that can answer for the envelope's source and
/// destination accounts.
async fn start_mock(envelope: &SignedTestEnvelope) -> MockServer {
    let server = MockServer::start().await;
    let accounts = vec![
        (
            account_ledger_key_xdr(envelope.source()),
            account_entry_xdr(envelope.source(), 100_000_000_000, 0),
        ),
        (
            account_ledger_key_xdr(envelope.destination()),
            account_entry_xdr(envelope.destination(), 100_000_000_000, 0),
        ),
    ];
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(StagedGateRpcResponder { accounts })
        .mount(&server)
        .await;
    server
}

/// The JSON-RPC method names the server received, in order.
async fn received_methods(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .iter()
        .filter_map(|req| {
            let body: Value = serde_json::from_slice(&req.body).ok()?;
            Some(body.get("method")?.as_str()?.to_owned())
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI driver
// ─────────────────────────────────────────────────────────────────────────────

/// Runs the binary with `args` against an isolated home and returns
/// `(exit_code, stdout_envelope)`.
fn run_cli(home: &Path, args: &[&str]) -> (i32, Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .output()
        .expect("stellar-agent binary must run");

    let code = output.status.code().expect("process must exit with a code");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let last = stdout
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or_else(|| panic!("expected an envelope on stdout; stderr={stderr}"));
    let json: Value = serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("stdout line must be JSON ({e}): {last}"));
    (code, json)
}

/// Creates a persisted `noop`-engine profile. It has the audit-log keyring
/// coordinate but no key material, which is what makes the audit pre-flight
/// fail closed for it.
fn init_persisted_profile(home: &Path, profile: &str) {
    let (code, envelope) = run_cli(
        home,
        &[
            "profile",
            "init",
            "--engine",
            "noop",
            &format!("--profile={profile}"),
        ],
    );
    assert_eq!(code, 0, "profile init must succeed: {envelope}");
}

/// Asserts the run refused with the endpoint-mismatch code, having issued only
/// the identity probe.
async fn assert_probe_refused_first(verb: &str, code: i32, envelope: &Value, server: &MockServer) {
    assert_eq!(code, 1, "{verb} must refuse: {envelope}");
    assert_eq!(
        envelope["error"]["code"].as_str(),
        Some("network.endpoint_network_mismatch"),
        "{verb} must refuse with the endpoint-mismatch code, not a code from a \
         later stage: {envelope}"
    );
    assert_eq!(
        received_methods(server).await,
        vec!["getNetwork"],
        "{verb} must issue the identity probe and nothing else; the staged gate \
         reads accounts and the mock would answer them"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// pay
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pay_submit_only_probes_before_the_gate_on_the_zero_config_profile() {
    let envelope = SignedTestEnvelope::for_source(SOURCE_SEED);
    let server = start_mock(&envelope).await;
    let home = tempfile::tempdir().expect("temp home");

    let (code, out) = run_cli(
        home.path(),
        &[
            "pay",
            envelope.destination(),
            "1 XLM",
            "--source",
            envelope.source(),
            "--network",
            "testnet",
            "--rpc-url",
            &server.uri(),
            "--submit-only",
            envelope.envelope_xdr(),
            "--output",
            "json",
        ],
    );

    assert_probe_refused_first("pay", code, &out, &server).await;
}

#[tokio::test]
async fn pay_submit_only_probes_before_the_audit_preflight_on_a_persisted_profile() {
    let envelope = SignedTestEnvelope::for_source(SOURCE_SEED);
    let server = start_mock(&envelope).await;
    let home = tempfile::tempdir().expect("temp home");
    init_persisted_profile(home.path(), "probe-order-pay");

    let (code, out) = run_cli(
        home.path(),
        &[
            "pay",
            envelope.destination(),
            "1 XLM",
            "--source",
            envelope.source(),
            "--profile",
            "probe-order-pay",
            "--network",
            "testnet",
            "--rpc-url",
            &server.uri(),
            "--submit-only",
            envelope.envelope_xdr(),
            "--output",
            "json",
        ],
    );

    assert_ne!(
        out["error"]["code"].as_str(),
        Some("audit.chain_key_unavailable"),
        "the persisted profile's audit key is unminted, so this code appearing \
         would mean the probe ran after the audit pre-flight: {out}"
    );
    assert_probe_refused_first("pay", code, &out, &server).await;
}

// ─────────────────────────────────────────────────────────────────────────────
// claim
// ─────────────────────────────────────────────────────────────────────────────

/// A syntactically valid claimable-balance id. The run never reaches the
/// balance lookup.
const BALANCE_ID: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

/// The same id as raw bytes, for the envelope's `ClaimClaimableBalance`
/// operation.
const BALANCE_ID_BYTES: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// A claim-shaped envelope. The staged claim gate fetches the decoded source
/// account only when the envelope decodes under the claim tool name, so a
/// payment envelope would leave the gate making no request of its own and the
/// ordering assertions below with nothing to discriminate.
fn claim_envelope() -> SignedTestEnvelope {
    SignedTestEnvelope::builder(SOURCE_SEED)
        .claim_claimable_balance(BALANCE_ID_BYTES)
        .build()
}

#[tokio::test]
async fn claim_submit_only_probes_before_the_gate_on_the_zero_config_profile() {
    let envelope = claim_envelope();
    let server = start_mock(&envelope).await;
    let home = tempfile::tempdir().expect("temp home");

    let (code, out) = run_cli(
        home.path(),
        &[
            "claim",
            BALANCE_ID,
            "--source",
            envelope.source(),
            "--network",
            "testnet",
            "--rpc-url",
            &server.uri(),
            "--submit-only",
            envelope.envelope_xdr(),
            "--output",
            "json",
        ],
    );

    assert_probe_refused_first("claim", code, &out, &server).await;
}

#[tokio::test]
async fn claim_submit_only_probes_before_the_audit_preflight_on_a_persisted_profile() {
    let envelope = claim_envelope();
    let server = start_mock(&envelope).await;
    let home = tempfile::tempdir().expect("temp home");
    init_persisted_profile(home.path(), "probe-order-claim");

    let (code, out) = run_cli(
        home.path(),
        &[
            "claim",
            BALANCE_ID,
            "--source",
            envelope.source(),
            "--profile",
            "probe-order-claim",
            "--network",
            "testnet",
            "--rpc-url",
            &server.uri(),
            "--submit-only",
            envelope.envelope_xdr(),
            "--output",
            "json",
        ],
    );

    assert_ne!(
        out["error"]["code"].as_str(),
        Some("audit.chain_key_unavailable"),
        "the persisted profile's audit key is unminted, so this code appearing \
         would mean the probe ran after the audit pre-flight: {out}"
    );
    assert_probe_refused_first("claim", code, &out, &server).await;
}
