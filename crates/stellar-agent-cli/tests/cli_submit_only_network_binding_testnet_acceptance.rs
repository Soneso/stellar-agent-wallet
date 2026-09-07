//! Testnet acceptance: `stellar-agent pay --submit-only` binds the envelope to
//! the network the RPC endpoint actually serves.
//!
//! Three live outcomes against real endpoints, all driven as subprocesses of
//! the real `stellar-agent` binary (the CLI crate has no `[lib]` target, so it
//! cannot be exercised in process — the `claim_testnet_acceptance.rs`
//! precedent):
//!
//! 1. An envelope built and signed for testnet, submitted to the testnet RPC,
//!    reaches ledger inclusion.
//! 2. The same staged flow pointed at the futurenet RPC while declaring
//!    `--network testnet` is refused with `network.endpoint_network_mismatch`,
//!    before anything is sent. The declaration is a claim about the endpoint;
//!    the endpoint's own answer decides.
//! 3. An envelope for the same funded testnet source, signed by that source's
//!    own key but under the FUTURENET network passphrase, is refused at the
//!    testnet endpoint with `network.envelope_signature_unverifiable`. The
//!    signer is a signer of the source account and the endpoint is the
//!    declared one, so the network id in the signing payload is the only thing
//!    that can produce this refusal.
//!
//! Scenario 3 is what a mock cannot prove: the signature is real, the account
//! is real, and the only difference from scenario 1 is which network the
//! signature was made for.
//!
//! # Fixtures
//!
//! A fresh temp directory stands in for `STELLAR_AGENT_HOME`, set only on the
//! child processes. No profile file is written, so the zero-config synthesized
//! testnet profile is used and no keyring or policy fixture is needed. Source
//! and destination accounts are generated in process and Friendbot-funded; a
//! native payment requires the destination to exist.
//!
//! # Endpoint availability
//!
//! The futurenet RPC endpoint is a requirement of this suite, not an optional
//! precondition. An unreachable futurenet endpoint answers the identity probe
//! with `network.endpoint_identity_unavailable` rather than
//! `network.endpoint_network_mismatch`, and the suite fails.
//!
//! Gated behind `testnet-acceptance`:
//!
//! ```text
//! cargo test -p stellar-agent-cli --features testnet-acceptance \
//!   --test cli_submit_only_network_binding_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in testnet acceptance tests"
)]

use std::process::Command;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::{SoftwareSigningKey, StellarRpcClient, fetch_account};
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_RPC_URL: &str = "https://soroban-testnet.stellar.org";
const FUTURENET_RPC_URL: &str = "https://rpc-futurenet.stellar.org";
const TESTNET_FRIENDBOT_URL: &str = "https://friendbot.stellar.org";

/// The futurenet network passphrase. Scenario 3 signs under this while the
/// endpoint serves testnet.
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// Name of the env var each spawned `stellar-agent pay` reads the source
/// account's S-strkey secret from. Set only on the child process.
const SECRET_ENV_VAR: &str = "CLI_SUBMIT_ONLY_BINDING_ACCEPTANCE_SECRET";

/// Payment amount for every envelope this suite builds.
const AMOUNT: &str = "1 XLM";

// ─────────────────────────────────────────────────────────────────────────────
// Keypair / funding helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `(G-strkey, S-strkey, raw seed)` for a fresh ed25519 keypair.
fn fresh_keypair() -> (String, Zeroizing<String>, Zeroizing<[u8; 32]>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let g_strkey = stellar_strkey::ed25519::PublicKey(signing_key.verifying_key().to_bytes())
        .to_string()
        .to_string();
    let s_strkey = stellar_strkey::ed25519::PrivateKey(signing_key.to_bytes())
        .as_unredacted()
        .to_string()
        .to_string();
    (
        g_strkey,
        Zeroizing::new(s_strkey),
        Zeroizing::new(signing_key.to_bytes()),
    )
}

async fn fund_via_friendbot(g_strkey: &str) {
    let url = format!("{TESTNET_FRIENDBOT_URL}?addr={g_strkey}");
    let resp = reqwest::get(&url)
        .await
        .expect("Friendbot HTTP request must succeed");
    assert!(
        resp.status().is_success(),
        "Friendbot must return 2xx for {g_strkey}; got {}",
        resp.status()
    );
}

/// Polls RPC until the freshly-funded account is queryable, tolerating
/// Friendbot/RPC eventual consistency.
async fn wait_until_account_queryable(client: &StellarRpcClient, g_strkey: &str) {
    for _ in 0..30 {
        if fetch_account(client, g_strkey, &[]).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("funded account {g_strkey} did not become RPC-queryable in time");
}

/// Returns the source account's sequence number.
async fn sequence_number(client: &StellarRpcClient, g_strkey: &str) -> i64 {
    fetch_account(client, g_strkey, &[])
        .await
        .expect("account fetch must succeed")
        .sequence_number
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI driver
// ─────────────────────────────────────────────────────────────────────────────

/// Runs `stellar-agent pay` with `extra` appended to the common flags and
/// returns `(exit_code, stdout_json_envelope)`.
fn run_pay(
    home: &std::path::Path,
    source_g: &str,
    source_secret: &str,
    destination_g: &str,
    rpc_url: &str,
    extra: &[&str],
) -> (i32, serde_json::Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let mut args: Vec<&str> = vec![
        "pay",
        destination_g,
        AMOUNT,
        "--source",
        source_g,
        "--secret-env",
        SECRET_ENV_VAR,
        "--network",
        "testnet",
        "--rpc-url",
        rpc_url,
        "--output",
        "json",
    ];
    args.extend_from_slice(extra);

    let output = Command::new(bin_path)
        .args(&args)
        .env(SECRET_ENV_VAR, source_secret)
        .env("STELLAR_AGENT_HOME", home)
        .output()
        .expect("stellar-agent pay subprocess must spawn");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "expected exactly one JSON envelope line on stdout; got {}: stdout={stdout} stderr={stderr}",
        lines.len()
    );
    let envelope: serde_json::Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|e| panic!("stdout line must be valid JSON ({e}): {}", lines[0]));

    let exit_code = output
        .status
        .code()
        .unwrap_or_else(|| panic!("process must exit with a status code; stderr={stderr}"));
    (exit_code, envelope)
}

/// Extracts `data.envelope_xdr` from a successful stage envelope.
fn envelope_xdr_of(stage: &str, envelope: &serde_json::Value) -> String {
    assert_eq!(
        envelope["ok"].as_bool(),
        Some(true),
        "the {stage} stage must succeed: {envelope}"
    );
    envelope["data"]["envelope_xdr"]
        .as_str()
        .unwrap_or_else(|| panic!("the {stage} stage must return envelope_xdr: {envelope}"))
        .to_owned()
}

/// Extracts `error.code` from a refusal envelope.
fn error_code_of(envelope: &serde_json::Value) -> String {
    assert_eq!(
        envelope["ok"].as_bool(),
        Some(false),
        "expected a refusal envelope: {envelope}"
    );
    envelope["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("a refusal envelope must carry error.code: {envelope}"))
        .to_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

/// The staged `--submit-only` flow accepts an envelope bound to the endpoint's
/// network and refuses both a foreign endpoint and a foreign-network signature.
#[tokio::test]
async fn cli_submit_only_network_binding_testnet_acceptance() {
    let home = tempfile::TempDir::new().expect("tempdir");
    let client = StellarRpcClient::new(TESTNET_RPC_URL).expect("testnet RPC URL must be valid");

    let (source_g, source_s, source_seed) = fresh_keypair();
    let (dest_g, _dest_s, _dest_seed) = fresh_keypair();
    fund_via_friendbot(&source_g).await;
    fund_via_friendbot(&dest_g).await;
    wait_until_account_queryable(&client, &source_g).await;
    wait_until_account_queryable(&client, &dest_g).await;

    let sequence_before = sequence_number(&client, &source_g).await;

    // ── Stage the envelope: build, then sign, both for testnet ────────────────
    let (code, built) = run_pay(
        home.path(),
        &source_g,
        &source_s,
        &dest_g,
        TESTNET_RPC_URL,
        &["--build-only"],
    );
    assert_eq!(code, 0, "build stage must succeed: {built}");
    let unsigned_xdr = envelope_xdr_of("build", &built);

    let (code, signed) = run_pay(
        home.path(),
        &source_g,
        &source_s,
        &dest_g,
        TESTNET_RPC_URL,
        &["--sign-only", &unsigned_xdr],
    );
    assert_eq!(code, 0, "sign stage must succeed: {signed}");
    let signed_xdr = envelope_xdr_of("sign", &signed);

    // ── Scenario 2: the endpoint serves another network ───────────────────────
    //
    // Run before the successful submit so the source's sequence number is
    // still unspent, and the assertion below that it is unchanged means the
    // refusal, not an already-consumed sequence.
    let (code, refused) = run_pay(
        home.path(),
        &source_g,
        &source_s,
        &dest_g,
        FUTURENET_RPC_URL,
        &["--submit-only", &signed_xdr],
    );
    assert_eq!(code, 1, "a futurenet endpoint must refuse: {refused}");
    assert_eq!(
        error_code_of(&refused),
        "network.endpoint_network_mismatch",
        "the futurenet endpoint must be reachable and must report its own \
         network; an unreachable endpoint reports \
         network.endpoint_identity_unavailable instead: {refused}"
    );
    assert_eq!(
        sequence_number(&client, &source_g).await,
        sequence_before,
        "a refused submission must not consume the source's sequence number"
    );

    // ── Scenario 1: the endpoint serves the declared network ──────────────────
    let (code, submitted) = run_pay(
        home.path(),
        &source_g,
        &source_s,
        &dest_g,
        TESTNET_RPC_URL,
        &["--submit-only", &signed_xdr],
    );
    assert_eq!(code, 0, "the testnet endpoint must accept: {submitted}");
    assert_eq!(submitted["ok"].as_bool(), Some(true), "{submitted}");
    let tx_hash = submitted["data"]["tx_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("a confirmed submit must carry data.tx_hash: {submitted}"));
    assert_eq!(tx_hash.len(), 64, "tx_hash must be 64 hex characters");
    assert!(
        submitted["data"]["ledger"].as_u64().is_some(),
        "a confirmed submit must carry data.ledger: {submitted}"
    );

    // ── Scenario 3: the right signer, the right endpoint, the wrong network ───
    //
    // Build a fresh envelope at the sequence the landed transaction advanced
    // to, and sign it with the source account's own key under the futurenet
    // passphrase. The signer is a signer of the source account and the
    // endpoint is the declared one, so only the network id in the signing
    // payload distinguishes this from the submission that just succeeded.
    let (code, rebuilt) = run_pay(
        home.path(),
        &source_g,
        &source_s,
        &dest_g,
        TESTNET_RPC_URL,
        &["--build-only"],
    );
    assert_eq!(code, 0, "the second build stage must succeed: {rebuilt}");
    let unsigned_again = envelope_xdr_of("build", &rebuilt);

    let signer = SoftwareSigningKey::new_from_bytes(*source_seed);
    let futurenet_signed = attach_signature(&unsigned_again, &signer, FUTURENET_PASSPHRASE)
        .await
        .expect("signing under the futurenet passphrase must succeed");

    let (code, unverifiable) = run_pay(
        home.path(),
        &source_g,
        &source_s,
        &dest_g,
        TESTNET_RPC_URL,
        &["--submit-only", &futurenet_signed],
    );
    assert_eq!(
        code, 1,
        "an envelope signed for another network must be refused: {unverifiable}"
    );
    assert_eq!(
        error_code_of(&unverifiable),
        "network.envelope_signature_unverifiable",
        "the signer is a signer of the source account and the endpoint is the \
         declared one, so the network id the signature was made under is the \
         only thing this refusal can be about: {unverifiable}"
    );
}
