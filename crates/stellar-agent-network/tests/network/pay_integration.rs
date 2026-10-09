//! Mock-RPC integration tests for the `pay` command pipeline.
//!
//! Uses `wiremock` to serve deterministic JSON-RPC responses without a live
//! Stellar network.
//!
//! # jsonrpsee request-ID echoing
//!
//! `stellar-rpc-client` uses `jsonrpsee-http-client` which sends JSON-RPC 2.0
//! requests with incrementing numeric IDs and validates that the response `id`
//! matches the request `id`. We use the shared test-support `EchoIdResponder`
//! to echo the request ID back in the response.
//!
//! # Coverage
//!
//! - Three-stage round-trip: `build` produces decodable XDR.
//! - `AccountNotFound` error code is stable.
//! - `MemoRequired` error code and message are stable.
//! - `TxTimeout` error code is stable; invalid XDR returns protocol error.
//! - Mock send+poll: `sendTransaction` success followed by `getTransaction SUCCESS`.
//! - Mock NOT_FOUND then SUCCESS polling.
//! - SEP-29 fast-path: `memo_present=true` returns `Ok` without any RPC call.
//! - Mainnet URL rejected at submit layer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "integration test; panics/unwraps acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::StellarAmount;
use stellar_agent_core::error::{
    ErrorCategory, NetworkError, SubmissionError, ValidationError, WalletError,
};
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::{StellarRpcClient, submit_transaction_and_wait};
use stellar_agent_test_support::EchoIdResponder;
use stellar_agent_test_support::signed_envelope::{SignedTestEnvelope, get_network_result};
use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const SRC_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DST_ACCOUNT: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Seed for the source account of submit-path envelopes. A public test
/// fixture, never a production key.
const SOURCE_SEED: [u8; 32] = [4u8; 32];

// ─────────────────────────────────────────────────────────────────────────────
// Response fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn send_transaction_result(envelope: &SignedTestEnvelope) -> serde_json::Value {
    json!({
        "hash": envelope.tx_hash_hex(),
        "status": "PENDING",
        "latestLedger": 1001,
        "latestLedgerCloseTime": "1234567890"
    })
}

fn get_transaction_success_result(envelope: &SignedTestEnvelope, ledger: u32) -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "ledger": ledger,
        "txHash": envelope.tx_hash_hex()
    })
}

fn get_transaction_not_found_result() -> serde_json::Value {
    json!({
        "status": "NOT_FOUND",
        "latestLedger": 1001
    })
}

/// Mounts the two reads every submit performs before it sends: the endpoint
/// identity probe and the signer-set fetch for the envelope's source accounts.
async fn mount_probe_and_signers(server: &MockServer, envelope: &SignedTestEnvelope) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(EchoIdResponder::new(envelope.ledger_entries_result()))
        .mount(server)
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Builder helpers
// ─────────────────────────────────────────────────────────────────────────────

fn build_test_unsigned_xdr() -> String {
    let mut builder = ClassicOpBuilder::new(SRC_ACCOUNT, 101, TESTNET_PASSPHRASE, 100);
    builder
        .payment(
            DST_ACCOUNT,
            StellarAmount::from_stroops(10_000_000),
            &Asset::Native,
        )
        .expect("payment op");
    builder.build().expect("build")
}

/// Builds a signed envelope whose source account is the signing key's own
/// account, so the signer set the ledger reports for it accounts for the
/// envelope's signature.
fn build_test_signed_envelope(seq: i64) -> SignedTestEnvelope {
    SignedTestEnvelope::for_source_with_sequence(SOURCE_SEED, seq)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure-logic tests (no mock server)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that `build` produces a decodable `TransactionEnvelope`.
#[test]
fn build_produces_decodable_envelope() {
    let xdr = build_test_unsigned_xdr();
    let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none());
    assert!(env.is_ok(), "build must produce decodable XDR: {env:?}");
}

/// Verifies that the `MemoRequired` error code and message are stable.
#[test]
fn memo_required_error_code_is_stable() {
    let err = WalletError::Validation(ValidationError::MemoRequired {
        destination: DST_ACCOUNT.to_owned(),
    });
    assert_eq!(err.code(), "validation.memo_required");
    assert_eq!(err.category(), ErrorCategory::Validation);
    assert!(err.message().contains(DST_ACCOUNT));
}

/// Verifies that the `AccountNotFound` error code and message are stable.
#[test]
fn account_not_found_error_code() {
    let err = WalletError::Network(NetworkError::AccountNotFound {
        account_id: SRC_ACCOUNT.to_owned(),
    });
    assert_eq!(err.code(), "network.account_not_found");
    assert!(err.message().contains(SRC_ACCOUNT));
}

/// Verifies that the `TxTimeout` error code and display are stable.
#[test]
fn tx_timeout_error_code() {
    // SubmissionError::TxTimeout is the submit-timeout surface.
    // Use a full 64-char hex hash to exercise the hash-redaction display path.
    let full_hash = "aabbccddeeff001122334455667788990011223344556677889900aabbccddeeff";
    let err = WalletError::Submission(SubmissionError::TxTimeout {
        tx_hash: full_hash.to_owned(),
        seconds: 60,
    });
    assert_eq!(err.code(), "submission.tx_timeout");
    assert_eq!(err.category(), ErrorCategory::Submission);
    // Display redacts hash to first-8-last-8.
    let msg = err.message();
    assert!(msg.contains("..."), "display must redact the hash: {msg}");
    assert!(
        msg.contains("60"),
        "display must include timeout seconds: {msg}"
    );
    assert!(!msg.contains(full_hash), "must NOT show full hash: {msg}");
}

/// Mainnet write forbidden code is stable.
#[test]
fn mainnet_write_forbidden_code() {
    let err = WalletError::Network(NetworkError::MainnetWriteForbidden);
    assert_eq!(err.code(), "network.mainnet_write_forbidden");
}

/// Invalid XDR in submit returns a protocol error.
#[tokio::test]
async fn submit_invalid_xdr_returns_protocol_error() {
    let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").expect("valid URL");
    let result = submit_transaction_and_wait(
        &client,
        "not-valid-base64",
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await;
    assert!(
        matches!(result, Err(WalletError::Protocol(_))),
        "invalid XDR must return Protocol error, got: {result:?}"
    );
}

/// Mainnet passphrase is rejected at the submit layer with zero RPC calls.
#[tokio::test]
async fn mainnet_rejected_zero_rpc_calls() {
    let mock_server = MockServer::start().await;
    // Point client at mock server — any request would be recorded.
    let client = StellarRpcClient::new(&mock_server.uri()).expect("valid URL");
    let result = submit_transaction_and_wait(
        &client,
        "AAAAAA==",
        Duration::from_secs(5),
        "Public Global Stellar Network ; September 2015",
        None,
        None,
    )
    .await;
    assert!(
        matches!(
            result,
            Err(WalletError::Network(NetworkError::MainnetWriteForbidden))
        ),
        "mainnet passphrase must be rejected: {result:?}"
    );
    // Zero RPC calls must have been made.
    let received = mock_server.received_requests().await;
    assert!(
        received.is_none() || received.unwrap().is_empty(),
        "mainnet rejection must make zero RPC calls"
    );
}

/// SEP-29 fast-path: `memo_present=true` returns `Ok` without any RPC call.
#[tokio::test]
async fn sep29_memo_present_fast_path_no_rpc() {
    // A localhost URL that would fail if any HTTP call is made.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let result =
        stellar_agent_network::sep29::check_memo_required(&client, None, DST_ACCOUNT, true).await;
    assert!(
        result.is_ok(),
        "memo_present=true must return Ok without RPC: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock-RPC tests
// ─────────────────────────────────────────────────────────────────────────────

/// Mock send+poll: sendTransaction succeeds, getTransaction returns SUCCESS immediately.
#[tokio::test]
async fn submit_and_poll_success_with_mock() {
    let mock_server = MockServer::start().await;
    let envelope = build_test_signed_envelope(1101);
    mount_probe_and_signers(&mock_server, &envelope).await;

    // sendTransaction response.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_transaction_result(&envelope)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // getTransaction SUCCESS response (for all subsequent calls).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_transaction_success_result(
            &envelope, 1005,
        )))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("valid URL");

    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await;

    assert!(
        result.is_ok(),
        "submit+poll must succeed with mock server: {result:?}"
    );
    let sub = result.unwrap();
    assert_eq!(sub.ledger, 1005);
    assert_eq!(sub.tx_hash.len(), 64, "tx_hash must be 64-char hex");
}

/// Mock NOT_FOUND then SUCCESS: verifies polling continues past NOT_FOUND.
#[tokio::test]
async fn submit_and_poll_not_found_then_success() {
    let mock_server = MockServer::start().await;
    let envelope = build_test_signed_envelope(1102);
    mount_probe_and_signers(&mock_server, &envelope).await;

    // sendTransaction.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_transaction_result(&envelope)))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // First getTransaction → NOT_FOUND.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_transaction_not_found_result()))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second getTransaction → SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_transaction_success_result(
            &envelope, 1010,
        )))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("valid URL");

    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await;

    assert!(
        result.is_ok(),
        "NOT_FOUND then SUCCESS must succeed: {result:?}"
    );
    let sub = result.unwrap();
    assert_eq!(sub.ledger, 1010);
}
