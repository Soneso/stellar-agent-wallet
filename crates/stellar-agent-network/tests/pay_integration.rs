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
use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope, WriteXdr};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const SRC_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DST_ACCOUNT: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

// ─────────────────────────────────────────────────────────────────────────────
// Response fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn send_transaction_result() -> serde_json::Value {
    json!({
        "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "status": "PENDING",
        "latestLedger": 1001,
        "latestLedgerCloseTime": "1234567890"
    })
}

fn get_transaction_success_result(ledger: u32) -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "ledger": ledger,
        "txHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    })
}

fn get_transaction_not_found_result() -> serde_json::Value {
    json!({
        "status": "NOT_FOUND",
        "latestLedger": 1001
    })
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

/// Builds a signed envelope by adding a placeholder signature.
///
/// For submit-only tests we need a structurally valid signed envelope; the
/// signature bytes are placeholder zeros (the mock RPC does not validate them).
fn build_test_signed_xdr() -> String {
    use stellar_xdr::{DecoratedSignature, Signature, SignatureHint};
    let unsigned = build_test_unsigned_xdr();
    let mut env =
        TransactionEnvelope::from_xdr_base64(&unsigned, Limits::none()).expect("decode unsigned");

    if let TransactionEnvelope::Tx(ref mut v1) = env {
        v1.signatures = vec![DecoratedSignature {
            hint: SignatureHint([0u8; 4]),
            signature: Signature([0u8; 64].to_vec().try_into().expect("64 bytes")),
        }]
        .try_into()
        .expect("single sig fits VecM<_, 20>");
    }

    env.to_xdr_base64(Limits::none()).expect("encode signed")
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

    // sendTransaction response.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(send_transaction_result()))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // getTransaction SUCCESS response (for all subsequent calls).
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(get_transaction_success_result(1005)))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("valid URL");
    let signed_xdr = build_test_signed_xdr();

    let result = submit_transaction_and_wait(
        &client,
        &signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
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

    // sendTransaction.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(send_transaction_result()))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // First getTransaction → NOT_FOUND.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(get_transaction_not_found_result()))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second getTransaction → SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(get_transaction_success_result(1010)))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("valid URL");
    let signed_xdr = build_test_signed_xdr();

    let result = submit_transaction_and_wait(
        &client,
        &signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
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
