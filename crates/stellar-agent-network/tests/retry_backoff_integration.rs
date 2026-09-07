//! Integration tests for bounded exponential-backoff retry.
//!
//! Tests the retry wrapper in the send and poll paths of both
//! `submit_transaction_and_wait` and `submit_transaction_idempotent`.
//!
//! Uses `wiremock` to serve deterministic JSON-RPC responses.  All mocks
//! disambiguate by JSON-RPC method name via `body_partial_json` (share a
//! single server endpoint for all JSON-RPC methods, matched by
//! `{ "method": "..." }`).
//!
//! # Coverage
//!
//! (a) Submit success path: `sendTransaction` → PENDING, `getTransaction` →
//!     SUCCESS — baseline no-regression.
//!
//! (b) Poll tolerates transient error: `getTransaction` returns a JSON error
//!     on the first poll, then SUCCESS → the poll loop continues, not aborts.
//!
//! (c) Retention non-regression: `getHealth` errors during a NOT_FOUND poll →
//!     `HealthCheckFailed` → keep-polling, NOT false-Ambiguous.
//!
//! (d) Idempotent submit success path: baseline no-regression.
//!
//! NOTE on send-path retry integration testing:
//! `stellar-rpc-client` wraps ALL `send_transaction` transport errors
//! (including JSON-RPC errors returned by a server) into
//! `Error::TransactionSubmissionFailed`.  `TransactionSubmissionFailed` is
//! intentionally NOT retried because it is indistinguishable from a genuine
//! on-chain rejection.  Therefore, the send-path retry for `JsonRpc(_)` /
//! timeout errors is verified at the unit level
//! (`retry::tests::send_timeout_is_retryable`,
//! `retry::tests::retry_then_success_returns_ok`) rather than via a mock
//! server.  The integration tests below verify that the success path is
//! unaffected and that poll-path tolerance works end-to-end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "integration test; panics/unwraps/eprintln acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::idempotent_submit::submit_transaction_idempotent;
use stellar_agent_network::submit::submit_transaction_and_wait;
use stellar_agent_test_support::EchoIdResponder;
use stellar_agent_test_support::signed_envelope::{SignedTestEnvelope, get_network_result};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FAKE_LEDGER: u32 = 5678;

/// Seed for the transaction source account.  A public test fixture, not a
/// production key.  Distinct from the seeds used in the other integration test
/// files so receipt stores never alias.
const SOURCE_SEED: [u8; 32] = [3u8; 32];

/// Builds a signed test envelope whose source account is the signing key's own
/// account, so the account the ledger reports is the one that signed.
fn build_signed_envelope() -> SignedTestEnvelope {
    SignedTestEnvelope::builder(SOURCE_SEED)
        .sequence(300)
        .amount_stroops(7_000_000)
        .build()
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

fn envelope_hash_for(signed_xdr: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signed_xdr.trim())
        .unwrap();
    Sha256::digest(&bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// JSON-RPC `sendTransaction` response for a PENDING submission.
fn send_pending(envelope: &SignedTestEnvelope) -> serde_json::Value {
    json!({
        "hash": envelope.tx_hash_hex(),
        "status": "PENDING",
        "latestLedger": 2001,
        "latestLedgerCloseTime": "1700000000"
    })
}

/// JSON-RPC `getTransaction` response for SUCCESS.
fn get_tx_success(envelope: &SignedTestEnvelope) -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "txHash": envelope.tx_hash_hex(),
        "ledger": FAKE_LEDGER,
        "createdAt": "1700000001",
        "envelopeXdr": null,
        "resultXdr": null,
        "resultMetaXdr": null
    })
}

/// JSON-RPC `getTransaction` response for NOT_FOUND (within retention window).
fn get_tx_not_found() -> serde_json::Value {
    json!({
        "status": "NOT_FOUND",
        "latestLedger": 2001,
        "latestLedgerCloseTime": "1700000000",
        "oldestLedger": 50,
        "ledgerRetentionWindow": 1951
    })
}

/// JSON-RPC `getHealth` response — within retention window.
fn get_health_within_window() -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": 2001,
        "oldestLedger": 50,
        "ledgerRetentionWindow": 1951
    })
}

/// A JSON-RPC error body (simulates a 429 / transport error returned by the
/// mock server as an application-level error response).  This is what jsonrpsee
/// parses into `Error::JsonRpc(_)`.
fn jsonrpc_error_body(id: Option<&serde_json::Value>) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": "rate limit exceeded"
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) Baseline success path — no regression
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_transaction_and_wait`: baseline success path — `sendTransaction`
/// returns PENDING, `getTransaction` returns SUCCESS.
///
/// Verifies the retry wrap does not break the happy path.
///
/// # Note on send-path retry integration
///
/// `stellar-rpc-client` wraps ALL `send_transaction` errors (including
/// transport errors) as `TransactionSubmissionFailed`.  This variant is
/// intentionally NOT retried, so mock-server-induced JSON-RPC errors cannot
/// exercise the `JsonRpc` retry branch.  The send-path retry for `JsonRpc` +
/// `TransactionSubmissionTimeout` is verified at unit level
/// (`retry::tests::send_timeout_is_retryable`,
/// `retry::tests::retry_then_success_returns_ok`).
#[tokio::test]
async fn submit_and_wait_success_path_no_regression() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    let server_url = server.uri();
    mount_probe_and_signers(&server, &envelope).await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_pending(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → SUCCESS immediately.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_tx_success(&envelope)))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server_url).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        result.is_ok(),
        "success path must not be broken by the retry wrapper: {result:?}"
    );
    assert_eq!(result.unwrap().ledger, FAKE_LEDGER);
}

// ─────────────────────────────────────────────────────────────────────────────
// (a2) Send-path: TransactionSubmissionFailed is NOT retried
// ─────────────────────────────────────────────────────────────────────────────

/// When `sendTransaction` returns a JSON-RPC error body (which
/// `stellar-rpc-client` wraps as `TransactionSubmissionFailed`), the error is
/// surfaced immediately and NOT retried.
///
/// A transport-rate-limit on send arrives as `TransactionSubmissionFailed`,
/// which is indistinguishable from a genuine on-chain rejection, so retrying
/// it is unsafe.  `is_retryable_send_error` returns false for
/// `TransactionSubmissionFailed`.
#[tokio::test]
async fn send_submission_failed_is_not_retried() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    let server_url = server.uri();
    mount_probe_and_signers(&server, &envelope).await;

    // sendTransaction: always returns a JSON-RPC error body.
    // stellar-rpc-client wraps this as TransactionSubmissionFailed.
    // We serve 10 copies; if the retry loop were to retry, it would consume
    // more than 1.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonrpc_error_body(None)))
        .expect(1) // must be called exactly once — no retry
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server_url).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(10),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    // Must fail immediately (1 attempt), not retry.
    assert!(
        result.is_err(),
        "TransactionSubmissionFailed must not be retried and must fail: {result:?}"
    );
    // The mock's `.expect(1)` assertion is checked when the server drops.
    // If we retried, wiremock would fail the test when the server is dropped.
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) Poll tolerates transient error — does not abort
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_transaction_and_wait`: `getTransaction` returns a JSON-RPC error
/// on the first poll, then returns SUCCESS.  The poll loop treats the error
/// like NOT_FOUND and continues polling rather than aborting.
#[tokio::test]
async fn poll_transient_error_treated_as_not_found_then_succeeds() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    let server_url = server.uri();
    mount_probe_and_signers(&server, &envelope).await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_pending(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction: first call returns a JSON-RPC error; second returns SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonrpc_error_body(None)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_tx_success(&envelope)))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server_url).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        result.is_ok(),
        "transient poll error should be treated as NOT_FOUND, not abort: {result:?}"
    );
    assert_eq!(result.unwrap().ledger, FAKE_LEDGER);
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) Block-B non-regression: get_health error → HealthCheckFailed → keep-polling
// ─────────────────────────────────────────────────────────────────────────────

/// Retention non-regression: when `getHealth` errors during a `NOT_FOUND` poll
/// window, the poll loop continues (`HealthCheckFailed` semantics) and does NOT
/// produce a false `Ambiguous`.
///
/// The sequence is:
/// 1. `sendTransaction` → PENDING.
/// 2. `getTransaction` → NOT_FOUND (first iteration).
/// 3. `getHealth` → JSON-RPC error (simulating health-check blip).
/// 4. `getTransaction` → SUCCESS (second iteration, no health call needed).
///
/// Expected: `submit_transaction_idempotent` returns `ReceiptStatus::Success`,
/// NOT `Ambiguous`.
#[tokio::test]
async fn block_b_non_regression_health_error_keeps_polling_not_ambiguous() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();
    let envelope_hash = envelope_hash_for(signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-c-health-regression").unwrap();

    let server = MockServer::start().await;
    let server_url = server.uri();
    mount_probe_and_signers(&server, &envelope).await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_pending(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction: first call → NOT_FOUND; second → SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_tx_not_found()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_tx_success(&envelope)))
        .mount(&server)
        .await;

    // getHealth → JSON-RPC error (blip).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(jsonrpc_error_body(None)))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server_url).unwrap();
    let result = submit_transaction_idempotent(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        300, // recorded_at_ledger — within the window (oldest=50 < 300)
    )
    .await;

    // Must succeed — HealthCheckFailed must NOT produce Ambiguous.
    assert!(
        result.is_ok(),
        "health-check error must not produce Ambiguous: {result:?}"
    );

    // Receipt must be Success, not Ambiguous.
    let receipt = store.get(&envelope_hash).unwrap().unwrap();
    assert!(
        matches!(receipt.status, ReceiptStatus::Success),
        "receipt must be Success after health-check blip, got: {:?}",
        receipt.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) Idempotent success path — no regression
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_transaction_idempotent`: baseline success path.
///
/// Verifies the retry wrap does not break the idempotent submit path.
/// The send-path retry integration limitation is documented in (a) above.
#[tokio::test]
async fn idempotent_submit_success_path_no_regression() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-c-idempotent-success").unwrap();

    let server = MockServer::start().await;
    let server_url = server.uri();
    mount_probe_and_signers(&server, &envelope).await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_pending(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_tx_success(&envelope)))
        .mount(&server)
        .await;

    // getHealth → within window (polled on NOT_FOUND iterations; not needed
    // here since we go straight to SUCCESS, but mount defensively).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(get_health_within_window()))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server_url).unwrap();
    let result = submit_transaction_idempotent(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        300, // recorded_at_ledger
    )
    .await;

    assert!(
        result.is_ok(),
        "idempotent success path must not be broken by the retry wrapper: {result:?}"
    );
    assert_eq!(result.unwrap().ledger, FAKE_LEDGER);
}
