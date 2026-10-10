//! Transaction status reads against a mocked `getTransaction` endpoint.
//!
//! A `getTransaction` answer's status, ledger and `createdAt` are read as
//! received. The result XDR is decoded only for a `FAILED` transaction and the
//! result meta is never decoded, so an answer whose meta the wallet's XDR
//! cannot decode still confirms. These tests serve such a meta (a
//! `TransactionMeta` with discriminant 99) and pin that each read path
//! confirms, and that an undecodable result on a `FAILED` answer is a typed
//! on-chain failure, not a retry and not a timeout.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::error::{LedgerError, SubmissionError, WalletError};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::idempotent_submit::submit_transaction_idempotent;
use stellar_agent_network::submit::submit_transaction_and_wait;
use stellar_agent_test_support::EchoIdResponder;
use stellar_agent_test_support::signed_envelope::{SignedTestEnvelope, get_network_result};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const LEDGER: u32 = 4_321;

/// Base64 of a `TransactionMeta` whose union discriminant is 99, which no
/// version of the XDR defines.
const UNDECODABLE_META: &str = "AAAAYw==";

/// Base64 that is not a `TransactionResult`.
const UNDECODABLE_RESULT: &str = "AAAA";

/// A `txBadSeq` `TransactionResult` (fee 100), base64.
fn tx_bad_seq_result() -> String {
    use stellar_xdr::{
        Limits, TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
    };
    TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxBadSeq,
        ext: TransactionResultExt::V0,
    }
    .to_xdr_base64(Limits::none())
    .unwrap()
}

fn envelope(seed: u8, seq: i64) -> SignedTestEnvelope {
    SignedTestEnvelope::for_source_with_sequence([seed; 32], seq)
}

/// Mounts the endpoint identity probe, the signer-set fetch and a PENDING
/// `sendTransaction` answer, the reads and write every submit performs before
/// it polls.
async fn mount_send(server: &MockServer, envelope: &SignedTestEnvelope) {
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
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "hash": envelope.tx_hash_hex(),
            "status": "PENDING",
            "latestLedger": 2_000,
            "latestLedgerCloseTime": "1700000000"
        })))
        .up_to_n_times(1)
        .mount(server)
        .await;
}

async fn mount_get_transaction(server: &MockServer, answer: serde_json::Value) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(answer))
        .mount(server)
        .await;
}

fn success_with_undecodable_meta(tx_hash: &str) -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "txHash": tx_hash,
        "ledger": LEDGER,
        "createdAt": "1700000000",
        "resultMetaXdr": UNDECODABLE_META,
    })
}

fn failed_with_result(tx_hash: &str, result_xdr: &str) -> serde_json::Value {
    json!({
        "status": "FAILED",
        "txHash": tx_hash,
        "ledger": LEDGER,
        "createdAt": "1700000000",
        "resultXdr": result_xdr,
        "resultMetaXdr": UNDECODABLE_META,
    })
}

async fn get_transaction_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("request recording is enabled")
        .iter()
        .filter(|r| {
            serde_json::from_slice::<serde_json::Value>(&r.body)
                .ok()
                .and_then(|b| b["method"].as_str().map(|m| m == "getTransaction"))
                .unwrap_or(false)
        })
        .count()
}

fn assert_undecodable_result_op_failed(err: &WalletError) {
    match err {
        WalletError::Ledger(LedgerError::OpFailed { op, result_code }) => {
            assert_eq!(op, "unknown");
            assert_eq!(
                result_code,
                "undecodable result XDR: RPC method 'getTransaction' returned a malformed \
                 response: resultXdr does not decode: length limit exceeded"
            );
        }
        other => panic!("an undecodable FAILED result must be OpFailed, got {other:?}"),
    }
    assert_eq!(err.code(), "ledger.op_failed");
}

// ─────────────────────────────────────────────────────────────────────────────
// submit_transaction_and_wait
// ─────────────────────────────────────────────────────────────────────────────

/// A SUCCESS answer whose meta does not decode confirms at the reported
/// ledger.
#[tokio::test]
async fn submit_and_wait_confirms_with_undecodable_meta() {
    let envelope = envelope(0x21, 500);
    let server = MockServer::start().await;
    mount_send(&server, &envelope).await;
    mount_get_transaction(
        &server,
        success_with_undecodable_meta(envelope.tx_hash_hex()),
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect("a SUCCESS answer confirms whatever its meta");

    assert_eq!(result.ledger, LEDGER);
}

/// A FAILED answer whose result does not decode is a typed on-chain failure
/// naming the result, returned on the first poll: not a retry, not a timeout.
#[tokio::test]
async fn submit_and_wait_failed_with_undecodable_result_is_op_failed() {
    let envelope = envelope(0x22, 501);
    let server = MockServer::start().await;
    mount_send(&server, &envelope).await;
    mount_get_transaction(
        &server,
        failed_with_result(envelope.tx_hash_hex(), UNDECODABLE_RESULT),
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect_err("a FAILED answer is a failure");

    assert_undecodable_result_op_failed(&err);
    assert_eq!(
        get_transaction_requests(&server).await,
        1,
        "a FAILED answer is definitive and is not polled again"
    );
}

/// A FAILED answer with a decodable result keeps its typed mapping.
#[tokio::test]
async fn submit_and_wait_failed_with_valid_result_keeps_typed_mapping() {
    let envelope = envelope(0x23, 502);
    let server = MockServer::start().await;
    mount_send(&server, &envelope).await;
    mount_get_transaction(
        &server,
        failed_with_result(envelope.tx_hash_hex(), &tx_bad_seq_result()),
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect_err("a FAILED answer is a failure");

    assert!(
        matches!(
            err,
            WalletError::Submission(SubmissionError::SequenceNumberStale)
        ),
        "txBadSeq must map to SequenceNumberStale, got {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// submit_transaction_idempotent (receipt path)
// ─────────────────────────────────────────────────────────────────────────────

/// The idempotent receipt path confirms a SUCCESS answer whose meta does not
/// decode and finalizes the receipt `Success` at the reported ledger.
#[tokio::test]
async fn idempotent_receipt_confirms_with_undecodable_meta() {
    let envelope = envelope(0x24, 503);
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "status-reads").unwrap();
    let server = MockServer::start().await;
    mount_send(&server, &envelope).await;
    mount_get_transaction(
        &server,
        success_with_undecodable_meta(envelope.tx_hash_hex()),
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await
    .expect("a SUCCESS answer confirms whatever its meta");

    assert_eq!(result.ledger, LEDGER);
    let receipt = store
        .get(&stellar_agent_network::envelope_hash_hex(
            envelope.envelope_xdr(),
        ))
        .unwrap()
        .expect("receipt");
    assert_eq!(receipt.status, ReceiptStatus::Success);
    assert_eq!(receipt.ledger, Some(LEDGER));
}

/// The idempotent receipt path finalizes `Failed` with `ledger.op_failed` for
/// a FAILED answer whose result does not decode.
#[tokio::test]
async fn idempotent_receipt_failed_with_undecodable_result_finalizes_failed() {
    let envelope = envelope(0x25, 504);
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "status-reads").unwrap();
    let server = MockServer::start().await;
    mount_send(&server, &envelope).await;
    mount_get_transaction(
        &server,
        failed_with_result(envelope.tx_hash_hex(), UNDECODABLE_RESULT),
    )
    .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let err = submit_transaction_idempotent(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await
    .expect_err("a FAILED answer is a failure");

    assert_undecodable_result_op_failed(&err);
    assert_eq!(get_transaction_requests(&server).await, 1);
    let receipt = store
        .get(&stellar_agent_network::envelope_hash_hex(
            envelope.envelope_xdr(),
        ))
        .unwrap()
        .expect("receipt");
    assert_eq!(
        receipt.status,
        ReceiptStatus::Failed {
            code: "ledger.op_failed".to_owned()
        }
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// get_transaction_status and get_transaction_raw
// ─────────────────────────────────────────────────────────────────────────────

/// The status read reports SUCCESS and the ledger for an answer whose meta
/// does not decode.
#[tokio::test]
async fn get_transaction_status_reports_success_with_undecodable_meta() {
    let hash = "cd".repeat(32);
    let server = MockServer::start().await;
    mount_get_transaction(&server, success_with_undecodable_meta(&hash)).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let view = client
        .get_transaction_status(&hash)
        .await
        .expect("the status read does not decode the meta");

    assert_eq!(view.status, "SUCCESS");
    assert_eq!(view.ledger, Some(LEDGER));
}

/// `createdAt` reads both as the decimal string endpoints send and as a JSON
/// number.
#[tokio::test]
async fn get_transaction_raw_reads_created_at_as_string_and_number() {
    for created_at in [json!("1700000123"), json!(1_700_000_123)] {
        let server = MockServer::start().await;
        mount_get_transaction(
            &server,
            json!({"status": "SUCCESS", "ledger": LEDGER, "createdAt": created_at}),
        )
        .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();

        let record = client
            .get_transaction_raw(&stellar_xdr::Hash([7u8; 32]))
            .await
            .expect("record");

        assert_eq!(record.created_at(), Some(1_700_000_123), "{created_at}");
        assert_eq!(record.status(), "SUCCESS");
    }
}

/// The request carries the hash as 64 lowercase hex under `hash`.
#[tokio::test]
async fn get_transaction_raw_sends_the_hash_as_hex() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction",
            "params": {"hash": "ab".repeat(32)}
        })))
        .respond_with(EchoIdResponder::new(json!({"status": "NOT_FOUND"})))
        .mount(&server)
        .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let record = client
        .get_transaction_raw(&stellar_xdr::Hash([0xab; 32]))
        .await
        .expect("the mock answers only a request carrying the hex hash");

    assert_eq!(record.status(), "NOT_FOUND");
}
