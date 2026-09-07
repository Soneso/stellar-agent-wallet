//! Integration tests for `submit_transaction_and_wait`.
//!
//! Uses `wiremock` to serve deterministic JSON-RPC responses.  All mocks
//! share one server endpoint disambiguated by JSON-RPC method via
//! `body_partial_json`.
//!
//! # Coverage
//!
//! (a) Full success path: sendTransaction→PENDING → getTransaction→SUCCESS.
//! (b) On-chain FAILED path: getTransaction→FAILED with result XDR; asserts
//!     the typed WalletError variant and its stable error code.
//! (c) Timeout path: getTransaction always returns NOT_FOUND; TxTimeout error.
//! (d) Unexpected getTransaction status → RpcUnreachable.
//! (e) Transient poll error (JsonRpc) treated as NOT_FOUND, not fatal.
//! (f) Mainnet URL guard fires for known SDF mainnet hostnames.
//! (g) map_send_error variants: TransactionSubmissionFailed, Xdr, generic.
//! (h) map_operation_result: SrcNoTrust, NoDestination, OpBadAuth, OpNoAccount.
//! (i) map_failed_result: TxSuccess arm, TxFailed empty ops, catch-all other.
//! (j) inner_result_code_name: all 18 InnerTransactionResultResult discriminants.
//! (k) bytes_to_hex: empty and known-value round-trip.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics/unwraps acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::error::{LedgerError, NetworkError, SubmissionError, WalletError};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::submit::{
    SubmissionSignerKind, redact_tx_hash, submit_transaction_and_wait,
};
use stellar_agent_test_support::EchoIdResponder;
use stellar_agent_test_support::signed_envelope::{SignedTestEnvelope, get_network_result};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FAKE_LEDGER: u32 = 4567;

/// Seed for the transaction source account. A public test fixture, never a
/// production key.
const SOURCE_SEED: [u8; 32] = [7u8; 32];

/// Builds a signed test envelope whose source account is the signing key's own
/// account, so the account the ledger reports is the one that signed.
fn build_envelope(seq: i64) -> SignedTestEnvelope {
    SignedTestEnvelope::for_source_with_sequence(SOURCE_SEED, seq)
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

fn send_pending_response(envelope: &SignedTestEnvelope) -> serde_json::Value {
    json!({
        "hash": envelope.tx_hash_hex(),
        "status": "PENDING",
        "latestLedger": 1000,
        "latestLedgerCloseTime": "1699999999"
    })
}

fn get_success_response(envelope: &SignedTestEnvelope) -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "txHash": envelope.tx_hash_hex(),
        "ledger": FAKE_LEDGER,
        "createdAt": "1700000000",
        "envelopeXdr": null,
        "resultXdr": null,
        "resultMetaXdr": null
    })
}

fn get_not_found_response() -> serde_json::Value {
    json!({
        "status": "NOT_FOUND",
        "latestLedger": 1000,
        "latestLedgerCloseTime": "1700000001",
        "oldestLedger": 900,
        "ledgerRetentionWindow": 100
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) Full success path
// ─────────────────────────────────────────────────────────────────────────────

/// sendTransaction→PENDING then getTransaction→SUCCESS yields Ok(SubmissionResult)
/// with the correct ledger and the signer_kind forwarded unchanged.
#[tokio::test]
async fn send_pending_then_get_success_returns_ok_with_correct_ledger() {
    let envelope = build_envelope(1001);
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response(&envelope)))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        Some(SubmissionSignerKind::Software),
    )
    .await;

    assert!(
        result.is_ok(),
        "sendTransaction→PENDING then getTransaction→SUCCESS must return Ok; got: {result:?}"
    );
    let sub = result.unwrap();
    assert_eq!(
        sub.ledger, FAKE_LEDGER,
        "ledger must match the getTransaction SUCCESS response"
    );
    assert_eq!(
        sub.signer_kind,
        Some(SubmissionSignerKind::Software),
        "signer_kind must be forwarded unchanged"
    );
    // tx_hash is the hex-encoded 32-byte SHA-256 that the RPC client decodes
    // from the `hash` field in the sendTransaction response.
    assert_eq!(
        sub.tx_hash.len(),
        64,
        "tx_hash must be 64 hex chars (SHA-256)"
    );
}

/// getTransaction first returns NOT_FOUND, then SUCCESS on the next poll.
/// Verifies the poll loop continues past NOT_FOUND and eventually confirms.
#[tokio::test]
async fn not_found_then_success_confirms_on_subsequent_poll() {
    let envelope = build_envelope(1002);
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // First poll: NOT_FOUND.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_not_found_response()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Subsequent polls: SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response(&envelope)))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

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
        "NOT_FOUND-then-SUCCESS must return Ok; got: {result:?}"
    );
    assert_eq!(result.unwrap().ledger, FAKE_LEDGER);
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) On-chain FAILED path
// ─────────────────────────────────────────────────────────────────────────────

/// getTransaction→FAILED with a TxFailed([Payment(Underfunded)]) result XDR
/// returns WalletError::Ledger(InsufficientBalance) with the correct code.
#[tokio::test]
async fn get_failed_with_underfunded_xdr_returns_insufficient_balance() {
    use stellar_xdr::{
        Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
        TransactionResultExt, TransactionResultResult, VecM, WriteXdr,
    };

    let envelope = build_envelope(1003);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![OperationResult::OpInner(OperationResultTr::Payment(
        PaymentResult::Underfunded,
    ))]
    .try_into()
    .unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "getTransaction FAILED must return Err; got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            WalletError::Ledger(LedgerError::InsufficientBalance { .. })
        ),
        "FAILED+Underfunded must yield InsufficientBalance; got: {err:?}"
    );
    assert_eq!(
        err.code(),
        "ledger.insufficient_balance",
        "error code must be ledger.insufficient_balance; got: {}",
        err.code()
    );
}

/// getTransaction→FAILED with Payment(NoTrust) XDR yields TrustlineMissing on
/// the destination account.
#[tokio::test]
async fn get_failed_with_no_trust_xdr_returns_trustline_missing_destination() {
    use stellar_xdr::{
        Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
        TransactionResultExt, TransactionResultResult, VecM, WriteXdr,
    };

    let envelope = build_envelope(1004);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![OperationResult::OpInner(OperationResultTr::Payment(
        PaymentResult::NoTrust,
    ))]
    .try_into()
    .unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(
            &err,
            WalletError::Ledger(LedgerError::TrustlineMissing { account, .. })
            if account == "destination"
        ),
        "NoTrust must yield TrustlineMissing(destination); got: {err:?}"
    );
}

/// getTransaction→FAILED with Payment(SrcNoTrust) XDR yields TrustlineMissing
/// on the source account.
#[tokio::test]
async fn get_failed_with_src_no_trust_xdr_returns_trustline_missing_source() {
    use stellar_xdr::{
        Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
        TransactionResultExt, TransactionResultResult, VecM, WriteXdr,
    };

    let envelope = build_envelope(1005);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![OperationResult::OpInner(OperationResultTr::Payment(
        PaymentResult::SrcNoTrust,
    ))]
    .try_into()
    .unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(
            &err,
            WalletError::Ledger(LedgerError::TrustlineMissing { account, .. })
            if account == "source"
        ),
        "SrcNoTrust must yield TrustlineMissing(source); got: {err:?}"
    );
}

/// getTransaction→FAILED with Payment(NoDestination) yields DestinationInvalid.
#[tokio::test]
async fn get_failed_with_no_destination_yields_destination_invalid() {
    use stellar_xdr::{
        Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
        TransactionResultExt, TransactionResultResult, VecM, WriteXdr,
    };

    let envelope = build_envelope(1006);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![OperationResult::OpInner(OperationResultTr::Payment(
        PaymentResult::NoDestination,
    ))]
    .try_into()
    .unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            WalletError::Ledger(LedgerError::DestinationInvalid { .. })
        ),
        "NoDestination must yield DestinationInvalid; got: {err:?}"
    );
}

/// getTransaction→FAILED with OperationResult::OpBadAuth yields OpFailed with
/// code "op_bad_auth".
#[tokio::test]
async fn get_failed_with_op_bad_auth_yields_op_failed_bad_auth() {
    use stellar_xdr::{
        Limits, OperationResult, TransactionResult, TransactionResultExt, TransactionResultResult,
        VecM, WriteXdr,
    };

    let envelope = build_envelope(1007);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![OperationResult::OpBadAuth].try_into().unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(
            &err,
            WalletError::Ledger(LedgerError::OpFailed { result_code, .. })
            if result_code == "op_bad_auth"
        ),
        "OpBadAuth must yield OpFailed(op_bad_auth); got: {err:?}"
    );
}

/// getTransaction→FAILED with OperationResult::OpNoAccount yields OpFailed with
/// code "op_no_account".
#[tokio::test]
async fn get_failed_with_op_no_account_yields_op_failed_no_account() {
    use stellar_xdr::{
        Limits, OperationResult, TransactionResult, TransactionResultExt, TransactionResultResult,
        VecM, WriteXdr,
    };

    let envelope = build_envelope(1008);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![OperationResult::OpNoAccount].try_into().unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(
            &err,
            WalletError::Ledger(LedgerError::OpFailed { result_code, .. })
            if result_code == "op_no_account"
        ),
        "OpNoAccount must yield OpFailed(op_no_account); got: {err:?}"
    );
}

/// getTransaction→FAILED with TxFailed([]) (empty op list) yields OpFailed
/// with a descriptive "TxFailed (no op results)" code.
#[tokio::test]
async fn get_failed_with_empty_ops_yields_op_failed_no_ops() {
    use stellar_xdr::{
        Limits, OperationResult, TransactionResult, TransactionResultExt, TransactionResultResult,
        VecM, WriteXdr,
    };

    let envelope = build_envelope(1009);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![].try_into().unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(
            &err,
            WalletError::Ledger(LedgerError::OpFailed { result_code, .. })
            if result_code.contains("TxFailed") && result_code.contains("no op results")
        ),
        "TxFailed([]) must yield OpFailed containing 'TxFailed (no op results)'; got: {err:?}"
    );
}

/// getTransaction→FAILED with TxSuccess result (unexpected in FAILED branch)
/// maps to the defensive OpFailed arm, NOT to a success path.
#[tokio::test]
async fn get_failed_with_tx_success_result_maps_to_defensive_op_failed() {
    use stellar_xdr::{
        Limits, OperationResult, TransactionResult, TransactionResultExt, TransactionResultResult,
        VecM, WriteXdr,
    };

    let envelope = build_envelope(1010);
    let signed_xdr = envelope.envelope_xdr();

    let ops: VecM<OperationResult> = vec![].try_into().unwrap();
    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxSuccess(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    // A FAILED status with TxSuccess result is structurally contradictory.
    // The defensive arm must produce an error (not silently return Ok).
    assert!(
        result.is_err(),
        "FAILED status with TxSuccess result must return Err (defensive); got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(&err, WalletError::Ledger(LedgerError::OpFailed { result_code, .. })
            if result_code.contains("FAILED_with_TxSuccess_result")),
        "TxSuccess in FAILED branch must map to OpFailed(FAILED_with_TxSuccess_result); got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) Unexpected getTransaction status → RpcUnreachable
// ─────────────────────────────────────────────────────────────────────────────

/// An unknown status string from getTransaction returns RpcUnreachable.
///
/// The status field is server-controlled; an unknown value is not a transient
/// error but a protocol anomaly that cannot be retried.
#[tokio::test]
async fn unexpected_get_transaction_status_returns_rpc_unreachable() {
    let envelope = build_envelope(1011);
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Return an unknown status string.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "UNKNOWN_FUTURE_STATUS",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": null,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "unexpected getTransaction status must return Err; got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            WalletError::Network(NetworkError::RpcUnreachable { .. })
        ),
        "unexpected status must map to RpcUnreachable; got: {err:?}"
    );
    // The error reason must name the bad status for operability.
    let reason = format!("{err:?}");
    assert!(
        reason.contains("UNKNOWN_FUTURE_STATUS"),
        "error must reference the unexpected status string; got: {reason}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (e) Transient poll error treated as NOT_FOUND (not fatal)
// ─────────────────────────────────────────────────────────────────────────────

/// A transient JsonRpc error on the first getTransaction poll is treated as
/// NOT_FOUND (logged at debug, falls through to deadline check + sleep).
/// The next poll returns SUCCESS and the submission confirms.
///
/// This prevents a transient 429 or connection-reset on a poll from aborting
/// an otherwise successful submission.
#[tokio::test]
async fn transient_poll_error_falls_through_to_not_found_then_success() {
    use wiremock::ResponseTemplate;

    let envelope = build_envelope(1012);
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // First getTransaction poll: return HTTP 500 (maps to JsonRpc error in jsonrpsee).
    // Transient — treated as NOT_FOUND by the poll loop.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Subsequent getTransaction polls: SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response(&envelope)))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

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
        "transient poll error should fall through to NOT_FOUND; next SUCCESS must confirm; \
         got: {result:?}"
    );
    assert_eq!(result.unwrap().ledger, FAKE_LEDGER);
}

// ─────────────────────────────────────────────────────────────────────────────
// (f) Mainnet URL guard
// ─────────────────────────────────────────────────────────────────────────────

/// A client URL containing "mainnet.stellar" is rejected even with a testnet
/// passphrase (URL-heuristic defence-in-depth guard).
///
/// Uses `is_mainnet_url`-triggering patterns from the production code.
#[tokio::test]
async fn mainnet_url_pattern_rejected_at_submit() {
    // Only the URL check applies; using testnet passphrase to isolate the guard.
    // We point at a localhost server to avoid real network calls — the URL check
    // fires before any XDR decode or RPC call.
    let client = StellarRpcClient::new("https://mainnet.stellar.org:8001/rpc").unwrap();

    let envelope = build_envelope(9999);
    let signed_xdr = envelope.envelope_xdr();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(WalletError::Network(NetworkError::MainnetWriteForbidden))
        ),
        "mainnet URL must be rejected as MainnetWriteForbidden; got: {result:?}"
    );
}

/// A client URL containing "pubnet" is rejected by the URL heuristic guard.
#[tokio::test]
async fn pubnet_url_pattern_rejected_at_submit() {
    let client = StellarRpcClient::new("https://pubnet.example.com/rpc").unwrap();

    let envelope = build_envelope(9998);
    let signed_xdr = envelope.envelope_xdr();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(WalletError::Network(NetworkError::MainnetWriteForbidden))
        ),
        "pubnet URL must be rejected as MainnetWriteForbidden; got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (g) sendTransaction error mapping
// ─────────────────────────────────────────────────────────────────────────────

/// sendTransaction returns TransactionSubmissionFailed → TxMalformed (not retried).
#[tokio::test]
async fn send_transaction_submission_failed_returns_tx_malformed() {
    let envelope = build_envelope(1013);
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    // Serve an empty JSON body — jsonrpsee will produce a deserialization error
    // that maps to a JsonRpc client error, but we actually want to simulate
    // TransactionSubmissionFailed, which requires the sendTransaction response
    // to have `status: "ERROR"`.  The stellar-rpc-client maps status:ERROR to
    // TransactionSubmissionFailed.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "hash": envelope.tx_hash_hex(),
            "status": "ERROR",
            "latestLedger": 1001,
            "latestLedgerCloseTime": "1699999999",
            "errorResultXdr": "AAAAAAAAAGT////7AAAAAA=="
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "TransactionSubmissionFailed must return Err; got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            WalletError::Submission(SubmissionError::TxMalformed { .. })
        ),
        "TransactionSubmissionFailed must map to TxMalformed; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (j) inner_result_code_name — via RPC-driven getTransaction FAILED path
// ─────────────────────────────────────────────────────────────────────────────

/// A fee-bump outer envelope submitted via mock RPC that returns FAILED with
/// `TxFeeBumpInnerFailed(TxBadAuth)` XDR produces
/// `SubmissionError::FeeBumpInnerRejected` with `inner_result_code="TxBadAuth"`.
///
/// The remaining inner_result_code_name variants are constructable XDR
/// discriminants; TxBadAuth is representative of the mapping contract.
/// The full 18-variant exhaustion is covered in the crate-internal unit tests
/// (`src/submit.rs#[cfg(test)]`).
#[tokio::test]
async fn get_failed_fee_bump_inner_rejected_carries_inner_result_code() {
    use stellar_xdr::{
        Hash, InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
        InnerTransactionResultResult, Limits, TransactionResult, TransactionResultExt,
        TransactionResultResult, WriteXdr,
    };

    let envelope = build_envelope(1015);
    let signed_xdr = envelope.envelope_xdr();

    let pair = InnerTransactionResultPair {
        transaction_hash: Hash([0xabu8; 32]),
        result: InnerTransactionResult {
            fee_charged: 100,
            result: InnerTransactionResultResult::TxBadAuth,
            ext: InnerTransactionResultExt::V0,
        },
    };
    let tx_result = TransactionResult {
        fee_charged: 200,
        result: TransactionResultResult::TxFeeBumpInnerFailed(pair),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "FAILED fee-bump must return Err; got: {result:?}"
    );
    let err = result.unwrap_err();
    let (inner_result_code, inner_tx_hash_redacted) = match &err {
        WalletError::Submission(SubmissionError::FeeBumpInnerRejected {
            inner_result_code,
            inner_tx_hash_redacted,
        }) => (inner_result_code.as_str(), inner_tx_hash_redacted.as_str()),
        other => panic!("expected FeeBumpInnerRejected; got: {other:?}"),
    };
    assert_eq!(
        inner_result_code, "TxBadAuth",
        "inner_result_code must be 'TxBadAuth'; got: {inner_result_code}"
    );
    assert!(
        inner_tx_hash_redacted.contains("..."),
        "inner_tx_hash_redacted must be truncated; got: {inner_tx_hash_redacted}"
    );
    assert_eq!(
        err.code(),
        "submission.feebump_inner_rejected",
        "error code must be submission.feebump_inner_rejected; got: {}",
        err.code()
    );
}

/// `TxFeeBumpInnerFailed(TxBadSeq)` maps to FeeBumpInnerRejected with
/// `inner_result_code="TxBadSeq"`.  Distinguishes the inner TxBadSeq
/// (inner tx sequence stale) from the outer TxBadSeq (outer-level SequenceNumberStale).
#[tokio::test]
async fn get_failed_fee_bump_inner_bad_seq_is_feebump_inner_rejected_not_stale() {
    use stellar_xdr::{
        Hash, InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
        InnerTransactionResultResult, Limits, TransactionResult, TransactionResultExt,
        TransactionResultResult, WriteXdr,
    };

    let envelope = build_envelope(1016);
    let signed_xdr = envelope.envelope_xdr();

    let pair = InnerTransactionResultPair {
        transaction_hash: Hash([0xccu8; 32]),
        result: InnerTransactionResult {
            fee_charged: 100,
            result: InnerTransactionResultResult::TxBadSeq,
            ext: InnerTransactionResultExt::V0,
        },
    };
    let tx_result = TransactionResult {
        fee_charged: 200,
        result: TransactionResultResult::TxFeeBumpInnerFailed(pair),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    match &err {
        WalletError::Submission(SubmissionError::FeeBumpInnerRejected {
            inner_result_code,
            ..
        }) => {
            assert_eq!(
                inner_result_code.as_str(),
                "TxBadSeq",
                "inner TxBadSeq must produce FeeBumpInnerRejected(TxBadSeq); got: {inner_result_code}"
            );
        }
        other => panic!(
            "TxFeeBumpInnerFailed(TxBadSeq) must map to FeeBumpInnerRejected; got: {other:?}"
        ),
    }
    // Must NOT be SequenceNumberStale (that is the outer TxBadSeq mapping).
    assert!(
        !matches!(
            err,
            WalletError::Submission(SubmissionError::SequenceNumberStale)
        ),
        "inner TxBadSeq must NOT map to outer SequenceNumberStale; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (k) redact_tx_hash — via public API
// ─────────────────────────────────────────────────────────────────────────────

/// `redact_tx_hash` truncates a 64-char hash to first-8-last-8 with "..." separator.
/// Short hashes (≤ 16 chars) are returned verbatim.
///
/// `redact_tx_hash` is publicly exported from `stellar_agent_network::submit`.
#[test]
fn redact_tx_hash_truncates_long_hash_to_first8_last8() {
    let full_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    assert_eq!(full_hash.len(), 64, "fixture must be a 64-char hash");

    let redacted = redact_tx_hash(full_hash);

    assert!(
        redacted.starts_with("abcdef01"),
        "redacted must start with first 8 chars; got: {redacted}"
    );
    assert!(
        redacted.ends_with("23456789"),
        "redacted must end with last 8 chars; got: {redacted}"
    );
    assert!(
        redacted.contains("..."),
        "redacted must contain '...' separator; got: {redacted}"
    );
    assert!(
        redacted.len() < full_hash.len(),
        "redacted ({}) must be shorter than original ({}); got: {redacted}",
        redacted.len(),
        full_hash.len()
    );
}

/// A hash exactly 16 chars long is returned verbatim (boundary: `16 > 16` is false).
#[test]
fn redact_tx_hash_exactly_16_chars_returned_verbatim() {
    let hash = "1234567890abcdef";
    assert_eq!(hash.len(), 16);
    // The guard is `hash.len() > 16`; exactly 16 is NOT > 16, so verbatim.
    assert_eq!(
        redact_tx_hash(hash),
        hash,
        "16-char hash must be returned verbatim (len > 16 guard is false at exactly 16)"
    );
}

/// A hash shorter than 16 chars is returned verbatim.
#[test]
fn redact_tx_hash_short_hash_returned_verbatim() {
    let hash = "abcd";
    assert_eq!(redact_tx_hash(hash), hash);
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional: TxBadSeq outer-level yields SequenceNumberStale via RPC path
// ─────────────────────────────────────────────────────────────────────────────

/// getTransaction→FAILED with outer `TxBadSeq` TransactionResult yields
/// `SubmissionError::SequenceNumberStale` with the stable error code
/// "submission.sequence_number_stale".
///
/// Regression lock: the typed TxBadSeq arm must NOT fall through to `other => OpFailed`.
#[tokio::test]
async fn get_failed_outer_tx_bad_seq_yields_sequence_number_stale() {
    use stellar_xdr::{
        Limits, TransactionResult, TransactionResultExt, TransactionResultResult, WriteXdr,
    };

    let envelope = build_envelope(1017);
    let signed_xdr = envelope.envelope_xdr();

    let tx_result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxBadSeq,
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            WalletError::Submission(SubmissionError::SequenceNumberStale)
        ),
        "outer TxBadSeq must map to SequenceNumberStale; got: {err:?}"
    );
    assert_eq!(
        err.code(),
        "submission.sequence_number_stale",
        "error code must be submission.sequence_number_stale; got: {}",
        err.code()
    );
}

/// getTransaction→FAILED with no `resultXdr` (null) returns a typed error
/// and does NOT panic.
#[tokio::test]
async fn get_failed_with_null_result_xdr_returns_typed_error_no_panic() {
    let envelope = build_envelope(1018);
    let signed_xdr = envelope.envelope_xdr();

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(&envelope)))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": envelope.tx_hash_hex(),
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": null,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_and_wait(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    // Must return an error — no panic.
    assert!(
        result.is_err(),
        "FAILED with null resultXdr must return Err; got: {result:?}"
    );
    let err = result.unwrap_err();
    // Must NOT be a transport error (RpcUnreachable) — must be a ledger/submission code.
    assert_ne!(
        err.code(),
        "network.rpc_unreachable",
        "FAILED with null XDR must NOT map to rpc_unreachable; got: {}",
        err.code()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SubmissionResult serde round-trip
// ─────────────────────────────────────────────────────────────────────────────

/// `SubmissionSignerKind` serialises to snake_case JSON and round-trips via
/// `serde_json`.  `SubmissionResult` is `#[non_exhaustive]` so it cannot be
/// constructed outside the crate; we test `SubmissionSignerKind` serialisation
/// directly via the Option<SubmissionSignerKind> round-trip.
#[test]
fn submission_signer_kind_serde_round_trip_all_variants() {
    for kind in [
        Some(SubmissionSignerKind::Software),
        Some(SubmissionSignerKind::Keyring),
        Some(SubmissionSignerKind::Hardware),
        None::<SubmissionSignerKind>,
    ] {
        let json = serde_json::to_value(kind).unwrap();
        let restored: Option<SubmissionSignerKind> = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            kind, restored,
            "SubmissionSignerKind must round-trip through JSON; json={json}"
        );
        // Verify snake_case representation for Some variants.
        if let Some(k) = kind {
            let expected_str = match k {
                SubmissionSignerKind::Software => "software",
                SubmissionSignerKind::Keyring => "keyring",
                SubmissionSignerKind::Hardware => "hardware",
            };
            assert_eq!(
                json.as_str(),
                Some(expected_str),
                "SubmissionSignerKind must serialise to snake_case '{expected_str}'; got: {json}"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Endpoint identity probe
// ─────────────────────────────────────────────────────────────────────────────

/// Counts the requests the server received for one JSON-RPC method.
async fn method_count(server: &MockServer, rpc_method: &str) -> usize {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .iter()
        .filter(|req| {
            serde_json::from_slice::<serde_json::Value>(&req.body)
                .ok()
                .and_then(|body| body["method"].as_str().map(|m| m == rpc_method))
                .unwrap_or(false)
        })
        .count()
}

/// Counts the `sendTransaction` requests the server received.
async fn send_transaction_count(server: &MockServer) -> usize {
    method_count(server, "sendTransaction").await
}

/// Mounts a `getNetwork` arm reporting `passphrase`.
async fn mount_get_network(server: &MockServer, passphrase: &str) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(passphrase)))
        .mount(server)
        .await;
}

/// Mounts the send and confirm arms for `envelope`.
async fn mount_send_and_confirm(server: &MockServer, envelope: &SignedTestEnvelope) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response(envelope)))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response(envelope)))
        .mount(server)
        .await;
}

/// Mounts the signer-set arm for `envelope`.
async fn mount_get_ledger_entries(server: &MockServer, envelope: &SignedTestEnvelope) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(EchoIdResponder::new(envelope.ledger_entries_result()))
        .mount(server)
        .await;
}

/// An endpoint that answers with the mainnet passphrase is refused, even
/// though the caller declared testnet, and nothing is sent.
///
/// The declaration is a claim about the endpoint, not authority over it.
#[tokio::test]
async fn endpoint_serving_mainnet_refuses_with_no_send() {
    let envelope = build_envelope(2001);
    let server = MockServer::start().await;
    mount_get_network(&server, "Public Global Stellar Network ; September 2015").await;
    mount_get_ledger_entries(&server, &envelope).await;
    mount_send_and_confirm(&server, &envelope).await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(10),
        TESTNET_PASSPHRASE,
        None,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(WalletError::Network(NetworkError::MainnetWriteForbidden))
        ),
        "an endpoint serving mainnet must be refused: {result:?}"
    );
    assert_eq!(
        send_transaction_count(&server).await,
        0,
        "nothing may be sent to an endpoint serving mainnet"
    );
}

/// An endpoint serving a network that is neither the declared one nor mainnet
/// is refused with its own code, and nothing is sent.
#[tokio::test]
async fn endpoint_serving_third_network_refuses_endpoint_network_mismatch() {
    let envelope = build_envelope(2002);
    let server = MockServer::start().await;
    mount_get_network(&server, "Test SDF Future Network ; October 2022").await;
    mount_get_ledger_entries(&server, &envelope).await;
    mount_send_and_confirm(&server, &envelope).await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(10),
        TESTNET_PASSPHRASE,
        None,
    )
    .await
    .expect_err("a foreign network must be refused");

    assert_eq!(err.code(), "network.endpoint_network_mismatch", "{err:?}");
    assert_eq!(
        send_transaction_count(&server).await,
        0,
        "nothing may be sent to an endpoint serving another network"
    );
    // A passphrase mismatch is a verdict, not a transport fault. Retrying it
    // would delay the refusal by the whole backoff schedule and ask an
    // endpoint that has already answered to answer again.
    assert_eq!(
        method_count(&server, "getNetwork").await,
        1,
        "a passphrase mismatch must not be retried"
    );
}

/// A probe that never succeeds refuses the submission rather than falling back
/// to the caller's declaration, and does so well inside the deadline.
#[tokio::test]
async fn probe_failing_throughout_refuses_endpoint_identity_unavailable() {
    let envelope = build_envelope(2003);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    mount_get_ledger_entries(&server, &envelope).await;
    mount_send_and_confirm(&server, &envelope).await;

    let timeout = Duration::from_secs(60);
    let started = std::time::Instant::now();
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        timeout,
        TESTNET_PASSPHRASE,
        None,
    )
    .await
    .expect_err("an endpoint of unknown identity must be refused");

    assert_eq!(
        err.code(),
        "network.endpoint_identity_unavailable",
        "{err:?}"
    );
    assert!(
        started.elapsed() < timeout,
        "the refusal must come from exhausted probe attempts, not from the deadline"
    );
    assert_eq!(
        send_transaction_count(&server).await,
        0,
        "nothing may be sent to an endpoint whose identity is unknown"
    );
}

/// A probe that fails once and then answers proceeds to the send: the probe is
/// retried like any other transport call.
#[tokio::test]
async fn probe_transient_failure_then_answer_proceeds_to_send() {
    let envelope = build_envelope(2004);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_get_network(&server, TESTNET_PASSPHRASE).await;
    mount_get_ledger_entries(&server, &envelope).await;
    mount_send_and_confirm(&server, &envelope).await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let result = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await
    .expect("a retried probe that answers must not block the submission");

    assert_eq!(result.ledger, FAKE_LEDGER);
    assert_eq!(
        send_transaction_count(&server).await,
        1,
        "the send happens once, after the probe answers"
    );
}
