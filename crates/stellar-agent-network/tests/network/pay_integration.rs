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
    clippy::panic,
    reason = "integration test; panics/unwraps acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::StellarAmount;
use stellar_agent_core::error::{ErrorCategory, NetworkError, ValidationError, WalletError};
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

#[tokio::test]
async fn sac_public_prepare_and_retained_rebuild() {
    use stellar_agent_core::{
        approval::{ClassicIntent, MemoFact, fixtures::sac_transfer},
        profile::caip2::Caip2,
        sac_payment::{SacPaymentContext, verify_sac_payment},
    };
    use stellar_agent_network::{
        fees::ClassicFeeChoice,
        sac_payment::{
            SacPaymentBuildRequest, SacPaymentCaller, prepare_sac_payment, rebuild_sac_payment,
        },
    };
    use stellar_xdr::*;
    let context = SacPaymentContext::new(
        Caip2::Testnet,
        stellar_agent_core::approval::IntentAsset::Native,
    )
    .unwrap();
    let original = sac_transfer(&context);
    let text = TransactionEnvelope::Tx(original.clone())
        .to_xdr_base64(Limits::none())
        .unwrap();
    let payment = verify_sac_payment(&text, &context).unwrap();
    let base = stellar_agent_network::operation_entry::contract_pay_base(
        Caip2::Testnet,
        payment.policy_args()["source"].as_str().unwrap(),
        [7; 32],
        MemoFact::None,
        stellar_agent_network::contract_transfer_fee_cap(Caip2::Testnet, None).unwrap(),
    )
    .unwrap();
    let intent = ClassicIntent::new(base, payment.intent_payload(Some(100))).unwrap();
    let request = SacPaymentBuildRequest {
        intent: &intent,
        context: &context,
        sequence: 77,
        conditions: Preconditions::None,
        fee_choice: ClassicFeeChoice::Explicit(100),
        default_inclusion_bid: 999,
        policy: None,
    };
    let server = MockServer::start().await;
    let key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: payment.invoke().contract_address.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let TransactionExt::V1(mut data) = original.tx.ext else {
        panic!("fixture data")
    };
    data.resources.footprint.read_write = vec![key.clone()].try_into().unwrap();
    data.ext = SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
        archived_soroban_entries: vec![0].try_into().unwrap(),
    });
    let OperationBody::InvokeHostFunction(host) = &original.tx.operations[0].body else {
        panic!("fixture host")
    };
    Mock::given(body_partial_json(json!({"method":"getLedgerEntries", "params":{"keys":[key.to_xdr_base64(Limits::none()).unwrap()]}})))
        .respond_with(EchoIdResponder::new(json!({"latestLedger":1000,"entries":[]}))).expect(1).mount(&server).await;
    let simulation = json!({"latestLedger":1000,"minResourceFee":"500000",
            "transactionData":data.to_xdr_base64(Limits::none()).unwrap(),
            "results":[{"xdr":ScVal::Void.to_xdr_base64(Limits::none()).unwrap(),"auth":[host.auth[0].to_xdr_base64(Limits::none()).unwrap()]}]});
    Mock::given(body_partial_json(json!({"method":"simulateTransaction"})))
        .respond_with(move |request: &wiremock::Request| {
            let body: serde_json::Value = request.body_json().unwrap();
            let envelope = TransactionEnvelope::from_xdr_base64(
                body["params"]["transaction"].as_str().unwrap(),
                Limits::none(),
            )
            .unwrap();
            let TransactionEnvelope::Tx(tx) = envelope else {
                panic!("tx")
            };
            let OperationBody::InvokeHostFunction(op) = &tx.tx.operations[0].body else {
                panic!("host")
            };
            let mut result = simulation.clone();
            if !op.auth.is_empty() {
                result["results"][0]["auth"] = json!([]);
            }
            wiremock::ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc":"2.0", "id":body["id"], "result":result}))
        })
        .expect(1)
        .mount(&server)
        .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let prepared = prepare_sac_payment(&client, &request).await.unwrap();
    let stellar_agent_core::approval::IntentPayload::ContractPay {
        destination,
        asset,
        amount_stroops,
        explicit_inclusion_bid_stroops,
    } = intent.payload()
    else {
        panic!("fixture intent")
    };
    let caller = SacPaymentCaller {
        source: intent.base().source(),
        destination,
        asset,
        amount_stroops: *amount_stroops,
        explicit_inclusion_bid_stroops: *explicit_inclusion_bid_stroops,
        memo: &MemoFact::None,
    };
    assert_eq!(prepared.payment.transaction().ext, TransactionExt::V1(data));
    assert_eq!(prepared.fee.total_stroops, 500_100);
    assert_eq!(
        rebuild_sac_payment(&request, &prepared.envelope_xdr, &caller)
            .unwrap()
            .envelope_xdr,
        prepared.envelope_xdr
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

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
        stellar_agent_network::sep29::check_memo_required(&client, DST_ACCOUNT, true).await;
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
