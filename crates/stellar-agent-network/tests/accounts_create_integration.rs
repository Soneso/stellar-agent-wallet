//! Mock-RPC integration tests for the `accounts create` command pipeline.
//!
//! Uses `wiremock` to serve deterministic JSON-RPC and HTTP responses without a
//! live Stellar network.
//!
//! # Coverage
//!
//! - `ClassicOpBuilder::create_account` produces a decodable `TransactionEnvelope`
//!   with the correct operation type (XDR round-trip).
//! - Friendbot mode: wiremock 200 response — asserts `FriendbotResult.tx_hash` is populated.
//! - Friendbot mainnet rejection: passphrase check returns `FriendbotMainnetForbidden`;
//!   wiremock sees zero requests.
//! - Sponsored mode: `ClassicOpBuilder::create_account` plus `attach_signature`
//!   plus `submit_transaction_and_wait` mock pipeline — asserts `SubmissionResult`
//!   is returned on mock SUCCESS response.
//!
//! # JSON-RPC request-ID echoing
//!
//! `stellar-rpc-client` uses `jsonrpsee-http-client` which sends JSON-RPC 2.0
//! requests with incrementing numeric IDs and validates that the response `id`
//! matches the request `id`. The shared test-support `EchoIdResponder` keeps
//! mocked responses aligned with those generated IDs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics/unwraps/expects acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::StellarAmount;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_network::builder::ClassicOpBuilder;
use stellar_agent_network::signing::envelope_signing::attach_signature;
use stellar_agent_network::signing::software::SoftwareSigningKey;
use stellar_agent_network::{StellarRpcClient, fund_with_friendbot, submit_transaction_and_wait};
use stellar_agent_test_support::EchoIdResponder;
use stellar_xdr::{Limits, OperationBody, ReadXdr, TransactionEnvelope};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Sponsor source account (seed [1u8;32] via ed25519-dalek).
const SPONSOR_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// New account destination (arbitrary valid G-strkey).
const NEW_ACCOUNT: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Mounts a `getLedgerEntries` mock on `mock_server` that reports `address` as
/// present — satisfies `fund_with_friendbot`'s post-funding verification poll.
async fn mount_account_present(mock_server: &MockServer, address: &str) {
    use stellar_agent_test_support::xdr_fixtures::{account_entry_xdr, account_ledger_key_xdr};

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": account_ledger_key_xdr(address),
                    "xdr": account_entry_xdr(address, 100_000_000_000, 0),
                    "lastModifiedLedgerSeq": 100
                }
            ],
            "latestLedger": 100
        })))
        .mount(mock_server)
        .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassicOpBuilder::create_account XDR round-trip
// ─────────────────────────────────────────────────────────────────────────────

/// `ClassicOpBuilder::create_account` produces a `TransactionEnvelope`
/// with a `CreateAccount` operation body.
#[test]
fn create_account_op_xdr_round_trip() {
    let mut builder = ClassicOpBuilder::new(SPONSOR_ACCOUNT, 201, TESTNET_PASSPHRASE, 100);
    builder
        .create_account(NEW_ACCOUNT, StellarAmount::from_stroops(50_000_000))
        .expect("create_account must succeed");

    let xdr = builder.build().expect("build must succeed");

    let envelope = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
        .expect("must decode as a valid TransactionEnvelope");

    // Verify the operation body is CreateAccount.
    match &envelope {
        TransactionEnvelope::Tx(v1) => {
            let ops = &v1.tx.operations;
            assert_eq!(ops.len(), 1, "exactly one operation expected");
            assert!(
                matches!(ops[0].body, OperationBody::CreateAccount(_)),
                "operation body must be CreateAccount"
            );
        }
        other => panic!("expected TransactionEnvelope::Tx, got: {other:?}"),
    }
}

/// `create_account` with an invalid destination returns an `AddressInvalid` error.
#[test]
fn create_account_invalid_destination_returns_error() {
    let mut builder = ClassicOpBuilder::new(SPONSOR_ACCOUNT, 201, TESTNET_PASSPHRASE, 100);
    let result = builder.create_account("NOTASTRKEY", StellarAmount::from_stroops(50_000_000));
    assert!(result.is_err(), "invalid destination must fail");
}

// ─────────────────────────────────────────────────────────────────────────────
// Friendbot mode — wiremock happy path
// ─────────────────────────────────────────────────────────────────────────────

/// Friendbot mode with a mocked 200 response.
///
/// Asserts that `FriendbotResult.tx_hash` matches the mocked hash and the
/// wiremock server saw exactly one GET request.
#[tokio::test]
async fn friendbot_mode_happy_path() {
    let mock_server = MockServer::start().await;

    let expected_hash = "def456abc123def456abc123def456abc123def456abc123def456abc123def4";

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hash": expected_hash,
            "_links": {}
        })))
        .expect(1)
        .mount(&mock_server)
        .await;
    mount_account_present(&mock_server, NEW_ACCOUNT).await;

    let result = fund_with_friendbot(
        &mock_server.uri(),
        NEW_ACCOUNT,
        TESTNET_PASSPHRASE,
        &mock_server.uri(),
    )
    .await
    .expect("fund_with_friendbot must succeed for a mocked 200 response");

    assert_eq!(
        result.tx_hash, expected_hash,
        "tx_hash must match the mocked response"
    );
    assert_eq!(result.account_id, NEW_ACCOUNT, "account_id must echo");
    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Friendbot mainnet rejection — zero HTTP requests issued
// ─────────────────────────────────────────────────────────────────────────────

/// Friendbot mainnet passphrase is rejected before any HTTP call.
///
/// Asserts `FriendbotMainnetForbidden` and that the wiremock server saw
/// zero requests.
#[tokio::test]
async fn friendbot_mainnet_rejected_zero_http_requests() {
    let mock_server = MockServer::start().await;

    // No mock registered: any request would cause an unexpected-request error.

    let result = fund_with_friendbot(
        &mock_server.uri(),
        NEW_ACCOUNT,
        MAINNET_PASSPHRASE,
        &mock_server.uri(),
    )
    .await;

    assert!(
        matches!(
            result,
            Err(WalletError::Network(
                NetworkError::FriendbotMainnetForbidden
            ))
        ),
        "expected FriendbotMainnetForbidden, got: {result:?}"
    );

    // Verify wiremock received zero requests.
    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sponsored mode — build + sign + submit mock pipeline
// ─────────────────────────────────────────────────────────────────────────────

/// Sponsored mode: `ClassicOpBuilder::create_account` → sign →
/// `submit_transaction_and_wait` with mocked `sendTransaction` and
/// `getTransaction SUCCESS` responses.
///
/// The sponsor account sequence number is set statically (201) to avoid a
/// `getLedgerEntries` mock round-trip in this integration test.
/// A full end-to-end test including `fetch_account` is in the
/// `#[ignore]`-gated live testnet suite.
#[tokio::test]
async fn sponsored_create_account_mock_pipeline() {
    let mock_server = MockServer::start().await;

    // Build and sign the CreateAccount transaction offline (no RPC needed).
    let mut builder = ClassicOpBuilder::new(SPONSOR_ACCOUNT, 201, TESTNET_PASSPHRASE, 100);
    builder
        .create_account(NEW_ACCOUNT, StellarAmount::from_stroops(50_000_000))
        .expect("create_account must succeed");
    let unsigned_xdr = builder.build().expect("build must succeed");

    // Sign with software key (seed [1u8; 32] matches SPONSOR_ACCOUNT G-strkey).
    let signer = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let signed_xdr = attach_signature(&unsigned_xdr, &signer, TESTNET_PASSPHRASE)
        .await
        .expect("attach_signature must succeed");

    // Mock 1: sendTransaction — `hash` field per soroban-client schema.
    let tx_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let send_result = json!({
        "hash": tx_hash,
        "status": "PENDING",
        "latestLedger": 200,
        "latestLedgerCloseTime": "1234567890",
    });
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(send_result))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Mock 2: getTransaction SUCCESS (minimal fields matching soroban-client schema).
    let get_result = json!({
        "status": "SUCCESS",
        "txHash": tx_hash,
        "ledger": 201,
    });
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(get_result))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("client must init");
    let result = submit_transaction_and_wait(
        &client,
        &signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
    )
    .await
    .expect("submit_transaction_and_wait must succeed");

    assert_eq!(result.ledger, 201, "ledger must match mocked response");
    assert!(!result.tx_hash.is_empty(), "tx_hash must be non-empty");
}
