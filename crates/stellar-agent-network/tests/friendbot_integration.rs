//! Integration tests for `fund_with_friendbot` using a wiremock HTTP server.
//!
//! Tests use `wiremock` to mock the Friendbot HTTP endpoint, providing CI-
//! deterministic coverage of both the happy path (successful funding) and the
//! mainnet structural rejection without live network access.
//!
//! Friendbot uses a plain HTTP GET with a query parameter — no JSON-RPC
//! request-ID echoing is needed (unlike the Stellar RPC tests). A straight
//! `Mock::given(method("GET"))` is sufficient.
//!
//! # Coverage
//!
//! - Happy path: wiremock returns `200 { "hash": "abc...", "_links": {} }`.
//!   Asserts `FriendbotResult.tx_hash == "abc..."` and `.account_id` echoes.
//! - Structural mainnet rejection: passing the mainnet passphrase returns
//!   `Err(WalletError::Network(NetworkError::FriendbotMainnetForbidden))` and
//!   wiremock sees zero requests (HTTP layer never reached).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; assertions via unwrap/expect/panic are idiomatic in integration tests"
)]

use serde_json::json;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_network::fund_with_friendbot;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Stellar mainnet passphrase — used to trigger the structural rejection path.
///
/// Duplicated here from the network crate's private constant so the test is
/// self-contained and does not require exposing the constant publicly.
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Stellar testnet passphrase.
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// A valid-looking testnet G-strkey for use in tests.
const TEST_ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

// ─────────────────────────────────────────────────────────────────────────────
// Happy path: Friendbot returns 200 with a hash
// ─────────────────────────────────────────────────────────────────────────────

/// Happy path: wiremock returns 200 with a `hash` field.
///
/// Asserts that `FriendbotResult.tx_hash` matches the mocked hash and that
/// `FriendbotResult.account_id` echoes the requested account ID.
#[tokio::test]
async fn fund_with_friendbot_happy_path() {
    let mock_server = MockServer::start().await;

    let expected_hash = "abc123def456abc123def456abc123def456abc123def456abc123def456abc1";

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hash": expected_hash,
            "_links": {
                "transaction": {
                    "href": "https://horizon-testnet.stellar.org/transactions/abc123"
                }
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = fund_with_friendbot(&mock_server.uri(), TEST_ACCOUNT, TESTNET_PASSPHRASE)
        .await
        .expect("fund_with_friendbot must succeed for a mocked 200 response");

    assert_eq!(
        result.tx_hash, expected_hash,
        "tx_hash must match the mocked response"
    );
    assert_eq!(
        result.account_id, TEST_ACCOUNT,
        "account_id must echo the requested account"
    );
    assert_eq!(
        result.friendbot_url_used,
        mock_server.uri(),
        "friendbot_url_used must record the endpoint called"
    );

    // Verify the mock received exactly one GET request.
    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mainnet structural rejection — zero HTTP requests issued
// ─────────────────────────────────────────────────────────────────────────────

/// Structural mainnet rejection.
///
/// Passes the mainnet passphrase and asserts:
/// 1. The call returns `Err(WalletError::Network(NetworkError::FriendbotMainnetForbidden))`.
/// 2. The wiremock server received zero requests — the HTTP layer is never reached.
#[tokio::test]
async fn fund_with_friendbot_mainnet_rejected_no_http_issued() {
    let mock_server = MockServer::start().await;

    // Mount a catch-all that would match any GET — if any request reaches
    // the mock, the test will detect it via received_requests().
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hash": "should_never_be_reached",
            "_links": {}
        })))
        // expect(0) means the mock asserts zero invocations at verify() time.
        .expect(0)
        .mount(&mock_server)
        .await;

    let result = fund_with_friendbot(&mock_server.uri(), TEST_ACCOUNT, MAINNET_PASSPHRASE).await;

    // Assert the structural rejection error variant.
    assert!(
        matches!(
            result,
            Err(WalletError::Network(
                NetworkError::FriendbotMainnetForbidden
            ))
        ),
        "expected FriendbotMainnetForbidden, got: {result:?}"
    );

    // Verify that the mock received zero requests.
    mock_server.verify().await;

    // Double-check via received_requests() as an explicit count assertion.
    let requests = mock_server
        .received_requests()
        .await
        .expect("received_requests available");
    assert_eq!(
        requests.len(),
        0,
        "no HTTP request must be issued for mainnet; got {} request(s)",
        requests.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Friendbot returns non-200 status
// ─────────────────────────────────────────────────────────────────────────────

/// Friendbot returns 429 (rate-limited) — surfaced as `RpcUnreachable`.
#[tokio::test]
async fn fund_with_friendbot_non_200_mapped_to_rpc_unreachable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = fund_with_friendbot(&mock_server.uri(), TEST_ACCOUNT, TESTNET_PASSPHRASE).await;

    assert!(result.is_err(), "non-200 response must return an error");
    assert_eq!(
        result.unwrap_err().category(),
        stellar_agent_core::error::ErrorCategory::Network,
        "error must be in the Network category"
    );

    mock_server.verify().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// Friendbot returns 200 but missing hash field
// ─────────────────────────────────────────────────────────────────────────────

/// Friendbot returns 200 but without a `hash` field — surfaced as `RpcUnreachable`.
///
/// A Friendbot mirror that returns `{}` on success should not cause the wallet
/// to report success without a transaction hash.
#[tokio::test]
async fn fund_with_friendbot_missing_hash_field_returns_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_links": {}
            // intentionally omit "hash"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let result = fund_with_friendbot(&mock_server.uri(), TEST_ACCOUNT, TESTNET_PASSPHRASE).await;

    assert!(result.is_err(), "missing hash field must return an error");
    assert_eq!(
        result.unwrap_err().category(),
        stellar_agent_core::error::ErrorCategory::Network
    );

    mock_server.verify().await;
}
