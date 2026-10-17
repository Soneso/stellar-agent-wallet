//! `StellarRpcClient::get_health_within` against a mocked Stellar RPC
//! endpoint.
//!
//! The read retries a failed attempt under the classification of the
//! endpoint identity check and the caller's deadline. An error object is
//! retried, an answer that does not deserialize is not, and no attempt
//! starts once the deadline has passed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::error::NetworkError;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Long enough for every retry the default policy allows against a local
/// server.
const GENEROUS_DEADLINE: Duration = Duration::from_secs(60);

/// A complete `getHealth` answer.
fn healthy(latest_ledger: u32) -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": latest_ledger,
        "oldestLedger": 1,
        "ledgerRetentionWindow": 17_280,
    })
}

/// Answers every request with a JSON-RPC error object carrying the request
/// id.
struct ErrorObject;

impl Respond for ErrorObject {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": body["id"],
            "error": {"code": -32603, "message": "ledger store unavailable"},
        }))
    }
}

fn unreachable_reason(err: NetworkError) -> String {
    match err {
        NetworkError::RpcUnreachable { reason, .. } => reason,
        other => panic!("expected RpcUnreachable, got {other:?}"),
    }
}

/// Two error objects, then an answer: the read retries and returns the
/// answer as received.
#[tokio::test]
async fn an_error_object_is_retried_until_the_endpoint_answers() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(ErrorObject)
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(healthy(5_000)))
        .with_priority(2)
        .mount(&server)
        .await;

    let health = StellarRpcClient::new(&server.uri())
        .unwrap()
        .get_health_within(tokio::time::Instant::now() + GENEROUS_DEADLINE)
        .await
        .expect("the third attempt answers");

    assert_eq!(health.status, "healthy");
    assert_eq!(health.latest_ledger, 5_000);
    assert_eq!(rpc_request_count(&server, "getHealth").await, 3);
}

/// An answer without `ledgerRetentionWindow` does not deserialize. The
/// endpoint did answer, so the read fails after one request.
#[tokio::test]
async fn an_answer_that_does_not_parse_is_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 5_000,
            "oldestLedger": 1,
        })))
        .mount(&server)
        .await;

    let err = StellarRpcClient::new(&server.uri())
        .unwrap()
        .get_health_within(tokio::time::Instant::now() + GENEROUS_DEADLINE)
        .await
        .expect_err("a missing field fails the read");

    assert!(
        unreachable_reason(err).starts_with("getHealth failed: "),
        "the reason names the read"
    );
    assert_eq!(rpc_request_count(&server, "getHealth").await, 1);
}

/// An HTTP 401 or 403 answer is not retried: the endpoint refused the
/// request's credential, and the read fails after one request.
#[tokio::test]
async fn a_401_or_403_answer_is_not_retried() {
    for status in [401u16, 403] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getHealth"})))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;

        let err = StellarRpcClient::new(&server.uri())
            .unwrap()
            .get_health_within(tokio::time::Instant::now() + GENEROUS_DEADLINE)
            .await
            .expect_err("a refused request fails the read");

        assert_eq!(
            unreachable_reason(err),
            format!("getHealth failed: \"Request rejected `{status}`\"")
        );
        assert_eq!(rpc_request_count(&server, "getHealth").await, 1, "{status}");
    }
}

/// An endpoint that always answers with an error object is read until the
/// deadline, then the read fails with the last error.
#[tokio::test]
async fn a_failing_endpoint_is_read_until_the_deadline() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ErrorObject)
        .mount(&server)
        .await;
    let budget = Duration::from_millis(600);
    let started = tokio::time::Instant::now();

    let err = StellarRpcClient::new(&server.uri())
        .unwrap()
        .get_health_within(started + budget)
        .await
        .expect_err("every attempt fails");

    let elapsed = started.elapsed();
    assert!(
        elapsed < budget + Duration::from_millis(500),
        "the read returns by the deadline, took {elapsed:?}"
    );
    assert!(
        unreachable_reason(err).starts_with("getHealth failed: "),
        "the reason names the read"
    );
    let attempts = rpc_request_count(&server, "getHealth").await;
    assert!(
        (1..=5).contains(&attempts),
        "at least one attempt and at most the policy's five: {attempts}"
    );
}
