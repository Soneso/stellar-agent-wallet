//! Wiremock integration tests for HTTP error paths in `stellar-agent-anchor`.
//!
//! Covers client.rs paths not reachable via offline unit tests:
//! - Non-200 HTTP status → `HttpStatusError`.
//! - Response body exceeding 64 KiB → `AnchorResponseDecodeFailed`.
//! - Non-UTF-8 body → `AnchorResponseDecodeFailed`.
//! - POST JSON + bearer → non-200 HTTP status → `HttpStatusError`.
//! - POST JSON + bearer → 200 with valid JSON body → decoded correctly.
//! - POST Content-Type assertion: mock requires `application/json`; a client
//!   sending form-encoded would not match and the test would fail.
//! - GET with valid 200 JSON body → decoded correctly.
//!
//! Uses `AnchorClient::new_without_https_enforcement()` (test-helpers feature)
//! which omits the HTTPS-only enforcement so that wiremock's HTTP server can be
//! the target.  All other security settings (redirect blocking, no
//! decompression, timeouts, body cap) are identical to the production client.
//! This ensures the wiremock tests exercise the REAL production fetch and
//! error-mapping code paths in `AnchorClient`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use stellar_agent_anchor::{AnchorError, test_helpers::AnchorClient};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper: deserialise a raw request body to a JSON object map.
fn parse_json_body_map(raw: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    let v: serde_json::Value =
        serde_json::from_slice(raw).expect("request body must be valid JSON");
    match v {
        serde_json::Value::Object(map) => map,
        other => panic!("expected JSON object body; got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GET fetch_json_str paths
// ─────────────────────────────────────────────────────────────────────────────

/// 200 response with valid JSON body → returned as-is (no decode here; caller decodes).
#[tokio::test]
async fn fetch_json_str_200_returns_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"deposit":{},"withdraw":{}}"#))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/info", server.uri());
    let body = client
        .fetch_json_str(&url, "localhost")
        .await
        .expect("200 response must succeed");
    assert!(body.contains("deposit"));
}

/// Non-200 HTTP status → `HttpStatusError` with the returned status code.
#[tokio::test]
async fn fetch_json_str_non_200_returns_http_status_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/info", server.uri());
    let result = client.fetch_json_str(&url, "localhost").await;
    assert!(
        matches!(
            result,
            Err(AnchorError::HttpStatusError { status: 404, .. })
        ),
        "404 must return HttpStatusError(404); got: {result:?}"
    );
}

/// 403 status → `HttpStatusError` with status 403.
#[tokio::test]
async fn fetch_json_str_403_returns_http_status_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/info", server.uri());
    let result = client.fetch_json_str(&url, "localhost").await;
    assert!(
        matches!(
            result,
            Err(AnchorError::HttpStatusError { status: 403, .. })
        ),
        "403 must return HttpStatusError(403); got: {result:?}"
    );
}

/// 500 status → `HttpStatusError` with status 500.
#[tokio::test]
async fn fetch_json_str_500_returns_http_status_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/info", server.uri());
    let result = client.fetch_json_str(&url, "localhost").await;
    assert!(
        matches!(
            result,
            Err(AnchorError::HttpStatusError { status: 500, .. })
        ),
        "500 must return HttpStatusError(500); got: {result:?}"
    );
}

/// Body exceeding 64 KiB → `AnchorResponseDecodeFailed` (body cap exceeded).
#[tokio::test]
async fn fetch_json_str_oversized_body_returns_decode_error() {
    let server = MockServer::start().await;
    // 65 KiB + 1 byte oversized body.
    let oversized = "x".repeat(65 * 1024 + 1);
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(oversized))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/info", server.uri());
    let result = client.fetch_json_str(&url, "localhost").await;
    assert!(
        matches!(result, Err(AnchorError::AnchorResponseDecodeFailed { .. })),
        "oversized body must return AnchorResponseDecodeFailed; got: {result:?}"
    );
}

/// Body at exactly 64 KiB (cap boundary) → accepted.
#[tokio::test]
async fn fetch_json_str_body_at_cap_is_accepted() {
    let server = MockServer::start().await;
    // Exactly 64 KiB — one byte under the >64KiB cap check.
    let exactly_cap = "x".repeat(64 * 1024);
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_string(exactly_cap.clone()))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/info", server.uri());
    let result = client.fetch_json_str(&url, "localhost").await;
    assert!(
        result.is_ok(),
        "exactly 64 KiB body must be accepted; got: {result:?}"
    );
    assert_eq!(result.unwrap().len(), 64 * 1024);
}

/// Non-UTF-8 body → `AnchorResponseDecodeFailed` (UTF-8 decode error).
#[tokio::test]
async fn fetch_json_str_non_utf8_body_returns_decode_error() {
    let server = MockServer::start().await;
    // Invalid UTF-8: a lone continuation byte.
    let bad_utf8: Vec<u8> = vec![0xFF, 0xFE, 0x80, 0x00];
    Mock::given(method("GET"))
        .and(path("/info"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bad_utf8))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/info", server.uri());
    let result = client.fetch_json_str(&url, "localhost").await;
    assert!(
        matches!(result, Err(AnchorError::AnchorResponseDecodeFailed { .. })),
        "non-UTF-8 body must return AnchorResponseDecodeFailed; got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// POST post_json_with_bearer paths
// ─────────────────────────────────────────────────────────────────────────────

/// POST with bearer → 200 + valid JSON body → body returned.
///
/// The mock requires `Content-Type: application/json` and `Authorization:
/// Bearer <jwt>` — if the client sends form-encoded or omits the header the
/// mock does not match and wiremock returns 404 → the test fails.
#[tokio::test]
async fn post_json_with_bearer_200_returns_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/deposit/interactive"))
        .and(header("authorization", "Bearer test-jwt-token"))
        .and(header("content-type", "application/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"type":"interactive_customer_info_needed","url":"https://anchor.example.com/kyc","id":"tx123"}"#
            ),
        )
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/transactions/deposit/interactive", server.uri());
    let json_body = serde_json::json!({"asset_code": "USDC"});
    let body = client
        .post_json_with_bearer(&url, "localhost", "test-jwt-token", &json_body)
        .await
        .expect("200 POST response must succeed");
    assert!(body.contains("interactive_customer_info_needed"));
}

/// POST JSON body is actually JSON: inspects the received request body.
///
/// This is the regression guard: if the client reverts to form-encoding, the
/// Content-Type header matcher above fails (mock returns 404 → test panics).
/// This test also explicitly verifies the body parses as JSON with the correct
/// field value.
#[tokio::test]
async fn post_json_with_bearer_sends_json_content_type_and_body() {
    let server = MockServer::start().await;
    // The content-type matcher is the regression guard: form-encoded would be
    // "application/x-www-form-urlencoded", which does NOT match, so the mock
    // returns 404 and the test fails.
    Mock::given(method("POST"))
        .and(path("/transactions/deposit/interactive"))
        .and(header("content-type", "application/json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(
                r#"{"type":"interactive_customer_info_needed","url":"https://anchor.example.com/kyc","id":"tx-rg"}"#
            ),
        )
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/transactions/deposit/interactive", server.uri());
    let json_body = serde_json::json!({"asset_code": "SRT", "amount": "10.0000000"});
    let body = client
        .post_json_with_bearer(&url, "localhost", "jwt", &json_body)
        .await
        .expect("200 must succeed; failure here means Content-Type was not application/json");
    assert!(body.contains("interactive_customer_info_needed"));

    // Inspect the actual received request body.
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];

    // Content-Type assertion (belt-and-suspenders — the matcher already enforced this).
    let ct = req
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.starts_with("application/json"),
        "Content-Type must be application/json; got {ct:?}"
    );

    let body_map = parse_json_body_map(&req.body);
    assert_eq!(
        body_map.get("asset_code"),
        Some(&serde_json::Value::String("SRT".to_owned())),
        "asset_code must be a JSON string; body = {body_map:?}"
    );
    // amount must be a JSON string, not a number.
    let amount_val = body_map.get("amount").expect("amount must be present");
    assert!(
        amount_val.is_string(),
        "amount must be a JSON string, not a number; got: {amount_val:?}"
    );
    assert_eq!(
        amount_val.as_str(),
        Some("10.0000000"),
        "amount string must be preserved verbatim; got: {amount_val:?}"
    );
}

/// POST with bearer → 401 → `HttpStatusError`.
#[tokio::test]
async fn post_json_with_bearer_401_returns_http_status_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/transactions/deposit/interactive"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/transactions/deposit/interactive", server.uri());
    let json_body = serde_json::json!({"asset_code": "USDC"});
    let result = client
        .post_json_with_bearer(&url, "localhost", "bad-jwt", &json_body)
        .await;
    assert!(
        matches!(
            result,
            Err(AnchorError::HttpStatusError { status: 401, .. })
        ),
        "401 POST must return HttpStatusError(401); got: {result:?}"
    );
}

/// Body read error mid-stream → `AnchorFetchFailed`.
///
/// Opens a raw TCP listener that sends valid HTTP response headers and the
/// first few bytes of a body, then abruptly closes the connection.  This
/// exercises the `Err(e)` arm in `read_capped_body` (the chunk-streaming
/// error path) without needing to cause a TLS-level failure.
#[tokio::test]
async fn fetch_json_str_mid_stream_close_returns_fetch_failed() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    // Bind to any available loopback port.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Spawn a task that accepts the connection, sends partial HTTP response,
    // and immediately closes — causing reqwest to report a body read error.
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Read and discard the HTTP request.
            let mut buf = [0u8; 4096];
            let _ = stream.try_read(&mut buf);

            // Write a valid response header claiming 10_000 bytes of body,
            // then close without sending the body.  reqwest will get an
            // unexpected EOF while streaming chunks.
            let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\npartial";
            let _ = stream.write_all(partial).await;
            // stream is dropped here, closing the connection abruptly.
        }
    });

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("http://127.0.0.1:{port}/info");
    let result = client.fetch_json_str(&url, "127.0.0.1").await;

    // reqwest reports the unexpected EOF / connection reset as either
    // AnchorFetchFailed (transport error) or AnchorResponseDecodeFailed
    // (body incomplete), depending on how the OS surfaces the truncation.
    assert!(
        matches!(
            result,
            Err(AnchorError::AnchorFetchFailed { .. })
                | Err(AnchorError::AnchorResponseDecodeFailed { .. })
        ),
        "mid-stream close must return a transport or decode error; got: {result:?}"
    );
}

/// GET request to a refused connection → `AnchorFetchFailed`.
///
/// Targets a loopback port that is not bound to any listener so that the
/// kernel returns ECONNREFUSED immediately — no timeout needed.
#[tokio::test]
async fn fetch_json_str_connection_refused_returns_fetch_failed() {
    let client = AnchorClient::new_without_https_enforcement().unwrap();
    // Port 1 is a system port; connection is refused immediately on all platforms.
    let result = client
        .fetch_json_str("http://127.0.0.1:1/info", "127.0.0.1:1")
        .await;
    assert!(
        matches!(result, Err(AnchorError::AnchorFetchFailed { .. })),
        "connection refused must return AnchorFetchFailed; got: {result:?}"
    );
}

/// POST request to a refused connection → `AnchorFetchFailed`.
#[tokio::test]
async fn post_json_with_bearer_connection_refused_returns_fetch_failed() {
    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let json_body = serde_json::json!({"asset_code": "USDC"});
    let result = client
        .post_json_with_bearer(
            "http://127.0.0.1:1/transactions/deposit/interactive",
            "127.0.0.1:1",
            "jwt",
            &json_body,
        )
        .await;
    assert!(
        matches!(result, Err(AnchorError::AnchorFetchFailed { .. })),
        "connection refused must return AnchorFetchFailed; got: {result:?}"
    );
}

/// POST with bearer → oversized body → `AnchorResponseDecodeFailed`.
#[tokio::test]
async fn post_json_with_bearer_oversized_body_returns_decode_error() {
    let server = MockServer::start().await;
    let oversized = "x".repeat(65 * 1024 + 1);
    Mock::given(method("POST"))
        .and(path("/transactions/deposit/interactive"))
        .respond_with(ResponseTemplate::new(200).set_body_string(oversized))
        .mount(&server)
        .await;

    let client = AnchorClient::new_without_https_enforcement().unwrap();
    let url = format!("{}/transactions/deposit/interactive", server.uri());
    let json_body = serde_json::json!({"asset_code": "USDC"});
    let result = client
        .post_json_with_bearer(&url, "localhost", "jwt", &json_body)
        .await;
    assert!(
        matches!(result, Err(AnchorError::AnchorResponseDecodeFailed { .. })),
        "oversized POST response must return AnchorResponseDecodeFailed; got: {result:?}"
    );
}
