//! Wiremock helpers for Stellar JSON-RPC integration tests.
//!
//! `jsonrpsee-http-client`, as used through `stellar-rpc-client`, validates
//! that every JSON-RPC response `id` equals the generated request `id`. Static
//! `ResponseTemplate` bodies drift from that invariant once request IDs
//! increment, so tests that mock Stellar RPC should use [`EchoIdResponder`] to
//! preserve request-ID parity while keeping the `result` payload fixed.
//!
//! Used by consumer crates' wiremock integration tests that exercise wallet
//! flows through a mocked Stellar RPC endpoint.

use std::sync::Arc;

use async_trait::async_trait;
use wiremock::{Request, Respond, ResponseTemplate};

/// A wiremock responder that wraps a fixed `result` in a JSON-RPC envelope.
///
/// The incoming request body's `id` value is copied into the response so
/// `jsonrpsee-http-client` accepts the mocked response.
pub struct EchoIdResponder {
    result: Arc<serde_json::Value>,
}

impl EchoIdResponder {
    /// Creates a responder that returns `result` as the JSON-RPC `result`.
    #[must_use]
    pub fn new(result: serde_json::Value) -> Self {
        Self {
            result: Arc::new(result),
        }
    }
}

#[async_trait]
impl Respond for EchoIdResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let req_id = serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|value| value.get("id").cloned())
            .unwrap_or_else(|| serde_json::json!(1));

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": *self.result,
            }))
            .insert_header("content-type", "application/json")
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer};

    #[tokio::test]
    async fn echoes_request_id_and_wraps_result() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(EchoIdResponder::new(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let resp: serde_json::Value = reqwest::Client::new()
            .post(server.uri())
            .json(&serde_json::json!({"jsonrpc": "2.0", "id": 42, "method": "x"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["result"]["ok"], true);
    }

    #[tokio::test]
    async fn defaults_id_to_one_when_absent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(EchoIdResponder::new(serde_json::json!("payload")))
            .mount(&server)
            .await;

        let resp: serde_json::Value = reqwest::Client::new()
            .post(server.uri())
            .json(&serde_json::json!({"jsonrpc": "2.0", "method": "x"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"], "payload");
    }
}
