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

/// A wiremock responder that answers with the transaction hash of the
/// transaction it was handed, the way a real endpoint does.
///
/// A submitting wallet computes the transaction hash from the bytes it signed
/// and treats a different hash from the endpoint as a submission whose outcome
/// it cannot account for. A mock answering a canned hash therefore trips that
/// on every call. This responder substitutes the request-derived hash into the
/// `hash` and `txHash` fields of a result template, so the test's fixed body
/// keeps every other field and the hash tells the truth:
///
/// - `sendTransaction`: the hash computed from the envelope in the request,
///   under `passphrase`.
/// - `getTransaction`: the hash the caller asked about.
///
/// Every other method is answered with the template unchanged.
pub struct SubmissionEchoResponder {
    result: Arc<serde_json::Value>,
    passphrase: String,
}

impl SubmissionEchoResponder {
    /// Creates a responder returning `result` with its hash fields rewritten
    /// to match the request.
    #[must_use]
    pub fn new(result: serde_json::Value, passphrase: impl Into<String>) -> Self {
        Self {
            result: Arc::new(result),
            passphrase: passphrase.into(),
        }
    }
}

#[async_trait]
impl Respond for SubmissionEchoResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = body
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));
        let method = body
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();

        let hash = match method {
            "sendTransaction" => Some(crate::signed_envelope::send_transaction_hash_hex(
                &body,
                &self.passphrase,
            )),
            "getTransaction" => body
                .get("params")
                .and_then(|p| p.get("hash"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            _ => None,
        };

        let mut result = (*self.result).clone();
        if let (Some(hash), Some(object)) = (hash, result.as_object_mut()) {
            for field in ["hash", "txHash"] {
                if object.contains_key(field) {
                    object.insert(field.to_owned(), serde_json::Value::String(hash.clone()));
                }
            }
        }

        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": result,
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
