//! Wiremock helpers for Stellar JSON-RPC integration tests.
//!
//! `jsonrpsee-http-client`, as used through `stellar-rpc-client`, validates
//! that every JSON-RPC response `id` equals the generated request `id`. Static
//! `ResponseTemplate` bodies drift from that invariant once request IDs
//! increment, so tests that mock Stellar RPC should use [`EchoIdResponder`] to
//! preserve request-ID parity while keeping the `result` payload fixed.
//! [`KeyedLedgerEntriesResponder`] keeps the same parity for flows that issue
//! several `getLedgerEntries` requests for different keys.
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

/// A wiremock responder that answers `getLedgerEntries` per requested key.
///
/// [`EchoIdResponder`] returns the same `result` for every request, so a flow
/// that issues a second `getLedgerEntries` for a different key (for example
/// the owner's executable-tag entry behind a contract instance) would receive
/// the first key's entry again. This responder reads the base64 `LedgerKey`
/// strings in the request's `params.keys` and answers with the registered
/// entry object for each requested key, in request order, skipping keys that
/// have no registered entry, the way a real endpoint omits entries that do
/// not exist. Every other method is answered with JSON-RPC error `-32601`.
///
/// The request `id` is echoed so `jsonrpsee-http-client` accepts the response.
#[derive(Clone, Debug, Default)]
pub struct KeyedLedgerEntriesResponder {
    entries: Arc<std::collections::HashMap<String, serde_json::Value>>,
}

impl KeyedLedgerEntriesResponder {
    /// Creates a responder with no registered entries; every requested key is
    /// answered as absent.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `entry` (an object with `key`, `xdr`, `lastModifiedLedgerSeq`
    /// and `liveUntilLedgerSeq`) under its own `key` field.
    ///
    /// # Panics
    ///
    /// Panics if `entry` has no string `key` field.
    #[must_use]
    #[allow(
        clippy::panic,
        reason = "test-helper fixture constructor exposes a documented panic path"
    )]
    pub fn with_entry(self, entry: serde_json::Value) -> Self {
        let key = entry
            .get("key")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| panic!("ledger entry fixture has no string `key` field"));
        self.with_entry_for_key(key, entry)
    }

    /// Starts a wiremock server that answers every `POST` with this
    /// responder, for a Stellar RPC client pointed at the server's URI.
    pub async fn serve(self) -> wiremock::MockServer {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(self)
            .mount(&server)
            .await;
        server
    }

    /// Registers `entry` as the answer for the requested base64 `key`,
    /// whatever `entry` itself carries in its `key` field.
    #[must_use]
    pub fn with_entry_for_key(mut self, key: impl Into<String>, entry: serde_json::Value) -> Self {
        Arc::make_mut(&mut self.entries).insert(key.into(), entry);
        self
    }
}

#[async_trait]
impl Respond for KeyedLedgerEntriesResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .unwrap_or_else(|_| serde_json::json!({}));
        let req_id = body
            .get("id")
            .cloned()
            .unwrap_or_else(|| serde_json::json!(1));

        let payload =
            if body.get("method").and_then(serde_json::Value::as_str) == Some("getLedgerEntries") {
                let requested = body
                    .get("params")
                    .and_then(|p| p.get("keys"))
                    .and_then(serde_json::Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let entries: Vec<serde_json::Value> = requested
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(|key| self.entries.get(key).cloned())
                    .collect();
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"entries": entries, "latestLedger": 100},
                })
            } else {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": "method not found"},
                })
            };

        ResponseTemplate::new(200)
            .set_body_json(payload)
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
///
/// Available with the `test-helpers` feature, which supplies the hash
/// computation.
#[cfg(feature = "test-helpers")]
pub struct SubmissionEchoResponder {
    result: Arc<serde_json::Value>,
    passphrase: String,
}

#[cfg(feature = "test-helpers")]
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

#[cfg(feature = "test-helpers")]
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

    async fn post(server: &MockServer, body: serde_json::Value) -> serde_json::Value {
        reqwest::Client::new()
            .post(server.uri())
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn keyed_responder_answers_only_requested_registered_keys_in_order() {
        let server = MockServer::start().await;
        let responder = KeyedLedgerEntriesResponder::new()
            .with_entry(serde_json::json!({"key": "AAAA", "xdr": "one"}))
            .with_entry(serde_json::json!({"key": "BBBB", "xdr": "two"}));
        Mock::given(method("POST"))
            .respond_with(responder)
            .mount(&server)
            .await;

        let resp = post(
            &server,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 7, "method": "getLedgerEntries",
                "params": {"keys": ["BBBB", "CCCC", "AAAA"]}
            }),
        )
        .await;
        assert_eq!(resp["id"], 7);
        let entries = resp["result"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["xdr"], "two");
        assert_eq!(entries[1]["xdr"], "one");

        let absent = post(
            &server,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 8, "method": "getLedgerEntries",
                "params": {"keys": ["CCCC"]}
            }),
        )
        .await;
        assert_eq!(absent["result"]["entries"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn keyed_responder_serves_an_entry_under_a_different_requested_key() {
        let server = MockServer::start().await;
        let responder = KeyedLedgerEntriesResponder::new()
            .with_entry_for_key("REQ", serde_json::json!({"key": "OTHER", "xdr": "x"}));
        Mock::given(method("POST"))
            .respond_with(responder)
            .mount(&server)
            .await;

        let resp = post(
            &server,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "getLedgerEntries",
                "params": {"keys": ["REQ"]}
            }),
        )
        .await;
        assert_eq!(resp["result"]["entries"][0]["key"], "OTHER");
    }

    #[tokio::test]
    async fn keyed_responder_rejects_other_methods() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(KeyedLedgerEntriesResponder::new())
            .mount(&server)
            .await;

        let resp = post(
            &server,
            serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "getLatestLedger"}),
        )
        .await;
        assert_eq!(resp["id"], 3);
        assert_eq!(resp["error"]["code"], -32601);
        assert!(resp.get("result").is_none());
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
