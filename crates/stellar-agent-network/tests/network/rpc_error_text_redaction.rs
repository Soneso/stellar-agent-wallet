//! Server-provided RPC error text reaches network errors scrubbed of URLs.
//!
//! A loopback endpoint answers HTTP 200 with a JSON-RPC error object. Its
//! `message` echoes the client's own request URL, query token included, the
//! way a proxy or upstream node can. Its `data` carries a second
//! credential-bearing URL with each slash JSON-escaped. Each error test drives
//! one public entry point through the real RPC client. It asserts that the text
//! field of the resulting error keeps only the host and port of both URLs.
//!
//! The status tests instead serve a success-shaped `getTransaction` answer
//! whose `status` holds the request URL, and assert that the resulting text
//! keeps only its host and port.
//!
//! The client URL carries `?token=CLIENTSECRET`, and every error mock matches
//! that query, so a request that lost it gets no error object and the test
//! fails.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::sync::Mutex;
use std::time::Duration;

use serde_json::json;
use stellar_agent_core::error::{NetworkError, SubmissionError, WalletError};
use stellar_agent_core::profile::receipt::ReceiptStore;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::fetch_account;
use stellar_agent_network::idempotent_submit::submit_transaction_idempotent;
use stellar_agent_network::sep29::check_memo_required;
use stellar_agent_network::submission_record::{
    SubmissionIntent, SubmissionOutcome, SubmissionRecorder,
};
use stellar_agent_network::submit::submit_transaction_and_wait;
use stellar_agent_network::wasm_hash::{FetchContractWasmHashError, fetch_contract_wasm_hash};
use stellar_agent_test_support::EchoIdResponder;
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use wiremock::matchers::{body_partial_json, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The account the read paths ask for.
const ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// Seed of the signed envelope's source account. A public test fixture.
const SOURCE_SEED: [u8; 32] = [9u8; 32];

/// The `data` member of the error object: a second credential-bearing URL,
/// written with JSON-escaped slashes.
const ESCAPED_DATA: &str =
    r#"{"url":"https:\/\/user:SECRET@archive.example.com:8443\/rpc?token=SECRET"}"#;

/// A loopback endpoint and the credential-bearing client URL that names it.
struct EchoingEndpoint {
    server: MockServer,
    client_url: String,
}

impl EchoingEndpoint {
    async fn start() -> Self {
        let server = MockServer::start().await;
        let client_url = format!("{}/?token=CLIENTSECRET", server.uri());
        Self { server, client_url }
    }

    fn client(&self) -> StellarRpcClient {
        StellarRpcClient::new(&self.client_url).expect("the loopback URL parses")
    }

    /// `host:port` of the loopback server, the form its echoed URL keeps.
    fn authority(&self) -> String {
        self.server
            .uri()
            .strip_prefix("http://")
            .expect("wiremock serves plain HTTP")
            .to_owned()
    }

    /// The error response: HTTP 200 carrying a JSON-RPC error object whose
    /// `message` echoes the request URL and whose `data` is [`ESCAPED_DATA`].
    /// The body is written raw so the escaped slashes reach the client as
    /// sent.
    fn error_response(&self) -> ResponseTemplate {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"upstream rejected {} for this caller","data":{ESCAPED_DATA}}}}}"#,
            self.client_url
        );
        ResponseTemplate::new(200).set_body_raw(body, "application/json")
    }

    /// Answers every request that carries the client's query token with the
    /// error response.
    async fn mount_error_for_every_method(&self) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(query_param("token", "CLIENTSECRET"))
            .respond_with(self.error_response())
            .mount(&self.server)
            .await;
    }

    /// Asserts that `field` keeps the host and port of both echoed URLs and
    /// none of their scheme, userinfo, path, or query.
    fn assert_scrubbed(&self, field: &str) {
        assert!(
            field.contains(&format!(
                "upstream rejected {} for this caller",
                self.authority()
            )),
            "the echoed request URL must keep its host and port: {field}"
        );
        assert!(
            field.contains(r#"{"url":"archive.example.com:8443"}"#),
            "the escaped URL in the data must keep its host and port: {field}"
        );
        for leaked in [
            "SECRET",
            "token=",
            "user:",
            "https://",
            r"https:\/",
            "/?",
            "/rpc",
        ] {
            assert!(
                !field.contains(leaked),
                "{leaked} survived the scrub: {field}"
            );
        }
    }
}

/// Splits an `RpcUnreachable` into its two fields.
fn unreachable_parts(err: NetworkError) -> (String, String) {
    match err {
        NetworkError::RpcUnreachable { url, reason } => (url, reason),
        other => panic!("expected RpcUnreachable, got {other:?}"),
    }
}

/// The `balances` path: the account read keeps only host and port of the
/// echoed URLs, and the endpoint field keeps its scheme, host, and port.
#[tokio::test]
async fn fetch_account_scrubs_the_server_text_from_its_reason() {
    let endpoint = EchoingEndpoint::start().await;
    endpoint.mount_error_for_every_method().await;

    let err = fetch_account(&endpoint.client(), ACCOUNT, &[])
        .await
        .expect_err("the endpoint answers with an error object");

    let WalletError::Network(network) = err else {
        panic!("expected a network error, got {err:?}");
    };
    let (url, reason) = unreachable_parts(network);
    assert_eq!(
        url,
        endpoint.server.uri(),
        "the endpoint keeps its authority"
    );
    endpoint.assert_scrubbed(&reason);
    assert!(
        !reason.contains("http://"),
        "no scheme survives in the reason: {reason}"
    );
}

/// `getLedgerEntries` on the client keeps its prefix and only host and port.
#[tokio::test]
async fn get_ledger_entries_scrubs_the_server_text_from_its_reason() {
    let endpoint = EchoingEndpoint::start().await;
    endpoint.mount_error_for_every_method().await;

    let err = endpoint
        .client()
        .get_ledger_entries(&[])
        .await
        .expect_err("the endpoint answers with an error object");

    let (_, reason) = unreachable_parts(err);
    assert!(
        reason.starts_with("getLedgerEntries failed: "),
        "the prefix stays: {reason}"
    );
    endpoint.assert_scrubbed(&reason);
    assert!(
        !reason.contains("http://"),
        "no scheme survives in the reason: {reason}"
    );
}

/// `getFeeStats` keeps only host and port.
#[tokio::test]
async fn get_fee_stats_scrubs_the_server_text_from_its_reason() {
    let endpoint = EchoingEndpoint::start().await;
    endpoint.mount_error_for_every_method().await;

    let err = endpoint
        .client()
        .get_fee_stats()
        .await
        .expect_err("the endpoint answers with an error object");

    let (_, reason) = unreachable_parts(err);
    endpoint.assert_scrubbed(&reason);
    assert!(
        !reason.contains("http://"),
        "no scheme survives in the reason: {reason}"
    );
}

/// `getHealth` keeps its prefix and only host and port.
#[tokio::test]
async fn get_health_scrubs_the_server_text_from_its_reason() {
    let endpoint = EchoingEndpoint::start().await;
    endpoint.mount_error_for_every_method().await;

    let err = endpoint
        .client()
        .get_health()
        .await
        .expect_err("the endpoint answers with an error object");

    let (_, reason) = unreachable_parts(err);
    assert!(
        reason.starts_with("getHealth failed: "),
        "the prefix stays: {reason}"
    );
    endpoint.assert_scrubbed(&reason);
    assert!(
        !reason.contains("http://"),
        "no scheme survives in the reason: {reason}"
    );
}

/// `simulateTransaction` sends the envelope it was given and no `authMode`,
/// and a failed call keeps its prefix and only host and port of the echoed
/// URLs.
#[tokio::test]
async fn simulate_wrapper_preserves_request_and_scrubs_transport_errors() {
    use stellar_xdr::ReadXdr as _;

    let envelope_xdr = SignedTestEnvelope::for_source(SOURCE_SEED)
        .envelope_xdr()
        .to_owned();
    let envelope = stellar_xdr::TransactionEnvelope::from_xdr_base64(
        &envelope_xdr,
        stellar_xdr::Limits::none(),
    )
    .expect("the fixture envelope decodes");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "simulateTransaction"})))
        .respond_with(EchoIdResponder::new(json!({"latestLedger": 4242})))
        .mount(&server)
        .await;
    let answer = StellarRpcClient::new(&server.uri())
        .unwrap()
        .simulate_transaction_envelope(&envelope)
        .await
        .expect("the endpoint answers the simulation");
    assert_eq!(
        answer.latest_ledger, 4242,
        "the answer is returned as received"
    );
    let requests = server
        .received_requests()
        .await
        .expect("request recording is on");
    let [request] = requests.as_slice() else {
        panic!("one request, got {}", requests.len());
    };
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["method"], "simulateTransaction");
    let params = body["params"]
        .as_object()
        .expect("the request carries named parameters");
    assert_eq!(
        params
            .get("transaction")
            .and_then(serde_json::Value::as_str),
        Some(envelope_xdr.as_str()),
        "the envelope is sent unchanged"
    );
    assert_eq!(
        params.keys().map(String::as_str).collect::<Vec<_>>(),
        vec!["transaction"],
        "the request carries no authMode"
    );

    let endpoint = EchoingEndpoint::start().await;
    endpoint.mount_error_for_every_method().await;
    let err = endpoint
        .client()
        .simulate_transaction_envelope(&envelope)
        .await
        .expect_err("the endpoint answers with an error object");
    let (url, reason) = unreachable_parts(err);
    assert_eq!(
        url,
        endpoint.server.uri(),
        "the endpoint keeps its authority"
    );
    assert!(
        reason.starts_with("simulateTransaction failed: "),
        "the prefix stays: {reason}"
    );
    endpoint.assert_scrubbed(&reason);
    assert!(
        !reason.contains("http://"),
        "no scheme survives in the reason: {reason}"
    );
}

/// `getTransaction` keeps its prefix and only host and port.
#[tokio::test]
async fn get_transaction_status_scrubs_the_server_text_from_its_reason() {
    let endpoint = EchoingEndpoint::start().await;
    endpoint.mount_error_for_every_method().await;

    let err = endpoint
        .client()
        .get_transaction_status(&"ab".repeat(32))
        .await
        .expect_err("the endpoint answers with an error object");

    let (_, reason) = unreachable_parts(err);
    assert!(
        reason.starts_with("getTransaction failed: "),
        "the prefix stays: {reason}"
    );
    endpoint.assert_scrubbed(&reason);
    assert!(
        !reason.contains("http://"),
        "no scheme survives in the reason: {reason}"
    );
}

/// The WASM-hash wrapper carries the scrubbed network error as its source,
/// and its own display holds no more of the echoed URLs.
#[tokio::test]
async fn wasm_hash_fetch_carries_the_scrubbed_network_error() {
    let endpoint = EchoingEndpoint::start().await;
    endpoint.mount_error_for_every_method().await;
    let contract = stellar_strkey::Contract([3u8; 32]).to_string();

    let err = fetch_contract_wasm_hash(&endpoint.client(), None, contract.as_str())
        .await
        .expect_err("the endpoint answers with an error object");

    let display = err.to_string();
    let FetchContractWasmHashError::Unavailable { source, .. } = err else {
        panic!("expected Unavailable, got {err:?}");
    };
    let (_, reason) = unreachable_parts(source);
    endpoint.assert_scrubbed(&reason);
    endpoint.assert_scrubbed(&display);
}

/// A secondary endpoint that fails the SEP-29 cross-check reports a
/// divergence whose context holds only host and port of the echoed URLs.
#[tokio::test]
async fn sep29_secondary_failure_reports_a_scrubbed_divergence() {
    let primary_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": null,
            "latestLedger": 1000
        })))
        .mount(&primary_server)
        .await;
    let primary = StellarRpcClient::new(&primary_server.uri()).unwrap();
    let secondary = EchoingEndpoint::start().await;
    secondary.mount_error_for_every_method().await;

    let err = check_memo_required(&primary, Some(&secondary.client()), ACCOUNT, false)
        .await
        .expect_err("the secondary answers with an error object");

    assert_eq!(err.code(), "network.rpc_divergence");
    let WalletError::Network(NetworkError::RpcDivergence { context }) = err else {
        panic!("expected RpcDivergence, got {err:?}");
    };
    assert!(
        context.starts_with("SEP-29 config.memo_required secondary fetch failed: "),
        "the context names the failed cross-check: {context}"
    );
    secondary.assert_scrubbed(&context);
}

/// Mounts the two reads every submit performs before it sends: the endpoint
/// identity probe and the signer-set fetch for the envelope's source account.
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

/// A send the endpoint answers with an error object, without a recorder,
/// reports a malformed transaction whose detail keeps the client's wording and
/// only host and port of the echoed URLs.
#[tokio::test]
async fn send_failure_reports_a_scrubbed_malformed_transaction() {
    let endpoint = EchoingEndpoint::start().await;
    let envelope = SignedTestEnvelope::for_source_with_sequence(SOURCE_SEED, 41);
    mount_probe_and_signers(&endpoint.server, &envelope).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("token", "CLIENTSECRET"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(endpoint.error_response())
        .mount(&endpoint.server)
        .await;

    let err = submit_transaction_and_wait(
        &endpoint.client(),
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect_err("the endpoint answers the send with an error object");

    let sends = endpoint
        .server
        .received_requests()
        .await
        .expect("request recording is on")
        .into_iter()
        .filter(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body)
                .is_ok_and(|body| body["method"] == "sendTransaction")
        })
        .count();
    assert_eq!(sends, 1, "the send must reach the endpoint once");
    assert_eq!(err.code(), "submission.tx_malformed");
    let WalletError::Submission(SubmissionError::TxMalformed { detail }) = err else {
        panic!("expected TxMalformed, got {err:?}");
    };
    assert!(
        detail.starts_with("No status yet:"),
        "the detail keeps the client's wording without a prefix: {detail}"
    );
    endpoint.assert_scrubbed(&detail);
    assert!(
        !detail.contains("http://"),
        "no scheme survives in the detail: {detail}"
    );
}

/// Answers `sendTransaction` with `PENDING` for `envelope` and every
/// `getTransaction` with a success-shaped answer whose status is `PROXIED`
/// followed by the request URL.
async fn mount_send_pending_and_proxied_status(
    endpoint: &EchoingEndpoint,
    envelope: &SignedTestEnvelope,
) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "hash": envelope.tx_hash_hex(),
            "status": "PENDING",
            "latestLedger": 2000,
            "latestLedgerCloseTime": "1700000000"
        })))
        .mount(&endpoint.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": format!("PROXIED {}", endpoint.client_url),
            "latestLedger": 2001,
            "oldestLedger": 1
        })))
        .mount(&endpoint.server)
        .await;
}

/// A recorder that accepts every send and keeps every outcome it receives.
#[derive(Default)]
struct OutcomeLog {
    outcomes: Mutex<Vec<SubmissionOutcome>>,
}

#[async_trait::async_trait]
impl SubmissionRecorder for OutcomeLog {
    async fn pre_send(&self, _intent: &SubmissionIntent) -> Result<(), WalletError> {
        Ok(())
    }

    async fn outcome(&self, _intent: &SubmissionIntent, outcome: &SubmissionOutcome) {
        self.outcomes.lock().unwrap().push(outcome.clone());
    }
}

/// A confirmation poll that reports a status the wallet does not know, which
/// holds a credential-bearing URL, reports it with only host and port. Without
/// a recorder the status enters the error; with one it enters the diagnostic
/// the recorder receives.
#[tokio::test]
async fn unexpected_transaction_status_enters_the_reason_scrubbed() {
    let endpoint = EchoingEndpoint::start().await;
    let envelope = SignedTestEnvelope::for_source_with_sequence(SOURCE_SEED, 42);
    mount_probe_and_signers(&endpoint.server, &envelope).await;
    mount_send_pending_and_proxied_status(&endpoint, &envelope).await;
    let client = endpoint.client();

    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        None,
    )
    .await
    .expect_err("the endpoint reports an unknown status");

    let WalletError::Network(network) = err else {
        panic!("expected a network error, got {err:?}");
    };
    let (_, reason) = unreachable_parts(network);
    assert_eq!(
        reason,
        format!(
            "unexpected getTransaction status: PROXIED {}",
            endpoint.authority()
        )
    );

    let log = OutcomeLog::default();
    let err = submit_transaction_and_wait(
        &client,
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        None,
        Some(&log),
    )
    .await
    .expect_err("the endpoint reports an unknown status");

    assert_eq!(
        err.code(),
        "submission.tx_timeout",
        "with a recorder the outcome is unknown: {err:?}"
    );
    assert_eq!(
        *log.outcomes.lock().unwrap(),
        vec![SubmissionOutcome::TransportAfterSend {
            error: format!(
                "the endpoint reported an unexpected transaction status: PROXIED {}",
                endpoint.authority()
            ),
        }],
        "the recorder receives the status with only host and port"
    );
}

/// The receipt-backed send, answered with an error object, reports a reason
/// that keeps only host and port of the echoed URLs.
#[tokio::test]
async fn idempotent_send_failure_reports_a_scrubbed_reason() {
    let endpoint = EchoingEndpoint::start().await;
    let envelope = SignedTestEnvelope::for_source_with_sequence(SOURCE_SEED, 43);
    mount_probe_and_signers(&endpoint.server, &envelope).await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(query_param("token", "CLIENTSECRET"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(endpoint.error_response())
        .mount(&endpoint.server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "test").unwrap();

    let err = submit_transaction_idempotent(
        &endpoint.client(),
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await
    .expect_err("the endpoint answers the send with an error object");

    let WalletError::Network(network) = err else {
        panic!("expected a network error, got {err:?}");
    };
    let (url, reason) = unreachable_parts(network);
    assert_eq!(
        url,
        endpoint.server.uri(),
        "the endpoint keeps its authority"
    );
    assert!(
        reason.starts_with("transaction submission failed: No status yet:"),
        "the reason is the send failure: {reason}"
    );
    endpoint.assert_scrubbed(&reason);
    assert!(
        !reason.contains("http://"),
        "no scheme survives in the reason: {reason}"
    );
}

/// The receipt-backed confirmation poll, answered with an unknown status that
/// holds the request URL, reports it with only host and port.
#[tokio::test]
async fn idempotent_unexpected_status_enters_the_reason_scrubbed() {
    let endpoint = EchoingEndpoint::start().await;
    let envelope = SignedTestEnvelope::for_source_with_sequence(SOURCE_SEED, 44);
    mount_probe_and_signers(&endpoint.server, &envelope).await;
    mount_send_pending_and_proxied_status(&endpoint, &envelope).await;
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "test").unwrap();

    let err = submit_transaction_idempotent(
        &endpoint.client(),
        envelope.envelope_xdr(),
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await
    .expect_err("the endpoint reports an unknown status");

    let WalletError::Network(network) = err else {
        panic!("expected a network error, got {err:?}");
    };
    let (_, reason) = unreachable_parts(network);
    assert_eq!(
        reason,
        format!(
            "unexpected getTransaction status: PROXIED {}",
            endpoint.authority()
        )
    );
}
