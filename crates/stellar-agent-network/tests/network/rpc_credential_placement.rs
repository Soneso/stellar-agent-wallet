//! A provider credential reaches a mocked endpoint at its placement, the
//! client's configured URL never carries it, and no error text or trace log
//! the client produces does.
//!
//! The credential holds a space, `+`, `/`, and `%`, so its query and path
//! forms differ from the raw value, and each mock answers only a request that
//! carries the credential exactly; any other request gets HTTP 401.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test; panics and unwraps are acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::error::{NetworkError, SubmissionError, WalletError};
use stellar_agent_core::profile::schema::RpcCredentialPlacement;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::submit::submit_transaction_and_wait;
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::{CaptureWriter, EchoIdResponder};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};
use zeroize::Zeroizing;

/// The stored credential.
const VALUE: &str = "k3y +/%2F v4lue";

/// [`VALUE`] form-urlencoded, as a query placement sends it.
const QUERY_FORM: &str = "k3y+%2B%2F%252F+v4lue";

/// [`VALUE`] as one percent-encoded path segment, as a path placement sends it.
const PATH_FORM: &str = "k3y%20+%2F%252F%20v4lue";

/// Long enough for every retry the default policy allows.
const GENEROUS_DEADLINE: Duration = Duration::from_secs(60);

fn header() -> RpcCredentialPlacement {
    RpcCredentialPlacement::Header {
        name: "X-API-Key".to_owned(),
    }
}

fn query() -> RpcCredentialPlacement {
    RpcCredentialPlacement::Query {
        name: "apikey".to_owned(),
    }
}

fn placements() -> [(RpcCredentialPlacement, &'static str); 3] {
    [
        (header(), VALUE),
        (query(), QUERY_FORM),
        (RpcCredentialPlacement::Path {}, PATH_FORM),
    ]
}

/// Matches a request that carries [`VALUE`] at the placement: the exact
/// header value, a decoded query pair, or a path segment in its encoded form.
struct CarriesCredential(RpcCredentialPlacement);

impl wiremock::Match for CarriesCredential {
    fn matches(&self, request: &Request) -> bool {
        match &self.0 {
            RpcCredentialPlacement::Header { name } => request
                .headers
                .get(name.as_str())
                .is_some_and(|value| value.as_bytes() == VALUE.as_bytes()),
            RpcCredentialPlacement::Query { name } => request
                .url
                .query_pairs()
                .any(|(key, value)| key == name.as_str() && value == VALUE),
            _ => request
                .url
                .path_segments()
                .is_some_and(|mut segments| segments.any(|segment| segment == PATH_FORM)),
        }
    }
}

fn client(url: &str, placement: &RpcCredentialPlacement) -> StellarRpcClient {
    StellarRpcClient::with_credential(url, placement, Zeroizing::new(VALUE.to_owned())).unwrap()
}

/// Answers `getNetwork` with the testnet identity for a request carrying the
/// credential, and every other request with HTTP 401.
async fn serve_identity(server: &MockServer, placement: &RpcCredentialPlacement) {
    Mock::given(method("POST"))
        .and(CarriesCredential(placement.clone()))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)))
        .with_priority(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .with_priority(10)
        .mount(server)
        .await;
}

async fn identity_passes(client: &StellarRpcClient) {
    client
        .endpoint_identity(
            TESTNET_PASSPHRASE,
            tokio::time::Instant::now() + GENEROUS_DEADLINE,
        )
        .await
        .expect("the endpoint answers the credentialed identity request");
}

async fn single_request(server: &MockServer) -> Request {
    let requests = server.received_requests().await.unwrap();
    let [request] = requests.as_slice() else {
        panic!("one request, got {}", requests.len());
    };
    request.clone()
}

#[tokio::test]
async fn header_placement_reaches_the_endpoint() {
    let server = MockServer::start().await;
    serve_identity(&server, &header()).await;
    let url = format!("{}/rpc?x=1", server.uri());
    let client = client(&url, &header());
    identity_passes(&client).await;
    assert_eq!(client.url(), url);
    let request = single_request(&server).await;
    assert_eq!(
        request.headers.get("x-api-key").unwrap().as_bytes(),
        VALUE.as_bytes()
    );
    assert_eq!(request.url.path(), "/rpc");
    assert_eq!(request.url.query(), Some("x=1"));
}

#[tokio::test]
async fn query_placement_reaches_the_endpoint_encoded() {
    let server = MockServer::start().await;
    serve_identity(&server, &query()).await;
    let url = format!("{}/rpc?x=1", server.uri());
    let client = client(&url, &query());
    identity_passes(&client).await;
    assert_eq!(client.url(), url);
    let request = single_request(&server).await;
    assert_eq!(
        request.url.query(),
        Some(format!("x=1&apikey={QUERY_FORM}").as_str())
    );
    assert!(request.headers.get("x-api-key").is_none());
}

#[tokio::test]
async fn path_placement_appends_one_segment() {
    let server = MockServer::start().await;
    serve_identity(&server, &RpcCredentialPlacement::Path {}).await;
    let url = format!("{}/v2", server.uri());
    let client = client(&url, &RpcCredentialPlacement::Path {});
    identity_passes(&client).await;
    assert_eq!(client.url(), url);
    assert_eq!(
        single_request(&server).await.url.path(),
        format!("/v2/{PATH_FORM}")
    );
}

#[tokio::test]
async fn path_placement_keeps_a_trailing_slash() {
    for (suffix, expected) in [
        ("/v1/", format!("/v1/{PATH_FORM}/")),
        ("", format!("/{PATH_FORM}/")),
        ("/", format!("/{PATH_FORM}/")),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(expected.as_str()))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)))
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .with_priority(10)
            .mount(&server)
            .await;
        let url = format!("{}{suffix}", server.uri());
        let client = client(&url, &RpcCredentialPlacement::Path {});
        identity_passes(&client).await;
        assert_eq!(client.url(), url);
        assert_eq!(single_request(&server).await.url.path(), expected);
    }
}

/// An error object whose `message` echoes the credential bare, in its wire
/// form, and inside the request URL.
fn echo_error(server: &MockServer, wire: &str) -> ResponseTemplate {
    let message = format!(
        "bad key {VALUE} sent as {wire} for {}/rpc?apikey={wire}",
        server.uri()
    );
    ResponseTemplate::new(200).set_body_json(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32000, "message": message, "data": {"key": VALUE}}
    }))
}

fn assert_no_credential(case: &str, text: &str) {
    for form in [VALUE, QUERY_FORM, PATH_FORM, "k3y", "v4lue"] {
        assert!(!text.contains(form), "{case}: {form} survived: {text}");
    }
}

/// Every failed read, a simulation's `error` field, a send failure, and a
/// transport failure lose every form of the credential, before the URL
/// scrub.
#[tokio::test]
async fn credential_is_scrubbed_from_json_rpc_transport_and_simulate_errors() {
    use stellar_xdr::ReadXdr as _;
    let envelope = SignedTestEnvelope::for_source_with_sequence([9u8; 32], 41);
    let decoded = stellar_xdr::TransactionEnvelope::from_xdr_base64(
        envelope.envelope_xdr(),
        stellar_xdr::Limits::none(),
    )
    .unwrap();
    let key = stellar_xdr::LedgerKey::Account(stellar_xdr::LedgerKeyAccount {
        account_id: stellar_xdr::AccountId(stellar_xdr::PublicKey::PublicKeyTypeEd25519(
            stellar_xdr::Uint256([7u8; 32]),
        )),
    });
    for (placement, wire) in placements() {
        let case = format!("{placement:?}");
        let server = MockServer::start().await;
        for method_name in ["getLedgerEntries", "getHealth", "simulateTransaction"] {
            Mock::given(method("POST"))
                .and(CarriesCredential(placement.clone()))
                .and(body_partial_json(json!({"method": method_name})))
                .respond_with(echo_error(&server, wire))
                .mount(&server)
                .await;
        }
        let reader = client(&format!("{}/rpc/", server.uri()), &placement);

        let reads = [
            reader
                .get_ledger_entries(std::slice::from_ref(&key))
                .await
                .err()
                .unwrap(),
            reader.get_health().await.err().unwrap(),
            reader
                .simulate_transaction_envelope(&decoded)
                .await
                .err()
                .unwrap(),
        ];
        for error in reads {
            let text = format!("{error} {error:?}");
            assert!(
                text.contains("bad key [redacted] sent as [redacted]"),
                "{case}: {text}"
            );
            assert_no_credential(&case, &text);
            assert!(!text.contains("/rpc?"), "{case}: the URL scrub ran: {text}");
        }

        let answer_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(CarriesCredential(placement.clone()))
            .and(body_partial_json(json!({"method": "simulateTransaction"})))
            .respond_with(EchoIdResponder::new(json!({
                "latestLedger": 7,
                "error": format!("host refused {VALUE} ({wire}) at https://h.example/{wire}")
            })))
            .mount(&answer_server)
            .await;
        let answer = client(&format!("{}/rpc/", answer_server.uri()), &placement)
            .simulate_transaction_envelope(&decoded)
            .await
            .unwrap();
        let error = answer.error.unwrap();
        assert_eq!(
            error, "host refused [redacted] ([redacted]) at https://h.example/[redacted]",
            "{case}"
        );

        let send_server = MockServer::start().await;
        for (method_name, result) in [
            ("getNetwork", get_network_result(TESTNET_PASSPHRASE)),
            ("getLedgerEntries", envelope.ledger_entries_result()),
        ] {
            Mock::given(method("POST"))
                .and(CarriesCredential(placement.clone()))
                .and(body_partial_json(json!({"method": method_name})))
                .respond_with(EchoIdResponder::new(result))
                .mount(&send_server)
                .await;
        }
        Mock::given(method("POST"))
            .and(CarriesCredential(placement.clone()))
            .and(body_partial_json(json!({"method": "sendTransaction"})))
            .respond_with(echo_error(&send_server, wire))
            .mount(&send_server)
            .await;
        let err = submit_transaction_and_wait(
            &client(&format!("{}/rpc/", send_server.uri()), &placement),
            envelope.envelope_xdr(),
            Duration::from_secs(30),
            TESTNET_PASSPHRASE,
            None,
            None,
        )
        .await
        .err()
        .unwrap();
        let WalletError::Submission(SubmissionError::TxMalformed { detail }) = &err else {
            panic!("{case}: expected a malformed transaction, got {err:?}");
        };
        assert!(detail.contains("bad key [redacted]"), "{case}: {detail}");
        assert_no_credential(&case, &format!("{err} {err:?}"));

        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let error = client(&format!("http://127.0.0.1:{port}/rpc/"), &placement)
            .get_health()
            .await
            .err()
            .unwrap();
        assert!(
            matches!(error, NetworkError::RpcUnreachable { .. }),
            "{error:?}"
        );
        assert_no_credential(&case, &format!("{error} {error:?}"));
    }
}

/// Forwards records of the `log` facade into `tracing`, as the wallet's
/// observability setup does, so the trace probe also sees what crates that
/// log through `log` write. Installed once for the test binary, which sets no
/// other global logger.
fn install_log_bridge() {
    static LOG_BRIDGE: std::sync::Once = std::sync::Once::new();
    LOG_BRIDGE.call_once(|| {
        tracing_log::LogTracer::init().expect("no other `log` logger in this test binary");
    });
}

/// With every `tracing` level enabled, `log` records bridged into `tracing`,
/// and no redacting formatter, a credentialed identity request leaves the
/// credential in no log line. The capture is shown to work by jsonrpsee's
/// TRACE line for the request and by a bridged `log` record.
///
/// The subscriber is the thread default of the thread that drives a
/// current-thread runtime, so the connection tasks the HTTP stack spawns on
/// that runtime log into it; the mock server runs on its own thread.
#[test]
fn credential_never_reaches_a_trace_log() {
    install_log_bridge();
    for (placement, wire) in placements() {
        let setup = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let server = setup.block_on(async {
            let server = MockServer::start().await;
            serve_identity(&server, &placement).await;
            server
        });
        let url = format!("{}/rpc/", server.uri());

        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            tracing_log::log::trace!(target: "log_bridge_probe", "bridged log record");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let client = client(&url, &placement);
                identity_passes(&client).await;
            });
        });

        let captured = capture.captured_str();
        assert!(
            captured
                .lines()
                .any(|line| line.contains("jsonrpsee") && line.contains("getNetwork")),
            "{placement:?}: the capture holds the request's trace line: {captured}"
        );
        assert!(
            captured.lines().any(
                |line| line.contains("log_bridge_probe") && line.contains("bridged log record")
            ),
            "{placement:?}: the capture holds the bridged log record: {captured}"
        );
        for form in [VALUE, wire, "k3y"] {
            assert!(
                !captured.contains(form),
                "{placement:?}: {form} reached a log line: {captured}"
            );
        }
        drop(setup);
    }
}
