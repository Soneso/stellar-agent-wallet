//! `StellarRpcClient::endpoint_identity` against a mocked Stellar RPC
//! endpoint.
//!
//! The check asks `getNetwork` once per attempt and decides, in order: an
//! endpoint reporting mainnet, a passphrase other than the expected one, and
//! the protocol rule. These tests pin each outcome, the request count behind
//! it, the authority the identity carries, and the warning a test network
//! outside the supported protocol range produces.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_network::{
    EndpointIdentity, SUPPORTED_PROTOCOL_VERSIONS, SigningLedgerObservation, StellarRpcClient,
};
use stellar_agent_test_support::signed_envelope::{
    MAINNET_PASSPHRASE, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::{EchoIdResponder, WarningCapture, rpc_request_count};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A network whose passphrase names neither testnet nor mainnet.
const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

/// Long enough for every retry the default policy allows: at most 7.5 s of
/// sleeps across five attempts against a local server.
const GENEROUS_DEADLINE: Duration = Duration::from_secs(60);

// ── Fixtures ────────────────────────────────────────────────────────────────

/// Starts a server that answers every `getNetwork` with `result`.
async fn serve_get_network(result: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(result))
        .mount(&server)
        .await;
    server
}

/// A `getNetwork` result reporting `passphrase` at `protocol_version`.
fn network(passphrase: &str, protocol_version: u32) -> Value {
    json!({
        "friendbotUrl": "https://friendbot.stellar.org",
        "passphrase": passphrase,
        "protocolVersion": protocol_version,
    })
}

async fn identity(
    server: &MockServer,
    expected_passphrase: &str,
) -> Result<EndpointIdentity, WalletError> {
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    client
        .endpoint_identity(
            expected_passphrase,
            tokio::time::Instant::now() + GENEROUS_DEADLINE,
        )
        .await
}

fn expect_unavailable(result: Result<EndpointIdentity, WalletError>, server: &MockServer) {
    match result {
        Err(WalletError::Network(NetworkError::EndpointIdentityUnavailable { url })) => {
            assert_eq!(url, server.uri(), "the error carries the authority");
        }
        other => panic!("expected network.endpoint_identity_unavailable; got {other:?}"),
    }
}

fn assert_one_protocol_warning(warnings: &[BTreeMap<String, String>], version: u32) {
    assert_eq!(warnings.len(), 1, "exactly one warning: {warnings:?}");
    let warning = &warnings[0];
    assert_eq!(
        warning.get("protocol_version").map(String::as_str),
        Some(version.to_string().as_str()),
        "{warning:?}"
    );
    assert_eq!(
        warning.get("supported_min").map(String::as_str),
        Some("29"),
        "{warning:?}"
    );
    assert_eq!(
        warning.get("supported_max").map(String::as_str),
        Some("29"),
        "{warning:?}"
    );
}

// ── The shared fixture ──────────────────────────────────────────────────────

/// The `getNetwork` fixture every offline submit-path test mounts reports a
/// supported protocol version, so those tests pass the protocol rule without
/// a warning.
#[test]
fn the_shared_get_network_fixture_reports_a_supported_version() {
    let version = get_network_result(TESTNET_PASSPHRASE)["protocolVersion"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .expect("the fixture reports a u32 protocolVersion");
    assert!(
        SUPPORTED_PROTOCOL_VERSIONS.contains(&version),
        "fixture version {version} is outside {SUPPORTED_PROTOCOL_VERSIONS:?}"
    );
}

// ── Outcomes ────────────────────────────────────────────────────────────────

/// Each client carries its own identity into the facts it establishes, so two
/// clients against one endpoint never yield the same identity.
#[tokio::test]
async fn the_identity_names_the_client_it_was_established_through() {
    let server = serve_get_network(network(TESTNET_PASSPHRASE, 29)).await;
    let first = StellarRpcClient::new(&server.uri()).unwrap();
    let second = StellarRpcClient::new(&server.uri()).unwrap();
    assert_ne!(first.id(), second.id());
    for client in [&first, &second] {
        let found = client
            .endpoint_identity(
                TESTNET_PASSPHRASE,
                tokio::time::Instant::now() + GENEROUS_DEADLINE,
            )
            .await
            .unwrap();
        assert_eq!(found.client_id(), client.id());
    }
}

/// A testnet endpoint at a supported version yields its chain, its version,
/// and an authority stripped of the userinfo, path, and query the endpoint
/// URL carries.
#[tokio::test]
async fn testnet_at_a_supported_version_yields_the_identity_with_a_bare_authority() {
    let server = serve_get_network(network(TESTNET_PASSPHRASE, 29)).await;
    let port = server.address().port();
    let url = format!("http://user:SECRET@127.0.0.1:{port}/rpc/path?token=SECRET");
    let client = StellarRpcClient::new(&url).unwrap();

    let found = client
        .endpoint_identity(
            TESTNET_PASSPHRASE,
            tokio::time::Instant::now() + GENEROUS_DEADLINE,
        )
        .await
        .unwrap();

    assert_eq!(found.chain_id(), Some(Caip2::Testnet));
    assert_eq!(found.protocol_version(), 29);
    assert_eq!(found.authority(), format!("http://127.0.0.1:{port}"));
    for leaked in ["user", "SECRET", "/rpc", "token", "?"] {
        assert!(
            !found.authority().contains(leaked),
            "{leaked} reached the authority: {}",
            found.authority()
        );
    }
    assert_eq!(rpc_request_count(&server, "getNetwork").await, 1);
}

/// An endpoint serving another network than the expected one is refused with
/// the declared passphrase and the class of the reported one; no rendering of
/// the error holds the reported value.
#[tokio::test]
async fn another_network_than_expected_is_a_mismatch() {
    const OTHER: &str = "Some Other Network ; 2015";
    let server = serve_get_network(network(OTHER, 29)).await;

    let result = identity(&server, TESTNET_PASSPHRASE).await;
    let debug = format!("{result:?}");
    assert!(!debug.contains(OTHER), "{debug}");
    match result {
        Err(WalletError::Network(NetworkError::EndpointNetworkMismatch { expected, server })) => {
            assert_eq!(expected, TESTNET_PASSPHRASE);
            assert_eq!(server.as_str(), "<other network>");
        }
        other => panic!("expected network.endpoint_network_mismatch; got {other:?}"),
    }
}

/// A mainnet endpoint is refused as a mainnet write when testnet was
/// expected.
#[tokio::test]
async fn a_mainnet_endpoint_under_a_testnet_expectation_is_a_mainnet_write() {
    let server = serve_get_network(network(MAINNET_PASSPHRASE, 29)).await;

    let result = identity(&server, TESTNET_PASSPHRASE).await;
    assert!(
        matches!(
            result,
            Err(WalletError::Network(NetworkError::MainnetWriteForbidden))
        ),
        "{result:?}"
    );
}

/// An answer that does not deserialize is answered once and not retried,
/// although the deadline leaves room for every retry.
#[tokio::test]
async fn an_answer_that_does_not_parse_is_not_retried() {
    let bodies = [
        (
            "no protocolVersion",
            json!({"friendbotUrl": "https://friendbot.stellar.org", "passphrase": TESTNET_PASSPHRASE}),
        ),
        (
            "string protocolVersion",
            json!({"passphrase": TESTNET_PASSPHRASE, "protocolVersion": "29"}),
        ),
    ];
    for (case, body) in bodies {
        let server = serve_get_network(body).await;
        let result = identity(&server, TESTNET_PASSPHRASE).await;
        expect_unavailable(result, &server);
        assert_eq!(
            rpc_request_count(&server, "getNetwork").await,
            1,
            "{case}: one request, no retry"
        );
    }
}

/// A transport failure is retried up to the policy's five attempts, then the
/// identity is unavailable.
#[tokio::test]
async fn a_failing_endpoint_is_retried_five_times_then_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let result = identity(&server, TESTNET_PASSPHRASE).await;
    expect_unavailable(result, &server);
    assert_eq!(rpc_request_count(&server, "getNetwork").await, 5);
}

/// An identity answer of HTTP 401 or 403 is final: one request, the
/// credential refusal code, and a text with the status and the authority but
/// no part of the body or the URL's path and query.
#[tokio::test]
async fn identity_401_and_403_report_the_status_and_authority() {
    for status in [401u16, 403] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(ResponseTemplate::new(status).set_body_string("BODY_SENTINEL"))
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&format!(
            "{}/PATH_SENTINEL?key=QUERY_SENTINEL",
            server.uri()
        ))
        .unwrap();
        let error = client
            .endpoint_identity(
                TESTNET_PASSPHRASE,
                tokio::time::Instant::now() + GENEROUS_DEADLINE,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), "network.rpc_credential_refused", "{status}");
        match &error {
            WalletError::Network(NetworkError::RpcCredentialRejected { url, status: got }) => {
                assert_eq!(url, &server.uri());
                assert_eq!(*got, status);
            }
            other => panic!("{status}: expected a credential refusal, got {other:?}"),
        }
        let text = error.to_string();
        assert_eq!(
            text,
            format!(
                "RPC endpoint '{}' answered a request with HTTP {status}; \
                 check the credential the profile configures for this endpoint",
                server.uri()
            )
        );
        for leaked in ["BODY_SENTINEL", "PATH_SENTINEL", "QUERY_SENTINEL"] {
            assert!(!format!("{text} {error:?}").contains(leaked), "{leaked}");
        }
        assert_eq!(
            rpc_request_count(&server, "getNetwork").await,
            1,
            "{status}"
        );
    }
}

/// A rate limit and a server error are still retried to the policy's five
/// attempts and end as an unavailable identity.
#[tokio::test]
async fn identity_429_and_500_are_still_retried() {
    for status in [429u16, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getNetwork"})))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        expect_unavailable(identity(&server, TESTNET_PASSPHRASE).await, &server);
        assert_eq!(
            rpc_request_count(&server, "getNetwork").await,
            5,
            "{status}"
        );
    }
}

/// A network other than testnet and mainnet whose passphrase matches the
/// expected one yields no chain. At a supported version it passes without a
/// warning; outside the range it passes with one warning.
#[tokio::test]
async fn a_matching_custom_network_yields_no_chain_and_warns_only_outside_the_range() {
    for (version, warns) in [(29, false), (30, true)] {
        let server = serve_get_network(network(FUTURENET_PASSPHRASE, version)).await;
        let (warnings, guard) = WarningCapture::capture(Some("stellar_agent_network"));
        let found = identity(&server, FUTURENET_PASSPHRASE).await.unwrap();
        drop(guard);

        assert_eq!(found.chain_id(), None, "version {version}");
        assert_eq!(found.protocol_version(), version);
        if warns {
            assert_one_protocol_warning(&warnings.seen(), version);
        } else {
            assert!(warnings.seen().is_empty(), "{:?}", warnings.seen());
        }
    }
}

/// A testnet endpoint outside the supported range passes with exactly one
/// warning carrying the version and the range; inside the range it emits
/// none.
#[tokio::test]
async fn testnet_outside_the_range_passes_with_one_warning() {
    for (version, warns) in [(30, true), (29, false)] {
        let server = serve_get_network(network(TESTNET_PASSPHRASE, version)).await;
        let (warnings, guard) = WarningCapture::capture(Some("stellar_agent_network"));
        let found = identity(&server, TESTNET_PASSPHRASE).await.unwrap();
        drop(guard);

        assert_eq!(found.chain_id(), Some(Caip2::Testnet));
        assert_eq!(found.protocol_version(), version);
        if warns {
            assert_one_protocol_warning(&warnings.seen(), version);
        } else {
            assert!(warnings.seen().is_empty(), "{:?}", warnings.seen());
        }
    }
}

// ── Precedence ──────────────────────────────────────────────────────────────

/// A mainnet endpoint is refused as a mainnet write before the protocol rule
/// sees its unsupported version, even when mainnet was expected.
#[tokio::test]
async fn a_mainnet_endpoint_is_refused_before_the_protocol_rule() {
    let server = serve_get_network(network(MAINNET_PASSPHRASE, 30)).await;

    let result = identity(&server, MAINNET_PASSPHRASE).await;
    assert!(
        matches!(
            result,
            Err(WalletError::Network(NetworkError::MainnetWriteForbidden))
        ),
        "{result:?}"
    );
}

/// A testnet endpoint under a mainnet expectation is a mismatch before the
/// protocol rule sees its unsupported version.
#[tokio::test]
async fn a_mismatch_is_refused_before_the_protocol_rule() {
    let server = serve_get_network(network(TESTNET_PASSPHRASE, 30)).await;

    let (warnings, _guard) = WarningCapture::capture(Some("stellar_agent_network"));

    match identity(&server, MAINNET_PASSPHRASE).await {
        Err(WalletError::Network(NetworkError::EndpointNetworkMismatch { expected, server })) => {
            assert_eq!(expected, MAINNET_PASSPHRASE);
            assert_eq!(server.as_str(), TESTNET_PASSPHRASE);
        }
        other => panic!("expected network.endpoint_network_mismatch; got {other:?}"),
    }
    assert!(
        warnings.seen().is_empty(),
        "mismatch precedes protocol warnings: {:?}",
        warnings.seen()
    );
}

/// An answer that does not deserialize is unavailable after one request under
/// a mainnet expectation as well.
#[tokio::test]
async fn an_answer_that_does_not_parse_under_a_mainnet_expectation_is_unavailable() {
    let server = serve_get_network(json!({"passphrase": MAINNET_PASSPHRASE})).await;

    let result = identity(&server, MAINNET_PASSPHRASE).await;
    expect_unavailable(result, &server);
    assert_eq!(rpc_request_count(&server, "getNetwork").await, 1);
}

// ── The signing ledger observation ──────────────────────────────────────────

/// A `getLatestLedger` result at `sequence`.
fn latest_ledger(sequence: u32) -> Value {
    json!({"id": "ab".repeat(32), "sequence": sequence, "protocolVersion": 29})
}

/// Mounts a `getLatestLedger` answer on `server`.
async fn mount_latest_ledger(server: &MockServer, result: Value) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getLatestLedger"})))
        .respond_with(EchoIdResponder::new(result))
        .mount(server)
        .await;
}

/// Prepares a read of `client` under `deadline` and reads one height through
/// it.
async fn observation(
    client: &StellarRpcClient,
    deadline: Duration,
) -> Result<SigningLedgerObservation, WalletError> {
    let prepared = client
        .prepare_signing_ledger_observation(
            TESTNET_PASSPHRASE,
            tokio::time::Instant::now() + deadline,
        )
        .await?;
    prepared.read().await
}

/// An observation binds the height to the identity of the endpoint that
/// reported it and to the local time of the answer.
#[tokio::test]
async fn an_observation_binds_the_height_to_the_checked_identity() {
    let server = serve_get_network(network(TESTNET_PASSPHRASE, 29)).await;
    mount_latest_ledger(&server, latest_ledger(4321)).await;
    let port = server.address().port();
    let client = StellarRpcClient::new(&format!(
        "http://user:SECRET@127.0.0.1:{port}/rpc?token=SECRET"
    ))
    .unwrap();
    let before = tokio::time::Instant::now();

    let found = observation(&client, GENEROUS_DEADLINE).await.unwrap();

    assert_eq!(found.ledger(), 4321);
    assert_eq!(found.identity().chain_id(), Some(Caip2::Testnet));
    assert_eq!(found.identity().client_id(), client.id());
    assert_eq!(
        found.identity().authority(),
        format!("http://127.0.0.1:{port}")
    );
    assert!(found.observed_at() >= before);
    assert!(found.observed_at() <= tokio::time::Instant::now());
    assert_eq!(rpc_request_count(&server, "getNetwork").await, 1);
    assert_eq!(rpc_request_count(&server, "getLatestLedger").await, 1);
}

/// The height of an endpoint on another network is never read.
#[tokio::test]
async fn an_endpoint_on_another_network_gives_no_observation() {
    let server = serve_get_network(network(FUTURENET_PASSPHRASE, 29)).await;
    mount_latest_ledger(&server, latest_ledger(4321)).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let error = observation(&client, GENEROUS_DEADLINE).await.unwrap_err();

    assert!(
        matches!(
            error,
            WalletError::Network(NetworkError::EndpointNetworkMismatch { .. })
        ),
        "{error:?}"
    );
    assert_eq!(rpc_request_count(&server, "getLatestLedger").await, 0);
}

/// A body that does not name a height gives no observation, and the failure
/// names the endpoint by its authority alone.
#[tokio::test]
async fn a_malformed_height_gives_no_observation() {
    let server = serve_get_network(network(TESTNET_PASSPHRASE, 29)).await;
    mount_latest_ledger(
        &server,
        json!({"id": "ab".repeat(32), "sequence": "not-a-ledger", "protocolVersion": 29}),
    )
    .await;
    let port = server.address().port();
    let client =
        StellarRpcClient::new(&format!("http://127.0.0.1:{port}/rpc?token=SECRET")).unwrap();

    let error = observation(&client, GENEROUS_DEADLINE).await.unwrap_err();

    assert!(
        matches!(
            error,
            WalletError::Network(NetworkError::RpcUnreachable { .. })
        ),
        "{error:?}"
    );
    assert!(!format!("{error}").contains("SECRET"), "{error}");
}

/// A height that arrives after the deadline gives no observation.
#[tokio::test]
async fn an_answer_past_the_deadline_gives_no_observation() {
    let server = serve_get_network(network(TESTNET_PASSPHRASE, 29)).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getLatestLedger"})))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let started = std::time::Instant::now();

    let error = observation(&client, Duration::from_millis(300))
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            WalletError::Network(
                NetworkError::RpcUnreachable { .. }
                    | NetworkError::EndpointIdentityUnavailable { .. }
            )
        ),
        "{error:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the deadline ends the read: {:?}",
        started.elapsed()
    );
}

/// Answers `getLatestLedger` with `first`, then `first + 1`, and so on, each
/// after `delay`, and records when each request arrived.
struct AdvancingLedger {
    first: u32,
    delay: Duration,
    arrivals: Arc<Mutex<Vec<tokio::time::Instant>>>,
}

impl Respond for AdvancingLedger {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut arrivals = self.arrivals.lock().unwrap();
        arrivals.push(tokio::time::Instant::now());
        let sequence = self.first + u32::try_from(arrivals.len() - 1).unwrap();
        let id = serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|body| body.get("id").cloned())
            .unwrap_or_else(|| json!(1));
        ResponseTemplate::new(200)
            .set_body_json(json!({"jsonrpc": "2.0", "id": id, "result": latest_ledger(sequence)}))
            .set_delay(self.delay)
    }
}

/// Every read of one prepared value goes through the client that checked the
/// identity, stamps the moment its own answer arrived, and stays under the
/// deadline given at preparation.
#[tokio::test]
async fn prepared_observation_keeps_client_deadline_and_arrival_time() {
    let server = serve_get_network(network(TESTNET_PASSPHRASE, 29)).await;
    let arrivals = Arc::new(Mutex::new(Vec::new()));
    let delay = Duration::from_millis(150);
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": "getLatestLedger"})))
        .respond_with(AdvancingLedger {
            first: 700,
            delay,
            arrivals: Arc::clone(&arrivals),
        })
        .mount(&server)
        .await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let prepared = client
        .prepare_signing_ledger_observation(TESTNET_PASSPHRASE, deadline)
        .await
        .unwrap();

    let first = prepared.read().await.unwrap();
    let second = prepared.read().await.unwrap();

    let arrived = arrivals.lock().unwrap().clone();
    assert_eq!((first.ledger(), second.ledger()), (700, 701));
    for (observation, arrival) in [(&first, arrived[0]), (&second, arrived[1])] {
        assert_eq!(observation.identity().client_id(), client.id());
        assert!(
            observation.observed_at() >= arrival + delay,
            "the stamp follows the answer to its own request"
        );
    }
    assert!(
        first.observed_at() < arrived[1],
        "the first stamp precedes the second request"
    );
    assert_eq!(rpc_request_count(&server, "getNetwork").await, 1);

    tokio::time::sleep_until(deadline).await;
    match prepared.read().await {
        Err(WalletError::Network(NetworkError::RpcUnreachable { reason, .. })) => {
            assert_eq!(reason, "getLatestLedger exceeded its deadline");
        }
        other => panic!("the original deadline bounds a later read: {other:?}"),
    }
}
