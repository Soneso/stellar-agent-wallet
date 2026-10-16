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
use std::time::Duration;

use serde_json::{Value, json};
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::caip2::Caip2;
use stellar_agent_network::{EndpointIdentity, SUPPORTED_PROTOCOL_VERSIONS, StellarRpcClient};
use stellar_agent_test_support::signed_envelope::{
    MAINNET_PASSPHRASE, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::{EchoIdResponder, WarningCapture, rpc_request_count};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
/// both passphrases.
#[tokio::test]
async fn another_network_than_expected_is_a_mismatch() {
    const OTHER: &str = "Some Other Network ; 2015";
    let server = serve_get_network(network(OTHER, 29)).await;

    match identity(&server, TESTNET_PASSPHRASE).await {
        Err(WalletError::Network(NetworkError::EndpointNetworkMismatch { expected, server })) => {
            assert_eq!(expected, TESTNET_PASSPHRASE);
            assert_eq!(server, OTHER);
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
            assert_eq!(server, TESTNET_PASSPHRASE);
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
