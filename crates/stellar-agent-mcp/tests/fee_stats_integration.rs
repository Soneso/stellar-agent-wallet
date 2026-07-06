//! Integration tests for the `stellar_fee_stats` MCP tool.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{StellarFeeStatsArgs, WalletServer};
use stellar_agent_test_support::xdr_fixtures::EchoIdResponder;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer};

fn fee_stat_json(p95: &str) -> serde_json::Value {
    serde_json::json!({
        "max": "1000",
        "min": "100",
        "mode": "100",
        "p10": "100",
        "p20": "110",
        "p30": "120",
        "p40": "130",
        "p50": "140",
        "p60": "150",
        "p70": "160",
        "p80": "170",
        "p90": "180",
        "p95": p95,
        "p99": "250",
        "transactionCount": "12",
        "ledgerCount": "5"
    })
}

fn fee_stats_result() -> serde_json::Value {
    serde_json::json!({
        "sorobanInclusionFee": fee_stat_json("300"),
        "inclusionFee": fee_stat_json("200"),
        "latestLedger": "12345"
    })
}

/// Testnet profile with `engine = Noop` and the given RPC URL for test isolation.
///
/// Explicitly sets `Noop` so `WalletServer::new` succeeds without a signed
/// policy file on disk (`PolicyEngineKind::default()` is `V1`, which requires
/// a signed policy file and a keyring owner-key entry).
fn testnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = rpc_url.to_owned();
    profile
}

/// Builds a mainnet profile with `engine = Noop` and the given RPC URL.
///
/// Explicitly sets `Noop` so `WalletServer::new` succeeds without a signed
/// policy file on disk.  `stellar_fee_stats` is a read-only tool; the policy
/// gate allows read-only tools unconditionally, but `build_policy_engine` must
/// still be able to construct the engine from the profile.
fn mainnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut profile = Profile::builder_mainnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    profile.rpc_url = rpc_url.to_owned();
    profile
}

fn call_result_text(result: &rmcp::model::CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
        .unwrap_or("")
}

#[tokio::test]
#[serial]
async fn stellar_fee_stats_with_mock_rpc_succeeds() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(fee_stats_result()))
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(testnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    let result = server
        .call_stellar_fee_stats(StellarFeeStatsArgs {
            chain_id: "stellar:testnet".to_owned(),
            rpc_url: None,
        })
        .await
        .expect("fee stats call should succeed");

    assert_ne!(result.is_error, Some(true));
    let json: serde_json::Value =
        serde_json::from_str(call_result_text(&result)).expect("tool result JSON");
    assert_eq!(
        json.pointer("/data/latest_ledger"),
        Some(&serde_json::json!(12345))
    );
    assert_eq!(
        json.pointer("/data/inclusion_fee/p95"),
        Some(&serde_json::json!("200"))
    );
    assert_eq!(
        json.pointer("/data/soroban_inclusion_fee/p95"),
        Some(&serde_json::json!("300"))
    );
}

#[tokio::test]
#[serial]
async fn stellar_fee_stats_mainnet_read_only_succeeds() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(fee_stats_result()))
        .mount(&mock_server)
        .await;

    let server =
        WalletServer::new(mainnet_profile_with_rpc(&mock_server.uri())).expect("WalletServer::new");
    let result = server
        .call_stellar_fee_stats(StellarFeeStatsArgs {
            chain_id: "stellar:mainnet".to_owned(),
            rpc_url: None,
        })
        .await
        .expect("mainnet read-only fee stats call should succeed");

    assert_ne!(result.is_error, Some(true));
}

#[tokio::test]
#[serial]
async fn stellar_fee_stats_non_allowlisted_rpc_url_is_invalid_params() {
    let server = WalletServer::new(testnet_profile_with_rpc(
        "https://soroban-testnet.stellar.org",
    ))
    .expect("WalletServer::new");
    let err = server
        .call_stellar_fee_stats(StellarFeeStatsArgs {
            chain_id: "stellar:testnet".to_owned(),
            rpc_url: Some("https://untrusted.example.com".to_owned()),
        })
        .await
        .expect_err("non-allowlisted rpc_url must fail");

    assert!(
        err.to_string().contains("invalid rpc_url"),
        "expected invalid rpc_url, got: {err}"
    );
}
