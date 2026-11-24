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
    Profile::builder_mainnet(rpc_url, "svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build()
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
async fn stellar_fee_stats_unconfigured_rpc_url_is_invalid_params() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
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
        .expect_err("an unconfigured rpc_url must fail");

    assert!(
        err.to_string().contains("invalid rpc_url"),
        "expected invalid rpc_url, got: {err}"
    );
}

fn fee_stats_result_at_ledger(latest_ledger: &str) -> serde_json::Value {
    serde_json::json!({
        "sorobanInclusionFee": fee_stat_json("300"),
        "inclusionFee": fee_stat_json("200"),
        "latestLedger": latest_ledger
    })
}

#[tokio::test]
#[serial]
async fn stellar_fee_stats_accepts_profile_and_oracle_endpoints_and_refuses_unconfigured() {
    use stellar_agent_core::redact::redact_url_authority;
    use stellar_agent_test_support::rejected_value::CREDENTIAL_MARKER;

    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());

    let primary_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(fee_stats_result_at_ledger("11111")))
        .mount(&primary_mock)
        .await;
    let secondary_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(fee_stats_result_at_ledger("33333")))
        .mount(&secondary_mock)
        .await;
    let oracle_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(fee_stats_result_at_ledger("22222")))
        .mount(&oracle_mock)
        .await;

    let mut profile = testnet_profile_with_rpc(&format!("{}/v1/rpc", primary_mock.uri()));
    profile.secondary_rpc_url = Some(format!("{}/v2", secondary_mock.uri()));
    profile.oracle_provider_url = Some(
        url::Url::parse(&format!("{}/oracle", oracle_mock.uri())).expect("valid oracle mock URL"),
    );
    let printed_primary = redact_url_authority(&profile.rpc_url);
    assert_eq!(printed_primary, primary_mock.uri());

    let server = WalletServer::new(profile).expect("WalletServer::new");

    // Primary endpoint as printed by `mcp-resource://profiles/<name>` (scheme, host, port).
    let primary_res = server
        .call_stellar_fee_stats(StellarFeeStatsArgs {
            chain_id: "stellar:testnet".to_owned(),
            rpc_url: Some(printed_primary),
        })
        .await
        .expect("profile primary endpoint must be accepted");
    assert_ne!(primary_res.is_error, Some(true));
    let primary_json: serde_json::Value =
        serde_json::from_str(call_result_text(&primary_res)).expect("primary JSON");
    assert_eq!(
        primary_json.pointer("/data/latest_ledger"),
        Some(&serde_json::json!(11111))
    );

    // Secondary endpoint configured on the profile.
    let secondary_res = server
        .call_stellar_fee_stats(StellarFeeStatsArgs {
            chain_id: "stellar:testnet".to_owned(),
            rpc_url: Some(secondary_mock.uri()),
        })
        .await
        .expect("profile secondary endpoint must be accepted");
    assert_ne!(secondary_res.is_error, Some(true));
    let secondary_json: serde_json::Value =
        serde_json::from_str(call_result_text(&secondary_res)).expect("secondary JSON");
    assert_eq!(
        secondary_json.pointer("/data/latest_ledger"),
        Some(&serde_json::json!(33333))
    );

    // Oracle endpoint configured on the profile.
    let oracle_res = server
        .call_stellar_fee_stats(StellarFeeStatsArgs {
            chain_id: "stellar:testnet".to_owned(),
            rpc_url: Some(oracle_mock.uri()),
        })
        .await
        .expect("profile oracle endpoint must be accepted");
    assert_ne!(oracle_res.is_error, Some(true));
    let oracle_json: serde_json::Value =
        serde_json::from_str(call_result_text(&oracle_res)).expect("oracle JSON");
    assert_eq!(
        oracle_json.pointer("/data/latest_ledger"),
        Some(&serde_json::json!(22222))
    );

    // Hosts the profile does not configure, public RPC hosts among them,
    // refuse with invalid_params, naming the rule and never the URL or a host list.
    for rejected in [
        format!("https://untrusted.example.com/{CREDENTIAL_MARKER}"),
        "https://soroban-testnet.stellar.org".to_owned(),
        "https://mainnet.sorobanrpc.com".to_owned(),
    ] {
        let err = server
            .call_stellar_fee_stats(StellarFeeStatsArgs {
                chain_id: "stellar:testnet".to_owned(),
                rpc_url: Some(rejected.clone()),
            })
            .await
            .expect_err("unconfigured rpc_url must fail");
        assert_eq!(err.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        let msg = err.to_string();
        assert!(
            msg.contains("configured endpoint"),
            "expected configured-endpoint rule in refusal for {rejected}, got: {msg}"
        );
        assert!(
            !msg.contains("allow-list"),
            "must not name allow-list: {msg}"
        );
        assert!(
            !msg.contains("untrusted.example.com"),
            "must not echo host: {msg}"
        );
        assert!(
            !msg.contains(CREDENTIAL_MARKER),
            "must not echo URL path: {msg}"
        );
        assert!(
            !msg.contains("soroban-testnet.stellar.org"),
            "must not name a host list: {msg}"
        );
        assert!(
            !msg.contains("mainnet.sorobanrpc.com"),
            "must not name a host list: {msg}"
        );
    }
}
