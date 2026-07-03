//! Integration tests for the Stellar RPC `getFeeStats` wrapper.

use std::error::Error;

use stellar_agent_core::error::NetworkError;
use stellar_agent_network::{StellarRpcClient, fetch_fee_stats};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

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

fn fee_stats_result(p95: &str) -> serde_json::Value {
    serde_json::json!({
        "sorobanInclusionFee": fee_stat_json("300"),
        "inclusionFee": fee_stat_json(p95),
        "latestLedger": "12345"
    })
}

#[tokio::test]
async fn get_fee_stats_happy_path_returns_view() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(fee_stats_result("200")))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri())?;
    let view = fetch_fee_stats(&client).await?;

    assert_eq!(view.latest_ledger, 12345);
    assert_eq!(view.inclusion_fee.p95, 200);
    assert_eq!(view.soroban_inclusion_fee.p95, 300);
    assert_eq!(view.inclusion_fee.transaction_count, 12);
    assert_eq!(view.inclusion_fee.ledger_count, 5);
    Ok(())
}

#[tokio::test]
async fn get_fee_stats_http_500_returns_network_error() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri())?;
    let err = match fetch_fee_stats(&client).await {
        Ok(view) => return Err(format!("expected error, got {view:?}").into()),
        Err(err) => err,
    };

    assert!(
        matches!(err, NetworkError::RpcUnreachable { .. }),
        "expected RpcUnreachable, got {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn get_fee_stats_malformed_fee_string_returns_parse_error() -> Result<(), Box<dyn Error>> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(fee_stats_result("not-a-fee")))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri())?;
    let err = match fetch_fee_stats(&client).await {
        Ok(view) => return Err(format!("expected error, got {view:?}").into()),
        Err(err) => err,
    };

    assert!(
        matches!(err, NetworkError::RpcResponseMalformed { .. }),
        "expected RpcResponseMalformed, got {err:?}"
    );
    Ok(())
}
