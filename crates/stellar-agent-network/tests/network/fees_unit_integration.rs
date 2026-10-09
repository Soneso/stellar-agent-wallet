//! Tests for `stellar_agent_network::fees` — percentile selection, classic-fee
//! choice parsing, classic-fee resolution (with mock RPC), RPC URL validation,
//! and `FeeStatsView`/`FeeDistribution` field mapping.
//!
//! Mock-RPC tests use `wiremock` + `EchoIdResponder`, mirroring the pattern in
//! `fee_stats_integration.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use serde_json::json;
use stellar_agent_core::error::{ValidationError, WalletError};
use stellar_agent_network::{
    ClassicFeeChoice, FeeDistribution, FeePercentile, FeeStatsView, RpcUrlError, StellarRpcClient,
    fetch_fee_stats, parse_classic_fee_choice, resolve_classic_fee_selection, validate_rpc_url,
};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fee-stats JSON fixture helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a canonical `FeeStat` JSON object where every percentile field is
/// unique so tests can confirm the correct field is read.
///
/// Field values are chosen to be small, distinct, and easily recognisable in
/// assertion failure messages.
#[allow(
    clippy::too_many_arguments,
    reason = "test fixture mirrors the RPC fee-stats field set"
)]
fn fee_stat_json(
    max: u64,
    min: u64,
    mode: u64,
    p10: u64,
    p20: u64,
    p30: u64,
    p40: u64,
    p50: u64,
    p60: u64,
    p70: u64,
    p80: u64,
    p90: u64,
    p95: u64,
    p99: u64,
    tx_count: u32,
    ledger_count: u32,
) -> serde_json::Value {
    json!({
        "max": max.to_string(),
        "min": min.to_string(),
        "mode": mode.to_string(),
        "p10": p10.to_string(),
        "p20": p20.to_string(),
        "p30": p30.to_string(),
        "p40": p40.to_string(),
        "p50": p50.to_string(),
        "p60": p60.to_string(),
        "p70": p70.to_string(),
        "p80": p80.to_string(),
        "p90": p90.to_string(),
        "p95": p95.to_string(),
        "p99": p99.to_string(),
        "transactionCount": tx_count.to_string(),
        "ledgerCount": ledger_count.to_string(),
    })
}

/// Builds a `getFeeStats` result envelope suitable for `EchoIdResponder`.
///
/// The inclusion fee and soroban inclusion fee use distinct value sets so tests
/// can verify that `FeeStatsView` maps each field to the correct sub-struct.
fn fee_stats_result_full() -> serde_json::Value {
    // Inclusion-fee fields: every value = 100*field-position for easy lookup.
    let inclusion = fee_stat_json(
        1000, // max
        100,  // min
        110,  // mode
        120,  // p10
        130,  // p20
        140,  // p30
        150,  // p40
        160,  // p50
        170,  // p60
        180,  // p70
        190,  // p80
        200,  // p90
        210,  // p95
        220,  // p99
        42,   // transactionCount
        7,    // ledgerCount
    );
    // Soroban-inclusion-fee: offset by 500 to be distinct from the classic set.
    let soroban = fee_stat_json(
        5000, // max
        500,  // min
        510,  // mode
        520,  // p10
        530,  // p20
        540,  // p30
        550,  // p40
        560,  // p50
        570,  // p60
        580,  // p70
        590,  // p80
        600,  // p90
        610,  // p95
        620,  // p99
        10,   // transactionCount
        3,    // ledgerCount
    );
    json!({
        "inclusionFee": inclusion,
        "sorobanInclusionFee": soroban,
        "latestLedger": "99999"
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// FeePercentile::label — all 11 variants
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn fee_percentile_label_p10() {
    assert_eq!(FeePercentile::P10.label(), "p10");
}

#[test]
fn fee_percentile_label_p20() {
    assert_eq!(FeePercentile::P20.label(), "p20");
}

#[test]
fn fee_percentile_label_p30() {
    assert_eq!(FeePercentile::P30.label(), "p30");
}

#[test]
fn fee_percentile_label_p40() {
    assert_eq!(FeePercentile::P40.label(), "p40");
}

#[test]
fn fee_percentile_label_p50() {
    assert_eq!(FeePercentile::P50.label(), "p50");
}

#[test]
fn fee_percentile_label_p60() {
    assert_eq!(FeePercentile::P60.label(), "p60");
}

#[test]
fn fee_percentile_label_p70() {
    assert_eq!(FeePercentile::P70.label(), "p70");
}

#[test]
fn fee_percentile_label_p80() {
    assert_eq!(FeePercentile::P80.label(), "p80");
}

#[test]
fn fee_percentile_label_p90() {
    assert_eq!(FeePercentile::P90.label(), "p90");
}

#[test]
fn fee_percentile_label_p95() {
    assert_eq!(FeePercentile::P95.label(), "p95");
}

#[test]
fn fee_percentile_label_p99() {
    assert_eq!(FeePercentile::P99.label(), "p99");
}

// ─────────────────────────────────────────────────────────────────────────────
// FeePercentile::select — verifies each variant reads the correct struct field
// ─────────────────────────────────────────────────────────────────────────────

fn distinct_distribution() -> FeeDistribution {
    FeeDistribution {
        max: 1000,
        min: 100,
        mode: 110,
        p10: 120,
        p20: 130,
        p30: 140,
        p40: 150,
        p50: 160,
        p60: 170,
        p70: 180,
        p80: 190,
        p90: 200,
        p95: 210,
        p99: 220,
        transaction_count: 42,
        ledger_count: 7,
    }
}

#[test]
fn fee_percentile_select_p10_reads_p10_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P10.select(&d), 120);
}

#[test]
fn fee_percentile_select_p20_reads_p20_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P20.select(&d), 130);
}

#[test]
fn fee_percentile_select_p30_reads_p30_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P30.select(&d), 140);
}

#[test]
fn fee_percentile_select_p40_reads_p40_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P40.select(&d), 150);
}

#[test]
fn fee_percentile_select_p50_reads_p50_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P50.select(&d), 160);
}

#[test]
fn fee_percentile_select_p60_reads_p60_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P60.select(&d), 170);
}

#[test]
fn fee_percentile_select_p70_reads_p70_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P70.select(&d), 180);
}

#[test]
fn fee_percentile_select_p80_reads_p80_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P80.select(&d), 190);
}

#[test]
fn fee_percentile_select_p90_reads_p90_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P90.select(&d), 200);
}

#[test]
fn fee_percentile_select_p95_reads_p95_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P95.select(&d), 210);
}

#[test]
fn fee_percentile_select_p99_reads_p99_field() {
    let d = distinct_distribution();
    assert_eq!(FeePercentile::P99.select(&d), 220);
}

// ─────────────────────────────────────────────────────────────────────────────
// parse_classic_fee_choice
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn parse_fee_choice_none_returns_profile_default() {
    let choice = parse_classic_fee_choice(None).unwrap();
    assert_eq!(choice, ClassicFeeChoice::ProfileDefault);
}

#[test]
fn parse_fee_choice_auto_returns_auto_p95() {
    // Bare "auto" defaults to P95.
    let choice = parse_classic_fee_choice(Some("auto")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P95));
}

#[test]
fn parse_fee_choice_auto_with_leading_space_returns_auto_p95() {
    // Whitespace is trimmed before parsing.
    let choice = parse_classic_fee_choice(Some("  auto  ")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P95));
}

#[test]
fn parse_fee_choice_explicit_integer() {
    let choice = parse_classic_fee_choice(Some("1000")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Explicit(1000));
}

#[test]
fn parse_fee_choice_explicit_zero() {
    let choice = parse_classic_fee_choice(Some("0")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Explicit(0));
}

#[test]
fn parse_fee_choice_explicit_u32_max() {
    let choice = parse_classic_fee_choice(Some("4294967295")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Explicit(u32::MAX));
}

#[test]
fn parse_fee_choice_explicit_integer_with_spaces() {
    let choice = parse_classic_fee_choice(Some("  500  ")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Explicit(500));
}

#[test]
fn parse_fee_choice_auto_colon_p10() {
    let choice = parse_classic_fee_choice(Some("auto:p10")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P10));
}

#[test]
fn parse_fee_choice_auto_colon_p20() {
    let choice = parse_classic_fee_choice(Some("auto:p20")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P20));
}

#[test]
fn parse_fee_choice_auto_colon_p30() {
    let choice = parse_classic_fee_choice(Some("auto:p30")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P30));
}

#[test]
fn parse_fee_choice_auto_colon_p40() {
    let choice = parse_classic_fee_choice(Some("auto:p40")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P40));
}

#[test]
fn parse_fee_choice_auto_colon_p50() {
    let choice = parse_classic_fee_choice(Some("auto:p50")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P50));
}

#[test]
fn parse_fee_choice_auto_colon_p60() {
    let choice = parse_classic_fee_choice(Some("auto:p60")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P60));
}

#[test]
fn parse_fee_choice_auto_colon_p70() {
    let choice = parse_classic_fee_choice(Some("auto:p70")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P70));
}

#[test]
fn parse_fee_choice_auto_colon_p80() {
    let choice = parse_classic_fee_choice(Some("auto:p80")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P80));
}

#[test]
fn parse_fee_choice_auto_colon_p90() {
    let choice = parse_classic_fee_choice(Some("auto:p90")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P90));
}

#[test]
fn parse_fee_choice_auto_colon_p95() {
    let choice = parse_classic_fee_choice(Some("auto:p95")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P95));
}

#[test]
fn parse_fee_choice_auto_colon_p99() {
    let choice = parse_classic_fee_choice(Some("auto:p99")).unwrap();
    assert_eq!(choice, ClassicFeeChoice::Auto(FeePercentile::P99));
}

#[test]
fn parse_fee_choice_invalid_text_returns_amount_malformed() {
    let err = parse_classic_fee_choice(Some("garbage")).unwrap_err();
    assert_eq!(
        err.code(),
        "validation.amount_malformed",
        "non-numeric, non-auto text must yield AmountMalformed; got: {err:?}"
    );
    assert!(
        matches!(
            err,
            WalletError::Validation(ValidationError::AmountMalformed { ref input })
                if input == "garbage"
        ),
        "AmountMalformed input must echo the rejected string; got: {err:?}"
    );
}

#[test]
fn parse_fee_choice_float_text_returns_amount_malformed() {
    let err = parse_classic_fee_choice(Some("100.5")).unwrap_err();
    assert_eq!(err.code(), "validation.amount_malformed");
}

#[test]
fn parse_fee_choice_negative_number_returns_amount_malformed() {
    // "-1" does not parse as u32.
    let err = parse_classic_fee_choice(Some("-1")).unwrap_err();
    assert_eq!(err.code(), "validation.amount_malformed");
}

#[test]
fn parse_fee_choice_u32_overflow_returns_amount_malformed() {
    // u32::MAX + 1 must not silently wrap.
    let err = parse_classic_fee_choice(Some("4294967296")).unwrap_err();
    assert_eq!(err.code(), "validation.amount_malformed");
}

#[test]
fn parse_fee_choice_auto_unknown_percentile_returns_amount_malformed() {
    // "auto:p101" is not a recognised percentile label.
    let err = parse_classic_fee_choice(Some("auto:p101")).unwrap_err();
    assert_eq!(err.code(), "validation.amount_malformed");
    // The rejected input string must include the full "auto:p101" form.
    assert!(
        matches!(
            err,
            WalletError::Validation(ValidationError::AmountMalformed { ref input })
                if input.contains("auto:p101")
        ),
        "AmountMalformed input must reference the rejected label; got: {err:?}"
    );
}

#[test]
fn parse_fee_choice_auto_empty_percentile_returns_amount_malformed() {
    // "auto:" with no suffix is not valid.
    let err = parse_classic_fee_choice(Some("auto:")).unwrap_err();
    assert_eq!(err.code(), "validation.amount_malformed");
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_classic_fee_selection — synchronous variants (no RPC)
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: build a mock RPC client that will never be called. Used for
/// ProfileDefault/Explicit tests that must NOT hit the network.
async fn no_call_client() -> (StellarRpcClient, MockServer) {
    let server = MockServer::start().await;
    // No mocks registered — any HTTP call would return 404.
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    (client, server)
}

#[tokio::test]
async fn resolve_profile_default_returns_default_fee_without_rpc() {
    let (client, server) = no_call_client().await;

    let selection = resolve_classic_fee_selection(&client, 150, ClassicFeeChoice::ProfileDefault)
        .await
        .unwrap();

    assert_eq!(selection.per_op_stroops, 150);
    assert_eq!(selection.selected_fee_percentile, "profile_default");
    // No RPC calls must be made for ProfileDefault.
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "ProfileDefault must not touch the RPC server"
    );
}

#[tokio::test]
async fn resolve_explicit_returns_explicit_fee_without_rpc() {
    let (client, server) = no_call_client().await;

    let selection = resolve_classic_fee_selection(&client, 150, ClassicFeeChoice::Explicit(5000))
        .await
        .unwrap();

    assert_eq!(selection.per_op_stroops, 5000);
    assert_eq!(selection.selected_fee_percentile, "explicit");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "Explicit must not touch the RPC server"
    );
}

#[tokio::test]
async fn resolve_explicit_zero_stroops() {
    let (client, _server) = no_call_client().await;
    let selection = resolve_classic_fee_selection(&client, 100, ClassicFeeChoice::Explicit(0))
        .await
        .unwrap();
    assert_eq!(selection.per_op_stroops, 0);
    assert_eq!(selection.selected_fee_percentile, "explicit");
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_classic_fee_selection — Auto variants (require mock RPC)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that `Auto(P50)` fetches fee stats and uses `inclusion_fee.p50`.
#[tokio::test]
async fn resolve_auto_p50_fetches_inclusion_fee_p50() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(fee_stats_result_full()))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let selection =
        resolve_classic_fee_selection(&client, 100, ClassicFeeChoice::Auto(FeePercentile::P50))
            .await
            .unwrap();

    // inclusion_fee.p50 = 160 in fee_stats_result_full()
    assert_eq!(selection.per_op_stroops, 160);
    assert_eq!(selection.selected_fee_percentile, "p50");
}

/// Verifies that `Auto(P95)` fetches fee stats and uses `inclusion_fee.p95`.
#[tokio::test]
async fn resolve_auto_p95_fetches_inclusion_fee_p95() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(fee_stats_result_full()))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let selection =
        resolve_classic_fee_selection(&client, 100, ClassicFeeChoice::Auto(FeePercentile::P95))
            .await
            .unwrap();

    // inclusion_fee.p95 = 210 in fee_stats_result_full()
    assert_eq!(selection.per_op_stroops, 210);
    assert_eq!(selection.selected_fee_percentile, "p95");
}

/// Verifies that `Auto(P99)` uses `inclusion_fee.p99` (not the soroban field).
#[tokio::test]
async fn resolve_auto_p99_uses_inclusion_fee_not_soroban() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(fee_stats_result_full()))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let selection =
        resolve_classic_fee_selection(&client, 100, ClassicFeeChoice::Auto(FeePercentile::P99))
            .await
            .unwrap();

    // inclusion_fee.p99 = 220 in fee_stats_result_full(); soroban p99 = 620 — must not be used.
    assert_eq!(
        selection.per_op_stroops, 220,
        "Auto must use inclusion_fee, not soroban_inclusion_fee"
    );
    assert_eq!(selection.selected_fee_percentile, "p99");
}

/// Verifies that a fee value exceeding u32::MAX causes `AmountOutOfRange`.
#[tokio::test]
async fn resolve_auto_fee_exceeds_u32_max_returns_amount_out_of_range() {
    let server = MockServer::start().await;
    // p95 value is u64::MAX — well above u32::MAX.
    let oversized_result = json!({
        "inclusionFee": {
            "max": "18446744073709551615",
            "min": "100",
            "mode": "100",
            "p10": "100", "p20": "100", "p30": "100", "p40": "100",
            "p50": "100", "p60": "100", "p70": "100", "p80": "100",
            "p90": "100",
            "p95": "18446744073709551615",
            "p99": "100",
            "transactionCount": "1",
            "ledgerCount": "1"
        },
        "sorobanInclusionFee": {
            "max": "100", "min": "100", "mode": "100",
            "p10": "100", "p20": "100", "p30": "100", "p40": "100",
            "p50": "100", "p60": "100", "p70": "100", "p80": "100",
            "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "1", "ledgerCount": "1"
        },
        "latestLedger": "1000"
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(oversized_result))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err =
        resolve_classic_fee_selection(&client, 100, ClassicFeeChoice::Auto(FeePercentile::P95))
            .await
            .unwrap_err();

    assert_eq!(
        err.code(),
        "validation.amount_out_of_range",
        "fee value exceeding u32::MAX must return AmountOutOfRange; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// FeeStatsView::from_rpc — field mapping verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that all `FeeDistribution` fields are mapped from the correct
/// JSON positions and that the `latest_ledger` is mapped correctly.
#[tokio::test]
async fn fee_stats_view_all_fields_mapped_correctly() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(fee_stats_result_full()))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let view = fetch_fee_stats(&client).await.unwrap();

    assert_eq!(view.latest_ledger, 99999);

    // inclusion_fee
    let inc = &view.inclusion_fee;
    assert_eq!(inc.max, 1000);
    assert_eq!(inc.min, 100);
    assert_eq!(inc.mode, 110);
    assert_eq!(inc.p10, 120);
    assert_eq!(inc.p20, 130);
    assert_eq!(inc.p30, 140);
    assert_eq!(inc.p40, 150);
    assert_eq!(inc.p50, 160);
    assert_eq!(inc.p60, 170);
    assert_eq!(inc.p70, 180);
    assert_eq!(inc.p80, 190);
    assert_eq!(inc.p90, 200);
    assert_eq!(inc.p95, 210);
    assert_eq!(inc.p99, 220);
    assert_eq!(inc.transaction_count, 42);
    assert_eq!(inc.ledger_count, 7);

    // soroban_inclusion_fee
    let sob = &view.soroban_inclusion_fee;
    assert_eq!(sob.max, 5000);
    assert_eq!(sob.min, 500);
    assert_eq!(sob.mode, 510);
    assert_eq!(sob.p10, 520);
    assert_eq!(sob.p20, 530);
    assert_eq!(sob.p30, 540);
    assert_eq!(sob.p40, 550);
    assert_eq!(sob.p50, 560);
    assert_eq!(sob.p60, 570);
    assert_eq!(sob.p70, 580);
    assert_eq!(sob.p80, 590);
    assert_eq!(sob.p90, 600);
    assert_eq!(sob.p95, 610);
    assert_eq!(sob.p99, 620);
    assert_eq!(sob.transaction_count, 10);
    assert_eq!(sob.ledger_count, 3);
}

/// Verifies that a malformed fee field in the **soroban** distribution
/// returns `RpcResponseMalformed` (not a panic or silently wrong value).
#[tokio::test]
async fn fee_stats_view_malformed_soroban_fee_returns_malformed_error() {
    let server = MockServer::start().await;
    let bad_result = json!({
        "inclusionFee": {
            "max": "1000", "min": "100", "mode": "100",
            "p10": "100", "p20": "100", "p30": "100", "p40": "100",
            "p50": "100", "p60": "100", "p70": "100", "p80": "100",
            "p90": "100", "p95": "200", "p99": "250",
            "transactionCount": "5", "ledgerCount": "2"
        },
        "sorobanInclusionFee": {
            // "max" contains a non-numeric string — must cause a parse error.
            "max": "NOT_A_NUMBER",
            "min": "100", "mode": "100",
            "p10": "100", "p20": "100", "p30": "100", "p40": "100",
            "p50": "100", "p60": "100", "p70": "100", "p80": "100",
            "p90": "100", "p95": "100", "p99": "100",
            "transactionCount": "1", "ledgerCount": "1"
        },
        "latestLedger": "12345"
    });

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(bad_result))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err = fetch_fee_stats(&client).await.unwrap_err();

    assert!(
        matches!(
            err,
            stellar_agent_core::error::NetworkError::RpcResponseMalformed { ref method, .. }
                if method == "getFeeStats"
        ),
        "malformed soroban fee field must yield RpcResponseMalformed; got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_rpc_url — allow-listed production hosts
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_rpc_url_testnet_https_allowed() {
    assert!(
        validate_rpc_url("https://soroban-testnet.stellar.org").is_ok(),
        "testnet RPC URL must be allowed"
    );
}

#[test]
fn validate_rpc_url_mainnet_sorobanrpc_allowed() {
    assert!(
        validate_rpc_url("https://mainnet.sorobanrpc.com").is_ok(),
        "mainnet sorobanrpc.com must be allowed"
    );
}

#[test]
fn validate_rpc_url_mainnet_stellar_org_allowed() {
    assert!(
        validate_rpc_url("https://soroban-mainnet.stellar.org").is_ok(),
        "mainnet stellar.org RPC URL must be allowed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_rpc_url — error cases
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn validate_rpc_url_garbage_string_returns_invalid_url() {
    let err = validate_rpc_url("not a url at all %%").unwrap_err();
    assert!(
        matches!(err, RpcUrlError::InvalidUrl(_)),
        "unparseable string must yield InvalidUrl; got: {err:?}"
    );
}

#[test]
fn validate_rpc_url_empty_string_returns_invalid_url() {
    let err = validate_rpc_url("").unwrap_err();
    assert!(
        matches!(err, RpcUrlError::InvalidUrl(_)),
        "empty string must yield InvalidUrl; got: {err:?}"
    );
}

#[test]
fn validate_rpc_url_http_scheme_not_allowed() {
    // HTTP is never permitted for production RPC hosts.
    let err = validate_rpc_url("http://soroban-testnet.stellar.org").unwrap_err();
    assert!(
        matches!(err, RpcUrlError::NonHttps(_)),
        "http:// scheme must yield NonHttps; got: {err:?}"
    );
}

#[test]
fn validate_rpc_url_non_listed_https_host_returns_host_not_allowed() {
    let err = validate_rpc_url("https://example.com/rpc").unwrap_err();
    match err {
        RpcUrlError::HostNotAllowed {
            ref host,
            ref allowed,
        } => {
            assert_eq!(host, "example.com");
            // The allowed string must contain all three production hosts.
            assert!(
                allowed.contains("soroban-testnet.stellar.org"),
                "allowed list must mention testnet; got: {allowed}"
            );
        }
        other => panic!("expected HostNotAllowed, got: {other:?}"),
    }
}

#[test]
fn validate_rpc_url_credentials_in_url_returns_credentials_error() {
    // Credentials embedded in the URL must be rejected before any host check.
    let err = validate_rpc_url("https://user:secret@soroban-testnet.stellar.org").unwrap_err();
    assert!(
        matches!(err, RpcUrlError::CredentialsInUrl),
        "URL with credentials must yield CredentialsInUrl; got: {err:?}"
    );
}

#[test]
fn validate_rpc_url_username_only_credentials_returns_credentials_error() {
    // Username without password is still a credential.
    let err = validate_rpc_url("https://user@soroban-testnet.stellar.org").unwrap_err();
    assert!(
        matches!(err, RpcUrlError::CredentialsInUrl),
        "URL with username-only credentials must yield CredentialsInUrl; got: {err:?}"
    );
}

#[test]
fn validate_rpc_url_loopback_http_is_rejected_by_production_validator() {
    // The production validator rejects loopback addresses (no allow_loopback).
    // 127.0.0.1 is checked for loopback bypass AFTER the HTTPS check in the
    // inner function, so it hits NonHttps.
    let err = validate_rpc_url("http://127.0.0.1:8000").unwrap_err();
    assert!(
        matches!(err, RpcUrlError::NonHttps(_)),
        "http://loopback must yield NonHttps from production validator; got: {err:?}"
    );
}

#[test]
fn validate_rpc_url_loopback_https_is_rejected_as_not_allow_listed() {
    // Even with HTTPS, loopback is not in the production allow-list.
    let err = validate_rpc_url("https://127.0.0.1:8000").unwrap_err();
    assert!(
        matches!(err, RpcUrlError::HostNotAllowed { .. }),
        "https://127.0.0.1 must yield HostNotAllowed (not in production list); got: {err:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_rpc_url_allowing_loopback — loopback bypass (test-loopback feature)
// ─────────────────────────────────────────────────────────────────────────────

// Integration test binaries are separate compilation units; cfg(test) is not
// set for them. The `validate_rpc_url_allowing_loopback` symbol is only present
// when the `test-loopback` feature is enabled. The coverage run uses
// --all-features, so these tests are included under coverage.
#[cfg(feature = "test-loopback")]
mod loopback_tests {
    use stellar_agent_network::validate_rpc_url_allowing_loopback;

    #[test]
    fn loopback_http_127_0_0_1_allowed() {
        assert!(
            validate_rpc_url_allowing_loopback("http://127.0.0.1:8000").is_ok(),
            "loopback validator must allow http://127.0.0.1"
        );
    }

    #[test]
    fn loopback_http_localhost_allowed() {
        assert!(
            validate_rpc_url_allowing_loopback("http://localhost:9000").is_ok(),
            "loopback validator must allow http://localhost"
        );
    }

    #[test]
    fn loopback_ipv6_allowed() {
        assert!(
            validate_rpc_url_allowing_loopback("http://[::1]:8000").is_ok(),
            "loopback validator must allow http://[::1]"
        );
    }

    #[test]
    fn loopback_validator_still_rejects_non_allow_listed_external_https() {
        let err = validate_rpc_url_allowing_loopback("https://example.com").unwrap_err();
        assert!(
            matches!(
                err,
                stellar_agent_network::RpcUrlError::HostNotAllowed { .. }
            ),
            "loopback validator must still reject unlisted external hosts; got: {err:?}"
        );
    }

    #[test]
    fn loopback_validator_still_allows_production_hosts() {
        assert!(
            validate_rpc_url_allowing_loopback("https://soroban-testnet.stellar.org").is_ok(),
            "loopback validator must still accept allow-listed production hosts"
        );
    }

    #[test]
    fn loopback_validator_rejects_credentials_even_on_loopback() {
        let err =
            validate_rpc_url_allowing_loopback("http://user:pass@127.0.0.1:8000").unwrap_err();
        assert!(
            matches!(err, stellar_agent_network::RpcUrlError::CredentialsInUrl),
            "loopback validator must reject credentialed loopback URLs; got: {err:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RpcUrlError Display coverage
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rpc_url_error_invalid_url_display_contains_url_text() {
    let err = validate_rpc_url("%%bad").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid RPC URL"),
        "InvalidUrl display must contain 'invalid RPC URL'; got: {msg}"
    );
}

#[test]
fn rpc_url_error_non_https_display_contains_url() {
    let err = validate_rpc_url("http://soroban-testnet.stellar.org").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("non-HTTPS"),
        "NonHttps display must mention 'non-HTTPS'; got: {msg}"
    );
    assert!(
        msg.contains("soroban-testnet.stellar.org"),
        "NonHttps display must include the rejected URL; got: {msg}"
    );
}

#[test]
fn rpc_url_error_credentials_display_mentions_credentials() {
    let err = validate_rpc_url("https://user:secret@soroban-testnet.stellar.org").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("credentials"),
        "CredentialsInUrl display must mention 'credentials'; got: {msg}"
    );
}

#[test]
fn rpc_url_error_host_not_allowed_display_contains_host_and_allowed_list() {
    let err = validate_rpc_url("https://rogue.example.com").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("rogue.example.com"),
        "HostNotAllowed display must contain the rejected host; got: {msg}"
    );
    assert!(
        msg.contains("soroban-testnet.stellar.org"),
        "HostNotAllowed display must contain the allowed list; got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ALLOWED_RPC_HOSTS constant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn allowed_rpc_hosts_contains_exactly_three_expected_entries() {
    use stellar_agent_network::ALLOWED_RPC_HOSTS;

    assert_eq!(
        ALLOWED_RPC_HOSTS.len(),
        3,
        "ALLOWED_RPC_HOSTS must contain exactly 3 entries"
    );
    assert!(
        ALLOWED_RPC_HOSTS.contains(&"soroban-testnet.stellar.org"),
        "ALLOWED_RPC_HOSTS must include the Stellar testnet RPC host"
    );
    assert!(
        ALLOWED_RPC_HOSTS.contains(&"mainnet.sorobanrpc.com"),
        "ALLOWED_RPC_HOSTS must include mainnet.sorobanrpc.com"
    );
    assert!(
        ALLOWED_RPC_HOSTS.contains(&"soroban-mainnet.stellar.org"),
        "ALLOWED_RPC_HOSTS must include soroban-mainnet.stellar.org"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// ClassicFeeSelection serde round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn classic_fee_selection_serde_round_trip() {
    use stellar_agent_network::ClassicFeeSelection;

    let original = ClassicFeeSelection {
        per_op_stroops: 12345,
        selected_fee_percentile: "p95".to_owned(),
    };
    let json = serde_json::to_string(&original).unwrap();
    let restored: ClassicFeeSelection = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.per_op_stroops, 12345);
    assert_eq!(restored.selected_fee_percentile, "p95");
}

// ─────────────────────────────────────────────────────────────────────────────
// FeeStatsView serde round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn fee_stats_view_serde_round_trip() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(fee_stats_result_full()))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let view = fetch_fee_stats(&client).await.unwrap();

    let json = serde_json::to_string(&view).unwrap();
    let restored: FeeStatsView = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.latest_ledger, view.latest_ledger);
    assert_eq!(restored.inclusion_fee.p95, view.inclusion_fee.p95);
    assert_eq!(
        restored.soroban_inclusion_fee.p99,
        view.soroban_inclusion_fee.p99
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// resolve_classic_fee_selection — Auto with RPC error
// ─────────────────────────────────────────────────────────────────────────────

/// When the RPC server returns an HTTP 500, `Auto` selection propagates
/// the network error instead of silently falling back to the default fee.
#[tokio::test]
async fn resolve_auto_propagates_rpc_error_on_http_500() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let err =
        resolve_classic_fee_selection(&client, 100, ClassicFeeChoice::Auto(FeePercentile::P50))
            .await
            .unwrap_err();

    assert_eq!(
        err.category(),
        stellar_agent_core::error::ErrorCategory::Network,
        "RPC 500 during Auto resolution must yield a Network error; got: {err:?}"
    );
}
