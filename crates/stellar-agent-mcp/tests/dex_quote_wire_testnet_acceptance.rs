//! Testnet acceptance: the `stellar_dex_quote` MCP tool wire carries i128
//! amounts as decimal strings without precision loss above `2^53`.
//!
//! Drives the real `stellar_dex_quote` `#[tool]` handler (not the
//! `stellar-agent-dex` library API — the existing `dex_swap_testnet_acceptance.rs`
//! suite in that crate never touches the MCP tool wire) with JSON string args,
//! including a `qty_in` above `2^53`, and asserts the response's `qty_in`,
//! `expected_out`, and `amounts` fields are JSON strings, with `qty_in`
//! round-tripping exactly.
//!
//! `stellar_dex_quote` is read-only: no signing, no Friendbot funding, only a
//! public RPC call to the live testnet Soroswap router.
//!
//! Gated behind the `testnet-acceptance` feature flag:
//!
//! ```text
//! cargo test -p stellar-agent-mcp --features testnet-acceptance \
//!   --test dex_quote_wire_testnet_acceptance
//! ```

#![cfg(feature = "testnet-acceptance")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics, unwraps, and eprintln are acceptable in testnet acceptance tests"
)]

use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_mcp::server::{DexQuoteArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_CHAIN_ID: &str = "stellar:testnet";

/// Known-answer XLM SAC on testnet.
///
/// Verified at `stellar-agent-dex/src/sac.rs` KAT test; also listed in
/// `soroswap-core/public/tokens.json` (testnet `XLM`).
const XLM_SAC_TESTNET: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// USDC on testnet (Soroswap-listed token with an XLM/USDC pool).
///
/// Source: `soroswap-core/public/tokens.json` (testnet `USDC`).
const USDC_TESTNET: &str = "CB3TLW74NBIOT3BUWOZ3TUM6RFDF6A4GVIRUQRQZABG5KPOUL4JJOV2F";

/// The first integer an `f64`-backed JSON number cannot represent exactly:
/// `2^53 + 1`. Sent as a JSON STRING to prove the wire boundary preserves it.
const QTY_IN_ABOVE_2_POW_53: &str = "9007199254740993";

// ─────────────────────────────────────────────────────────────────────────────
// Test
// ─────────────────────────────────────────────────────────────────────────────

/// **Acceptance** — `stellar_dex_quote` accepts a decimal-string `qty_in`
/// above `2^53`, and its JSON response echoes `qty_in`, `expected_out`, and
/// `amounts` as JSON strings (not JSON numbers), with `qty_in` round-tripping
/// exactly.
///
/// `router_get_amounts_out` is a pure read-only computation over the pool's
/// stored reserves (no balance transfer, no signing); the magnitude of
/// `qty_in` does not require the caller to hold or move any real balance.
#[tokio::test]
#[serial]
#[ignore = "live testnet acceptance; run in the testnet-acceptance CI job via -- --ignored"]
async fn dex_quote_wire_round_trips_qty_in_above_2_pow_53() {
    keyring_mock::install().expect("mock keyring store init");

    // builder_testnet's derived-name arg only needs to be stable and unique;
    // this tool is read-only and never touches the signer/nonce keyring.
    let profile = Profile::builder_testnet(
        "stellar-agent",
        "dex-quote-wire-acceptance",
        "stellar-agent-nonce",
        "dex-quote-wire-acceptance",
    )
    .with_noop_engine()
    .build();

    let server = WalletServer::new(profile).expect("WalletServer::new");

    // JSON constructed as literal text so qty_in is parsed by serde as a
    // string from the start — proving the value never passes through an
    // f64-backed JSON number at any point in the request path.
    let request_json = serde_json::json!({
        "chain_id": TESTNET_CHAIN_ID,
        "qty_in": QTY_IN_ABOVE_2_POW_53,
        "path": [XLM_SAC_TESTNET, USDC_TESTNET],
    });
    let args: DexQuoteArgs =
        serde_json::from_value(request_json).expect("DexQuoteArgs must deserialise from JSON");
    assert_eq!(
        args.qty_in, QTY_IN_ABOVE_2_POW_53,
        "qty_in must survive JSON deserialisation as the exact decimal string"
    );

    let result = server
        .call_stellar_dex_quote(args)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Acceptance FAIL — stellar_dex_quote must succeed for a live testnet \
                 XLM->USDC path (hard failure; testnet-acceptance requires live \
                 connectivity): {e:?}"
            )
        });

    let text = result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .expect("tool result must carry text content");
    let response: serde_json::Value =
        serde_json::from_str(text).expect("tool result text must be valid JSON");

    assert_eq!(
        response["status"].as_str(),
        Some("ok"),
        "Acceptance FAIL — quote must succeed: {response}"
    );

    // ── qty_in: JSON string, exact round-trip ─────────────────────────────
    assert!(
        response["qty_in"].is_string(),
        "qty_in must serialise as a JSON string, not a JSON number: {response}"
    );
    assert_eq!(
        response["qty_in"].as_str().expect("string"),
        QTY_IN_ABOVE_2_POW_53,
        "qty_in must round-trip EXACTLY through the wire above 2^53: {response}"
    );

    // ── expected_out: JSON string ──────────────────────────────────────────
    assert!(
        response["expected_out"].is_string(),
        "expected_out must serialise as a JSON string, not a JSON number: {response}"
    );
    let expected_out: i128 = response["expected_out"]
        .as_str()
        .expect("string")
        .parse()
        .expect("expected_out must parse as a decimal i128");
    assert!(
        expected_out > 0,
        "Acceptance FAIL — on-chain expected_out must be positive: {response}"
    );

    // ── amounts: JSON array of strings ─────────────────────────────────────
    let amounts = response["amounts"]
        .as_array()
        .expect("amounts must be a JSON array");
    assert!(!amounts.is_empty(), "amounts must be non-empty: {response}");
    for element in amounts {
        assert!(
            element.is_string(),
            "every amounts element must serialise as a JSON string: {response}"
        );
    }
    // amounts.last() is the expected output for the swap (QuoteResult
    // convention); it must match expected_out exactly.
    let last_amount: i128 = amounts
        .last()
        .and_then(serde_json::Value::as_str)
        .expect("string")
        .parse()
        .expect("amounts.last() must parse as a decimal i128");
    assert_eq!(
        last_amount, expected_out,
        "amounts.last() must equal expected_out: {response}"
    );

    eprintln!(
        "Acceptance PASS — qty_in={QTY_IN_ABOVE_2_POW_53} round-tripped exactly; \
         expected_out={expected_out}"
    );
}
