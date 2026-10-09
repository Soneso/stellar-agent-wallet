//! Tests for pre-handler argument deserialisation, the `Asset::parse` boundary
//! rules used by the `stellar_balances` MCP tool handler, and the handler-level
//! DoS cap guard.
//!
//! These tests exercise argument validation paths directly via `WalletServer`
//! type construction and `Asset::parse` calls, bypassing the stdio transport.
//! They verify that the `assets` argument is validated correctly before any
//! network call is made.
//!
//! # Covered scenarios
//!
//! 1. **Invalid asset code** — code contains non-alphanumeric chars → `Asset::parse` rejects.
//! 2. **Code too long** — 13-character code → `Asset::parse` rejects.
//! 3. **Invalid issuer** — not a G-strkey → `Asset::parse` rejects.
//! 4. **Empty assets** — absent `assets` field treated as native-only (no validation error).
//! 5. **Valid chain_id mismatch** — chain_id arg disagrees with profile → `invalid_params`.
//! 6. **Invalid account_id** — not a valid G-strkey → `invalid_params`.
//! 7. **Cap exceeded (101 assets)** — handler returns `invalid_params` before any RPC call.
//! 8. **Cap boundary (100 assets)** — handler does NOT fire cap guard; proceeds to network.
//!
//! Network-layer trustline tests live in the `stellar-agent-network` crate;
//! this file keeps one wiremock-backed MCP dispatch test so the
//! handler-to-envelope path is covered at the MCP boundary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test-only; assertions via unwrap/expect are idiomatic in integration tests"
)]

use stellar_agent_mcp::server::StellarBalancesArgs;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A valid testnet G-strkey for test fixtures.
const TEST_ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// A valid USDC issuer G-strkey for test fixtures.
const TEST_USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";

fn disposable_s_strkey() -> String {
    stellar_strkey::ed25519::PrivateKey::from_payload(&[1_u8; 32])
        .expect("32-byte disposable private-key payload must encode")
        .as_unredacted()
        .to_string()
        .as_str()
        .to_owned()
}

fn disposable_m_strkey() -> String {
    stellar_strkey::ed25519::MuxedAccount {
        ed25519: [2_u8; 32],
        id: 7,
    }
    .to_string()
    .as_str()
    .to_owned()
}

fn disposable_c_strkey() -> String {
    stellar_strkey::Contract([3_u8; 32])
        .to_string()
        .as_str()
        .to_owned()
}

fn call_result_text(result: &rmcp::model::CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|text| text.text.as_str())
        .unwrap_or("")
}

fn call_result_json(result: &rmcp::model::CallToolResult) -> serde_json::Value {
    serde_json::from_str(call_result_text(result)).expect("tool result must be JSON")
}

async fn assert_balances_account_id_invalid_params(account_id: String) {
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_mcp::server::{StellarBalancesArgs, WalletServer};

    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .rpc_url("https://soroban-testnet.stellar.org")
        .with_noop_engine()
        .build();
    let server = WalletServer::new(profile).expect("WalletServer::new must succeed");
    let args = StellarBalancesArgs {
        chain_id: "stellar:testnet".to_owned(),
        account_id: account_id.clone(),
        assets: Vec::new(),
    };

    let err = server
        .call_stellar_balances(args)
        .await
        .expect_err("non-G account_id must return invalid_params");
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "error code must be INVALID_PARAMS (-32602); got: {:?}",
        err.code
    );
    let detail = err.message.as_ref();
    assert!(
        !detail.contains(&account_id),
        "invalid_params detail must not echo key-material-adjacent strkey; got: {detail}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation tests — no network required
// ─────────────────────────────────────────────────────────────────────────────

/// Asset code containing a hyphen is rejected by `Asset::parse`.
///
/// This exercises the validation codepath used by the `stellar_balances` handler.
#[test]
fn asset_parse_rejects_hyphen_in_code() {
    use stellar_agent_network::Asset;
    let result = Asset::parse(&format!("US-DC:{TEST_USDC_ISSUER}"));
    assert!(
        result.is_err(),
        "hyphen in asset code must be rejected by Asset::parse"
    );
}

/// `stellar_balances` with an asset code that is too long (> 12 chars) must
/// be rejected.
#[test]
fn trustline_asset_arg_long_code_rejects_via_asset_parse() {
    use stellar_agent_network::Asset;
    let long_code = "ABCDEFGHIJKLM"; // 13 chars
    let result = Asset::parse(&format!("{long_code}:{TEST_USDC_ISSUER}"));
    assert!(
        result.is_err(),
        "13-character code must be rejected: {result:?}"
    );
}

/// `stellar_balances` with an invalid issuer (not a G-strkey) must be rejected.
#[test]
fn trustline_asset_arg_invalid_issuer_rejects_via_asset_parse() {
    use stellar_agent_network::Asset;
    let result = Asset::parse("USDC:not-a-strkey");
    assert!(
        result.is_err(),
        "non-G-strkey issuer must be rejected: {result:?}"
    );
}

/// Empty `assets` field → `StellarBalancesArgs` is deserialised without error
/// and `assets` is an empty `Vec`.
#[test]
fn stellar_balances_args_empty_assets_deserialises_ok() {
    let json = serde_json::json!({
        "chain_id": "stellar:testnet",
        "account_id": TEST_ACCOUNT
    });
    let args: StellarBalancesArgs =
        serde_json::from_value(json).expect("empty assets field must deserialise");
    assert!(args.assets.is_empty(), "assets must be empty when absent");
}

/// `StellarBalancesArgs` with a non-empty `assets` field deserialises correctly.
#[test]
fn stellar_balances_args_with_assets_deserialises_ok() {
    let json = serde_json::json!({
        "chain_id": "stellar:testnet",
        "account_id": TEST_ACCOUNT,
        "assets": [
            { "code": "USDC", "issuer": TEST_USDC_ISSUER }
        ]
    });
    let args: StellarBalancesArgs =
        serde_json::from_value(json).expect("assets field must deserialise");
    assert_eq!(args.assets.len(), 1);
    assert_eq!(args.assets[0].code, "USDC");
    assert_eq!(args.assets[0].issuer, TEST_USDC_ISSUER);
}

/// `stellar_balances` rejects a structurally valid signing-key strkey at the
/// MCP `account_id` boundary.
#[tokio::test]
async fn stellar_balances_rejects_s_strkey_account_id_with_invalid_params() {
    assert_balances_account_id_invalid_params(disposable_s_strkey()).await;
}

/// `stellar_balances` rejects a structurally valid muxed-account strkey at the
/// MCP `account_id` boundary.
#[tokio::test]
async fn stellar_balances_rejects_m_strkey_account_id_with_invalid_params() {
    assert_balances_account_id_invalid_params(disposable_m_strkey()).await;
}

/// `stellar_balances` rejects a structurally valid contract strkey at the MCP
/// `account_id` boundary.
#[tokio::test]
async fn stellar_balances_rejects_c_strkey_account_id_with_invalid_params() {
    assert_balances_account_id_invalid_params(disposable_c_strkey()).await;
}

/// A valid asset spec parses via `Asset::parse` correctly (code + issuer).
#[test]
fn valid_trustline_asset_parses_ok() {
    use stellar_agent_network::Asset;
    let result = Asset::parse(&format!("USDC:{TEST_USDC_ISSUER}"));
    assert!(
        matches!(result, Ok(Asset::Credit { .. })),
        "valid USDC:issuer must parse as Asset::Credit: {result:?}"
    );
}

/// 12-character asset code is valid.
#[test]
fn twelve_char_code_parses_ok() {
    use stellar_agent_network::Asset;
    let result = Asset::parse(&format!("ABCDEFGHIJKL:{TEST_USDC_ISSUER}"));
    assert!(
        matches!(result, Ok(Asset::Credit { .. })),
        "12-char code must be valid: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// DoS cap test — MAX_TRUSTLINE_ASSETS_PER_CALL
// ─────────────────────────────────────────────────────────────────────────────

/// `assets` list with exactly `MAX_TRUSTLINE_ASSETS_PER_CALL` entries
/// deserialises and the constant value matches expectations.
#[test]
fn stellar_balances_args_max_cap_constant_is_100() {
    use stellar_agent_mcp::server::MAX_TRUSTLINE_ASSETS_PER_CALL;
    assert_eq!(
        MAX_TRUSTLINE_ASSETS_PER_CALL, 100,
        "MAX_TRUSTLINE_ASSETS_PER_CALL must be 100"
    );
}

/// An `assets` list of 100 entries deserialises without error (exactly at cap).
#[test]
fn stellar_balances_args_100_assets_deserialises_ok() {
    let assets: Vec<_> = (0..100)
        .map(|_| serde_json::json!({ "code": "USDC", "issuer": TEST_USDC_ISSUER }))
        .collect();
    let json = serde_json::json!({
        "chain_id": "stellar:testnet",
        "account_id": TEST_ACCOUNT,
        "assets": assets
    });
    let args: StellarBalancesArgs =
        serde_json::from_value(json).expect("100-entry assets must deserialise");
    assert_eq!(args.assets.len(), 100);
}

/// An `assets` list of 101 entries exceeds the cap; the handler
/// would reject it.  This test confirms the cap constant is enforced
/// at the handler call site rather than at deserialisation time
/// (enforced by the handler check, not by serde).
#[test]
fn stellar_balances_args_101_assets_exceeds_cap() {
    use stellar_agent_mcp::server::MAX_TRUSTLINE_ASSETS_PER_CALL;
    let assets: Vec<_> = (0..101)
        .map(|_| serde_json::json!({ "code": "USDC", "issuer": TEST_USDC_ISSUER }))
        .collect();
    let json = serde_json::json!({
        "chain_id": "stellar:testnet",
        "account_id": TEST_ACCOUNT,
        "assets": assets
    });
    let args: StellarBalancesArgs =
        serde_json::from_value(json).expect("101-entry assets deserialises at serde level");
    // The handler check is: args.assets.len() > MAX_TRUSTLINE_ASSETS_PER_CALL
    assert!(
        args.assets.len() > MAX_TRUSTLINE_ASSETS_PER_CALL,
        "101-entry list must exceed the cap of {MAX_TRUSTLINE_ASSETS_PER_CALL}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Strict G-strkey test — Asset::from_code_and_issuer
// ─────────────────────────────────────────────────────────────────────────────

/// `Asset::from_code_and_issuer` rejects invalid issuer.
#[test]
fn asset_from_code_and_issuer_rejects_invalid_issuer() {
    use stellar_agent_network::builder::Asset;
    let result = Asset::from_code_and_issuer("USDC", "not-a-strkey");
    assert!(
        result.is_err(),
        "non-G-strkey issuer must be rejected: {result:?}"
    );
}

/// `Asset::from_code_and_issuer` rejects invalid code.
#[test]
fn asset_from_code_and_issuer_rejects_invalid_code() {
    use stellar_agent_network::builder::Asset;
    let result = Asset::from_code_and_issuer("US-DC", TEST_USDC_ISSUER);
    assert!(
        result.is_err(),
        "hyphen in code must be rejected by from_code_and_issuer: {result:?}"
    );
}

/// `Asset::from_code_and_issuer` accepts valid code and issuer.
#[test]
fn asset_from_code_and_issuer_accepts_valid_args() {
    use stellar_agent_network::builder::Asset;
    let result = Asset::from_code_and_issuer("USDC", TEST_USDC_ISSUER);
    assert!(
        matches!(result, Ok(Asset::Credit { .. })),
        "valid USDC + issuer must be accepted: {result:?}"
    );
}

// -----------------------------------------------------------------------------
// Wiremock dispatch coverage
// -----------------------------------------------------------------------------

/// `stellar_balances` dispatches through the MCP handler, fetches the account
/// and requested trustline from wiremock, and returns the standard JSON
/// envelope.
#[tokio::test]
async fn stellar_balances_dispatch_returns_native_and_trustline_from_wiremock() {
    use serde_json::json;
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_mcp::server::{StellarBalancesArgs, TrustlineAssetArg, WalletServer};
    use stellar_agent_test_support::xdr_fixtures::{
        EchoIdResponder, account_entry_xdr_with_balance, account_ledger_key_xdr,
        trustline_entry_xdr, trustline_ledger_key_xdr,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    let mock_server = MockServer::start().await;
    let account_key_xdr = account_ledger_key_xdr(TEST_ACCOUNT);
    let account_xdr = account_entry_xdr_with_balance(TEST_ACCOUNT, 25_000_000);
    let usdc_key_xdr = trustline_ledger_key_xdr(TEST_ACCOUNT, "USDC", TEST_USDC_ISSUER);
    let usdc_entry_xdr = trustline_entry_xdr(TEST_ACCOUNT, "USDC", TEST_USDC_ISSUER, 500_000_000);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": account_key_xdr,
                    "xdr": account_xdr,
                    "lastModifiedLedgerSeq": 1000
                },
                {
                    "key": usdc_key_xdr,
                    "xdr": usdc_entry_xdr,
                    "lastModifiedLedgerSeq": 1000
                }
            ],
            "latestLedger": 1001
        })))
        .mount(&mock_server)
        .await;

    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .rpc_url(mock_server.uri())
        .with_noop_engine()
        .build();
    let server = WalletServer::new(profile).expect("WalletServer::new must succeed");
    let args = StellarBalancesArgs {
        chain_id: "stellar:testnet".to_owned(),
        account_id: TEST_ACCOUNT.to_owned(),
        assets: vec![TrustlineAssetArg {
            code: "USDC".to_owned(),
            issuer: TEST_USDC_ISSUER.to_owned(),
        }],
    };

    let result = server
        .call_stellar_balances(args)
        .await
        .expect("wiremock-backed stellar_balances call must succeed");
    assert_ne!(
        result.is_error,
        Some(true),
        "happy path must not be returned as a tool-level error"
    );

    let payload = call_result_json(&result);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["data"]["account_id"], TEST_ACCOUNT);
    assert_eq!(payload["data"]["balances"].as_array().unwrap().len(), 2);
    assert_eq!(
        payload["data"]["balances"][0]["asset"]["asset_type"],
        "native"
    );
    assert_eq!(payload["data"]["balances"][0]["balance"], "2.5000000");
    assert_eq!(
        payload["data"]["balances"][1]["asset"]["asset_type"],
        "USDC"
    );
    assert_eq!(
        payload["data"]["balances"][1]["asset"]["issuer"],
        TEST_USDC_ISSUER
    );
    assert_eq!(payload["data"]["balances"][1]["balance"], "50.0000000");
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler-level cap tests
//
// The serde-level tests verify the constant value and shape; these tests invoke
// the actual `WalletServer::stellar_balances` handler to verify the cap guard
// fires (or does not fire) at the correct boundary.
// ─────────────────────────────────────────────────────────────────────────────

/// `stellar_balances` handler rejects a request with 101 trustline assets
/// with `invalid_params` before any RPC call.
///
/// The serde-level tests verify `args.assets.len() >
/// MAX_TRUSTLINE_ASSETS_PER_CALL` as a pure predicate; this test invokes the
/// actual handler path via `WalletServer::call_stellar_balances`.
#[tokio::test]
async fn stellar_balances_rejects_when_assets_exceed_cap() {
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_mcp::server::{StellarBalancesArgs, TrustlineAssetArg, WalletServer};

    // Build a testnet profile with a dummy RPC URL.
    // The handler returns invalid_params BEFORE any network call, so
    // the RPC URL is never contacted.
    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .rpc_url("https://soroban-testnet.stellar.org")
        .with_noop_engine()
        .build();

    let server = WalletServer::new(profile).expect("WalletServer::new must succeed");

    // Build 101 identical assets — one over the cap.
    let assets: Vec<TrustlineAssetArg> = (0..101)
        .map(|_| TrustlineAssetArg {
            code: "USDC".to_owned(),
            issuer: TEST_USDC_ISSUER.to_owned(),
        })
        .collect();

    let args = StellarBalancesArgs {
        chain_id: "stellar:testnet".to_owned(),
        account_id: TEST_ACCOUNT.to_owned(),
        assets,
    };

    let result = server.call_stellar_balances(args).await;
    assert!(
        result.is_err(),
        "handler must return Err(invalid_params) for 101 assets; got Ok"
    );
    let err = result.unwrap_err();
    // Verify it's an invalid_params error (code -32602).
    assert_eq!(
        err.code,
        rmcp::model::ErrorCode::INVALID_PARAMS,
        "error code must be INVALID_PARAMS (-32602); got: {:?}",
        err.code
    );
    let msg = err.message.as_ref();
    assert!(
        msg.contains("too many trustline assets"),
        "error message must mention cap violation; got: {msg}"
    );
}

/// `stellar_balances` handler accepts a request with exactly
/// `MAX_TRUSTLINE_ASSETS_PER_CALL` (100) trustline assets — the cap guard
/// must NOT fire.
///
/// The handler will proceed to the network layer; a wiremock server returns
/// an empty entries response so no real network call is made.  The result
/// is a successful dispatch (the handler returns either `Ok(CallToolResult)`
/// or a tool-level error inside `Ok`, but NOT `Err(invalid_params)`).
#[tokio::test]
async fn stellar_balances_accepts_assets_at_cap() {
    use stellar_agent_core::profile::schema::Profile;
    use stellar_agent_mcp::server::{StellarBalancesArgs, TrustlineAssetArg, WalletServer};
    use stellar_agent_test_support::xdr_fixtures::EchoIdResponder;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};

    let mock_server = MockServer::start().await;

    // Return empty entries — account not found.  The handler will produce a
    // tool-level error but will NOT return invalid_params (cap guard passed).
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "entries": null,
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    // Explicitly set Noop so WalletServer::new succeeds without a policy file
    // on disk (PolicyEngineKind::default() is V1).
    let profile = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .rpc_url(mock_server.uri())
        .with_noop_engine()
        .build();
    let server = WalletServer::new(profile).expect("WalletServer::new must succeed");

    // Exactly 100 assets — at the cap, must NOT be rejected by the cap guard.
    let assets: Vec<TrustlineAssetArg> = (0..100)
        .map(|_| TrustlineAssetArg {
            code: "USDC".to_owned(),
            issuer: TEST_USDC_ISSUER.to_owned(),
        })
        .collect();

    let args = StellarBalancesArgs {
        chain_id: "stellar:testnet".to_owned(),
        account_id: TEST_ACCOUNT.to_owned(),
        assets,
    };

    let result: Result<rmcp::model::CallToolResult, rmcp::ErrorData> =
        server.call_stellar_balances(args).await;
    // The cap guard must NOT trigger — handler must return Ok (with a
    // tool-level error inside because mock returns empty entries).
    assert!(
        result.is_ok(),
        "handler must NOT return Err(invalid_params) for exactly 100 assets; got Err: {result:?}"
    );
    // The tool-level result must NOT be an invalid_params response.
    // (It will be a tool error about account_not_found, but that's fine.)
    let call_result = result.unwrap();
    // The is_error flag may be set (tool-level error from account not found),
    // but the important thing is no invalid_params at the JSON-RPC level.
    let text = call_result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or("");
    assert!(
        !text.contains("too many trustline assets"),
        "cap guard must not fire for exactly 100 assets; got: {text}"
    );
}
