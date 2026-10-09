//! Integration tests for the subentry-aware pre-flight balance checks.
//!
//! Verifies that `stellar_create_account` and `stellar_pay` correctly compute
//! available native balance using the full Stellar protocol formula:
//!
//! ```text
//! available = balance - (2 + subentry_count) * BASE_RESERVE_STROOPS
//! ```
//!
//! for `stellar_create_account`:
//!
//! ```text
//! required = starting_balance + BASE_RESERVE_STROOPS (recipient) + fee
//! ```
//!
//! for `stellar_pay` (native):
//!
//! ```text
//! required = amount + fee
//! ```
//!
//! Test matrix:
//!
//! - `subentry_count = 0`, `1`, `5`, `25`: for each, assert:
//!   - `balance = required - 1` triggers `ledger.insufficient_balance`.
//!   - `balance = required + available_floor` passes (returns envelope + nonce).
//! - `stellar_pay` non-native: trustline-missing case, trustline-balance-
//!   insufficient case, native-fee-insufficient case.
//!
//! # Mock RPC pattern
//!
//! Tests build minimal `LedgerEntryData::Account` XDR with the desired
//! `num_sub_entries` and `balance` and serve it from a `wiremock::MockServer`,
//! matching the pattern established in `pay_integration.rs`.
//!
//! # Keyring isolation
//!
//! All tests call `keyring_mock::install` and are serialised via `#[serial]`
//! because the mock keyring is process-global state.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use serial_test::serial;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_core::{BASE_RESERVE_STROOPS, DEFAULT_CLASSIC_FEE_STROOPS};
use stellar_agent_mcp::server::{StellarCreateAccountArgs, StellarPayArgs, WalletServer};
use stellar_agent_test_support::keyring_mock;
use stellar_agent_test_support::xdr_fixtures::{
    EchoIdResponder, account_entry_xdr, account_ledger_key_xdr, trustline_entry_xdr,
    trustline_ledger_key_xdr,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

const SOURCE_G: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// A valid issuer G-strkey distinct from SOURCE_G and DEST_G.
///
/// Uses the well-known testnet USDC issuer fixture key.
const USDC_ISSUER_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// The classic transaction fee in stroops — sourced from
/// `stellar_agent_core::DEFAULT_CLASSIC_FEE_STROOPS`.
#[allow(
    clippy::cast_lossless,
    reason = "u32→i64 widening; const context disallows i64::from()"
)]
const FEE_STROOPS: i64 = DEFAULT_CLASSIC_FEE_STROOPS as i64;

/// Testnet profile with `engine = Noop` and the given RPC URL for test isolation.
///
/// Explicitly sets `Noop` so `WalletServer::new` succeeds without a signed
/// policy file on disk (`PolicyEngineKind::default()` is `V1`, which requires
/// a signed policy file and a keyring owner-key entry).
fn testnet_profile_with_rpc(rpc_url: &str) -> Profile {
    let mut p = Profile::builder_testnet("svc", "acct", "n-svc", "n-acct")
        .with_noop_engine()
        .build();
    p.rpc_url = rpc_url.to_owned();
    p
}

/// Returns `(Ok(tool_result), false)` on tool-level error or `(Ok(tool_result), true)` on success.
///
/// Checks that:
/// - The tool result has `is_error = Some(true)`.
/// - The JSON body contains `code_substr`.
fn assert_tool_error(
    result: Result<rmcp::model::CallToolResult, rmcp::ErrorData>,
    code_substr: &str,
) {
    match result {
        Ok(tool_result) => {
            assert_eq!(
                tool_result.is_error,
                Some(true),
                "expected is_error=true, got is_error={:?}",
                tool_result.is_error
            );
            let json_str = tool_result
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.as_str())
                .unwrap_or("");
            assert!(
                json_str.contains(code_substr),
                "response must contain '{code_substr}', got: {json_str}"
            );
        }
        Err(err) => {
            panic!("expected Ok(is_error=true), got Err: {err}");
        }
    }
}

/// Checks that a tool result is a success (no `is_error=true`) and contains
/// `envelope_xdr` and `nonce`.
fn assert_tool_success(result: Result<rmcp::model::CallToolResult, rmcp::ErrorData>) {
    match result {
        Ok(tool_result) => {
            assert_ne!(
                tool_result.is_error,
                Some(true),
                "expected success, got is_error=true; content: {:?}",
                tool_result.content
            );
            let json_str = tool_result
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.as_str())
                .unwrap_or("");
            assert!(
                json_str.contains("envelope_xdr"),
                "success response must contain envelope_xdr, got: {json_str}"
            );
            assert!(
                json_str.contains("nonce"),
                "success response must contain nonce, got: {json_str}"
            );
        }
        Err(err) => {
            panic!("expected Ok(success), got Err: {err}");
        }
    }
}

fn success_json(result: Result<rmcp::model::CallToolResult, rmcp::ErrorData>) -> serde_json::Value {
    match result {
        Ok(tool_result) => {
            assert_ne!(
                tool_result.is_error,
                Some(true),
                "expected success, got is_error=true; content: {:?}",
                tool_result.content
            );
            let json_str = tool_result
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.as_str())
                .unwrap_or("");
            serde_json::from_str(json_str).expect("tool response must be valid JSON")
        }
        Err(err) => {
            panic!("expected Ok(success), got Err: {err}");
        }
    }
}

fn tx_fee_from_envelope_xdr(envelope_xdr: &str) -> u32 {
    use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};

    match TransactionEnvelope::from_xdr_base64(envelope_xdr, Limits::none())
        .expect("envelope_xdr must decode")
    {
        TransactionEnvelope::Tx(tx) => tx.tx.fee,
        _ => panic!("expected v1 transaction envelope"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// create_account pre-flight — subentry-count matrix
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the minimum balance to pass the create_account pre-flight for a
/// given `subentry_count`.
///
/// ```text
/// available = balance - (2 + subentry_count) * BASE_RESERVE_STROOPS
/// required  = starting_balance + BASE_RESERVE_STROOPS + fee
/// passes when available >= required
/// i.e. balance >= required + (2 + subentry_count) * BASE_RESERVE_STROOPS
/// ```
fn create_account_min_balance(subentry_count: u32, starting_balance: i64, fee: i64) -> i64 {
    let source_reserves = (i64::from(subentry_count) + 2).saturating_mul(BASE_RESERVE_STROOPS);
    let required = starting_balance
        .saturating_add(BASE_RESERVE_STROOPS)
        .saturating_add(fee);
    required.saturating_add(source_reserves)
}

async fn run_create_account_preflight(
    mock_server: &MockServer,
    subentry_count: u32,
    balance_stroops: i64,
) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    use base64::Engine;
    use keyring_core::Entry;

    keyring_mock::install().expect("mock keyring store init");

    // Provide a nonce key so NonceMint::from_profile works.
    let nonce_key_bytes = [0u8; 32];
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_key_bytes);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let account_xdr = account_entry_xdr(SOURCE_G, balance_stroops, subentry_count);
    let key_xdr = account_ledger_key_xdr(SOURCE_G);

    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": account_xdr,
                    "lastModifiedLedgerSeq": 1000
                }
            ],
            "latestLedger": 1001
        })))
        .mount(mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    server
        .call_stellar_create_account(StellarCreateAccountArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE_G.to_owned(),
            destination: DEST_G.to_owned(),
            // 1 XLM starting balance = 10_000_000 stroops.
            starting_balance: serde_json::from_str(r#""1 XLM""#).unwrap(),
            classic_base: None,
        })
        .await
}

/// subentry_count=0: balance = required - 1 triggers insufficient_balance.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry0_insufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(0, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 0, min_balance - 1).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// subentry_count=0: balance = exact minimum passes.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry0_sufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(0, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 0, min_balance).await;
    assert_tool_success(result);
}

/// subentry_count=1: balance = required - 1 triggers insufficient_balance.
///
/// Minimum increases by BASE_RESERVE_STROOPS compared to subentry_count=0
/// because the source account needs an extra reserve unit for its 1 subentry.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry1_insufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(1, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 1, min_balance - 1).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// subentry_count=1: balance = exact minimum passes.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry1_sufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(1, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 1, min_balance).await;
    assert_tool_success(result);
}

/// subentry_count=5: balance = required - 1 triggers insufficient_balance.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry5_insufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(5, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 5, min_balance - 1).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// subentry_count=5: balance = exact minimum passes.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry5_sufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(5, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 5, min_balance).await;
    assert_tool_success(result);
}

/// subentry_count=25: balance = required - 1 triggers insufficient_balance.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry25_insufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(25, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 25, min_balance - 1).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// subentry_count=25: balance = exact minimum passes.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry25_sufficient() {
    let mock_server = MockServer::start().await;
    let fee = FEE_STROOPS;
    let starting_balance = 10_000_000_i64;
    let min_balance = create_account_min_balance(25, starting_balance, fee);
    let result = run_create_account_preflight(&mock_server, 25, min_balance).await;
    assert_tool_success(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_pay non-native pre-flight
// ─────────────────────────────────────────────────────────────────────────────

/// Helper: returns mock result JSON for a single getLedgerEntries call with
/// account + trustline entries.
fn mock_result_with_trustline(
    account_xdr: &str,
    account_key: &str,
    trustline_xdr: &str,
    trustline_key: &str,
) -> serde_json::Value {
    serde_json::json!({
        "entries": [
            { "key": account_key, "xdr": account_xdr, "lastModifiedLedgerSeq": 1000 },
            { "key": trustline_key, "xdr": trustline_xdr, "lastModifiedLedgerSeq": 1000 }
        ],
        "latestLedger": 1001
    })
}

fn mock_result_account_only(account_xdr: &str, account_key: &str) -> serde_json::Value {
    serde_json::json!({
        "entries": [
            { "key": account_key, "xdr": account_xdr, "lastModifiedLedgerSeq": 1000 }
        ],
        "latestLedger": 1001
    })
}

fn make_non_native_pay_args(amount_xlm_str: &str) -> StellarPayArgs {
    StellarPayArgs {
        chain_id: "stellar:testnet".to_owned(),
        source: SOURCE_G.to_owned(),
        destination: DEST_G.to_owned(),
        amount: Some(serde_json::from_str(amount_xlm_str).unwrap()),
        amount_in_stroops: None,
        asset: format!("USDC:{USDC_ISSUER_G}"),
        memo_text: None,
        memo_id: None,
        memo_hash_hex: None,
        memo_return_hex: None,
        classic_base: None,
    }
}

/// Non-native payment: no trustline → ledger.trustline_missing.
///
/// The mock returns the account entry but omits the trustline entry (simulating
/// the case where the source account has no trustline for USDC).
#[tokio::test]
#[serial]
async fn pay_nonnative_preflight_trustline_missing() {
    use base64::Engine;
    use keyring_core::Entry;

    keyring_mock::install().expect("mock keyring store init");
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;

    // Source has ample XLM (20 XLM = 200_000_000 stroops, 0 subentries).
    let account_xdr = account_entry_xdr(SOURCE_G, 200_000_000, 0);
    let account_key = account_ledger_key_xdr(SOURCE_G);

    // Mock returns ONLY the account entry — no trustline.
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(mock_result_account_only(
            &account_xdr,
            &account_key,
        )))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let result = server
        .call_stellar_pay(make_non_native_pay_args(r#""10 XLM""#))
        .await;
    assert_tool_error(result, "ledger.trustline_missing");
}

/// Non-native payment: trustline balance insufficient → ledger.insufficient_balance
/// with asset = USDC.
#[tokio::test]
#[serial]
async fn pay_nonnative_preflight_trustline_balance_insufficient() {
    use base64::Engine;
    use keyring_core::Entry;

    keyring_mock::install().expect("mock keyring store init");
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;

    // Source has ample XLM (20 XLM, 0 subentries) but USDC trustline has only
    // 5_000_000 stroops (0.5 USDC), while payment requests 10 XLM worth.
    let account_xdr = account_entry_xdr(SOURCE_G, 200_000_000, 0);
    let account_key = account_ledger_key_xdr(SOURCE_G);
    // Trustline balance: 5_000_000 (below the 10_000_000 requested as "10 XLM").
    let tl_xdr = trustline_entry_xdr(SOURCE_G, "USDC", USDC_ISSUER_G, 5_000_000);
    let tl_key = trustline_ledger_key_xdr(SOURCE_G, "USDC", USDC_ISSUER_G);

    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(mock_result_with_trustline(
            &account_xdr,
            &account_key,
            &tl_xdr,
            &tl_key,
        )))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let result = server
        .call_stellar_pay(make_non_native_pay_args(r#""10 XLM""#))
        .await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// Non-native payment: XLM fee insufficient (not enough XLM after reserves to
/// pay the fee), trustline balance OK → ledger.insufficient_balance with
/// asset = XLM (fee error wins, surfaced first).
#[tokio::test]
#[serial]
async fn pay_nonnative_preflight_xlm_fee_insufficient() {
    use base64::Engine;
    use keyring_core::Entry;

    keyring_mock::install().expect("mock keyring store init");
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;

    // Source has barely enough XLM to cover reserves but NOT the fee.
    // 0 subentries → reserves = 2 * 5_000_000 = 10_000_000.
    // fee = 100 stroops (DEFAULT_CLASSIC_FEE_STROOPS).
    // Set balance = 10_000_000 (exactly covers reserves, 0 available for fee).
    let account_xdr = account_entry_xdr(SOURCE_G, 10_000_000, 0);
    let account_key = account_ledger_key_xdr(SOURCE_G);
    // Trustline has ample USDC (100_000_000 stroops).
    let tl_xdr = trustline_entry_xdr(SOURCE_G, "USDC", USDC_ISSUER_G, 100_000_000);
    let tl_key = trustline_ledger_key_xdr(SOURCE_G, "USDC", USDC_ISSUER_G);

    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(mock_result_with_trustline(
            &account_xdr,
            &account_key,
            &tl_xdr,
            &tl_key,
        )))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    // Request a small amount to ensure trustline balance check would pass.
    let result = server
        .call_stellar_pay(make_non_native_pay_args(r#""0.0000001 XLM""#))
        .await;
    // The XLM fee check must fire first, surfacing as XLM insufficient_balance.
    assert_tool_error(result, "ledger.insufficient_balance");
}

// ─────────────────────────────────────────────────────────────────────────────
// u32::MAX subentry_count → saturating path produces InsufficientBalance
// ─────────────────────────────────────────────────────────────────────────────

/// Asserts that `subentry_count = u32::MAX` produces `ledger.insufficient_balance`
/// rather than `internal_error`.  `saturating_sub` saturates to `available = 0`
/// for wildly under-reserved accounts, triggering the normal InsufficientBalance
/// path.
#[tokio::test]
#[serial]
async fn create_account_preflight_subentry_u32_max_returns_insufficient_balance() {
    let mock_server = MockServer::start().await;
    // balance = 1 stroop; reserves for u32::MAX subentries are astronomically
    // higher, so saturating_sub(reserves) = 0 < required.
    let result = run_create_account_preflight(&mock_server, u32::MAX, 1).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

// ─────────────────────────────────────────────────────────────────────────────
// stellar_pay native — subentry matrix (mirrors create_account matrix)
// ─────────────────────────────────────────────────────────────────────────────

/// Computes the minimum balance to pass the stellar_pay native pre-flight for a
/// given `subentry_count`.
///
/// ```text
/// available = balance - (2 + subentry_count) * BASE_RESERVE_STROOPS
/// required  = amount + fee
/// passes when available >= required
/// i.e. balance >= required + (2 + subentry_count) * BASE_RESERVE_STROOPS
/// ```
fn pay_native_min_balance(subentry_count: u32, amount: i64, fee: i64) -> i64 {
    let source_reserves = (i64::from(subentry_count) + 2).saturating_mul(BASE_RESERVE_STROOPS);
    let required = amount.saturating_add(fee);
    required.saturating_add(source_reserves)
}

async fn run_pay_native_preflight(
    mock_server: &MockServer,
    subentry_count: u32,
    balance_stroops: i64,
    amount_xlm_str: &str,
) -> Result<rmcp::model::CallToolResult, rmcp::ErrorData> {
    use base64::Engine;
    use keyring_core::Entry;

    keyring_mock::install().expect("mock keyring store init");
    let nonce_key_bytes = [10u8; 32];
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_key_bytes);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let account_xdr = account_entry_xdr(SOURCE_G, balance_stroops, subentry_count);
    let key_xdr = account_ledger_key_xdr(SOURCE_G);

    // First call: getLedgerEntries for the source account (pre-flight balance check).
    // Limited to one response so the SEP-29 check picks up the second mock.
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": account_xdr,
                    "lastModifiedLedgerSeq": 1000
                }
            ],
            "latestLedger": 1001
        })))
        .up_to_n_times(1)
        .mount(mock_server)
        .await;

    // Second call: getLedgerEntries for the SEP-29 config.memo_required data entry.
    // Empty entries = no memo required; allows the happy path to proceed.
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "entries": [],
            "latestLedger": 1001
        })))
        .mount(mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    server
        .call_stellar_pay(StellarPayArgs {
            chain_id: "stellar:testnet".to_owned(),
            source: SOURCE_G.to_owned(),
            destination: DEST_G.to_owned(),
            amount: Some(serde_json::from_str(amount_xlm_str).unwrap()),
            amount_in_stroops: None,
            asset: "native".to_owned(),
            memo_text: None,
            memo_id: None,
            memo_hash_hex: None,
            memo_return_hex: None,
            classic_base: None,
        })
        .await
}

async fn run_pay_native_preflight_with_profile_fee(
    fee_per_op_stroops: Option<u32>,
) -> serde_json::Value {
    use base64::Engine;
    use keyring_core::Entry;

    keyring_mock::install().expect("mock keyring store init");
    let nonce_key_bytes = [12u8; 32];
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_key_bytes);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;
    let account_xdr = account_entry_xdr(SOURCE_G, 100_000_000, 0);
    let key_xdr = account_ledger_key_xdr(SOURCE_G);

    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": account_xdr,
                    "lastModifiedLedgerSeq": 1000
                }
            ],
            "latestLedger": 1001
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "entries": [],
            "latestLedger": 1001
        })))
        .mount(&mock_server)
        .await;

    let mut profile = testnet_profile_with_rpc(&mock_server.uri());
    profile.classic_fee_per_op_stroops = fee_per_op_stroops;
    let server = WalletServer::new(profile).expect("WalletServer::new");

    success_json(
        server
            .call_stellar_pay(StellarPayArgs {
                chain_id: "stellar:testnet".to_owned(),
                source: SOURCE_G.to_owned(),
                destination: DEST_G.to_owned(),
                amount: Some(serde_json::from_str(r#""1 XLM""#).unwrap()),
                amount_in_stroops: None,
                asset: "native".to_owned(),
                memo_text: None,
                memo_id: None,
                memo_hash_hex: None,
                memo_return_hex: None,
                classic_base: None,
            })
            .await,
    )
}

/// Profile fee override is interpreted as a per-operation classic base fee.
#[tokio::test]
#[serial]
async fn pay_native_profile_fee_override_sets_envelope_total_fee() {
    let response = run_pay_native_preflight_with_profile_fee(Some(250)).await;
    let data = response
        .get("data")
        .expect("success envelope must contain data");
    let envelope_xdr = data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("data.envelope_xdr must be present");
    assert_eq!(tx_fee_from_envelope_xdr(envelope_xdr), 250);
    assert_eq!(data["simulation"]["fee_stroops"], "250");
}

/// Missing profile fee override falls back to the protocol minimum per-op fee.
#[tokio::test]
#[serial]
async fn pay_native_profile_fee_none_uses_default_envelope_total_fee() {
    let response = run_pay_native_preflight_with_profile_fee(None).await;
    let data = response
        .get("data")
        .expect("success envelope must contain data");
    let envelope_xdr = data
        .get("envelope_xdr")
        .and_then(serde_json::Value::as_str)
        .expect("data.envelope_xdr must be present");
    assert_eq!(
        tx_fee_from_envelope_xdr(envelope_xdr),
        DEFAULT_CLASSIC_FEE_STROOPS
    );
    assert_eq!(
        data["simulation"]["fee_stroops"],
        DEFAULT_CLASSIC_FEE_STROOPS.to_string()
    );
}

/// pay native subentry_count=0: balance = required - 1 → insufficient_balance.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry0_insufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(0, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 0, min_balance - 1, r#""1 XLM""#).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// pay native subentry_count=0: exact minimum passes.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry0_sufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(0, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 0, min_balance, r#""1 XLM""#).await;
    assert_tool_success(result);
}

/// pay native subentry_count=1: balance = required - 1 → insufficient_balance.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry1_insufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(1, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 1, min_balance - 1, r#""1 XLM""#).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// pay native subentry_count=1: exact minimum passes.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry1_sufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(1, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 1, min_balance, r#""1 XLM""#).await;
    assert_tool_success(result);
}

/// pay native subentry_count=5: balance = required - 1 → insufficient_balance.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry5_insufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(5, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 5, min_balance - 1, r#""1 XLM""#).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// pay native subentry_count=5: exact minimum passes.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry5_sufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(5, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 5, min_balance, r#""1 XLM""#).await;
    assert_tool_success(result);
}

/// pay native subentry_count=25: balance = required - 1 → insufficient_balance.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry25_insufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(25, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 25, min_balance - 1, r#""1 XLM""#).await;
    assert_tool_error(result, "ledger.insufficient_balance");
}

/// pay native subentry_count=25: exact minimum passes.
#[tokio::test]
#[serial]
async fn pay_native_preflight_subentry25_sufficient() {
    let mock_server = MockServer::start().await;
    let amount = 10_000_000_i64;
    let min_balance = pay_native_min_balance(25, amount, FEE_STROOPS);
    let result = run_pay_native_preflight(&mock_server, 25, min_balance, r#""1 XLM""#).await;
    assert_tool_success(result);
}

// ─────────────────────────────────────────────────────────────────────────────
// non-native pay pre-flight positive case
// ─────────────────────────────────────────────────────────────────────────────

/// Non-native payment: trustline balance sufficient and XLM fee affordable →
/// pre-flight succeeds (returns envelope_xdr + nonce).
#[tokio::test]
#[serial]
async fn pay_nonnative_preflight_succeeds_when_trustline_balance_sufficient_and_xlm_fee_affordable()
{
    use base64::Engine;
    use keyring_core::Entry;

    keyring_mock::install().expect("mock keyring store init");
    let nonce_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([3u8; 32]);
    Entry::new("n-svc", "n-acct")
        .expect("Entry::new")
        .set_password(&nonce_key_b64)
        .expect("set_password");

    let mock_server = MockServer::start().await;

    // Source has 20 XLM (200_000_000 stroops, 0 subentries); fee is 100 stroops.
    // Trustline has 50_000_000 stroops (enough for the 10_000_000 requested).
    let account_xdr = account_entry_xdr(SOURCE_G, 200_000_000, 0);
    let account_key = account_ledger_key_xdr(SOURCE_G);
    let tl_xdr = trustline_entry_xdr(SOURCE_G, "USDC", USDC_ISSUER_G, 50_000_000);
    let tl_key = trustline_ledger_key_xdr(SOURCE_G, "USDC", USDC_ISSUER_G);

    // First call: getLedgerEntries for account + trustline (pre-flight balance check).
    // Limited to one response so the SEP-29 check picks up the second mock.
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(mock_result_with_trustline(
            &account_xdr,
            &account_key,
            &tl_xdr,
            &tl_key,
        )))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second call: getLedgerEntries for the SEP-29 config.memo_required data entry.
    // Empty entries = no memo required; allows the happy path to proceed.
    Mock::given(method("POST"))
        .respond_with(EchoIdResponder::new(serde_json::json!({
            "entries": [],
            "latestLedger": 1001
        })))
        .mount(&mock_server)
        .await;

    let profile = testnet_profile_with_rpc(&mock_server.uri());
    let server = WalletServer::new(profile).expect("WalletServer::new");

    let result = server
        .call_stellar_pay(make_non_native_pay_args(r#""1 XLM""#))
        .await;
    assert_tool_success(result);
}
