//! Integration tests for `fetch_account` using a wiremock HTTP server.
//!
//! Tests use `wiremock` to mock the Stellar RPC endpoint, providing CI-
//! deterministic coverage of both the happy path (account found) and the
//! `AccountNotFound` error path without live network access.
//!
//! # Coverage
//!
//! - Against an unfunded account → `network.account_not_found` error code.
//! - Against a funded account → `AccountView` with a native XLM balance.
//!
//! # Live testnet tests
//!
//! See `tests/balances_live.rs` for `#[ignore]`-gated live testnet tests that
//! run against `https://soroban-testnet.stellar.org`. Those tests are excluded
//! from CI; invoke manually with `cargo test -- --ignored`.
//!
//! # Implementation note: jsonrpsee request-ID echoing
//!
//! `stellar-rpc-client` uses `jsonrpsee-http-client` which sends JSON-RPC 2.0
//! requests with incrementing numeric IDs and validates that the response `id`
//! matches the request `id`. We use a custom `Respond` implementation
//! (`EchoIdResponder`) that reads the incoming JSON body, extracts the request
//! `id`, and injects it into the canned response before returning it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; assertions via unwrap/expect/panic are idiomatic in integration tests"
)]

use serde_json::json;
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_network::{Asset, StellarRpcClient, fetch_account};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A real XDR-base64 `LedgerEntryData::Account` blob for a funded testnet
/// account. Sourced from the `rs-soroban-client` test suite for address
/// `GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI`.
const FUNDED_ACCOUNT_XDR: &str = "AAAAAAAAAABzdv3ojkzWHMD7KUoXhrPx0GH18vHKV0ZfqpMiEblG1gAAAFwVZH3YAAABdgAAAQgAAAAFAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAADAAAAAAAOZYQAAAAAaJsIJQ==";

/// The test account address matching `FUNDED_ACCOUNT_XDR`.
const FUNDED_ADDRESS: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// A valid G-strkey that is almost certainly unfunded on testnet.
/// Derived from key bytes [0xfe, 0x00, ..., 0x00] — a valid public key
/// but not associated with any real account.
const UNFUNDED_ADDRESS: &str = "GD7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2HQ";

/// Builds the XDR-base64 `LedgerKey::Account` for an address.
fn account_ledger_key_xdr(address: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyAccount, Limits, PublicKey, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(address)
        .expect("valid address")
        .0;
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
    });
    key.to_xdr_base64(Limits::none()).expect("valid XDR")
}

/// Builds the XDR-base64 `LedgerKey::Trustline` for an account + asset.
fn trustline_ledger_key_xdr(
    account_address: &str,
    asset_code: &str,
    issuer_address: &str,
) -> String {
    use stellar_xdr::{
        AccountId, AlphaNum4, AssetCode4, LedgerKey, LedgerKeyTrustLine, Limits, PublicKey,
        TrustLineAsset, Uint256, WriteXdr,
    };
    let account_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_address)
        .expect("valid account address")
        .0;
    let issuer_bytes = stellar_strkey::ed25519::PublicKey::from_string(issuer_address)
        .expect("valid issuer address")
        .0;

    let mut code_arr = [0u8; 4];
    let code_b = asset_code.as_bytes();
    code_arr[..code_b.len().min(4)].copy_from_slice(&code_b[..code_b.len().min(4)]);

    let key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_bytes))),
        asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code_arr),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes))),
        }),
    });
    key.to_xdr_base64(Limits::none()).expect("valid XDR")
}

/// Builds a minimal XDR-base64 `LedgerEntryData::Trustline` for a given balance.
///
/// The Stellar RPC `getLedgerEntries` returns `LedgerEntryResult { key, xdr }` where
/// `xdr` is the `LedgerEntryData` XDR — NOT a full `LedgerEntry`.  This helper
/// constructs only the `LedgerEntryData` portion, matching what the RPC returns.
fn trustline_entry_xdr(
    account_address: &str,
    asset_code: &str,
    issuer_address: &str,
    balance_stroops: i64,
    limit_stroops: i64,
) -> String {
    use stellar_xdr::{
        AccountId, AlphaNum4, AssetCode4, LedgerEntryData, Limits, PublicKey, TrustLineAsset,
        TrustLineEntry, TrustLineEntryExt, Uint256, WriteXdr,
    };
    let account_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_address)
        .expect("valid account address")
        .0;
    let issuer_bytes = stellar_strkey::ed25519::PublicKey::from_string(issuer_address)
        .expect("valid issuer address")
        .0;

    let mut code_arr = [0u8; 4];
    let code_b = asset_code.as_bytes();
    code_arr[..code_b.len().min(4)].copy_from_slice(&code_b[..code_b.len().min(4)]);

    let tl = TrustLineEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(account_bytes))),
        asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(code_arr),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes))),
        }),
        balance: balance_stroops,
        limit: limit_stroops,
        flags: 1, // AUTHORIZED
        ext: TrustLineEntryExt::V0,
    };

    LedgerEntryData::Trustline(tl)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR")
}

// ─────────────────────────────────────────────────────────────────────────────
// Happy path: funded account
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_account_returns_native_balance_for_funded_account() {
    let mock_server = MockServer::start().await;
    let key_xdr = account_ledger_key_xdr(FUNDED_ADDRESS);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": FUNDED_ACCOUNT_XDR,
                    "lastModifiedLedgerSeq": 2552504
                }
            ],
            "latestLedger": 2552990
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");

    let account = fetch_account(&client, FUNDED_ADDRESS, &[])
        .await
        .expect("fetch_account must succeed for a funded account");

    // Funded account returns balances including native XLM.
    assert_eq!(account.account_id, FUNDED_ADDRESS);
    assert!(
        !account.balances.is_empty(),
        "balances must not be empty for a funded account"
    );
    let native = &account.balances[0];
    assert_eq!(
        native.asset.asset_type, "native",
        "first balance must be native XLM"
    );
    assert!(
        !native.balance.is_empty(),
        "native balance string must not be empty"
    );
    assert!(
        native.balance.contains('.'),
        "native balance must be in decimal form, got: {}",
        native.balance
    );
    assert!(
        account.sequence_number > 0,
        "sequence number must be > 0 for a funded account"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Unfunded account → AccountNotFound
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_account_returns_account_not_found_for_unfunded_account() {
    let mock_server = MockServer::start().await;

    // RPC returns `"entries": null` when the account does not exist.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": null,
            "latestLedger": 2552990
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");

    let result = fetch_account(&client, UNFUNDED_ADDRESS, &[]).await;

    // Unfunded account must return AccountNotFound with the correct error code.
    assert!(
        result.is_err(),
        "fetch_account must fail for an unfunded account"
    );

    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "network.account_not_found",
        "error code must be network.account_not_found; got: {}",
        err.code()
    );

    assert!(
        matches!(
            &err,
            WalletError::Network(NetworkError::AccountNotFound { account_id })
                if account_id == UNFUNDED_ADDRESS
        ),
        "expected AccountNotFound with correct account_id"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC unreachable → mapped to WalletError
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn fetch_account_returns_rpc_error_when_server_unreachable() {
    // Bind to a port and immediately drop so the port is closed.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local_addr").port()
    };
    let unreachable_url = format!("http://127.0.0.1:{port}");

    let client =
        StellarRpcClient::new(&unreachable_url).expect("URL parses even if port is closed");

    let result = fetch_account(&client, FUNDED_ADDRESS, &[]).await;

    assert!(
        result.is_err(),
        "fetch_account must fail when the RPC endpoint is unreachable"
    );

    assert_eq!(
        result.unwrap_err().category(),
        stellar_agent_core::error::ErrorCategory::Network,
        "error must be in the Network category"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Trustline enumeration: present trustline included, absent trustline omitted
// ─────────────────────────────────────────────────────────────────────────────

/// A plausible USDC issuer address for test fixtures.
const TEST_USDC_ISSUER: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
/// A plausible EURC issuer address for test fixtures.  The same address as
/// `FUNDED_ADDRESS` is reused because the issuer address only needs to be a
/// syntactically valid G-strkey for the ledger-key XDR construction; it does
/// not need to be a real issuer in these wiremock tests.
const TEST_EURC_ISSUER: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// Tests the core trustline-enumeration contract:
/// - RPC response includes the account entry + one trustline entry (USDC trusted).
/// - A second trustline key (EURC) was requested but is absent from the response.
/// - `balances` must contain native XLM + USDC; EURC must be absent.
///
/// All keys are fetched in a single `getLedgerEntries` call (the mock responds
/// to any POST with the canned two-entry response).
#[tokio::test]
async fn fetch_account_with_trustlines_present_included_absent_omitted() {
    let mock_server = MockServer::start().await;

    let acct_key_xdr = account_ledger_key_xdr(FUNDED_ADDRESS);
    let usdc_key_xdr = trustline_ledger_key_xdr(FUNDED_ADDRESS, "USDC", TEST_USDC_ISSUER);
    // USDC trustline: 50 XLM worth = 500_000_000 stroops; limit = 1000 XLM = 10_000_000_000.
    let usdc_entry_xdr = trustline_entry_xdr(
        FUNDED_ADDRESS,
        "USDC",
        TEST_USDC_ISSUER,
        500_000_000,
        10_000_000_000,
    );

    // The response contains only the account entry and the USDC trustline.
    // The EURC key was "requested" (we build the key) but the RPC does not return it —
    // simulating an absent trustline.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": acct_key_xdr,
                    "xdr": FUNDED_ACCOUNT_XDR,
                    "lastModifiedLedgerSeq": 2552504
                },
                {
                    "key": usdc_key_xdr,
                    "xdr": usdc_entry_xdr,
                    "lastModifiedLedgerSeq": 2552600
                }
            ],
            "latestLedger": 2552990
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");

    let usdc_asset = Asset::parse(&format!("USDC:{TEST_USDC_ISSUER}")).expect("valid asset");
    let eurc_asset = Asset::parse(&format!("EURC:{TEST_EURC_ISSUER}")).expect("valid asset");

    let account = fetch_account(&client, FUNDED_ADDRESS, &[usdc_asset, eurc_asset])
        .await
        .expect("fetch_account must succeed");

    // Should have native + USDC (2 entries).
    assert_eq!(
        account.balances.len(),
        2,
        "expected native + USDC; EURC must be absent: got {:?}",
        account.balances
    );

    let native = &account.balances[0];
    assert_eq!(
        native.asset.asset_type, "native",
        "first entry must be native"
    );
    assert!(native.limit.is_none(), "native must have no limit");

    let usdc = &account.balances[1];
    assert_eq!(usdc.asset.asset_type, "USDC", "second entry must be USDC");
    assert_eq!(
        usdc.asset.issuer.as_deref(),
        Some(TEST_USDC_ISSUER),
        "USDC issuer must match"
    );
    assert_eq!(
        usdc.balance, "50.0000000",
        "USDC balance must be 50.0000000"
    );
    assert_eq!(
        usdc.limit.as_deref(),
        Some("1000.0000000"),
        "USDC limit must be 1000.0000000"
    );

    // EURC must be absent.
    let eurc_present = account
        .balances
        .iter()
        .any(|b| b.asset.asset_type == "EURC");
    assert!(!eurc_present, "EURC must be absent from balances");
}

/// Tests that a native-only request (empty trustline slice) still returns the
/// native XLM balance only.
#[tokio::test]
async fn fetch_account_empty_trustline_slice_returns_native_only() {
    let mock_server = MockServer::start().await;
    let acct_key_xdr = account_ledger_key_xdr(FUNDED_ADDRESS);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": acct_key_xdr,
                    "xdr": FUNDED_ACCOUNT_XDR,
                    "lastModifiedLedgerSeq": 2552504
                }
            ],
            "latestLedger": 2552990
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");

    let account = fetch_account(&client, FUNDED_ADDRESS, &[])
        .await
        .expect("fetch_account must succeed");

    assert_eq!(
        account.balances.len(),
        1,
        "empty trustline slice → native only"
    );
    assert_eq!(account.balances[0].asset.asset_type, "native");
}

// ─────────────────────────────────────────────────────────────────────────────
// Request-order guarantee: balances[1..] in trustline_assets order
// ─────────────────────────────────────────────────────────────────────────────

/// Tests that trustline balances are returned in request order regardless of
/// the order entries appear in the RPC response.
///
/// The request passes `[USDC, EURC]`. The RPC response returns EURC first,
/// then USDC (reverse order). The implementation must still produce
/// `balances[1] = USDC`, `balances[2] = EURC`.
#[tokio::test]
async fn fetch_account_trustlines_in_request_order_despite_response_order() {
    let mock_server = MockServer::start().await;

    let acct_key_xdr = account_ledger_key_xdr(FUNDED_ADDRESS);
    let usdc_key_xdr = trustline_ledger_key_xdr(FUNDED_ADDRESS, "USDC", TEST_USDC_ISSUER);
    let eurc_key_xdr = trustline_ledger_key_xdr(FUNDED_ADDRESS, "EURC", TEST_EURC_ISSUER);
    let usdc_entry_xdr = trustline_entry_xdr(
        FUNDED_ADDRESS,
        "USDC",
        TEST_USDC_ISSUER,
        500_000_000,
        10_000_000_000,
    );
    let eurc_entry_xdr = trustline_entry_xdr(
        FUNDED_ADDRESS,
        "EURC",
        TEST_EURC_ISSUER,
        100_000_000,
        5_000_000_000,
    );

    // Response returns EURC first, then USDC (reverse of request order).
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": acct_key_xdr,
                    "xdr": FUNDED_ACCOUNT_XDR,
                    "lastModifiedLedgerSeq": 2552504
                },
                {
                    "key": eurc_key_xdr,
                    "xdr": eurc_entry_xdr,
                    "lastModifiedLedgerSeq": 2552600
                },
                {
                    "key": usdc_key_xdr,
                    "xdr": usdc_entry_xdr,
                    "lastModifiedLedgerSeq": 2552601
                }
            ],
            "latestLedger": 2552990
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");

    let usdc_asset = Asset::parse(&format!("USDC:{TEST_USDC_ISSUER}")).expect("valid USDC");
    let eurc_asset = Asset::parse(&format!("EURC:{TEST_EURC_ISSUER}")).expect("valid EURC");

    // Request order: [USDC, EURC]
    let account = fetch_account(&client, FUNDED_ADDRESS, &[usdc_asset, eurc_asset])
        .await
        .expect("fetch_account must succeed");

    assert_eq!(
        account.balances.len(),
        3,
        "expected native + USDC + EURC: got {:?}",
        account.balances
    );

    // Verify REQUEST ORDER: balances[1] must be USDC (first in request),
    // balances[2] must be EURC (second in request).
    assert_eq!(
        account.balances[1].asset.asset_type, "USDC",
        "balances[1] must be USDC (first in request order)"
    );
    assert_eq!(
        account.balances[2].asset.asset_type, "EURC",
        "balances[2] must be EURC (second in request order)"
    );
}
