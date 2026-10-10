//! Wiremock integration tests for [`stellar_agent_network::sep29::check_memo_required`]
//! cross-RPC consistency check.
//!
//! # Tested scenarios
//!
//! 1. **`primary_required_secondary_absent_divergence`** — primary returns
//!    `b"1"` (memo required); secondary returns no entry (not required).
//!    Expected: `NetworkError::RpcDivergence` (`network.rpc_divergence`).
//!
//! 2. **`primary_absent_secondary_required_divergence`** — primary returns no
//!    entry (not required); secondary returns `b"1"` (memo required).
//!    Expected: `NetworkError::RpcDivergence`.
//!
//! 3. **`both_required_agree_returns_memo_required`** — both RPCs return `b"1"`.
//!    Expected: `WalletError::Validation(ValidationError::MemoRequired)` — the
//!    memo-required gate fires after the consistency check passes.
//!
//! 4. **`both_absent_agree_returns_ok`** — both RPCs return no entry.
//!    Expected: `Ok(())`.
//!
//! 5. **`secondary_none_bypasses_cross_check`** — `secondary_rpc = None`.
//!    Primary returns `b"1"` without a memo; memo-required gate fires.
//!    Expected: `WalletError::Validation(ValidationError::MemoRequired)`.
//!
//! 6. **`secondary_rpc_error_propagates`** — secondary returns HTTP 500.
//!    Expected: `NetworkError::RpcDivergence` — a failing secondary means the
//!    cross-check cannot be completed; fail-closed.
//!
//! # Live acceptance
//!
//! A live cross-RPC divergence test is impossible against a single public
//! testnet RPC — both public endpoints see the same ledger state, so they
//! always agree.  The divergence path can only be exercised with mock servers
//! that return controlled responses.  These wiremock tests provide that
//! coverage; live acceptance of the no-divergence path is covered by the
//! existing `pay_integration.rs` SEP-29 tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; assertions via unwrap/expect/panic are idiomatic in integration tests"
)]

use serde_json::json;
use stellar_agent_core::error::{NetworkError, ValidationError, WalletError};
use stellar_agent_network::{StellarRpcClient, sep29::check_memo_required};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Fixture: test account G-strkey
// ─────────────────────────────────────────────────────────────────────────────

const TEST_ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

// ─────────────────────────────────────────────────────────────────────────────
// XDR helpers (copied from fetch_data_entry_regression.rs to avoid cross-test
// module imports; both are in the same `tests/` tree)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a `LedgerEntryData::Data` XDR-base64 for `config.memo_required`.
fn memo_required_entry_xdr(account: &str, value: &[u8]) -> String {
    use stellar_xdr::{
        AccountId, DataEntry, DataEntryExt, DataValue, LedgerEntryData, Limits, PublicKey,
        String64, StringM, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account)
        .expect("valid address")
        .0;
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));
    let key_str: StringM<64> = "config.memo_required"
        .as_bytes()
        .to_vec()
        .try_into()
        .expect("fits in 64 bytes");
    let data_value = DataValue(
        stellar_xdr::BytesM::<64>::try_from(value.to_vec()).expect("value fits in 64 bytes"),
    );
    let entry = DataEntry {
        account_id,
        data_name: String64::from(key_str),
        data_value,
        ext: DataEntryExt::V0,
    };
    LedgerEntryData::Data(entry)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR")
}

/// Builds the XDR-base64 `LedgerKey::Data` for the test account + `config.memo_required`.
fn memo_required_key_xdr(account: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyData, Limits, PublicKey, String64, StringM, Uint256,
        WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account)
        .expect("valid address")
        .0;
    let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));
    let key_str: StringM<64> = "config.memo_required"
        .as_bytes()
        .to_vec()
        .try_into()
        .expect("fits in 64 bytes");
    let key = LedgerKey::Data(LedgerKeyData {
        account_id,
        data_name: String64::from(key_str),
    });
    key.to_xdr_base64(Limits::none()).expect("valid XDR")
}

/// Builds the JSON body for a `getLedgerEntries` response with a present entry.
fn present_entry_body(account: &str, value: &[u8]) -> serde_json::Value {
    let key_xdr = memo_required_key_xdr(account);
    let entry_xdr = memo_required_entry_xdr(account, value);
    json!({
        "entries": [
            {
                "key": key_xdr,
                "xdr": entry_xdr,
                "lastModifiedLedgerSeq": 12345
            }
        ],
        "latestLedger": 99999
    })
}

/// Builds the JSON body for a `getLedgerEntries` response with NO entry (absent).
fn absent_entry_body() -> serde_json::Value {
    json!({
        "entries": null,
        "latestLedger": 99999
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// Primary requires memo (`b"1"`); secondary has no entry.
/// Expected: `network.rpc_divergence` before the memo-required gate fires.
#[tokio::test]
async fn primary_required_secondary_absent_divergence() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary: memo-required entry present.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(present_entry_body(TEST_ACCOUNT, b"1")))
        .mount(&primary)
        .await;

    // Secondary: no entry.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(absent_entry_body()))
        .mount(&secondary)
        .await;

    let primary_client =
        StellarRpcClient::new(&primary.uri()).expect("primary mock URL must be valid");
    let secondary_client =
        StellarRpcClient::new(&secondary.uri()).expect("secondary mock URL must be valid");

    let result = check_memo_required(
        &primary_client,
        Some(&secondary_client),
        TEST_ACCOUNT,
        false,
    )
    .await;

    assert!(
        result.is_err(),
        "primary-required / secondary-absent must diverge"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "network.rpc_divergence",
        "expected network.rpc_divergence; got: {}",
        err.code()
    );
    assert!(
        matches!(
            err,
            WalletError::Network(NetworkError::RpcDivergence { .. })
        ),
        "error must be NetworkError::RpcDivergence; got: {err:?}"
    );
}

/// Primary has no entry (not required); secondary requires memo (`b"1"`).
/// Expected: `network.rpc_divergence`.
///
/// This is the DoS-attack-vector case: a compromised primary silently suppresses
/// the memo-required entry; the secondary RPC catches it.
#[tokio::test]
async fn primary_absent_secondary_required_divergence() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary: no entry.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(absent_entry_body()))
        .mount(&primary)
        .await;

    // Secondary: memo-required entry present.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(present_entry_body(TEST_ACCOUNT, b"1")))
        .mount(&secondary)
        .await;

    let primary_client =
        StellarRpcClient::new(&primary.uri()).expect("primary mock URL must be valid");
    let secondary_client =
        StellarRpcClient::new(&secondary.uri()).expect("secondary mock URL must be valid");

    let result = check_memo_required(
        &primary_client,
        Some(&secondary_client),
        TEST_ACCOUNT,
        false,
    )
    .await;

    assert!(
        result.is_err(),
        "primary-absent / secondary-required must diverge"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "network.rpc_divergence",
        "expected network.rpc_divergence; got: {}",
        err.code()
    );
}

/// Both primary and secondary return `b"1"` (both agree memo is required).
/// Expected: `validation.memo_required` — the memo-required gate fires after
/// the consistency check passes.
#[tokio::test]
async fn both_required_agree_returns_memo_required() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(present_entry_body(TEST_ACCOUNT, b"1")))
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(present_entry_body(TEST_ACCOUNT, b"1")))
        .mount(&secondary)
        .await;

    let primary_client =
        StellarRpcClient::new(&primary.uri()).expect("primary mock URL must be valid");
    let secondary_client =
        StellarRpcClient::new(&secondary.uri()).expect("secondary mock URL must be valid");

    let result = check_memo_required(
        &primary_client,
        Some(&secondary_client),
        TEST_ACCOUNT,
        false,
    )
    .await;

    assert!(
        result.is_err(),
        "both-agree-required without memo must fail"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "validation.memo_required",
        "expected validation.memo_required after consistency-check passes; got: {}",
        err.code()
    );
    assert!(
        matches!(
            err,
            WalletError::Validation(ValidationError::MemoRequired { .. })
        ),
        "error must be ValidationError::MemoRequired; got: {err:?}"
    );
}

/// Both primary and secondary return no entry (both agree memo is NOT required).
/// Expected: `Ok(())`.
#[tokio::test]
async fn both_absent_agree_returns_ok() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(absent_entry_body()))
        .mount(&primary)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(absent_entry_body()))
        .mount(&secondary)
        .await;

    let primary_client =
        StellarRpcClient::new(&primary.uri()).expect("primary mock URL must be valid");
    let secondary_client =
        StellarRpcClient::new(&secondary.uri()).expect("secondary mock URL must be valid");

    let result = check_memo_required(
        &primary_client,
        Some(&secondary_client),
        TEST_ACCOUNT,
        false,
    )
    .await;

    assert!(
        result.is_ok(),
        "both-absent must return Ok; got: {result:?}"
    );
}

/// When `secondary_rpc = None`, the cross-RPC check is skipped and the
/// primary-only memo-required gate fires normally.
#[tokio::test]
async fn secondary_none_bypasses_cross_check() {
    let primary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(present_entry_body(TEST_ACCOUNT, b"1")))
        .mount(&primary)
        .await;

    let primary_client =
        StellarRpcClient::new(&primary.uri()).expect("primary mock URL must be valid");

    let result = check_memo_required(&primary_client, None, TEST_ACCOUNT, false).await;

    assert!(
        result.is_err(),
        "secondary=None + primary-required must trigger memo-required"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "validation.memo_required",
        "expected validation.memo_required (not divergence) when secondary=None; got: {}",
        err.code()
    );
}

/// When `secondary_rpc` fails (mock returns a malformed response), the error
/// propagates as a network/protocol error, not a divergence — fail-closed.
///
/// The design doc specifies: "Oracle RPC fails → divergence error for
/// configured-oracle profiles."  Here `fetch_data_entry` returns an error
/// from the malformed response (not `None`), so the cross-check propagates
/// the error up before reaching the normalise comparison.
#[tokio::test]
async fn secondary_rpc_error_propagates() {
    let primary = MockServer::start().await;
    let secondary = MockServer::start().await;

    // Primary: memo-required present.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(present_entry_body(TEST_ACCOUNT, b"1")))
        .mount(&primary)
        .await;

    // Secondary: HTTP 500 → RPC-level error propagated by the client.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&secondary)
        .await;

    let primary_client =
        StellarRpcClient::new(&primary.uri()).expect("primary mock URL must be valid");
    let secondary_client =
        StellarRpcClient::new(&secondary.uri()).expect("secondary mock URL must be valid");

    let result = check_memo_required(
        &primary_client,
        Some(&secondary_client),
        TEST_ACCOUNT,
        false,
    )
    .await;

    // A failing secondary is classified as divergence (fail-closed) per the
    // design doc: the cross-check cannot be completed, so the call refuses
    // with `network.rpc_divergence` rather than degrading to primary-only.
    let err = result.expect_err("secondary RPC error must propagate fail-closed");
    assert_eq!(
        err.code(),
        "network.rpc_divergence",
        "secondary-RPC failure must classify as divergence per the design doc; got: {}",
        err.code()
    );
}
