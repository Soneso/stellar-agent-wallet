//! Tests for the `fetch_data_entry` XDR decoder.
//!
//! `fetch_data_entry` decodes RPC responses via `LedgerEntryData::from_xdr_base64`
//! (the entry-data-only union variant).  The Stellar RPC `getLedgerEntries`
//! returns `LedgerEntryData` XDR, not the full `LedgerEntry` wrapper that
//! includes last-modified-ledger and ledger-entry-hash metadata.
//!
//! These tests use wiremock to verify the decoder works correctly against
//! canned RPC responses. The upstream decoding pattern is consistent with
//! `rs-stellar-rpc-client`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; assertions via unwrap/expect/panic are idiomatic in integration tests"
)]

use serde_json::json;
use stellar_agent_network::{StellarRpcClient, fetch_data_entry};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Test account
// ─────────────────────────────────────────────────────────────────────────────

const TEST_ACCOUNT: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

// ─────────────────────────────────────────────────────────────────────────────
// Helpers: build LedgerKey and LedgerEntryData XDR
// ─────────────────────────────────────────────────────────────────────────────

/// Builds the XDR-base64 `LedgerKey::Data` for an account + data name.
fn data_ledger_key_xdr(account_address: &str, data_key: &str) -> String {
    use stellar_xdr::{
        AccountId, LedgerKey, LedgerKeyData, Limits, PublicKey, String64, StringM, Uint256,
        WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_address)
        .expect("valid address")
        .0;
    let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));
    let key_bytes = data_key.as_bytes().to_vec();
    let string_m: StringM<64> = key_bytes.try_into().expect("key fits in 64 bytes");
    let data_name = String64::from(string_m);
    let key = LedgerKey::Data(LedgerKeyData {
        account_id: xdr_account_id,
        data_name,
    });
    key.to_xdr_base64(Limits::none()).expect("valid XDR")
}

/// Builds a `LedgerEntryData::Data` XDR-base64 with the given value bytes.
///
/// This is what the Stellar RPC `getLedgerEntries` actually returns for a
/// `LedgerKey::Data` entry.
fn data_entry_xdr(account_address: &str, data_key: &str, value: &[u8]) -> String {
    use stellar_xdr::{
        AccountId, DataEntry, DataEntryExt, DataValue, LedgerEntryData, Limits, PublicKey,
        String64, StringM, Uint256, WriteXdr,
    };
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_address)
        .expect("valid address")
        .0;
    let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));
    let key_bytes = data_key.as_bytes().to_vec();
    let string_m: StringM<64> = key_bytes.try_into().expect("key fits in 64 bytes");
    let data_name = String64::from(string_m);
    let data_value_bytes: Vec<u8> = value.to_vec();
    let data_value = DataValue(
        stellar_xdr::BytesM::<64>::try_from(data_value_bytes).expect("value fits in 64 bytes"),
    );
    let entry = DataEntry {
        account_id: xdr_account_id,
        data_name,
        data_value,
        ext: DataEntryExt::V0,
    };
    LedgerEntryData::Data(entry)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR")
}

/// Builds a `LedgerEntryData::Account` XDR-base64 for type-mismatch testing.
///
/// Returns a valid `LedgerEntryData` but of the wrong variant (Account instead of Data).
const FUNDED_ACCOUNT_ENTRY_XDR: &str = "AAAAAAAAAABzdv3ojkzWHMD7KUoXhrPx0GH18vHKV0ZfqpMiEblG1gAAAFwVZH3YAAABdgAAAQgAAAAFAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAADAAAAAAAOZYQAAAAAaJsIJQ==";

// ─────────────────────────────────────────────────────────────────────────────
// Regression test: happy path — LedgerEntryData::Data returned correctly
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that `fetch_data_entry` returns the correct value from a
/// `LedgerEntryData::Data` RPC response.
///
/// The decoder uses `LedgerEntryData::from_xdr_base64` to match the actual
/// Stellar RPC wire format returned by `getLedgerEntries`.
#[tokio::test]
async fn fetch_data_entry_decodes_ledger_entry_data_correctly() {
    let mock_server = MockServer::start().await;

    let key_xdr = data_ledger_key_xdr(TEST_ACCOUNT, "config.memo_required");
    let entry_xdr = data_entry_xdr(TEST_ACCOUNT, "config.memo_required", b"1");

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": entry_xdr,
                    "lastModifiedLedgerSeq": 12345
                }
            ],
            "latestLedger": 99999
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let result = fetch_data_entry(&client, TEST_ACCOUNT, "config.memo_required")
        .await
        .expect("fetch_data_entry must succeed with a valid LedgerEntryData::Data response");

    assert_eq!(
        result,
        Some(b"1".to_vec()),
        "fetch_data_entry must return Some(b\"1\") for a data entry with value b\"1\""
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Regression test: type-mismatch path — wrong entry type returns error
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that `fetch_data_entry` returns `XdrCodecFailed` when the RPC
/// response contains the wrong `LedgerEntryData` variant (Account instead of Data).
///
/// This covers the `other =>` arm of the match in `fetch_data_entry`.
#[tokio::test]
async fn fetch_data_entry_wrong_entry_type_returns_xdr_error() {
    let mock_server = MockServer::start().await;

    let key_xdr = data_ledger_key_xdr(TEST_ACCOUNT, "config.memo_required");
    // Return an Account entry XDR (wrong type) for the data key.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": FUNDED_ACCOUNT_ENTRY_XDR,
                    "lastModifiedLedgerSeq": 12345
                }
            ],
            "latestLedger": 99999
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let result = fetch_data_entry(&client, TEST_ACCOUNT, "config.memo_required").await;

    assert!(
        result.is_err(),
        "fetch_data_entry must fail when the RPC returns the wrong LedgerEntryData variant"
    );

    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "protocol.xdr_codec_failed",
        "expected XdrCodecFailed error code; got: {}",
        err.code()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Not-found path: empty entries returns None
// ─────────────────────────────────────────────────────────────────────────────

/// When the RPC returns `entries: null` or empty, `fetch_data_entry` returns `None`.
#[tokio::test]
async fn fetch_data_entry_returns_none_when_entry_absent() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": null,
            "latestLedger": 99999
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let result = fetch_data_entry(&client, TEST_ACCOUNT, "config.memo_required")
        .await
        .expect("fetch_data_entry must succeed with no entries (returns None)");

    assert!(
        result.is_none(),
        "fetch_data_entry must return None when the RPC returns no entries"
    );
}
