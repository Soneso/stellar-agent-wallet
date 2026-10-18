//! Primary SEP-29 memo enforcement.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]

use serde_json::json;
use stellar_agent_network::{StellarRpcClient, sep29::check_memo_required};
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

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

#[tokio::test]
async fn primary_required_refuses_missing_memo() {
    let primary = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(present_entry_body(TEST_ACCOUNT, b"1")))
        .mount(&primary)
        .await;

    let primary_client =
        StellarRpcClient::new(&primary.uri()).expect("primary mock URL must be valid");

    let result = check_memo_required(&primary_client, TEST_ACCOUNT, false).await;

    assert!(
        result.is_err(),
        "a required primary flag must trigger memo-required"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "validation.memo_required",
        "expected validation.memo_required from the primary gate; got: {}",
        err.code()
    );
}

#[tokio::test]
async fn check_memo_required_reads_primary_only() {
    let primary = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(
            json!({"entries": [], "latestLedger": 100}),
        ))
        .expect(1)
        .mount(&primary)
        .await;
    let client = StellarRpcClient::new(&primary.uri()).unwrap();
    assert_eq!(
        check_memo_required(&client, TEST_ACCOUNT, false)
            .await
            .unwrap(),
        stellar_agent_network::cross_check::MemoObservation::Read(false)
    );
    assert_eq!(
        check_memo_required(&client, TEST_ACCOUNT, true)
            .await
            .unwrap(),
        stellar_agent_network::cross_check::MemoObservation::NotRead
    );
    assert_eq!(primary.received_requests().await.unwrap().len(), 1);
}
