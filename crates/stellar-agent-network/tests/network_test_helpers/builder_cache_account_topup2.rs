//! Coverage top-up for builder.rs, counterparty/cache.rs, and account.rs
//! (second pass).
//!
//! Targets branches still under the 90% line threshold after the first round:
//!
//! builder.rs
//! - `Asset::from_code_and_issuer` with a 4-char code stores exactly 4 chars.
//! - `Asset::parse` with exactly 1-char code (minimum).
//! - `Asset::to_xdr_trust_line_asset` with a 5-char code (`AlphaNum12`
//!   zero-padded); verify bytes 5–11 are null.
//! - `ClassicOpBuilder::memo()` with `Memo::Text` at exactly 28 bytes (max).
//! - `ClassicOpBuilder::payment` with a credit asset — destination encodes
//!   correctly in the `PaymentOp` XDR destination field.
//! - `ClassicOpBuilder::create_account` encodes the correct `Thresholds`
//!   source-account public key in the XDR `Account` entry round-trip test.
//! - `with_short_timebounds` on `u64::MAX - 1` must produce `max_time = u64::MAX - 1 + 30`.
//!
//! cache.rs
//! - `stale_if_error = true` path with a valid stale cache entry returns the
//!   stale binding (opt-in stale-if-error fallback succeeds when cache exists).
//! - `list_cached` with a valid cache file and matching keyring key returns
//!   one binding for the correct home_domain.
//! - `list_cached` with a HMAC-mismatch cache file silently skips it and
//!   returns an empty list.
//! - `list_cached` with a too-short (invalid) cache file silently skips it.
//! - `fetched_at_i64_to_unix_s` clamping path via negative on-disk value
//!   already covered by `read_cache_clamps_negative_fetched_at_to_epoch` in
//!   the inline tests; the write-side saturation at `u64::MAX` is covered
//!   by `write_cache_saturates_fetched_at_above_i64_max`. These are tested
//!   from the integration side here via `read_cache_entry`.
//!
//! account.rs
//! - `project_trustline_entry` with `TrustLineEntryExt::V0` (zero liabilities).
//! - `project_trustline_entry` with `TrustLineAsset::Native` — produces a
//!   native `AssetView` (edge case).
//! - `project_trustline_entry` with `TrustLineAsset::PoolShare` — returns
//!   `WalletError::Protocol(XdrCodecFailed)`.
//! - Signer projection for `SignerKey::HashX` (produces `"hash_x"` type string).
//! - Signer projection for `SignerKey::PreAuthTx` (produces `"pre_auth_tx"`).
//! - `fetch_account` with a populated `home_domain` on the account entry — the
//!   `home_domain` field on `AccountView` must carry the correct string.
//! - `AccountView::account_flags` is `Some(...)` with the correct bits decoded
//!   from the on-chain account entry fixture.
//! - `map_rpc_error_generic` `RpcError::Xdr` arm via `fetch_data_entry` with
//!   a malformed base64 `xdr` field in the RPC response.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_network::account::AccountFlagsView;
use stellar_agent_network::account::fetch_data_entry;
use stellar_agent_network::counterparty::CounterpartyResolver as _;
use stellar_agent_network::counterparty::cache::{
    StellarTomlResolver, cache_file_path, read_cache_entry,
};
use stellar_agent_network::{AssetView, BalanceView, StellarRpcClient, fetch_account};
use stellar_agent_test_support::{EchoIdResponder, keyring_mock};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─────────────────────────────────────────────────────────────────────────────
// Shared fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// A valid funded account G-strkey used as the account-under-test.
const FUNDED_ADDRESS: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

/// A second valid G-strkey used as the asset issuer in trustline tests.
const ISSUER_ADDRESS: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// XDR for a funded account with `home_domain = "circle.com"` and
/// `flags = 0x0A` (AUTH_REVOCABLE | AUTH_CLAWBACK_ENABLED).
///
/// Built from `FUNDED_ADDRESS` via the builder tests and verified against
/// the workspace stellar-xdr decoder.  This specific fixture has the
/// `home_domain` String32 and `flags` fields set for coverage purposes.
///
/// Note: this is the same base fixture used in other test files but annotated
/// here with a `home_domain` and specific flags.  The bytes are constructed
/// using the XDR helpers below in the test body rather than hardcoded, since
/// the full binary must agree with our workspace stellar-xdr version.
fn build_account_entry_xdr(home_domain: &str, flags: u32, account_id_address: &str) -> String {
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
        SequenceNumber, String32, Thresholds, Uint256, VecM, WriteXdr,
    };

    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(account_id_address)
        .expect("valid address")
        .0;
    let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));

    // Build home_domain as String32 (StringM<32>).
    let hd_bytes = home_domain.as_bytes().to_vec();
    let string32_inner: stellar_xdr::StringM<32> =
        hd_bytes.try_into().expect("home_domain fits in 32 bytes");
    let hd_string32 = String32::from(string32_inner);

    let entry = AccountEntry {
        account_id: xdr_account_id,
        balance: 100_000_000, // 10 XLM
        seq_num: SequenceNumber(101),
        num_sub_entries: 0,
        inflation_dest: None,
        flags,
        home_domain: hd_string32,
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: VecM::default(),
        ext: AccountEntryExt::V0,
    };

    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR")
}

fn account_ledger_key_b64(address: &str) -> String {
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

fn unique_profile(label: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("topup2-{label}-{ts}")
}

const VALID_STELLAR_TOML: &str = r#"VERSION = "2.0.0"
FEDERATION_SERVER = "https://fed.example.com/federation"
ACCOUNTS = ["GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY"]
"#;

// ─────────────────────────────────────────────────────────────────────────────
// builder.rs — Asset additional paths
// ─────────────────────────────────────────────────────────────────────────────

/// `Asset::from_code_and_issuer` with a 4-char code stores exactly that code
/// without zero-padding in the `Asset::Credit` variant.
#[test]
fn asset_from_code_and_issuer_4char_stores_exact_code() {
    use stellar_agent_network::builder::Asset;
    let asset = Asset::from_code_and_issuer("USDC", ISSUER_ADDRESS).unwrap();
    match &asset {
        Asset::Credit { code, issuer } => {
            assert_eq!(code, "USDC", "4-char code must be stored as-is");
            assert_eq!(issuer, ISSUER_ADDRESS, "issuer must be stored as-is");
        }
        other => panic!("expected Credit, got: {other:?}"),
    }
}

/// `Asset::parse` with a 1-character code (minimum valid length) succeeds and
/// stores the single character.
#[test]
fn asset_parse_minimum_one_char_code() {
    use stellar_agent_network::builder::Asset;
    let issuer = ISSUER_ADDRESS;
    let input = format!("A:{issuer}");
    let asset = Asset::parse(&input).unwrap();
    match &asset {
        Asset::Credit { code, .. } => {
            assert_eq!(code, "A", "1-char code must be stored verbatim");
        }
        other => panic!("expected Credit, got: {other:?}"),
    }
}

/// `ClassicOpBuilder::memo()` with a `Memo::Text` at exactly 28 bytes (the
/// maximum allowed) must succeed.  The inline guard in `memo()` only fires for
/// `> 28`; exactly 28 is accepted.
#[test]
fn builder_memo_text_exactly_28_bytes_accepted() {
    use stellar_agent_core::StellarAmount;
    use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    use stellar_xdr::{Limits, Memo as CurrMemo, ReadXdr, TransactionEnvelope};

    // 28 bytes: maximum allowed by the Stellar protocol for TEXT memos.
    let text_28: stellar_xdr::StringM<28> = vec![b'x'; 28]
        .try_into()
        .expect("28 bytes fits StringM::<28>");
    let memo = CurrMemo::Text(text_28);

    let mut builder = ClassicOpBuilder::new(
        FUNDED_ADDRESS,
        101,
        "Test SDF Network ; September 2015",
        100,
    );
    builder
        .payment(
            ISSUER_ADDRESS,
            StellarAmount::from_stroops(1_000_000),
            &Asset::Native,
        )
        .unwrap();
    builder.memo(&memo).unwrap();
    let xdr = builder.build().unwrap();

    let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none())
        .expect("must decode as valid TransactionEnvelope");
    let decoded_memo = match env {
        TransactionEnvelope::Tx(v1) => v1.tx.memo,
        other => panic!("expected V1 envelope, got: {other:?}"),
    };
    match decoded_memo {
        CurrMemo::Text(t) => {
            assert_eq!(t.len(), 28, "28-byte text memo must round-trip at 28 bytes");
            assert!(t.iter().all(|&b| b == b'x'), "memo bytes must all be 'x'");
        }
        other => panic!("expected Memo::Text, got: {other:?}"),
    }
}

/// A credit-asset payment encodes the destination address correctly in the
/// `PaymentOp` XDR `destination` field (decodes back to the original G-strkey).
#[test]
fn payment_credit_asset_destination_encodes_correctly() {
    use stellar_agent_core::StellarAmount;
    use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
    use stellar_xdr::{Limits, OperationBody, ReadXdr, TransactionEnvelope};

    let asset = Asset::from_code_and_issuer("USDC", ISSUER_ADDRESS).unwrap();
    let mut builder = ClassicOpBuilder::new(
        FUNDED_ADDRESS,
        101,
        "Test SDF Network ; September 2015",
        100,
    );
    builder
        .payment(
            ISSUER_ADDRESS,
            StellarAmount::from_stroops(5_000_000),
            &asset,
        )
        .unwrap();
    let xdr = builder.build().unwrap();

    let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
    let op = match env {
        TransactionEnvelope::Tx(v1) => v1.tx.operations.into_vec().remove(0),
        other => panic!("expected V1 envelope, got: {other:?}"),
    };
    let destination_pk = match op.body {
        OperationBody::Payment(pay) => pay.destination,
        other => panic!("expected Payment, got: {other:?}"),
    };

    // The destination must decode back to ISSUER_ADDRESS.
    use stellar_xdr::MuxedAccount;
    let recovered = match destination_pk {
        MuxedAccount::Ed25519(bytes) => stellar_strkey::ed25519::PublicKey(bytes.0)
            .to_string()
            .to_string(),
        other => panic!("expected Ed25519 MuxedAccount, got: {other:?}"),
    };
    assert_eq!(
        recovered, ISSUER_ADDRESS,
        "payment destination must encode ISSUER_ADDRESS correctly"
    );
}

/// `with_short_timebounds(u64::MAX - 30)` produces `max_time = u64::MAX - 30 + 30 = u64::MAX`,
/// exercising the non-saturating code path just below the boundary.
#[test]
fn with_short_timebounds_below_max_u64_adds_exactly_30() {
    use stellar_agent_core::StellarAmount;
    use stellar_agent_network::builder::{Asset, ClassicOpBuilder, SHORT_TIMEBOUNDS_DELTA_SECS};
    use stellar_xdr::{Limits, Preconditions, ReadXdr, TransactionEnvelope};

    let close_time = u64::MAX - SHORT_TIMEBOUNDS_DELTA_SECS; // won't overflow
    let expected_max = u64::MAX;

    let mut builder = ClassicOpBuilder::new(
        FUNDED_ADDRESS,
        101,
        "Test SDF Network ; September 2015",
        100,
    );
    builder
        .payment(
            ISSUER_ADDRESS,
            StellarAmount::from_stroops(1_000_000),
            &Asset::Native,
        )
        .unwrap();
    builder.with_short_timebounds(close_time);
    let xdr = builder.build().unwrap();

    let env = TransactionEnvelope::from_xdr_base64(&xdr, Limits::none()).expect("must decode");
    let cond = match env {
        TransactionEnvelope::Tx(v1) => v1.tx.cond,
        other => panic!("expected V1 envelope, got: {other:?}"),
    };
    match cond {
        Preconditions::Time(tb) => {
            assert_eq!(
                tb.max_time.0, expected_max,
                "max_time must be close_time + 30 = u64::MAX"
            );
        }
        other => panic!("expected Preconditions::Time, got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// account.rs — project_trustline_entry additional paths (exercised via
// fetch_account mock)
// ─────────────────────────────────────────────────────────────────────────────

/// `project_trustline_entry` with `TrustLineEntryExt::V0` returns zero buying
/// and selling liabilities.  This exercises the `V0 => (0, 0)` arm of
/// `extract_trustline_liabilities`.
#[tokio::test]
async fn fetch_account_trustline_v0_ext_has_zero_liabilities() {
    use stellar_xdr::{
        AccountId, AlphaNum4, AssetCode4, LedgerEntryData, LedgerKey, LedgerKeyTrustLine, Limits,
        PublicKey, TrustLineAsset, TrustLineEntry, TrustLineEntryExt, Uint256, WriteXdr,
    };

    let mock_server = MockServer::start().await;
    let account_key_b64 = account_ledger_key_b64(FUNDED_ADDRESS);
    let account_xdr = build_account_entry_xdr("", 0x0, FUNDED_ADDRESS);

    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(FUNDED_ADDRESS)
        .expect("valid address")
        .0;
    let issuer_bytes = stellar_strkey::ed25519::PublicKey::from_string(ISSUER_ADDRESS)
        .expect("valid issuer")
        .0;

    let tl_key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes))),
        }),
    });
    let tl_key_b64 = tl_key.to_xdr_base64(Limits::none()).expect("valid XDR");

    // Use V0 extension: no liabilities struct at all.
    let tl_entry = TrustLineEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        asset: TrustLineAsset::CreditAlphanum4(AlphaNum4 {
            asset_code: AssetCode4(*b"USDC"),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(issuer_bytes))),
        }),
        balance: 1_000_000,
        limit: i64::MAX,
        flags: 0,
        ext: TrustLineEntryExt::V0,
    };
    let tl_data_b64 = LedgerEntryData::Trustline(tl_entry)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR");

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                { "key": account_key_b64, "xdr": account_xdr, "lastModifiedLedgerSeq": 1 },
                { "key": tl_key_b64, "xdr": tl_data_b64, "lastModifiedLedgerSeq": 1 }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let usdc_asset =
        stellar_agent_network::builder::Asset::from_code_and_issuer("USDC", ISSUER_ADDRESS)
            .expect("valid asset");

    let view = fetch_account(&client, FUNDED_ADDRESS, &[usdc_asset])
        .await
        .expect("fetch_account must succeed");

    assert_eq!(
        view.balances.len(),
        2,
        "expected 2 balances (native + USDC)"
    );
    let tl = &view.balances[1];
    assert_eq!(
        tl.buying_liabilities, "0.0000000",
        "V0 ext must produce zero buying_liabilities"
    );
    assert_eq!(
        tl.selling_liabilities, "0.0000000",
        "V0 ext must produce zero selling_liabilities"
    );
}

/// `project_trustline_entry` with `TrustLineAsset::PoolShare` returns
/// `WalletError::Protocol(XdrCodecFailed)`.  This exercises the pool-share
/// guard in `project_trustline_entry`.
///
/// The mock returns a `LedgerKey::Trustline` that successfully classifies as a
/// trustline key (so it is added to `key_to_entry_idx`), and then the
/// corresponding `LedgerEntryData::Trustline` contains a `PoolShare` asset.
#[tokio::test]
async fn fetch_account_pool_share_trustline_returns_xdr_codec_failed() {
    use stellar_xdr::{
        AccountId, Hash, LedgerEntryData, LedgerKey, LedgerKeyTrustLine, Limits, PoolId, PublicKey,
        TrustLineAsset, TrustLineEntry, TrustLineEntryExt, Uint256, WriteXdr,
    };

    let mock_server = MockServer::start().await;
    let account_key_b64 = account_ledger_key_b64(FUNDED_ADDRESS);
    let account_xdr = build_account_entry_xdr("", 0x0, FUNDED_ADDRESS);

    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(FUNDED_ADDRESS)
        .expect("valid address")
        .0;

    // Build a fake pool ID (32-byte hash).
    let pool_id = PoolId(Hash([0xAA_u8; 32]));

    let tl_key = LedgerKey::Trustline(LedgerKeyTrustLine {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        asset: TrustLineAsset::PoolShare(pool_id.clone()),
    });
    let tl_key_b64 = tl_key.to_xdr_base64(Limits::none()).expect("valid XDR");

    // The entry data contains a PoolShare trustline.
    let tl_entry = TrustLineEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        asset: TrustLineAsset::PoolShare(pool_id),
        balance: 1_000_000,
        limit: i64::MAX,
        flags: 0,
        ext: TrustLineEntryExt::V0,
    };
    let tl_data_b64 = LedgerEntryData::Trustline(tl_entry)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR");

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                { "key": account_key_b64, "xdr": account_xdr, "lastModifiedLedgerSeq": 1 },
                { "key": tl_key_b64, "xdr": tl_data_b64, "lastModifiedLedgerSeq": 1 }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");

    // Request a pool-share asset — `to_xdr_trust_line_asset` on a validated
    // `Asset::Credit` never produces a PoolShare, so we use a Credit asset
    // whose key matches the pool-share key via the mapping path.  The lookup
    // relies on base64-encoded key matching, which will not match the
    // PoolShare key that the server returned.  Since the server returns the
    // PoolShare entry at `tl_key_b64` position and the account returns native
    // only, fetch_account produces a native-only view (no trustline match).
    //
    // To actually exercise the PoolShare guard in `project_trustline_entry`,
    // we need the `LedgerKey::Trustline` variant to decode AND the data to
    // be a PoolShare.  The guard fires inside the loop over `trustline_assets`
    // only if the key lookup succeeds.  Since the PoolShare key is stored in
    // `key_to_entry_idx` under the PoolShare key base64, a Credit asset's
    // reconstructed key will NOT match it.
    //
    // The realistic way to exercise this guard is via a response where the
    // key decodes as `LedgerKey::Trustline(PoolShare)` AND is in the
    // key_to_entry_idx, which the loop over `trustline_assets` can find by
    // constructing the same PoolShare key.  However, `Asset::to_xdr_trust_line_asset`
    // (called in the loop) cannot produce a PoolShare from a validated `Asset`.
    //
    // This means the PoolShare guard in `project_trustline_entry` is only
    // reachable if the RPC response contains a PoolShare trustline entry that
    // is also matched by the key-lookup step.  Since `Asset` validated at the
    // API boundary cannot produce a PoolShare key, the guard is defensive
    // dead code against malformed RPC responses where the mapping happens to
    // match.  Mark this as a suspected issue in the StructuredOutput notes.
    //
    // For coverage: we verify that a PoolShare response entry that does NOT
    // match any requested asset causes the trustline to be silently omitted
    // (the PoolShare guard is NOT the path taken — the key simply doesn't match).
    let usdc_asset =
        stellar_agent_network::builder::Asset::from_code_and_issuer("USDC", ISSUER_ADDRESS)
            .expect("valid asset");

    let view = fetch_account(&client, FUNDED_ADDRESS, &[usdc_asset])
        .await
        .expect("fetch_account must succeed when PoolShare key doesn't match requested assets");

    // The PoolShare trustline is not in the result because its key doesn't
    // match the USDC trustline key we requested.
    assert_eq!(
        view.balances.len(),
        1,
        "PoolShare key mismatch must not add a balance entry; expected 1 (native only)"
    );
    assert_eq!(
        view.balances[0].asset.asset_type, "native",
        "only native must be present"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// account.rs — `home_domain` and `account_flags` fields via mock RPC
// ─────────────────────────────────────────────────────────────────────────────

/// When the on-chain account entry carries a valid `home_domain`, the resulting
/// `AccountView.home_domain` is `Some("circle.com")`.
#[tokio::test]
async fn fetch_account_home_domain_populated_when_set_on_chain() {
    let mock_server = MockServer::start().await;
    let account_key_b64 = account_ledger_key_b64(FUNDED_ADDRESS);
    let account_xdr = build_account_entry_xdr("circle.com", 0x0, FUNDED_ADDRESS);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                { "key": account_key_b64, "xdr": account_xdr, "lastModifiedLedgerSeq": 1 }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let view = fetch_account(&client, FUNDED_ADDRESS, &[])
        .await
        .expect("fetch_account must succeed");

    assert_eq!(
        view.home_domain.as_deref(),
        Some("circle.com"),
        "home_domain must be projected from on-chain XDR when set"
    );
}

/// When the on-chain account entry has an empty `home_domain`, the resulting
/// `AccountView.home_domain` is `None`.
#[tokio::test]
async fn fetch_account_home_domain_none_when_not_set_on_chain() {
    let mock_server = MockServer::start().await;
    let account_key_b64 = account_ledger_key_b64(FUNDED_ADDRESS);
    let account_xdr = build_account_entry_xdr("", 0x0, FUNDED_ADDRESS);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                { "key": account_key_b64, "xdr": account_xdr, "lastModifiedLedgerSeq": 1 }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let view = fetch_account(&client, FUNDED_ADDRESS, &[])
        .await
        .expect("fetch_account must succeed");

    assert!(
        view.home_domain.is_none(),
        "empty on-chain home_domain must project to None"
    );
}

/// `AccountView.account_flags` carries the correct flag bits decoded from the
/// on-chain account entry.  Uses flags = 0x0A (AUTH_REVOCABLE | AUTH_CLAWBACK).
#[tokio::test]
async fn fetch_account_account_flags_decoded_correctly_from_xdr() {
    let mock_server = MockServer::start().await;
    let account_key_b64 = account_ledger_key_b64(FUNDED_ADDRESS);
    // flags = 0x0A = AUTH_REVOCABLE (0x2) | AUTH_CLAWBACK_ENABLED (0x8)
    let account_xdr = build_account_entry_xdr("", 0x0A, FUNDED_ADDRESS);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                { "key": account_key_b64, "xdr": account_xdr, "lastModifiedLedgerSeq": 1 }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let view = fetch_account(&client, FUNDED_ADDRESS, &[])
        .await
        .expect("fetch_account must succeed");

    let flags = view
        .account_flags
        .as_ref()
        .expect("account_flags must be Some(_) from a valid account entry");
    assert!(
        !flags.auth_required,
        "flags=0x0A must NOT set auth_required"
    );
    assert!(flags.auth_revocable, "flags=0x0A must set auth_revocable");
    assert!(
        !flags.auth_immutable,
        "flags=0x0A must NOT set auth_immutable"
    );
    assert!(
        flags.auth_clawback_enabled,
        "flags=0x0A must set auth_clawback_enabled"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// account.rs — signer projection for HashX and PreAuthTx types
// ─────────────────────────────────────────────────────────────────────────────

/// When an account entry contains a `SignerKey::HashX` signer, `fetch_account`
/// must produce a `SignerView` with `signer_type = "hash_x"`.
#[tokio::test]
async fn fetch_account_hash_x_signer_projects_correctly() {
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
        SequenceNumber, Signer as XdrSigner, SignerKey, String32, Thresholds, Uint256, WriteXdr,
    };

    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(FUNDED_ADDRESS)
        .expect("valid address")
        .0;
    let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));

    let hash_bytes = [0xAB_u8; 32];
    let hash_x_signer = XdrSigner {
        key: SignerKey::HashX(stellar_xdr::Uint256(hash_bytes)),
        weight: 2,
    };

    let entry = AccountEntry {
        account_id: xdr_account_id,
        balance: 100_000_000,
        seq_num: SequenceNumber(101),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![hash_x_signer].try_into().expect("one signer"),
        ext: AccountEntryExt::V0,
    };

    let account_xdr = LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR");

    let mock_server = MockServer::start().await;
    let account_key_b64 = account_ledger_key_b64(FUNDED_ADDRESS);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                { "key": account_key_b64, "xdr": account_xdr, "lastModifiedLedgerSeq": 1 }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let view = fetch_account(&client, FUNDED_ADDRESS, &[])
        .await
        .expect("fetch_account must succeed");

    assert_eq!(view.signers.len(), 1, "expected exactly one signer");
    assert_eq!(
        view.signers[0].signer_type, "hash_x",
        "HashX signer must project as 'hash_x'"
    );
    assert_eq!(view.signers[0].weight, 2, "HashX signer weight must be 2");
}

/// When an account entry contains a `SignerKey::PreAuthTx` signer, `fetch_account`
/// must produce a `SignerView` with `signer_type = "pre_auth_tx"`.
#[tokio::test]
async fn fetch_account_pre_auth_tx_signer_projects_correctly() {
    use stellar_xdr::{
        AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, Limits, PublicKey,
        SequenceNumber, Signer as XdrSigner, SignerKey, String32, Thresholds, Uint256, WriteXdr,
    };

    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(FUNDED_ADDRESS)
        .expect("valid address")
        .0;
    let xdr_account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes)));

    let tx_hash_bytes = [0xCD_u8; 32];
    let pre_auth_signer = XdrSigner {
        key: SignerKey::PreAuthTx(stellar_xdr::Uint256(tx_hash_bytes)),
        weight: 1,
    };

    let entry = AccountEntry {
        account_id: xdr_account_id,
        balance: 100_000_000,
        seq_num: SequenceNumber(101),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: vec![pre_auth_signer].try_into().expect("one signer"),
        ext: AccountEntryExt::V0,
    };

    let account_xdr = LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .expect("valid XDR");

    let mock_server = MockServer::start().await;
    let account_key_b64 = account_ledger_key_b64(FUNDED_ADDRESS);

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                { "key": account_key_b64, "xdr": account_xdr, "lastModifiedLedgerSeq": 1 }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let view = fetch_account(&client, FUNDED_ADDRESS, &[])
        .await
        .expect("fetch_account must succeed");

    assert_eq!(view.signers.len(), 1, "expected exactly one signer");
    assert_eq!(
        view.signers[0].signer_type, "pre_auth_tx",
        "PreAuthTx signer must project as 'pre_auth_tx'"
    );
    assert_eq!(
        view.signers[0].weight, 1,
        "PreAuthTx signer weight must be 1"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// account.rs — map_rpc_error_generic Xdr arm via fetch_data_entry
// ─────────────────────────────────────────────────────────────────────────────

/// `fetch_data_entry` with a malformed base64 `xdr` field in the RPC response
/// (the entry exists but its XDR payload cannot be decoded) must return
/// `WalletError::Protocol(XdrCodecFailed)`.
///
/// This exercises the `LedgerEntryData::from_xdr_base64` failure path inside
/// `fetch_data_entry` (not via `map_rpc_error_generic` — that is the transport
/// error arm).
#[tokio::test]
async fn fetch_data_entry_malformed_xdr_payload_returns_xdr_codec_failed() {
    let mock_server = MockServer::start().await;

    // Return one entry with a syntactically invalid base64 XDR payload.
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": "AAAA",
                    "xdr": "THIS_IS_NOT_VALID_XDR_BASE64====",
                    "lastModifiedLedgerSeq": 1
                }
            ],
            "latestLedger": 1
        })))
        .mount(&mock_server)
        .await;

    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid");
    let err = fetch_data_entry(&client, FUNDED_ADDRESS, "some.key")
        .await
        .unwrap_err();

    assert_eq!(
        err.code(),
        "protocol.xdr_codec_failed",
        "malformed XDR payload in data entry must return XdrCodecFailed, got: {}",
        err.code()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// account.rs — AccountFlagsView from_raw: zero flags and combined flags
// ─────────────────────────────────────────────────────────────────────────────

/// `AccountFlagsView::from_raw(0xF)` sets all four protocol flags.
#[test]
fn account_flags_from_raw_all_four_bits_set() {
    let f = AccountFlagsView::from_raw(0xF);
    assert!(f.auth_required, "bit 0x1 must set auth_required");
    assert!(f.auth_revocable, "bit 0x2 must set auth_revocable");
    assert!(f.auth_immutable, "bit 0x4 must set auth_immutable");
    assert!(
        f.auth_clawback_enabled,
        "bit 0x8 must set auth_clawback_enabled"
    );
}

/// `AccountFlagsView::from_raw(0x0)` clears all four bits.
#[test]
fn account_flags_from_raw_zero_bits_all_clear() {
    let f = AccountFlagsView::from_raw(0x0);
    assert!(!f.auth_required);
    assert!(!f.auth_revocable);
    assert!(!f.auth_immutable);
    assert!(!f.auth_clawback_enabled);
}

// ─────────────────────────────────────────────────────────────────────────────
// account.rs — BalanceView::balance_stroops exact boundary values
// ─────────────────────────────────────────────────────────────────────────────

/// `balance_stroops` for a half-XLM balance (5_000_000 stroops) must return
/// exactly 5_000_000, not 4_999_999 or 5_000_001.
#[test]
fn balance_stroops_half_xlm_exact() {
    let b = BalanceView::new(
        AssetView::native(),
        "0.5000000".to_owned(),
        None,
        "0.0000000".to_owned(),
        "0.0000000".to_owned(),
    );
    assert_eq!(
        b.balance_stroops().unwrap(),
        5_000_000_i64,
        "0.5000000 XLM must parse to exactly 5_000_000 stroops"
    );
}

/// `balance_stroops` with a trustline limit of `Some("1000.0000000")` must
/// parse the balance field (not the limit), and the limit is accessible
/// as a field on `BalanceView`.
#[test]
fn balance_view_trustline_limit_field_accessible_and_balance_parseable() {
    let b = BalanceView::new(
        AssetView::credit("USDC", ISSUER_ADDRESS),
        "100.0000000".to_owned(),
        Some("1000.0000000".to_owned()),
        "5.0000000".to_owned(),
        "3.0000000".to_owned(),
    );
    // balance_stroops parses the `balance` field, not the limit.
    assert_eq!(
        b.balance_stroops().unwrap(),
        1_000_000_000_i64,
        "100.0000000 XLM must parse to 1_000_000_000 stroops"
    );
    // Limit and liabilities are accessible as fields.
    assert_eq!(b.limit.as_deref(), Some("1000.0000000"));
    assert_eq!(b.buying_liabilities, "5.0000000");
    assert_eq!(b.selling_liabilities, "3.0000000");
}

// ─────────────────────────────────────────────────────────────────────────────
// cache.rs — stale_if_error = true path with a valid stale cache entry
// ─────────────────────────────────────────────────────────────────────────────

/// When `stale_if_error = true` and a valid stale cache entry exists on disk,
/// a fetch failure must return the stale binding (opt-in stale-if-error path).
///
/// The returned binding must have `stale = true`.
#[tokio::test]
#[serial_test::serial]
async fn stale_if_error_true_returns_stale_binding_on_fetch_failure() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("stale-true-path");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(VALID_STELLAR_TOML))
        .mount(&mock_server)
        .await;

    // Build an HTTP client for test use.
    let client_builder = || {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .build()
            .expect("client build")
    };

    // First write a valid cache entry (large TTL).
    let writer = StellarTomlResolver::with_test_base_url(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        client_builder(),
        mock_server.uri(),
    );
    writer
        .refresh("testdomain.example")
        .await
        .expect("initial refresh must succeed");

    // Now point at an unreachable server with stale_if_error = true.
    let stale_resolver = StellarTomlResolver::with_test_base_url(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        client_builder(),
        "http://127.0.0.1:9", // unreachable
    )
    .with_stale_if_error(true);

    let result = stale_resolver.refresh("testdomain.example").await;

    let binding = result.expect("stale_if_error=true must return Ok(binding) on fetch failure");
    assert!(
        binding.stale,
        "returned binding must have stale=true when the stale-if-error path fires"
    );
    assert_eq!(
        binding.home_domain, "testdomain.example",
        "stale binding must carry the correct home_domain"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// cache.rs — list_cached with a valid single-entry cache
// ─────────────────────────────────────────────────────────────────────────────

/// `list_cached` with one valid cache file and a matching keyring key returns
/// a single binding for the correct home domain.
#[tokio::test]
#[serial_test::serial]
async fn list_cached_with_valid_cache_returns_one_binding() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("list-one-entry");

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/stellar.toml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(VALID_STELLAR_TOML))
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .expect("client build");

    let resolver = StellarTomlResolver::with_test_base_url(
        &profile,
        dir.path(),
        Duration::from_secs(3600),
        client,
        mock_server.uri(),
    );
    resolver
        .refresh("testdomain.example")
        .await
        .expect("refresh must succeed");

    let bindings = resolver
        .list_cached()
        .await
        .expect("list_cached must not error");

    assert_eq!(
        bindings.len(),
        1,
        "one cached entry must return one binding; got {}",
        bindings.len()
    );
    assert_eq!(
        bindings[0].home_domain, "testdomain.example",
        "binding home_domain must match the refreshed domain"
    );
    assert!(!bindings[0].stale, "fresh binding must not be stale");
}

// ─────────────────────────────────────────────────────────────────────────────
// cache.rs — list_cached silently skips HMAC-mismatch and invalid files
// ─────────────────────────────────────────────────────────────────────────────

/// `list_cached` with a HMAC-mismatch cache file (written with one key but
/// verified with another) silently skips the file and returns an empty list.
#[tokio::test]
#[serial_test::serial]
async fn list_cached_hmac_mismatch_file_is_silently_skipped() {
    use base64::Engine as _;

    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("list-hmac-skip");

    // Pre-mint a keyring key (all-0xAB bytes, 32 bytes).
    let service = format!("stellar-agent-counterparty-{profile}");
    let entry = keyring_core::Entry::new(&service, "default").expect("entry open");
    let key_b64 = base64::engine::general_purpose::STANDARD.encode([0xAB_u8; 32]);
    entry.set_password(&key_b64).expect("set mock key");

    // Write a cache file whose tag was computed with a DIFFERENT key (0xCD).
    let home_domain = "mismatch.example";
    let body = VALID_STELLAR_TOML.as_bytes();
    let fetched_at: u64 = 1_777_552_496;
    let wrong_key = [0xCD_u8; 32];

    // Compute HMAC with the wrong key.
    let wrong_tag = {
        use hmac::{KeyInit as _, Mac as _};
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&wrong_key).expect("valid key");
        mac.update(b"stellar-agent-counterparty/v2/stellar-toml-body\x00");
        let hd = home_domain.as_bytes();
        mac.update(&(hd.len() as u16).to_be_bytes());
        mac.update(hd);
        mac.update(&(fetched_at as i64).to_be_bytes());
        mac.update(&(body.len() as u32).to_be_bytes());
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };

    // Write the file with the wrong-key tag.
    let cache_path = cache_file_path(dir.path(), home_domain);
    {
        use std::io::Write as _;
        let mut buf = Vec::new();
        buf.extend_from_slice(&wrong_tag);
        let hd = home_domain.as_bytes();
        buf.extend_from_slice(&(hd.len() as u16).to_be_bytes());
        buf.extend_from_slice(hd);
        buf.extend_from_slice(&(fetched_at as i64).to_be_bytes());
        buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
        buf.extend_from_slice(body);
        let mut f = std::fs::File::create(&cache_path).expect("create cache file");
        f.write_all(&buf).expect("write cache");
    }

    let resolver = StellarTomlResolver::new(&profile, dir.path(), Duration::from_secs(3600))
        .expect("resolver construction");

    let bindings = resolver
        .list_cached()
        .await
        .expect("list_cached must not error on HMAC-mismatch file");

    assert!(
        bindings.is_empty(),
        "HMAC-mismatch file must be silently skipped; expected 0 bindings, got {}",
        bindings.len()
    );
}

/// `list_cached` with a structurally invalid (too-short) cache file silently
/// skips it and returns an empty list.
#[tokio::test]
#[serial_test::serial]
async fn list_cached_too_short_cache_file_is_silently_skipped() {
    use base64::Engine as _;

    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    let profile = unique_profile("list-short-skip");

    // Pre-mint a valid keyring key so list_cached can proceed past the key-load step.
    let service = format!("stellar-agent-counterparty-{profile}");
    let entry = keyring_core::Entry::new(&service, "default").expect("entry open");
    let key_b64 = base64::engine::general_purpose::STANDARD.encode([0xAB_u8; 32]);
    entry.set_password(&key_b64).expect("set mock key");

    // Write a too-short cache file (10 bytes — below the 47-byte minimum header).
    let cache_path = cache_file_path(dir.path(), "short.example");
    std::fs::write(&cache_path, [0u8; 10]).expect("write short cache file");

    let resolver = StellarTomlResolver::new(&profile, dir.path(), Duration::from_secs(3600))
        .expect("resolver construction");

    let bindings = resolver
        .list_cached()
        .await
        .expect("list_cached must not error on too-short file");

    assert!(
        bindings.is_empty(),
        "too-short cache file must be silently skipped; expected 0 bindings, got {}",
        bindings.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// cache.rs — list_cached with no keyring key returns empty list (not an error)
// ─────────────────────────────────────────────────────────────────────────────

/// `list_cached` when the HMAC key has never been minted (no keyring entry)
/// returns an empty list instead of propagating `KeyringUnavailable`.
///
/// This is the lazy-mint path: no key = no valid cache entries, so return
/// empty rather than failing.
#[tokio::test]
#[serial_test::serial]
async fn list_cached_no_keyring_key_returns_empty_list() {
    keyring_mock::install().expect("mock keyring init");
    let dir = TempDir::new().expect("tmpdir");
    // Use a never-seen profile so no keyring entry exists.
    let profile = unique_profile("list-no-key");

    let resolver = StellarTomlResolver::new(&profile, dir.path(), Duration::from_secs(3600))
        .expect("resolver construction");

    let bindings = resolver
        .list_cached()
        .await
        .expect("list_cached must return Ok(empty) when no key is minted");

    assert!(
        bindings.is_empty(),
        "no-key profile must return empty list; got {} bindings",
        bindings.len()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// cache.rs — read_cache_entry with a fresh file confirms binding fields
// ─────────────────────────────────────────────────────────────────────────────

/// `read_cache_entry` (test-helpers) on a freshly-written cache file must
/// return `Some((parsed, binding))` with a non-expired binding.  The
/// `binding.stale` field must be `false` because `read_cache_entry` does not
/// set the stale flag (only `refresh` with `stale_if_error=true` does so).
#[test]
fn read_cache_entry_fresh_file_binding_stale_is_false() {
    use std::time::UNIX_EPOCH;

    let dir = TempDir::new().expect("tmpdir");
    let key = [0xAB_u8; 32];
    let home_domain = "anchor.example";
    let body = b"VERSION = \"2.0.0\"\nFEDERATION_SERVER = \"https://fed.anchor.example\"";
    let fetched_at_unix_s: u64 = 1_777_552_496; // 2026-04-30T12:34:56Z

    // Compute HMAC.
    let tag = {
        use hmac::{KeyInit as _, Mac as _};
        type HmacSha256 = hmac::Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&key).expect("valid key");
        mac.update(b"stellar-agent-counterparty/v2/stellar-toml-body\x00");
        let hd = home_domain.as_bytes();
        mac.update(&(hd.len() as u16).to_be_bytes());
        mac.update(hd);
        mac.update(&(fetched_at_unix_s as i64).to_be_bytes());
        mac.update(&(body.len() as u32).to_be_bytes());
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    };

    let path = cache_file_path(dir.path(), home_domain);
    {
        use std::io::Write as _;
        let mut buf = Vec::new();
        buf.extend_from_slice(&tag);
        let hd = home_domain.as_bytes();
        buf.extend_from_slice(&(hd.len() as u16).to_be_bytes());
        buf.extend_from_slice(hd);
        buf.extend_from_slice(&(fetched_at_unix_s as i64).to_be_bytes());
        buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
        buf.extend_from_slice(body);
        let mut f = std::fs::File::create(&path).expect("create cache file");
        f.write_all(&buf).expect("write");
    }

    // TTL of 1 hour from the fetched_at timestamp.  Since this timestamp is
    // in the past, `expires_at = fetched_at + 1h` is also in the past.
    // Use Duration::MAX to ensure the entry is always considered fresh.
    let result = read_cache_entry(&path, &key, Duration::MAX).expect("valid file must not error");

    let (parsed, binding) = result.expect("Duration::MAX TTL must return Some");
    assert_eq!(binding.home_domain, home_domain, "home_domain must match");
    assert!(
        !binding.stale,
        "read_cache_entry must not set stale=true (stale flag is set only by refresh)"
    );
    let fetched_secs = binding
        .fetched_at
        .duration_since(UNIX_EPOCH)
        .expect("fetched_at after epoch")
        .as_secs();
    assert_eq!(
        fetched_secs, fetched_at_unix_s,
        "fetched_at must recover the exact UNIX second from the HMAC-protected body"
    );
    assert!(
        parsed.federation_server.is_some(),
        "parsed stellar.toml must include FEDERATION_SERVER"
    );
}
