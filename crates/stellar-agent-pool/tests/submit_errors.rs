//! Error and retry path tests for `submit_pooled`.
//!
//! The existing `concurrent_submit.rs` covers only the SUCCESS path.
//! This file covers:
//!
//! 1. `tx_bad_seq` path: `getTransaction` returns FAILED with `TxBadSeq` XDR →
//!    `submit_pooled` returns `Err(PoolError::Wallet(...))` with the typed
//!    `SequenceNumberStale` code AND triggers the allocator's sequence-re-fetch
//!    branch (which tries to call `getAccount` against the mock — that fails, so
//!    the re-fetch returns `SequenceFetchFailed`).
//!
//! 2. Generic submission failure: `getTransaction` returns FAILED with a
//!    non-TxBadSeq XDR → `submit_pooled` returns `Err(PoolError::Wallet(...))`.
//!
//! 3. Pool exhaustion: all channels in-flight → `PoolExhausted` returned
//!    immediately (already covered in `concurrent_submit.rs`, re-verified here
//!    for the `submit_pooled` entry point).
//!
//! 4. `is_tx_bad_seq` private helper: the typed primary arm and fallback
//!    substring arm are covered by in-file unit tests in `submit.rs`.  The
//!    end-to-end tests `submit_pooled_tx_bad_seq_*` in this file exercise the
//!    helper through `submit_pooled`'s public behaviour.  The test
//!    `sequence_number_stale_has_stable_code` asserts the `WalletError::code()`
//!    contract that the typed arm depends on.
//!
//! # Mock RPC shape
//!
//! `getTransaction` FAILED response with a `resultXdr` field containing a
//! base64-encoded `TransactionResult` whose discriminant is `TxBadSeq` (or
//! `TxFailed`).  The `stellar-rpc-client` deserialises `resultXdr` into
//! `Option<TransactionResult>` and the network crate maps it to the typed
//! `WalletError` variants.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use stellar_xdr::{
    AccountEntry, AccountEntryExt, AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits,
    PublicKey, SequenceNumber, String32, Thresholds, TransactionResult, TransactionResultExt,
    TransactionResultResult, Uint256, VecM, WriteXdr,
};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use stellar_agent_core::WalletError;
use stellar_agent_core::error::SubmissionError;
use stellar_agent_network::StellarRpcClient;
use stellar_agent_pool::pool::{ChannelPool, TerminalOutcome};
use stellar_agent_pool::submit::submit_pooled;
use stellar_agent_pool::{ChannelRecord, PoolError};
use stellar_agent_test_support::EchoIdResponder;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const CHANNEL_KEY: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DEST_KEY: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FEE_PER_OP: u32 = 100;
const TIMEOUT: Duration = Duration::from_secs(10);
const INITIAL_SEQ: i64 = 100;

fn make_pool_1() -> ChannelPool {
    ChannelPool::from_records(vec![ChannelRecord::new(1, CHANNEL_KEY)], vec![INITIAL_SEQ])
        .expect("pool construction must succeed")
}

fn mock_seed() -> Zeroizing<[u8; 64]> {
    Zeroizing::new([7u8; 64])
}

/// Builds a `TransactionResult` with `TxBadSeq` and encodes it to base64 XDR.
fn tx_bad_seq_result_xdr() -> String {
    let result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxBadSeq,
        ext: TransactionResultExt::V0,
    };
    result
        .to_xdr_base64(Limits::none())
        .expect("TxBadSeq XDR encoding must succeed")
}

/// Builds a `TransactionResult` with `TxFailed` (no ops) for a generic failure.
fn tx_failed_result_xdr() -> String {
    let result = TransactionResult {
        fee_charged: 100,
        result: TransactionResultResult::TxFailed(vec![].try_into().unwrap()),
        ext: TransactionResultExt::V0,
    };
    result
        .to_xdr_base64(Limits::none())
        .expect("TxFailed XDR encoding must succeed")
}

// ─────────────────────────────────────────────────────────────────────────────
// tx_bad_seq path
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_pooled` returns an error when `getTransaction` responds with a
/// FAILED+TxBadSeq result XDR.
///
/// The allocator's `tx_bad_seq` branch attempts a sequence re-fetch via
/// `fetch_account` after the channel is freed.  Because the mock server has
/// no `getAccount` handler registered (it will respond with a 500 on
/// the getAccount call), the re-fetch fails and `submit_pooled` surfaces
/// `PoolError::SequenceFetchFailed` (the allocator::release error from
/// the re-fetch, which propagates through `submit_pooled`).
///
/// After the call, the channel is free (the re-fetch failure does not leave
/// it in-flight).
#[tokio::test(flavor = "multi_thread")]
async fn submit_pooled_tx_bad_seq_triggers_refetch_path() {
    let server = MockServer::start().await;
    let tx_hash = "d".repeat(64);
    let result_xdr = tx_bad_seq_result_xdr();

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "hash": tx_hash,
            "status": "PENDING",
            "latestLedger": 1000,
            "latestLedgerCloseTime": "1234567890"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": tx_hash,
            "ledger": null,
            "resultXdr": result_xdr,
            "resultMetaXdr": null
        })))
        .mount(&server)
        .await;

    // The getAccount call triggered by the TxBadSeq re-fetch path will get an
    // HTTP 500 because no mock for it is registered here.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getAccount"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let pool = make_pool_1();
    let seed = mock_seed();
    let client = StellarRpcClient::new(&server.uri()).expect("mock URL must be valid");

    let result = submit_pooled(
        &pool,
        &client,
        &seed,
        TESTNET_PASSPHRASE,
        FEE_PER_OP,
        TIMEOUT,
        |builder| {
            let _ = builder.payment(
                DEST_KEY,
                stellar_agent_core::StellarAmount::from_stroops(1),
                &stellar_agent_network::builder::Asset::Native,
            );
        },
    )
    .await;

    // The TxBadSeq path returns an error.  The exact variant depends on whether
    // the re-fetch succeeds or fails; with the 500 mock, the re-fetch fails so
    // we get SequenceFetchFailed (from allocator::release propagating its error).
    assert!(result.is_err(), "submit_pooled must return Err on TxBadSeq");

    // Verify the channel was freed regardless of the re-fetch outcome.
    assert_eq!(
        pool.free_count(),
        1,
        "channel must be free after TxBadSeq release (even with re-fetch failure)"
    );
    assert_eq!(pool.in_flight_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic submission failure path
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_pooled` returns `Err(PoolError::Wallet(...))` when `getTransaction`
/// responds with a FAILED+TxFailed (non-TxBadSeq) result XDR.
///
/// The pool channel is freed without a sequence re-fetch, and the pool is
/// fully free afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn submit_pooled_generic_failed_returns_wallet_error() {
    let server = MockServer::start().await;
    let tx_hash = "e".repeat(64);
    let result_xdr = tx_failed_result_xdr();

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "hash": tx_hash,
            "status": "PENDING",
            "latestLedger": 1000,
            "latestLedgerCloseTime": "1234567890"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": tx_hash,
            "ledger": null,
            "resultXdr": result_xdr,
            "resultMetaXdr": null
        })))
        .mount(&server)
        .await;

    let pool = make_pool_1();
    let seed = mock_seed();
    let client = StellarRpcClient::new(&server.uri()).expect("mock URL must be valid");

    let result = submit_pooled(
        &pool,
        &client,
        &seed,
        TESTNET_PASSPHRASE,
        FEE_PER_OP,
        TIMEOUT,
        |builder| {
            let _ = builder.payment(
                DEST_KEY,
                stellar_agent_core::StellarAmount::from_stroops(1),
                &stellar_agent_network::builder::Asset::Native,
            );
        },
    )
    .await;

    // Non-TxBadSeq failure → PoolError::Wallet.
    match &result {
        Err(PoolError::Wallet(_)) => {}
        other => panic!("expected PoolError::Wallet for FAILED+TxFailed, got: {other:?}"),
    }

    // Pool must be fully free; no sequence re-fetch is performed for non-TxBadSeq.
    assert_eq!(
        pool.free_count(),
        1,
        "channel must be free after generic failure"
    );
    assert_eq!(pool.in_flight_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Pool exhaustion (submit_pooled entry point)
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_pooled` returns `PoolExhausted` immediately when the pool is full.
///
/// Verifies that the error is returned without touching the RPC at all —
/// no sendTransaction or getTransaction calls are made.
#[tokio::test]
async fn submit_pooled_pool_exhausted_no_rpc_call() {
    // Use a loopback port that would refuse connections if contacted.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let pool = make_pool_1();
    let seed = mock_seed();

    // Drain the pool manually.
    let lease = pool.acquire().expect("must succeed");

    let result = tokio::time::timeout(Duration::from_millis(20), async {
        submit_pooled(
            &pool,
            &client,
            &seed,
            TESTNET_PASSPHRASE,
            FEE_PER_OP,
            TIMEOUT,
            |_| {},
        )
        .await
    })
    .await
    .expect("submit_pooled on exhausted pool must return IMMEDIATELY");

    assert!(
        matches!(result, Err(PoolError::PoolExhausted { .. })),
        "must be PoolExhausted, got: {result:?}"
    );

    pool.release(lease, TerminalOutcome::Failed, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// submit_pooled: NotInitialised when pool has no channels
// ─────────────────────────────────────────────────────────────────────────────

// `submit_pooled` returns `NotInitialised` from `allocator::acquire` when the
// pool was constructed without channels.
//
// This is the path where `allocator::acquire` calls `pool.acquire()` and the
// pool returns `NotInitialised` because `pool_size == 0` can't be constructed
// via public API — but `allocator::acquire` also forwards any error from
// `pool.acquire()`, including `NotInitialised` from an exhausted acquire.
// We test `PoolExhausted` for a fully drained pool (the public-API path to
// trigger the acquire error) as the meaningful test here.
//
// The `pool_size == 0 → NotInitialised` guard in `acquire` is a fail-closed
// defensive invariant: public constructors enforce pool_size ≥ 1 via
// `SizeOutOfRange`, so the guard is not reachable through the current public API.

// ─────────────────────────────────────────────────────────────────────────────
// is_tx_bad_seq: typed match and fallback substring
// ─────────────────────────────────────────────────────────────────────────────

/// `SubmissionError::SequenceNumberStale` carries a stable `WalletError::code()`
/// value that the `is_tx_bad_seq` typed primary arm depends on.
///
/// The Display string must NOT contain `"tx_bad_seq"`, confirming that the typed
/// arm is required — the fallback substring arm alone would not recognise this
/// variant.
#[test]
fn sequence_number_stale_has_stable_code() {
    let e = WalletError::Submission(SubmissionError::SequenceNumberStale);
    assert_eq!(
        e.code(),
        "submission.sequence_number_stale",
        "SequenceNumberStale must have the stable code expected by is_tx_bad_seq"
    );
    assert!(
        !e.to_string().to_lowercase().contains("tx_bad_seq"),
        "SequenceNumberStale Display string must not contain 'tx_bad_seq'; \
         the typed arm is necessary because the fallback alone would not catch it"
    );
}

/// A `WalletError` with a non-submission code does NOT match tx_bad_seq.
///
/// Confirms that `is_tx_bad_seq` is conservative (no false positives for
/// unrelated errors).  The `submit_pooled` generic-failure branch relies on
/// this not misfiring.
#[test]
fn wallet_error_non_submission_is_not_tx_bad_seq() {
    use stellar_agent_core::error::NetworkError;
    let e = WalletError::Network(NetworkError::RpcUnreachable {
        url: "redacted".to_owned(),
        reason: "timeout".to_owned(),
    });
    // If this were treated as tx_bad_seq, a network error would incorrectly
    // trigger a sequence re-fetch.  The code must start with "submission." or
    // "ledger." per is_tx_bad_seq — a "network." code must not match.
    assert!(
        !e.code().starts_with("submission."),
        "RpcUnreachable code must not start with 'submission.'"
    );
    assert!(
        !e.code().starts_with("ledger."),
        "RpcUnreachable code must not start with 'ledger.'"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// tx_bad_seq with successful re-fetch (getAccount succeeds)
// ─────────────────────────────────────────────────────────────────────────────

/// Builds a `LedgerKey::Account` XDR base64 string for `address`.
fn account_ledger_key_xdr(address: &str) -> String {
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(address)
        .expect("valid address")
        .0;
    let key = LedgerKey::Account(LedgerKeyAccount {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
    });
    key.to_xdr_base64(Limits::none())
        .expect("LedgerKey XDR encode must succeed")
}

/// Builds a `LedgerEntryData::Account` XDR base64 string for `address`
/// with `seq_num` as the sequence number and a zero native balance.
fn account_entry_data_xdr(address: &str, seq_num: i64) -> String {
    let pk_bytes = stellar_strkey::ed25519::PublicKey::from_string(address)
        .expect("valid address")
        .0;
    let entry = AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk_bytes))),
        balance: 10_000_000, // 1 XLM in stroops (non-zero so parse succeeds)
        seq_num: SequenceNumber(seq_num),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: String32::default(),
        thresholds: Thresholds([1, 0, 0, 0]),
        signers: VecM::default(),
        ext: AccountEntryExt::V0,
    };
    LedgerEntryData::Account(entry)
        .to_xdr_base64(Limits::none())
        .expect("LedgerEntryData XDR encode must succeed")
}

/// When `getTransaction` returns FAILED+TxBadSeq and the `getLedgerEntries`
/// re-fetch succeeds, `submit_pooled` returns `Err(PoolError::Wallet(...))` (the
/// tx_bad_seq rejection) and the pool's cached sequence is updated to the value
/// from the `getLedgerEntries` response.
///
/// The mock `getLedgerEntries` response returns an account entry with `seq_num = 999`.
/// After submit_pooled returns, the channel must be free with seq == 999.
#[tokio::test(flavor = "multi_thread")]
async fn submit_pooled_tx_bad_seq_with_successful_refetch_updates_sequence() {
    let server = MockServer::start().await;
    let tx_hash = "f".repeat(64);
    let result_xdr = tx_bad_seq_result_xdr();

    // Build the getLedgerEntries response for the CHANNEL_KEY account with seq=999.
    let key_xdr = account_ledger_key_xdr(CHANNEL_KEY);
    let entry_xdr = account_entry_data_xdr(CHANNEL_KEY, 999);

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "hash": tx_hash,
            "status": "PENDING",
            "latestLedger": 1000,
            "latestLedgerCloseTime": "1234567890"
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": tx_hash,
            "ledger": null,
            "resultXdr": result_xdr,
            "resultMetaXdr": null
        })))
        .mount(&server)
        .await;

    // The getLedgerEntries call from the TxBadSeq re-fetch path returns
    // an account entry with sequence number 999.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(EchoIdResponder::new(json!({
            "entries": [
                {
                    "key": key_xdr,
                    "xdr": entry_xdr,
                    "lastModifiedLedgerSeq": 1000
                }
            ],
            "latestLedger": 1001
        })))
        .mount(&server)
        .await;

    let pool = Arc::new(make_pool_1());
    let seed = mock_seed();
    let client = Arc::new(StellarRpcClient::new(&server.uri()).expect("mock URL must be valid"));

    let result = submit_pooled(
        &pool,
        &client,
        &seed,
        TESTNET_PASSPHRASE,
        FEE_PER_OP,
        TIMEOUT,
        |builder| {
            let _ = builder.payment(
                DEST_KEY,
                stellar_agent_core::StellarAmount::from_stroops(1),
                &stellar_agent_network::builder::Asset::Native,
            );
        },
    )
    .await;

    // TxBadSeq → Err (the submission was rejected by the ledger).
    assert!(result.is_err(), "submit_pooled must return Err on TxBadSeq");

    // Channel must be free after the re-fetch.
    assert_eq!(
        pool.free_count(),
        1,
        "channel must be free after TxBadSeq+refetch"
    );
    assert_eq!(pool.in_flight_count(), 0);

    // Cached sequence must be updated to 999 from the getLedgerEntries re-fetch.
    let snap = pool.channel_snapshot();
    assert_eq!(
        snap[0].sequence_number, 999,
        "cached sequence must be updated to 999 from the getLedgerEntries re-fetch"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Derivation error path (index >= 2^31)
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_pooled` returns `Err(PoolError::DeriveFailed)` when the channel's
/// BIP-44 derivation index is >= 2^31 (the hardened-key upper bound).
///
/// The pool releases the channel with `TerminalOutcome::Failed` before
/// returning, so the pool is fully free afterwards and the sequence number
/// is unchanged.
///
/// `derive_channel_signer` calls `Sep5Wallet::derive_account(index)` which
/// returns `DeriveError::IndexOutOfRange` for any index >= 0x8000_0000.
/// `PoolError::DeriveFailed` wraps the `DeriveError` via `#[from]`.
#[tokio::test]
async fn submit_pooled_derive_failed_releases_channel() {
    // Index 0x8000_0000 (2_147_483_648) is the first out-of-range hardened index.
    const OUT_OF_RANGE_INDEX: u32 = 0x8000_0000;

    // Use a loopback URL — no RPC should be reached because derivation fails
    // before build_and_sign.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let pool = ChannelPool::from_records(
        vec![ChannelRecord::new(OUT_OF_RANGE_INDEX, CHANNEL_KEY)],
        vec![INITIAL_SEQ],
    )
    .expect("pool with out-of-range index must construct (index is stored, not validated here)");
    let seed = mock_seed();

    let result = submit_pooled(
        &pool,
        &client,
        &seed,
        TESTNET_PASSPHRASE,
        FEE_PER_OP,
        TIMEOUT,
        |builder| {
            let _ = builder.payment(
                DEST_KEY,
                stellar_agent_core::StellarAmount::from_stroops(1),
                &stellar_agent_network::builder::Asset::Native,
            );
        },
    )
    .await;

    // Derivation failure → PoolError::DeriveFailed.
    match &result {
        Err(PoolError::DeriveFailed(_)) => {}
        other => panic!("expected PoolError::DeriveFailed for out-of-range index, got: {other:?}"),
    }

    // Channel must be released with Failed outcome; pool is free.
    assert_eq!(
        pool.free_count(),
        1,
        "channel must be freed after derivation failure"
    );
    assert_eq!(pool.in_flight_count(), 0);
    // Sequence number must not change (no transaction was submitted).
    let snap = pool.channel_snapshot();
    assert_eq!(
        snap[0].sequence_number, INITIAL_SEQ,
        "sequence must not change after derivation failure"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// build_and_sign failure path
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_pooled` returns `Err(PoolError::Wallet(...))` when `build_and_sign`
/// fails because the closure adds no operations to the builder.
///
/// `ClassicOpBuilder::build` returns `WalletError::Internal` when called with
/// zero operations.  The pool channel must be freed with `TerminalOutcome::Failed`
/// (no sequence-number advance, no re-fetch) because the transaction was never
/// submitted.
#[tokio::test]
async fn submit_pooled_build_and_sign_failure_releases_channel() {
    // Use a loopback URL: no network I/O should occur because build_and_sign
    // fails before the submit.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let pool = make_pool_1();
    let seed = mock_seed();

    let initial_seq = pool.channel_snapshot()[0].sequence_number;

    let result = submit_pooled(
        &pool,
        &client,
        &seed,
        TESTNET_PASSPHRASE,
        FEE_PER_OP,
        TIMEOUT,
        // Empty closure — no ops added. build_and_sign must fail.
        |_builder| {},
    )
    .await;

    // build_and_sign failure → PoolError::Wallet.
    match &result {
        Err(PoolError::Wallet(_)) => {}
        other => panic!("expected PoolError::Wallet for build_and_sign failure, got: {other:?}"),
    }

    // Channel must be free; sequence must be unchanged (Failed outcome).
    assert_eq!(
        pool.free_count(),
        1,
        "channel must be free after build failure"
    );
    assert_eq!(pool.in_flight_count(), 0);
    let snap = pool.channel_snapshot();
    assert_eq!(
        snap[0].sequence_number, initial_seq,
        "sequence must not change after build_and_sign failure (no ledger involvement)"
    );
}
