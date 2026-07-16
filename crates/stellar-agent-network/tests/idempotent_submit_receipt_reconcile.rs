//! Integration tests targeting receipt-status branches and reconciliation paths
//! in `idempotent_submit`.
//!
//! Covers:
//! - Mainnet passphrase guard fires before any RPC call
//! - Invalid base64 and invalid XDR rejection
//! - Cached `Failed`, `Ambiguous`, and `Reorged` terminal receipts returned
//!   without RPC calls (`receipt_to_result` Failed/Ambiguous/Reorged arms)
//! - `reconcile_receipt` with a missing entry (returns Pending)
//! - `reconcile_receipt` on non-Success receipts (no-op: Ambiguous, Failed, Reorged)
//! - `reconcile_receipt` with `prior_ledger > latest_ledger` (impossible) → Ambiguous
//! - `reconcile_receipt` second NOT_FOUND but same latest_ledger → Success (2-poll rule)
//! - `reconcile_receipt` getHealth fails on NOT_FOUND → Ambiguous
//! - `reconcile_receipt` unexpected getTransaction status for Success → unchanged
//! - Winner-path: unexpected getTransaction status → RpcUnreachable error

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "integration test"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::StellarAmount;
use stellar_agent_core::error::{ErrorCategory, ProtocolError, WalletError};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::idempotent_submit::{reconcile_receipt, submit_transaction_idempotent};
use stellar_agent_network::signing::software::SoftwareSigningKey;
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const SRC_ACCOUNT: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const DST_ACCOUNT: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
const FAKE_TX_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FAKE_LEDGER: u32 = 1234;
const RECORDED_AT_LEDGER: u32 = 100;

/// Builds and signs a test V1 envelope using seed `[3u8; 32]`.  Distinct from
/// seeds used in other test files to avoid hash collisions between test stores.
async fn build_signed_envelope() -> String {
    let key = SoftwareSigningKey::new_from_bytes([3u8; 32]);
    let mut builder = ClassicOpBuilder::new(SRC_ACCOUNT, 300, TESTNET_PASSPHRASE, 300);
    builder
        .payment(
            DST_ACCOUNT,
            StellarAmount::from_stroops(7_000_000),
            &Asset::Native,
        )
        .unwrap();
    builder.build_and_sign(&key).await.unwrap()
}

/// Computes the SHA-256 envelope hash (the idempotency key) for a signed XDR.
fn envelope_hash_for(signed_xdr: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signed_xdr.trim())
        .unwrap();
    Sha256::digest(&bytes)
        .iter()
        .fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn open_store(dir: &tempfile::TempDir, name: &str) -> ReceiptStore {
    ReceiptStore::open_at(dir.path(), name).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Mainnet passphrase guard
// ─────────────────────────────────────────────────────────────────────────────

/// `submit_transaction_idempotent` with the mainnet passphrase returns
/// `MainnetWriteForbidden` before any receipt is written or any RPC call is made.
///
/// The mainnet guard fires at the `submit_transaction_idempotent` entry point,
/// before the envelope decode, the receipt-store read, and `try_begin`; the
/// retention-poll winner path repeats it defence-in-depth.  A valid signed V1
/// envelope keeps every later refusal path out of play, so the zero-request
/// and empty-store assertions pin the entry-point guard specifically: were it
/// absent, `try_begin` would write a Pending receipt before the inner guard
/// refused.
#[tokio::test]
async fn mainnet_passphrase_rejected_mainnet_write_forbidden() {
    let signed_xdr = build_signed_envelope().await;
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "mainnet-guard-test");

    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        &signed_xdr,
        Duration::from_secs(5),
        MAINNET_PASSPHRASE,
        &store,
        RECORDED_AT_LEDGER,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(WalletError::Network(
                stellar_agent_core::error::NetworkError::MainnetWriteForbidden
            ))
        ),
        "mainnet passphrase must produce MainnetWriteForbidden; got: {result:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC call must occur when the mainnet guard fires"
    );
    let envelope_hash = envelope_hash_for(&signed_xdr);
    assert!(
        store.get(&envelope_hash).unwrap().is_none(),
        "no receipt must be written when the entry-point mainnet guard fires"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Invalid base64 input
// ─────────────────────────────────────────────────────────────────────────────

/// Passing a string that is not valid base64 to `submit_transaction_idempotent`
/// is rejected immediately with `ProtocolError::XdrCodecFailed` containing
/// "base64", before any receipt is written or RPC call is made.
#[tokio::test]
async fn invalid_base64_rejected_with_xdr_codec_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "invalid-b64-test");
    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        "!!!not-base64!!!",
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        &store,
        0,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(WalletError::Protocol(ProtocolError::XdrCodecFailed {
                ref detail
            })) if detail.contains("base64")
        ),
        "invalid base64 must produce XdrCodecFailed mentioning 'base64'; got: {result:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC calls must occur on invalid base64 input"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Valid base64 but invalid XDR
// ─────────────────────────────────────────────────────────────────────────────

/// Valid base64 encoding of bytes that are not a valid `TransactionEnvelope` XDR
/// is rejected with `ProtocolError::XdrCodecFailed` before any receipt is written.
#[tokio::test]
async fn valid_base64_of_invalid_xdr_rejected() {
    use base64::Engine as _;
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "invalid-xdr-test");
    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // 16 bytes that form valid base64 but are not valid XDR.
    let not_xdr = base64::engine::general_purpose::STANDARD.encode(b"notvalidxdr12345");

    let result = submit_transaction_idempotent(
        &client,
        &not_xdr,
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        &store,
        0,
    )
    .await;

    assert!(
        matches!(
            result,
            Err(WalletError::Protocol(ProtocolError::XdrCodecFailed { .. }))
        ),
        "invalid XDR must produce XdrCodecFailed; got: {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cached terminal receipts: receipt_to_result branches
// ─────────────────────────────────────────────────────────────────────────────

/// A cached terminal `Failed` receipt is returned without any `sendTransaction`
/// call.  The error carries the stored failure code.
///
/// Exercises the `ReceiptStatus::Failed { code }` arm of `receipt_to_result`.
#[tokio::test]
async fn cached_failed_receipt_returned_without_rpc_call() {
    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "cached-failed-test");

    store
        .try_begin(&envelope_hash, FAKE_TX_HASH, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(
            &envelope_hash,
            ReceiptStatus::Failed {
                code: "ledger.insufficient_balance".to_owned(),
            },
            None,
        )
        .unwrap();

    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        &signed_xdr,
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        &store,
        RECORDED_AT_LEDGER,
    )
    .await;

    let err = result.expect_err("cached Failed receipt must produce Err");
    // A cached on-chain failure is a deterministic, non-retryable outcome: it
    // must be categorised as Submission (NOT Network/retryable) and preserve the
    // original wire code recorded at submission time.
    assert_eq!(
        err.category(),
        ErrorCategory::Submission,
        "cached on-chain failure must be Submission, not a retryable Network error; got code={}",
        err.code()
    );
    assert_eq!(err.code(), "submission.on_chain_failed");
    assert!(
        format!("{err:?}").contains("ledger.insufficient_balance"),
        "the original wire code must be preserved; got: {err:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC call must occur for a cached terminal Failed receipt"
    );
}

/// A cached terminal `Ambiguous` receipt is returned without any `sendTransaction`
/// call.  The error mentions "ambiguous".
///
/// Exercises the `ReceiptStatus::Ambiguous` arm of `receipt_to_result`.
#[tokio::test]
async fn cached_ambiguous_receipt_returned_without_rpc_call() {
    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "cached-ambiguous-test");

    store
        .try_begin(&envelope_hash, FAKE_TX_HASH, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(&envelope_hash, ReceiptStatus::Ambiguous, None)
        .unwrap();

    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        &signed_xdr,
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        &store,
        RECORDED_AT_LEDGER,
    )
    .await;

    assert!(
        result.is_err(),
        "cached Ambiguous receipt must produce Err; got: {result:?}"
    );
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("ambiguous"),
        "error must mention 'ambiguous'; got: {err_str}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC call must occur for a cached terminal Ambiguous receipt"
    );
}

/// A cached terminal `Reorged` receipt is returned without any `sendTransaction`
/// call.  The error mentions "reorged" or "rewound".
///
/// Exercises the `ReceiptStatus::Reorged` arm of `receipt_to_result`.
#[tokio::test]
async fn cached_reorged_receipt_returned_without_rpc_call() {
    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "cached-reorged-test");

    store
        .try_begin(&envelope_hash, FAKE_TX_HASH, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    // finalize_reorged requires the receipt to be Success first.
    store
        .finalize(&envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();
    store.finalize_reorged(&envelope_hash).unwrap();

    let r = store.get(&envelope_hash).unwrap().unwrap();
    assert_eq!(r.status, ReceiptStatus::Reorged);

    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        &signed_xdr,
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        &store,
        RECORDED_AT_LEDGER,
    )
    .await;

    assert!(
        result.is_err(),
        "cached Reorged receipt must produce Err; got: {result:?}"
    );
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("reorged") || err_str.contains("rewound"),
        "error must mention re-org; got: {err_str}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC call must occur for a cached terminal Reorged receipt"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// reconcile_receipt: missing entry → Pending (no-op)
// ─────────────────────────────────────────────────────────────────────────────

/// `reconcile_receipt` for an envelope hash that has no entry in the store
/// returns `Pending` and makes no RPC calls.
#[tokio::test]
async fn reconcile_receipt_missing_entry_returns_pending() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-missing-test");
    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(
        &client,
        &store,
        "0100010001000100010001000100010001000100010001000100010001000100",
    )
    .await
    .unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Pending,
        "missing entry must return Pending; got: {status:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC calls for a missing entry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// reconcile_receipt: non-Success receipts are no-ops
// ─────────────────────────────────────────────────────────────────────────────

/// `reconcile_receipt` on an `Ambiguous` receipt returns `Ambiguous` unchanged
/// without calling `getTransaction`.
#[tokio::test]
async fn reconcile_receipt_noop_on_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-ambiguous-noop");

    let hash = "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
    store
        .try_begin(hash, FAKE_TX_HASH, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(hash, ReceiptStatus::Ambiguous, None)
        .unwrap();

    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(&client, &store, hash).await.unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Ambiguous,
        "must return Ambiguous unchanged; got: {status:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

/// `reconcile_receipt` on a `Failed` receipt returns `Failed` unchanged without
/// calling `getTransaction`.
#[tokio::test]
async fn reconcile_receipt_noop_on_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-failed-noop");

    let hash = "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1";
    store
        .try_begin(hash, FAKE_TX_HASH, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(
            hash,
            ReceiptStatus::Failed {
                code: "ledger.insufficient_balance".to_owned(),
            },
            None,
        )
        .unwrap();

    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(&client, &store, hash).await.unwrap();

    assert!(
        matches!(status, ReceiptStatus::Failed { ref code } if code == "ledger.insufficient_balance"),
        "must return Failed unchanged; got: {status:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

/// `reconcile_receipt` on a `Reorged` receipt returns `Reorged` unchanged
/// without calling `getTransaction`.
#[tokio::test]
async fn reconcile_receipt_noop_on_reorged() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-reorged-noop");

    let hash = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";
    store
        .try_begin(hash, FAKE_TX_HASH, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();
    store.finalize_reorged(hash).unwrap();
    assert_eq!(
        store.get(hash).unwrap().unwrap().status,
        ReceiptStatus::Reorged
    );

    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(&client, &store, hash).await.unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Reorged,
        "must return Reorged unchanged; got: {status:?}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// reconcile_receipt: prior_ledger > latest_ledger → Ambiguous
// ─────────────────────────────────────────────────────────────────────────────

/// When `getTransaction` returns NOT_FOUND for a Success receipt whose
/// confirmation ledger (9000) is NUMERICALLY HIGHER than `getHealth`'s
/// `latest_ledger` (500), the state is impossible (a ledger cannot confirm
/// beyond the current chain tip).  `reconcile_receipt` returns `Ambiguous` and
/// does NOT demote to `Reorged`.
///
/// Exercises the `prior > health.latest_ledger` guard in
/// `reconcile_receipt`'s NOT_FOUND arm.
#[tokio::test]
async fn reconcile_receipt_impossible_prior_ledger_returns_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-impossible-ledger");

    let hash = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3";
    store
        .try_begin(hash, FAKE_TX_HASH, 0, RECORDED_AT_LEDGER)
        .unwrap();
    // Confirmed at ledger 9000 — far above what getHealth will claim.
    store
        .finalize(hash, ReceiptStatus::Success, Some(9000))
        .unwrap();

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getTransaction"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 500,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 450
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    // getHealth: latest_ledger=500 < prior_ledger=9000 (impossible state).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getHealth"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 500,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 450
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(&client, &store, hash).await.unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Ambiguous,
        "prior_ledger (9000) > latest_ledger (500) must return Ambiguous; got: {status:?}"
    );
    // Must NOT be demoted to Reorged: the state is impossible, not a genuine re-org.
    let r = store.get(hash).unwrap().unwrap();
    assert_ne!(
        r.status,
        ReceiptStatus::Reorged,
        "impossible ledger state must NOT demote to Reorged"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// reconcile_receipt: second NOT_FOUND with no ledger advance → Success (2-poll rule)
// ─────────────────────────────────────────────────────────────────────────────

/// When the first-miss anchor is set and a second NOT_FOUND arrives with
/// `latest_ledger` equal to the anchor (no new ledger has closed), the 2-poll
/// confirmation rule is not yet satisfied: `reconcile_receipt` returns
/// `Success` without demoting to `Reorged`.
///
/// Exercises the `health.latest_ledger < first_miss_ledger.saturating_add(1)`
/// branch in `reconcile_receipt`'s NOT_FOUND arm.
#[tokio::test]
async fn reconcile_receipt_second_not_found_no_ledger_advance_returns_success() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-no-ledger-advance");

    let hash = "e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4";
    store
        .try_begin(hash, FAKE_TX_HASH, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    // Pre-set the first-miss anchor to ledger 3000.
    store.mark_reorg_pending(hash, 3000).unwrap();
    let mid = store.get(hash).unwrap().unwrap();
    assert_eq!(mid.reorg_pending_at_ledger, Some(3000));

    // Second NOT_FOUND with latest_ledger=3000 (same as anchor; no ledger closed).
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getTransaction"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 3000,
            "latestLedgerCloseTime": "1700000002",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 2950
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getHealth"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 3000,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 2950
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let status = reconcile_receipt(&client, &store, hash).await.unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Success,
        "second NOT_FOUND with no ledger advance must return Success (2-poll rule); got: {status:?}"
    );
    let r = store.get(hash).unwrap().unwrap();
    assert_ne!(
        r.status,
        ReceiptStatus::Reorged,
        "must not demote when ledger has not advanced"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// reconcile_receipt: getHealth error on NOT_FOUND → Ambiguous
// ─────────────────────────────────────────────────────────────────────────────

/// When `getTransaction` returns NOT_FOUND and `getHealth` returns a JSON-RPC
/// error (cannot be parsed as `GetHealthResponse`), `reconcile_receipt` cannot
/// distinguish retention-drop from re-org and returns `Ambiguous`.
///
/// Exercises the `Err(e)` arm of `client.get_health().await` in
/// `reconcile_receipt`'s NOT_FOUND arm.
#[tokio::test]
async fn reconcile_receipt_health_error_on_not_found_returns_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-health-fail");

    let hash = "f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5";
    store
        .try_begin(hash, FAKE_TX_HASH, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getTransaction"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 600,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 550
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    // getHealth returns a JSON-RPC result that cannot be deserialized as
    // GetHealthResponse (missing required fields), which stellar-rpc-client
    // surfaces as a parse error, triggering the Err branch in reconcile_receipt.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getHealth"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "not_a_health_response": true
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let status = reconcile_receipt(&client, &store, hash).await.unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Ambiguous,
        "getHealth error on NOT_FOUND must return Ambiguous; got: {status:?}"
    );
    // The store must NOT have been demoted to Reorged (health failure is not evidence of re-org).
    let r = store.get(hash).unwrap().unwrap();
    assert_ne!(
        r.status,
        ReceiptStatus::Reorged,
        "store must not be demoted to Reorged on health failure"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// reconcile_receipt: unexpected getTransaction status for Success → unchanged
// ─────────────────────────────────────────────────────────────────────────────

/// When `getTransaction` returns an unexpected status (neither SUCCESS nor
/// NOT_FOUND) for a previously-Success receipt, `reconcile_receipt` logs a
/// warning and returns the current `Success` status unchanged.
///
/// Exercises the `other =>` arm in `reconcile_receipt`'s status match.
#[tokio::test]
async fn reconcile_receipt_unexpected_get_transaction_status_returns_success_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "reconcile-unexpected-status");

    let hash = "9191919191919191919191919191919191919191919191919191919191919191";
    store
        .try_begin(hash, FAKE_TX_HASH, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    let server = MockServer::start().await;

    // "PROCESSING" is not a real Stellar getTransaction status; exercises the `other` arm.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getTransaction"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "PROCESSING",
            "latestLedger": 600,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 550
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let status = reconcile_receipt(&client, &store, hash).await.unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Success,
        "unexpected getTransaction status must return current Success unchanged; got: {status:?}"
    );
    let r = store.get(hash).unwrap().unwrap();
    assert_eq!(
        r.status,
        ReceiptStatus::Success,
        "store must remain Success after unexpected status"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Winner path: unexpected getTransaction status → error
// ─────────────────────────────────────────────────────────────────────────────

/// When `submit_with_retention_poll`'s `getTransaction` poll returns an
/// unexpected status (not SUCCESS, FAILED, or NOT_FOUND), the function returns
/// `RpcUnreachable` with the unexpected status string in the reason.
///
/// Exercises the `other =>` arm in `submit_with_retention_poll`'s poll loop.
#[tokio::test]
async fn winner_path_unexpected_get_transaction_status_returns_rpc_error() {
    let signed_xdr = build_signed_envelope().await;
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir, "winner-unexpected-status");

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "sendTransaction"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "hash": FAKE_TX_HASH,
            "status": "PENDING",
            "latestLedger": 1001,
            "latestLedgerCloseTime": "1699999999"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // "DUPLICATE" is not a real poll status and exercises the `other` arm.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getTransaction"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "DUPLICATE",
            "latestLedger": 1002,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 900,
            "ledgerRetentionWindow": 100
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    // Register a getHealth mock so the server does not return empty responses
    // if the poll loop happens to call getHealth before hitting the unexpected status.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(
            json!({"method": "getHealth"}),
        ))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 1002,
            "oldestLedger": 900,
            "ledgerRetentionWindow": 100
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        &signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        RECORDED_AT_LEDGER,
    )
    .await;

    assert!(
        result.is_err(),
        "unexpected getTransaction status must return Err; got: {result:?}"
    );
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("DUPLICATE") || err_str.contains("unexpected"),
        "error must contain the unexpected status or 'unexpected'; got: {err_str}"
    );
}
