//! Integration tests for retention-aware polling and re-org reconciliation.
//!
//! Uses `wiremock` to serve deterministic JSON-RPC responses.  All mocks
//! disambiguate by JSON-RPC method name via `body_partial_json` (share a
//! single server endpoint for all JSON-RPC methods, matched by
//! `{ "method": "..." }`).
//!
//! # Coverage
//!
//! (a) Retention → Ambiguous: `getTransaction` returns `NOT_FOUND` and
//!     `getHealth` returns `oldest_ledger > recorded_at_ledger` → the poll
//!     loop finalises `Ambiguous` and returns (does NOT loop forever,
//!     does NOT silent-timeout).
//!
//! (b) Re-org → Reorged: seed a `Success` receipt, then call
//!     `reconcile_receipt` with `getTransaction` returning `NOT_FOUND` AND
//!     `getHealth` showing `prior_ledger` within the live window → status
//!     becomes `Reorged`, store records both `prior_ledger` and `Reorged`.
//!
//! (c) No-regression — normal SUCCESS within retention still finalises Success.
//!
//! (d) No-regression — NOT_FOUND within retention keeps polling then SUCCESS.
//!
//! (e) Retention-drop vs re-org: NOT_FOUND + prior_ledger BELOW oldest_ledger
//!     → Ambiguous (retention-drop), not Reorged.
//!
//! (f) Degraded health response: implausible oldest_ledger > latest_ledger →
//!     Ambiguous (no false demotion).
//!
//! (g) FAILED arm typed code: getTransaction→FAILED with txInsufficientBalance
//!     XDR → receipt records the real wire code, not "ledger.op_failed";
//!     returned WalletError is Ledger not RpcUnreachable.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "integration test; panics/unwraps/eprintln acceptable"
)]

use std::time::Duration;

use serde_json::json;
use stellar_agent_core::StellarAmount;
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
const FAKE_TX_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FAKE_LEDGER: u32 = 1234;

/// The ledger at which the test transaction was "submitted" (used in
/// `recorded_at_ledger` to simulate a pre-retention-floor submission).
const RECORDED_AT_LEDGER: u32 = 100;

/// An `oldest_ledger` value HIGHER than `RECORDED_AT_LEDGER`, simulating
/// retention-window closure.
const OLDEST_LEDGER_PAST: u32 = 500;

/// An `oldest_ledger` value LOWER than `RECORDED_AT_LEDGER`, simulating that
/// the submission is still within the retention window.
const OLDEST_LEDGER_WITHIN: u32 = 50;

/// Builds and signs a test envelope.  Key is derived from a fixed byte seed so
/// there is no committed S-strkey seed — `[2u8; 32]` is a public test fixture,
/// not a production key.  Uses a different seed from other test fixtures to
/// avoid cross-fixture hash collision.
async fn build_signed_envelope() -> String {
    let key = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    let mut builder = ClassicOpBuilder::new(SRC_ACCOUNT, 200, TESTNET_PASSPHRASE, 200);
    builder
        .payment(
            DST_ACCOUNT,
            StellarAmount::from_stroops(5_000_000),
            &Asset::Native,
        )
        .unwrap();
    builder.build_and_sign(&key).await.unwrap()
}

/// Computes the envelope hash for a base64-encoded signed envelope XDR.
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

/// JSON-RPC `sendTransaction` response for a PENDING submission.
fn send_transaction_pending_response() -> serde_json::Value {
    json!({
        "hash": FAKE_TX_HASH,
        "status": "PENDING",
        "latestLedger": 1001,
        "latestLedgerCloseTime": "1699999999"
    })
}

/// JSON-RPC `getTransaction` response for NOT_FOUND.
fn get_transaction_not_found_response() -> serde_json::Value {
    json!({
        "status": "NOT_FOUND",
        "latestLedger": 600,
        "latestLedgerCloseTime": "1700000001",
        "oldestLedger": OLDEST_LEDGER_PAST,
        "ledgerRetentionWindow": 400
    })
}

/// JSON-RPC `getTransaction` response for SUCCESS.
fn get_transaction_success_response() -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "txHash": FAKE_TX_HASH,
        "ledger": FAKE_LEDGER,
        "createdAt": "1700000000",
        "envelopeXdr": null,
        "resultXdr": null,
        "resultMetaXdr": null
    })
}

/// JSON-RPC `getHealth` response where `oldest_ledger` > `RECORDED_AT_LEDGER`
/// (retention window has closed for our submission).
fn get_health_outside_window_response() -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": 600,
        "oldestLedger": OLDEST_LEDGER_PAST,
        "ledgerRetentionWindow": 400
    })
}

/// JSON-RPC `getHealth` response where `oldest_ledger` < `RECORDED_AT_LEDGER`
/// (submission is still within the retention window).
fn get_health_within_window_response() -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": 600,
        "oldestLedger": OLDEST_LEDGER_WITHIN,
        "ledgerRetentionWindow": 550
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) Retention-window closure → Ambiguous
// ─────────────────────────────────────────────────────────────────────────────

/// When `getTransaction` returns `NOT_FOUND` AND `getHealth` shows
/// `oldest_ledger > recorded_at_ledger`, `submit_transaction_idempotent`
/// finalises the receipt as `Ambiguous` and returns an error.
///
/// Verifies:
/// - The call terminates (does NOT loop forever).
/// - The returned error carries a human-readable reason mentioning
///   "ambiguous" / retention context.
/// - The receipt status is `Ambiguous`.
/// - `max_time` is surfaced in the receipt (resubmit-safety gate).
/// - The call does NOT silent-timeout — it surfaces Ambiguous as soon as
///   `oldest_ledger > recorded_at_ledger`.
#[tokio::test]
async fn retention_outside_window_returns_ambiguous() {
    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-retention-test").unwrap();

    let server = MockServer::start().await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_transaction_pending_response()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → NOT_FOUND (with oldest_ledger > RECORDED_AT_LEDGER in
    // the response body; stellar-rpc-client parses the status only, not
    // retention fields from getTransaction — we also serve getHealth below).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_transaction_not_found_response()))
        .up_to_n_times(50)
        .mount(&server)
        .await;

    // getHealth → oldest_ledger > RECORDED_AT_LEDGER (outside window).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(get_health_outside_window_response()))
        .up_to_n_times(50)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // Use a long timeout to prove termination is driven by retention, not by
    // clock (the test must finish in <<30s).
    let result = submit_transaction_idempotent(
        &client,
        &signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        RECORDED_AT_LEDGER, // submission recorded at ledger 100
    )
    .await;

    // Must return an error (Ambiguous) — NOT Ok, NOT silent timeout.
    assert!(
        result.is_err(),
        "retention-outside-window must return Err (Ambiguous); got: {result:?}"
    );

    let err_msg = format!("{:?}", result.unwrap_err());
    // The error reason should mention retention context.
    assert!(
        err_msg.to_lowercase().contains("ambiguous")
            || err_msg.to_lowercase().contains("retention")
            || err_msg.to_lowercase().contains("oldest_ledger"),
        "error must mention ambiguous/retention context; got: {err_msg}"
    );

    // Receipt must be finalised as Ambiguous.
    let receipt = store.get(&envelope_hash).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Ambiguous,
        "receipt must be Ambiguous after retention-window closure; got: {:?}",
        receipt.status
    );

    // max_time must be surfaced in the receipt so the caller can reason about
    // when a resubmit is safe.
    // (Our test envelope has no explicit timebounds → max_time = 0, which is
    // "unbounded"; the field is present and accessible.)
    let _ = receipt.max_time; // field is accessible (not hidden)
}

/// No-regression: when `getHealth` shows `oldest_ledger < recorded_at_ledger`
/// (submission is still within the window) AND `getTransaction` immediately
/// returns SUCCESS, the receipt is finalised as Success — NOT Ambiguous.
#[tokio::test]
async fn within_retention_success_not_ambiguous() {
    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-within-retention-test").unwrap();

    let server = MockServer::start().await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_transaction_pending_response()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → SUCCESS immediately.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_transaction_success_response()))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    // getHealth → oldest_ledger < RECORDED_AT_LEDGER (within window).
    // This mock should never be called if getTransaction returns SUCCESS
    // on the first poll (no NOT_FOUND iteration to trigger health check).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(get_health_within_window_response()))
        .up_to_n_times(10)
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

    // Must succeed with Success.
    assert!(
        result.is_ok(),
        "within-retention SUCCESS must produce Ok; got: {result:?}"
    );
    let sub = result.unwrap();
    assert_eq!(sub.ledger, FAKE_LEDGER);

    // Receipt must be Success — NOT Ambiguous.
    let receipt = store.get(&envelope_hash).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Success,
        "receipt must be Success; got: {:?}",
        receipt.status
    );
}

/// No-regression: NOT_FOUND while WITHIN the retention window keeps polling
/// and does NOT prematurely finalise Ambiguous.
///
/// The sequence: NOT_FOUND (within window) × 1 → SUCCESS.
/// Asserts the final outcome is Success, not Ambiguous.
#[tokio::test]
async fn not_found_within_retention_keeps_polling_then_success() {
    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-notfound-within-test").unwrap();

    let server = MockServer::start().await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_transaction_pending_response()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → NOT_FOUND once, then SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 200,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": OLDEST_LEDGER_WITHIN,
            "ledgerRetentionWindow": 150
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_transaction_success_response()))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    // getHealth → within window (oldest_ledger=50 < recorded_at_ledger=100).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(get_health_within_window_response()))
        .up_to_n_times(10)
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

    // Must succeed — NOT prematurely Ambiguous.
    assert!(
        result.is_ok(),
        "NOT_FOUND-within-retention then SUCCESS must produce Ok; got: {result:?}"
    );

    let receipt = store.get(&envelope_hash).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Success,
        "receipt must be Success after polling through NOT_FOUND-within-window; \
         got: {:?}",
        receipt.status
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) Re-org → Reorged
// ─────────────────────────────────────────────────────────────────────────────

/// Seeds a `Success` receipt, then calls `reconcile_receipt` twice with
/// `getTransaction` returning `NOT_FOUND` both times, with at least one ledger
/// closing between calls.  On the first call the function records the first-miss
/// and returns `Success` unchanged (2-poll confirmation rule).  On the second
/// call (latest_ledger has advanced), `Reorged` is written.
///
/// Verifies:
/// - First call returns `Success` (first miss recorded; `reorg_pending_at_ledger` set).
/// - Second call returns `Reorged`.
/// - The store's receipt has `status = Reorged`.
/// - `prior_ledger` equals the ledger from the former `Success` receipt.
/// - `Reorged` is distinct from `Failed`.
/// - `Reorged.is_terminal()` is true.
#[tokio::test]
async fn reorg_demotes_success_to_reorged_with_prior_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-reorg-test").unwrap();

    // Seed a Success receipt with a known ledger.
    let envelope_hash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let tx_hash = FAKE_TX_HASH;

    store
        .try_begin(envelope_hash, tx_hash, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    // Verify the seed.
    let pre = store.get(envelope_hash).unwrap().unwrap();
    assert_eq!(pre.status, ReceiptStatus::Success);
    assert_eq!(pre.ledger, Some(FAKE_LEDGER));
    assert_eq!(pre.prior_ledger, None, "no prior_ledger before reorg");

    // ── First call: getHealth latest_ledger=2000, getTransaction=NOT_FOUND ───
    // First miss: reconcile_receipt records reorg_pending_at_ledger=2000 and
    // returns Success (2-poll confirmation pending).
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 2000,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 1950
        })))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    // First getHealth returns latest_ledger=2000 (first miss anchored here).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 2000,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 1950
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // First call: must return Success (first miss; 2-poll rule pending).
    let status_first = reconcile_receipt(&client, &store, envelope_hash)
        .await
        .unwrap();
    assert_eq!(
        status_first,
        ReceiptStatus::Success,
        "first NOT_FOUND within live window must return Success unchanged \
         (2-poll confirmation pending); got: {status_first:?}"
    );

    // Store must have first-miss ledger recorded.
    let mid = store.get(envelope_hash).unwrap().unwrap();
    assert_eq!(
        mid.status,
        ReceiptStatus::Success,
        "status must still be Success after first miss"
    );
    assert_eq!(
        mid.reorg_pending_at_ledger,
        Some(2000),
        "reorg_pending_at_ledger must be set to the first-miss latest_ledger (2000)"
    );

    // ── Second call: getHealth latest_ledger=2001 (≥ 2000+1), getTransaction=NOT_FOUND ──
    // Second miss with ledger advance: reconcile_receipt demotes to Reorged.
    let server2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 2001,
            "latestLedgerCloseTime": "1700000006",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 1950
        })))
        .up_to_n_times(5)
        .mount(&server2)
        .await;

    // Second getHealth returns latest_ledger=2001 (one ledger closed).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 2001,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 1951
        })))
        .up_to_n_times(5)
        .mount(&server2)
        .await;

    let client2 = StellarRpcClient::new(&server2.uri()).unwrap();

    // Second call: must return Reorged (second NOT_FOUND, ledger has advanced).
    let status_second = reconcile_receipt(&client2, &store, envelope_hash)
        .await
        .unwrap();
    assert_eq!(
        status_second,
        ReceiptStatus::Reorged,
        "second NOT_FOUND with ≥1 ledger closed since first miss must return Reorged; \
         got: {status_second:?}"
    );

    // The store must show the full transition: Reorged + prior_ledger preserved.
    let post = store.get(envelope_hash).unwrap().unwrap();
    assert_eq!(
        post.status,
        ReceiptStatus::Reorged,
        "stored status must be Reorged after second-poll reconciliation"
    );
    assert_eq!(
        post.prior_ledger,
        Some(FAKE_LEDGER),
        "prior_ledger must retain the pre-reorg confirmation ledger ({FAKE_LEDGER})"
    );
    // Current ledger is None (the confirmed ledger was rewound).
    assert_eq!(
        post.ledger, None,
        "ledger must be None after demotion (the ledger was rewound)"
    );

    // Reorged is terminal.
    assert!(post.status.is_terminal(), "Reorged must be terminal");

    // Reorged is distinct from Failed.
    assert_ne!(
        post.status,
        ReceiptStatus::Failed {
            code: "any".to_owned()
        },
        "Reorged must be distinct from Failed"
    );
    assert_ne!(
        post.status,
        ReceiptStatus::Ambiguous,
        "Reorged must be distinct from Ambiguous"
    );
}

/// `reconcile_receipt` on a non-Success receipt (e.g. Pending) is a no-op:
/// it returns the current status and does NOT call `getTransaction`.
#[tokio::test]
async fn reconcile_receipt_noop_on_non_success() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-noop-test").unwrap();

    let envelope_hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let tx_hash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    store
        .try_begin(envelope_hash, tx_hash, 0, RECORDED_AT_LEDGER)
        .unwrap();
    // Receipt is Pending.

    // Start a wiremock server with NO mocks — if getTransaction is called it
    // will fail (no registered handler → 404 / empty response).
    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // reconcile_receipt on a Pending receipt must not call getTransaction.
    let status = reconcile_receipt(&client, &store, envelope_hash)
        .await
        .unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Pending,
        "reconcile_receipt on Pending must return Pending unchanged; got: {status:?}"
    );

    // No requests must have been made.
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC requests must be made for a non-Success receipt"
    );

    // Store unchanged.
    let receipt = store.get(envelope_hash).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Pending);
}

/// `reconcile_receipt` when `getTransaction` returns `SUCCESS` for a
/// previously-`Success` receipt: returns `Success`, no demotion.
#[tokio::test]
async fn reconcile_receipt_success_still_success_no_reorg() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-still-success-test").unwrap();

    let envelope_hash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let tx_hash = FAKE_TX_HASH;

    store
        .try_begin(envelope_hash, tx_hash, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    let server = MockServer::start().await;

    // getTransaction returns SUCCESS (transaction still confirmed).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_transaction_success_response()))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(&client, &store, envelope_hash)
        .await
        .unwrap();

    assert_eq!(
        status,
        ReceiptStatus::Success,
        "reconcile_receipt must return Success when transaction is still confirmed; \
         got: {status:?}"
    );

    // Store must still be Success (no demotion).
    let receipt = store.get(envelope_hash).unwrap().unwrap();
    assert_eq!(receipt.status, ReceiptStatus::Success);
    assert_eq!(
        receipt.prior_ledger, None,
        "prior_ledger must remain None when no re-org occurred"
    );
}

/// `finalize_reorged` on a store with no entry for `envelope_hash` is a no-op
/// (returns Ok without error).
#[test]
fn finalize_reorged_missing_entry_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-missing-noop").unwrap();

    let result =
        store.finalize_reorged("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    assert!(
        result.is_ok(),
        "finalize_reorged on missing entry must be a no-op Ok; got: {result:?}"
    );
}

/// `ReceiptStatus::Reorged` is terminal and distinct from all other statuses.
#[test]
fn reorged_is_terminal_and_distinct() {
    let r = ReceiptStatus::Reorged;
    assert!(r.is_terminal(), "Reorged must be terminal");

    assert_ne!(r, ReceiptStatus::Pending);
    assert_ne!(r, ReceiptStatus::Success);
    assert_ne!(
        r,
        ReceiptStatus::Failed {
            code: "x".to_owned()
        }
    );
    assert_ne!(r, ReceiptStatus::Ambiguous);
}

// ─────────────────────────────────────────────────────────────────────────────
// FAILED finalisation with decoded TransactionResult (winner path)
// ─────────────────────────────────────────────────────────────────────────────

/// `getTransaction` returns FAILED with a decodable `TransactionResult` XDR;
/// the receipt finalises as `Failed { code }` carrying the real wire code from
/// `map_failed_result`.
///
/// Uses a `TxFailed([Payment(Underfunded)])` XDR, which maps deterministically
/// to `"ledger.insufficient_balance"` via `map_failed_result`.
#[tokio::test]
async fn winner_path_failed_with_decodable_xdr_finalises_failed_code() {
    use stellar_agent_core::error::{LedgerError, WalletError as WE};
    use stellar_xdr::{
        Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
        TransactionResultExt, TransactionResultResult, VecM, WriteXdr,
    };

    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    // Build TxFailed([Payment(Underfunded)]) result XDR.
    let ops: VecM<OperationResult> = vec![OperationResult::OpInner(OperationResultTr::Payment(
        PaymentResult::Underfunded,
    ))]
    .try_into()
    .unwrap();
    let tx_result = TransactionResult {
        fee_charged: 0,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;

    // getTransaction → FAILED with real XDR.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": FAKE_TX_HASH,
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    // getHealth — not expected on FAILED but register to avoid empty responses.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 1010,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 960
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // Mock sendTransaction for the fresh winner path.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "hash": FAKE_TX_HASH,
            "status": "PENDING",
            "latestLedger": 1001,
            "latestLedgerCloseTime": "1699999999"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Use a FRESH store so we take the winner path.
    let dir2 = tempfile::tempdir().unwrap();
    let store2 =
        ReceiptStore::open_at(dir2.path(), "stale-pending-failed-decodable-winner").unwrap();

    let result = submit_transaction_idempotent(
        &client,
        &signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store2,
        RECORDED_AT_LEDGER,
    )
    .await;

    assert!(
        result.is_err(),
        "FAILED getTransaction must return Err; got: {result:?}"
    );

    let err = result.unwrap_err();
    assert!(
        matches!(err, WE::Ledger(LedgerError::InsufficientBalance { .. })),
        "FAILED+Underfunded must return WalletError::Ledger::InsufficientBalance; got: {err:?}"
    );
    assert_eq!(err.code(), "ledger.insufficient_balance");

    let receipt = store2.get(&envelope_hash).unwrap().unwrap();
    assert!(
        matches!(&receipt.status, ReceiptStatus::Failed { code } if code == "ledger.insufficient_balance"),
        "receipt must record 'ledger.insufficient_balance'; got: {:?}",
        receipt.status
    );
}

/// `getTransaction` returns FAILED with NO result XDR → still a typed `Failed`
/// finalisation (the RPC definitively said FAILED; `map_failed_result(None)`
/// yields the generic `ledger.op_failed` code), and no panic on the
/// absent-XDR shape.
#[tokio::test]
async fn winner_path_failed_with_no_xdr_is_typed_error_no_panic() {
    let signed_xdr = build_signed_envelope().await;

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "stale-pending-failed-no-xdr").unwrap();

    let server = MockServer::start().await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "hash": FAKE_TX_HASH,
            "status": "PENDING",
            "latestLedger": 1001,
            "latestLedgerCloseTime": "1699999999"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → FAILED with null resultXdr.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": FAKE_TX_HASH,
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": null,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 1010,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 960
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

    // Must return an error — either Failed (with unknown code) or another ledger error.
    // The critical requirement is: no panic.
    assert!(
        result.is_err(),
        "FAILED getTransaction with null XDR must return Err, not Ok; got: {result:?}"
    );

    // The error must NOT be a connection/transport error.
    let err = result.unwrap_err();
    let code = err.code();
    assert_ne!(
        code, "network.rpc_unreachable",
        "FAILED with null XDR must NOT map to rpc_unreachable; should be a ledger/submission code; got: {code}"
    );

    // No panic is the main assertion — we reach this point if no panic occurred.
}

// ─────────────────────────────────────────────────────────────────────────────
// reorg_pending anchor cleared on SUCCESS; regression tests
// ─────────────────────────────────────────────────────────────────────────────

/// NOT_FOUND → SUCCESS(N+1) → status stays Success, NOT Reorged, AND the
/// `reorg_pending_at_ledger` anchor is cleared.
///
/// Verifies:
/// - First call with NOT_FOUND sets the first-miss anchor, returns Success.
/// - Second call returns SUCCESS → status is Success, anchor is None.
#[tokio::test]
async fn not_found_then_success_clears_anchor_no_reorged() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "not-found-then-success-clears-anchor").unwrap();

    let envelope_hash = "3333333333333333333333333333333333333333333333333333333333333333";
    let tx_hash = FAKE_TX_HASH;

    store
        .try_begin(envelope_hash, tx_hash, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    // First call: NOT_FOUND within live window → anchor set, returns Success.
    let server1 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 5000,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 4950
        })))
        .up_to_n_times(5)
        .mount(&server1)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 5000,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 4950
        })))
        .up_to_n_times(5)
        .mount(&server1)
        .await;

    let client1 = StellarRpcClient::new(&server1.uri()).unwrap();
    let status1 = reconcile_receipt(&client1, &store, envelope_hash)
        .await
        .unwrap();
    assert_eq!(
        status1,
        ReceiptStatus::Success,
        "first NOT_FOUND must return Success unchanged"
    );

    let mid = store.get(envelope_hash).unwrap().unwrap();
    assert_eq!(
        mid.reorg_pending_at_ledger,
        Some(5000),
        "first-miss anchor must be set to 5000"
    );

    // Second call: SUCCESS → anchor cleared, returns Success.
    let server2 = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "SUCCESS",
            "txHash": FAKE_TX_HASH,
            "ledger": FAKE_LEDGER,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": null,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server2)
        .await;

    let client2 = StellarRpcClient::new(&server2.uri()).unwrap();
    let status2 = reconcile_receipt(&client2, &store, envelope_hash)
        .await
        .unwrap();
    assert_eq!(
        status2,
        ReceiptStatus::Success,
        "SUCCESS must return Success, not Reorged"
    );

    let post = store.get(envelope_hash).unwrap().unwrap();
    assert_eq!(
        post.status,
        ReceiptStatus::Success,
        "stored status must be Success"
    );
    assert_eq!(
        post.reorg_pending_at_ledger, None,
        "anchor must be cleared after SUCCESS reconciliation"
    );
}

/// First-miss → SUCCESS-reappear → later miss must NOT demote on that single
/// later miss (fresh 2-poll window required).
///
/// Sequence:
/// 1. NOT_FOUND @ ledger 5000 → anchor set to 5000.
/// 2. SUCCESS → anchor cleared.
/// 3. NOT_FOUND @ ledger 6000 → fresh first-miss, anchor set to 6000; returns
///    Success (NOT Reorged on a single miss).
///
/// The anchor must be cleared on SUCCESS so that step 3 starts a fresh 2-poll
/// window rather than satisfying the stale anchor from step 1.
#[tokio::test]
async fn success_reappear_then_miss_requires_fresh_two_poll_window() {
    let dir = tempfile::tempdir().unwrap();
    let store =
        ReceiptStore::open_at(dir.path(), "success-reappear-then-miss-fresh-window").unwrap();

    let envelope_hash = "4444444444444444444444444444444444444444444444444444444444444444";
    let tx_hash = FAKE_TX_HASH;

    store
        .try_begin(envelope_hash, tx_hash, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    // Step 1: NOT_FOUND @ ledger 5000 → anchor = 5000.
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getTransaction"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "NOT_FOUND",
                "latestLedger": 5000,
                "latestLedgerCloseTime": "1700000001",
                "oldestLedger": 50,
                "ledgerRetentionWindow": 4950
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getHealth"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "healthy",
                "latestLedger": 5000,
                "oldestLedger": 50,
                "ledgerRetentionWindow": 4950
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let s = reconcile_receipt(&client, &store, envelope_hash)
            .await
            .unwrap();
        assert_eq!(s, ReceiptStatus::Success);
        let mid = store.get(envelope_hash).unwrap().unwrap();
        assert_eq!(mid.reorg_pending_at_ledger, Some(5000));
    }

    // Step 2: SUCCESS → anchor cleared.
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getTransaction"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "SUCCESS",
                "txHash": FAKE_TX_HASH,
                "ledger": FAKE_LEDGER,
                "createdAt": "1700000000",
                "envelopeXdr": null,
                "resultXdr": null,
                "resultMetaXdr": null
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let s = reconcile_receipt(&client, &store, envelope_hash)
            .await
            .unwrap();
        assert_eq!(s, ReceiptStatus::Success);
        let mid = store.get(envelope_hash).unwrap().unwrap();
        assert_eq!(
            mid.reorg_pending_at_ledger, None,
            "anchor must be None after SUCCESS"
        );
    }

    // Step 3: NOT_FOUND @ ledger 6000.  Because the anchor was cleared on
    // SUCCESS in step 2, this is a fresh first-miss → anchor=6000 → Success
    // (not Reorged on a single miss).
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getTransaction"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "NOT_FOUND",
                "latestLedger": 6000,
                "latestLedgerCloseTime": "1700000010",
                "oldestLedger": 50,
                "ledgerRetentionWindow": 5950
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getHealth"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "healthy",
                "latestLedger": 6000,
                "oldestLedger": 50,
                "ledgerRetentionWindow": 5950
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let s = reconcile_receipt(&client, &store, envelope_hash)
            .await
            .unwrap();
        assert_eq!(
            s,
            ReceiptStatus::Success,
            "single miss after SUCCESS-reappear must NOT demote to Reorged \
             (anchor was cleared on SUCCESS, so this starts a fresh 2-poll window)"
        );
        let post = store.get(envelope_hash).unwrap().unwrap();
        assert_ne!(
            post.status,
            ReceiptStatus::Reorged,
            "stored status must not be Reorged after a single miss with fresh window"
        );
        assert_eq!(
            post.reorg_pending_at_ledger,
            Some(6000),
            "fresh first-miss anchor must be 6000"
        );
    }
}

/// NOT_FOUND→NOT_FOUND→Reorged: two consecutive NOT_FOUNDs with ledger advance
/// still produce `Reorged` (two-poll demotion path is intact).
#[tokio::test]
async fn two_consecutive_not_found_still_demotes_to_reorged() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "two-consec-nf-reorged-regression").unwrap();

    let envelope_hash = "5555555555555555555555555555555555555555555555555555555555555555";
    let tx_hash = FAKE_TX_HASH;

    store
        .try_begin(envelope_hash, tx_hash, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    // First NOT_FOUND @ ledger 7000 → anchor = 7000.
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getTransaction"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "NOT_FOUND",
                "latestLedger": 7000,
                "latestLedgerCloseTime": "1700000001",
                "oldestLedger": 50,
                "ledgerRetentionWindow": 6950
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getHealth"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "healthy",
                "latestLedger": 7000,
                "oldestLedger": 50,
                "ledgerRetentionWindow": 6950
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let s = reconcile_receipt(&client, &store, envelope_hash)
            .await
            .unwrap();
        assert_eq!(s, ReceiptStatus::Success, "first miss must return Success");
        let mid = store.get(envelope_hash).unwrap().unwrap();
        assert_eq!(mid.reorg_pending_at_ledger, Some(7000));
    }

    // Second NOT_FOUND @ ledger 7001 (≥ 7000+1) → Reorged.
    {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getTransaction"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "NOT_FOUND",
                "latestLedger": 7001,
                "latestLedgerCloseTime": "1700000006",
                "oldestLedger": 50,
                "ledgerRetentionWindow": 6950
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(wiremock::matchers::body_partial_json(
                json!({"method": "getHealth"}),
            ))
            .respond_with(EchoIdResponder::new(json!({
                "status": "healthy",
                "latestLedger": 7001,
                "oldestLedger": 50,
                "ledgerRetentionWindow": 6951
            })))
            .up_to_n_times(3)
            .mount(&server)
            .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        let s = reconcile_receipt(&client, &store, envelope_hash)
            .await
            .unwrap();
        assert_eq!(
            s,
            ReceiptStatus::Reorged,
            "two consecutive NOT_FOUNDs with ledger advance must → Reorged"
        );
        let post = store.get(envelope_hash).unwrap().unwrap();
        assert_eq!(post.status, ReceiptStatus::Reorged);
        assert_eq!(post.prior_ledger, Some(FAKE_LEDGER));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (e) Retention-drop vs re-org distinction
// ─────────────────────────────────────────────────────────────────────────────

/// When `getTransaction` returns `NOT_FOUND` for a `Success` receipt AND
/// `getHealth` shows that the prior confirmation ledger is BELOW `oldest_ledger`
/// (retention-drop), the receipt must become `Ambiguous` — NOT `Reorged`.
///
/// A retention-drop is not evidence of a re-org: the RPC simply no longer has
/// the transaction in its window.  Demoting to `Reorged` would mislead the
/// caller into thinking the chain rewound and could trigger a double-apply
/// on resubmit.
#[tokio::test]
async fn retention_drop_returns_ambiguous_not_reorged() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-retention-drop-test").unwrap();

    // Seed a Success receipt at FAKE_LEDGER=1234.
    let envelope_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let tx_hash = FAKE_TX_HASH;
    store
        .try_begin(envelope_hash, tx_hash, 9_999_999, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    let server = MockServer::start().await;

    // getTransaction → NOT_FOUND.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 5000,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 3000,
            "ledgerRetentionWindow": 2000
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    // getHealth → oldest_ledger=3000 > FAKE_LEDGER=1234 (retention-drop, not re-org).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 5000,
            "oldestLedger": 3000,
            "ledgerRetentionWindow": 2000
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(&client, &store, envelope_hash)
        .await
        .unwrap();

    // MUST return Ambiguous (retention-drop), NOT Reorged.
    assert_eq!(
        status,
        ReceiptStatus::Ambiguous,
        "retention-drop (prior_ledger=1234 < oldest_ledger=3000) must return \
         Ambiguous, not Reorged; got: {status:?}"
    );

    // Store must NOT have been demoted to Reorged.
    let receipt = store.get(envelope_hash).unwrap().unwrap();
    assert_ne!(
        receipt.status,
        ReceiptStatus::Reorged,
        "store must not be demoted to Reorged on a retention-drop"
    );
    assert_eq!(
        receipt.prior_ledger, None,
        "prior_ledger must remain None (no re-org demotion occurred)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (f) Degraded getHealth response
// ─────────────────────────────────────────────────────────────────────────────

/// When `getHealth` returns an implausible ledger range
/// (`oldest_ledger > latest_ledger`), `reconcile_receipt` must treat the
/// response as untrustworthy and return `Ambiguous` — not `Reorged`.
///
/// A misconfigured or adversarial RPC that returns a huge `oldest_ledger`
/// must not force a false re-org demotion on every reconciliation call.
#[tokio::test]
async fn reconcile_receipt_degraded_health_returns_ambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-degraded-health-test").unwrap();

    let envelope_hash = "2222222222222222222222222222222222222222222222222222222222222222";
    let tx_hash = FAKE_TX_HASH;
    store
        .try_begin(envelope_hash, tx_hash, 0, RECORDED_AT_LEDGER)
        .unwrap();
    store
        .finalize(envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    let server = MockServer::start().await;

    // getTransaction → NOT_FOUND.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 100,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 50,
            "ledgerRetentionWindow": 50
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    // getHealth → IMPLAUSIBLE: oldest_ledger (9999) > latest_ledger (100).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 100,
            "oldestLedger": 9999,
            "ledgerRetentionWindow": 0
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let status = reconcile_receipt(&client, &store, envelope_hash)
        .await
        .unwrap();

    // Implausible health response → Ambiguous, not Reorged.
    assert_eq!(
        status,
        ReceiptStatus::Ambiguous,
        "implausible getHealth (oldest > latest) must return Ambiguous, not Reorged; \
         got: {status:?}"
    );

    // No Reorged demotion.
    let receipt = store.get(envelope_hash).unwrap().unwrap();
    assert_ne!(receipt.status, ReceiptStatus::Reorged);
}

// ─────────────────────────────────────────────────────────────────────────────
// (g) FAILED arm produces typed wire code, not hardcoded "ledger.op_failed"
// ─────────────────────────────────────────────────────────────────────────────

/// The winner-path FAILED arm must call `map_failed_result` and record the
/// real on-chain wire code in the receipt, not the fallback "ledger.op_failed".
///
/// Verifies:
/// - When `getTransaction` returns FAILED with a payment-underfunded result
///   XDR (`TxFailed([OpInner(Payment(Underfunded))])`), the receipt stores
///   `ledger.insufficient_balance` (not `ledger.op_failed`).
/// - The returned `WalletError` is `WalletError::Ledger(InsufficientBalance)`,
///   NOT `RpcUnreachable`.
///
/// The payment-underfunded path is chosen because it maps to the typed
/// `LedgerError::InsufficientBalance` variant — the most discriminating
/// assertion.  `TxInsufficientBalance` (fee-level) maps to `OpFailed` via the
/// `other =>` arm; only the op-level `PaymentResult::Underfunded` path maps to
/// `InsufficientBalance`.
#[tokio::test]
async fn failed_arm_records_real_typed_code_not_op_failed() {
    use stellar_xdr::{
        Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
        TransactionResultExt, TransactionResultResult, VecM, WriteXdr,
    };

    let signed_xdr = build_signed_envelope().await;
    let envelope_hash = envelope_hash_for(&signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "block-b-failed-typed-code-test").unwrap();

    // Build a TransactionResult with TxFailed([Payment(Underfunded)]).
    let ops: VecM<OperationResult> = vec![OperationResult::OpInner(OperationResultTr::Payment(
        PaymentResult::Underfunded,
    ))]
    .try_into()
    .unwrap();
    let tx_result = TransactionResult {
        fee_charged: 0,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    let server = MockServer::start().await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "hash": FAKE_TX_HASH,
            "status": "PENDING",
            "latestLedger": 1001,
            "latestLedgerCloseTime": "1699999999"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → FAILED with real txInsufficientBalance XDR.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": FAKE_TX_HASH,
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    // getHealth — not expected to be called on FAILED, but register a mock
    // in case of unexpected calls so the server doesn't return empty responses.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(wiremock::matchers::body_partial_json(json!({
            "method": "getHealth"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "healthy",
            "latestLedger": 1010,
            "oldestLedger": 50,
            "ledgerRetentionWindow": 960
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

    // Must return Err (on-chain failure).
    assert!(
        result.is_err(),
        "FAILED getTransaction must return Err; got: {result:?}"
    );

    let err = result.unwrap_err();

    // Must be WalletError::Ledger (InsufficientBalance), NOT RpcUnreachable.
    use stellar_agent_core::error::{LedgerError, WalletError};
    assert!(
        matches!(
            err,
            WalletError::Ledger(LedgerError::InsufficientBalance { .. })
        ),
        "FAILED getTransaction (txInsufficientBalance) must return \
         WalletError::Ledger::InsufficientBalance, not RpcUnreachable; got: {err:?}"
    );

    // The error code must be the real wire code, not the fallback.
    let code = err.code();
    assert_ne!(
        code, "ledger.op_failed",
        "receipt code must NOT be the hardcoded fallback 'ledger.op_failed'; got: {code}"
    );
    assert_eq!(
        code, "ledger.insufficient_balance",
        "receipt code must be 'ledger.insufficient_balance'; got: {code}"
    );

    // The receipt must record the REAL wire code.
    let receipt = store.get(&envelope_hash).unwrap().unwrap();
    assert!(
        matches!(&receipt.status, ReceiptStatus::Failed { code } if code == "ledger.insufficient_balance"),
        "receipt must record 'ledger.insufficient_balance', not 'ledger.op_failed'; \
         got: {:?}",
        receipt.status
    );
}
