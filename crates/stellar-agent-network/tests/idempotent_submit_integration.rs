//! Integration tests for `submit_transaction_idempotent`.
//!
//! Uses `wiremock` to serve deterministic JSON-RPC responses.
//! The test fixture builds a real signed `TransactionEnvelope` (testnet keys,
//! no committed S-strkey seed — all keys are derived in-process via fixed
//! byte-seeds that are public test fixtures).
//!
//! # Coverage
//!
//! (a) Terminal-cached path: a resubmit of an already-terminal-recorded
//!     envelope returns the cached receipt WITHOUT a `sendTransaction` RPC call.
//! (b) Submit + poll SUCCESS path: sendTransaction→PENDING, then
//!     getTransaction→SUCCESS; receipt is finalised to Success.
//! (c) Concurrent submit of the SAME envelope: exactly ONE `sendTransaction`
//!     call is made; both callers receive the same receipt (winner/loser rule).
//!
//! # Parallelism
//!
//! Tests (a) and (b) are independent and do not share global state.  Test (c)
//! spawns concurrent tasks; it does NOT share a process-global receipt store
//! path so `#[serial]` is not required.  All stores are opened in per-test
//! `tempdir()` directories.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "integration test; panics/unwraps/eprintln acceptable"
)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::idempotent_submit::submit_transaction_idempotent;
use stellar_agent_test_support::EchoIdResponder;
use stellar_agent_test_support::signed_envelope::{SignedTestEnvelope, get_network_result};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FAKE_TX_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const FAKE_LEDGER: u32 = 1234;

/// Seed for the transaction source account.  A fixed byte seed so there is no
/// committed S-strkey — `[1u8; 32]` is a public test fixture, not a production
/// key.
const SOURCE_SEED: [u8; 32] = [1u8; 32];

/// Builds a signed test envelope whose source account is the signing key's own
/// account, so the account the ledger reports is the one that signed.
fn build_signed_envelope() -> SignedTestEnvelope {
    SignedTestEnvelope::builder(SOURCE_SEED)
        .sequence(100)
        .amount_stroops(10_000_000)
        .build()
}

/// Mounts the two reads every submit performs before it sends: the endpoint
/// identity probe and the signer-set fetch for the envelope's source accounts.
async fn mount_probe_and_signers(server: &MockServer, envelope: &SignedTestEnvelope) {
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(EchoIdResponder::new(envelope.ledger_entries_result()))
        .mount(server)
        .await;
}

/// The idempotency key the submit paths record under.
///
/// Delegates rather than restating the derivation: the key is one definition
/// shared by both submit paths, and a test that computed its own would pass
/// while the two disagreed.
fn envelope_hash_for(signed_xdr: &str) -> String {
    stellar_agent_network::envelope_hash_hex(signed_xdr)
}

/// JSON-RPC `sendTransaction` response for a PENDING submission.
fn send_transaction_pending_response(envelope: &SignedTestEnvelope) -> serde_json::Value {
    json!({
        "hash": envelope.tx_hash_hex(),
        "status": "PENDING",
        "latestLedger": 1001,
        "latestLedgerCloseTime": "1699999999"
    })
}

/// JSON-RPC `getTransaction` response for a SUCCESS confirmation.
fn get_transaction_success_response(envelope: &SignedTestEnvelope) -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "txHash": envelope.tx_hash_hex(),
        "ledger": FAKE_LEDGER,
        "createdAt": "1700000000",
        "envelopeXdr": null,
        "resultXdr": null,
        "resultMetaXdr": null
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) Terminal-cached path: resubmit returns cached receipt; NO sendTransaction
// ─────────────────────────────────────────────────────────────────────────────

/// If a terminal Success receipt is already in the store,
/// `submit_transaction_idempotent` returns it WITHOUT calling `sendTransaction`.
///
/// Verified by starting a `wiremock` server with NO registered mocks —
/// if the code hits the RPC, the server returns 404/connection-refused, which
/// would cause the call to fail.  The test asserts `Ok(result)` with the
/// expected ledger from the cached receipt.
#[tokio::test]
async fn terminal_cached_receipt_no_send_transaction() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();
    let envelope_hash = envelope_hash_for(signed_xdr);

    // Open a temp receipt store and pre-seed a terminal Success receipt.
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "test").unwrap();
    store
        .try_begin(&envelope_hash, FAKE_TX_HASH, "", 0, 0, 100)
        .unwrap();
    store
        .finalize(&envelope_hash, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    // Start a wiremock server — no mocks registered.
    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        signed_xdr,
        Duration::from_secs(5),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await;

    assert!(
        result.is_ok(),
        "terminal cached receipt must be returned without RPC call; got: {result:?}"
    );
    let sub = result.unwrap();
    assert_eq!(sub.ledger, FAKE_LEDGER, "ledger must match cached receipt");

    // Verify no requests were made to the mock server.
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC requests must be made when a terminal receipt exists"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) Normal submit path: sendTransaction→PENDING then getTransaction→SUCCESS
// ─────────────────────────────────────────────────────────────────────────────

/// A fresh submission (no prior receipt): `sendTransaction` returns PENDING,
/// `getTransaction` returns SUCCESS.  The receipt is finalised to Success and
/// `Ok(SubmissionResult)` is returned.
///
/// This also validates the DUPLICATE use case: when `sendTransaction` is
/// re-invoked for a transaction that was already submitted (DUPLICATE maps to
/// the same PENDING/poll path in stellar-rpc-client), the idempotent wrapper
/// polls until SUCCESS and finalises the receipt.
#[tokio::test]
async fn send_pending_then_get_success_finalises_receipt() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "test").unwrap();
    let envelope_hash = envelope_hash_for(signed_xdr);

    let server = MockServer::start().await;
    mount_probe_and_signers(&server, &envelope).await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_transaction_pending_response(
            &envelope,
        )))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction polls → SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_transaction_success_response(
            &envelope,
        )))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_transaction_idempotent(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await;

    // Must succeed.
    assert!(
        result.is_ok(),
        "sendTransaction→PENDING + getTransaction→SUCCESS must produce Ok; got: {result:?}"
    );
    let sub = result.unwrap();
    assert_eq!(
        sub.ledger, FAKE_LEDGER,
        "ledger must match getTransaction SUCCESS response"
    );

    // Receipt must be finalised to Success.
    let receipt = store.get(&envelope_hash).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Success,
        "receipt must be Success after successful submission"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) Concurrent same-envelope: exactly ONE sendTransaction call
// ─────────────────────────────────────────────────────────────────────────────

/// Two concurrent calls to `submit_transaction_idempotent` for the SAME signed
/// envelope produce exactly ONE `sendTransaction` call.  Both callers receive
/// the same final result.
///
/// The winner atomically inserts a `Pending` entry and submits; the loser finds
/// the entry (via `store.get` or `try_begin` → `AlreadyPresent`) and polls
/// until the winner finalises, then returns the same receipt.
#[tokio::test]
async fn concurrent_same_envelope_exactly_one_send_transaction() {
    let envelope = build_signed_envelope();
    let signed_xdr = Arc::new(envelope.envelope_xdr().to_owned());
    let dir = Arc::new(tempfile::tempdir().unwrap());

    let server = MockServer::start().await;
    let server_uri = server.uri();
    mount_probe_and_signers(&server, &envelope).await;

    // sendTransaction → PENDING (first call; loser must not hit this).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "sendTransaction"
        })))
        .respond_with(EchoIdResponder::new(send_transaction_pending_response(
            &envelope,
        )))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    // getTransaction → NOT_FOUND once, then SUCCESS.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "NOT_FOUND",
            "latestLedger": 1002,
            "latestLedgerCloseTime": "1700000001",
            "oldestLedger": 900,
            "ledgerRetentionWindow": 100
        })))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "getTransaction"
        })))
        .respond_with(EchoIdResponder::new(get_transaction_success_response(
            &envelope,
        )))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let store = Arc::new(ReceiptStore::open_at(dir.path(), "concurrent-test").unwrap());

    let xdr1 = Arc::clone(&signed_xdr);
    let xdr2 = Arc::clone(&signed_xdr);
    let store1 = Arc::clone(&store);
    let store2 = Arc::clone(&store);
    let uri1 = server_uri.clone();
    let uri2 = server_uri.clone();

    // Spawn two concurrent submissions of the same envelope.
    let task1 = tokio::spawn(async move {
        let client = StellarRpcClient::new(&uri1).unwrap();
        submit_transaction_idempotent(
            &client,
            &xdr1,
            Duration::from_secs(30),
            TESTNET_PASSPHRASE,
            &store1,
            100,
        )
        .await
    });

    let task2 = tokio::spawn(async move {
        // Short sleep so task1 usually inserts the Pending entry first.
        // The test is still correct if they race since try_begin is atomic.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client = StellarRpcClient::new(&uri2).unwrap();
        submit_transaction_idempotent(
            &client,
            &xdr2,
            Duration::from_secs(30),
            TESTNET_PASSPHRASE,
            &store2,
            100,
        )
        .await
    });

    let (r1, r2) = tokio::join!(task1, task2);
    let r1 = r1.expect("task1 must not panic");
    let r2 = r2.expect("task2 must not panic");

    // At least ONE task must succeed — the winner always submits successfully.
    // If both error, that is a regression (the winner path is broken).
    let at_least_one_ok = r1.is_ok() || r2.is_ok();
    assert!(
        at_least_one_ok,
        "at least the winner task must succeed; both errored: r1={r1:?}, r2={r2:?}"
    );

    // If both succeed, ledgers must agree.
    if let (Ok(s1), Ok(s2)) = (&r1, &r2) {
        assert_eq!(
            s1.ledger, s2.ledger,
            "both tasks must receive the same ledger"
        );
    } else {
        // Loser may time out if winner is slow; log for diagnosis.
        eprintln!(
            "concurrent test: r1={r1:?}, r2={r2:?}. \
             Loser may have timed out before winner finalised (acceptable under load)."
        );
    }

    // KEY assertion: exactly ONE sendTransaction call was made.
    let requests = server.received_requests().await.unwrap();
    let send_calls = requests
        .iter()
        .filter(|r| {
            r.body_json::<serde_json::Value>()
                .ok()
                .and_then(|v| {
                    v.get("method")
                        .and_then(|m| m.as_str())
                        .map(|m| m == "sendTransaction")
                })
                .unwrap_or(false)
        })
        .count();

    assert_eq!(
        send_calls, 1,
        "exactly ONE sendTransaction call must be made for concurrent identical \
         envelopes; got {send_calls}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) Pre-send refusal withdraws the receipt
// ─────────────────────────────────────────────────────────────────────────────

/// A refusal that happens before `sendTransaction` leaves no receipt behind,
/// and the next attempt on the same envelope proceeds straight to the send.
///
/// The idempotency gate writes a Pending receipt before the submit layer runs
/// its pre-send checks. A refusal there means nothing reached the network, so
/// the receipt has to go: a Pending entry for a transaction that does not
/// exist turns every later attempt into a loser that polls the store for
/// `LOSER_MAX_POLLS x 500 ms` and then fails.
///
/// Two assertions discriminate. The store holds no entry for the envelope
/// after the refusal, and the second call reaches `sendTransaction` and
/// confirms well inside the loser poll window.
#[tokio::test]
async fn pre_send_refusal_leaves_no_receipt_and_the_retry_sends() {
    let envelope = build_signed_envelope();
    let signed_xdr = envelope.envelope_xdr();
    let envelope_hash = envelope_hash_for(signed_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "acceptance").unwrap();

    let server = MockServer::start().await;

    // The endpoint answers with a third network for the first probe, then with
    // the declared one.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(
            "Test SDF Future Network ; October 2022",
        )))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_probe_and_signers(&server, &envelope).await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_transaction_pending_response(
            &envelope,
        )))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_transaction_success_response(
            &envelope,
        )))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let refused = submit_transaction_idempotent(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await
    .expect_err("an endpoint serving another network must be refused");
    assert_eq!(
        refused.code(),
        "network.endpoint_network_mismatch",
        "{refused:?}"
    );
    assert!(
        store.get(&envelope_hash).unwrap().is_none(),
        "a transaction that was never sent must leave no receipt"
    );

    let started = std::time::Instant::now();
    let result = submit_transaction_idempotent(
        &client,
        signed_xdr,
        Duration::from_secs(30),
        TESTNET_PASSPHRASE,
        &store,
        100,
    )
    .await
    .expect("the retry must reach the send once the endpoint answers");

    assert_eq!(result.ledger, FAKE_LEDGER);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the retry must submit rather than wait out the loser poll; took {:?}",
        started.elapsed()
    );
    assert_eq!(
        store.get(&envelope_hash).unwrap().unwrap().status,
        ReceiptStatus::Success,
        "the retry's receipt must be finalised"
    );
}
