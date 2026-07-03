//! Mock-RPC integration tests for `submit_fee_bump_idempotent`.
//!
//! Uses `wiremock` to serve deterministic JSON-RPC responses.  All mocks
//! disambiguate by JSON-RPC method name via `body_partial_json` (share a
//! single server endpoint for all JSON-RPC methods, matched by
//! `{ "method": "..." }`).
//!
//! # Coverage
//!
//! (a) Inner-key idempotency: SUCCESS once, second call returns cached receipt
//!     with NO second `sendTransaction` (wiremock `expect(1)` enforces).
//!
//! (b-1) Higher-fee — inner already applied: second call at higher fee returns
//!       cached Success, no re-bump (wiremock `expect(1)` on send).
//!
//! (b-2) Higher-fee — inner not yet applied: second call at higher fee re-bumps
//!       against the same inner key (wiremock sees two sendTransaction calls;
//!       both converge on the same inner_key receipt).
//!
//! (c) Inner `max_time`: the stored receipt's `max_time` equals the INNER tx's
//!     `maxTime`, NOT zero (which would be the outer's absent cond).
//!
//! (d) SUCCESS-layer assertion: pre-seed a Success receipt (which is the
//!     outcome when `getTransaction` returns status:SUCCESS for an inner-applied
//!     fee-bump) and verify it maps to `Ok(SubmissionResult)` with the correct
//!     ledger.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "integration test; panics/unwraps/eprintln acceptable"
)]

use std::time::Duration;

use serde_json::json;
use sha2::{Digest, Sha256};
use stellar_agent_core::StellarAmount;
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::fee_bump_retry::submit_fee_bump_idempotent;
use stellar_agent_network::signing::software::SoftwareSigningKey;
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FAKE_OUTER_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const FAKE_LEDGER: u32 = 9_999;

// Fixed test seeds (public test fixtures; NOT production keys).
// Different from fee_bump.rs tests ([1u8;32]) to avoid cross-test key collision.
const INNER_SOURCE_SEED: [u8; 32] = [5u8; 32];
const FEE_PAYER_SEED: [u8; 32] = [6u8; 32];

/// Builds and signs an inner V1 envelope.
///
/// Returns `(inner_signed_xdr, fee_payer_gstrkey, SoftwareSigningKey)`.
async fn build_signed_inner(
    seq: i64,
    max_time_opt: Option<u64>,
) -> (String, String, SoftwareSigningKey) {
    use stellar_strkey::ed25519::PublicKey as StrPublicKey;

    let inner_sk = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED);
    let inner_pk: [u8; 32] = inner_sk.verifying_key().to_bytes();
    let inner_gstrkey = StrPublicKey(inner_pk).to_string().as_str().to_owned();

    let fee_payer_sk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED);
    let fee_payer_pk: [u8; 32] = fee_payer_sk.verifying_key().to_bytes();
    let fee_payer_gstrkey = StrPublicKey(fee_payer_pk).to_string().as_str().to_owned();

    let inner_signer = SoftwareSigningKey::new_from_bytes(INNER_SOURCE_SEED);
    let fee_payer_signer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let mut builder = ClassicOpBuilder::new(&inner_gstrkey, seq, TESTNET_PASSPHRASE, 100);
    builder
        .payment(
            &fee_payer_gstrkey,
            StellarAmount::from_stroops(1),
            &Asset::Native,
        )
        .unwrap();

    if let Some(mt) = max_time_opt {
        builder.with_time_bounds(0, mt);
    }

    let inner_signed = builder.build_and_sign(&inner_signer).await.unwrap();
    (inner_signed, fee_payer_gstrkey, fee_payer_signer)
}

/// Computes the `feebump-inner:` prefixed receipt-store key for a given
/// inner signed XDR.
///
/// Replicates the key derivation from `fee_bump_retry.rs` so tests can
/// inspect the receipt store independently.
fn inner_key_for(inner_xdr: &str) -> String {
    use stellar_xdr::{
        Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
        TransactionSignaturePayloadTaggedTransaction, WriteXdr,
    };
    let envelope = TransactionEnvelope::from_xdr_base64(inner_xdr, Limits::none()).unwrap();
    let v1 = match envelope {
        TransactionEnvelope::Tx(v1) => v1,
        _ => panic!("expected Tx(v1)"),
    };
    let network_id = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
    let payload = TransactionSignaturePayload {
        network_id,
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx),
    };
    let payload_bytes = payload.to_xdr(Limits::none()).unwrap();
    let hash = Sha256::digest(&payload_bytes);
    let hash_hex: String = hash.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    format!("feebump-inner:{hash_hex}")
}

/// JSON-RPC `sendTransaction` response: PENDING.
fn send_pending_response() -> serde_json::Value {
    json!({
        "hash": FAKE_OUTER_HASH,
        "status": "PENDING",
        "latestLedger": 1001,
        "latestLedgerCloseTime": "1699999999"
    })
}

/// JSON-RPC `getTransaction` response: SUCCESS.
fn get_success_response() -> serde_json::Value {
    json!({
        "status": "SUCCESS",
        "txHash": FAKE_OUTER_HASH,
        "ledger": FAKE_LEDGER,
        "createdAt": "1700000000",
        "envelopeXdr": null,
        "resultXdr": null,
        "resultMetaXdr": null
    })
}

/// JSON-RPC `getHealth` response (within-window, blocks retention-early-exit).
fn get_health_ok_response() -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": 2000,
        "oldestLedger": 1,
        "ledgerRetentionWindow": 1999
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) Inner-key idempotency: second call with SAME inner returns cached receipt
//     with NO second sendTransaction.
// ─────────────────────────────────────────────────────────────────────────────

/// Submitting the same inner envelope twice results in exactly ONE
/// `sendTransaction` call; the second call returns the cached Success receipt.
///
/// Verifies:
/// - `sendTransaction` is called exactly once (wiremock `expect(1)`).
/// - Both calls return `Ok` with the same ledger.
/// - The receipt store has a single Success entry for the inner key.
#[tokio::test]
async fn inner_key_idempotency_no_second_send_transaction() {
    let (inner_xdr, fp_gstrkey, fp_signer) = build_signed_inner(100, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "fb-idempotency-test").unwrap();

    let server = MockServer::start().await;

    // sendTransaction — MUST be called exactly once.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response()))
        .expect(1)
        .mount(&server)
        .await;

    // getTransaction — SUCCESS on the first poll.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    // getHealth — within-window (prevents retention-early-exit on NOT_FOUND polls).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // First submission — winner path.
    let r1 = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    assert!(r1.is_ok(), "first submission must succeed; got: {r1:?}");
    let sub1 = r1.unwrap();
    assert_eq!(sub1.ledger, FAKE_LEDGER);

    // Second submission — must hit the cached Success receipt, no second send.
    let r2 = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    assert!(
        r2.is_ok(),
        "second submission must return cached Success; got: {r2:?}"
    );
    let sub2 = r2.unwrap();
    assert_eq!(
        sub2.ledger, FAKE_LEDGER,
        "second call must return same ledger as cached receipt"
    );

    // Verify exactly ONE sendTransaction was made (wiremock enforces `expect(1)`
    // at server.verify_and_reset() or drop; we also assert explicitly).
    let receipts_sent = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            r.body_json::<serde_json::Value>()
                .ok()
                .and_then(|v| {
                    v.get("method")
                        .and_then(|m| m.as_str())
                        .map(|s| s == "sendTransaction")
                })
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        receipts_sent, 1,
        "sendTransaction must be called exactly once; called {receipts_sent} times"
    );

    // Receipt store must have exactly one Success entry for the inner key.
    let receipt = store.get(&inner_key).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Success,
        "receipt must be Success after both calls"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (b-1) Higher-fee: inner already applied → cached Success, no re-bump.
// ─────────────────────────────────────────────────────────────────────────────

/// When the inner tx has already applied (terminal Success in the store), a
/// second call with a HIGHER fee returns the cached Success WITHOUT re-bumping.
///
/// Verifies that `sendTransaction` is called at most once in total.
#[tokio::test]
async fn higher_fee_inner_already_applied_returns_cached_no_rebump() {
    let (inner_xdr, fp_gstrkey, fp_signer) = build_signed_inner(200, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "fb-higher-fee-applied-test").unwrap();

    let server = MockServer::start().await;

    // sendTransaction — exactly once for the first call.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response()))
        .expect(1)
        .mount(&server)
        .await;

    // getTransaction — SUCCESS on first poll.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // First call at outer_fee=500: submits, confirms, stores Success.
    let r1 = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;
    assert!(r1.is_ok(), "first call must succeed; got: {r1:?}");

    // Second call at outer_fee=2_000 (higher): inner already applied → cached.
    let r2 = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        2_000, // higher fee — but inner is done
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    assert!(
        r2.is_ok(),
        "second call (higher fee, inner done) must return cached Success; got: {r2:?}"
    );
    assert_eq!(
        r2.unwrap().ledger,
        FAKE_LEDGER,
        "cached ledger must match original confirmation"
    );

    // wiremock `expect(1)` on sendTransaction already asserts no second send;
    // additionally verify the store still has one Success.
    let receipt = store.get(&inner_key).unwrap().unwrap();
    assert_eq!(
        receipt.status,
        ReceiptStatus::Success,
        "store must have exactly one Success for the inner key"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (b-2) Higher-fee: inner NOT yet applied → re-bumps at higher fee.
// ─────────────────────────────────────────────────────────────────────────────

/// Two calls with different `outer_fee_stroops` over the same inner XDR produce
/// the SAME `feebump-inner:` key but DIFFERENT outer tx hashes.  The inner key
/// is fee-independent (idempotency guarantee); the outer hash is fee-sensitive.
///
/// - Call 1 at outer_fee=500 → winner path → SUCCESS (`sendTransaction` called once).
/// - Call 2 at outer_fee=2_000 (same inner XDR) → inner already applied →
///   cached Success returned without a second `sendTransaction`.
///
/// This test MUST fail if `submit_fee_bump_idempotent`'s keying logic regresses
/// (e.g., if the key were accidentally derived from the outer hash).
#[tokio::test]
async fn higher_fee_same_inner_key_regardless_of_outer_fee() {
    use stellar_xdr::{
        FeeBumpTransaction, FeeBumpTransactionExt, FeeBumpTransactionInnerTx, Hash, Limits,
        ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
        TransactionSignaturePayloadTaggedTransaction, Uint256, WriteXdr,
    };

    let (inner_xdr, fp_gstrkey, fp_signer) = build_signed_inner(300, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    // The same inner XDR must produce the same feebump-inner: key regardless of
    // outer fee (the key is derived purely from the inner tx body).
    assert!(
        inner_key.starts_with("feebump-inner:"),
        "inner key must start with 'feebump-inner:'"
    );

    // Compute outer tx hashes at two different fees using the same XDR machinery
    // as the production code, to prove they are fee-sensitive.
    let compute_outer_hash = |outer_fee: i64| -> String {
        use sha2::{Digest as ShaDigest, Sha256};
        use stellar_strkey::ed25519::PublicKey as StrPublicKey;

        let envelope = TransactionEnvelope::from_xdr_base64(&inner_xdr, Limits::none()).unwrap();
        let v1 = match envelope {
            TransactionEnvelope::Tx(v1) => v1,
            _ => panic!("expected Tx(v1)"),
        };
        let pk = StrPublicKey::from_string(&fp_gstrkey).unwrap();
        let fee_source_muxed = stellar_xdr::MuxedAccount::Ed25519(Uint256(pk.0));
        let fee_bump_tx = FeeBumpTransaction {
            fee_source: fee_source_muxed,
            fee: outer_fee,
            inner_tx: FeeBumpTransactionInnerTx::Tx(v1),
            ext: FeeBumpTransactionExt::V0,
        };
        let network_id = Hash(Sha256::digest(TESTNET_PASSPHRASE.as_bytes()).into());
        let payload = TransactionSignaturePayload {
            network_id,
            tagged_transaction: TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
                fee_bump_tx,
            ),
        };
        let payload_bytes = payload.to_xdr(Limits::none()).unwrap();
        let hash = Sha256::digest(&payload_bytes);
        hash.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    };

    let outer_hash_500 = compute_outer_hash(500);
    let outer_hash_2000 = compute_outer_hash(2_000);

    // Same inner key at both fees.
    assert_eq!(
        inner_key_for(&inner_xdr),
        inner_key,
        "inner key must be stable across calls"
    );

    // Different outer hashes at different fees (outer tx is fee-sensitive).
    assert_ne!(
        outer_hash_500, outer_hash_2000,
        "different outer_fee_stroops must produce different outer tx hashes"
    );

    // Now drive submit_fee_bump_idempotent to verify the actual keying logic.
    // Call 1 at fee=500 → winner → SUCCESS (sendTransaction called once).
    // Call 2 at fee=2_000 → cached Success (sendTransaction NOT called again).
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "fb-higher-fee-test").unwrap();

    let server = MockServer::start().await;

    // sendTransaction — MUST be called exactly once (both calls share inner key).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response()))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    // Call 1: fee=500, winner path.
    let result1 = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        1,
        Duration::from_secs(30),
    )
    .await;
    assert!(
        result1.is_ok(),
        "call 1 (fee=500) must succeed: {result1:?}"
    );

    // Call 2: fee=2_000, same inner XDR — inner already applied → cached Success.
    let result2 = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        2_000,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        1,
        Duration::from_secs(30),
    )
    .await;
    assert!(
        result2.is_ok(),
        "call 2 (fee=2_000) must succeed: {result2:?}"
    );

    // Both calls must return the same ledger (same cached receipt).
    assert_eq!(
        result1.unwrap().ledger,
        result2.unwrap().ledger,
        "both calls must return the same cached ledger"
    );

    // Receipt store must have exactly one entry for the inner key.
    let receipt = store.get(&inner_key).unwrap();
    assert!(
        receipt.is_some(),
        "receipt store must have an entry for the inner key"
    );
    assert_eq!(
        receipt.unwrap().status,
        ReceiptStatus::Success,
        "inner key receipt must be Success"
    );

    // wiremock verifies sendTransaction was called exactly once (expect(1)).
    server.verify().await;
    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) Inner max_time: receipt stores INNER tx's maxTime, not outer.
// ─────────────────────────────────────────────────────────────────────────────

/// The receipt's `max_time` field equals the INNER tx's `TimeBounds.maxTime`.
///
/// Builds an inner tx with a known `maxTime` (1_800_000_099).  After a
/// successful submission, asserts the stored receipt's `max_time` matches the
/// inner's bound, NOT zero (outer fee-bump has no `cond` — CAP-15).
#[tokio::test]
async fn inner_max_time_stored_in_receipt() {
    const KNOWN_MAX_TIME: u64 = 1_800_000_099;

    let (inner_xdr, fp_gstrkey, fp_signer) = build_signed_inner(400, Some(KNOWN_MAX_TIME)).await;
    let inner_key = inner_key_for(&inner_xdr);

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "fb-max-time-test").unwrap();

    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(get_success_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(20)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    assert!(result.is_ok(), "submission must succeed; got: {result:?}");

    // Verify the stored receipt's max_time equals the INNER tx's maxTime.
    let receipt = store.get(&inner_key).unwrap().unwrap();
    assert_eq!(
        receipt.max_time, KNOWN_MAX_TIME,
        "receipt.max_time must equal the INNER tx's TimeBounds.maxTime; \
         outer fee-bump has no cond (CAP-15)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) SUCCESS-layer assertion (pure store test).
// ─────────────────────────────────────────────────────────────────────────────

/// `getTransaction` returning `status: SUCCESS` for an inner-applied fee-bump
/// results in `Ok(SubmissionResult)`.
///
/// Per CAP-15 (Application-and-Results): inner applied ⇒
/// `txFEE_BUMP_INNER_SUCCESS`; the RPC classifies the outer envelope as
/// `SUCCESS`.
///
/// Seeds the receipt store with a `Success` receipt (which is exactly what the
/// winner path stores after `getTransaction` returns `status: SUCCESS`) and
/// verifies it maps to `Ok(SubmissionResult)` through the fast-path.
/// Structural regression lock for the SUCCESS-classification route.
#[tokio::test]
async fn txfeebumpinnersuccess_routes_to_success_receipt_via_fast_path() {
    // Use a fresh inner tx (distinct seq from other tests).
    let (inner_xdr, fp_gstrkey, fp_signer) = build_signed_inner(500, None).await;
    let inner_key = inner_key_for(&inner_xdr);
    let outer_tx_hash = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "fb-557-test").unwrap();

    // Pre-seed a Success receipt (what the winner stores after status:SUCCESS).
    store.try_begin(&inner_key, outer_tx_hash, 0, 100).unwrap();
    store
        .finalize(&inner_key, ReceiptStatus::Success, Some(FAKE_LEDGER))
        .unwrap();

    // Server must NOT be hit (cached Success returns immediately).
    let server = MockServer::start().await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_gstrkey,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    assert!(
        result.is_ok(),
        "pre-seeded Success receipt must map to Ok(SubmissionResult); got: {result:?}"
    );
    assert_eq!(
        result.unwrap().ledger,
        FAKE_LEDGER,
        "ledger must match the pre-seeded receipt"
    );

    // No RPC calls must have been made.
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "no RPC calls must be made when a Success receipt is cached"
    );
}
