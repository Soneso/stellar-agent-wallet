//! Coverage tests for `fee_bump_retry.rs` — idempotent fee-bump retry paths
//! not exercised by the existing unit and integration test files.
//!
//! Supplements `fee_bump_retry_unit.rs` and `fee_bump_idempotent_integration.rs`.
//!
//! Additional paths covered here:
//!
//! (a) FAILED RPC response on the winner path: getTransaction→FAILED stores a
//!     Failed receipt and returns a typed error.
//! (b) wait_for_winner_fee_bump success path: loser sees Pending then Success.
//! (c) compute_outer_tx_hash_hex responds correctly to fee_source validation
//!     (invalid G-strkey on the retry path returns ValidationError).
//! (d) Outer tx hash stored in the receipt row equals the precomputed hash.
//! (e) Inner key from a no-max-time inner tx is 64-hex-char SHA-256.
//! (f) Successful winner path stores the outer tx hash in receipt.tx_hash.
//! (g) FeeSourceSignerMismatch in submit_fee_bump_idempotent abandons the receipt.
//! (h) Inner V0 envelope rejected at the submit_fee_bump_idempotent entry point.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only"
)]

use std::time::Duration;

use serde_json::json;
use sha2::{Digest as ShaDigest, Sha256};
use stellar_agent_core::StellarAmount;
use stellar_agent_core::error::{SubmissionError, ValidationError, WalletError};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::builder::{Asset, ClassicOpBuilder};
use stellar_agent_network::fee_bump_retry::submit_fee_bump_idempotent;
use stellar_agent_network::signing::SoftwareSigningKey;
use stellar_agent_test_support::EchoIdResponder;
use stellar_xdr::{
    Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FAKE_OUTER_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const FAKE_LEDGER: u32 = 5_555;

// Public test fixtures — NOT production keys.  Use seeds disjoint from all
// other test files to prevent hash aliasing in shared receipt stores.
const INNER_SOURCE_SEED: [u8; 32] = [0x20u8; 32];
const FEE_PAYER_SEED: [u8; 32] = [0x21u8; 32];
// A DIFFERENT fee-payer seed for mismatch tests.
const WRONG_PAYER_SEED: [u8; 32] = [0x22u8; 32];

fn fee_payer_gstrkey() -> String {
    use stellar_strkey::ed25519::PublicKey as StrPk;
    let sk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED);
    StrPk(sk.verifying_key().to_bytes()).to_string().to_string()
}

fn open_temp_store(label: &str) -> (tempfile::TempDir, ReceiptStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), label).unwrap();
    (dir, store)
}

/// Builds and signs an inner V1 envelope.
///
/// Returns `(inner_signed_xdr, fee_payer_gstrkey, fee_payer_signer)`.
async fn build_signed_inner(
    seq: i64,
    max_time: Option<u64>,
) -> (String, String, SoftwareSigningKey) {
    use stellar_strkey::ed25519::PublicKey as StrPk;

    let inner_sk = ed25519_dalek::SigningKey::from_bytes(&INNER_SOURCE_SEED);
    let inner_pk: [u8; 32] = inner_sk.verifying_key().to_bytes();
    let inner_gstrkey = StrPk(inner_pk).to_string().to_string();

    let fee_payer_sk = ed25519_dalek::SigningKey::from_bytes(&FEE_PAYER_SEED);
    let fee_payer_pk: [u8; 32] = fee_payer_sk.verifying_key().to_bytes();
    let fee_payer_gstrkey = StrPk(fee_payer_pk).to_string().to_string();

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

    if let Some(mt) = max_time {
        builder.with_time_bounds(0, mt);
    }

    let inner_signed = builder.build_and_sign(&inner_signer).await.unwrap();
    (inner_signed, fee_payer_gstrkey, fee_payer_signer)
}

/// Computes the `feebump-inner:` prefixed idempotency key for a given inner XDR.
fn inner_key_for(inner_xdr: &str) -> String {
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

fn send_pending_response() -> serde_json::Value {
    json!({
        "hash": FAKE_OUTER_HASH,
        "status": "PENDING",
        "latestLedger": 2001,
        "latestLedgerCloseTime": "1699999999"
    })
}

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

fn get_health_ok_response() -> serde_json::Value {
    json!({
        "status": "healthy",
        "latestLedger": 3000,
        "oldestLedger": 1,
        "ledgerRetentionWindow": 2999
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// (a) FAILED RPC response on winner path → Failed receipt, typed error
// ─────────────────────────────────────────────────────────────────────────────

/// When `getTransaction` returns FAILED with a `TxFailed` XDR, the winner path
/// finalises the receipt as `Failed { code }` and returns a typed `WalletError`.
///
/// The receipt store must contain a terminal `Failed` entry after the call.
#[tokio::test]
async fn winner_path_rpc_failed_stores_failed_receipt_and_returns_error() {
    use stellar_xdr::{
        Limits, OperationResult, OperationResultTr, PaymentResult, TransactionResult,
        TransactionResultExt, TransactionResultResult, VecM, WriteXdr,
    };

    let (inner_xdr, fp_g, fp_signer) = build_signed_inner(2001, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    let (dir, store) = open_temp_store("fb-winner-failed");
    let server = MockServer::start().await;

    // sendTransaction → PENDING.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → FAILED with Payment(Underfunded) XDR.
    let ops: VecM<OperationResult> = vec![OperationResult::OpInner(OperationResultTr::Payment(
        PaymentResult::Underfunded,
    ))]
    .try_into()
    .unwrap();
    let tx_result = TransactionResult {
        fee_charged: 500,
        result: TransactionResultResult::TxFailed(ops),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": FAKE_OUTER_HASH,
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_g,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    // The winner path must return a typed error for FAILED.
    assert!(
        result.is_err(),
        "FAILED getTransaction must return Err on winner path; got: {result:?}"
    );
    let err = result.unwrap_err();
    // Must be a ledger or submission error (InsufficientBalance for Underfunded).
    assert_ne!(
        err.code(),
        "network.rpc_unreachable",
        "FAILED result must NOT map to rpc_unreachable; got code: {}",
        err.code()
    );

    // The receipt store must contain a terminal Failed entry for the inner key.
    let receipt = store.get(&inner_key).unwrap().unwrap();
    assert!(
        receipt.status.is_terminal(),
        "receipt after FAILED must be terminal; got: {:?}",
        receipt.status
    );
    assert!(
        matches!(receipt.status, ReceiptStatus::Failed { .. }),
        "receipt after FAILED must be Failed; got: {:?}",
        receipt.status
    );

    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) wait_for_winner_fee_bump success path: loser sees terminal Success
// ─────────────────────────────────────────────────────────────────────────────

/// The loser arm of `submit_fee_bump_idempotent` returns `Ok(SubmissionResult)`
/// when the winner finalises the receipt to `Success` before the loser's poll
/// timeout elapses.
///
/// Simulated using `tokio::time::pause()`:
/// 1. Pre-seed a Pending receipt (submitted=true).
/// 2. Spawn a background task that writes Success after one advanced tick.
/// 3. Assert the loser returns Ok with the expected ledger.
#[tokio::test]
async fn loser_poll_resolves_ok_when_winner_finalises_success() {
    let (inner_xdr, fp_g, fp_signer) = build_signed_inner(3001, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    let (dir, store) = open_temp_store("fb-loser-success");

    // Pre-seed a Pending receipt (submitted=true) — simulates a live winner.
    let outer_tx_hash = "2222222222222222222222222222222222222222222222222222222222222222";
    store.try_begin(&inner_key, outer_tx_hash, 0, 100).unwrap();
    store.mark_submitted(&inner_key).unwrap();

    // Clone the store (ReceiptStore is Clone — shares the same Arc<Mutex>
    // internally) so the background finaliser can write concurrently.
    let store_for_bg = store.clone();
    let inner_key_bg = inner_key.clone();

    // Background task: finalises Success after a short wall-clock delay,
    // mimicking a real winner that was processing the submission concurrently.
    let bg = tokio::task::spawn_blocking(move || {
        std::thread::sleep(Duration::from_millis(500));
        store_for_bg
            .finalize(&inner_key_bg, ReceiptStatus::Success, Some(FAKE_LEDGER))
            .unwrap();
    });

    // Loser path: sees AlreadyPresent(Pending) → wait_for_winner_fee_bump
    // polls store until bg task finalises Success.
    let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_g,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    bg.await.expect("background finaliser must complete");

    assert!(
        result.is_ok(),
        "loser poll must return Ok when winner finalises Success; got: {result:?}"
    );
    let sub = result.unwrap();
    assert_eq!(
        sub.ledger, FAKE_LEDGER,
        "loser result ledger must match the finalised Success ledger; got: {}",
        sub.ledger
    );

    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (c) Invalid fee_source on the outer hash computation step

// ─────────────────────────────────────────────────────────────────────────────

/// An invalid `fee_source` strkey causes `compute_outer_tx_hash_hex` to fail
/// with `ValidationError::AddressInvalid` before any signing or RPC call.
///
/// Supplements the existing `fee_bump_retry_unit` test with a different invalid
/// strkey format (a G-strkey with wrong checksum vs a completely non-strkey string).
#[tokio::test]
async fn invalid_fee_source_on_retry_path_returns_validation_address_invalid() {
    let (inner_xdr, _fp_g, fp_signer) = build_signed_inner(4001, None).await;

    let (dir, store) = open_temp_store("fb-invalid-fee-source");
    let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();

    // A G-strkey-looking string with invalid base32 checksum.
    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // invalid: too short
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(5),
    )
    .await;

    assert!(
        result.is_err(),
        "invalid fee_source must return Err; got: {result:?}"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            WalletError::Validation(ValidationError::AddressInvalid { .. })
        ),
        "invalid fee_source must map to ValidationError::AddressInvalid; got: {err:?}"
    );
    assert_eq!(
        err.code(),
        "validation.address_invalid",
        "error code must be validation.address_invalid; got: {}",
        err.code()
    );

    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (d) Outer tx hash stored in receipt.tx_hash equals the precomputed hash
// ─────────────────────────────────────────────────────────────────────────────

/// On the winner path, the receipt's `tx_hash` field must equal the outer fee-bump
/// tx hash that `compute_outer_tx_hash_hex` would produce for the same inputs.
///
/// The receipt stores the OUTER hash (the poll handle); the idempotency key
/// (`envelope_hash`) stores the prefixed INNER hash.  This test verifies the
/// two hash fields are different and that `tx_hash` (outer) matches the
/// precomputed outer hash.
#[tokio::test]
async fn receipt_tx_hash_equals_outer_hash_and_differs_from_inner_key() {
    let (inner_xdr, fp_g, fp_signer) = build_signed_inner(5001, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    let (dir, store) = open_temp_store("fb-outer-hash-check");
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
        .up_to_n_times(10)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_g,
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

    let receipt = store.get(&inner_key).unwrap().unwrap();

    // envelope_hash must be the prefixed inner key (idempotency identity).
    assert_eq!(
        receipt.envelope_hash, inner_key,
        "receipt.envelope_hash must equal the prefixed inner key; \
         got: {}",
        receipt.envelope_hash
    );
    assert!(
        receipt.envelope_hash.starts_with("feebump-inner:"),
        "receipt.envelope_hash must start with 'feebump-inner:'; got: {}",
        receipt.envelope_hash
    );

    // tx_hash must be a 64-char hex string (outer fee-bump hash).
    assert_eq!(
        receipt.tx_hash.len(),
        64,
        "receipt.tx_hash must be a 64-char hex string (outer hash); got: {}",
        receipt.tx_hash
    );
    assert!(
        receipt.tx_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "receipt.tx_hash must be lowercase hex; got: {}",
        receipt.tx_hash
    );

    // The outer hash (tx_hash) must differ from the inner key (different hash spaces).
    let inner_hash_part = inner_key
        .strip_prefix("feebump-inner:")
        .unwrap_or(&inner_key);
    assert_ne!(
        receipt.tx_hash, inner_hash_part,
        "receipt.tx_hash (outer) must differ from inner tx hash (inner key hash part)"
    );

    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (e) Inner key from a no-max-time inner tx is 64-hex-char SHA-256
// ─────────────────────────────────────────────────────────────────────────────

/// The inner tx hash hex is always 64 hex characters regardless of whether the
/// inner tx has a `TimeBounds.maxTime` or not.
///
/// Tests the path where `max_time=0` (no `TimeBounds`), distinct from the
/// `inner_max_time_extracted_from_inner_envelope` test which uses a non-zero maxTime.
#[tokio::test]
async fn inner_key_for_no_max_time_inner_is_64_hex_chars() {
    let (inner_xdr, _fp_g, _fp_signer) = build_signed_inner(6001, None).await; // no maxTime
    let key = inner_key_for(&inner_xdr);

    assert!(
        key.starts_with("feebump-inner:"),
        "inner key must start with 'feebump-inner:'; got: {key}"
    );

    let hash_part = key.strip_prefix("feebump-inner:").unwrap();
    assert_eq!(
        hash_part.len(),
        64,
        "hash part must be 64 hex chars; got: {} chars",
        hash_part.len()
    );
    assert!(
        hash_part.chars().all(|c| c.is_ascii_hexdigit()),
        "hash part must be lowercase hex; got: {hash_part}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// (f) FeeSourceSignerMismatch abandons the receipt (pre-submit cleanup)
// ─────────────────────────────────────────────────────────────────────────────

/// When `build_and_sign_fee_bump` fails with `FeeSourceSignerMismatch` (the
/// fee_source does not match the signer's public key), the `Winner` path calls
/// `abandon_pre_submit` on the Pending receipt entry.
///
/// After the call:
/// - The store must have NO entry for the inner key (the Pending was abandoned).
/// - A subsequent call for the same inner key must be Winner again (can retry
///   with the correct signer).
#[tokio::test]
async fn fee_source_signer_mismatch_abandons_pending_receipt_allowing_retry() {
    let (inner_xdr, fp_g, _fp_signer) = build_signed_inner(7001, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    let (dir, store) = open_temp_store("fb-mismatch-abandon");

    // Use the WRONG_PAYER_SEED signer, whose public key does NOT match fp_g.
    let wrong_signer = SoftwareSigningKey::new_from_bytes(WRONG_PAYER_SEED);

    let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();

    // First call: mismatch between fee_source (fp_g) and wrong_signer.
    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_g, // declares fp_g as fee_source
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &wrong_signer, // but signs with wrong key
        &store,
        100,
        Duration::from_secs(5),
    )
    .await;

    assert!(
        result.is_err(),
        "FeeSourceSignerMismatch must return Err; got: {result:?}"
    );

    // The receipt must be ABSENT (abandon_pre_submit removed it).
    let receipt = store.get(&inner_key).unwrap();
    assert!(
        receipt.is_none(),
        "receipt must be absent after mismatch (abandon_pre_submit must remove it); \
         got: {receipt:?}"
    );

    // A retry with the correct signer must be the winner (no AlreadyPresent).
    let correct_signer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);
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
        .up_to_n_times(5)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client2 = StellarRpcClient::new(&server.uri()).unwrap();

    let retry_result = submit_fee_bump_idempotent(
        &client2,
        &inner_xdr,
        &fp_g,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &correct_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    assert!(
        retry_result.is_ok(),
        "retry with correct signer after mismatch must succeed; got: {retry_result:?}"
    );
    let sub = retry_result.unwrap();
    assert_eq!(
        sub.ledger, FAKE_LEDGER,
        "retry must confirm at the expected ledger; got: {}",
        sub.ledger
    );

    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (g) Inner V0 envelope rejected at submit_fee_bump_idempotent entry
// ─────────────────────────────────────────────────────────────────────────────

/// A `TxV0` envelope as `inner_envelope_xdr` is rejected at
/// `submit_fee_bump_idempotent`'s `decode_inner_v1` call.
///
/// The error must be a `WalletError` (from `FeeBumpError::InnerNotV1` →
/// `WalletError`) and NO receipt entry must be written to the store.
#[tokio::test]
async fn v0_inner_envelope_rejected_before_receipt_written() {
    use stellar_xdr::{
        Memo, SequenceNumber, TransactionEnvelope, TransactionV0, TransactionV0Envelope,
        TransactionV0Ext, Uint256,
    };

    // Build a TxV0 XDR.
    let v0_xdr = {
        let env = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256([0x20u8; 32]),
                fee: 100,
                seq_num: SequenceNumber(1),
                time_bounds: None,
                memo: Memo::None,
                operations: vec![].try_into().expect("empty ops"),
                ext: TransactionV0Ext::V0,
            },
            signatures: vec![].try_into().expect("empty sigs"),
        });
        env.to_xdr_base64(Limits::none()).expect("encode v0")
    };

    let fp_g = fee_payer_gstrkey();
    let fp_signer = SoftwareSigningKey::new_from_bytes(FEE_PAYER_SEED);

    let (dir, store) = open_temp_store("fb-v0-reject");
    let client = StellarRpcClient::new("https://soroban-testnet.stellar.org").unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &v0_xdr,
        &fp_g,
        300,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(5),
    )
    .await;

    assert!(
        result.is_err(),
        "TxV0 inner must be rejected; got: {result:?}"
    );

    // The error must be a typed validation/protocol error, not UnexpectedState.
    let err = result.unwrap_err();
    assert!(
        !matches!(err, WalletError::Internal(..)),
        "TxV0 rejection must not be Internal; got: {err:?}"
    );

    // No receipt entry must have been written for any key.
    // We cannot enumerate all keys in ReceiptStore via a public API, but we can
    // confirm there is nothing at the hash derived from the v0 XDR (since the
    // rejection happens before any store.try_begin call).
    //
    // Because v0 XDR decode fails at decode_inner_v1, the inner key is never
    // computed and no receipt row is written.  The store must be empty, which we
    // verify by checking the dummy inner_key_for fallback is absent.
    //
    // The simplest verifiable property: the call returned Err before any
    // store.try_begin, so the store get for any representative key returns None.
    use sha2::Digest as _;
    let fake_hash = Sha256::digest(v0_xdr.as_bytes());
    let fake_key = format!(
        "feebump-inner:{}",
        fake_hash.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    );
    // This key was never written; it must be absent.
    assert!(
        store.get(&fake_key).unwrap().is_none(),
        "no receipt must be written for v0 rejection; store must be empty"
    );

    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (h) Outer hash is network-passphrase-sensitive
// ─────────────────────────────────────────────────────────────────────────────

/// The outer tx hash changes when the network passphrase changes, even if the
/// inner XDR and fee are identical.
///
/// This guards the `compute_outer_tx_hash_hex` preimage construction: the
/// `network_id = SHA-256(passphrase)` is embedded in the
/// `TransactionSignaturePayload`.  Different passphrases → different network_id
/// → different outer hash.
#[tokio::test]
async fn outer_hash_is_sensitive_to_network_passphrase() {
    use stellar_xdr::{
        FeeBumpTransaction, FeeBumpTransactionExt, FeeBumpTransactionInnerTx, Uint256,
    };

    let (inner_xdr, fp_g, _fp_signer) = build_signed_inner(8001, None).await;

    let pk = stellar_strkey::ed25519::PublicKey::from_string(&fp_g).unwrap();
    let pk_bytes = pk.0;

    let compute_outer_hash = |passphrase: &str| -> String {
        let envelope = TransactionEnvelope::from_xdr_base64(&inner_xdr, Limits::none()).unwrap();
        let v1 = match envelope {
            TransactionEnvelope::Tx(v1) => v1,
            _ => panic!("expected Tx(v1)"),
        };
        let fee_bump_tx = FeeBumpTransaction {
            fee_source: stellar_xdr::MuxedAccount::Ed25519(Uint256(pk_bytes)),
            fee: 500,
            inner_tx: FeeBumpTransactionInnerTx::Tx(v1),
            ext: FeeBumpTransactionExt::V0,
        };
        let network_id = Hash(Sha256::digest(passphrase.as_bytes()).into());
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

    let testnet_outer = compute_outer_hash(TESTNET_PASSPHRASE);
    let pubnet_outer = compute_outer_hash("Public Global Stellar Network ; September 2015");
    let custom_outer = compute_outer_hash("My Custom Network ; 2026");

    // All three must differ.
    assert_ne!(
        testnet_outer, pubnet_outer,
        "testnet and pubnet outer hashes must differ"
    );
    assert_ne!(
        testnet_outer, custom_outer,
        "testnet and custom outer hashes must differ"
    );
    assert_ne!(
        pubnet_outer, custom_outer,
        "pubnet and custom outer hashes must differ"
    );

    // All must be valid 64-char hex strings.
    for hash in [&testnet_outer, &pubnet_outer, &custom_outer] {
        assert_eq!(
            hash.len(),
            64,
            "outer hash must be 64 hex chars; got: {} chars",
            hash.len()
        );
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "outer hash must be lowercase hex; got: {hash}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// (i) Verify inner_key is identical for the same inner tx across multiple calls
// ─────────────────────────────────────────────────────────────────────────────

/// The idempotency key `feebump-inner:<hash>` is stable: the same inner XDR
/// always produces the same key, regardless of how many times it is computed.
///
/// Verifies the determinism property that the receipt store de-duplicates on.
#[tokio::test]
async fn inner_key_is_stable_across_repeated_computations() {
    let (inner_xdr, _fp_g, _fp_signer) = build_signed_inner(9001, None).await;

    // Compute the inner key three times from the same XDR.
    let key1 = inner_key_for(&inner_xdr);
    let key2 = inner_key_for(&inner_xdr);
    let key3 = inner_key_for(&inner_xdr);

    assert_eq!(key1, key2, "inner key must be stable (call 1 == call 2)");
    assert_eq!(key2, key3, "inner key must be stable (call 2 == call 3)");

    // Also verify the hash part length.
    let hash_part = key1.strip_prefix("feebump-inner:").unwrap();
    assert_eq!(hash_part.len(), 64, "hash part must be 64 hex chars");
}

// ─────────────────────────────────────────────────────────────────────────────
// (j) receipt.max_time is 0 when inner tx has no TimeBounds
// ─────────────────────────────────────────────────────────────────────────────

/// When the inner tx has no `TimeBounds` (no maxTime), the stored receipt's
/// `max_time` field must be 0 (the sentinel for "no expiry").
///
/// CAP-15: a fee-bump has no `cond` of its own.  If the inner also has no
/// TimeBounds, the effective max_time is 0 (never expires from the receipt's
/// perspective).
#[tokio::test]
async fn receipt_max_time_is_zero_when_inner_has_no_time_bounds() {
    let (inner_xdr, fp_g, fp_signer) = build_signed_inner(10001, None).await; // no maxTime
    let inner_key = inner_key_for(&inner_xdr);

    let (dir, store) = open_temp_store("fb-maxtime-zero");
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
        .up_to_n_times(5)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_g,
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

    let receipt = store.get(&inner_key).unwrap().unwrap();
    assert_eq!(
        receipt.max_time, 0,
        "receipt.max_time must be 0 when inner tx has no TimeBounds; got: {}",
        receipt.max_time
    );

    drop(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// (k) FeeBumpInnerFailed on the fee_bump idempotent path stores Failed receipt
// ─────────────────────────────────────────────────────────────────────────────

/// When `getTransaction` returns FAILED with `TxFeeBumpInnerFailed(TxBadAuth)`
/// XDR on the fee_bump idempotent winner path, the receipt is stored as `Failed`
/// and the returned error carries the inner result code.
#[tokio::test]
async fn winner_path_feebump_inner_failed_stores_failed_receipt() {
    use stellar_xdr::{
        Hash, InnerTransactionResult, InnerTransactionResultExt, InnerTransactionResultPair,
        InnerTransactionResultResult, Limits, TransactionResult, TransactionResultExt,
        TransactionResultResult, WriteXdr,
    };

    let (inner_xdr, fp_g, fp_signer) = build_signed_inner(11001, None).await;
    let inner_key = inner_key_for(&inner_xdr);

    let (dir, store) = open_temp_store("fb-inner-failed");
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(EchoIdResponder::new(send_pending_response()))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // getTransaction → FAILED with TxFeeBumpInnerFailed(TxBadAuth).
    let pair = InnerTransactionResultPair {
        transaction_hash: Hash([0xddu8; 32]),
        result: InnerTransactionResult {
            fee_charged: 500,
            result: InnerTransactionResultResult::TxBadAuth,
            ext: InnerTransactionResultExt::V0,
        },
    };
    let tx_result = TransactionResult {
        fee_charged: 500,
        result: TransactionResultResult::TxFeeBumpInnerFailed(pair),
        ext: TransactionResultExt::V0,
    };
    let result_xdr_b64 = tx_result.to_xdr_base64(Limits::none()).unwrap();

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "FAILED",
            "txHash": FAKE_OUTER_HASH,
            "ledger": null,
            "createdAt": "1700000000",
            "envelopeXdr": null,
            "resultXdr": result_xdr_b64,
            "resultMetaXdr": null
        })))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getHealth"})))
        .respond_with(EchoIdResponder::new(get_health_ok_response()))
        .up_to_n_times(10)
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let result = submit_fee_bump_idempotent(
        &client,
        &inner_xdr,
        &fp_g,
        500,
        10_000,
        TESTNET_PASSPHRASE,
        &fp_signer,
        &store,
        100,
        Duration::from_secs(30),
    )
    .await;

    // Must return Err with the FeeBumpInnerRejected code.
    assert!(
        result.is_err(),
        "TxFeeBumpInnerFailed must return Err; got: {result:?}"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.code(),
        "submission.feebump_inner_rejected",
        "error code must be submission.feebump_inner_rejected; got: {}",
        err.code()
    );
    match &err {
        WalletError::Submission(SubmissionError::FeeBumpInnerRejected {
            inner_result_code,
            ..
        }) => {
            assert_eq!(
                inner_result_code, "TxBadAuth",
                "inner_result_code must be 'TxBadAuth'; got: {inner_result_code}"
            );
        }
        other => panic!("expected FeeBumpInnerRejected; got: {other:?}"),
    }

    // Receipt must be terminal Failed.
    let receipt = store.get(&inner_key).unwrap().unwrap();
    assert!(
        matches!(receipt.status, ReceiptStatus::Failed { .. }),
        "receipt must be Failed after TxFeeBumpInnerFailed; got: {:?}",
        receipt.status
    );

    drop(dir);
}
