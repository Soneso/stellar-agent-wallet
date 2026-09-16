//! Offline tests for `init_pool`.
//!
//! Uses a `wiremock` mock RPC server to avoid any live network dependency.
//! The mock answers the endpoint-identity probe (`getNetwork`) and the
//! signer-set fetch (`getLedgerEntries`) that precede the send, then returns a
//! JSON-RPC `sendTransaction` PENDING response followed by a `getTransaction`
//! SUCCESS response, reproducing the submit-and-confirm flow that `init_pool`
//! calls via `submit_transaction_and_wait`.
//!
//! Validation-error paths (N=0, N>MAX, mismatched signers/indices) return
//! before any RPC call, so no mock server is needed for those cases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    reason = "test-only; panics and unwraps acceptable in integration tests"
)]

use std::sync::LazyLock;

use serde_json::json;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::{SoftwareSigningKey, StellarRpcClient};
use stellar_agent_pool::PoolError;
use stellar_agent_pool::init::{InitParams, assert_sandwich_structure, init_pool};
use stellar_agent_pool::pool::ChannelPool;
use stellar_agent_test_support::signed_envelope::{
    account_id_for_seed, get_network_result, ledger_entries_result_for,
};
use stellar_agent_test_support::{EchoIdResponder, SubmissionEchoResponder};
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FEE_PER_OP: u32 = 100;

// ─────────────────────────────────────────────────────────────────────────────
// The funder and channel accounts, each derived from the seed of the key that
// signs for it. The submit layer verifies every signature against the signer
// set of the account it answers for, so an account and its signing key must be
// the same key; a strkey chosen independently of the seed cannot satisfy that.
const FUNDER_SEED: [u8; 32] = [1u8; 32];
const CHANNEL_SEED_1: [u8; 32] = [2u8; 32];
const CHANNEL_SEED_2: [u8; 32] = [3u8; 32];

static FUNDER_KEY: LazyLock<String> = LazyLock::new(|| account_id_for_seed(FUNDER_SEED));
static CHANNEL_KEY_1: LazyLock<String> = LazyLock::new(|| account_id_for_seed(CHANNEL_SEED_1));
static CHANNEL_KEY_2: LazyLock<String> = LazyLock::new(|| account_id_for_seed(CHANNEL_SEED_2));

// ─────────────────────────────────────────────────────────────────────────────
// Validation errors — no RPC needed
// ─────────────────────────────────────────────────────────────────────────────

/// N=0 is rejected with `SizeOutOfRange` before any RPC call.
#[tokio::test]
async fn init_pool_n0_returns_size_out_of_range() {
    // Use a dummy URL: init_pool must return before touching the network.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let funder_key = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 100,
        funder_signer: &funder_key as &dyn Signer,
        channel_signers: vec![],
        channel_strkeys: vec![],
        channel_indices: vec![],
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    match init_pool(&client, params).await {
        Err(PoolError::SizeOutOfRange { requested: 0 }) => {}
        Err(e) => panic!("expected SizeOutOfRange(0), got Err: {e}"),
        Ok(_) => panic!("expected SizeOutOfRange(0), got Ok"),
    }
}

/// N > MAX_SIZE is rejected with `SizeOutOfRange` before any RPC call.
#[tokio::test]
async fn init_pool_n_exceeds_max_returns_size_out_of_range() {
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let funder_key = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);

    let n = ChannelPool::MAX_SIZE + 1; // 20
    let channel_strkeys: Vec<String> = (0..n).map(|_| CHANNEL_KEY_1.clone()).collect();
    let channel_signers: Vec<SoftwareSigningKey> = (0..n as u8)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i + 2;
            SoftwareSigningKey::new_from_bytes(seed)
        })
        .collect();
    let channel_indices: Vec<u32> = (1..=n as u32).collect();

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 100,
        funder_signer: &funder_key as &dyn Signer,
        channel_signers,
        channel_strkeys,
        channel_indices,
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    match init_pool(&client, params).await {
        Err(PoolError::SizeOutOfRange { requested }) if requested == n => {}
        Err(e) => panic!("expected SizeOutOfRange({n}), got Err: {e}"),
        Ok(_) => panic!("expected SizeOutOfRange({n}), got Ok"),
    }
}

/// `channel_signers.len()` != `channel_strkeys.len()` → `InitFailed`.
#[tokio::test]
async fn init_pool_signers_len_mismatch_returns_init_failed() {
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let funder_key = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 100,
        funder_signer: &funder_key as &dyn Signer,
        // 2 strkeys, only 1 signer.
        channel_strkeys: vec![CHANNEL_KEY_1.clone(), CHANNEL_KEY_2.clone()],
        channel_signers: vec![SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_1)],
        channel_indices: vec![1, 2],
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    match init_pool(&client, params).await {
        Err(PoolError::InitFailed { .. }) => {}
        Err(e) => panic!("expected InitFailed for signer mismatch, got Err: {e}"),
        Ok(_) => panic!("expected InitFailed for signer mismatch, got Ok"),
    }
}

/// `channel_indices.len()` != `channel_strkeys.len()` → `InitFailed`.
#[tokio::test]
async fn init_pool_indices_len_mismatch_returns_init_failed() {
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let funder_key = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 100,
        funder_signer: &funder_key as &dyn Signer,
        // 2 strkeys + 2 signers, but only 1 index.
        channel_strkeys: vec![CHANNEL_KEY_1.clone(), CHANNEL_KEY_2.clone()],
        channel_signers: vec![
            SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_1),
            SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_2),
        ],
        channel_indices: vec![1], // too few
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    match init_pool(&client, params).await {
        Err(PoolError::InitFailed { .. }) => {}
        Err(e) => panic!("expected InitFailed for index mismatch, got Err: {e}"),
        Ok(_) => panic!("expected InitFailed for index mismatch, got Ok"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Success path — N=2 with wiremock
// ─────────────────────────────────────────────────────────────────────────────

/// `init_pool` succeeds with N=2 channels against a mock RPC server.
///
/// Asserts:
/// - `InitResult.channel_records.len() == 2` with the correct strkeys.
/// - `tx_hash` is non-empty.
/// - `ledger` is the value returned by the mock.
/// - The submitted envelope has the correct CAP-33 sandwich structure
///   (verified by decoding the captured request body and calling
///   `assert_sandwich_structure`).
#[tokio::test]
async fn init_pool_n2_success_submits_valid_sandwich() {
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use wiremock::{Request, Respond};

    // ── Capture sendTransaction bodies so we can inspect the envelope XDR ──
    let captured: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));

    struct CapturingResponder {
        result: Value,
        captured: Arc<Mutex<Vec<Value>>>,
    }
    impl Respond for CapturingResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            if let Ok(body) = serde_json::from_slice::<Value>(&request.body)
                && let Ok(mut g) = self.captured.lock()
            {
                g.push(body);
            }
            let body = serde_json::from_slice::<Value>(&request.body).unwrap_or_else(|_| json!({}));
            let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
            // A real endpoint answers `sendTransaction` with the hash of the
            // transaction it was handed, and the submitting wallet refuses a
            // hash that does not describe what it signed.
            let mut result = self.result.clone();
            if body.get("method").and_then(Value::as_str) == Some("sendTransaction")
                && let Some(object) = result.as_object_mut()
            {
                object.insert(
                    "hash".to_owned(),
                    json!(stellar_agent_test_support::send_transaction_hash_hex(
                        &body,
                        TESTNET_PASSPHRASE
                    )),
                );
            }
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc":"2.0","id":id,"result":result}))
                .insert_header("content-type", "application/json")
        }
    }

    let server = MockServer::start().await;
    let tx_hash = "b".repeat(64);

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)))
        .mount(&server)
        .await;

    // The ledger as it stands before the sandwich is applied: the funder is
    // the only account that exists, each with its own master key as sole
    // signer. The channel accounts are created by this very transaction.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(EchoIdResponder::new(ledger_entries_result_for(&[
            FUNDER_KEY.as_str(),
        ])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(CapturingResponder {
            result: json!({
                "hash": tx_hash,
                "status": "PENDING",
                "latestLedger": 1000,
                "latestLedgerCloseTime": "1234567890"
            }),
            captured: Arc::clone(&captured),
        })
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "SUCCESS",
            "ledger": 1005,
            "txHash": tx_hash
        })))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).expect("mock URL must be valid");

    let funder_signer = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);
    let ch1_signer = SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_1);
    let ch2_signer = SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_2);

    let channel_strkeys = vec![CHANNEL_KEY_1.clone(), CHANNEL_KEY_2.clone()];
    let channel_indices = vec![1u32, 2u32];

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 500,
        funder_signer: &funder_signer as &dyn Signer,
        channel_signers: vec![ch1_signer, ch2_signer],
        channel_strkeys: channel_strkeys.clone(),
        channel_indices: channel_indices.clone(),
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    let result = init_pool(&client, params)
        .await
        .expect("init_pool must succeed against mock RPC");

    // ── Structural assertions on InitResult ──────────────────────────────────
    assert_eq!(
        result.channel_records.len(),
        2,
        "InitResult must contain 2 channel records"
    );
    assert_eq!(
        result.channel_records[0].index, 1,
        "first channel record index must be 1"
    );
    assert_eq!(
        result.channel_records[0].public_key, *CHANNEL_KEY_1,
        "first channel public key must match"
    );
    assert_eq!(
        result.channel_records[1].index, 2,
        "second channel record index must be 2"
    );
    assert_eq!(
        result.channel_records[1].public_key, *CHANNEL_KEY_2,
        "second channel public key must match"
    );
    assert!(!result.tx_hash.is_empty(), "tx_hash must be non-empty");
    assert_eq!(
        result.ledger, 1005,
        "ledger must match mock getTransaction response"
    );

    // ── Sandwich structure verification ──────────────────────────────────────
    // Extract the submitted envelope XDR from the captured sendTransaction body.
    let bodies = captured.lock().expect("captured lock");
    let send_body = bodies
        .iter()
        .find(|v| v.get("method").and_then(|m| m.as_str()) == Some("sendTransaction"))
        .expect("must have captured at least one sendTransaction body");

    let envelope_xdr = send_body["params"]["transaction"]
        .as_str()
        .expect("params.transaction must be a base64-XDR string");

    assert_sandwich_structure(envelope_xdr, FUNDER_KEY.as_str(), &channel_strkeys)
        .expect("submitted envelope must have valid N=2 CAP-33 sandwich structure");
}

/// `init_pool` with N=1 against a mock RPC server succeeds and produces a
/// single-channel `InitResult`.
#[tokio::test]
async fn init_pool_n1_success_single_channel() {
    let server = MockServer::start().await;
    let tx_hash = "c".repeat(64);

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)))
        .mount(&server)
        .await;

    // The ledger as it stands before the sandwich is applied: the funder is
    // the only account that exists, each with its own master key as sole
    // signer. The channel accounts are created by this very transaction.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(EchoIdResponder::new(ledger_entries_result_for(&[
            FUNDER_KEY.as_str(),
        ])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(SubmissionEchoResponder::new(
            json!({
                "hash": tx_hash,
                "status": "PENDING",
                "latestLedger": 1000,
                "latestLedgerCloseTime": "1234567890"
            }),
            TESTNET_PASSPHRASE,
        ))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getTransaction"})))
        .respond_with(EchoIdResponder::new(json!({
            "status": "SUCCESS",
            "ledger": 2000,
            "txHash": tx_hash
        })))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).expect("mock URL must be valid");

    let funder_signer = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);
    let ch_signer = SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_1);

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 200,
        funder_signer: &funder_signer as &dyn Signer,
        channel_signers: vec![ch_signer],
        channel_strkeys: vec![CHANNEL_KEY_1.clone()],
        channel_indices: vec![1],
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    let result = init_pool(&client, params)
        .await
        .expect("init_pool must succeed for N=1");

    assert_eq!(result.channel_records.len(), 1);
    assert_eq!(result.channel_records[0].index, 1);
    assert_eq!(result.channel_records[0].public_key, *CHANNEL_KEY_1);
    assert_eq!(result.ledger, 2000);
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC error → InitFailed
// ─────────────────────────────────────────────────────────────────────────────

/// When the RPC rejects the send, `init_pool` must return `InitFailed`.
///
/// The endpoint answers the identity probe and the signer-set fetch so the
/// submission reaches the send step; the 500 lands only on `sendTransaction`,
/// which is the network rejection this test is about. A blanket 500 would be
/// consumed by the probe and never exercise the send path at all.
#[tokio::test]
async fn init_pool_rpc_error_returns_init_failed() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getNetwork"})))
        .respond_with(EchoIdResponder::new(get_network_result(TESTNET_PASSPHRASE)))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "getLedgerEntries"})))
        .respond_with(EchoIdResponder::new(ledger_entries_result_for(&[
            FUNDER_KEY.as_str(),
        ])))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "sendTransaction"})))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).expect("mock URL must be valid");
    let funder_signer = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);
    let ch_signer = SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_1);

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 100,
        funder_signer: &funder_signer as &dyn Signer,
        channel_signers: vec![ch_signer],
        channel_strkeys: vec![CHANNEL_KEY_1.clone()],
        channel_indices: vec![1],
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    match init_pool(&client, params).await {
        Err(PoolError::InitFailed { .. }) => {}
        Err(e) => panic!("expected InitFailed on RPC error, got Err: {e}"),
        Ok(_) => panic!("expected InitFailed on RPC error, got Ok"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Invalid channel strkey — builder error paths
// ─────────────────────────────────────────────────────────────────────────────

/// `init_pool` with an invalid channel G-strkey returns `InitFailed`.
///
/// The invalid strkey is passed as `channel_strkeys[0]`.  After the N and
/// length checks pass, the builder's `begin_sponsoring_future_reserves` call
/// parses the strkey and fails because "INVALID-KEY" is not a valid G-strkey.
/// This triggers the `map_err` closure at the `begin_sponsoring_future_reserves`
/// call site inside `init_pool`.
#[tokio::test]
async fn init_pool_invalid_channel_strkey_returns_init_failed() {
    // Use a loopback URL: init_pool must return before any network call.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let funder_signer = SoftwareSigningKey::new_from_bytes(FUNDER_SEED);
    let ch_signer = SoftwareSigningKey::new_from_bytes(CHANNEL_SEED_1);

    let params = InitParams {
        funder_strkey: FUNDER_KEY.as_str(),
        funder_sequence: 100,
        funder_signer: &funder_signer as &dyn Signer,
        channel_signers: vec![ch_signer],
        // Invalid G-strkey: builder validation must catch this.
        channel_strkeys: vec!["INVALID-CHANNEL-KEY".to_owned()],
        channel_indices: vec![1],
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    match init_pool(&client, params).await {
        Err(PoolError::InitFailed { detail }) => {
            assert!(
                detail.contains("begin_sponsoring_future_reserves") || detail.contains("failed"),
                "error detail must mention the builder failure; got: {detail}"
            );
        }
        Err(e) => panic!("expected InitFailed for invalid strkey, got Err: {e}"),
        Ok(_) => panic!("expected InitFailed for invalid strkey, got Ok"),
    }
}
