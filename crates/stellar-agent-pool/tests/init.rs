//! Offline tests for `init_pool`.
//!
//! Uses a `wiremock` mock RPC server to avoid any live network dependency.
//! The mock returns a JSON-RPC `sendTransaction` PENDING response followed by a
//! `getTransaction` SUCCESS response, reproducing the minimal submit-and-confirm
//! flow that `init_pool` calls via `submit_transaction_and_wait`.
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

use serde_json::json;
use stellar_agent_network::signing::Signer;
use stellar_agent_network::{SoftwareSigningKey, StellarRpcClient};
use stellar_agent_pool::PoolError;
use stellar_agent_pool::init::{InitParams, assert_sandwich_structure, init_pool};
use stellar_agent_pool::pool::ChannelPool;
use stellar_agent_test_support::EchoIdResponder;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FEE_PER_OP: u32 = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Known-valid G-strkeys for the funder and channels.
// Derived from fixed seeds, verified against stellar-agent-network builder.rs.
// seed=[1u8;32] → GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY
// seed=[2u8;32] → GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL
// seed=[3u8;32] → GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6
// ─────────────────────────────────────────────────────────────────────────────
const FUNDER_KEY: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const CHANNEL_KEY_1: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";
const CHANNEL_KEY_2: &str = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";

// ─────────────────────────────────────────────────────────────────────────────
// Validation errors — no RPC needed
// ─────────────────────────────────────────────────────────────────────────────

/// N=0 is rejected with `SizeOutOfRange` before any RPC call.
#[tokio::test]
async fn init_pool_n0_returns_size_out_of_range() {
    // Use a dummy URL: init_pool must return before touching the network.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
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
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);

    let n = ChannelPool::MAX_SIZE + 1; // 20
    let channel_strkeys: Vec<String> = (0..n).map(|_| CHANNEL_KEY_1.to_owned()).collect();
    let channel_signers: Vec<SoftwareSigningKey> = (0..n as u8)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i + 2;
            SoftwareSigningKey::new_from_bytes(seed)
        })
        .collect();
    let channel_indices: Vec<u32> = (1..=n as u32).collect();

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
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
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
        funder_sequence: 100,
        funder_signer: &funder_key as &dyn Signer,
        // 2 strkeys, only 1 signer.
        channel_strkeys: vec![CHANNEL_KEY_1.to_owned(), CHANNEL_KEY_2.to_owned()],
        channel_signers: vec![SoftwareSigningKey::new_from_bytes([2u8; 32])],
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
    let funder_key = SoftwareSigningKey::new_from_bytes([1u8; 32]);

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
        funder_sequence: 100,
        funder_signer: &funder_key as &dyn Signer,
        // 2 strkeys + 2 signers, but only 1 index.
        channel_strkeys: vec![CHANNEL_KEY_1.to_owned(), CHANNEL_KEY_2.to_owned()],
        channel_signers: vec![
            SoftwareSigningKey::new_from_bytes([2u8; 32]),
            SoftwareSigningKey::new_from_bytes([3u8; 32]),
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
            let id = serde_json::from_slice::<Value>(&request.body)
                .ok()
                .and_then(|v| v.get("id").cloned())
                .unwrap_or_else(|| json!(1));
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc":"2.0","id":id,"result":self.result.clone()}))
                .insert_header("content-type", "application/json")
        }
    }

    let server = MockServer::start().await;
    let tx_hash = "b".repeat(64);

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

    let funder_signer = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch1_signer = SoftwareSigningKey::new_from_bytes([2u8; 32]);
    let ch2_signer = SoftwareSigningKey::new_from_bytes([3u8; 32]);

    let channel_strkeys = vec![CHANNEL_KEY_1.to_owned(), CHANNEL_KEY_2.to_owned()];
    let channel_indices = vec![1u32, 2u32];

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
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
        result.channel_records[0].public_key, CHANNEL_KEY_1,
        "first channel public key must match"
    );
    assert_eq!(
        result.channel_records[1].index, 2,
        "second channel record index must be 2"
    );
    assert_eq!(
        result.channel_records[1].public_key, CHANNEL_KEY_2,
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

    assert_sandwich_structure(envelope_xdr, FUNDER_KEY, &channel_strkeys)
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
            "status": "SUCCESS",
            "ledger": 2000,
            "txHash": tx_hash
        })))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).expect("mock URL must be valid");

    let funder_signer = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch_signer = SoftwareSigningKey::new_from_bytes([2u8; 32]);

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
        funder_sequence: 200,
        funder_signer: &funder_signer as &dyn Signer,
        channel_signers: vec![ch_signer],
        channel_strkeys: vec![CHANNEL_KEY_1.to_owned()],
        channel_indices: vec![1],
        network_passphrase: TESTNET_PASSPHRASE,
        fee_per_op: FEE_PER_OP,
    };

    let result = init_pool(&client, params)
        .await
        .expect("init_pool must succeed for N=1");

    assert_eq!(result.channel_records.len(), 1);
    assert_eq!(result.channel_records[0].index, 1);
    assert_eq!(result.channel_records[0].public_key, CHANNEL_KEY_1);
    assert_eq!(result.ledger, 2000);
}

// ─────────────────────────────────────────────────────────────────────────────
// RPC error → InitFailed
// ─────────────────────────────────────────────────────────────────────────────

/// When the mock RPC returns HTTP 500, `init_pool` must return `InitFailed`.
///
/// The 500 simulates a network or RPC rejection that causes
/// `submit_transaction_and_wait` to fail, which `init_pool` maps to `InitFailed`.
#[tokio::test]
async fn init_pool_rpc_error_returns_init_failed() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = StellarRpcClient::new(&server.uri()).expect("mock URL must be valid");
    let funder_signer = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch_signer = SoftwareSigningKey::new_from_bytes([2u8; 32]);

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
        funder_sequence: 100,
        funder_signer: &funder_signer as &dyn Signer,
        channel_signers: vec![ch_signer],
        channel_strkeys: vec![CHANNEL_KEY_1.to_owned()],
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
    let funder_signer = SoftwareSigningKey::new_from_bytes([1u8; 32]);
    let ch_signer = SoftwareSigningKey::new_from_bytes([2u8; 32]);

    let params = InitParams {
        funder_strkey: FUNDER_KEY,
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
