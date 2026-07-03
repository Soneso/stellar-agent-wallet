//! Concurrent `submit_pooled` integration test — mock RPC, no testnet.
//!
//! Drives K concurrent [`submit_pooled`] calls against a `wiremock` mock
//! RPC server and asserts:
//!
//! a) Each submission used a DISTINCT channel (no two concurrent tasks share
//!    the same `channel_index`).
//! b) Each submitted tx's `seq_num == channel_account_seq + 1` — proven by
//!    decoding the `sendTransaction` envelope XDR from the captured request body.
//! c) The pool is fully free after all K submissions complete.
//! d) `PoolExhausted` is returned IMMEDIATELY when the pool is full.
//!
//! # Mock RPC shape
//!
//! The `stellar-rpc-client` JSON-RPC `sendTransaction` method sends:
//! `{"method":"sendTransaction","params":{"transaction":"<base64-xdr>"},...}`.
//!
//! The `CapturingEchoResponder` captures the request body (so we can extract
//! the submitted XDR envelope) and returns the required JSON-RPC envelope.
//!
//! # Sequence-number proof
//!
//! Each `submit_pooled` call adds a single XLM `payment` of 1 stroop.  We
//! capture each `sendTransaction` body, decode the `params.transaction` XDR,
//! and assert `tx.seq_num == INITIAL_SEQ + 1` for every submission.  This
//! proves that `ClassicOpBuilder::new` received `lease.sequence_number()` AS-IS
//! (not `+1`) and that the builder auto-incremented correctly.
//!
//! # No keyring
//!
//! The pool master seed is a mock `[7u8; 64]`.  The mock RPC does not verify
//! signatures, only that the request is well-formed JSON.
//!

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::explicit_auto_deref,
    reason = "test-only; panics, unwraps, and eprintln acceptable in integration tests"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::json;
use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope};
use tokio::task::JoinSet;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use stellar_agent_network::StellarRpcClient;
use stellar_agent_pool::pool::{ChannelPool, TerminalOutcome};
use stellar_agent_pool::submit::submit_pooled;
use stellar_agent_pool::{ChannelRecord, PoolError};
use stellar_agent_test_support::EchoIdResponder;
use zeroize::Zeroizing;

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// 4 known-valid G-strkeys (from builder.rs TEST_SOURCE / TEST_DEST fixtures).
const CHANNEL_KEYS: [&str; 4] = [
    "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
    "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
    "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
    "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7",
];

/// Payment destination (must differ from channel keys).
///
/// Derived deterministically: `stellar_strkey::ed25519::PublicKey([7u8; 32]).to_string()`.
/// Any 32-byte array encodes to a valid G-strkey; this value is distinct from all
/// CHANNEL_KEYS entries and from FUNDER.
const DEST_KEY: &str = "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI";

const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const FEE_PER_OP: u32 = 100;
const SUBMIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Initial sequence number for all channels.
const INITIAL_SEQ: i64 = 100;

// ─────────────────────────────────────────────────────────────────────────────
// Fixture invariant checks
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that `DEST_KEY` parses as a valid G-strkey and is distinct from
/// all `CHANNEL_KEYS` entries.
#[test]
fn dest_key_is_valid_and_distinct_from_channel_keys() {
    // Must parse without error.
    stellar_strkey::ed25519::PublicKey::from_string(DEST_KEY)
        .expect("DEST_KEY must be a valid G-strkey");

    // Must not collide with any channel key.
    for ck in &CHANNEL_KEYS {
        assert_ne!(
            DEST_KEY, *ck,
            "DEST_KEY must differ from CHANNEL_KEYS entry {ck}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pool factory
// ─────────────────────────────────────────────────────────────────────────────

fn make_pool_k4() -> Arc<ChannelPool> {
    let channels: Vec<ChannelRecord> = CHANNEL_KEYS
        .iter()
        .enumerate()
        .map(|(i, &key)| ChannelRecord::new((i + 1) as u32, key))
        .collect();
    let seqs = vec![INITIAL_SEQ; 4];
    Arc::new(ChannelPool::from_records(channels, seqs).expect("pool construction must succeed"))
}

/// An ephemeral mock seed (not real; mock RPC does not verify signatures).
fn mock_seed() -> Zeroizing<[u8; 64]> {
    Zeroizing::new([7u8; 64])
}

// ─────────────────────────────────────────────────────────────────────────────
// Capturing responder
// ─────────────────────────────────────────────────────────────────────────────

/// A wiremock responder that captures request bodies and returns JSON-RPC
/// responses with the request `id` echoed back.
///
/// This allows us to capture the `sendTransaction` XDR envelopes for
/// sequence-number verification.
struct CapturingEchoResponder {
    result: Arc<serde_json::Value>,
    captured: Arc<Mutex<Vec<serde_json::Value>>>,
}

impl CapturingEchoResponder {
    fn new(result: serde_json::Value, captured: Arc<Mutex<Vec<serde_json::Value>>>) -> Self {
        Self {
            result: Arc::new(result),
            captured,
        }
    }
}

// wiremock::Respond is a synchronous trait; no async_trait needed.
impl Respond for CapturingEchoResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        // Parse the body and push a clone to the capture buffer.
        if let (Ok(body_val), Ok(mut guard)) = (
            serde_json::from_slice::<serde_json::Value>(&request.body),
            self.captured.lock(),
        ) {
            guard.push(body_val);
        }

        let req_id = serde_json::from_slice::<serde_json::Value>(&request.body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or_else(|| json!(1));

        ResponseTemplate::new(200)
            .set_body_json(json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": *self.result,
            }))
            .insert_header("content-type", "application/json")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// XDR inspection
// ─────────────────────────────────────────────────────────────────────────────

fn extract_seq_num_from_xdr(xdr_b64: &str) -> i64 {
    let env = TransactionEnvelope::from_xdr_base64(xdr_b64, Limits::none())
        .expect("envelope must decode from base64 XDR");
    match env {
        TransactionEnvelope::Tx(v1) => v1.tx.seq_num.0,
        other => panic!("expected V1 Tx envelope; got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

/// K=4 concurrent `submit_pooled` calls:
///
/// a) Pool is fully free after all K complete.
/// b) Each submitted envelope's `seq_num == INITIAL_SEQ + 1`.
/// c) After Success release, each channel's cached seq advanced by 1.
///
/// The `sendTransaction` method in `stellar-rpc-client` sends ObjectParams:
/// `{"method":"sendTransaction","params":{"transaction":"<b64-xdr>"},...}`
/// We capture and decode these to verify assertion (b).
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_submit_k4_distinct_channels_correct_seq_nums() {
    const K: usize = 4;

    // ── Set up mock RPC ──────────────────────────────────────────────────────
    let mock_server = MockServer::start().await;
    let tx_hash = "c".repeat(64);

    // Capture all sendTransaction bodies.  The two mocks are disambiguated by
    // the JSON-RPC `method` in the request body (`body_partial_json`), so a
    // concurrent `getTransaction` poll can never consume the `sendTransaction`
    // PENDING response (or vice versa) regardless of arrival order.  Matching on
    // the body method is deterministic under concurrency.
    let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": "sendTransaction" })))
        .respond_with(CapturingEchoResponder::new(
            json!({
                "hash": tx_hash,
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            Arc::clone(&captured),
        ))
        .mount(&mock_server)
        .await;

    // getTransaction SUCCESS mock for polling (body-method-matched).
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": "getTransaction" })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "SUCCESS",
            "ledger": 1005,
            "txHash": tx_hash
        })))
        .mount(&mock_server)
        .await;

    // ── Build pool ───────────────────────────────────────────────────────────
    let pool = make_pool_k4();
    let seed = mock_seed();
    let client =
        Arc::new(StellarRpcClient::new(&mock_server.uri()).expect("mock server URL must be valid"));

    // ── Spawn K concurrent tasks ─────────────────────────────────────────────
    let mut join_set: JoinSet<Result<u32, PoolError>> = JoinSet::new();

    for _ in 0..K {
        let pool_clone = Arc::clone(&pool);
        let client_clone = Arc::clone(&client);
        let seed_clone = Zeroizing::new(*seed);

        join_set.spawn(async move {
            let result = submit_pooled(
                &pool_clone,
                &client_clone,
                &seed_clone,
                TESTNET_PASSPHRASE,
                FEE_PER_OP,
                SUBMIT_TIMEOUT,
                |builder| {
                    // 1-stroop XLM payment; mock RPC does not validate balances.
                    let _ = builder.payment(
                        DEST_KEY,
                        stellar_agent_core::StellarAmount::from_stroops(1),
                        &stellar_agent_network::builder::Asset::Native,
                    );
                },
            )
            .await?;
            Ok(result.channel_index)
        });
    }

    // Collect all results.
    let mut channel_indices: Vec<u32> = Vec::with_capacity(K);
    let mut all_ok = true;
    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok(Ok(idx)) => channel_indices.push(idx),
            Ok(Err(e)) => {
                eprintln!("submit_pooled error: {e}");
                all_ok = false;
            }
            Err(e) => {
                eprintln!("task join error: {e}");
                all_ok = false;
            }
        }
    }
    assert!(all_ok, "all K submit_pooled tasks must succeed");

    // ── Assertion (a): distinct channels ────────────────────────────────────
    channel_indices.sort_unstable();
    for window in channel_indices.windows(2) {
        assert_ne!(
            window[0], window[1],
            "two concurrent submissions must not share the same channel \
             (channel_index={})",
            window[0]
        );
    }

    // ── Assertion (c): pool fully free ───────────────────────────────────────
    assert_eq!(
        pool.free_count(),
        K,
        "pool must be fully free after all K submissions"
    );
    assert_eq!(pool.in_flight_count(), 0);

    // ── Assertion (d): cached sequence advanced by 1 on each channel ─────────
    // After Success release, each channel's seq = INITIAL_SEQ + 1 = 101.
    for snap in pool.channel_snapshot() {
        assert_eq!(
            snap.sequence_number,
            INITIAL_SEQ + 1,
            "channel[{}] cached seq must be INITIAL_SEQ+1={} after Success release; got {}",
            snap.index,
            INITIAL_SEQ + 1,
            snap.sequence_number
        );
    }

    // ── Assertion (b): seq_num in each submitted envelope == INITIAL_SEQ + 1 ─
    // Extract sendTransaction bodies from the capture buffer.
    let bodies = captured.lock().expect("captured lock");
    let send_bodies: Vec<&serde_json::Value> = bodies
        .iter()
        .filter(|v| {
            v.get("method")
                .and_then(|m| m.as_str())
                .map(|m| m == "sendTransaction")
                .unwrap_or(false)
        })
        .collect();

    assert_eq!(
        send_bodies.len(),
        K,
        "expected exactly K={K} sendTransaction requests captured; got {}. \
         If 0: no sendTransaction body was captured; verify the body_partial_json \
         method matcher and that CapturingEchoResponder parsed and pushed the request body.",
        send_bodies.len()
    );

    for body in &send_bodies {
        // stellar-rpc-client sends ObjectParams: params.transaction = "<b64-xdr>"
        let xdr = body["params"]["transaction"]
            .as_str()
            .expect("params.transaction must be a base64-XDR string");
        let seq_num = extract_seq_num_from_xdr(xdr);
        assert_eq!(
            seq_num,
            INITIAL_SEQ + 1,
            "assertion (b): envelope seq_num must be INITIAL_SEQ+1={}; \
             ClassicOpBuilder::new receives current_seq (not +1); \
             baselib auto-increments internally; got seq_num={seq_num}",
            INITIAL_SEQ + 1
        );
    }
}

/// Single `submit_pooled` against a mock RPC — baseline seq_num correctness.
#[tokio::test(flavor = "multi_thread")]
async fn single_submit_mock_rpc_seq_num_correct() {
    let mock_server = MockServer::start().await;
    let tx_hash = "d".repeat(64);

    let captured: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));

    // Body-method-matched mocks: disambiguating sendTransaction vs getTransaction
    // by the JSON-RPC body method means the getTransaction poll can never consume
    // the sendTransaction PENDING response regardless of arrival order.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": "sendTransaction" })))
        .respond_with(CapturingEchoResponder::new(
            json!({
                "hash": tx_hash,
                "status": "PENDING",
                "latestLedger": 1001,
                "latestLedgerCloseTime": "1234567890"
            }),
            Arc::clone(&captured),
        ))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({ "method": "getTransaction" })))
        .respond_with(EchoIdResponder::new(json!({
            "status": "SUCCESS",
            "ledger": 1005,
            "txHash": tx_hash
        })))
        .mount(&mock_server)
        .await;

    let pool = make_pool_k4();
    let seed = mock_seed();
    let client = Arc::new(StellarRpcClient::new(&mock_server.uri()).expect("valid URL"));

    let result = submit_pooled(
        &pool,
        &client,
        &seed,
        TESTNET_PASSPHRASE,
        FEE_PER_OP,
        SUBMIT_TIMEOUT,
        |builder| {
            let _ = builder.payment(
                DEST_KEY,
                stellar_agent_core::StellarAmount::from_stroops(1),
                &stellar_agent_network::builder::Asset::Native,
            );
        },
    )
    .await
    .expect("submit_pooled must succeed");

    assert_eq!(result.outcome, TerminalOutcome::Success);
    assert!(result.submission.is_some());
    assert_eq!(
        pool.free_count(),
        4,
        "pool must be fully free after release"
    );

    // Verify seq_num from the captured sendTransaction envelope.
    let bodies = captured.lock().expect("lock");
    let send_body = bodies
        .iter()
        .find(|v| v.get("method").and_then(|m| m.as_str()) == Some("sendTransaction"))
        .expect("must have captured one sendTransaction body");

    let xdr = send_body["params"]["transaction"]
        .as_str()
        .expect("params.transaction must be a base64-XDR string");
    let seq_num = extract_seq_num_from_xdr(xdr);
    assert_eq!(
        seq_num,
        INITIAL_SEQ + 1,
        "seq_num must be INITIAL_SEQ+1={}; got {seq_num}",
        INITIAL_SEQ + 1
    );
}

/// `PoolExhausted` is returned IMMEDIATELY when all K channels are busy.
///
/// `submit_pooled` on an exhausted pool must return within a tight
/// wall-time bound — no blocking, no queuing.
#[tokio::test]
async fn submit_pooled_pool_exhausted_immediate() {
    let pool = make_pool_k4();
    // Drain the pool manually.
    let leases: Vec<_> = (0..4)
        .map(|_| pool.acquire().expect("must succeed"))
        .collect();

    let seed = mock_seed();
    // Use a loopback URL that would error if any I/O were attempted.
    let client = StellarRpcClient::new("http://127.0.0.1:1").expect("URL parses");

    let result = tokio::time::timeout(Duration::from_millis(20), async {
        submit_pooled(
            &pool,
            &client,
            &seed,
            TESTNET_PASSPHRASE,
            FEE_PER_OP,
            SUBMIT_TIMEOUT,
            |_builder| {}, // no ops — never reaches build_and_sign
        )
        .await
    })
    .await
    .expect(
        "submit_pooled on exhausted pool must return IMMEDIATELY (within 20 ms); \
             if it times out, the pool is silently queuing",
    );

    assert!(
        matches!(result, Err(PoolError::PoolExhausted { .. })),
        "must return PoolExhausted when all channels are in-flight, got: {result:?}"
    );

    for lease in leases {
        pool.release(lease, TerminalOutcome::Failed, None);
    }
}
