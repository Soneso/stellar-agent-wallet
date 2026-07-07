//! Allocator unit tests.
//!
//! Validates the structural properties of the channel-account pool:
//!
//! - Acquiring N leases from an N-channel pool succeeds.
//! - The (N+1)th acquire returns `PoolError::PoolExhausted` IMMEDIATELY.
//! - Releasing one lease allows a subsequent acquire to succeed.
//! - Releasing with `TerminalOutcome::Success` advances the cached sequence.
//! - Releasing with `TerminalOutcome::TxBadSeq` + `fresh_sequence` updates
//!   the cached sequence to the supplied value.
//! - Releasing with `TerminalOutcome::Failed` leaves the sequence unchanged.
//!
//! The (N+1)th acquire must return `PoolExhausted` IMMEDIATELY and NOT block.
//! Non-blocking behaviour is asserted by wrapping the acquire call in a
//! `tokio::time::timeout` with a 10ms bound.  A correct implementation returns
//! synchronously; any blocking path fires the timeout.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in unit tests"
)]

use std::time::Duration;

use stellar_agent_pool::ChannelRecord;
use stellar_agent_pool::PoolError;
use stellar_agent_pool::pool::{ChannelPool, TerminalOutcome};

// ─────────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────────

use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

/// Known-valid G-strkeys verified against stellar-agent-network builder.rs +
/// stellar-agent-sep5 SEP-5 test vectors.
const TEST_KEYS: &[&str] = &[
    "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY", // seed=[1u8;32]
    "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL", // seed=[2u8;32]
    "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6", // SEP-5 Test 1 acct 0
];

/// Builds a test pool with `n` channels.
///
/// Each channel uses a distinct known-valid G-strkey from `TEST_KEYS`.
/// `n` must be `<= TEST_KEYS.len()`.
fn make_test_pool(n: usize) -> ChannelPool {
    assert!(
        n <= TEST_KEYS.len(),
        "test pool size must be <= {}",
        TEST_KEYS.len()
    );
    let channels: Vec<ChannelRecord> = (0..n)
        .map(|i| ChannelRecord::new((i + 1) as u32, TEST_KEYS[i]))
        .collect();
    let sequences: Vec<i64> = (0..n as i64).map(|i| 100 + i * 10).collect();
    ChannelPool::from_records(channels, sequences).unwrap()
}

// ─────────────────────────────────────────────────────────────────────────────
// Acquire N leases → all succeed
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn acquire_n_leases_from_n_channel_pool() {
    let n = 3;
    let pool = make_test_pool(n);

    let mut leases = Vec::new();
    for _ in 0..n {
        let lease = pool
            .acquire()
            .expect("should succeed while free channels remain");
        leases.push(lease);
    }
    assert_eq!(pool.in_flight_count(), n);
    assert_eq!(pool.free_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// (N+1)th acquire returns PoolExhausted IMMEDIATELY
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that acquire returns `PoolExhausted` without blocking.
///
/// The pool never queues — the exhaustion check is synchronous (no `.await`),
/// so it completes in microseconds.  The result must arrive within a generous
/// 100ms timeout confirmed via `tokio::time::timeout`.
#[tokio::test]
async fn nth_plus_one_acquire_returns_pool_exhausted_immediately() {
    let n = 3;
    let pool = make_test_pool(n);

    // Acquire all N channels.
    let mut leases = Vec::new();
    for _ in 0..n {
        leases.push(pool.acquire().unwrap());
    }

    // The (N+1)th acquire must return PoolExhausted IMMEDIATELY.
    // We use tokio::time::timeout with a tight bound to verify non-blocking.
    // A correct implementation returns in < 1µs; 100ms is a generous bound.
    let result = tokio::time::timeout(Duration::from_millis(100), async { pool.acquire() }).await;

    // The timeout must NOT fire (if it does, acquire blocked — a bug).
    let result = result.expect("acquire should not block (completed within 100ms)");

    // The result must be PoolExhausted.
    match result {
        Err(PoolError::PoolExhausted { pool_size }) => {
            assert_eq!(pool_size, n, "pool_size in error should equal pool size");
        }
        other => panic!("expected PoolExhausted, got {:?}", other),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Release → next acquire succeeds
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn release_allows_next_acquire() {
    let n = 2;
    let pool = make_test_pool(n);

    let lease0 = pool.acquire().unwrap();
    let lease1 = pool.acquire().unwrap();

    // Both acquired — pool exhausted.
    assert!(pool.acquire().is_err());

    // Release lease0.
    pool.release(lease0, TerminalOutcome::Success, None);

    // Now one slot is free.
    let lease2 = pool.acquire().expect("should succeed after release");
    drop(lease1);
    drop(lease2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Success outcome advances cached sequence
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn success_advances_cached_sequence() {
    let pool = make_test_pool(1);

    // Channel 0: index=1, seq=100.
    let lease = pool.acquire().unwrap();
    let seq_before = lease.sequence_number();
    assert_eq!(seq_before, 100);

    pool.release(lease, TerminalOutcome::Success, None);

    // Acquire again; sequence should be 101.
    let lease2 = pool.acquire().unwrap();
    assert_eq!(
        lease2.sequence_number(),
        seq_before + 1,
        "sequence should advance by 1 on Success"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TxBadSeq with fresh_sequence updates the cached sequence
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tx_bad_seq_with_fresh_sequence_updates_cache() {
    let pool = make_test_pool(1);

    // Channel 0: index=1, seq=100.
    let lease = pool.acquire().unwrap();

    // Simulate tx_bad_seq — network tells us the real sequence is 200.
    let fresh = 200i64;
    pool.release(lease, TerminalOutcome::TxBadSeq, Some(fresh));

    // Re-acquire; sequence should be 200 (not 100+1).
    let lease2 = pool.acquire().unwrap();
    assert_eq!(
        lease2.sequence_number(),
        fresh,
        "sequence should be updated to fresh value on TxBadSeq"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Failed outcome leaves sequence unchanged
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn failed_outcome_leaves_sequence_unchanged() {
    let pool = make_test_pool(1);

    let lease = pool.acquire().unwrap();
    let seq = lease.sequence_number();

    pool.release(lease, TerminalOutcome::Failed, None);

    let lease2 = pool.acquire().unwrap();
    assert_eq!(
        lease2.sequence_number(),
        seq,
        "sequence should not change on Failed"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Size validation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn size_zero_rejected() {
    let result = ChannelPool::from_records(vec![], vec![]);
    match result {
        Err(PoolError::SizeOutOfRange { requested: 0 }) => {}
        other => panic!("expected SizeOutOfRange(0), got {:?}", other),
    }
}

#[test]
fn size_20_rejected() {
    // 20 > MAX_SIZE (19): N+1=21 signatures exceed the 20-signature VecM cap.
    let channels: Vec<ChannelRecord> = (1..=20u32)
        .map(|i| ChannelRecord::new(i, TEST_KEYS[0]))
        .collect();
    let seqs: Vec<i64> = vec![100; 20];
    match ChannelPool::from_records(channels, seqs) {
        Err(PoolError::SizeOutOfRange { requested: 20 }) => {}
        other => panic!("expected SizeOutOfRange(20), got {:?}", other),
    }
}

#[test]
fn size_19_accepted() {
    // MAX_SIZE = 19: N+1=20 signatures exactly fills the VecM<_, 20> cap.
    let channels: Vec<ChannelRecord> = (1..=19u32)
        .map(|i| ChannelRecord::new(i, TEST_KEYS[0]))
        .collect();
    let seqs: Vec<i64> = vec![100; 19];
    assert!(
        ChannelPool::from_records(channels, seqs).is_ok(),
        "size 19 (boundary: 20 sigs total) must be accepted"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Pool status helpers
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pool_status_counts_correct() {
    let pool = make_test_pool(3);
    assert_eq!(pool.pool_size(), 3);
    assert_eq!(pool.free_count(), 3);
    assert_eq!(pool.in_flight_count(), 0);

    let lease = pool.acquire().unwrap();
    assert_eq!(pool.free_count(), 2);
    assert_eq!(pool.in_flight_count(), 1);

    pool.release(lease, TerminalOutcome::Success, None);
    assert_eq!(pool.free_count(), 3);
    assert_eq!(pool.in_flight_count(), 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// allocator::release tx_bad_seq re-fetch error path
// ─────────────────────────────────────────────────────────────────────────────

/// Drives the async `allocator::release` `tx_bad_seq` re-fetch branch with an
/// injected error server.
///
/// When `release` is called with `TxBadSeq` and no `fresh_sequence`, the
/// allocator calls `fetch_account` against the RPC client.  If that RPC call
/// fails, `allocator::release` returns `PoolError::SequenceFetchFailed`.
/// This test asserts:
///
/// 1. The channel is freed (InFlight → Free) even when the re-fetch fails.
/// 2. The error variant is `PoolError::SequenceFetchFailed` with the correct
///    `channel_index` matching the acquired lease.
#[tokio::test]
async fn tx_bad_seq_refetch_error_maps_to_sequence_fetch_failed() {
    // Use wiremock to serve an HTTP 500 error for the getAccount RPC call.
    // `jsonrpsee-http-client` will parse the HTTP 500 as a transport error.
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    use stellar_agent_network::StellarRpcClient;
    let client = StellarRpcClient::new(&mock_server.uri()).expect("mock server URI must be valid");

    let pool = make_test_pool(1);
    let lease = pool.acquire().expect("should acquire from 1-channel pool");
    // Capture the expected channel index before consuming the lease.
    let expected_index = lease.index();

    // Call allocator::release with TxBadSeq and no fresh_sequence.
    // The allocator will attempt to re-fetch the sequence, which will fail.
    let result = stellar_agent_pool::allocator::release(
        &pool,
        &client,
        lease,
        TerminalOutcome::TxBadSeq,
        None,
        None,
        "",
    )
    .await;

    // The re-fetch failed — result must be SequenceFetchFailed.
    match result {
        Err(PoolError::SequenceFetchFailed {
            channel_index,
            channel_redacted: _,
            reason: _,
        }) => {
            assert_eq!(
                channel_index, expected_index,
                "channel_index in SequenceFetchFailed must match the acquired lease index"
            );
        }
        other => panic!("expected SequenceFetchFailed, got {:?}", other),
    }

    // Regardless of re-fetch failure, the channel must have been freed.
    assert_eq!(
        pool.free_count(),
        1,
        "channel must be free even when re-fetch fails"
    );
    assert_eq!(
        pool.in_flight_count(),
        0,
        "no channel should remain in-flight after release"
    );
}
