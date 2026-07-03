//! Structural concurrency test — no-silent-queue-under-load proof.
//!
//! Verifies the credit-as-capability allocation semantics:
//!
//! - With N channels and M=2N concurrent `acquire()` callers:
//!   - Exactly N succeed and return a `ChannelLease`.
//!   - Exactly M-N (=N) return `PoolError::PoolExhausted` IMMEDIATELY.
//!   - All M futures resolve within a tight wall-time bound — nothing queues.
//!   - At peak: `in_flight_count()==N`, `free_count()==0`.
//! - After releasing all N leases: `free_count()==N`, `in_flight_count()==0`.
//!
//! # No network, no keyring
//!
//! Built from `ChannelPool::from_records` with dummy (structurally valid)
//! G-strkeys.  No `#[serial]` annotation required because no process-global
//! state is touched.
//!
//! # Invariant split
//!
//! The concurrency guarantee has two parts:
//!
//! 1. **No cross-channel sequence sharing under concurrency** — each `acquire()`
//!    hands out a single exclusive `ChannelLease`; two concurrent callers can
//!    never receive the same channel.  Proven here.
//!
//! 2. **Per-channel cached-sequence correctness across acquire → submit → release** —
//!    proven in `concurrent_submit.rs` by asserting each submitted envelope's
//!    `seq_num == channel_account_seq + 1`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics and unwraps are acceptable in structural tests"
)]

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use stellar_agent_pool::PoolError;
use stellar_agent_pool::pool::{ChannelPool, TerminalOutcome};
use stellar_agent_pool::{ChannelLease, ChannelRecord};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures — structurally valid G-strkeys (from builder.rs test fixtures;
// verified in the existing tests/init_structure.rs and builder.rs unit tests)
// ─────────────────────────────────────────────────────────────────────────────

/// 4 known-valid G-strkeys used as dummy channel public keys.
const DUMMY_KEYS: [&str; 4] = [
    "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY",
    "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL",
    "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
    "GAAZI4TCR3TY5OJHCTJC2A4QSY6CJWJH5IAJTGKIN2ER7LBNVKOCCWN7",
];

/// Build a 4-channel pool from dummy records with seq=100 per channel.
fn make_pool_n4() -> Arc<ChannelPool> {
    let channels: Vec<ChannelRecord> = DUMMY_KEYS
        .iter()
        .enumerate()
        .map(|(i, &key)| ChannelRecord::new((i + 1) as u32, key))
        .collect();
    let seqs = vec![100i64; 4];
    Arc::new(ChannelPool::from_records(channels, seqs).expect("pool construction must succeed"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural test: N=4, M=8
// ─────────────────────────────────────────────────────────────────────────────

/// With N=4 channels and M=8 concurrent `acquire()` calls:
///
/// - Exactly 4 succeed (Ok).
/// - Exactly 4 return `PoolExhausted` IMMEDIATELY.
/// - All 8 resolve within a tight timeout (proving nothing queues).
/// - At peak: `in_flight_count()==4`, `free_count()==0`.
/// - After release: `free_count()==4`.
#[tokio::test(flavor = "multi_thread")]
async fn n4_m8_exactly_n_succeed_m_minus_n_exhausted_immediately() {
    const N: usize = 4;
    const M: usize = 8;
    // Tight per-future timeout: each acquire() must return in ≤ 50 ms.
    // The pool never queues, so any await exceeding this is a bug.
    const ACQUIRE_TIMEOUT_MS: u64 = 50;

    let pool = make_pool_n4();

    // Spawn M concurrent acquire() tasks.
    let mut join_set: JoinSet<Result<ChannelLease, PoolError>> = JoinSet::new();
    for _ in 0..M {
        let pool_clone = Arc::clone(&pool);
        join_set.spawn(async move {
            // Wrap each acquire() in a tight timeout to prove non-blocking.
            tokio::time::timeout(Duration::from_millis(ACQUIRE_TIMEOUT_MS), async move {
                pool_clone.acquire()
            })
            .await
            .expect("acquire() must not block for more than ACQUIRE_TIMEOUT_MS")
        });
    }

    // Collect all M results.
    let mut leases: Vec<ChannelLease> = Vec::with_capacity(N);
    let mut ok_count = 0usize;
    let mut exhausted_count = 0usize;

    while let Some(result) = join_set.join_next().await {
        match result.expect("task must not panic") {
            Ok(lease) => {
                ok_count += 1;
                leases.push(lease);
            }
            Err(PoolError::PoolExhausted { .. }) => {
                exhausted_count += 1;
            }
            Err(other) => panic!("unexpected error from acquire(): {other}"),
        }
    }

    // Assertion 1: exactly N leases granted, M-N exhausted.
    assert_eq!(
        ok_count, N,
        "exactly N={N} acquire() calls must succeed; got {ok_count}"
    );
    assert_eq!(
        exhausted_count,
        M - N,
        "exactly M-N={} acquire() calls must return PoolExhausted; got {exhausted_count}",
        M - N
    );

    // Assertion 2: at peak, all N channels are in-flight, none free.
    assert_eq!(
        pool.in_flight_count(),
        N,
        "at peak, in_flight_count must be N={N}"
    );
    assert_eq!(pool.free_count(), 0, "at peak, free_count must be 0");

    // Assertion 3: each successful lease has a distinct channel index.
    {
        let mut seen_indices: std::collections::HashSet<u32> =
            std::collections::HashSet::with_capacity(N);
        for lease in &leases {
            assert!(
                seen_indices.insert(lease.index()),
                "two leases must not share the same channel index (found duplicate {})",
                lease.index()
            );
        }
        assert_eq!(seen_indices.len(), N, "exactly N distinct indices");
    }

    // ── Release all N leases ─────────────────────────────────────────────────
    for lease in leases {
        pool.release(lease, TerminalOutcome::Success, None);
    }

    // Assertion 4: pool fully restored after release.
    assert_eq!(
        pool.free_count(),
        N,
        "after release, free_count must be N={N}"
    );
    assert_eq!(
        pool.in_flight_count(),
        0,
        "after release, in_flight_count must be 0"
    );
}

/// A single `acquire()` on an exhausted pool returns `PoolExhausted`
/// immediately, even when all channels are in-flight.
#[tokio::test]
async fn acquire_returns_exhausted_immediately_when_full() {
    let pool = make_pool_n4();

    // Drain all 4 channels.
    let leases: Vec<ChannelLease> = (0..4)
        .map(|_| {
            pool.acquire()
                .expect("acquire must succeed while slots free")
        })
        .collect();
    assert_eq!(pool.free_count(), 0, "pool must be fully in-flight");

    // One more acquire must return PoolExhausted, not block.
    let result = tokio::time::timeout(Duration::from_millis(10), async { pool.acquire() })
        .await
        .expect("PoolExhausted must be returned immediately, not after 10 ms");

    assert!(
        matches!(result, Err(PoolError::PoolExhausted { pool_size: 4 })),
        "must be PoolExhausted{{pool_size:4}}, got: {result:?}"
    );

    // Cleanup.
    for lease in leases {
        pool.release(lease, TerminalOutcome::Failed, None);
    }
}

/// Releasing one channel makes it immediately re-acquirable.
#[tokio::test]
async fn released_channel_is_immediately_re_acquirable() {
    let pool = make_pool_n4();

    // Drain all channels.
    let mut leases: Vec<ChannelLease> = (0..4)
        .map(|_| pool.acquire().expect("must succeed"))
        .collect();

    // Release one.
    let released_index = leases[0].index();
    let lease_to_release = leases.remove(0);
    pool.release(lease_to_release, TerminalOutcome::Success, None);

    assert_eq!(pool.free_count(), 1);

    // Re-acquire must succeed and return the freed channel.
    let new_lease = pool.acquire().expect("must succeed after release");
    assert_eq!(
        new_lease.index(),
        released_index,
        "re-acquired channel must be the one just released (pool is LIFO/FIFO depending on impl; \
         with a single free slot, only one option exists)"
    );

    // Cleanup.
    pool.release(new_lease, TerminalOutcome::Failed, None);
    for lease in leases {
        pool.release(lease, TerminalOutcome::Failed, None);
    }
    assert_eq!(pool.free_count(), 4);
}

/// After a `TerminalOutcome::Success` release, the cached sequence is
/// incremented by 1.
#[tokio::test]
async fn success_release_increments_sequence() {
    let pool = make_pool_n4();

    let lease = pool.acquire().expect("must succeed");
    let original_seq = lease.sequence_number();
    let index = lease.index();
    pool.release(lease, TerminalOutcome::Success, None);

    // Verify the sequence via a snapshot.
    let snap = pool.channel_snapshot();
    let ch = snap.iter().find(|c| c.index == index).expect("must exist");
    assert_eq!(
        ch.sequence_number,
        original_seq + 1,
        "Success release must increment sequence by 1"
    );
}

/// After a `TerminalOutcome::Failed` release, the cached sequence is unchanged.
#[tokio::test]
async fn failed_release_does_not_change_sequence() {
    let pool = make_pool_n4();

    let lease = pool.acquire().expect("must succeed");
    let original_seq = lease.sequence_number();
    let index = lease.index();
    pool.release(lease, TerminalOutcome::Failed, None);

    let snap = pool.channel_snapshot();
    let ch = snap.iter().find(|c| c.index == index).expect("must exist");
    assert_eq!(
        ch.sequence_number, original_seq,
        "Failed release must leave the sequence unchanged"
    );
}

/// A `TerminalOutcome::TxBadSeq` release with a fresh sequence applies it.
#[tokio::test]
async fn txbadseq_release_with_fresh_seq_applies_it() {
    let pool = make_pool_n4();

    let lease = pool.acquire().expect("must succeed");
    let index = lease.index();
    let fresh_seq = 999i64;
    pool.release(lease, TerminalOutcome::TxBadSeq, Some(fresh_seq));

    let snap = pool.channel_snapshot();
    let ch = snap.iter().find(|c| c.index == index).expect("must exist");
    assert_eq!(
        ch.sequence_number, fresh_seq,
        "TxBadSeq release with fresh_sequence must apply the fresh sequence"
    );
}
