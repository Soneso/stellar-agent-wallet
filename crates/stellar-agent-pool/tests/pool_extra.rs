//! Unit tests for uncovered `ChannelPool` methods:
//! `from_config`, `from_records` error paths, `update_sequence`,
//! and the `release` no-op path when a lease index is not found.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in unit tests"
)]

use stellar_agent_pool::pool::{ChannelPool, TerminalOutcome};
use stellar_agent_pool::{ChannelRecord, PoolConfig, PoolError};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const KEY_A: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
const KEY_B: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

fn make_config(n: usize) -> PoolConfig {
    let keys = [KEY_A, KEY_B];
    let channels: Vec<ChannelRecord> = (0..n)
        .map(|i| ChannelRecord::new((i + 1) as u32, keys[i % keys.len()]))
        .collect();
    PoolConfig::new(n, channels)
}

// ─────────────────────────────────────────────────────────────────────────────
// from_config — success path
// ─────────────────────────────────────────────────────────────────────────────

/// `from_config` with a valid 2-channel config produces a pool with correct state.
#[test]
fn from_config_success_two_channels() {
    let config = make_config(2);
    let seqs = vec![100i64, 200i64];
    let pool = ChannelPool::from_config(&config, &seqs).expect("from_config must succeed");

    assert_eq!(pool.pool_size(), 2);
    assert_eq!(pool.free_count(), 2);
    assert_eq!(pool.in_flight_count(), 0);

    // Channel snapshot must reflect the initial sequence numbers.
    let snap = pool.channel_snapshot();
    assert_eq!(snap.len(), 2);
    let ch0 = snap
        .iter()
        .find(|c| c.index == 1)
        .expect("channel 1 must exist");
    let ch1 = snap
        .iter()
        .find(|c| c.index == 2)
        .expect("channel 2 must exist");
    assert_eq!(ch0.sequence_number, 100);
    assert_eq!(ch1.sequence_number, 200);
}

/// `from_config` with a 1-channel config (boundary: MIN_SIZE).
#[test]
fn from_config_single_channel_boundary() {
    let config = make_config(1);
    let pool =
        ChannelPool::from_config(&config, &[42]).expect("single-channel from_config must succeed");
    assert_eq!(pool.pool_size(), 1);
    let snap = pool.channel_snapshot();
    assert_eq!(snap[0].sequence_number, 42);
    assert!(!snap[0].in_flight);
}

// ─────────────────────────────────────────────────────────────────────────────
// from_config — size validation errors
// ─────────────────────────────────────────────────────────────────────────────

/// `from_config` with pool_size == 0 returns `SizeOutOfRange`.
#[test]
fn from_config_size_zero_returns_size_out_of_range() {
    let config = PoolConfig::new(0, vec![]);
    match ChannelPool::from_config(&config, &[]) {
        Err(PoolError::SizeOutOfRange { requested: 0 }) => {}
        other => panic!("expected SizeOutOfRange(0), got: {other:?}"),
    }
}

/// `from_config` with pool_size == 20 (> MAX_SIZE) returns `SizeOutOfRange`.
#[test]
fn from_config_size_20_returns_size_out_of_range() {
    let channels: Vec<ChannelRecord> = (1..=20u32).map(|i| ChannelRecord::new(i, KEY_A)).collect();
    let config = PoolConfig::new(20, channels);
    let seqs: Vec<i64> = vec![100; 20];
    match ChannelPool::from_config(&config, &seqs) {
        Err(PoolError::SizeOutOfRange { requested: 20 }) => {}
        other => panic!("expected SizeOutOfRange(20), got: {other:?}"),
    }
}

/// `from_config` where `config.channels.len()` does not match `pool_size`
/// returns `InitFailed`.
#[test]
fn from_config_channels_len_mismatch_returns_init_failed() {
    // pool_size says 2 but channels vec has only 1 entry.
    let config = PoolConfig::new(2, vec![ChannelRecord::new(1, KEY_A)]);
    let seqs = vec![100i64, 200i64];
    match ChannelPool::from_config(&config, &seqs) {
        Err(PoolError::InitFailed { .. }) => {}
        other => panic!("expected InitFailed, got: {other:?}"),
    }
}

/// `from_config` where `sequence_numbers.len()` does not match `pool_size`
/// returns `InitFailed`.
#[test]
fn from_config_sequence_len_mismatch_returns_init_failed() {
    let config = make_config(2);
    // Only 1 sequence number supplied for a 2-channel pool.
    match ChannelPool::from_config(&config, &[100]) {
        Err(PoolError::InitFailed { .. }) => {}
        other => panic!("expected InitFailed, got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// from_records — sequence length mismatch
// ─────────────────────────────────────────────────────────────────────────────

/// `from_records` with too few sequence numbers returns `InitFailed`.
#[test]
fn from_records_seq_len_mismatch_returns_init_failed() {
    let channels = vec![ChannelRecord::new(1, KEY_A), ChannelRecord::new(2, KEY_B)];
    // 2 channels, only 1 sequence number.
    match ChannelPool::from_records(channels, vec![100]) {
        Err(PoolError::InitFailed { .. }) => {}
        other => panic!("expected InitFailed, got: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// update_sequence
// ─────────────────────────────────────────────────────────────────────────────

/// `update_sequence` updates the cached sequence for the identified channel.
#[test]
fn update_sequence_applies_to_correct_channel() {
    let channels = vec![ChannelRecord::new(1, KEY_A), ChannelRecord::new(2, KEY_B)];
    let pool = ChannelPool::from_records(channels, vec![100, 200]).unwrap();

    pool.update_sequence(1, 999);

    let snap = pool.channel_snapshot();
    let ch1 = snap.iter().find(|c| c.index == 1).unwrap();
    let ch2 = snap.iter().find(|c| c.index == 2).unwrap();
    assert_eq!(ch1.sequence_number, 999, "channel 1 seq must be updated");
    assert_eq!(ch2.sequence_number, 200, "channel 2 seq must be unchanged");
}

/// `update_sequence` with a non-existent index is a no-op (does not panic).
#[test]
fn update_sequence_unknown_index_is_noop() {
    let pool = ChannelPool::from_records(vec![ChannelRecord::new(1, KEY_A)], vec![100]).unwrap();

    // Index 99 does not exist in the pool.
    pool.update_sequence(99, 999);

    let snap = pool.channel_snapshot();
    assert_eq!(
        snap[0].sequence_number, 100,
        "seq must be unchanged for unknown index"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// channel_snapshot reflects in_flight status
// ─────────────────────────────────────────────────────────────────────────────

/// `channel_snapshot` marks acquired channels as `in_flight=true`.
#[test]
fn channel_snapshot_reflects_in_flight_status() {
    let channels = vec![ChannelRecord::new(1, KEY_A), ChannelRecord::new(2, KEY_B)];
    let pool = ChannelPool::from_records(channels, vec![10, 20]).unwrap();

    // Before acquire: both free.
    let snap = pool.channel_snapshot();
    assert!(
        snap.iter().all(|c| !c.in_flight),
        "all channels must be free initially"
    );

    // Acquire channel 1.
    let lease = pool.acquire().unwrap();
    let acquired_index = lease.index();

    let snap = pool.channel_snapshot();
    let acquired = snap.iter().find(|c| c.index == acquired_index).unwrap();
    let other = snap.iter().find(|c| c.index != acquired_index).unwrap();
    assert!(acquired.in_flight, "acquired channel must be in_flight");
    assert!(!other.in_flight, "non-acquired channel must be free");

    pool.release(lease, TerminalOutcome::Success, None);
}

// ─────────────────────────────────────────────────────────────────────────────
// release: lease index not found (no-op / tracing warn path)
// ─────────────────────────────────────────────────────────────────────────────

/// `release` with a `ChannelLease` whose index is not in the pool is a no-op.
///
/// This exercises the else-branch in `release` where the channel is not found,
/// which emits a tracing warn and does nothing else.  The pool state must be
/// unchanged.
#[test]
fn release_unknown_lease_index_is_noop() {
    // Build a real pool and acquire a lease to get a valid ChannelLease struct,
    // then drop the first pool and try to release into a different pool that
    // does not contain that channel index.
    let pool_a = ChannelPool::from_records(vec![ChannelRecord::new(1, KEY_A)], vec![100]).unwrap();
    let lease = pool_a.acquire().unwrap();

    // pool_b contains only index 2; releasing index 1 into it is a no-op.
    let pool_b = ChannelPool::from_records(vec![ChannelRecord::new(2, KEY_B)], vec![200]).unwrap();

    // pool_b has 1 free channel before release.
    assert_eq!(pool_b.free_count(), 1);

    // Release into the wrong pool — must not panic, must be a no-op.
    pool_b.release(lease, TerminalOutcome::Success, None);

    // pool_b state is unchanged.
    assert_eq!(
        pool_b.free_count(),
        1,
        "pool_b free_count must be unchanged"
    );
    let snap = pool_b.channel_snapshot();
    assert_eq!(
        snap[0].sequence_number, 200,
        "channel 2 seq must be unchanged"
    );

    // pool_a: the original lease was consumed by release into pool_b.
    // pool_a channel 1 remains in_flight (no release was applied to pool_a).
    assert_eq!(
        pool_a.in_flight_count(),
        1,
        "pool_a channel 1 must still be in-flight"
    );
}
