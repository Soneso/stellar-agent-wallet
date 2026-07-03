//! `ChannelPool`, `Channel`, and `ChannelLease` — the pool's runtime state.
//!
//! The pool holds an `Arc<Mutex<PoolState>>` that tracks per-channel runtime
//! state: sequence number and free/in-flight status.  The lock is a
//! synchronous in-memory critical section and is NEVER held across an
//! async `.await` boundary.
//!
//! # Lock discipline
//!
//! All pool operations that need the lock:
//!
//! 1. Take the lock (`std::sync::Mutex`).
//! 2. Mutate in-memory state.
//! 3. Release the lock (drop the guard) **before** any `await`.
//!
//! `acquire()` and `release()` both comply: they operate on an already-taken
//! lock guard for an in-memory swap only; no I/O happens while the lock is
//! held.

use std::sync::{Arc, Mutex};

use crate::config::{PoolChannelRecord, PoolConfig};
// Internal alias for readability within this module.
use crate::error::PoolError;
use PoolChannelRecord as ChannelRecord;

// ─────────────────────────────────────────────────────────────────────────────
// ChannelStatus
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime status of a single channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelStatus {
    /// The channel is available for allocation.
    Free,
    /// The channel has been allocated to an in-flight submission.
    InFlight,
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelEntry (internal)
// ─────────────────────────────────────────────────────────────────────────────

/// Internal per-channel runtime state (behind the pool lock).
#[derive(Debug, Clone)]
pub(crate) struct ChannelEntry {
    /// BIP-44 derivation index for this channel (`m/44'/148'/index'`).
    pub(crate) index: u32,
    /// The `G...` Stellar strkey (cached from config; no secret).
    pub(crate) public_key: String,
    /// Cached on-chain sequence number (incremented locally on success;
    /// re-fetched on `tx_bad_seq`).
    pub(crate) sequence_number: i64,
    /// Current runtime status.
    pub(crate) status: ChannelStatus,
}

// ─────────────────────────────────────────────────────────────────────────────
// PoolState (behind the Arc<Mutex>)
// ─────────────────────────────────────────────────────────────────────────────

/// Mutable pool state protected by a `std::sync::Mutex`.
///
/// Never accessed without the mutex.  All mutations happen inside a sync lock
/// guard that is dropped before any `await`.
#[derive(Debug)]
pub(crate) struct PoolState {
    /// Per-channel runtime entries, in derivation-index order.
    pub(crate) channels: Vec<ChannelEntry>,
}

impl PoolState {
    /// Returns the number of channels currently free.
    pub(crate) fn free_count(&self) -> usize {
        self.channels
            .iter()
            .filter(|c| c.status == ChannelStatus::Free)
            .count()
    }

    /// Returns the number of channels currently in-flight.
    pub(crate) fn in_flight_count(&self) -> usize {
        self.channels
            .iter()
            .filter(|c| c.status == ChannelStatus::InFlight)
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelLease
// ─────────────────────────────────────────────────────────────────────────────

/// A handle to an exclusively-acquired pool channel.
///
/// Created by [`ChannelPool::acquire`] and consumed by [`ChannelPool::release`].
/// While a `ChannelLease` is alive, the corresponding channel is marked
/// `InFlight` in the pool and cannot be acquired by another caller.
///
/// # Invariant
///
/// A lease MUST be returned via [`ChannelPool::release`] — not dropped
/// silently — so the channel transitions back to `Free` and the pool
/// accounting stays correct.  Dropping without releasing leaves the channel
/// permanently `InFlight`.
#[derive(Debug)]
pub struct ChannelLease {
    /// BIP-44 derivation index.
    pub(crate) index: u32,
    /// `G...` public key strkey.
    pub(crate) public_key: String,
    /// Cached sequence number at the time of acquisition.
    /// The caller uses this as the transaction `seq_num` field.
    pub(crate) sequence_number: i64,
}

impl ChannelLease {
    /// The BIP-44 account index (`m/44'/148'/index'`) for this channel.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The `G...` Stellar strkey of this channel.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// The cached on-chain sequence number for this channel at acquisition time.
    ///
    /// Pass this value **AS-IS** to `ClassicOpBuilder::new` as the
    /// `sequence_number` argument.  The builder's internal
    /// `Account::increment_sequence_number` (stellar-baselib `transaction_builder`)
    /// auto-increments to produce an on-chain `tx.seq_num` of
    /// `sequence_number + 1`.
    ///
    /// **Do NOT add 1 at the call site.**  Passing `sequence_number() + 1` would
    /// cause the envelope to carry `current_seq + 2`, which Stellar core rejects
    /// with `tx_bad_seq`.  The regression test
    /// `builder.rs::builder_envelope_seq_num_is_caller_seq_plus_one` locks this
    /// invariant.
    #[must_use]
    pub fn sequence_number(&self) -> i64 {
        self.sequence_number
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TerminalOutcome
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of a pooled submission, reported back to the pool on release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// The transaction was confirmed on-chain.
    ///
    /// The pool advances the cached sequence number by 1.
    Success,

    /// The transaction was rejected with `tx_bad_seq`.
    ///
    /// The pool schedules a sequence re-fetch for this channel on the next
    /// opportunity (the caller may supply a freshly-fetched sequence, or pass
    /// `None` to indicate the pool should re-fetch).
    TxBadSeq,

    /// The transaction failed for a reason other than `tx_bad_seq`.
    ///
    /// The pool marks the channel free without advancing the sequence (the
    /// sequence is unchanged because the transaction was rejected before
    /// the ledger consumed the sequence slot).
    Failed,
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelPool
// ─────────────────────────────────────────────────────────────────────────────

/// A channel-account pool with credit-as-capability allocation.
///
/// `ChannelPool` holds N pre-funded Stellar accounts whose sequence numbers
/// are managed in-pool for concurrent submission.  Each channel is
/// SEP-5-derived (`m/44'/148'/<index>'`) from a pool master seed held in the
/// OS keyring; only the public keys and sequence numbers are held in memory.
///
/// # Concurrency guarantee
///
/// `acquire()` returns a `ChannelLease` IMMEDIATELY if a free channel exists,
/// or [`PoolError::PoolExhausted`] IMMEDIATELY if all channels are in-flight.
/// The pool NEVER queues beyond its capacity.
///
/// # Lock discipline
///
/// Internal state is protected by a `std::sync::Mutex`.  The lock is taken
/// only for synchronous in-memory operations; it is NEVER held across an
/// `.await` boundary.
///
/// # Thread-safety
///
/// `ChannelPool` is `Send + Sync` because `Arc<Mutex<PoolState>>` is.
#[derive(Debug, Clone)]
pub struct ChannelPool {
    /// Shared, lock-protected runtime state.
    state: Arc<Mutex<PoolState>>,
    /// Total number of channels in this pool.
    pool_size: usize,
}

impl ChannelPool {
    /// The minimum valid pool size.
    pub const MIN_SIZE: usize = 1;

    /// The maximum valid pool size.
    ///
    /// Each channel requires 1 signature in the sandwich envelope.  The funder
    /// also produces 1 signature, so the envelope carries N+1 signatures total.
    /// `attach_signature` packs into `VecM<DecoratedSignature, 20>`
    /// (`stellar-agent-network/src/signing/envelope_signing.rs`), therefore
    /// N+1 ≤ 20 → N ≤ 19.
    ///
    /// Note: the 100-op classic-tx limit (N×3 ≤ 100 → N ≤ 33) is the looser
    /// bound; the 20-signature `VecM` cap is the binding constraint.
    pub const MAX_SIZE: usize = 19;

    /// Constructs a new `ChannelPool` from a `PoolConfig` and a slice of
    /// per-channel sequence numbers (one per channel, in order).
    ///
    /// This is the post-init or post-refresh construction path.  The caller
    /// must supply an up-to-date sequence number for each channel (fetched
    /// via `fetch_account`).
    ///
    /// # Errors
    ///
    /// Returns [`PoolError::SizeOutOfRange`] if `config.pool_size` is outside
    /// `1..=19`, or if `config.channels.len()` does not equal `config.pool_size`.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn from_config(config: &PoolConfig, sequence_numbers: &[i64]) -> Result<Self, PoolError> {
        let pool_size = config.pool_size;
        if !(Self::MIN_SIZE..=Self::MAX_SIZE).contains(&pool_size) {
            return Err(PoolError::SizeOutOfRange {
                requested: pool_size,
            });
        }
        if config.channels.len() != pool_size || sequence_numbers.len() != pool_size {
            return Err(PoolError::InitFailed {
                detail: format!(
                    "config.channels.len() ({}) or sequence_numbers.len() ({}) \
                     does not match pool_size ({})",
                    config.channels.len(),
                    sequence_numbers.len(),
                    pool_size,
                ),
            });
        }

        let entries: Vec<ChannelEntry> = config
            .channels
            .iter()
            .zip(sequence_numbers.iter().copied())
            .map(|(rec, seq)| ChannelEntry {
                index: rec.index,
                public_key: rec.public_key.clone(),
                sequence_number: seq,
                status: ChannelStatus::Free,
            })
            .collect();

        Ok(Self {
            state: Arc::new(Mutex::new(PoolState { channels: entries })),
            pool_size,
        })
    }

    /// Constructs a `ChannelPool` from a vec of pre-built `ChannelRecord`s
    /// and their sequence numbers.
    ///
    /// This is the post-`pool init` construction path: the init module builds
    /// the channels from derivation + submits the sandwich, then passes the
    /// records + initial sequences here.
    ///
    /// # Errors
    ///
    /// Returns [`PoolError::SizeOutOfRange`] if `channels.len()` is outside
    /// `1..=19`.
    ///
    /// # Panics
    ///
    /// Never panics.
    pub fn from_records(
        channels: Vec<ChannelRecord>,
        sequence_numbers: Vec<i64>,
    ) -> Result<Self, PoolError> {
        let pool_size = channels.len();
        if !(Self::MIN_SIZE..=Self::MAX_SIZE).contains(&pool_size) {
            return Err(PoolError::SizeOutOfRange {
                requested: pool_size,
            });
        }
        if sequence_numbers.len() != pool_size {
            return Err(PoolError::InitFailed {
                detail: format!(
                    "sequence_numbers.len() ({}) does not match channels.len() ({})",
                    sequence_numbers.len(),
                    pool_size,
                ),
            });
        }

        let entries: Vec<ChannelEntry> = channels
            .into_iter()
            .zip(sequence_numbers)
            .map(|(rec, seq)| ChannelEntry {
                index: rec.index,
                public_key: rec.public_key,
                sequence_number: seq,
                status: ChannelStatus::Free,
            })
            .collect();

        Ok(Self {
            state: Arc::new(Mutex::new(PoolState { channels: entries })),
            pool_size,
        })
    }

    /// Total number of channels in this pool.
    #[must_use]
    pub fn pool_size(&self) -> usize {
        self.pool_size
    }

    /// Returns the number of channels currently free.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only if a previous thread
    /// panicked while holding the lock, which does not happen in normal use).
    #[must_use]
    pub fn free_count(&self) -> usize {
        // SAFETY: lock poisoning can only occur if a panic happened while
        // holding the lock; pool code does not panic while holding the lock.
        // If the lock is poisoned we recover the guard — the state is still
        // valid for reading.
        #[allow(clippy::expect_used)]
        self.state.lock().expect("pool lock poisoned").free_count()
    }

    /// Returns the number of channels currently in-flight.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only if a previous thread
    /// panicked while holding the lock, which does not happen in normal use).
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        #[allow(clippy::expect_used)]
        self.state
            .lock()
            .expect("pool lock poisoned")
            .in_flight_count()
    }

    /// Returns a snapshot of all channels (index, public_key, seq, status).
    ///
    /// Used by `pool list` to display current channel state.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only if a previous thread
    /// panicked while holding the lock, which does not happen in normal use).
    #[must_use]
    pub fn channel_snapshot(&self) -> Vec<ChannelSnapshot> {
        #[allow(clippy::expect_used)]
        let state = self.state.lock().expect("pool lock poisoned");
        state
            .channels
            .iter()
            .map(|c| ChannelSnapshot {
                index: c.index,
                public_key: c.public_key.clone(),
                sequence_number: c.sequence_number,
                in_flight: c.status == ChannelStatus::InFlight,
            })
            .collect()
    }

    /// Acquires a free channel, returning a [`ChannelLease`].
    ///
    /// The channel is marked `InFlight` while the lease is held.  The caller
    /// MUST call [`ChannelPool::release`] after the submission completes.
    ///
    /// Returns [`PoolError::PoolExhausted`] IMMEDIATELY when all channels are
    /// in-flight.  The pool NEVER blocks or queues.
    ///
    /// # Errors
    ///
    /// Returns [`PoolError::PoolExhausted`] if no free channel is available.
    /// Returns [`PoolError::NotInitialised`] as a fail-closed defensive guard
    /// if the pool was somehow constructed with zero channels (an invariant the
    /// public constructors enforce via `SizeOutOfRange`).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only if a previous thread
    /// panicked while holding the lock, which does not happen in normal use).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stellar_agent_pool::pool::ChannelPool;
    /// # use stellar_agent_pool::{ChannelRecord, PoolConfig};
    /// # let channels = vec![ChannelRecord::new(1, "GABC...XYZ")];
    /// # let pool = ChannelPool::from_records(channels, vec![100]).unwrap();
    /// let lease = pool.acquire().unwrap();
    /// // ... submit transaction using lease.public_key() and lease.sequence_number() ...
    /// ```
    pub fn acquire(&self) -> Result<ChannelLease, PoolError> {
        // Fail-closed guard: public constructors reject pool_size == 0 via
        // SizeOutOfRange, so this branch is not reachable through the public API.
        // It is retained as a release-build defensive invariant.
        if self.pool_size == 0 {
            return Err(PoolError::NotInitialised);
        }

        // Lock, inspect, mutate, unlock — never hold across await.
        #[allow(clippy::expect_used)]
        let mut state = self.state.lock().expect("pool lock poisoned");
        let entry = state
            .channels
            .iter_mut()
            .find(|c| c.status == ChannelStatus::Free);

        match entry {
            Some(channel) => {
                channel.status = ChannelStatus::InFlight;
                Ok(ChannelLease {
                    index: channel.index,
                    public_key: channel.public_key.clone(),
                    sequence_number: channel.sequence_number,
                })
            }
            None => Err(PoolError::PoolExhausted {
                pool_size: self.pool_size,
            }),
        }
    }

    /// Releases a channel lease back to the pool.
    ///
    /// The `outcome` drives how the cached sequence number is updated:
    ///
    /// - [`TerminalOutcome::Success`]: increments the cached sequence by 1.
    /// - [`TerminalOutcome::TxBadSeq`]: marks the sequence as stale; the caller
    ///   should re-fetch via `fetch_account` and call
    ///   [`ChannelPool::update_sequence`] before the next acquire.  If a
    ///   fresh sequence is already known (e.g. from the `tx_bad_seq` response),
    ///   the caller may pass it via `fresh_sequence`.
    /// - [`TerminalOutcome::Failed`]: returns the channel to `Free` without
    ///   advancing the sequence (the transaction was rejected before consuming
    ///   a sequence slot).
    ///
    /// If the channel identified by `lease.index` is not found (should not
    /// happen in practice), this is a no-op.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only if a previous thread
    /// panicked while holding the lock, which does not happen in normal use).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stellar_agent_pool::pool::{ChannelPool, TerminalOutcome};
    /// # use stellar_agent_pool::ChannelRecord;
    /// # let channels = vec![ChannelRecord::new(1, "GABC...XYZ")];
    /// # let pool = ChannelPool::from_records(channels, vec![100]).unwrap();
    /// let lease = pool.acquire().unwrap();
    /// // ... submit transaction ...
    /// pool.release(lease, TerminalOutcome::Success, None);
    /// ```
    #[allow(
        clippy::needless_pass_by_value,
        reason = "ChannelLease is consumed to prevent double-release: taking it \
                  by value ensures the caller cannot re-use the lease after release"
    )]
    pub fn release(
        &self,
        lease: ChannelLease,
        outcome: TerminalOutcome,
        fresh_sequence: Option<i64>,
    ) {
        #[allow(clippy::expect_used)]
        let mut state = self.state.lock().expect("pool lock poisoned");
        if let Some(channel) = state.channels.iter_mut().find(|c| c.index == lease.index) {
            match outcome {
                TerminalOutcome::Success => {
                    channel.sequence_number += 1;
                    channel.status = ChannelStatus::Free;
                }
                TerminalOutcome::TxBadSeq => {
                    // If caller already has the fresh sequence, apply it now.
                    if let Some(seq) = fresh_sequence {
                        channel.sequence_number = seq;
                    }
                    // Either way, free the channel; the sequence may be stale
                    // but will be reconciled before the next submission.
                    channel.status = ChannelStatus::Free;
                }
                TerminalOutcome::Failed => {
                    // Sequence is unchanged (tx rejected before ledger consumed it).
                    channel.status = ChannelStatus::Free;
                }
            }
        } else {
            // The lease index was not found in the pool.  This should not happen
            // in normal use (leases come from `acquire` which only hands out valid
            // indices), but if it does, emit a warning so the discrepancy is
            // visible rather than silently leaking an InFlight slot.
            tracing::warn!(
                index = lease.index,
                "pool release: lease index not found; InFlight slot not reclaimed"
            );
        }
    }

    /// Updates the cached sequence number for a channel by its derivation index.
    ///
    /// Called after a `tx_bad_seq` re-fetch to inject the corrected on-chain
    /// sequence into the pool.  If no channel with `index` exists, this is a
    /// no-op.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (only if a previous thread
    /// panicked while holding the lock, which does not happen in normal use).
    pub fn update_sequence(&self, index: u32, fresh_sequence: i64) {
        #[allow(clippy::expect_used)]
        let mut state = self.state.lock().expect("pool lock poisoned");
        if let Some(channel) = state.channels.iter_mut().find(|c| c.index == index) {
            channel.sequence_number = fresh_sequence;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelSnapshot (display output)
// ─────────────────────────────────────────────────────────────────────────────

/// A snapshot of a single channel's current state (for display / JSON output).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct ChannelSnapshot {
    /// BIP-44 derivation index.
    pub index: u32,
    /// `G...` Stellar strkey.
    pub public_key: String,
    /// Cached sequence number.
    pub sequence_number: i64,
    /// Whether this channel is currently in-flight.
    pub in_flight: bool,
}
