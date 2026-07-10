//! In-memory sliding-window state store for per-period cap and rate-limit
//! criteria.
//!
//! [`PolicyStateStore`] is the runtime state holder injected into
//! [`crate::policy::v1::EvalContext`].  It maintains per-key `VecDeque` records
//! of `(timestamp_ms, amount_or_count)` tuples, where entries older than the
//! configured window are evicted on each read pass.
//!
//! The store is in-process only; persistence across restarts is not provided.
//! Every entry it holds is therefore reconstructed fresh at process start —
//! there is no on-disk wire form or legacy-numeric-vs-string boundary for this
//! store to migrate across.
//!
//! # Accumulator width
//!
//! The recorded amount is `i128`, exact across the full range a token
//! quantity or an aggregated per-period stroop total can take (a Soroban SAC
//! transfer, or a rolling-window sum across many legs, can exceed
//! `i64::MAX`). `query_window` sums entries with `i128::saturating_add`; the
//! call-count field stays `u32` (call counts never approach that range).
//!
//! # Sliding-window API pattern
//!
//! Records accumulate and are evicted lazily on each call (no background
//! sweeper).  The criterion evaluator reads the accumulated total; the dispatch
//! site is responsible for appending new entries at commit time.
//!
//! # Thread safety
//!
//! `PolicyStateStore` wraps all mutable state in `std::sync::Mutex` so it is
//! `Send + Sync` and can live behind `Arc<PolicyEngineV1>`.
//!

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// Maximum tolerated future clock skew for state-store entries, in milliseconds.
const CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;

// ─────────────────────────────────────────────────────────────────────────────
// StateKey
// ─────────────────────────────────────────────────────────────────────────────

/// Composite key for the state store.
///
/// Groups sliding-window entries by (profile_name, scope_specificity, bucket,
/// window_secs) where `bucket` is typically an asset identifier for per-period
/// caps or the literal string `"rate_limit"` for rate-limit criteria.
///
/// `scope_specificity` is the numeric specificity of the resolved
/// [`crate::policy::v1::loader::ScopeId`] so that a narrower scope's window
/// does not share state with a broader scope's window for the same profile.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::state_store::StateKey;
///
/// let key = StateKey::new("alice", 2, "native", 86_400);
/// assert_eq!(key.profile_name(), "alice");
/// assert_eq!(key.window_secs(), 86_400);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StateKey {
    profile_name: String,
    scope_specificity: u8,
    bucket: String,
    window_secs: u64,
}

impl StateKey {
    /// Constructs a new [`StateKey`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::state_store::StateKey;
    ///
    /// let key = StateKey::new("default", 1, "native", 3_600);
    /// assert_eq!(key.profile_name(), "default");
    /// assert_eq!(key.bucket(), "native");
    /// assert_eq!(key.scope_specificity(), 1);
    /// assert_eq!(key.window_secs(), 3_600);
    /// ```
    #[must_use]
    pub fn new(profile_name: &str, scope_specificity: u8, bucket: &str, window_secs: u64) -> Self {
        Self {
            profile_name: profile_name.to_owned(),
            scope_specificity,
            bucket: bucket.to_owned(),
            window_secs,
        }
    }

    /// Returns the profile name component of the key.
    #[must_use]
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Returns the scope specificity component of the key.
    #[must_use]
    pub fn scope_specificity(&self) -> u8 {
        self.scope_specificity
    }

    /// Returns the bucket component (asset identifier or `"rate_limit"`).
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Returns the window length in seconds.
    #[must_use]
    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyStateStore
// ─────────────────────────────────────────────────────────────────────────────

/// In-memory sliding-window state store for per-period cap and rate-limit
/// criteria.
///
/// Each entry is a `(timestamp_ms, amount_or_count)` pair stored in a
/// `VecDeque` keyed by [`StateKey`].  Entries are evicted when their
/// `timestamp_ms` is older than `now_ms - window_ms` (where
/// `window_ms = window_secs × 1_000`).
///
/// Clock-skew tolerance: entries with `timestamp_ms > now_ms + 30_000`
/// (i.e. more than 30 seconds in the future) are treated as evidence of
/// excessive clock skew and cause [`StateStoreError::ClockSkewExceeded`].
///
/// The store is read-only from the criterion evaluator's perspective.
/// Recording new entries after a successful commit is the dispatch site's
/// responsibility.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
///
/// let store = PolicyStateStore::new();
/// let key = StateKey::new("alice", 2, "native", 3_600);
///
/// // No entries yet — query returns 0 / empty counts.
/// let now_ms = 1_000_000;
/// let (sum, count) =
///     store.query_window(&key, now_ms).expect("query should succeed");
/// assert_eq!(sum, 0);
/// assert_eq!(count, 0);
/// ```
///
#[derive(Debug)]
pub struct PolicyStateStore {
    /// Map from state key to a deque of (timestamp_ms, amount_or_count)
    /// entries in insertion order (oldest at front).  The amount is `i128`
    /// (see the module-level "Accumulator width" section) — exact across the
    /// full range a per-period stroop total can take.
    ///
    /// `Mutex<HashMap<...>>` enables `Send + Sync` without `parking_lot`
    /// (not yet a workspace dep; std Mutex is adequate here because this
    /// store is never held across an await point).
    inner: Mutex<HashMap<StateKey, VecDeque<(u64, i128)>>>,
}

/// Error variants for [`PolicyStateStore`] operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StateStoreError {
    /// The state store lock is poisoned (internal invariant violation).
    #[error("state store lock poisoned: {detail}")]
    LockPoisoned {
        /// Non-secret diagnostic detail.
        detail: String,
    },

    /// A recorded timestamp is more than 30 seconds in the future.
    ///
    /// Indicates excessive clock skew; the caller should surface a
    /// `PolicyError::CriterionEvaluationFailed` to the engine.
    #[error(
        "clock skew exceeded: entry timestamp {entry_ts_ms} ms is more than 30s in the future (now={now_ms} ms)"
    )]
    ClockSkewExceeded {
        /// The offending entry timestamp in unix-milliseconds.
        entry_ts_ms: u64,
        /// The wall-clock time at the moment of detection in unix-milliseconds.
        now_ms: u64,
    },
}

impl PolicyStateStore {
    /// Creates a new, empty [`PolicyStateStore`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::state_store::PolicyStateStore;
    ///
    /// let store = PolicyStateStore::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Queries the current window for a given key, evicting stale entries and
    /// returning `(sum_of_amounts, count_of_entries)` for the surviving window.
    ///
    /// Eviction removes entries with `timestamp_ms < now_ms -
    /// (window_secs * 1_000)`.
    ///
    /// Clock-skew check: any entry with
    /// `timestamp_ms > now_ms + 30_000` (30-second tolerance) causes
    /// [`StateStoreError::ClockSkewExceeded`].
    ///
    /// # Errors
    ///
    /// - [`StateStoreError::LockPoisoned`] — the mutex was poisoned by a
    ///   previous panic.
    /// - [`StateStoreError::ClockSkewExceeded`] — an entry is more than 30
    ///   seconds in the future relative to `now_ms`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
    ///
    /// let store = PolicyStateStore::new();
    /// let key = StateKey::new("alice", 2, "native", 3_600);
    ///
    /// // Seed one entry inside the window.
    /// store.append(&key, 500_000, 100).unwrap();
    ///
    /// // Query one second later; the entry is within the 1-hour window.
    /// let (sum, count) = store.query_window(&key, 501_000).unwrap();
    /// assert_eq!(sum, 100);
    /// assert_eq!(count, 1);
    /// ```
    pub fn query_window(
        &self,
        key: &StateKey,
        now_ms: u64,
    ) -> Result<(i128, u32), StateStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| StateStoreError::LockPoisoned {
                detail: e.to_string(),
            })?;

        let deque = guard.entry(key.clone()).or_default();

        let window_ms = key.window_secs.saturating_mul(1_000);
        let cutoff = now_ms.saturating_sub(window_ms);
        let future_limit = now_ms.saturating_add(CLOCK_SKEW_TOLERANCE_MS);

        // Check for clock-skew violations before eviction so we surface the
        // error before silently discarding future entries.
        for &(ts, _) in deque.iter() {
            if ts > future_limit {
                return Err(StateStoreError::ClockSkewExceeded {
                    entry_ts_ms: ts,
                    now_ms,
                });
            }
        }

        // Evict entries older than the window.
        while deque.front().is_some_and(|&(ts, _)| ts < cutoff) {
            deque.pop_front();
        }

        let mut sum: i128 = 0;
        let mut count: u32 = 0;
        for &(_, amount) in deque.iter() {
            sum = sum.saturating_add(amount);
            count = count.saturating_add(1);
        }

        Ok((sum, count))
    }

    /// Appends an entry to the store for the given key.
    ///
    /// This method is called by the dispatch site after a successful commit to
    /// record the transaction amount or a single call-count token (pass `1`
    /// for rate-limit accounting).
    ///
    /// # Errors
    ///
    /// Returns [`StateStoreError::LockPoisoned`] if the mutex is poisoned.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
    ///
    /// let store = PolicyStateStore::new();
    /// let key = StateKey::new("alice", 2, "native", 3_600);
    /// store.append(&key, 1_000_000, 500_000_000).unwrap();
    /// let (sum, count) = store.query_window(&key, 1_001_000).unwrap();
    /// assert_eq!(sum, 500_000_000);
    /// assert_eq!(count, 1);
    /// ```
    pub fn append(
        &self,
        key: &StateKey,
        timestamp_ms: u64,
        amount_or_count: i128,
    ) -> Result<(), StateStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| StateStoreError::LockPoisoned {
                detail: e.to_string(),
            })?;

        guard
            .entry(key.clone())
            .or_default()
            .push_back((timestamp_ms, amount_or_count));

        Ok(())
    }
}

impl Default for PolicyStateStore {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    fn key() -> StateKey {
        StateKey::new("alice", 2, "native", 3_600)
    }

    #[test]
    fn empty_store_returns_zero_sum_and_count() {
        let store = PolicyStateStore::new();
        let (sum, count) = store.query_window(&key(), 1_000_000).unwrap();
        assert_eq!(sum, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn entries_inside_window_are_summed() {
        let store = PolicyStateStore::new();
        let k = key();
        // window = 3600s = 3_600_000ms
        // now = 5_000_000ms; cutoff = 1_400_000ms
        store.append(&k, 2_000_000, 100).unwrap(); // inside window
        store.append(&k, 3_000_000, 200).unwrap(); // inside window
        let (sum, count) = store.query_window(&k, 5_000_000).unwrap();
        assert_eq!(sum, 300);
        assert_eq!(count, 2);
    }

    #[test]
    fn entries_before_cutoff_are_evicted() {
        let store = PolicyStateStore::new();
        let k = key();
        // now = 10_000_000ms; window = 3_600_000ms; cutoff = 6_400_000ms
        store.append(&k, 1_000_000, 999).unwrap(); // outside window → evicted
        store.append(&k, 7_000_000, 50).unwrap(); // inside window
        let (sum, count) = store.query_window(&k, 10_000_000).unwrap();
        assert_eq!(sum, 50);
        assert_eq!(count, 1);
    }

    #[test]
    fn state_key_scope_specificity_reflects_key_scope() {
        let global_key = StateKey::new("alice", 0, "native", 3_600);
        let profile_key = StateKey::new("alice", 1, "native", 3_600);
        let tool_key = StateKey::new("alice", 2, "native", 3_600);

        assert_eq!(global_key.scope_specificity(), 0);
        assert_eq!(profile_key.scope_specificity(), 1);
        assert_eq!(tool_key.scope_specificity(), 2);
        assert_ne!(
            global_key.scope_specificity(),
            tool_key.scope_specificity(),
            "different state scopes must not collapse to one specificity"
        );
    }

    #[test]
    fn entry_at_cutoff_boundary_remains_in_window() {
        // query_window evicts via strict `ts < cutoff`, so an entry at exactly
        // cutoff_ms must remain in the window; the mutant `<=` would evict it.
        // Decoy entry at cutoff_ms - 1 confirms eviction is wired.
        let store = PolicyStateStore::new();
        let k = StateKey::new("alice", 2, "native", 5);
        let cutoff_ms = 5_000;
        let now_ms = cutoff_ms + 5_000;

        store.append(&k, cutoff_ms - 1, 999).unwrap();
        store.append(&k, cutoff_ms, 7).unwrap();

        let (sum, count) = store.query_window(&k, now_ms).unwrap();
        assert_eq!(sum, 7);
        assert_eq!(count, 1);
    }

    #[test]
    fn clock_skew_over_30s_future_is_rejected() {
        let store = PolicyStateStore::new();
        let k = key();
        let now_ms = 1_000_000u64;
        // Entry is 31 seconds in the future — exceeds tolerance.
        store.append(&k, now_ms + 31_000, 1).unwrap();
        let err = store.query_window(&k, now_ms).unwrap_err();
        assert!(
            matches!(err, StateStoreError::ClockSkewExceeded { .. }),
            "expected ClockSkewExceeded, got {err:?}"
        );
    }

    #[test]
    fn clock_skew_within_30s_future_is_accepted() {
        let store = PolicyStateStore::new();
        let k = key();
        let now_ms = 1_000_000u64;
        // Entry is exactly 30 seconds in the future — within tolerance.
        store.append(&k, now_ms + 30_000, 1).unwrap();
        let result = store.query_window(&k, now_ms);
        assert!(result.is_ok(), "30s future should be within tolerance");
    }

    #[test]
    fn separate_keys_do_not_share_state() {
        let store = PolicyStateStore::new();
        let k1 = StateKey::new("alice", 2, "native", 3_600);
        let k2 = StateKey::new("bob", 2, "native", 3_600);
        store.append(&k1, 1_000_000, 500).unwrap();
        let (sum_k2, _) = store.query_window(&k2, 2_000_000).unwrap();
        assert_eq!(sum_k2, 0);
    }

    #[test]
    fn default_constructs_empty_store() {
        let store = PolicyStateStore::default();
        let (sum, count) = store.query_window(&key(), 0).unwrap();
        assert_eq!(sum, 0);
        assert_eq!(count, 0);
    }

    // ── i128 accumulator round-trip matrix ──────────────────────────────────
    //
    // Every shape a window record can hold, written via the real `append` /
    // `query_window` API pair and read back exactly. This store has no
    // on-disk form (see the module-level doc), so "round-trip" here means:
    // write via one store handle, read via `query_window` — the only
    // persistence boundary this store has.

    /// Fresh: an empty store's query returns `(0, 0)` exactly.
    #[test]
    fn round_trip_fresh_store_reads_zero() {
        let store = PolicyStateStore::new();
        let k = key();
        let (sum, count) = store.query_window(&k, 1_000_000).unwrap();
        assert_eq!(sum, 0_i128);
        assert_eq!(count, 0);
    }

    /// Accumulated, small (well within the old `i64` width): several entries
    /// summing to a value any `i64`-backed store could also have held — pins
    /// that ordinary sub-`i64::MAX` accounting is unaffected by the widening.
    #[test]
    fn round_trip_accumulated_small_total_reads_exact() {
        let store = PolicyStateStore::new();
        let k = key();
        store.append(&k, 1_000_000, 500_000_000).unwrap();
        store.append(&k, 1_100_000, 250_000_000).unwrap();
        store.append(&k, 1_200_000, 250_000_000).unwrap();
        let (sum, count) = store.query_window(&k, 1_300_000).unwrap();
        assert_eq!(sum, 1_000_000_000_i128);
        assert_eq!(count, 3);
    }

    /// A single entry at exactly `i64::MAX` — the old accumulator's ceiling —
    /// round-trips exactly under the widened `i128` type.
    #[test]
    fn round_trip_single_entry_at_i64_max_reads_exact() {
        let store = PolicyStateStore::new();
        let k = key();
        let at_i64_max = i128::from(i64::MAX);
        store.append(&k, 1_000_000, at_i64_max).unwrap();
        let (sum, count) = store.query_window(&k, 1_100_000).unwrap();
        assert_eq!(sum, at_i64_max);
        assert_eq!(count, 1);
    }

    /// A single entry strictly above `i64::MAX` round-trips exactly — the
    /// core new capability: no truncation, wraparound, or saturation to
    /// `i64::MAX`.
    #[test]
    fn round_trip_single_entry_above_i64_max_reads_exact() {
        let store = PolicyStateStore::new();
        let k = key();
        let beyond_i64_max = i128::from(i64::MAX) + 1_000;
        store.append(&k, 1_000_000, beyond_i64_max).unwrap();
        let (sum, count) = store.query_window(&k, 1_100_000).unwrap();
        assert_eq!(
            sum, beyond_i64_max,
            "a single above-i64::MAX entry must read back exactly, not clamped to i64::MAX"
        );
        assert_eq!(count, 1);
    }

    /// Several entries whose SUM exceeds `i64::MAX`, though no single entry
    /// does — proves the accumulation itself (not just a single stored value)
    /// is exact across the boundary.
    #[test]
    fn round_trip_accumulated_sum_above_i64_max_reads_exact() {
        let store = PolicyStateStore::new();
        let k = key();
        let half = i128::from(i64::MAX) / 2 + 1_000_000_000;
        store.append(&k, 1_000_000, half).unwrap();
        store.append(&k, 1_100_000, half).unwrap();
        store.append(&k, 1_200_000, half).unwrap();
        let expected = half.saturating_mul(3);
        assert!(
            expected > i128::from(i64::MAX),
            "test fixture must actually cross the i64::MAX boundary"
        );
        let (sum, count) = store.query_window(&k, 1_300_000).unwrap();
        assert_eq!(sum, expected);
        assert_eq!(count, 3);
    }
}
