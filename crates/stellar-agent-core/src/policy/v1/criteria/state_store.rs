//! In-memory sliding-window state store for per-period cap and rate-limit
//! criteria.
//!
//! [`PolicyStateStore`] is the runtime state holder injected into
//! [`crate::policy::v1::EvalContext`].  It maintains per-key `VecDeque` records
//! carrying a timestamp, amount, and pending status. Confirmed entries age out
//! of their window; unresolved entries hold headroom until settlement.
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
//! # Carrying the limit with the entry
//!
//! [`WindowEntry`] is what a stateful criterion hands back from
//! [`crate::policy::v1::criteria::Criterion::record_confirmed`]: the key, the
//! timestamp, the amount, and the [`WindowLimit`] that governs the bucket.
//! The durable store behind this one holds its own lock at the moment a
//! submission's spend is reserved, and re-applies the criterion's comparison
//! there via [`WindowEntry::refusal`]. The limit is policy rather than
//! history, so it travels with the entry and is never written to the file.
//!
//! # Thread safety
//!
//! `PolicyStateStore` wraps all mutable state in `std::sync::Mutex` so it is
//! `Send + Sync` and can live behind `Arc<PolicyEngineV1>`.
//!

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use crate::policy::DenyReason;

/// Maximum tolerated future clock skew for state-store entries, in milliseconds.
pub const CLOCK_SKEW_TOLERANCE_MS: u64 = 30_000;

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
// WindowLimit / WindowEntry
// ─────────────────────────────────────────────────────────────────────────────

/// The operator limit governing one window bucket.
///
/// A stateful criterion compares a call against this limit when it evaluates,
/// and carries the same limit on every entry it records. The reservation write
/// re-applies the comparison under the store's lock against the state the file
/// holds at that moment, so two calls that were each admissible against the
/// state they read cannot both reserve past the bucket. The limit is policy,
/// not history: it travels with the entry and is never persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowLimit {
    /// An aggregate-amount bucket, as `per_period_cap` and
    /// `bundle_per_period_cap` configure it.
    Amount {
        /// The asset identifier the cap is configured for, as its denial names it.
        asset: String,
        /// The window label its denial names (e.g. `"1d"`).
        window: String,
        /// The aggregate stroops the window admits.
        max_stroops: i128,
    },
    /// A call-count bucket, as `rate_limit` and `bundle_rate_limit` configure it.
    Count {
        /// The window label its denial names (e.g. `"1m"`).
        window: String,
        /// The calls the window admits.
        max_calls: u32,
    },
}

/// One window record a call contributes, with the limit that governs it.
///
/// Produced by the stateful criteria from the same fields their `evaluate`
/// compares against, so the key, the amount and the limit on the entry are the
/// ones the gate decided with.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::state_store::{
///     StateKey, WindowEntry, WindowLimit,
/// };
///
/// let entry = WindowEntry::new(
///     StateKey::new("alice", 1, "native", 86_400),
///     1_000_000,
///     400,
///     WindowLimit::Amount {
///         asset: "native".to_owned(),
///         window: "1d".to_owned(),
///         max_stroops: 1_000,
///     },
/// );
/// assert_eq!(entry.amount(), 400);
/// assert!(entry.refusal(500, 1).is_none());
/// assert!(entry.refusal(700, 1).is_some());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowEntry {
    key: StateKey,
    timestamp_ms: u64,
    amount: i128,
    limit: WindowLimit,
}

impl WindowEntry {
    /// Constructs a window entry for `key` at `timestamp_ms`.
    ///
    /// `amount` is the stroop total for an amount bucket and `1` for a
    /// call-count bucket, matching what the criterion appends to the
    /// in-memory store.
    #[must_use]
    pub fn new(key: StateKey, timestamp_ms: u64, amount: i128, limit: WindowLimit) -> Self {
        Self {
            key,
            timestamp_ms,
            amount,
            limit,
        }
    }

    /// Returns the bucket this entry accumulates into.
    #[must_use]
    pub fn key(&self) -> &StateKey {
        &self.key
    }

    /// Returns the entry's timestamp in unix milliseconds.
    #[must_use]
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// Returns the stroop total, or `1` for a call-count bucket.
    #[must_use]
    pub fn amount(&self) -> i128 {
        self.amount
    }

    /// Returns the limit governing this entry's bucket.
    #[must_use]
    pub fn limit(&self) -> &WindowLimit {
        &self.limit
    }

    /// Returns the denial this entry's limit produces against a window that
    /// already holds `used_stroops` across `calls` entries, or `None` when the
    /// window admits it.
    ///
    /// The comparison is the gate's own: an amount entry is refused when
    /// `used_stroops + amount > max_stroops`, a count entry when
    /// `calls + 1 > max_calls`.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::state_store::{
    ///     StateKey, WindowEntry, WindowLimit,
    /// };
    ///
    /// let entry = WindowEntry::new(
    ///     StateKey::new("alice", 1, "rate_limit", 60),
    ///     1_000_000,
    ///     1,
    ///     WindowLimit::Count {
    ///         window: "1m".to_owned(),
    ///         max_calls: 2,
    ///     },
    /// );
    /// assert!(entry.refusal(0, 1).is_none());
    /// assert!(entry.refusal(0, 2).is_some());
    /// ```
    #[must_use]
    pub fn refusal(&self, used_stroops: i128, calls: u32) -> Option<DenyReason> {
        match &self.limit {
            WindowLimit::Amount {
                asset,
                window,
                max_stroops,
            } => {
                let would_use = used_stroops.saturating_add(self.amount);
                (would_use > *max_stroops).then(|| DenyReason::PerPeriodCapExceeded {
                    asset: asset.clone(),
                    window: window.clone(),
                    max_stroops: *max_stroops,
                    attempted_stroops: self.amount,
                    period_used_stroops: used_stroops,
                })
            }
            // `calls >= max_calls` is `calls + 1 > max_calls` over the whole
            // `u32` range, and is the comparison the rate-limit criteria make.
            WindowLimit::Count { window, max_calls } => {
                (calls >= *max_calls).then(|| DenyReason::RateLimitExceeded {
                    window: window.clone(),
                    max_calls: *max_calls,
                    calls_in_window: calls,
                })
            }
        }
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
    /// Map from state key to entries in insertion order. Ledger close times
    /// need not follow that order. The amount is `i128`
    /// (see the module-level "Accumulator width" section) — exact across the
    /// full range a per-period stroop total can take.
    ///
    /// `Mutex<HashMap<...>>` enables `Send + Sync` without `parking_lot`
    /// (not yet a workspace dep; std Mutex is adequate here because this
    /// store is never held across an await point).
    inner: Mutex<HashMap<StateKey, VecDeque<StateEntry>>>,
}

#[derive(Debug)]
struct StateEntry {
    timestamp_ms: u64,
    amount: i128,
    pending: bool,
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
    /// Eviction removes confirmed entries with `timestamp_ms < now_ms -
    /// (window_secs * 1_000)`. Pending entries count regardless of age.
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
        for entry in deque.iter() {
            let ts = entry.timestamp_ms;
            if ts > future_limit {
                return Err(StateStoreError::ClockSkewExceeded {
                    entry_ts_ms: ts,
                    now_ms,
                });
            }
        }

        // Pending entries hold headroom until settlement. Confirmed entries
        // age from ledger close time, which need not follow insertion order.
        deque.retain(|entry| entry.pending || entry.timestamp_ms >= cutoff);

        let mut sum: i128 = 0;
        let mut count: u32 = 0;
        for entry in deque.iter() {
            sum = sum.saturating_add(entry.amount);
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
        self.append_entry(key, timestamp_ms, amount_or_count, false)
    }

    /// Appends an unresolved debit that counts regardless of its age.
    ///
    /// # Errors
    /// Returns [`StateStoreError::LockPoisoned`] if the mutex is poisoned.
    pub fn append_pending(
        &self,
        key: &StateKey,
        timestamp_ms: u64,
        amount_or_count: i128,
    ) -> Result<(), StateStoreError> {
        self.append_entry(key, timestamp_ms, amount_or_count, true)
    }

    fn append_entry(
        &self,
        key: &StateKey,
        timestamp_ms: u64,
        amount_or_count: i128,
        pending: bool,
    ) -> Result<(), StateStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| StateStoreError::LockPoisoned {
                detail: e.to_string(),
            })?;

        guard.entry(key.clone()).or_default().push_back(StateEntry {
            timestamp_ms,
            amount: amount_or_count,
            pending,
        });

        Ok(())
    }

    /// Removes every entry for every key, resetting the store to empty.
    ///
    /// Used by a long-lived engine (the MCP server) to REPLACE its in-memory
    /// view with a freshly re-hydrated one from the persisted window-state
    /// store before each dispatch, rather than merging on top of
    /// potentially-stale entries: `clear()` then re-append is the "replace,
    /// not merge" discipline that keeps a long-running process from
    /// accumulating entries a concurrent process (e.g. the CLI) has already
    /// superseded on disk.
    ///
    /// # Errors
    ///
    /// Returns [`StateStoreError::LockPoisoned`] if the mutex was poisoned by
    /// a previous panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::state_store::{PolicyStateStore, StateKey};
    ///
    /// let store = PolicyStateStore::new();
    /// let key = StateKey::new("alice", 1, "native", 3_600);
    /// store.append(&key, 1_000, 500).unwrap();
    /// store.clear().unwrap();
    /// let (sum, count) = store.query_window(&key, 2_000).unwrap();
    /// assert_eq!((sum, count), (0, 0));
    /// ```
    pub fn clear(&self) -> Result<(), StateStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|e| StateStoreError::LockPoisoned {
                detail: e.to_string(),
            })?;
        guard.clear();
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
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    fn key() -> StateKey {
        StateKey::new("alice", 2, "native", 3_600)
    }

    // ── WindowEntry admission boundaries ────────────────────────────────────

    fn amount_entry(amount: i128, max_stroops: i128) -> WindowEntry {
        WindowEntry::new(
            key(),
            1_000_000,
            amount,
            WindowLimit::Amount {
                asset: "native".to_owned(),
                window: "1d".to_owned(),
                max_stroops,
            },
        )
    }

    fn count_entry(max_calls: u32) -> WindowEntry {
        WindowEntry::new(
            StateKey::new("alice", 1, "rate_limit", 60),
            1_000_000,
            1,
            WindowLimit::Count {
                window: "1m".to_owned(),
                max_calls,
            },
        )
    }

    /// A spend that lands exactly on the cap is admitted; one stroop past it
    /// is refused. `per_period_cap` denies on `used + attempted > max`, so the
    /// cap is a ceiling the window may reach.
    #[test]
    fn an_amount_entry_is_admitted_at_the_cap_and_refused_one_past_it() {
        let entry = amount_entry(400, 1_000);
        assert!(entry.refusal(600, 0).is_none(), "600 + 400 reaches the cap");
        assert!(
            entry.refusal(601, 0).is_some(),
            "601 + 400 is one stroop past it"
        );
    }

    /// The refusal reports the numbers the criterion's own denial reports.
    #[test]
    fn an_amount_refusal_carries_the_cap_the_attempt_and_the_window_total() {
        match amount_entry(600, 1_000).refusal(600, 1) {
            Some(DenyReason::PerPeriodCapExceeded {
                asset,
                window,
                max_stroops,
                attempted_stroops,
                period_used_stroops,
            }) => {
                assert_eq!(asset, "native");
                assert_eq!(window, "1d");
                assert_eq!(max_stroops, 1_000);
                assert_eq!(attempted_stroops, 600);
                assert_eq!(period_used_stroops, 600);
            }
            other => panic!("expected PerPeriodCapExceeded, got {other:?}"),
        }
    }

    /// A call is admitted while the window holds fewer than `max_calls`, and
    /// refused once it holds that many. `rate_limit` denies on
    /// `calls_in_window >= max_calls`.
    #[test]
    fn a_count_entry_is_admitted_below_the_limit_and_refused_at_it() {
        let entry = count_entry(2);
        assert!(entry.refusal(0, 1).is_none(), "one call so far, limit two");
        assert!(entry.refusal(0, 2).is_some(), "the window is already full");
    }

    /// The comparison holds at the top of the `u32` range: a window already at
    /// `u32::MAX` calls under a `u32::MAX` limit admits nothing further, which
    /// an `n + 1` form would get wrong by saturating.
    #[test]
    fn a_count_entry_is_refused_at_the_top_of_the_u32_range() {
        assert!(count_entry(u32::MAX).refusal(0, u32::MAX).is_some());
        assert!(count_entry(u32::MAX).refusal(0, u32::MAX - 1).is_none());
    }

    /// The refusal reports the numbers the criterion's own denial reports.
    #[test]
    fn a_count_refusal_carries_the_limit_and_the_window_total() {
        match count_entry(1).refusal(0, 1) {
            Some(DenyReason::RateLimitExceeded {
                window,
                max_calls,
                calls_in_window,
            }) => {
                assert_eq!(window, "1m");
                assert_eq!(max_calls, 1);
                assert_eq!(calls_in_window, 1);
            }
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
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
