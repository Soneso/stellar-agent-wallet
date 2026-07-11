//! In-process per-source-account confirmed-sequence floor, and the bounded
//! catch-up poll built on top of it.
//!
//! The MCP server is long-lived and serves every dispatch for a given source
//! account from the same process. Each CONFIRMED submit already knows the
//! sequence number the transaction consumed (the account's pre-submit
//! sequence plus one); [`SequenceFloorTracker`] remembers the highest such
//! value per source account so a build-time `fetch_account` call that
//! observes a STALE sequence (the RPC node has not yet caught up with a
//! submit this same process just confirmed) can wait it out instead of
//! immediately handing a stale sequence to the transaction builder.
//!
//! This is a read-side latency optimisation, not a correctness mechanism:
//! [`fetch_account_with_sequence_catchup`] never fabricates a sequence number
//! and never blocks indefinitely. If the node has not caught up within the
//! bounded window, the caller proceeds with the fetched value exactly as it
//! would without this module, and the eventual submit fails typed
//! `SubmissionError::SequenceNumberStale` exactly as it would today — the
//! mitigation only removes AVOIDABLE staleness from ordinary
//! read-after-write propagation lag between the node that served the confirm
//! and the node that serves the next build.
//!
//! CLI processes are short-lived (one process per invocation) and hold no
//! history to track against, so this tracker is MCP-server-only; the CLI is
//! out of scope by design (see the module's own single-process lifetime
//! discussion in `stellar_agent_network::policy_state`).
//!
//! # DeFi adapter submit paths
//!
//! The classic commit verbs below thread [`SequenceFloorTracker`] directly.
//! The DeFi adapter submit paths (`stellar_dex_trade`, `stellar_blend_lend`,
//! `stellar_defindex_vault_*`) delegate build and submit to their adapter
//! crates via `DefiAdapterCtx`, which never sees this tracker's concrete
//! type. Those call sites instead thread [`hook`]'s
//! `stellar_agent_network::SequenceFloorHook` object into
//! `DefiAdapterCtx::sequence_floor`, which reaches the adapter's own
//! `submit_signed_invoke` call through `SubmitInvokeArgs::sequence_floor`.
//! Both paths read and write the SAME tracker; a confirmed classic-verb
//! submit and a confirmed DeFi submit for the same source account advance
//! one shared floor.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use stellar_agent_core::error::WalletError;
use stellar_agent_network::{AccountView, Asset, StellarRpcClient};
use tokio::sync::Mutex as TokioMutex;

/// Maximum distinct source accounts tracked at once.
///
/// Eviction policy: FIFO by first-insertion order (not LRU — an account's
/// position in the eviction queue does not move on update, only on first
/// insertion). This tracker is advisory: evicting a still-active account
/// costs at most one avoidable extra poll on its next build, never a wrong
/// sequence, so the simpler FIFO policy is preferred over the bookkeeping an
/// LRU would add for no correctness benefit.
const MAX_TRACKED_ACCOUNTS: usize = 4_096;

/// Bound on catch-up polls once a build-time fetch observes a sequence below
/// the tracked floor.
const CATCHUP_MAX_POLLS: u32 = 5;

/// Delay between catch-up polls (5 polls × 2s ≈ 10s total re-poll window).
const CATCHUP_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Tracks, per source account (G-strkey), the highest sequence number known
/// to have been consumed by a CONFIRMED submit in this process's lifetime.
///
/// # Concurrency
///
/// Shared across concurrent dispatches behind [`TokioMutex`] (see
/// `WalletServer::sequence_floor`), matching the discipline
/// `WalletServer::replay_window` uses for its own shared in-memory state: the
/// lock is held only for a brief, non-blocking map read or write, never
/// across an `.await` on network I/O.
pub(crate) struct SequenceFloorTracker {
    floors: HashMap<String, i64>,
    insertion_order: VecDeque<String>,
}

impl SequenceFloorTracker {
    /// Creates a new, empty tracker.
    pub(crate) fn new() -> Self {
        Self {
            floors: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    /// Records that a submit for `account_id` was confirmed consuming
    /// `consumed_sequence`.
    ///
    /// Only ever advances the floor: an out-of-order or duplicate record can
    /// never regress a higher value already recorded for the same account.
    pub(crate) fn record_confirmed(&mut self, account_id: &str, consumed_sequence: i64) {
        if let Some(existing) = self.floors.get_mut(account_id) {
            if consumed_sequence > *existing {
                *existing = consumed_sequence;
            }
            return;
        }
        if self.floors.len() >= MAX_TRACKED_ACCOUNTS
            && let Some(oldest) = self.insertion_order.pop_front()
        {
            self.floors.remove(&oldest);
        }
        self.floors.insert(account_id.to_owned(), consumed_sequence);
        self.insertion_order.push_back(account_id.to_owned());
    }

    /// Returns the tracked floor for `account_id`, if this process has
    /// recorded a confirmed submit for it.
    pub(crate) fn floor(&self, account_id: &str) -> Option<i64> {
        self.floors.get(account_id).copied()
    }

    /// Returns the number of distinct accounts currently tracked.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.floors.len()
    }
}

/// Fetches `account_id`'s current account state, then — if the returned
/// sequence number is BELOW the tracker's recorded floor for that account —
/// re-polls up to [`CATCHUP_MAX_POLLS`] times at [`CATCHUP_POLL_INTERVAL`]
/// before giving up and returning the last-fetched value as-is.
///
/// A `None` floor (no confirmed submit recorded for this account in this
/// process) skips the catch-up entirely — there is nothing to catch up to.
///
/// # Errors
///
/// Propagates any [`WalletError`] `fetch_account` returns.
pub(crate) async fn fetch_account_with_sequence_catchup(
    tracker: &TokioMutex<SequenceFloorTracker>,
    client: &StellarRpcClient,
    account_id: &str,
    trustline_assets: &[Asset],
) -> Result<AccountView, WalletError> {
    fetch_account_with_sequence_catchup_using(
        tracker,
        client,
        account_id,
        trustline_assets,
        CATCHUP_MAX_POLLS,
        CATCHUP_POLL_INTERVAL,
    )
    .await
}

/// [`fetch_account_with_sequence_catchup`] with caller-supplied poll count and
/// interval. Production goes through the wrapper above with the module
/// constants; tests inject millisecond-scale timing so the exhausted-window
/// path runs without real multi-second sleeps.
///
/// Delegates to `stellar_agent_network::sequence_floor`'s shared catch-up
/// loop via [`TrackerHook`] — the SAME implementation the DeFi adapter submit
/// paths use through `DefiAdapterCtx::sequence_floor`, so both surfaces share
/// one poll algorithm.
async fn fetch_account_with_sequence_catchup_using(
    tracker: &TokioMutex<SequenceFloorTracker>,
    client: &StellarRpcClient,
    account_id: &str,
    trustline_assets: &[Asset],
    max_polls: u32,
    poll_interval: Duration,
) -> Result<AccountView, WalletError> {
    let hook = TrackerHook(tracker);
    stellar_agent_network::sequence_floor::fetch_account_with_sequence_catchup_using(
        Some(&hook),
        client,
        account_id,
        trustline_assets,
        max_polls,
        poll_interval,
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// TrackerHook — SequenceFloorHook adapter for DefiAdapterCtx threading
// ─────────────────────────────────────────────────────────────────────────────

/// Local newtype satisfying Rust's orphan rules for implementing the shared
/// `stellar_agent_network::SequenceFloorHook` trait over this crate's
/// `TokioMutex`-guarded [`SequenceFloorTracker`].
struct TrackerHook<'a>(&'a TokioMutex<SequenceFloorTracker>);

#[async_trait::async_trait]
impl stellar_agent_network::SequenceFloorHook for TrackerHook<'_> {
    async fn floor(&self, account_id: &str) -> Option<i64> {
        self.0.lock().await.floor(account_id)
    }

    async fn record_confirmed(&self, account_id: &str, consumed_sequence: i64) {
        self.0
            .lock()
            .await
            .record_confirmed(account_id, consumed_sequence);
    }
}

/// Builds a [`SequenceFloorHook`](stellar_agent_network::SequenceFloorHook)
/// borrowing `tracker`, for threading into `DefiAdapterCtx::sequence_floor`
/// at the DeFi MCP tool call sites (`dex_trade`, `blend_lend`, `vault`).
pub(crate) fn hook(
    tracker: &TokioMutex<SequenceFloorTracker>,
) -> impl stellar_agent_network::SequenceFloorHook + '_ {
    TrackerHook(tracker)
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

    #[test]
    fn new_is_empty() {
        let t = SequenceFloorTracker::new();
        assert_eq!(t.len(), 0);
        assert_eq!(t.floor("GABC"), None);
    }

    #[test]
    fn record_confirmed_sets_floor() {
        let mut t = SequenceFloorTracker::new();
        t.record_confirmed("GABC", 42);
        assert_eq!(t.floor("GABC"), Some(42));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn record_confirmed_advances_but_never_regresses() {
        let mut t = SequenceFloorTracker::new();
        t.record_confirmed("GABC", 42);
        t.record_confirmed("GABC", 100);
        assert_eq!(
            t.floor("GABC"),
            Some(100),
            "a higher recorded sequence must advance the floor"
        );
        t.record_confirmed("GABC", 50);
        assert_eq!(
            t.floor("GABC"),
            Some(100),
            "a lower recorded sequence (out-of-order confirm) must never regress the floor"
        );
    }

    #[test]
    fn distinct_accounts_tracked_independently() {
        let mut t = SequenceFloorTracker::new();
        t.record_confirmed("GABC", 1);
        t.record_confirmed("GDEF", 2);
        assert_eq!(t.floor("GABC"), Some(1));
        assert_eq!(t.floor("GDEF"), Some(2));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn eviction_bounds_tracked_account_count() {
        let mut t = SequenceFloorTracker::new();
        for i in 0..(MAX_TRACKED_ACCOUNTS + 10) {
            t.record_confirmed(&format!("G{i}"), i as i64);
        }
        assert_eq!(
            t.len(),
            MAX_TRACKED_ACCOUNTS,
            "tracked account count must never exceed the bound"
        );
        // The earliest-inserted accounts must have been evicted (FIFO).
        assert_eq!(t.floor("G0"), None, "oldest entry must be evicted");
        // The most recently inserted account must still be present.
        let last = MAX_TRACKED_ACCOUNTS + 9;
        assert_eq!(t.floor(&format!("G{last}")), Some(last as i64));
    }

    #[test]
    fn updating_an_existing_account_does_not_grow_tracked_count() {
        let mut t = SequenceFloorTracker::new();
        t.record_confirmed("GABC", 1);
        t.record_confirmed("GABC", 2);
        t.record_confirmed("GABC", 3);
        assert_eq!(t.len(), 1);
        assert_eq!(t.floor("GABC"), Some(3));
    }

    // ── fetch_account_with_sequence_catchup: wiremock RPC ─────────────────────

    /// Mounts a `getLedgerEntries` mock reporting `address` at `seq_num`,
    /// matching at most `times` requests before wiremock stops honouring it —
    /// so a SECOND call with a different `seq_num` and an unlimited `times`
    /// takes over from the caller-chosen point onward (the standard
    /// wiremock-rs "response changes after N calls" pattern; matching by
    /// registration order alone is not reliable when two mocks could both
    /// match the same request).
    async fn mount_account_at_sequence(
        mock_server: &wiremock::MockServer,
        address: &str,
        seq_num: i64,
        times: u64,
    ) {
        use stellar_agent_test_support::EchoIdResponder;
        use stellar_agent_test_support::xdr_fixtures::{
            account_entry_xdr_with_seq, account_ledger_key_xdr,
        };
        use wiremock::Mock;
        use wiremock::matchers::{method, path};

        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(EchoIdResponder::new(serde_json::json!({
                "entries": [
                    {
                        "key": account_ledger_key_xdr(address),
                        "xdr": account_entry_xdr_with_seq(address, 100_000_000_000, 0, seq_num),
                        "lastModifiedLedgerSeq": 100
                    }
                ],
                "latestLedger": 100
            })))
            .up_to_n_times(times)
            .mount(mock_server)
            .await;
    }

    const CATCHUP_TEST_ADDRESS: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

    /// No floor recorded for the account: the fetched value is returned
    /// as-is, with no catch-up polling at all.
    #[tokio::test(flavor = "current_thread")]
    async fn no_floor_recorded_skips_catchup() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, CATCHUP_TEST_ADDRESS, 41, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let tracker = TokioMutex::new(SequenceFloorTracker::new());

        let account =
            fetch_account_with_sequence_catchup(&tracker, &client, CATCHUP_TEST_ADDRESS, &[])
                .await
                .expect("fetch must succeed");

        assert_eq!(account.sequence_number, 41);
    }

    /// The fetched sequence already meets the tracked floor: returned
    /// immediately, no catch-up polling.
    #[tokio::test(flavor = "current_thread")]
    async fn sequence_at_or_above_floor_returns_immediately() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, CATCHUP_TEST_ADDRESS, 50, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let tracker = TokioMutex::new(SequenceFloorTracker::new());
        tracker
            .lock()
            .await
            .record_confirmed(CATCHUP_TEST_ADDRESS, 50);

        let account =
            fetch_account_with_sequence_catchup(&tracker, &client, CATCHUP_TEST_ADDRESS, &[])
                .await
                .expect("fetch must succeed");

        assert_eq!(account.sequence_number, 50);
    }

    /// A stale first fetch that catches up to the floor WITHIN the bounded
    /// window is returned at the caught-up value, not the initial stale one.
    #[tokio::test(flavor = "current_thread")]
    async fn catches_up_within_the_bounded_window() {
        let mock_server = wiremock::MockServer::start().await;
        // First response: stale (below the floor of 50); expires after the
        // one initial fetch.
        mount_account_at_sequence(&mock_server, CATCHUP_TEST_ADDRESS, 40, 1).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let tracker = TokioMutex::new(SequenceFloorTracker::new());
        tracker
            .lock()
            .await
            .record_confirmed(CATCHUP_TEST_ADDRESS, 50);

        // Takes over once the first mock is exhausted: every catch-up poll
        // from here on reports the caught-up sequence.
        mount_account_at_sequence(&mock_server, CATCHUP_TEST_ADDRESS, 50, u64::MAX).await;

        let account = fetch_account_with_sequence_catchup_using(
            &tracker,
            &client,
            CATCHUP_TEST_ADDRESS,
            &[],
            CATCHUP_MAX_POLLS,
            Duration::from_millis(1),
        )
        .await
        .expect("fetch must succeed");

        assert_eq!(
            account.sequence_number, 50,
            "must return the caught-up sequence, not the initial stale one"
        );
    }

    /// A sequence that NEVER catches up within the bounded window is
    /// returned as-is (still stale) — the mitigation never fabricates a
    /// sequence and never blocks indefinitely.
    #[tokio::test(flavor = "current_thread")]
    async fn proceeds_with_stale_value_after_window_exhausted() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, CATCHUP_TEST_ADDRESS, 40, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let tracker = TokioMutex::new(SequenceFloorTracker::new());
        tracker
            .lock()
            .await
            .record_confirmed(CATCHUP_TEST_ADDRESS, 50);

        let account = fetch_account_with_sequence_catchup_using(
            &tracker,
            &client,
            CATCHUP_TEST_ADDRESS,
            &[],
            CATCHUP_MAX_POLLS,
            Duration::from_millis(1),
        )
        .await
        .expect("fetch must succeed even though it never catches up");

        assert_eq!(
            account.sequence_number, 40,
            "must proceed with the fetched (stale) value rather than block indefinitely or invent a sequence"
        );
    }
}
