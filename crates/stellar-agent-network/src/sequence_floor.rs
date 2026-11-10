//! Confirmed-sequence floor hook and the bounded catch-up poll built on it.
//!
//! [`SequenceFloorHook`] is the seam through which any account-fetch call
//! site — MCP's classic commit verbs and the DeFi adapter submit paths
//! (threaded through `DefiAdapterCtx` and `SubmitInvokeArgs`) — reads a
//! process-local confirmed-sequence floor and records newly confirmed
//! submits, without the lower crates in the dependency graph
//! (`stellar-agent-smart-account`, `stellar-agent-defi`) depending on
//! `stellar-agent-mcp`, which owns the concrete tracker as process-local,
//! long-lived state.
//!
//! This is a read-side latency optimisation, not a correctness mechanism:
//! [`fetch_account_with_sequence_catchup`] never fabricates a sequence number
//! and never blocks indefinitely. A hook that never catches up within the
//! bounded window, or no hook at all (`None`), leaves the caller with exactly
//! the plain [`crate::account::fetch_account`] behaviour — the eventual
//! submit fails typed `SubmissionError::SequenceNumberStale` exactly as it
//! would without this module.

use std::time::Duration;

use stellar_agent_core::error::WalletError;
use tokio::time::Instant;

use crate::account::{AccountView, fetch_account};
use crate::builder::Asset;
use crate::client::StellarRpcClient;
use crate::operational::read_within_readiness_deadline;

/// Bound on catch-up polls once a build-time fetch observes a sequence below
/// the tracked floor.
pub const CATCHUP_MAX_POLLS: u32 = 5;

/// Delay between catch-up polls (5 polls x 2s = 10s total re-poll window).
pub const CATCHUP_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Read+record hook into a confirmed-sequence floor tracker.
///
/// Implementations are advisory-only bookkeeping: `floor` and
/// `record_confirmed` must never fail the caller and must never block
/// materially (a brief, non-blocking lock acquisition is the expected
/// implementation shape — see `stellar-agent-mcp`'s `SequenceFloorTracker`,
/// the concrete implementation this trait was extracted to decouple from).
#[async_trait::async_trait]
pub trait SequenceFloorHook: Send + Sync {
    /// Returns the tracked floor for `account_id`, or `None` if no confirmed
    /// submit has been recorded for it in this process.
    async fn floor(&self, account_id: &str) -> Option<i64>;

    /// Records that `account_id`'s confirmed submit consumed
    /// `consumed_sequence`. Implementations must only ever advance a
    /// per-account floor, never regress it.
    async fn record_confirmed(&self, account_id: &str, consumed_sequence: i64);
}

/// Fetches `account_id`'s current account state, then — if `hook` is
/// present, has a recorded floor for the account, AND the returned sequence
/// number is BELOW that floor — re-polls up to [`CATCHUP_MAX_POLLS`] times at
/// [`CATCHUP_POLL_INTERVAL`] before giving up and returning the last-fetched
/// value as-is.
///
/// `hook = None` skips catch-up entirely and behaves exactly like a plain
/// [`fetch_account`] call — the back-compat default for callers that carry
/// no floor tracker (e.g. CLI processes, or any `submit_signed_invoke`
/// caller that does not thread a hook through).
///
/// # Errors
///
/// Propagates any [`WalletError`] `fetch_account` returns.
pub async fn fetch_account_with_sequence_catchup(
    hook: Option<&dyn SequenceFloorHook>,
    client: &StellarRpcClient,
    account_id: &str,
    trustline_assets: &[Asset],
) -> Result<AccountView, WalletError> {
    fetch_account_with_sequence_catchup_using(
        hook,
        client,
        account_id,
        trustline_assets,
        CATCHUP_MAX_POLLS,
        CATCHUP_POLL_INTERVAL,
    )
    .await
}

/// [`fetch_account_with_sequence_catchup`] with caller-supplied poll count
/// and interval. Production goes through the wrapper above with the module
/// constants; tests inject millisecond-scale timing so the exhausted-window
/// path runs without real multi-second sleeps.
///
/// # Errors
///
/// Propagates any [`WalletError`] `fetch_account` returns.
pub async fn fetch_account_with_sequence_catchup_using(
    hook: Option<&dyn SequenceFloorHook>,
    client: &StellarRpcClient,
    account_id: &str,
    trustline_assets: &[Asset],
    max_polls: u32,
    poll_interval: Duration,
) -> Result<AccountView, WalletError> {
    catch_up(
        hook,
        client,
        account_id,
        trustline_assets,
        max_polls,
        poll_interval,
        None,
    )
    .await
}

/// [`fetch_account_with_sequence_catchup`] for the account read that
/// follows [`crate::operational::operational_check`], under the `deadline`
/// the check ran under.
///
/// Every account read runs under `deadline`. The catch-up window ends at
/// `deadline` as it ends after [`CATCHUP_MAX_POLLS`]: a poll that would
/// start at or after `deadline` is not made, and the last-fetched value is
/// returned as-is.
///
/// # Errors
///
/// - `network.endpoint_not_ready` when an account read is still running at
///   `deadline`.
/// - Any other [`WalletError`] `fetch_account` returns.
pub async fn fetch_account_with_sequence_catchup_within(
    hook: Option<&dyn SequenceFloorHook>,
    client: &StellarRpcClient,
    account_id: &str,
    trustline_assets: &[Asset],
    deadline: Instant,
) -> Result<AccountView, WalletError> {
    catch_up(
        hook,
        client,
        account_id,
        trustline_assets,
        CATCHUP_MAX_POLLS,
        CATCHUP_POLL_INTERVAL,
        Some(deadline),
    )
    .await
}

/// The catch-up poll, every account read and the window bounded by
/// `deadline` when there is one.
async fn catch_up(
    hook: Option<&dyn SequenceFloorHook>,
    client: &StellarRpcClient,
    account_id: &str,
    trustline_assets: &[Asset],
    max_polls: u32,
    poll_interval: Duration,
    deadline: Option<Instant>,
) -> Result<AccountView, WalletError> {
    let read = || async {
        let read = fetch_account(client, account_id, trustline_assets);
        match deadline {
            Some(deadline) => read_within_readiness_deadline(deadline, read).await,
            None => read.await,
        }
    };
    let mut account = read().await?;

    let Some(hook) = hook else {
        return Ok(account);
    };
    let Some(floor) = hook.floor(account_id).await else {
        return Ok(account);
    };
    if account.sequence_number >= floor {
        return Ok(account);
    }

    for _ in 0..max_polls {
        if deadline.is_some_and(|deadline| Instant::now() + poll_interval >= deadline) {
            break;
        }
        tokio::time::sleep(poll_interval).await;
        account = read().await?;
        if account.sequence_number >= floor {
            break;
        }
    }
    Ok(account)
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

    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// In-memory [`SequenceFloorHook`] for tests: a plain `HashMap` behind a
    /// `std::sync::Mutex`, matching the "brief, non-blocking lock" discipline
    /// the trait's docs require of implementations.
    struct FakeHook {
        floors: Mutex<HashMap<String, i64>>,
    }

    impl FakeHook {
        fn new() -> Self {
            Self {
                floors: Mutex::new(HashMap::new()),
            }
        }

        fn with_floor(account_id: &str, floor: i64) -> Self {
            let hook = Self::new();
            hook.floors
                .lock()
                .expect("lock")
                .insert(account_id.to_owned(), floor);
            hook
        }
    }

    #[async_trait::async_trait]
    impl SequenceFloorHook for FakeHook {
        async fn floor(&self, account_id: &str) -> Option<i64> {
            self.floors.lock().expect("lock").get(account_id).copied()
        }

        async fn record_confirmed(&self, account_id: &str, consumed_sequence: i64) {
            let mut floors = self.floors.lock().expect("lock");
            let entry = floors.entry(account_id.to_owned()).or_insert(0);
            if consumed_sequence > *entry {
                *entry = consumed_sequence;
            }
        }
    }

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

    const TEST_ADDRESS: &str = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";

    #[tokio::test(flavor = "current_thread")]
    async fn no_hook_skips_catchup() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, TEST_ADDRESS, 41, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");

        let account = fetch_account_with_sequence_catchup(None, &client, TEST_ADDRESS, &[])
            .await
            .expect("fetch must succeed");

        assert_eq!(account.sequence_number, 41);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_floor_recorded_skips_catchup() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, TEST_ADDRESS, 41, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let hook = FakeHook::new();

        let account = fetch_account_with_sequence_catchup(Some(&hook), &client, TEST_ADDRESS, &[])
            .await
            .expect("fetch must succeed");

        assert_eq!(account.sequence_number, 41);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sequence_at_or_above_floor_returns_immediately() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, TEST_ADDRESS, 50, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let hook = FakeHook::with_floor(TEST_ADDRESS, 50);

        let account = fetch_account_with_sequence_catchup(Some(&hook), &client, TEST_ADDRESS, &[])
            .await
            .expect("fetch must succeed");

        assert_eq!(account.sequence_number, 50);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn catches_up_within_the_bounded_window() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, TEST_ADDRESS, 40, 1).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let hook = FakeHook::with_floor(TEST_ADDRESS, 50);

        mount_account_at_sequence(&mock_server, TEST_ADDRESS, 50, u64::MAX).await;

        let account = fetch_account_with_sequence_catchup_using(
            Some(&hook),
            &client,
            TEST_ADDRESS,
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

    #[tokio::test(flavor = "current_thread")]
    async fn proceeds_with_stale_value_after_window_exhausted() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, TEST_ADDRESS, 40, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let hook = FakeHook::with_floor(TEST_ADDRESS, 50);

        let account = fetch_account_with_sequence_catchup_using(
            Some(&hook),
            &client,
            TEST_ADDRESS,
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

    /// Under a deadline, the catch-up window ends at the deadline as it ends
    /// after the last poll: no poll that would start at or after the
    /// deadline is made, and the stale value is returned.
    #[tokio::test(flavor = "current_thread")]
    async fn the_catchup_window_ends_at_the_deadline() {
        let mock_server = wiremock::MockServer::start().await;
        mount_account_at_sequence(&mock_server, TEST_ADDRESS, 40, u64::MAX).await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");
        let hook = FakeHook::with_floor(TEST_ADDRESS, 50);
        let poll_interval = Duration::from_millis(400);

        let started = std::time::Instant::now();
        let account = catch_up(
            Some(&hook),
            &client,
            TEST_ADDRESS,
            &[],
            CATCHUP_MAX_POLLS,
            poll_interval,
            Some(Instant::now() + Duration::from_millis(1_000)),
        )
        .await
        .expect("a window cut at the deadline returns the last-fetched value");

        assert_eq!(account.sequence_number, 40);
        assert!(
            started.elapsed() < Duration::from_millis(1_000),
            "no poll starts at or after the deadline: {:?}",
            started.elapsed()
        );
        let requests = mock_server.received_requests().await.unwrap().len();
        assert_eq!(requests, 3, "the first read and two polls fit the window");
    }

    /// Under a deadline, an account read still running at the deadline
    /// refuses with `network.endpoint_not_ready`.
    #[tokio::test(flavor = "current_thread")]
    async fn an_account_read_past_the_deadline_refuses() {
        use stellar_agent_test_support::EchoIdResponder;
        use wiremock::Mock;
        use wiremock::matchers::method;

        let mock_server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(DelayedAnswer(
                EchoIdResponder::new(serde_json::json!({"entries": [], "latestLedger": 100})),
                Duration::from_secs(3),
            ))
            .mount(&mock_server)
            .await;
        let client = StellarRpcClient::new(&mock_server.uri()).expect("valid mock URL");

        let error = fetch_account_with_sequence_catchup_within(
            None,
            &client,
            TEST_ADDRESS,
            &[],
            Instant::now() + Duration::from_millis(300),
        )
        .await
        .expect_err("a read past the deadline refuses");

        assert_eq!(error.code(), "network.endpoint_not_ready", "{error:?}");
    }

    /// Answers as the inner responder does, after a delay.
    struct DelayedAnswer(stellar_agent_test_support::EchoIdResponder, Duration);

    impl wiremock::Respond for DelayedAnswer {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            self.0.respond(request).set_delay(self.1)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn record_confirmed_advances_but_never_regresses() {
        let hook = FakeHook::new();
        hook.record_confirmed(TEST_ADDRESS, 42).await;
        assert_eq!(hook.floor(TEST_ADDRESS).await, Some(42));
        hook.record_confirmed(TEST_ADDRESS, 100).await;
        assert_eq!(hook.floor(TEST_ADDRESS).await, Some(100));
        hook.record_confirmed(TEST_ADDRESS, 50).await;
        assert_eq!(
            hook.floor(TEST_ADDRESS).await,
            Some(100),
            "a lower recorded sequence (out-of-order confirm) must never regress the floor"
        );
    }
}
