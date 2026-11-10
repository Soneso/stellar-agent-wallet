//! The operational check a value ceremony runs before it reads the account
//! it signs against.
//!
//! [`operational_check`] asks the endpoint three things, in this order: its
//! `getHealth` status, the close time of its latest ledger through
//! `getLedgers`, and the lag of that close time against the host clock. An
//! endpoint that reports a status other than healthy, that answers without a
//! valid close time, or whose latest ledger closed further than
//! [`MAX_LEDGER_CLOSE_LAG`] from the host clock refuses with
//! [`NetworkError::EndpointNotReady`].
//!
//! # Property the callers rely on
//!
//! A value ceremony reads the account state after this check, through the
//! same client under the same deadline, so the sequence it signs against is
//! at least as fresh as the ledger the [`OperationalReport`] names.
//! [`read_within_readiness_deadline`] bounds that read by the deadline the
//! check ran under, so a healthy check followed by a slow account answer
//! refuses instead of preparing after that deadline.
//! [`crate::sequence_floor::fetch_account_with_sequence_catchup_within`]
//! bounds every read of its catch-up the same way and ends its wait at the
//! deadline.

use std::future::Future;
use std::time::Duration;

use stellar_agent_core::error::{NetworkError, WalletError, WalletStateError};
use tokio::time::Instant;

use crate::client::StellarRpcClient;

/// The largest distance between the close time of the endpoint's latest
/// ledger and the host clock that the check accepts.
///
/// Ledgers close about every five seconds. A close time older than this
/// bound means a stalled endpoint, a stalled network, or a host clock the
/// operator must fix. A close time further in the future than this bound
/// means a skewed host clock. The value is a starting point for the first
/// release and changes in this one place.
pub const MAX_LEDGER_CLOSE_LAG: Duration = Duration::from_secs(60);

/// Bounds the `getLedgers` read independently of the caller's deadline.
pub const LEDGER_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// The `getHealth` status of an endpoint that serves current ledgers.
const HEALTHY_STATUS: &str = "healthy";

/// The refusal reason of a `getLedgers` answer the check cannot use.
const INVALID_CLOSE_TIME: &str = "getLedgers answered without a valid ledger close time";

/// The refusal reason of an account read still running at the deadline the
/// check ran under.
const ACCOUNT_READ_PAST_DEADLINE: &str = "account read exceeded the readiness deadline";

/// What the operational check observed on an endpoint that passed it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OperationalReport {
    /// The latest ledger the endpoint's `getLedgers` answer names.
    pub latest_ledger: u32,
    /// The close time of that ledger, in Unix seconds.
    pub close_time_unix: u64,
    /// The host clock's Unix seconds minus [`Self::close_time_unix`],
    /// saturating at zero.
    pub close_lag_seconds: u64,
}

/// Checks that `client`'s endpoint is healthy and current before a value
/// ceremony reads the account it signs against.
///
/// The check reads `getHealth` under `deadline`, then the endpoint's latest
/// ledger through `getLedgers` under the earlier of `deadline` and
/// [`LEDGER_READ_TIMEOUT`] from now, then the host clock. The caller reads
/// the account afterwards through the same client.
///
/// # Errors
///
/// - [`NetworkError::EndpointNotReady`] when `getHealth` fails or reports a
///   status other than healthy, when `getLedgers` fails, times out, or
///   answers without a valid close time, or when the latest ledger closed
///   more than [`MAX_LEDGER_CLOSE_LAG`] before or after the host clock. The
///   reason never carries the endpoint URL or a credential.
/// - [`WalletStateError::ClockError`] (`wallet.clock_error`) when the host
///   clock cannot be read.
pub async fn operational_check(
    client: &StellarRpcClient,
    deadline: Instant,
) -> Result<OperationalReport, WalletError> {
    operational_check_at(client, deadline, host_clock_unix).await
}

/// The host clock in Unix seconds, mapped to the wallet's clock error.
fn host_clock_unix() -> Result<u64, WalletError> {
    stellar_agent_core::timefmt::now_unix_ms()
        .map(|ms| ms / 1_000)
        .map_err(|error| {
            WalletError::WalletState(WalletStateError::ClockError {
                detail: error.to_string(),
            })
        })
}

/// [`operational_check`] with the host clock supplied by `now_unix`, which
/// the check reads once, after both endpoint reads.
async fn operational_check_at(
    client: &StellarRpcClient,
    deadline: Instant,
    now_unix: impl FnOnce() -> Result<u64, WalletError>,
) -> Result<OperationalReport, WalletError> {
    let health = client
        .get_health_within(deadline)
        .await
        .map_err(|error| not_ready(network_failure_reason(error)))?;
    if health.status != HEALTHY_STATUS {
        return Err(not_ready(format!(
            "endpoint reports status {}",
            client.url.scrub(&health.status)
        )));
    }

    let own = Instant::now() + LEDGER_READ_TIMEOUT;
    let answer = tokio::time::timeout_at(
        deadline.min(own),
        client.inner.get_ledgers(
            stellar_rpc_client::LedgerStart::Ledger(health.latest_ledger),
            Some(1),
            None,
        ),
    )
    .await;
    let (latest_ledger, close_time_unix) = match answer {
        Ok(Ok(answer))
            if answer.latest_ledger_close_time > 0
                && answer.latest_ledger_close_time >= answer.oldest_ledger_close_time
                && answer.latest_ledger >= health.latest_ledger
                && answer.oldest_ledger <= answer.latest_ledger =>
        {
            (
                answer.latest_ledger,
                answer.latest_ledger_close_time.unsigned_abs(),
            )
        }
        Ok(Ok(_)) => return Err(not_ready(INVALID_CLOSE_TIME.to_owned())),
        Ok(Err(error)) => {
            return Err(not_ready(format!(
                "getLedgers failed: {}",
                client.url.scrub_display(&error)
            )));
        }
        Err(_) if deadline < own => {
            return Err(not_ready(
                "getLedgers did not answer before the caller's deadline".to_owned(),
            ));
        }
        Err(_) => {
            return Err(not_ready(format!(
                "getLedgers did not answer within {}s",
                LEDGER_READ_TIMEOUT.as_secs()
            )));
        }
    };

    let now_unix = now_unix()?;
    let bound = MAX_LEDGER_CLOSE_LAG.as_secs();
    if close_time_unix > now_unix.saturating_add(bound) {
        return Err(not_ready(format!(
            "ledger {latest_ledger} closed {} s in the future of the host clock",
            close_time_unix - now_unix
        )));
    }
    let close_lag_seconds = now_unix.saturating_sub(close_time_unix);
    if close_lag_seconds > bound {
        return Err(not_ready(format!(
            "ledger {latest_ledger} closed {close_lag_seconds} s ago; the endpoint or the host \
             clock is behind"
        )));
    }
    Ok(OperationalReport {
        latest_ledger,
        close_time_unix,
        close_lag_seconds,
    })
}

/// Runs `read`, the account read that follows [`operational_check`] on the
/// same client, under the `deadline` the check ran under.
///
/// # Errors
///
/// - [`NetworkError::EndpointNotReady`] with the reason `account read
///   exceeded the readiness deadline` when `read` has not finished at
///   `deadline`.
/// - The error of `read` otherwise.
pub async fn read_within_readiness_deadline<T, E>(
    deadline: Instant,
    read: impl Future<Output = Result<T, E>>,
) -> Result<T, E>
where
    E: From<WalletError>,
{
    tokio::time::timeout_at(deadline, read)
        .await
        .unwrap_or_else(|_| Err(not_ready(ACCOUNT_READ_PAST_DEADLINE.to_owned()).into()))
}

fn not_ready(reason: String) -> WalletError {
    WalletError::Network(NetworkError::EndpointNotReady { reason })
}

/// The reason text of a failed `getHealth` read, without the endpoint's
/// authority. The client's read already scrubs the reason.
fn network_failure_reason(error: NetworkError) -> String {
    match error {
        NetworkError::RpcUnreachable { reason, .. } => reason,
        other => other.code().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics and unwraps are acceptable in unit tests"
    )]

    use super::*;
    use serde_json::json;
    use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
    use wiremock::matchers::{body_partial_json, method};
    use wiremock::{Mock, MockServer};

    /// The fixed host clock of these tests, in Unix seconds.
    const NOW: u64 = 1_800_000_000;

    fn health(status: &str, latest: u32) -> serde_json::Value {
        json!({
            "status": status,
            "latestLedger": latest,
            "oldestLedger": 1,
            "ledgerRetentionWindow": latest - 1,
        })
    }

    fn ledgers(latest: u32, close: u64) -> serde_json::Value {
        json!({
            "latestLedger": latest,
            "latestLedgerCloseTime": close.to_string(),
            "oldestLedger": 1,
            "oldestLedgerCloseTime": 1,
            "cursor": latest.to_string(),
            "ledgers": [],
        })
    }

    async fn server(
        health: serde_json::Value,
        ledgers: Option<(serde_json::Value, Duration)>,
    ) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getHealth"})))
            .respond_with(EchoIdResponder::new(health))
            .mount(&server)
            .await;
        if let Some((ledgers, delay)) = ledgers {
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method": "getLedgers"})))
                .respond_with(DelayedResponder {
                    inner: EchoIdResponder::new(ledgers),
                    delay,
                })
                .mount(&server)
                .await;
        }
        server
    }

    /// Answers as `inner` does, after `delay`.
    struct DelayedResponder {
        inner: EchoIdResponder,
        delay: Duration,
    }

    impl wiremock::Respond for DelayedResponder {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            self.inner.respond(request).set_delay(self.delay)
        }
    }

    async fn check(
        server: &MockServer,
        deadline: Duration,
    ) -> Result<OperationalReport, WalletError> {
        let client = StellarRpcClient::new(&server.uri()).unwrap();
        operational_check_at(&client, Instant::now() + deadline, || Ok(NOW)).await
    }

    /// Mounts `getLedgers` on `server` answering a JSON-RPC error whose
    /// message echoes `text`.
    async fn mount_ledgers_error(server: &MockServer, text: &str) {
        let text = text.to_owned();
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": "getLedgers"})))
            .respond_with(move |request: &wiremock::Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                wiremock::ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32603, "message": text},
                }))
            })
            .mount(server)
            .await;
    }

    fn reason<T: std::fmt::Debug>(result: Result<T, WalletError>) -> String {
        match result {
            Err(WalletError::Network(NetworkError::EndpointNotReady { reason })) => {
                assert_eq!(
                    WalletError::Network(NetworkError::EndpointNotReady {
                        reason: reason.clone()
                    })
                    .code(),
                    "network.endpoint_not_ready"
                );
                reason
            }
            other => panic!("expected network.endpoint_not_ready, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_healthy_current_endpoint_returns_the_report() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(100, NOW - 4), Duration::ZERO)),
        )
        .await;
        let report = check(&server, Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            report,
            OperationalReport {
                latest_ledger: 100,
                close_time_unix: NOW - 4,
                close_lag_seconds: 4,
            }
        );
        assert_eq!(rpc_request_count(&server, "getHealth").await, 1);
        assert_eq!(rpc_request_count(&server, "getLedgers").await, 1);
    }

    #[tokio::test]
    async fn an_unhealthy_status_refuses() {
        let server = server(
            health("unhealthy", 100),
            Some((ledgers(100, NOW - 4), Duration::ZERO)),
        )
        .await;
        let reason = reason(check(&server, Duration::from_secs(5)).await);
        assert_eq!(reason, "endpoint reports status \"unhealthy\"");
        assert_eq!(rpc_request_count(&server, "getLedgers").await, 0);
    }

    #[tokio::test]
    async fn a_stale_close_time_refuses() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(100, NOW - 61), Duration::ZERO)),
        )
        .await;
        let reason = reason(check(&server, Duration::from_secs(5)).await);
        assert_eq!(
            reason,
            "ledger 100 closed 61 s ago; the endpoint or the host clock is behind"
        );
    }

    #[tokio::test]
    async fn a_close_time_at_the_bound_passes() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(100, NOW - 60), Duration::ZERO)),
        )
        .await;
        let report = check(&server, Duration::from_secs(5)).await.unwrap();
        assert_eq!(report.close_lag_seconds, 60);
    }

    #[tokio::test]
    async fn a_future_close_time_refuses() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(100, NOW + 61), Duration::ZERO)),
        )
        .await;
        let reason = reason(check(&server, Duration::from_secs(5)).await);
        assert_eq!(
            reason,
            "ledger 100 closed 61 s in the future of the host clock"
        );
    }

    #[tokio::test]
    async fn a_ledger_answer_below_health_refuses() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(99, NOW - 4), Duration::ZERO)),
        )
        .await;
        let reason = reason(check(&server, Duration::from_secs(5)).await);
        assert_eq!(reason, INVALID_CLOSE_TIME);
    }

    #[tokio::test]
    async fn a_slow_ledger_read_refuses_at_the_deadline() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(100, NOW - 4), Duration::from_secs(5))),
        )
        .await;
        let started = std::time::Instant::now();
        let reason = reason(check(&server, Duration::from_millis(800)).await);
        assert_eq!(
            reason,
            "getLedgers did not answer before the caller's deadline"
        );
        assert!(
            started.elapsed() < LEDGER_READ_TIMEOUT,
            "the caller's deadline ends the read before the own bound"
        );
    }

    /// The ledger read has its own bound: with the caller's deadline far
    /// away, a `getLedgers` answer slower than [`LEDGER_READ_TIMEOUT`]
    /// refuses at that bound.
    #[tokio::test]
    async fn a_slow_ledger_read_refuses_at_its_own_bound() {
        let delay = LEDGER_READ_TIMEOUT * 2;
        let server = server(health("healthy", 100), Some((ledgers(100, NOW - 4), delay))).await;
        let started = std::time::Instant::now();
        let reason = reason(check(&server, Duration::from_secs(30)).await);
        assert_eq!(reason, "getLedgers did not answer within 2s");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= LEDGER_READ_TIMEOUT && elapsed < delay,
            "the own bound ends the read: {elapsed:?}"
        );
    }

    /// A failed ledger read names the failure without the credential of an
    /// endpoint URL that carries userinfo: the echoed URL keeps host and
    /// port only.
    #[tokio::test]
    async fn a_failed_ledger_read_scrubs_the_endpoint_credential() {
        let server = server(health("healthy", 100), None).await;
        let authority = server.address().to_string();
        let url = format!("http://agent:S3CRET-PASS@{authority}/rpc");
        mount_ledgers_error(&server, &format!("upstream {url} refused the read")).await;
        let client = StellarRpcClient::new(&url).unwrap();

        let reason = reason(
            operational_check_at(&client, Instant::now() + Duration::from_secs(5), || Ok(NOW))
                .await,
        );

        assert!(reason.starts_with("getLedgers failed: "), "{reason}");
        assert!(
            reason.contains(&format!("upstream {authority} refused the read")),
            "{reason}"
        );
        for leaked in ["S3CRET-PASS", "agent:", "http://", "/rpc"] {
            assert!(
                !reason.contains(leaked),
                "{leaked} reached the reason: {reason}"
            );
        }
    }

    /// A host clock that cannot be read refuses with the wallet's clock
    /// error, not with `network.endpoint_not_ready`.
    #[tokio::test]
    async fn a_host_clock_failure_refuses_with_the_clock_error() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(100, NOW - 4), Duration::ZERO)),
        )
        .await;
        let client = StellarRpcClient::new(&server.uri()).unwrap();

        let error = operational_check_at(&client, Instant::now() + Duration::from_secs(5), || {
            Err(WalletError::WalletState(WalletStateError::ClockError {
                detail: "the host clock is before the Unix epoch".to_owned(),
            }))
        })
        .await
        .unwrap_err();

        assert_eq!(error.code(), "wallet.clock_error", "{error:?}");
    }

    /// A close time at the bound ahead of the host clock passes with a lag
    /// of zero; `a_future_close_time_refuses` pins one second further.
    #[tokio::test]
    async fn a_close_time_at_the_future_bound_passes_with_lag_zero() {
        let server = server(
            health("healthy", 100),
            Some((ledgers(100, NOW + 60), Duration::ZERO)),
        )
        .await;
        let report = check(&server, Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            report,
            OperationalReport {
                latest_ledger: 100,
                close_time_unix: NOW + 60,
                close_lag_seconds: 0,
            }
        );
    }

    /// An account read still running at the readiness deadline refuses with
    /// `network.endpoint_not_ready`; a read that finishes in time returns
    /// its own result.
    #[tokio::test]
    async fn an_account_read_past_the_readiness_deadline_refuses() {
        let late = read_within_readiness_deadline::<(), WalletError>(
            Instant::now() + Duration::from_millis(50),
            std::future::pending(),
        )
        .await;
        assert_eq!(reason(late), ACCOUNT_READ_PAST_DEADLINE);

        let in_time =
            read_within_readiness_deadline(Instant::now() + Duration::from_secs(5), async {
                Ok::<_, WalletError>(7_u32)
            })
            .await;
        assert_eq!(in_time.unwrap(), 7);
    }
}
