//! The submission deadline bounds the retention-aware confirmation poll of
//! `submit_transaction_idempotent`.
//!
//! Each poll request and each in-loop `getHealth` is cut at the deadline,
//! each sleep between polls ends at it, and the one retention check that runs
//! after it has its own two-second bound. Every deadline exit finalises the
//! receipt `Ambiguous` and returns `network.rpc_unreachable`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::idempotent_submit::submit_transaction_idempotent;
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The submission timeout every test here runs under.
const TIMEOUT: Duration = Duration::from_secs(1);

/// The bound on the retention check after the deadline.
const FINAL_CHECK_BOUND: Duration = Duration::from_secs(2);

/// The hang every held-open request below uses: far past the deadline and
/// the final-check bound, so a request left to run would overrun both.
const HANG: Duration = Duration::from_secs(10);

/// What a deadline exit may add to its bound: the receipt write and
/// scheduling. Smaller than the one-second overrun of an unclamped
/// two-second poll sleep.
const MARGIN: Duration = Duration::from_millis(500);

/// The ledger the submission is recorded against; [`within_window`] keeps it
/// inside the retention window.
const RECORDED_AT_LEDGER: u32 = 100;

// ── Fixtures ────────────────────────────────────────────────────────────────

/// Answers each call like `inner`, delayed by the call's entry in `delays`;
/// a call past the end takes the last entry.
struct DelayedPerCall<R> {
    inner: R,
    delays: Vec<Duration>,
    calls: AtomicUsize,
}

impl<R> DelayedPerCall<R> {
    fn new(inner: R, delays: &[Duration]) -> Self {
        Self {
            inner,
            delays: delays.to_vec(),
            calls: AtomicUsize::new(0),
        }
    }
}

impl<R: Respond> Respond for DelayedPerCall<R> {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let delay = self
            .delays
            .get(call)
            .or_else(|| self.delays.last())
            .copied()
            .unwrap_or_default();
        self.inner.respond(request).set_delay(delay)
    }
}

/// A `getHealth` result whose retention window covers [`RECORDED_AT_LEDGER`].
fn within_window() -> Value {
    json!({
        "status": "healthy",
        "latestLedger": 200,
        "oldestLedger": 50,
        "ledgerRetentionWindow": 150,
    })
}

fn not_found() -> Value {
    json!({"status": "NOT_FOUND", "latestLedger": 1_002, "oldestLedger": 1})
}

/// Starts a server that answers the reads before the send and the send
/// itself for `envelope`.
async fn serve_through_the_send(envelope: &SignedTestEnvelope) -> MockServer {
    let server = MockServer::start().await;
    for (rpc, result) in [
        ("getNetwork", get_network_result(TESTNET_PASSPHRASE)),
        ("getLedgerEntries", envelope.ledger_entries_result()),
        (
            "sendTransaction",
            json!({
                "hash": envelope.tx_hash_hex(),
                "status": "PENDING",
                "latestLedger": 1_001,
                "latestLedgerCloseTime": "1699999999",
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method": rpc})))
            .respond_with(EchoIdResponder::new(result))
            .mount(&server)
            .await;
    }
    server
}

async fn mount(server: &MockServer, rpc: &str, responder: impl Respond + 'static) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": rpc})))
        .respond_with(responder)
        .mount(server)
        .await;
}

/// Submits `envelope` idempotently under [`TIMEOUT`] and checks that the
/// submission ended within `bound` with an ambiguous outcome whose reason
/// contains `reason`, and a receipt finalised `Ambiguous`.
async fn assert_ambiguous_within(
    envelope: &SignedTestEnvelope,
    server: &MockServer,
    bound: Duration,
    reason: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "retention-deadline").unwrap();
    let client = StellarRpcClient::new(&server.uri()).unwrap();

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        HANG,
        submit_transaction_idempotent(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT,
            TESTNET_PASSPHRASE,
            &store,
            RECORDED_AT_LEDGER,
        ),
    )
    .await
    .expect("the submission must end before the held-open request would");
    let elapsed = started.elapsed();

    assert!(
        elapsed < bound,
        "the submission must end within {bound:?}; elapsed {elapsed:?}"
    );
    match result {
        Err(WalletError::Network(NetworkError::RpcUnreachable { reason: got, .. })) => {
            assert!(
                got.contains(reason),
                "expected a reason with {reason:?}: {got}"
            );
        }
        other => panic!("expected an ambiguous network.rpc_unreachable; got {other:?}"),
    }
    let receipt = store
        .get(&stellar_agent_network::envelope_hash_hex(
            envelope.envelope_xdr(),
        ))
        .unwrap()
        .expect("the winner path writes a receipt");
    assert_eq!(
        receipt.status,
        ReceiptStatus::Ambiguous,
        "a deadline exit finalises Ambiguous"
    );
}

/// The within-window reason of a deadline exit.
fn within_window_reason() -> String {
    format!("not confirmed within {}s", TIMEOUT.as_secs())
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// A poll request the endpoint holds open past the deadline is cut at the
/// deadline; the final retention check answers at once and keeps the
/// within-window outcome.
#[tokio::test]
async fn a_poll_request_held_past_the_deadline_is_cut_at_the_deadline() {
    let envelope = SignedTestEnvelope::for_source([0x31; 32]);
    let server = serve_through_the_send(&envelope).await;
    mount(
        &server,
        "getTransaction",
        DelayedPerCall::new(EchoIdResponder::new(not_found()), &[HANG]),
    )
    .await;
    mount(&server, "getHealth", EchoIdResponder::new(within_window())).await;

    assert_ambiguous_within(
        &envelope,
        &server,
        TIMEOUT + MARGIN,
        &within_window_reason(),
    )
    .await;
    assert_eq!(rpc_request_count(&server, "getTransaction").await, 1);
    assert_eq!(
        rpc_request_count(&server, "getHealth").await,
        1,
        "the cut request is followed by the one final retention check"
    );
}

/// An in-loop `getHealth` the endpoint holds open is cut at the deadline. The
/// final retention check that follows answers at once.
#[tokio::test]
async fn an_in_loop_health_check_held_past_the_deadline_is_cut_at_the_deadline() {
    let envelope = SignedTestEnvelope::for_source([0x32; 32]);
    let server = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", EchoIdResponder::new(not_found())).await;
    mount(
        &server,
        "getHealth",
        DelayedPerCall::new(
            EchoIdResponder::new(within_window()),
            &[HANG, Duration::ZERO],
        ),
    )
    .await;

    assert_ambiguous_within(
        &envelope,
        &server,
        TIMEOUT + MARGIN,
        &within_window_reason(),
    )
    .await;
    assert_eq!(rpc_request_count(&server, "getTransaction").await, 1);
    assert_eq!(rpc_request_count(&server, "getHealth").await, 2);
}

/// The final retention check, the one request past the deadline, is cut at
/// its own two-second bound and keeps the within-window outcome.
#[tokio::test]
async fn the_final_retention_check_is_cut_at_its_bound() {
    let envelope = SignedTestEnvelope::for_source([0x33; 32]);
    let server = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", EchoIdResponder::new(not_found())).await;
    mount(
        &server,
        "getHealth",
        DelayedPerCall::new(
            EchoIdResponder::new(within_window()),
            &[Duration::ZERO, HANG],
        ),
    )
    .await;

    assert_ambiguous_within(
        &envelope,
        &server,
        TIMEOUT + FINAL_CHECK_BOUND + MARGIN,
        &within_window_reason(),
    )
    .await;
    assert_eq!(rpc_request_count(&server, "getTransaction").await, 1);
    assert_eq!(rpc_request_count(&server, "getHealth").await, 2);
}

/// The sleep after a `NOT_FOUND` ends at the deadline rather than a full poll
/// interval later, and no poll request reaches the endpoint after it.
#[tokio::test]
async fn the_sleep_after_a_not_found_ends_at_the_deadline() {
    let envelope = SignedTestEnvelope::for_source([0x34; 32]);
    let server = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", EchoIdResponder::new(not_found())).await;
    mount(&server, "getHealth", EchoIdResponder::new(within_window())).await;

    assert_ambiguous_within(
        &envelope,
        &server,
        TIMEOUT + MARGIN,
        &within_window_reason(),
    )
    .await;
    assert_eq!(
        rpc_request_count(&server, "getTransaction").await,
        1,
        "no poll request reaches the endpoint after the sleep that ended at the deadline"
    );
}

/// The sleep after a transient poll error ends at the deadline rather than a
/// full poll interval later, no poll request reaches the endpoint after it,
/// and the exit reports the transient error without a retention check.
#[tokio::test]
async fn the_sleep_after_a_transient_poll_error_ends_at_the_deadline() {
    let envelope = SignedTestEnvelope::for_source([0x35; 32]);
    let server = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", ResponseTemplate::new(500)).await;
    mount(&server, "getHealth", EchoIdResponder::new(within_window())).await;

    assert_ambiguous_within(
        &envelope,
        &server,
        TIMEOUT + MARGIN,
        "timeout with transient poll error",
    )
    .await;
    assert_eq!(
        rpc_request_count(&server, "getTransaction").await,
        1,
        "no poll request reaches the endpoint after the sleep that ended at the deadline"
    );
    assert_eq!(rpc_request_count(&server, "getHealth").await, 0);
}
