//! The submission deadline bounds the retention-aware confirmation poll of
//! `submit_transaction_idempotent`.
//!
//! Each poll request and each in-loop `getHealth` is cut at the deadline,
//! each sleep between polls ends at it, and the one retention check that runs
//! after it has its own two-second bound. Every deadline exit finalises the
//! receipt `Ambiguous` and returns `network.rpc_unreachable`.
//!
//! Every test runs on a paused Tokio clock held still from its start, so the
//! submission arms its deadline at the instant the call starts. A test moves
//! the clock only after it observes the request state the wait follows and
//! the submission is parked. One tick before the bound it checks that the
//! submission is parked, has not woken, and has not begun the transition.
//! It then reads the transition on the clock at the exact instant the bound
//! ends, from the wake and the event that precede any I/O after it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use stellar_agent_core::error::{NetworkError, WalletError};
use stellar_agent_core::profile::receipt::{ReceiptStatus, ReceiptStore};
use stellar_agent_network::StellarRpcClient;
use stellar_agent_network::idempotent_submit::submit_transaction_idempotent;
use stellar_agent_test_support::signed_envelope::{
    SignedTestEnvelope, TESTNET_PASSPHRASE, get_network_result,
};
use stellar_agent_test_support::timing::{ClockHold, Probe, Stamp, drive_call, wait_until};
use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
use tokio::time::Instant;
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The submission timeout every test here runs under.
const TIMEOUT: Duration = Duration::from_secs(1);

/// The bound on the retention check after the deadline.
const FINAL_CHECK_BOUND: Duration = Duration::from_secs(2);

/// The hang every held-open request below uses: far past the deadline and
/// the final-check bound, so a request left to run would overrun both.
const HANG: Duration = Duration::from_secs(10);

/// The clock step that separates "before the bound ends" from "at it".
const TICK: Duration = Duration::from_millis(1);

/// The start of every warning a deadline exit emits before it writes the
/// receipt.
const EXIT_WARNING: &str = "submit_with_retention_poll: timeout";

/// The start of the debug event a transient poll error emits right before
/// the poll sleeps, in the same task poll that parks in the sleep.
const TRANSIENT_POLL_ERROR: &str = "submit_with_retention_poll: transient getTransaction error";

/// The start of the warning a retention check emits in the task poll its
/// deadline cuts it, before any request follows.
const HEALTH_CUT: &str = "check_retention_window: getHealth did not answer before its deadline";

/// The target of the RPC client's request and answer events. The client
/// emits a request event in the task poll that starts the request, before
/// any I/O, and an answer event in the task poll that reads the answer.
const RPC_CLIENT_TARGET: &str = "jsonrpsee";

/// The start of the RPC client's request event.
const RPC_REQUEST: &str = "request = ";

/// The start of the RPC client's answer event.
const RPC_ANSWER: &str = "response = ";

/// A field only a `getHealth` answer carries.
const HEALTH_ANSWER_FIELD: &str = "\"ledgerRetentionWindow\"";

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

/// The number of requests a [`Counted`] responder has received.
#[derive(Clone, Default)]
struct Arrivals(Arc<AtomicUsize>);

impl Arrivals {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// Answers like `inner` and counts the requests it receives.
struct Counted<R> {
    inner: R,
    arrivals: Arrivals,
}

impl<R: Respond> Respond for Counted<R> {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.arrivals.0.fetch_add(1, Ordering::SeqCst);
        self.inner.respond(request)
    }
}

/// Mounts `responder` for `rpc` on `server` and returns its arrivals.
async fn mount_counted(
    server: &MockServer,
    rpc: &str,
    responder: impl Respond + 'static,
) -> Arrivals {
    let arrivals = Arrivals::default();
    mount(
        server,
        rpc,
        Counted {
            inner: responder,
            arrivals: arrivals.clone(),
        },
    )
    .await;
    arrivals
}

/// The instants at which an event recurred, in order. Clones share one
/// record.
#[derive(Clone, Default)]
struct Marks(Arc<Mutex<Vec<Instant>>>);

impl Marks {
    fn mark(&self) {
        self.0.lock().unwrap().push(Instant::now());
    }

    fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    /// The instant of the event's occurrence `n`, counted from zero.
    fn nth(&self, n: usize) -> Option<Instant> {
        self.0.lock().unwrap().get(n).copied()
    }
}

/// The boundaries the submission reports through its events, on the thread
/// it runs on.
#[derive(Clone, Default)]
struct Signals {
    /// The first warning that starts with [`EXIT_WARNING`].
    exit: Stamp,
    /// The first event that starts with [`TRANSIENT_POLL_ERROR`].
    transient_poll_error: Stamp,
    /// Every warning that starts with [`HEALTH_CUT`].
    health_cuts: Marks,
    /// Every `getHealth` request the RPC client starts.
    health_requests: Marks,
    /// Every `getHealth` answer the RPC client reads.
    health_answers: Marks,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Signals {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{value:?}");
                }
            }
        }
        let mut message = Message(String::new());
        event.record(&mut message);
        if *event.metadata().level() == tracing::Level::WARN && message.0.starts_with(EXIT_WARNING)
        {
            self.exit.mark();
        }
        if message.0.starts_with(TRANSIENT_POLL_ERROR) {
            self.transient_poll_error.mark();
        }
        if *event.metadata().level() == tracing::Level::WARN && message.0.starts_with(HEALTH_CUT) {
            self.health_cuts.mark();
        }
        if event.metadata().target() == RPC_CLIENT_TARGET {
            if message.0.starts_with(RPC_REQUEST) && message.0.contains("\"method\":\"getHealth\"")
            {
                self.health_requests.mark();
            }
            if message.0.starts_with(RPC_ANSWER) && message.0.contains(HEALTH_ANSWER_FIELD) {
                self.health_answers.mark();
            }
        }
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
/// itself for `envelope`, and returns it with the arrivals of the send.
async fn serve_through_the_send(envelope: &SignedTestEnvelope) -> (MockServer, Arrivals) {
    let server = MockServer::start().await;
    for (rpc, result) in [
        ("getNetwork", get_network_result(TESTNET_PASSPHRASE)),
        ("getLedgerEntries", envelope.ledger_entries_result()),
    ] {
        mount(&server, rpc, EchoIdResponder::new(result)).await;
    }
    let send = EchoIdResponder::new(json!({
        "hash": envelope.tx_hash_hex(),
        "status": "PENDING",
        "latestLedger": 1_001,
        "latestLedgerCloseTime": "1699999999",
    }));
    let sent = mount_counted(&server, "sendTransaction", send).await;
    (server, sent)
}

async fn mount(server: &MockServer, rpc: &str, responder: impl Respond + 'static) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method": rpc})))
        .respond_with(responder)
        .mount(server)
        .await;
}

/// Moves the held clock onto `at` and checks that the submission's
/// `transition` begins there and not a tick before.
///
/// The submission must already be in the state the wait follows, with no
/// I/O left for it to read. The barrier is acknowledged by the submission's
/// own polls: it parks, then the clock moves to one tick before `at`, and
/// there it is parked again, has not woken, and has begun neither
/// `transition` nor the deadline exit. After the last tick, its first wake
/// and `transition` both read `at`. `transition` is an event the submission
/// emits in the task poll its timer wakes, before any I/O follows.
async fn transition_at(
    probe: &Probe,
    signals: &Signals,
    at: Instant,
    what: &str,
    transition: impl Fn() -> Option<Instant>,
) {
    wait_until("the submission parks before the clock moves", || {
        probe.parked()
    })
    .await;
    let woken = probe.wakes().len();
    assert_eq!(transition(), None, "{what} began before the clock moved");

    tokio::time::advance(at - TICK - Instant::now()).await;
    // A submission that ended early never parks again; the checks below
    // report its wake.
    wait_until("the submission parks one tick before the bound", || {
        probe.parked() || probe.finished()
    })
    .await;
    let early = probe.wakes().split_off(woken);
    assert!(
        early.is_empty(),
        "the submission woke at {early:?}, before {what} at {at:?}"
    );
    assert_eq!(transition(), None, "{what} began before the bound");
    assert_eq!(
        signals.exit.at(),
        None,
        "the deadline exit began before the bound"
    );

    tokio::time::advance(TICK).await;
    wait_until(what, || transition().is_some()).await;
    assert_eq!(
        probe.wakes().get(woken).copied(),
        Some(at),
        "the submission first wakes at the bound"
    );
    assert_eq!(transition(), Some(at), "{what} begins at the bound");
}

/// Moves the held clock onto `at`, checks there that `transition` begins
/// there and not a tick before, and then that the deadline exit's warning is
/// emitted at that instant.
async fn exit_at(
    probe: &Probe,
    signals: &Signals,
    at: Instant,
    what: &str,
    transition: impl Fn() -> Option<Instant>,
) {
    transition_at(probe, signals, at, what, transition).await;
    wait_until("the deadline exit", || signals.exit.at().is_some()).await;
    assert_eq!(signals.exit.get("the deadline exit"), at);
}

/// Submits `envelope` idempotently under [`TIMEOUT`] on the held clock while
/// `drive` moves that clock, and checks an ambiguous outcome whose reason
/// contains `reason` and a receipt finalised `Ambiguous`.
///
/// `drive` receives the instant the call starts, where the deadline is
/// armed, the submission's signals, and its probe. The exit's warning
/// precedes the receipt write. The joined run is bounded in real time by
/// [`drive_call`].
async fn assert_ambiguous_exit<F, Fut>(
    envelope: &SignedTestEnvelope,
    server: &MockServer,
    reason: &str,
    drive: F,
) where
    F: FnOnce(Instant, Signals, Probe) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use tracing_subscriber::layer::SubscriberExt as _;

    let dir = tempfile::tempdir().unwrap();
    let store = ReceiptStore::open_at(dir.path(), "retention-deadline").unwrap();
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let signals = Signals::default();
    // The test runtime polls the submission on this thread, so a thread-local
    // subscriber sees every event it emits. The inert dispatcher and the
    // rebuild keep every callsite's interest current while it is installed.
    let inert = stellar_agent_test_support::inert_dispatcher();
    let guard =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(signals.clone()));
    tracing::callsite::rebuild_interest_cache();

    let started = Instant::now();
    let result = drive_call(
        submit_transaction_idempotent(
            &client,
            envelope.envelope_xdr(),
            TIMEOUT,
            TESTNET_PASSPHRASE,
            &store,
            RECORDED_AT_LEDGER,
        ),
        |probe| drive(started, signals, probe),
    )
    .await;
    drop(guard);
    drop(inert);

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
#[tokio::test(start_paused = true)]
async fn a_poll_request_held_past_the_deadline_is_cut_at_the_deadline() {
    let _hold = ClockHold::new();
    let envelope = SignedTestEnvelope::for_source([0x31; 32]);
    let (server, sent) = serve_through_the_send(&envelope).await;
    let polls = mount_counted(
        &server,
        "getTransaction",
        DelayedPerCall::new(EchoIdResponder::new(not_found()), &[HANG]),
    )
    .await;
    mount(&server, "getHealth", EchoIdResponder::new(within_window())).await;

    assert_ambiguous_exit(
        &envelope,
        &server,
        &within_window_reason(),
        |started, signals, probe| async move {
            wait_until("the held poll", || sent.count() == 1 && polls.count() == 1).await;
            // The cut of the held poll starts the final retention check.
            exit_at(
                &probe,
                &signals,
                started + TIMEOUT,
                "the final retention check",
                || signals.health_requests.nth(0),
            )
            .await;
        },
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
#[tokio::test(start_paused = true)]
async fn an_in_loop_health_check_held_past_the_deadline_is_cut_at_the_deadline() {
    let _hold = ClockHold::new();
    let envelope = SignedTestEnvelope::for_source([0x32; 32]);
    let (server, _sent) = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", EchoIdResponder::new(not_found())).await;
    let checks = mount_counted(
        &server,
        "getHealth",
        DelayedPerCall::new(
            EchoIdResponder::new(within_window()),
            &[HANG, Duration::ZERO],
        ),
    )
    .await;

    assert_ambiguous_exit(
        &envelope,
        &server,
        &within_window_reason(),
        |started, signals, probe| async move {
            wait_until("the held in-loop check", || checks.count() == 1).await;
            exit_at(
                &probe,
                &signals,
                started + TIMEOUT,
                "the cut of the held in-loop check",
                || signals.health_cuts.nth(0),
            )
            .await;
        },
    )
    .await;
    assert_eq!(rpc_request_count(&server, "getTransaction").await, 1);
    assert_eq!(rpc_request_count(&server, "getHealth").await, 2);
}

/// The final retention check, the one request past the deadline, starts at
/// the deadline, is cut at its own two-second bound, and keeps the
/// within-window outcome.
#[tokio::test(start_paused = true)]
async fn the_final_retention_check_is_cut_at_its_bound() {
    let _hold = ClockHold::new();
    let envelope = SignedTestEnvelope::for_source([0x33; 32]);
    let (server, _sent) = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", EchoIdResponder::new(not_found())).await;
    let checks = mount_counted(
        &server,
        "getHealth",
        DelayedPerCall::new(
            EchoIdResponder::new(within_window()),
            &[Duration::ZERO, HANG],
        ),
    )
    .await;

    assert_ambiguous_exit(
        &envelope,
        &server,
        &within_window_reason(),
        |started, signals, probe| async move {
            // The answer of the in-loop check is read; the poll then sleeps.
            wait_until("the in-loop check's answer", || {
                checks.count() == 1 && signals.health_answers.count() == 1
            })
            .await;
            transition_at(
                &probe,
                &signals,
                started + TIMEOUT,
                "the final retention check",
                || signals.health_requests.nth(1),
            )
            .await;
            wait_until("the final retention check", || checks.count() == 2).await;
            exit_at(
                &probe,
                &signals,
                started + TIMEOUT + FINAL_CHECK_BOUND,
                "the cut of the final retention check",
                || signals.health_cuts.nth(0),
            )
            .await;
        },
    )
    .await;
    assert_eq!(rpc_request_count(&server, "getTransaction").await, 1);
    assert_eq!(rpc_request_count(&server, "getHealth").await, 2);
}

/// The sleep after a `NOT_FOUND` ends at the deadline rather than a full poll
/// interval later, and no poll request reaches the endpoint after it.
#[tokio::test(start_paused = true)]
async fn the_sleep_after_a_not_found_ends_at_the_deadline() {
    let _hold = ClockHold::new();
    let envelope = SignedTestEnvelope::for_source([0x34; 32]);
    let (server, _sent) = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", EchoIdResponder::new(not_found())).await;
    let checks = mount_counted(&server, "getHealth", EchoIdResponder::new(within_window())).await;

    assert_ambiguous_exit(
        &envelope,
        &server,
        &within_window_reason(),
        |started, signals, probe| async move {
            // The in-loop check is the last request before the sleep, which
            // starts once its answer is read.
            wait_until("the in-loop check's answer", || {
                checks.count() == 1 && signals.health_answers.count() == 1
            })
            .await;
            // The end of the sleep starts the final retention check.
            exit_at(
                &probe,
                &signals,
                started + TIMEOUT,
                "the final retention check",
                || signals.health_requests.nth(1),
            )
            .await;
        },
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
#[tokio::test(start_paused = true)]
async fn the_sleep_after_a_transient_poll_error_ends_at_the_deadline() {
    let _hold = ClockHold::new();
    let envelope = SignedTestEnvelope::for_source([0x35; 32]);
    let (server, _sent) = serve_through_the_send(&envelope).await;
    mount(&server, "getTransaction", ResponseTemplate::new(500)).await;
    mount(&server, "getHealth", EchoIdResponder::new(within_window())).await;

    assert_ambiguous_exit(
        &envelope,
        &server,
        "timeout with transient poll error",
        |started, signals, probe| async move {
            wait_until("the transient poll error", || {
                signals.transient_poll_error.at().is_some()
            })
            .await;
            // After a transient error the end of the sleep emits the exit
            // warning with no request before it.
            exit_at(
                &probe,
                &signals,
                started + TIMEOUT,
                "the deadline exit",
                || signals.exit.at(),
            )
            .await;
        },
    )
    .await;
    assert_eq!(
        rpc_request_count(&server, "getTransaction").await,
        1,
        "no poll request reaches the endpoint after the sleep that ended at the deadline"
    );
    assert_eq!(rpc_request_count(&server, "getHealth").await, 0);
}
