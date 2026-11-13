//! Primitives for tests that assert how long the code under test waits.
//!
//! A timing test proves its bound on the span the code governs: from the
//! instant the code arms the bound to the instant it reports the end.
//!
//! - [`Stamp`] records the first instant a named boundary is reached, as the
//!   Tokio clock reads it. Under a paused clock that instant is exact.
//! - [`ClockHold`] keeps a paused Tokio clock still while the code under test
//!   does real I/O, so the clock moves only through `tokio::time::advance`.
//! - [`wait_until`] waits for observable state without moving the clock.
//! - [`drive_call`] joins the code under test with a driver that moves the
//!   clock, bounds the whole joined run in real time, and lets the driver
//!   observe through a [`Probe`] when the call is parked and when it wakes.

// The `expect` calls in this module are on `std::sync::Mutex::lock()` results
// and on joins of blocking tasks that cannot panic.
#![allow(clippy::expect_used)]

use std::future::Future;
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use tokio::time::Instant;

/// The real time [`wait_until`] waits before it reports a hang.
pub const HANG_LIMIT: Duration = Duration::from_secs(10);

/// The first instant a boundary was reached, shared between the observer
/// that reaches it and the test that reads it.
///
/// The instant is the Tokio clock's, so a test under a paused clock reads
/// the exact virtual instant. Clones share one record.
#[derive(Clone, Debug, Default)]
pub struct Stamp(Arc<Mutex<Option<Instant>>>);

impl Stamp {
    /// Records now as the boundary's instant unless an earlier one is
    /// recorded.
    ///
    /// # Panics
    ///
    /// Panics if a thread panicked while holding the stamp's mutex.
    pub fn mark(&self) {
        self.0
            .lock()
            .expect("stamp mutex poisoned")
            .get_or_insert_with(Instant::now);
    }

    /// The recorded instant, if the boundary was reached.
    ///
    /// # Panics
    ///
    /// Panics if a thread panicked while holding the stamp's mutex.
    #[must_use]
    pub fn at(&self) -> Option<Instant> {
        *self.0.lock().expect("stamp mutex poisoned")
    }

    /// The recorded instant of `boundary`.
    ///
    /// # Panics
    ///
    /// Panics, naming `boundary`, when the boundary was never reached.
    #[must_use]
    pub fn get(&self, boundary: &str) -> Instant {
        let at = self.at();
        assert!(at.is_some(), "{boundary} was never reached");
        at.expect("the boundary was reached")
    }
}

/// Keeps a paused Tokio clock still while it lives.
///
/// A current-thread runtime advances a paused clock on its own whenever it
/// idles, including while it waits on real I/O. A running blocking task stops
/// that, so the hold runs one until it drops; `tokio::time::advance` still
/// moves the clock. Create it inside a current-thread runtime, before the
/// code under test arms a timer.
#[derive(Debug)]
pub struct ClockHold {
    release: Option<mpsc::Sender<()>>,
}

impl ClockHold {
    /// Starts holding the clock of the current runtime.
    ///
    /// # Panics
    ///
    /// Panics outside a Tokio runtime.
    #[must_use]
    pub fn new() -> Self {
        let (release, released) = mpsc::channel::<()>();
        drop(tokio::task::spawn_blocking(move || {
            let _ = released.recv();
        }));
        Self {
            release: Some(release),
        }
    }
}

impl Default for ClockHold {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ClockHold {
    fn drop(&mut self) {
        drop(self.release.take());
    }
}

/// Lets the runtime run its I/O for `real` time without moving a held clock.
///
/// # Panics
///
/// Panics outside a Tokio runtime.
pub async fn let_io_run(real: Duration) {
    tokio::task::spawn_blocking(move || std::thread::sleep(real))
        .await
        .expect("the pause task runs");
}

/// Waits until `ready` holds, letting the runtime run its I/O meanwhile and
/// leaving a held clock where it is.
///
/// # Panics
///
/// Panics, naming `what`, when `ready` does not hold within [`HANG_LIMIT`]
/// of real time. The limit only bounds a hang.
pub async fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let limit = std::time::Instant::now() + HANG_LIMIT;
    while !ready() {
        assert!(
            std::time::Instant::now() < limit,
            "{what} did not happen within {HANG_LIMIT:?}"
        );
        let_io_run(Duration::from_millis(2)).await;
    }
}

/// What a [`drive_call`] driver observes of the call it drives.
///
/// The call is parked when its last poll returned pending and nothing has
/// woken it since. Each wake is recorded with the Tokio instant it happened
/// at, so under a held clock a timer's wake reads the instant the clock was
/// moved onto. Clones share one record.
#[derive(Clone, Debug, Default)]
pub struct Probe(Arc<Mutex<Polls>>);

#[derive(Debug, Default)]
struct Polls {
    parked: bool,
    finished: bool,
    wakes: Vec<Instant>,
}

impl Probe {
    /// Whether the call's last poll returned pending and no wake followed.
    ///
    /// # Panics
    ///
    /// Panics if a thread panicked while holding the probe's mutex.
    #[must_use]
    pub fn parked(&self) -> bool {
        self.0.lock().expect("probe mutex poisoned").parked
    }

    /// Whether the call has completed.
    ///
    /// # Panics
    ///
    /// Panics if a thread panicked while holding the probe's mutex.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.0.lock().expect("probe mutex poisoned").finished
    }

    /// The instant of every wake of the call, in order.
    ///
    /// # Panics
    ///
    /// Panics if a thread panicked while holding the probe's mutex.
    #[must_use]
    pub fn wakes(&self) -> Vec<Instant> {
        self.0.lock().expect("probe mutex poisoned").wakes.clone()
    }

    fn woke(&self) {
        let mut polls = self.0.lock().expect("probe mutex poisoned");
        polls.parked = false;
        polls.wakes.push(Instant::now());
    }

    /// Polls `call` with a waker that records its wakes here. A wake during
    /// the poll leaves the call unparked.
    fn poll<C: Future + ?Sized>(
        &self,
        call: std::pin::Pin<&mut C>,
        cx: &Context<'_>,
    ) -> Poll<C::Output> {
        let woken = self.0.lock().expect("probe mutex poisoned").wakes.len();
        let waker = Waker::from(Arc::new(ProbeWaker {
            probe: self.clone(),
            task: cx.waker().clone(),
        }));
        let poll = call.poll(&mut Context::from_waker(&waker));
        let mut polls = self.0.lock().expect("probe mutex poisoned");
        polls.parked = poll.is_pending() && polls.wakes.len() == woken;
        polls.finished = poll.is_ready();
        poll
    }
}

/// The waker a [`Probe`] polls its call with.
struct ProbeWaker {
    probe: Probe,
    task: Waker,
}

impl Wake for ProbeWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.probe.woke();
        self.task.wake_by_ref();
    }
}

/// Runs `call` to completion beside `drive`, which moves the held clock, and
/// returns the call's output.
///
/// `drive` receives the [`Probe`] of the call. The whole joined run, the
/// call and the drive together, must complete within [`HANG_LIMIT`] of real
/// time, so a deadline the clock never reaches fails the test rather than
/// leaving it pending. The real-time watchdog is a blocking task, which keeps
/// a paused clock still like [`ClockHold`].
///
/// # Panics
///
/// Panics when the joined run does not complete within [`HANG_LIMIT`] of
/// real time, and outside a Tokio runtime.
#[allow(clippy::panic, reason = "a hang of the driven call fails the test")]
pub async fn drive_call<C, D, DF>(call: C, drive: D) -> C::Output
where
    C: Future,
    D: FnOnce(Probe) -> DF,
    DF: Future<Output = ()>,
{
    let probe = Probe::default();
    let mut call = std::pin::pin!(call);
    let watched = {
        let probe = probe.clone();
        std::future::poll_fn(move |cx| probe.poll(call.as_mut(), cx))
    };
    let (cancel, cancelled) = mpsc::channel::<()>();
    // The watchdog ends early once `cancel` drops with this call.
    let watchdog = tokio::task::spawn_blocking(move || {
        matches!(
            cancelled.recv_timeout(HANG_LIMIT),
            Err(mpsc::RecvTimeoutError::Timeout)
        )
    });
    let output = tokio::select! {
        biased;
        (output, ()) = async { tokio::join!(watched, drive(probe)) } => output,
        expired = watchdog => panic!(
            "the driven call did not complete within {HANG_LIMIT:?} of real time \
             (watchdog expired: {expired:?})"
        ),
    };
    drop(cancel);
    output
}
