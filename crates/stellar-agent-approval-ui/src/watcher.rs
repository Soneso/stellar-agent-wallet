//! Pending-approval watcher: notifies the operator when the queue grows.
//!
//! A 500ms interval task opens the store (never resident), snapshots it, drops
//! it, and diffs the set of genuinely-pending nonces against the previous tick.
//! When the count increases it (a) sends the new total on an mpsc channel the
//! CLI reads to print a one-line notice + optional terminal bell, and (b) fires
//! a best-effort OS toast, rate-limited to at most one per 30 seconds.
//!
//! The library never prints: `print_stdout` / `print_stderr` are denied
//! crate-wide, so all operator-visible text is emitted by the CLI from the mpsc
//! receiver. The toast text is count-only — never a URL, address, amount, or
//! nonce.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use stellar_agent_core::approval::{
    DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF, open_with_retry,
};
use stellar_agent_core::timefmt;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use tokio::task::JoinHandle;

/// Watcher poll interval.
const WATCH_INTERVAL: Duration = Duration::from_millis(500);

/// Minimum real-time spacing between OS toasts, regardless of how many
/// count-increase events occur in the window.
const TOAST_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// Builds the exact `osascript` argv for a macOS toast of `count` pending
/// approvals.
///
/// The count is passed as `argv[1]` to the AppleScript (`item 1 of argv`), never
/// interpolated into the script source, so no operator input reaches the script
/// text. Element `[0]` is the program name.
#[must_use]
#[cfg_attr(
    not(target_os = "macos"),
    allow(
        dead_code,
        reason = "macOS toast builder; unused on other targets' non-test build, exercised by unit tests everywhere"
    )
)]
pub(crate) fn build_osascript_argv(count: usize) -> Vec<String> {
    vec![
        "osascript".to_owned(),
        "-e".to_owned(),
        "on run argv".to_owned(),
        "-e".to_owned(),
        "display notification (item 1 of argv)".to_owned(),
        "-e".to_owned(),
        "end run".to_owned(),
        "--".to_owned(),
        format!("{count} approvals pending"),
    ]
}

/// Builds the exact `notify-send` argv for a Linux toast of `count` pending
/// approvals. Element `[0]` is the program name.
#[must_use]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "Linux toast builder; unused on other targets' non-test build, exercised by unit tests everywhere"
    )
)]
pub(crate) fn build_notify_send_argv(count: usize) -> Vec<String> {
    vec![
        "notify-send".to_owned(),
        "Stellar Agent Wallet".to_owned(),
        format!("{count} approvals pending"),
    ]
}

/// Returns the platform toast argv, or `None` on platforms without a wired
/// notifier.
#[must_use]
fn os_toast_argv(count: usize) -> Option<Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        Some(build_osascript_argv(count))
    }
    #[cfg(target_os = "linux")]
    {
        Some(build_notify_send_argv(count))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = count;
        None
    }
}

/// Fires a best-effort OS toast from `argv`, ignoring any failure.
///
/// Runs on a detached OS thread that reaps the child via `output()`, so the
/// async runtime is never blocked and no zombie accumulates. A missing notifier
/// binary surfaces as a spawn error that is silently ignored.
fn fire_toast(argv: Vec<String>) {
    if argv.is_empty() {
        return;
    }
    std::thread::spawn(move || {
        let program = &argv[0];
        let rest = &argv[1..];
        let _ = std::process::Command::new(program).args(rest).output();
    });
}

/// Counts genuinely-pending entries in a snapshot: kind is not `Rejected`,
/// not expired, not yet attested.
///
/// Only the count is needed for the count-transition check below (never
/// which nonces changed), so this counts directly rather than collecting a
/// set of nonces just to discard them.
fn pending_count(views: &[stellar_agent_core::approval::PendingApprovalView]) -> usize {
    views
        .iter()
        .filter(|v| !v.expired && !v.attested && v.kind_name != REJECTED_KIND_NAME)
        .count()
}

/// `ApprovalKind::kind_name()` value for a rejected tombstone.
const REJECTED_KIND_NAME: &str = "Rejected";

/// Spawns the watcher task. Returns its [`JoinHandle`]; the task runs until
/// `shutdown_rx` resolves.
pub(crate) fn spawn_watcher(
    store_path: PathBuf,
    notify_enabled: bool,
    on_pending_count_changed: UnboundedSender<usize>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(WATCH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut prev: usize = 0;
        let mut last_toast_at: Option<Instant> = None;

        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = interval.tick() => {
                    let store = match open_with_retry(
                        &store_path,
                        DEFAULT_RETRY_ATTEMPTS,
                        DEFAULT_RETRY_BACKOFF,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            // Lock contention or transient I/O: skip this tick,
                            // keep the previous set for the next diff.
                            tracing::debug!(error = %e, "watcher: store open skipped this tick");
                            continue;
                        }
                    };
                    let now_ms = match timefmt::now_unix_ms() {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::debug!(error = %e, "watcher: clock read failed; skip tick");
                            continue;
                        }
                    };
                    let views = store.snapshot(now_ms);
                    drop(store);

                    let new_count = pending_count(&views);
                    if new_count > prev {
                        // Content-free count notice for the CLI to print.
                        let _ = on_pending_count_changed.send(new_count);
                        if notify_enabled && toast_due(last_toast_at) {
                            if let Some(argv) = os_toast_argv(new_count) {
                                fire_toast(argv);
                            }
                            last_toast_at = Some(Instant::now());
                        }
                    }
                    prev = new_count;
                }
            }
        }
    })
}

/// Returns `true` when enough real time has passed since the last toast.
fn toast_due(last_toast_at: Option<Instant>) -> bool {
    match last_toast_at {
        None => true,
        Some(t) => t.elapsed() >= TOAST_MIN_INTERVAL,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only; panics acceptable in unit tests"
    )]
    use super::*;

    /// Returns `true` if `s` contains a substring shaped like a Stellar
    /// G-address (`G` followed by 55 base32 chars).
    fn contains_g_address(s: &str) -> bool {
        let bytes = s.as_bytes();
        for i in 0..bytes.len() {
            if bytes[i] != b'G' {
                continue;
            }
            if i + 56 > bytes.len() {
                continue;
            }
            let tail = &s[i + 1..i + 56];
            if tail
                .chars()
                .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
            {
                return true;
            }
        }
        false
    }

    #[test]
    fn osascript_argv_is_count_only_and_leak_free() {
        let argv = build_osascript_argv(3);
        assert_eq!(argv[0], "osascript");
        assert_eq!(argv.len(), 9);
        assert_eq!(argv.last().unwrap(), "3 approvals pending");
        let joined = argv.join(" ");
        assert!(joined.contains('3'));
        assert!(!joined.contains("http"));
        assert!(!contains_g_address(&joined));
        // The AppleScript source must not interpolate the count directly.
        assert!(argv.contains(&"display notification (item 1 of argv)".to_owned()));
    }

    #[test]
    fn notify_send_argv_is_count_only_and_leak_free() {
        let argv = build_notify_send_argv(7);
        assert_eq!(argv[0], "notify-send");
        assert_eq!(argv.len(), 3);
        assert_eq!(argv.last().unwrap(), "7 approvals pending");
        let joined = argv.join(" ");
        assert!(joined.contains('7'));
        assert!(!joined.contains("http"));
        assert!(!contains_g_address(&joined));
    }

    #[test]
    fn g_address_detector_matches_real_shape() {
        assert!(contains_g_address(
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        ));
        assert!(!contains_g_address("5 approvals pending"));
    }

    #[test]
    fn toast_due_respects_interval() {
        assert!(toast_due(None));
        assert!(!toast_due(Some(Instant::now())));
    }

    // ── spawn_watcher: end-to-end tick lifecycle ────────────────────────────
    //
    // These tests run against the real `WATCH_INTERVAL` (500ms) and real wall
    // time — there is no house precedent for a paused/mocked clock in this
    // workspace's async tests — so each assertion waits generously (multiple
    // interval widths) rather than pinning an exact tick count.

    use std::time::Duration as StdDuration;
    use stellar_agent_core::approval::{
        DEFAULT_TTL_MS, PendingApproval, PendingApprovalStore, process_uid_for_attestation,
    };
    use tempfile::TempDir;

    fn uid() -> String {
        process_uid_for_attestation().expect("uid on test host")
    }

    fn payment_entry() -> PendingApproval {
        PendingApproval::new_payment_pending(
            "b64xdr".to_owned(),
            b"fake-xdr",
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            1_000,
            "XLM".to_owned(),
            None,
            100,
            1,
            uid(),
            DEFAULT_TTL_MS,
        )
        .unwrap()
    }

    fn insert_entry(path: &std::path::Path) -> String {
        let mut store = PendingApprovalStore::open(path.to_path_buf()).unwrap();
        let entry = payment_entry();
        let nonce = entry.approval_nonce.clone();
        store
            .insert(entry, stellar_agent_core::timefmt::now_unix_ms().unwrap())
            .unwrap();
        nonce
    }

    /// A pending-count increase (1, then 2) is reported on the channel; a
    /// subsequent decrease (reject back down to 1) reports nothing further;
    /// a later increase (back to 2) reports again. Shutdown then joins
    /// cleanly.
    #[tokio::test]
    async fn spawn_watcher_reports_increases_and_stays_silent_on_decrease() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = spawn_watcher(path.clone(), false, tx, shutdown_rx);

        insert_entry(&path);
        let first = tokio::time::timeout(StdDuration::from_secs(3), rx.recv())
            .await
            .expect("a count-increase notice must arrive")
            .expect("channel must not close early");
        assert_eq!(first, 1);

        let second_nonce = insert_entry(&path);
        let second = tokio::time::timeout(StdDuration::from_secs(3), rx.recv())
            .await
            .expect("a second count-increase notice must arrive")
            .expect("channel must not close early");
        assert_eq!(second, 2);

        // Reject one entry: the pending count drops back to 1. A decrease
        // must never produce a channel message.
        {
            let mut store = PendingApprovalStore::open(path.clone()).unwrap();
            store
                .reject(
                    &second_nonce,
                    stellar_agent_core::timefmt::now_unix_ms().unwrap(),
                    DEFAULT_TTL_MS,
                )
                .unwrap();
        }
        let silence = tokio::time::timeout(StdDuration::from_millis(1_300), rx.recv()).await;
        assert!(
            silence.is_err(),
            "a count decrease must not send a notice, got: {silence:?}"
        );

        // A later increase (back to 2) reports again — the watcher did not
        // get stuck after the silent tick.
        insert_entry(&path);
        let third = tokio::time::timeout(StdDuration::from_secs(3), rx.recv())
            .await
            .expect("a count-increase notice must arrive after the quiet tick")
            .expect("channel must not close early");
        assert_eq!(third, 2);

        let _ = shutdown_tx.send(());
        tokio::time::timeout(StdDuration::from_secs(3), handle)
            .await
            .expect("watcher task must join within the timeout")
            .expect("watcher task must not panic");
    }

    /// A `WriterLocked` tick is skipped silently (no panic, no notice); once
    /// the lock is released the next tick observes the change normally.
    #[tokio::test]
    async fn spawn_watcher_skips_locked_tick_and_recovers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = spawn_watcher(path.clone(), false, tx, shutdown_rx);

        // Hold the store open across at least one tick.
        let holder_path = path.clone();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let _store = PendingApprovalStore::open(holder_path).unwrap();
            acquired_tx.send(()).unwrap();
            std::thread::sleep(StdDuration::from_millis(700));
        });
        acquired_rx.recv().unwrap();
        holder.join().unwrap();

        // Now that the lock is released, an insert must be observed normally.
        insert_entry(&path);
        let count = tokio::time::timeout(StdDuration::from_secs(3), rx.recv())
            .await
            .expect("watcher must recover after a skipped tick")
            .expect("channel must not close early");
        assert_eq!(count, 1);

        let _ = shutdown_tx.send(());
        tokio::time::timeout(StdDuration::from_secs(3), handle)
            .await
            .expect("watcher task must join within the timeout")
            .expect("watcher task must not panic");
    }

    /// `notify_enabled: true` drives the watcher through the toast-firing
    /// branch (`os_toast_argv` + `fire_toast`) without panicking. The OS
    /// notifier binary itself is best-effort and may be absent in CI; only
    /// the Rust-side branch execution is asserted here, not the subprocess
    /// outcome.
    #[tokio::test]
    async fn spawn_watcher_with_notify_enabled_does_not_panic() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let handle = spawn_watcher(path.clone(), true, tx, shutdown_rx);

        insert_entry(&path);
        let count = tokio::time::timeout(StdDuration::from_secs(3), rx.recv())
            .await
            .expect("a count-increase notice must arrive")
            .expect("channel must not close early");
        assert_eq!(count, 1);

        let _ = shutdown_tx.send(());
        tokio::time::timeout(StdDuration::from_secs(3), handle)
            .await
            .expect("watcher task must join within the timeout")
            .expect("watcher task must not panic");
    }
}
