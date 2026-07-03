//! Bounded-retry helper for cross-process [`PendingApprovalStore::open`]
//! contention.
//!
//! [`PendingApprovalStore::open`] holds its exclusive advisory lock for the
//! entire lifetime of the store, so two processes that legitimately need to
//! touch the same profile's store within a short window (an MCP tool
//! persisting a fresh pending entry while the operator runs `approve` or
//! `approve gc`, or two MCP tool calls racing on the same profile) can
//! observe a transient [`ApprovalError::WriterLocked`] even though neither
//! side holds the store for long. [`open_with_retry`] absorbs that window
//! with a short, bounded backoff instead of surfacing the collision to the
//! agent or the operator.

use std::path::Path;
use std::time::Duration;

use super::error::ApprovalError;
use super::store::PendingApprovalStore;

/// Default number of open attempts for [`open_with_retry`].
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 5;

/// Default backoff between open attempts for [`open_with_retry`].
pub const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(20);

/// Opens the pending-approval store at `path`, retrying on
/// [`ApprovalError::WriterLocked`] with a fixed `backoff` between attempts.
///
/// Only lock contention is transient: any other [`ApprovalError`] (I/O,
/// TOML parse, permission, invalid entry) is returned immediately on the
/// first attempt without retrying, since retrying would not change the
/// outcome.
///
/// `attempts` is clamped to at least `1`. The backoff sleep is a plain
/// [`std::thread::sleep`] — this function is synchronous and, at the default
/// `5 x 20ms` settings, blocks its caller for at most 80ms across the four
/// inter-attempt sleeps in the worst case (every attempt but the last
/// observes the lock held). Call sites inside an async tool handler already
/// perform the same class of blocking synchronous file I/O for the store
/// open, insert, and persist calls this function wraps; the bounded retry
/// keeps that same profile rather than introducing a new one.
///
/// # Errors
///
/// Returns [`ApprovalError::WriterLocked`] if every attempt still observes
/// the lock held by another writer. Returns any other [`ApprovalError`]
/// immediately from the first attempt that produces it.
///
/// # Panics
///
/// Never panics.
pub fn open_with_retry(
    path: &Path,
    attempts: u32,
    backoff: Duration,
) -> Result<PendingApprovalStore, ApprovalError> {
    let attempts = attempts.max(1);
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        match PendingApprovalStore::open(path.to_path_buf()) {
            Ok(store) => return Ok(store),
            Err(ApprovalError::WriterLocked) if attempt < attempts => {
                std::thread::sleep(backoff);
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::TempDir;

    #[test]
    fn succeeds_immediately_when_uncontended() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let store = open_with_retry(&path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn succeeds_after_release_within_retry_window() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        // Hold the store open on a background thread, confirm (via a channel,
        // not a guessed sleep) that the holder has actually acquired the lock
        // before this thread starts retrying, then release the holder's lock
        // after a short delay — well within the default retry window (4 x
        // 20ms inter-attempt sleeps = up to 80ms).
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel::<()>();
        let released = Arc::new(AtomicBool::new(false));
        let released_writer = Arc::clone(&released);
        let holder_path = path.clone();
        let handle = std::thread::spawn(move || {
            let _holder = PendingApprovalStore::open(holder_path).unwrap();
            acquired_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(30));
            released_writer.store(true, Ordering::SeqCst);
            // _holder drops here, releasing the lock.
        });

        // Block until the holder thread confirms it holds the lock, rather
        // than guessing a wait duration (which is flaky under system load).
        acquired_rx.recv().unwrap();

        let result = open_with_retry(&path, DEFAULT_RETRY_ATTEMPTS, DEFAULT_RETRY_BACKOFF);
        handle.join().unwrap();

        assert!(
            result.is_ok(),
            "open_with_retry must succeed once the holder releases the lock: {result:?}"
        );
        assert!(
            released.load(Ordering::SeqCst),
            "retry must not have succeeded before the holder released the lock"
        );
    }

    #[test]
    fn exhausted_retries_surface_writer_locked() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");

        // Hold the store open for the entire test — every retry attempt must
        // observe WriterLocked.
        let _holder = PendingApprovalStore::open(path.clone()).unwrap();

        let result = open_with_retry(&path, 3, Duration::from_millis(1));
        assert!(
            matches!(result, Err(ApprovalError::WriterLocked)),
            "expected WriterLocked after exhausting retries, got {result:?}"
        );
    }

    #[test]
    fn zero_attempts_is_clamped_to_one() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("default.toml");
        let store = open_with_retry(&path, 0, Duration::from_millis(1)).unwrap();
        assert!(store.is_empty());
    }
}
