//! The audit outbox: consent rows queued beside the log while a draining
//! writer in another process holds the log's sidecar lock.
//!
//! # Files
//!
//! Three files sit beside `<audit_log_path>`:
//!
//! - `<audit_log_path>.outbox`: JSON lines, one serialized [`AuditEntry`] per
//!   line, mode `0600` on Unix. Each entry is built at the moment of consent
//!   and keeps its own timestamp.
//! - `<audit_log_path>.outbox.lock`: the lock every append and every drain
//!   holds while it touches the outbox.
//! - `<audit_log_path>.drain.lock`: held for its whole life by every draining
//!   writer, so another process can tell a draining writer from one that does
//!   not drain.
//!
//! # Locks
//!
//! The approval store lock and the outbox lock are the two locks callers wait
//! on. They are taken in that order, never the reverse. The outbox lock waits
//! for up to [`OUTBOX_LOCK_WAIT`] in 20 ms steps and then refuses with
//! [`WriterError::OutboxBusy`], whose detail is `audit.outbox_busy`. Every
//! writer open takes the writer's sidecar lock with one `try_lock`; only
//! `stellar-agent approve --id` retries it, within the approval store's retry
//! bound. A draining writer then takes the drain lock with a short bounded
//! retry. Neither lock is waited on indefinitely, so no cycle of waiters can
//! form.
//!
//! # Append
//!
//! Under the outbox lock an append first repairs a torn tail. A final segment
//! with no terminating newline is an append that never returned `Ok`, so the
//! file is truncated back to just after the last newline and synced. It then
//! appends one line and syncs it. Any write, flush, or sync error truncates
//! the file back to its length before the append and returns the error, so a
//! refused append leaves the file as it found it. If that truncate-back also
//! fails, a complete line can remain for a consent that was refused; it
//! drains as a consent row that did not take effect, which the at-least-once
//! delivery below covers. Truncation is always in place: the writer refuses
//! to open beside a `*.tmp` file in the audit directory.
//!
//! # Drain
//!
//! [`AuditWriter::drain_outbox`](super::writer::AuditWriter::drain_outbox)
//! takes the outbox lock, reads the file, discards a torn final segment,
//! parses every complete line strictly, appends each entry to the log, and
//! then truncates the outbox to zero. A complete line that does not parse
//! refuses the drain with `audit.outbox_unusable` and leaves the file
//! unchanged. A refused append also leaves the file unchanged, and the entries
//! appended before it are appended again by the next drain.
//!
//! # Delivery and its limits
//!
//! Delivery is at least once. A crash between the appends and the truncation
//! repeats those rows on the next drain; a repeated row keeps its
//! `request_id`, which identifies it. Queued rows sit outside the tip anchor
//! until they are drained, so a process that can write the audit directory
//! can delete them without the anchor noticing.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::entry::AuditEntry;
use super::lock::AuditWriterLock;
use super::writer::{WriterError, basename_lossy_path as basename, sidecar_path};

/// How long an append or a drain waits for the outbox lock before refusing
/// with [`WriterError::OutboxBusy`].
pub const OUTBOX_LOCK_WAIT: Duration = Duration::from_secs(2);

/// Delay between two attempts on the outbox lock.
pub(crate) const OUTBOX_LOCK_STEP: Duration = Duration::from_millis(20);

/// Number of `try_lock` attempts a draining writer's open makes on the drain
/// lock before it refuses.
///
/// The only other holder of the drain lock besides a draining writer is a
/// one-shot probe, which releases it at once, so a short bound suffices.
pub(crate) const DRAIN_LOCK_ATTEMPTS: u32 = 5;

/// Delay between two attempts on the drain lock.
pub(crate) const DRAIN_LOCK_BACKOFF: Duration = Duration::from_millis(20);

/// Returns `<log_path>.outbox`.
#[must_use]
pub(crate) fn outbox_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".outbox")
}

/// Returns `<log_path>.outbox.lock`.
#[must_use]
pub(crate) fn outbox_lock_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".outbox.lock")
}

/// Returns `<log_path>.drain.lock`.
#[must_use]
pub(crate) fn drain_lock_path(log_path: &Path) -> PathBuf {
    sidecar_path(log_path, ".drain.lock")
}

/// Returns `true` when a draining writer holds the drain lock of the log at
/// `log_path`.
///
/// One `try_lock`, released before this function returns. A lock that could
/// be taken is not held by any draining writer.
///
/// # Errors
///
/// [`WriterError::Io`] when the lock file cannot be opened or locked for a
/// reason other than contention.
pub fn drain_lock_is_held(log_path: &Path) -> Result<bool, WriterError> {
    match AuditWriterLock::acquire(&drain_lock_path(log_path)) {
        Ok(lock) => {
            drop(lock);
            Ok(false)
        }
        Err(WriterError::FileLocked) => Ok(true),
        Err(e) => Err(e),
    }
}

/// Takes the drain lock of the log at `log_path` for a draining writer.
///
/// Bounded: [`DRAIN_LOCK_ATTEMPTS`] attempts, [`DRAIN_LOCK_BACKOFF`] apart.
///
/// # Errors
///
/// [`WriterError::FileLocked`] when every attempt finds the lock held, and
/// [`WriterError::Io`] for any other failure.
pub(crate) fn acquire_drain_lock(log_path: &Path) -> Result<AuditWriterLock, WriterError> {
    let path = drain_lock_path(log_path);
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        match AuditWriterLock::acquire(&path) {
            Err(WriterError::FileLocked) if attempt < DRAIN_LOCK_ATTEMPTS => {
                std::thread::sleep(DRAIN_LOCK_BACKOFF);
            }
            other => return other,
        }
    }
}

/// Takes the outbox lock at `lock_path`, waiting up to [`OUTBOX_LOCK_WAIT`].
///
/// # Errors
///
/// [`WriterError::OutboxBusy`] when the lock stays held for the whole wait,
/// and [`WriterError::Io`] for any other failure.
pub(crate) fn lock_outbox(lock_path: &Path) -> Result<AuditWriterLock, WriterError> {
    let deadline = Instant::now() + OUTBOX_LOCK_WAIT;
    loop {
        match AuditWriterLock::acquire(lock_path) {
            Err(WriterError::FileLocked) => {
                if Instant::now() >= deadline {
                    return Err(WriterError::OutboxBusy);
                }
                std::thread::sleep(OUTBOX_LOCK_STEP);
            }
            other => return other,
        }
    }
}

/// The outbox of one audit log, to which a consent row is appended while a
/// draining writer in another process holds the log.
///
/// Holds paths only; every append takes the outbox lock for its own duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditOutbox {
    path: PathBuf,
    lock_path: PathBuf,
}

impl AuditOutbox {
    /// The outbox of the audit log at `log_path`.
    #[must_use]
    pub fn for_log(log_path: &Path) -> Self {
        Self {
            path: outbox_path(log_path),
            lock_path: outbox_lock_path(log_path),
        }
    }

    /// Path of the outbox file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends `entry` as one line and syncs it, under the outbox lock.
    ///
    /// `Ok` means the line is durable. Any error leaves the file at the length
    /// it had before the append, after the torn-tail repair; see the module
    /// documentation.
    ///
    /// # Errors
    ///
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::Serialise`] when the entry cannot be serialized.
    /// - [`WriterError::Io`] on any read, write, flush, or sync failure.
    pub fn append(&self, entry: &AuditEntry) -> Result<(), WriterError> {
        let mut line = serde_json::to_vec(entry).map_err(WriterError::Serialise)?;
        line.push(b'\n');

        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        let _lock = lock_outbox(&self.lock_path)?;
        let created = !self.path.try_exists()?;
        let mut file = open_outbox_0600(&self.path)?;
        repair_torn_tail(&mut file, &self.path)?;

        let before = file.metadata()?.len();
        // The append that created the file also makes the creation durable,
        // so a crash cannot keep the synced line and lose the directory entry.
        let appended = write_line(&mut file, &self.path, &line).and_then(|()| {
            if created {
                sync_parent_dir(&self.path)?;
            }
            Ok(())
        });
        if let Err(error) = appended {
            if let Err(rollback) = truncate_in_place(&file, before) {
                tracing::error!(
                    outbox = %basename(&self.path),
                    error = %rollback,
                    "audit outbox: a refused append could not be truncated back; a line \
                     for a consent that did not take effect may remain"
                );
            }
            return Err(error);
        }
        Ok(())
    }
}

/// Opens the outbox for reading and writing, creating it with mode `0600` on
/// Unix. Never `O_APPEND`: an append seeks to the end itself, under the lock.
fn open_outbox_0600(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Syncs the directory holding `path`, so the creation of `path` is durable.
fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Truncates `file` back to just after its last newline when its final
/// segment has none, and syncs it.
///
/// Such a segment is an append that never returned `Ok`, so nothing relied on
/// it; it is dropped with a `warn`.
fn repair_torn_tail(file: &mut File, path: &Path) -> Result<(), WriterError> {
    let bytes = read_all(file)?;
    let Some(&last) = bytes.last() else {
        return Ok(());
    };
    if last == b'\n' {
        return Ok(());
    }
    let keep = bytes
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |idx| idx + 1);
    tracing::warn!(
        outbox = %basename(path),
        torn_bytes = bytes.len() - keep,
        "audit outbox: dropping a torn final segment left by an append that never completed"
    );
    truncate_in_place(file, keep as u64)?;
    Ok(())
}

/// Writes `line` at the end of the file, flushes, and syncs it.
fn write_line(file: &mut File, path: &Path, line: &[u8]) -> Result<(), WriterError> {
    file.seek(SeekFrom::End(0))?;
    #[cfg(any(test, feature = "test-helpers"))]
    if let Some(written) = test_seam::take_partial_write(path) {
        let cut = written.min(line.len());
        file.write_all(&line[..cut])?;
        file.flush()?;
        return Err(WriterError::Io(io::Error::other(
            "test fault: partial outbox write",
        )));
    }
    #[cfg(not(any(test, feature = "test-helpers")))]
    let _ = path;
    file.write_all(line)?;
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

/// Truncates `file` to `len` in place and syncs it.
pub(crate) fn truncate_in_place(file: &File, len: u64) -> io::Result<()> {
    file.set_len(len)?;
    file.sync_all()
}

fn read_all(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The parsed contents of an outbox, held under its lock until the drain
/// either clears it or drops it unchanged.
pub(crate) struct OutboxBatch {
    _lock: AuditWriterLock,
    file: File,
    entries: Vec<AuditEntry>,
    torn_bytes: usize,
}

impl OutboxBatch {
    /// Takes the outbox lock of the log at `log_path` and parses every
    /// complete line.
    ///
    /// `Ok(None)` means there is no outbox file, so there is nothing to drain
    /// and no lock is taken. A torn final segment is discarded with a `warn`
    /// and is removed when the batch is cleared.
    ///
    /// # Errors
    ///
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::OutboxUnusable`] when a complete line does not parse
    ///   as an [`AuditEntry`]. The file is left unchanged.
    /// - [`WriterError::Io`] when the file cannot be read, or when whether it
    ///   exists cannot be determined.
    pub(crate) fn take(log_path: &Path) -> Result<Option<Self>, WriterError> {
        let path = outbox_path(log_path);
        if !path.try_exists()? {
            return Ok(None);
        }
        let lock = lock_outbox(&outbox_lock_path(log_path))?;
        let mut file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(WriterError::Io(e)),
        };
        let bytes = read_all(&mut file)?;
        let parsed = parse_lines(&bytes);
        if parsed.torn_bytes > 0 {
            tracing::warn!(
                outbox = %basename(&path),
                torn_bytes = parsed.torn_bytes,
                "audit outbox: discarding a torn final segment left by an append that never \
                 completed"
            );
        }
        let mut entries = Vec::with_capacity(parsed.lines.len());
        for (index, line) in parsed.lines.iter().enumerate() {
            let entry = serde_json::from_slice::<AuditEntry>(line).map_err(|e| {
                WriterError::OutboxUnusable {
                    line: index + 1,
                    column: e.column(),
                    reason: parse_failure_class(&e),
                }
            })?;
            entries.push(entry);
        }
        Ok(Some(Self {
            _lock: lock,
            file,
            entries,
            torn_bytes: parsed.torn_bytes,
        }))
    }

    /// `true` when the outbox holds no complete line and no torn segment, so
    /// there is nothing to append and nothing to truncate.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.torn_bytes == 0
    }

    /// Moves the parsed entries out, in the order they were queued.
    pub(crate) fn take_entries(&mut self) -> Vec<AuditEntry> {
        std::mem::take(&mut self.entries)
    }

    /// Truncates the outbox to zero and syncs it, then releases the lock.
    ///
    /// # Errors
    ///
    /// [`WriterError::Io`] when the truncation or the sync fails.
    pub(crate) fn clear(self) -> Result<(), WriterError> {
        truncate_in_place(&self.file, 0)?;
        Ok(())
    }
}

/// The class of a parse failure, from a closed set that carries none of the
/// parsed input.
///
/// The parser's own message can quote the line, for example an unknown
/// variant's name or a whole string placed in a typed field.
fn parse_failure_class(e: &serde_json::Error) -> &'static str {
    match e.classify() {
        serde_json::error::Category::Data => "JSON that is not an audit entry",
        serde_json::error::Category::Eof => "truncated JSON",
        serde_json::error::Category::Syntax | serde_json::error::Category::Io => "invalid JSON",
    }
}

/// Complete lines and the size of the torn final segment of an outbox.
struct ParsedLines<'a> {
    lines: Vec<&'a [u8]>,
    torn_bytes: usize,
}

fn parse_lines(bytes: &[u8]) -> ParsedLines<'_> {
    let complete_end = bytes
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |idx| idx + 1);
    let (complete, torn) = bytes.split_at(complete_end);
    let lines = complete
        .split_inclusive(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\n").unwrap_or(line))
        .collect();
    ParsedLines {
        lines,
        torn_bytes: torn.len(),
    }
}

/// What `audit verify` reports about the outbox of a log, read without the
/// outbox lock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutboxInspection {
    /// Number of newline-terminated lines: rows queued and not yet drained.
    pub pending: usize,
    /// Size of a final segment with no terminating newline, or zero.
    pub torn_bytes: usize,
    /// One-based numbers of complete lines that do not parse as an
    /// [`AuditEntry`].
    pub unparseable_lines: Vec<usize>,
}

/// Inspects the outbox of the log at `log_path` without taking its lock.
///
/// A missing outbox reports nothing pending. The result describes the file
/// as read and may already be stale when it returns: a drain or an append in
/// another process can run concurrently.
///
/// # Errors
///
/// [`io::Error`] when the outbox exists and cannot be read.
pub fn inspect_outbox(log_path: &Path) -> io::Result<OutboxInspection> {
    let bytes = match fs::read(outbox_path(log_path)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(OutboxInspection::default()),
        Err(e) => return Err(e),
    };
    let parsed = parse_lines(&bytes);
    let unparseable_lines = parsed
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| serde_json::from_slice::<AuditEntry>(line).is_err())
        .map(|(index, _)| index + 1)
        .collect();
    Ok(OutboxInspection {
        pending: parsed.lines.len(),
        torn_bytes: parsed.torn_bytes,
        unparseable_lines,
    })
}

/// Test-only fault seam that makes the next append to one outbox write part of
/// its line and then fail.
///
/// Keyed by the outbox path, so tests running in parallel threads never see
/// or clear one another's fault.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_seam {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static PARTIAL_WRITES: Mutex<Vec<(PathBuf, usize)>> = Mutex::new(Vec::new());

    /// Arms the seam for `outbox_path`: the next append to that outbox writes
    /// `bytes` bytes of its line and returns an I/O error. The arm is consumed
    /// by that append.
    pub fn arm_partial_write(outbox_path: &Path, bytes: usize) {
        if let Ok(mut armed) = PARTIAL_WRITES.lock() {
            armed.retain(|(path, _)| path != outbox_path);
            armed.push((outbox_path.to_path_buf(), bytes));
        }
    }

    /// Disarms the seam for `outbox_path`. Arms on other outboxes stay.
    pub fn disarm(outbox_path: &Path) {
        if let Ok(mut armed) = PARTIAL_WRITES.lock() {
            armed.retain(|(path, _)| path != outbox_path);
        }
    }

    pub(super) fn take_partial_write(path: &Path) -> Option<usize> {
        let mut armed = PARTIAL_WRITES.lock().ok()?;
        let index = armed
            .iter()
            .position(|(armed_path, _)| armed_path == path)?;
        Some(armed.swap_remove(index).1)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use std::sync::Arc;

    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::audit_log::entry::NewToolInvocation;
    use crate::audit_log::schema::PolicyDecision;
    use crate::audit_log::tip_anchor::{InMemoryTipAnchorStore, KeyedAuditAccess, TipAnchorStore};
    use crate::audit_log::writer::{AuditWriter, AuditWriterRegistry};

    /// A consent-shaped row with a fixed request id.
    fn row(request_id: &str) -> AuditEntry {
        AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            "ABCDEFGHIJKLMNOPQRSTUV",
            "cli",
            request_id,
        )
    }

    fn own_row(request_id: &str) -> AuditEntry {
        AuditEntry::new_tool_invocation(NewToolInvocation::new(
            "stellar_pay_commit",
            "stellar:testnet",
            vec![],
            PolicyDecision::Allow,
            request_id.to_owned(),
        ))
    }

    fn log_path(dir: &TempDir) -> PathBuf {
        dir.path().join("audit").join("audit.jsonl")
    }

    /// A draining writer: opened with a tip-anchor store in `Check` mode.
    fn open_draining(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        AuditWriter::open_with_tip_anchor(
            path.to_path_buf(),
            None,
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap()
    }

    /// Every row in the log, as JSON.
    fn log_rows(path: &Path) -> Vec<serde_json::Value> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn request_ids(path: &Path) -> Vec<String> {
        log_rows(path)
            .iter()
            .map(|row| row["request_id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn outbox_bytes(path: &Path) -> Vec<u8> {
        fs::read(outbox_path(path)).unwrap_or_default()
    }

    #[test]
    fn append_and_drain_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let outbox = AuditOutbox::for_log(&path);
        outbox.append(&row("queued-1")).unwrap();
        outbox.append(&row("queued-2")).unwrap();
        assert_eq!(inspect_outbox(&path).unwrap().pending, 2);

        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        assert!(!writer.drains_outbox(), "an unkeyed writer does not drain");
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        assert_eq!(request_ids(&path), vec!["queued-1", "queued-2"]);
        assert!(
            outbox_bytes(&path).is_empty(),
            "the drain empties the outbox"
        );
        assert_eq!(writer.drain_outbox().unwrap(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(outbox_path(&path))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_failing_append_leaves_the_outbox_byte_identical() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let outbox = AuditOutbox::for_log(&path);
        outbox.append(&row("kept")).unwrap();
        let before = outbox_bytes(&path);

        test_seam::arm_partial_write(outbox.path(), 17);
        let err = outbox.append(&row("refused")).unwrap_err();
        test_seam::disarm(outbox.path());
        assert!(matches!(err, WriterError::Io(_)), "{err:?}");
        assert_eq!(
            outbox_bytes(&path),
            before,
            "a refused append truncates back to where it started"
        );
    }

    /// A partial-write fault belongs to one outbox: consuming or disarming
    /// the fault of one outbox leaves another outbox's fault armed.
    #[test]
    fn a_partial_write_fault_is_kept_per_outbox() {
        let dir = TempDir::new().unwrap();
        let consumed = AuditOutbox::for_log(&dir.path().join("consumed").join("audit.jsonl"));
        let kept = AuditOutbox::for_log(&dir.path().join("kept").join("audit.jsonl"));
        let disarmed = AuditOutbox::for_log(&dir.path().join("disarmed").join("audit.jsonl"));
        test_seam::arm_partial_write(consumed.path(), 3);
        test_seam::arm_partial_write(kept.path(), 3);
        test_seam::arm_partial_write(disarmed.path(), 3);

        let first = consumed.append(&row("refused"));
        assert!(
            matches!(first, Err(WriterError::Io(_))),
            "the fault armed for this outbox fires: {first:?}"
        );
        consumed
            .append(&row("accepted"))
            .expect("the fault is consumed by the append it fired on");
        test_seam::disarm(disarmed.path());
        disarmed
            .append(&row("accepted"))
            .expect("a disarmed fault does not fire");

        let other = kept.append(&row("refused"));
        test_seam::disarm(kept.path());
        assert!(
            matches!(other, Err(WriterError::Io(_))),
            "the other outbox's fault stays armed: {other:?}"
        );
    }

    #[test]
    fn a_torn_tail_is_dropped_by_the_next_append_and_only_that_append_drains() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let outbox = AuditOutbox::for_log(&path);
        // An append that never returned: a partial line, no newline.
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(outbox_path(&path), b"{\"ts\":\"2026-").unwrap();

        outbox.append(&row("after-the-tear")).unwrap();
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(request_ids(&path), vec!["after-the-tear"]);
    }

    #[test]
    fn a_torn_final_line_at_drain_is_discarded_and_the_complete_lines_drain() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let outbox = AuditOutbox::for_log(&path);
        outbox.append(&row("complete-1")).unwrap();
        outbox.append(&row("complete-2")).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"{\"ts\":\"torn").unwrap();
        drop(file);
        assert_eq!(inspect_outbox(&path).unwrap().torn_bytes, 11);

        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        assert_eq!(request_ids(&path), vec!["complete-1", "complete-2"]);
        assert!(
            outbox_bytes(&path).is_empty(),
            "the tail goes with the drain"
        );
    }

    #[test]
    fn a_complete_unparseable_line_fails_the_drain_and_leaves_the_outbox_untouched() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let outbox = AuditOutbox::for_log(&path);
        outbox.append(&row("good")).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"not an audit entry\n").unwrap();
        drop(file);
        let before = outbox_bytes(&path);

        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        let err = writer.drain_outbox().unwrap_err();
        assert!(
            matches!(err, WriterError::OutboxUnusable { line: 2, .. }),
            "{err:?}"
        );
        assert!(
            err.to_string().starts_with("audit.outbox_unusable"),
            "{err}"
        );
        assert_eq!(outbox_bytes(&path), before, "the outbox is left as it was");
        assert!(log_rows(&path).is_empty(), "nothing is appended");
        assert_eq!(inspect_outbox(&path).unwrap().unparseable_lines, vec![2]);
    }

    /// The refusal names the line, the column, and the class of the failure,
    /// and none of the line's content: the parser's own message would quote
    /// a planted value back into agent and CLI envelopes.
    #[test]
    fn an_unusable_outbox_line_is_reported_without_its_content() {
        const MARKER: &str = "planted-outbox-marker";
        let entry = serde_json::to_value(row("planted")).unwrap();
        let mut unknown_kind = entry.clone();
        unknown_kind["kind"] = serde_json::json!(MARKER);
        let mut string_in_a_typed_field = entry;
        string_in_a_typed_field["truncated"] = serde_json::json!(MARKER);
        for planted in [unknown_kind, string_in_a_typed_field] {
            let line = format!("{planted}\n");
            assert!(
                serde_json::from_str::<AuditEntry>(&line)
                    .unwrap_err()
                    .to_string()
                    .contains(MARKER),
                "the parser's own message quotes this line: {line}"
            );
            let dir = TempDir::new().unwrap();
            let path = log_path(&dir);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(outbox_path(&path), line.as_bytes()).unwrap();

            let mut writer = AuditWriter::open(path.clone(), None).unwrap();
            let err = writer.drain_outbox().unwrap_err();
            assert!(
                matches!(err, WriterError::OutboxUnusable { line: 1, .. }),
                "{line}: {err:?}"
            );
            let detail = crate::audit_log::writer::audit_log_unusable_detail(&err).unwrap();
            assert!(detail.starts_with("audit.outbox_unusable"), "{detail}");
            for rendered in [err.to_string(), format!("{err:?}"), detail] {
                assert!(!rendered.contains(MARKER), "{line}: {rendered}");
            }
        }
    }

    /// An outbox whose existence cannot be determined refuses the drain with
    /// an I/O error: it is never read as an absent, empty outbox.
    // Unix only: Windows reports a path below a regular file as not found.
    #[cfg(unix)]
    #[test]
    fn an_outbox_whose_existence_cannot_be_read_refuses_the_drain() {
        let dir = TempDir::new().unwrap();
        // A regular file where the audit directory belongs: every path below
        // it fails to stat with "not a directory".
        fs::write(dir.path().join("audit"), b"not a directory").unwrap();
        let path = log_path(&dir);
        match OutboxBatch::take(&path) {
            Err(WriterError::Io(_)) => {}
            Err(other) => panic!("expected an I/O error, got {other:?}"),
            Ok(batch) => panic!(
                "an unreadable outbox read as {}",
                if batch.is_some() { "a batch" } else { "absent" }
            ),
        }
    }

    #[test]
    fn a_refusal_on_the_second_of_three_appends_leaves_the_outbox_byte_identical() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let outbox = AuditOutbox::for_log(&path);
        for id in ["one", "two", "three"] {
            outbox.append(&row(id)).unwrap();
        }
        let before = outbox_bytes(&path);

        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        writer.set_appends_before_fault(Some(1));
        writer.drain_outbox().unwrap_err();
        assert_eq!(
            outbox_bytes(&path),
            before,
            "a partial drain leaves every queued row in place"
        );
        assert_eq!(request_ids(&path), vec!["one"]);

        // The next drain appends all three again: delivery is at least once.
        writer.set_appends_before_fault(None);
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        assert_eq!(request_ids(&path), vec!["one", "one", "two", "three"]);
    }

    #[test]
    fn concurrent_appends_from_two_threads_both_drain() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let threads: Vec<_> = (0..2)
            .map(|t| {
                let path = path.clone();
                std::thread::spawn(move || {
                    let outbox = AuditOutbox::for_log(&path);
                    for i in 0..10 {
                        outbox.append(&row(&format!("thread-{t}-{i}"))).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 20);
        let mut ids = request_ids(&path);
        ids.sort();
        let mut expected: Vec<String> = (0..2)
            .flat_map(|t| (0..10).map(move |i| format!("thread-{t}-{i}")))
            .collect();
        expected.sort();
        assert_eq!(ids, expected);
    }

    #[test]
    fn a_draining_writer_drains_at_open_before_any_append() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        AuditOutbox::for_log(&path)
            .append(&row("queued-while-closed"))
            .unwrap();
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let writer = open_draining(&path, &store);
        assert!(writer.drains_outbox());
        assert_eq!(
            request_ids(&path),
            vec!["queued-while-closed"],
            "the open drained the row before anything was appended"
        );
        assert!(outbox_bytes(&path).is_empty());
        assert!(
            drain_lock_is_held(&path).unwrap(),
            "the writer holds the drain lock"
        );
        drop(writer);
        assert!(
            !drain_lock_is_held(&path).unwrap(),
            "released with the writer"
        );
    }

    #[test]
    fn a_writer_without_an_anchor_store_neither_drains_nor_holds_the_drain_lock() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        AuditOutbox::for_log(&path).append(&row("queued")).unwrap();
        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        assert!(!drain_lock_is_held(&path).unwrap());
        writer.write_entry(own_row("own")).unwrap();
        assert_eq!(request_ids(&path), vec!["own"], "write_entry did not drain");
        assert_eq!(inspect_outbox(&path).unwrap().pending, 1);
    }

    #[test]
    fn an_opener_that_loses_the_sidecar_never_touches_the_drain_lock() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let _holder = AuditWriter::open(path.clone(), None).unwrap();
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let err = AuditWriter::open_with_tip_anchor(
            path.clone(),
            None,
            Arc::clone(&store) as Arc<dyn TipAnchorStore>,
        )
        .unwrap_err();
        assert!(matches!(err, WriterError::FileLocked), "{err:?}");
        assert!(
            !drain_lock_path(&path).exists(),
            "the drain lock is taken only after the sidecar lock"
        );
    }

    #[test]
    fn a_registry_cache_hit_drains_with_no_append_of_its_own() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let key = || Zeroizing::new([0x42_u8; 32]);
        let access = || {
            KeyedAuditAccess::new(
                key(),
                Arc::new(InMemoryTipAnchorStore::new()) as Arc<dyn TipAnchorStore>,
            )
        };
        let profile = "outbox-cache-hit";
        let _first = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap();
        AuditOutbox::for_log(&path)
            .append(&row("queued-after-open"))
            .unwrap();
        let _second = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap();
        assert_eq!(request_ids(&path), vec!["queued-after-open"]);
        assert!(outbox_bytes(&path).is_empty());
    }

    #[test]
    fn drained_rows_precede_the_writers_own_row_and_keep_their_consent_timestamps() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_draining(&path, &store);
        let mut queued = row("consent");
        queued.ts = "2026-01-02T03:04:05.000Z".to_owned();
        AuditOutbox::for_log(&path).append(&queued).unwrap();

        writer.write_entry(own_row("own")).unwrap();
        let rows = log_rows(&path);
        assert_eq!(
            rows.iter()
                .map(|row| row["request_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["consent", "own"]
        );
        assert_eq!(rows[0]["ts"], "2026-01-02T03:04:05.000Z");
    }

    #[test]
    fn a_crash_between_the_appends_and_the_truncate_repeats_the_rows_once() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        {
            let mut writer = open_draining(&path, &store);
            AuditOutbox::for_log(&path)
                .append(&row("repeated"))
                .unwrap();
            writer.set_skip_outbox_truncate(true);
            assert_eq!(writer.drain_outbox().unwrap(), 1);
        }
        let _reopened = open_draining(&path, &store);
        assert_eq!(request_ids(&path), vec!["repeated", "repeated"]);
        assert!(outbox_bytes(&path).is_empty());
    }

    /// A signer-set baseline whose `prev_chain_tip_hash` is the writer's tip
    /// at the moment it is built.
    fn baseline_built_from(writer: &AuditWriter) -> AuditEntry {
        use crate::audit_log::signer_set::{
            BaselineReason, SignerEntryV2, SignerIdentityV2, SignerSetSnapshotV2,
        };

        let snapshot = SignerSetSnapshotV2 {
            signers: vec![SignerEntryV2 {
                id: 0,
                identity: SignerIdentityV2::Ed25519 { pubkey: [0x22; 32] },
            }],
            threshold: None,
        };
        AuditEntry::new_sa_signer_set_baselined_v2(
            1,
            &snapshot,
            1000,
            1_700_000_000_000,
            BaselineReason::first_observation(),
            writer.current_chain_tip(),
            [0x33; 32],
            crate::observability::RedactedStrkey::from_already_redacted("CAAAA...AAAAA"),
            "stellar:testnet",
            "baseline",
        )
    }

    /// Asserts that a baseline row's two predecessor fields name one entry.
    fn assert_predecessors_agree(baseline: &serde_json::Value) {
        assert_eq!(
            baseline["prev_chain_tip_hash"].as_str().unwrap(),
            baseline["previous_entry_hash"]
                .as_str()
                .unwrap()
                .strip_prefix("sha256:")
                .unwrap(),
            "prev_chain_tip_hash names the row this one directly follows: {baseline}"
        );
    }

    /// The rows of the newest rotated archive of the log at `path`.
    fn archive_rows(path: &Path) -> Vec<serde_json::Value> {
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let mut archives: Vec<PathBuf> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|candidate| {
                let file = candidate.file_name().unwrap().to_str().unwrap();
                file.strip_prefix(&format!("{name}."))
                    .is_some_and(|suffix| suffix.starts_with(|c: char| c.is_ascii_digit()))
                    && !file.ends_with(".root_hmac")
            })
            .collect();
        archives.sort();
        archives
            .last()
            .map(|archive| log_rows(archive))
            .unwrap_or_default()
    }

    #[test]
    fn write_built_names_the_drained_row_as_its_predecessor() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_draining(&path, &store);
        writer.write_entry(own_row("first")).unwrap();
        AuditOutbox::for_log(&path).append(&row("queued")).unwrap();

        writer.write_built(baseline_built_from).unwrap();
        let rows = log_rows(&path);
        assert_eq!(
            rows.iter()
                .map(|row| row["request_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["first", "queued", "baseline"],
            "the drain runs before the build"
        );
        assert_predecessors_agree(&rows[2]);
    }

    /// At the rotation boundary: the drained row fills the active file, so the
    /// append rotates. The rotation completes before `build` reads the tip, so
    /// both predecessor fields of the baseline name the rotation's handoff.
    #[test]
    fn write_built_names_its_predecessor_across_a_rotation() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_draining(&path, &store);
        writer.write_entry(own_row("first")).unwrap();
        AuditOutbox::for_log(&path).append(&row("queued")).unwrap();
        // The active file reaches the threshold once the queued row lands.
        let threshold = fs::metadata(&path).unwrap().len() + 1;
        let threshold_guard =
            crate::audit_log::rotation::test_seam::set_rotation_threshold(&path, threshold);
        writer.write_built(baseline_built_from).unwrap();
        drop(threshold_guard);

        let archived = archive_rows(&path);
        assert_eq!(
            archived
                .iter()
                .map(|row| row["kind"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "tool_invocation",
                "approval_attested",
                "audit_rotation_handoff"
            ],
            "the drained row precedes the rotation"
        );
        let rows = log_rows(&path);
        assert_eq!(
            request_ids(&path),
            vec!["baseline"],
            "the baseline opens the new file"
        );
        assert_predecessors_agree(&rows[0]);
    }

    #[test]
    fn an_outbox_lock_held_past_the_wait_is_outbox_busy() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let outbox = AuditOutbox::for_log(&path);
        outbox.append(&row("queued")).unwrap();
        let held = AuditWriterLock::acquire(&outbox_lock_path(&path)).unwrap();

        let started = Instant::now();
        let err = outbox.append(&row("refused")).unwrap_err();
        assert!(matches!(err, WriterError::OutboxBusy), "{err:?}");
        assert!(started.elapsed() >= OUTBOX_LOCK_WAIT);
        assert!(err.to_string().starts_with("audit.outbox_busy"), "{err}");

        let mut writer = AuditWriter::open(path.clone(), None).unwrap();
        let err = writer.drain_outbox().unwrap_err();
        assert!(matches!(err, WriterError::OutboxBusy), "{err:?}");
        drop(held);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
    }
}
