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
//! Under the outbox lock an append first checks the keyring commitment against
//! the complete lines as read, so a committed line that lost its newline or
//! its tail refuses the append with the file unchanged. Only then does it
//! repair a torn tail. A final segment with no terminating newline is an
//! append that never returned `Ok`, so the file is truncated back to just
//! after the last newline and synced. It then appends one line, syncs
//! it, and stores the new count and chain head. Any write or state error
//! truncates the file back to its length before the append and returns the
//! error, so a refused append leaves the file as it found it. If that
//! truncate-back also fails, a complete line can remain for a consent that
//! was refused; it drains as a consent row that did not take effect, which
//! the at-least-once delivery below covers. Truncation is always in place:
//! the writer refuses to open beside a `*.tmp` file in the audit directory.
//!
//! # Drain
//!
//! [`AuditWriter::drain_outbox`](super::writer::AuditWriter::drain_outbox)
//! takes the outbox lock, reads the file, discards a torn final segment,
//! checks the committed prefix, parses every complete line strictly, appends
//! each entry to the log, stores the zero state, and truncates the outbox to
//! zero. A complete line that does not parse refuses the drain with
//! `audit.outbox_unusable` and leaves the file unchanged. A refused append
//! also leaves the file unchanged, and the entries appended before it are
//! appended again by the next drain.
//!
//! # Delivery and its limits
//!
//! Delivery is at least once. A crash between the appends and the truncation
//! repeats those rows on the next drain; a repeated row keeps its
//! `request_id`, which identifies it. The keyring commitment detects missing,
//! changed, or reordered queued rows before parsing or appending any of them.
//! An absent commitment reads as zero. Raw deletion or restore of keyring
//! entries outside the wallet rests on the platform keyring. The commitment
//! does not authenticate who queues a row.
//!
//! The stored value is `{"v":1,"pending":N,"head":"sha256:<64 hex>"}`.
//! The initial head is zero; each next head hashes `stellar-agent-outbox:v1`,
//! the prior head, and the line bytes without the newline, in that order.
//! Rows beyond the committed prefix drain too, preserving interrupted appends.

use super::tip_anchor::{TipAnchorStore, TipAnchorStoreError};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::entry::AuditEntry;
use super::lock::AuditWriterLock;
use super::writer::{WriterError, basename_lossy_path as basename, sidecar_path};

/// Commitment to the complete lines queued in one outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboxState {
    /// Number of committed complete lines.
    pub pending: u64,
    /// SHA-256 chain head over the committed lines, without newlines.
    pub head: [u8; 32],
}

impl OutboxState {
    /// Encodes the versioned keyring value.
    #[must_use]
    pub fn to_keyring_value(&self) -> String {
        format!(
            r#"{{"v":1,"pending":{},"head":"sha256:{}"}}"#,
            self.pending,
            crate::hex::encode(&self.head)
        )
    }

    /// Parses a keyring value, refusing malformed or unsupported states.
    ///
    /// # Errors
    /// Returns a store error when the value is unusable.
    pub fn parse(raw: &str) -> Result<Self, TipAnchorStoreError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Stored {
            v: u8,
            pending: u64,
            head: String,
        }
        let invalid = || TipAnchorStoreError::new("outbox state is unusable");
        let stored: Stored = serde_json::from_str(raw).map_err(|_| invalid())?;
        if stored.v != 1 {
            return Err(invalid());
        }
        let head = super::chain::decode_hash(&stored.head).map_err(|_| invalid())?;
        if stored.pending == 0 && head != [0; 32] {
            return Err(invalid());
        }
        Ok(Self {
            pending: stored.pending,
            head,
        })
    }

    fn push(&mut self, line: &[u8]) {
        let mut hash = Sha256::new();
        hash.update(b"stellar-agent-outbox:v1");
        hash.update(self.head);
        hash.update(line);
        self.head = hash.finalize().into();
        self.pending += 1;
    }

    fn over(lines: &[&[u8]]) -> Self {
        let mut state = Self::default();
        for line in lines {
            state.push(line);
        }
        state
    }
}

/// Counts describing a missing or changed committed prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxLoss {
    /// Number of lines committed in the keyring.
    pub expected_rows: u64,
    /// Number of complete lines found in the outbox.
    pub found_rows: u64,
}

/// The loss, when the first `state.pending` of `lines` do not exist or do not
/// chain to `state.head`.
fn committed_prefix_loss(lines: &[&[u8]], state: &OutboxState) -> Option<OutboxLoss> {
    let committed = usize::try_from(state.pending)
        .ok()
        .and_then(|pending| lines.get(..pending));
    match committed {
        Some(prefix) if OutboxState::over(prefix).head == state.head => None,
        _ => Some(OutboxLoss {
            expected_rows: state.pending,
            found_rows: lines.len() as u64,
        }),
    }
}

fn check_committed_prefix(lines: &[&[u8]], state: &OutboxState) -> Result<(), WriterError> {
    match committed_prefix_loss(lines, state) {
        None => Ok(()),
        Some(loss) => Err(WriterError::OutboxRowsMissing {
            recorded: loss.expected_rows,
            found: loss.found_rows,
        }),
    }
}

fn load_state(store: &dyn TipAnchorStore) -> Result<OutboxState, WriterError> {
    store
        .load_outbox_state()
        .map(Option::unwrap_or_default)
        .map_err(WriterError::TipAnchorStore)
}

/// Checks the outbox's committed prefix under its lock.
///
/// # Errors
/// Returns a writer error on lock contention, unavailable state, unreadable
/// files, or a missing or changed committed prefix.
pub fn check_outbox_commitment(
    log_path: &Path,
    store: &dyn TipAnchorStore,
) -> Result<(), WriterError> {
    let batch = OutboxBatch::read_locked(log_path, store)?;
    check_committed_prefix(&parse_lines(&batch.bytes).lines, &batch.state)
}

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
pub fn outbox_path(log_path: &Path) -> PathBuf {
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
/// Every append takes the outbox lock for its own duration.
#[derive(Debug, Clone)]
pub struct AuditOutbox {
    path: PathBuf,
    lock_path: PathBuf,
    state: Arc<dyn TipAnchorStore>,
}

impl AuditOutbox {
    /// The outbox of the audit log at `log_path`, committed in `state`.
    ///
    /// `state` must be the log's own commitment store: the tip-anchor store
    /// the log's draining writers hold, at the same keyring coordinate. An
    /// append commits to `state` and a drain checks the store of the writer
    /// that drains, so an append committed to any other store reads as a
    /// loss at the next drain.
    #[must_use]
    pub fn for_log(log_path: &Path, state: Arc<dyn TipAnchorStore>) -> Self {
        Self {
            path: outbox_path(log_path),
            lock_path: outbox_lock_path(log_path),
            state,
        }
    }

    /// Path of the outbox file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends `entry` as one line and syncs it, under the outbox lock.
    ///
    /// `Ok` means the line is durable and committed. A refusal on the
    /// commitment leaves the file unchanged; any later error leaves it at the
    /// length it had before the append, after the torn-tail repair. See the
    /// module documentation.
    ///
    /// # Errors
    ///
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::OutboxRowsMissing`] when committed rows are lost or
    ///   changed, a missing file included. The file is neither created nor
    ///   changed.
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read or
    ///   stored.
    /// - [`WriterError::Serialise`] when the entry cannot be serialized.
    /// - [`WriterError::Io`] on any read, write, flush, or sync failure.
    pub fn append(&self, entry: &AuditEntry) -> Result<(), WriterError> {
        self.prepare_append()?.append(entry)
    }

    /// Acquires the outbox lock and loads the state needed for one append.
    pub(crate) fn prepare_append(&self) -> Result<PreparedOutboxAppend<'_>, WriterError> {
        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        let lock = lock_outbox(&self.lock_path)?;
        let state = load_state(self.state.as_ref())?;
        let created = !self.path.try_exists()?;
        if created && state.pending > 0 {
            return Err(WriterError::OutboxRowsMissing {
                recorded: state.pending,
                found: 0,
            });
        }
        let mut file = open_outbox_0600(&self.path)?;
        // The check reads the bytes as they are: the torn-tail repair would
        // cut a committed line that lost its newline, turning a restorable
        // file into a loss.
        let bytes = read_all(&mut file)?;
        let lines = parse_lines(&bytes).lines;
        check_committed_prefix(&lines, &state)?;
        repair_torn_tail(&file, &self.path, &bytes)?;

        Ok(PreparedOutboxAppend {
            outbox: self,
            before: file.metadata()?.len(),
            file,
            committed: OutboxState::over(&lines),
            created,
            _lock: lock,
        })
    }
}

/// One append with the outbox lock and commitment state already acquired.
pub(crate) struct PreparedOutboxAppend<'a> {
    outbox: &'a AuditOutbox,
    file: File,
    committed: OutboxState,
    before: u64,
    created: bool,
    _lock: AuditWriterLock,
}

impl PreparedOutboxAppend<'_> {
    /// Writes one row and commits it while retaining the acquired lock.
    pub(crate) fn append(mut self, entry: &AuditEntry) -> Result<(), WriterError> {
        let mut line = serde_json::to_vec(entry).map_err(WriterError::Serialise)?;
        line.push(b'\n');
        self.committed.push(&line[..line.len() - 1]);
        // The append that created the file also makes the creation durable,
        // so a crash cannot keep the synced line and lose the directory entry.
        let appended = write_line(&mut self.file, &self.outbox.path, &line).and_then(|()| {
            if self.created {
                sync_parent_dir(&self.outbox.path)?;
            }
            self.outbox
                .state
                .store_outbox_state(&self.committed)
                .map_err(WriterError::TipAnchorStore)
        });
        if let Err(error) = appended {
            if let Err(rollback) = truncate_in_place(&self.file, self.before) {
                tracing::error!(
                    outbox = %basename(&self.outbox.path),
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

/// Truncates `file`, whose contents are `bytes`, back to just after its last
/// newline when its final segment has none, and syncs it.
///
/// Such a segment is an append that never returned `Ok`, so nothing relied on
/// it; it is dropped with a `warn`.
fn repair_torn_tail(file: &File, path: &Path, bytes: &[u8]) -> Result<(), WriterError> {
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

/// The raw bytes of an outbox and its commitment, read together under the
/// outbox lock and held under it until the drain either clears the file or
/// drops it unchanged.
pub(crate) struct OutboxBatch {
    _lock: AuditWriterLock,
    path: PathBuf,
    file: Option<File>,
    bytes: Vec<u8>,
    state: OutboxState,
}

impl OutboxBatch {
    /// Takes the outbox lock of the log at `log_path`, then reads the
    /// commitment from `store` and the outbox file as it is.
    ///
    /// A missing file reads as no bytes. Nothing is checked or parsed.
    ///
    /// # Errors
    ///
    /// - [`WriterError::OutboxBusy`] when the outbox lock stays held.
    /// - [`WriterError::TipAnchorStore`] when the commitment cannot be read.
    /// - [`WriterError::Io`] when the file cannot be opened or read for a
    ///   reason other than its absence.
    pub(crate) fn read_locked(
        log_path: &Path,
        store: &dyn TipAnchorStore,
    ) -> Result<Self, WriterError> {
        let lock = lock_outbox(&outbox_lock_path(log_path))?;
        let state = load_state(store)?;
        let path = outbox_path(log_path);
        let mut file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => Some(file),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(WriterError::Io(e)),
        };
        let bytes = file.as_mut().map(read_all).transpose()?.unwrap_or_default();
        Ok(Self {
            _lock: lock,
            path,
            file,
            bytes,
            state,
        })
    }

    /// Reads the outbox under its lock and checks its committed prefix.
    ///
    /// `Ok(None)` means there is no outbox file and nothing is committed, so
    /// there is nothing to drain. A torn final segment is left for
    /// [`Self::parse_entries`] to report and [`Self::clear`] to remove.
    ///
    /// # Errors
    ///
    /// - Every error of [`Self::read_locked`].
    /// - [`WriterError::OutboxRowsMissing`] when the committed prefix is
    ///   missing, changed, or reordered, a missing file under a nonzero
    ///   commitment included. The file is left unchanged.
    pub(crate) fn take(
        log_path: &Path,
        store: &dyn TipAnchorStore,
    ) -> Result<Option<Self>, WriterError> {
        let batch = Self::read_locked(log_path, store)?;
        let lines = parse_lines(&batch.bytes).lines;
        check_committed_prefix(&lines, &batch.state)?;
        if batch.file.is_none() {
            return Ok(None);
        }
        Ok(Some(batch))
    }

    /// Whether the checked file has neither complete lines nor a torn tail.
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The loss of committed rows this batch shows, without changing either
    /// the commitment or the file.
    pub(crate) fn loss(&self) -> Option<OutboxLoss> {
        committed_prefix_loss(&parse_lines(&self.bytes).lines, &self.state)
    }

    /// Parses every complete line, in queue order, before the caller appends
    /// any of them. A torn final segment is discarded with a `warn`.
    ///
    /// # Errors
    ///
    /// [`WriterError::OutboxUnusable`] when a complete line does not parse as
    /// an [`AuditEntry`]. The file is left unchanged.
    pub(crate) fn parse_entries(&self) -> Result<Vec<AuditEntry>, WriterError> {
        let parsed = parse_lines(&self.bytes);
        if parsed.torn_bytes > 0 {
            tracing::warn!(
                outbox = %basename(&self.path),
                torn_bytes = parsed.torn_bytes,
                "audit outbox: discarding a torn final segment left by an append that never \
                 completed"
            );
        }
        parsed
            .lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                serde_json::from_slice::<AuditEntry>(line).map_err(|e| {
                    WriterError::OutboxUnusable {
                        line: index + 1,
                        column: e.column(),
                        reason: parse_failure_class(&e),
                    }
                })
            })
            .collect()
    }

    /// Truncates the outbox to zero and syncs it, then releases the lock.
    ///
    /// # Errors
    ///
    /// [`WriterError::Io`] when the truncation or the sync fails.
    pub(crate) fn clear(self) -> Result<(), WriterError> {
        if let Some(file) = self.file {
            truncate_in_place(&file, 0)?;
        }
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

/// Informational outbox counts and parse warnings, read separately from the
/// locked commitment check.
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
            crate::audit_log::BindingHistory::NotRecorded,
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("queued-1")).unwrap();
        outbox.append(&row("queued-2")).unwrap();
        assert_eq!(inspect_outbox(&path).unwrap().pending, 2);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
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
        let consumed = AuditOutbox::for_log(
            &dir.path().join("consumed").join("audit.jsonl"),
            Arc::new(InMemoryTipAnchorStore::new()),
        );
        let kept = AuditOutbox::for_log(
            &dir.path().join("kept").join("audit.jsonl"),
            Arc::new(InMemoryTipAnchorStore::new()),
        );
        let disarmed = AuditOutbox::for_log(
            &dir.path().join("disarmed").join("audit.jsonl"),
            Arc::new(InMemoryTipAnchorStore::new()),
        );
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
        // An append that never returned: a partial line, no newline.
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(outbox_path(&path), b"{\"ts\":\"2026-").unwrap();

        outbox.append(&row("after-the-tear")).unwrap();
        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(request_ids(&path), vec!["after-the-tear"]);
    }

    #[test]
    fn a_torn_final_line_at_drain_is_discarded_and_the_complete_lines_drain() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("complete-1")).unwrap();
        outbox.append(&row("complete-2")).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"{\"ts\":\"torn").unwrap();
        drop(file);
        assert_eq!(inspect_outbox(&path).unwrap().torn_bytes, 11);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("good")).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"not an audit entry\n").unwrap();
        drop(file);
        let before = outbox_bytes(&path);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
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
            let store = Arc::new(InMemoryTipAnchorStore::new());
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(outbox_path(&path), line.as_bytes()).unwrap();

            let mut writer =
                AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        match OutboxBatch::take(&path, store.as_ref()) {
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
        for id in ["one", "two", "three"] {
            outbox.append(&row(id)).unwrap();
        }
        let before = outbox_bytes(&path);

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        // The outbox lock is not fair, and unbounded contention can outlast
        // `OUTBOX_LOCK_WAIT`. Each round lets a worker wait for at most one append
        // of the other.
        let barrier = std::sync::Barrier::new(2);
        let joined: Vec<_> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..2)
                .map(|t| {
                    let path = &path;
                    let store = &store;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let outbox = AuditOutbox::for_log(path, store.clone());
                        let mut rounds = Vec::with_capacity(10);
                        for i in 0..10 {
                            barrier.wait();
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    outbox
                                        .append(&row(&format!("thread-{t}-{i}")))
                                        .map_err(|error| format!("{error:?}"))
                                }))
                                .unwrap_or_else(|_| Err("panicked".to_owned()));
                            rounds.push(result);
                        }
                        rounds
                    })
                })
                .collect();
            workers.into_iter().map(|worker| worker.join()).collect()
        });
        for (t, worker) in joined.into_iter().enumerate() {
            let rounds = worker.unwrap_or_else(|_| panic!("worker {t} panicked"));
            for (i, result) in rounds.into_iter().enumerate() {
                assert!(result.is_ok(), "worker {t}, round {i}: {result:?}");
            }
        }
        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued-while-closed"))
            .unwrap();
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued"))
            .unwrap();
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
            crate::audit_log::BindingHistory::NotRecorded,
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let key = || Zeroizing::new([0x42_u8; 32]);
        let access = || KeyedAuditAccess::new(key(), store.clone() as Arc<dyn TipAnchorStore>);
        let profile = "outbox-cache-hit";
        let _first = AuditWriterRegistry::get_or_open_keyed(profile, &path, access()).unwrap();
        AuditOutbox::for_log(&path, store.clone())
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
        AuditOutbox::for_log(&path, store.clone())
            .append(&queued)
            .unwrap();

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
            AuditOutbox::for_log(&path, store.clone())
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
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued"))
            .unwrap();

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
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("queued"))
            .unwrap();
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
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("queued")).unwrap();
        let held = AuditWriterLock::acquire(&outbox_lock_path(&path)).unwrap();

        let started = Instant::now();
        let err = outbox.append(&row("refused")).unwrap_err();
        assert!(matches!(err, WriterError::OutboxBusy), "{err:?}");
        assert!(started.elapsed() >= OUTBOX_LOCK_WAIT);
        assert!(err.to_string().starts_with("audit.outbox_busy"), "{err}");

        let mut writer = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        let err = writer.drain_outbox().unwrap_err();
        assert!(matches!(err, WriterError::OutboxBusy), "{err:?}");
        drop(held);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
    }

    fn committed_pair() -> (TempDir, PathBuf, Arc<InMemoryTipAnchorStore>, AuditWriter) {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let writer = open_draining(&path, &store);
        let outbox = AuditOutbox::for_log(&path, store.clone());
        outbox.append(&row("one")).unwrap();
        outbox.append(&row("two")).unwrap();
        (dir, path, store, writer)
    }

    #[test]
    fn append_commits_the_count_and_the_head() {
        let (_dir, path, store, _writer) = committed_pair();
        let state = store.load_outbox_state().unwrap().unwrap();
        assert_eq!(state.pending, 2);
        let mut head = [0; 32];
        for line in outbox_bytes(&path).split_inclusive(|b| *b == b'\n') {
            let mut hash = Sha256::new();
            hash.update(b"stellar-agent-outbox:v1");
            hash.update(head);
            hash.update(&line[..line.len() - 1]);
            head = hash.finalize().into();
        }
        assert_eq!(state.head, head);
    }

    fn assert_changed_queue_refuses(change: impl FnOnce(&Path), found: u64) {
        let (_dir, path, store, mut writer) = committed_pair();
        change(&outbox_path(&path));
        let bytes = fs::read(outbox_path(&path)).ok();
        let log = fs::read(&path).unwrap();
        let state = store.load_outbox_state().unwrap();
        assert!(matches!(writer.drain_outbox(),
            Err(WriterError::OutboxRowsMissing { recorded: 2, found: n }) if n == found));
        assert_eq!(fs::read(outbox_path(&path)).ok(), bytes);
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(store.load_outbox_state().unwrap(), state);
    }

    fn remove_first_line(path: &Path) {
        let bytes = fs::read(path).unwrap();
        let end = bytes.iter().position(|b| *b == b'\n').unwrap() + 1;
        fs::write(path, &bytes[end..]).unwrap();
    }

    #[test]
    fn a_drain_after_a_deleted_line_refuses() {
        assert_changed_queue_refuses(remove_first_line, 1);
    }

    #[test]
    fn a_drain_after_a_truncated_outbox_refuses() {
        assert_changed_queue_refuses(|path| fs::write(path, []).unwrap(), 0);
    }

    #[test]
    fn a_drain_after_a_deleted_outbox_refuses() {
        assert_changed_queue_refuses(|path| fs::remove_file(path).unwrap(), 0);
    }

    #[test]
    fn a_drain_after_a_changed_line_refuses() {
        assert_changed_queue_refuses(
            |path| {
                let bytes = fs::read_to_string(path).unwrap().replace("two", "six");
                fs::write(path, bytes).unwrap();
            },
            2,
        );
    }

    #[test]
    fn a_drain_after_reordered_lines_refuses() {
        assert_changed_queue_refuses(
            |path| {
                let bytes = fs::read_to_string(path).unwrap();
                let mut lines: Vec<_> = bytes.split_inclusive('\n').collect();
                lines.reverse();
                fs::write(path, lines.concat()).unwrap();
            },
            2,
        );
    }

    #[test]
    fn an_append_after_a_deletion_refuses() {
        let (_dir, path, store, _writer) = committed_pair();
        remove_first_line(&outbox_path(&path));
        let bytes = outbox_bytes(&path);
        let state = store.load_outbox_state().unwrap();
        assert!(matches!(
            AuditOutbox::for_log(&path, store.clone()).append(&row("three")),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 1
            })
        ));
        assert_eq!(outbox_bytes(&path), bytes);
        assert_eq!(store.load_outbox_state().unwrap(), state);
    }

    #[test]
    fn a_state_store_failure_truncates_the_line_back() {
        let (_dir, path, store, _writer) = committed_pair();
        let bytes = outbox_bytes(&path);
        let state = store.load_outbox_state().unwrap();
        store.set_outbox_failing(false, true);
        assert!(matches!(
            AuditOutbox::for_log(&path, store.clone()).append(&row("three")),
            Err(WriterError::TipAnchorStore(_))
        ));
        assert_eq!(outbox_bytes(&path), bytes);
        assert_eq!(store.load_outbox_state().unwrap(), state);
    }

    #[test]
    fn a_line_beyond_the_commitment_drains() {
        let (_dir, path, store, mut writer) = committed_pair();
        let outbox = outbox_path(&path);
        let mut line = serde_json::to_vec(&row("uncommitted")).unwrap();
        line.push(b'\n');
        // Sync the bytes without advancing state, as an interrupted append does.
        write_line(&mut open_outbox_0600(&outbox).unwrap(), &outbox, &line).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        assert_eq!(request_ids(&path), ["one", "two", "uncommitted"]);
        assert_eq!(
            store.load_outbox_state().unwrap(),
            Some(OutboxState::default())
        );
    }

    #[test]
    fn a_drain_interrupted_before_its_truncation_redelivers() {
        let (_dir, path, store, mut writer) = committed_pair();
        writer.set_skip_outbox_truncate(true);
        assert_eq!(writer.drain_outbox().unwrap(), 2);
        assert_eq!(
            store.load_outbox_state().unwrap(),
            Some(OutboxState::default())
        );
        drop(writer);
        let _writer = open_draining(&path, &store);
        assert_eq!(request_ids(&path), ["one", "two", "one", "two"]);
        assert!(outbox_bytes(&path).is_empty());
    }

    #[test]
    fn an_outbox_without_a_state_drains() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let mut writer = open_draining(&path, &store);
        let mut line = serde_json::to_vec(&row("upgrade")).unwrap();
        line.push(b'\n');
        fs::write(outbox_path(&path), line).unwrap();
        assert_eq!(store.load_outbox_state().unwrap(), None);
        assert_eq!(writer.drain_outbox().unwrap(), 1);
        assert_eq!(request_ids(&path), ["upgrade"]);
        assert_eq!(
            store.load_outbox_state().unwrap(),
            Some(OutboxState::default())
        );
    }

    #[test]
    fn a_keyed_open_after_a_loss_refuses() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let access = || KeyedAuditAccess::new(Zeroizing::new([0x42; 32]), store.clone());
        let writer = AuditWriter::open(path.clone(), Some(access())).unwrap();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("lost"))
            .unwrap();
        fs::remove_file(outbox_path(&path)).unwrap();
        drop(writer);
        let err = AuditWriter::open(path, Some(access())).unwrap_err();
        assert!(matches!(
            err,
            WriterError::OutboxRowsMissing {
                recorded: 1,
                found: 0
            }
        ));
        let refusal = crate::audit_log::audit_writer_refusal("fixture", &err);
        assert!(matches!(refusal, crate::error::WalletError::Validation(
            crate::error::ValidationError::AuditLogUnusable { ref detail, .. }
        ) if detail.starts_with("audit.outbox_rows_missing")));
    }

    fn open_acknowledging(path: &Path, store: &Arc<InMemoryTipAnchorStore>) -> AuditWriter {
        AuditWriter::open_for_outbox_acknowledgement(
            path.to_path_buf(),
            None,
            Arc::clone(store) as Arc<dyn TipAnchorStore>,
            crate::audit_log::BindingHistory::NotRecorded,
        )
        .unwrap()
    }

    #[test]
    fn acknowledging_without_a_loss_writes_nothing() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let store = Arc::new(InMemoryTipAnchorStore::new());
        open_draining(&path, &store)
            .write_entry(own_row("kept"))
            .unwrap();
        let mut writer = open_acknowledging(&path, &store);
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            writer.acknowledge_outbox_loss("inspection", Default::default()),
            Err(WriterError::OutboxLossNotFound)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn acknowledging_a_loss_records_it_before_the_found_rows() {
        let (_dir, path, store, writer) = committed_pair();
        remove_first_line(&outbox_path(&path));
        drop(writer);
        let mut writer = open_acknowledging(&path, &store);
        assert!(drain_lock_is_held(&path).unwrap());
        let report = writer
            .acknowledge_outbox_loss(
                "queue inspection",
                crate::audit_log::RevokedCounts {
                    approvals: 3,
                    grants: 4,
                },
            )
            .unwrap();
        assert_eq!(
            (report.expected_rows, report.found_rows, report.drained),
            (2, 1, 1)
        );
        let rows = log_rows(&path);
        assert_eq!(rows[0]["kind"], "audit_outbox_loss_acknowledged");
        assert_eq!(rows[0]["expected_rows"], 2);
        assert_eq!(rows[0]["found_rows"], 1);
        assert_eq!(rows[0]["revoked_approvals"], 3);
        assert_eq!(rows[0]["revoked_grants"], 4);
        assert_eq!(rows[1]["request_id"], "two");
        assert_eq!(
            store.load_outbox_state().unwrap(),
            Some(OutboxState::default())
        );
        assert!(outbox_bytes(&path).is_empty());
        drop(writer);
        let _writer = open_draining(&path, &store);
    }

    /// A committed last line that lost its newline is not a torn tail to
    /// repair: the append refuses on the commitment and leaves the file
    /// byte-identical, so restoring the newline restores the queue.
    #[test]
    fn an_append_over_a_committed_line_without_its_newline_refuses_unchanged() {
        let (_dir, path, store, mut writer) = committed_pair();
        let outbox = AuditOutbox::for_log(&path, store.clone());
        let intact = outbox_bytes(&path);
        let cut = &intact[..intact.len() - 1];
        fs::write(outbox_path(&path), cut).unwrap();
        let state = store.load_outbox_state().unwrap();

        assert!(matches!(
            outbox.append(&row("three")),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 1
            })
        ));
        assert_eq!(outbox_bytes(&path), cut, "the outbox is byte-identical");
        assert_eq!(store.load_outbox_state().unwrap(), state);

        fs::write(outbox_path(&path), &intact).unwrap();
        outbox.append(&row("three")).unwrap();
        assert_eq!(writer.drain_outbox().unwrap(), 3);
        assert_eq!(request_ids(&path), ["one", "two", "three"]);
    }

    /// A deleted outbox under a nonzero commitment refuses the append, which
    /// does not create a new file either.
    #[test]
    fn an_append_after_a_deleted_outbox_refuses_without_creating_it() {
        let (_dir, path, store, _writer) = committed_pair();
        fs::remove_file(outbox_path(&path)).unwrap();
        let state = store.load_outbox_state().unwrap();
        assert!(matches!(
            AuditOutbox::for_log(&path, store.clone()).append(&row("three")),
            Err(WriterError::OutboxRowsMissing {
                recorded: 2,
                found: 0
            })
        ));
        assert!(!outbox_path(&path).exists(), "no outbox is created");
        assert_eq!(store.load_outbox_state().unwrap(), state);
    }

    /// An append commits every complete line in the file, a line synced by an
    /// append that stopped before its state write included, so the next drain
    /// finds the prefix it commits to.
    #[test]
    fn an_append_absorbs_an_uncommitted_line_into_the_commitment() {
        let (_dir, path, store, mut writer) = committed_pair();
        let outbox = outbox_path(&path);
        let mut line = serde_json::to_vec(&row("uncommitted")).unwrap();
        line.push(b'\n');
        write_line(&mut open_outbox_0600(&outbox).unwrap(), &outbox, &line).unwrap();
        AuditOutbox::for_log(&path, store.clone())
            .append(&row("four"))
            .unwrap();

        let bytes = outbox_bytes(&path);
        let lines = parse_lines(&bytes).lines;
        assert_eq!(lines.len(), 4);
        assert_eq!(
            store.load_outbox_state().unwrap(),
            Some(OutboxState::over(&lines))
        );
        assert_eq!(writer.drain_outbox().unwrap(), 4);
        assert_eq!(request_ids(&path), ["one", "two", "uncommitted", "four"]);
    }

    /// The state parser accepts exactly the value the store writes: a zero
    /// count carries the zero head, and no field beyond the three it defines.
    #[test]
    fn the_state_parser_refuses_values_it_does_not_define() {
        let zero = format!("sha256:{}", "00".repeat(32));
        let nonzero = format!("sha256:{}", "11".repeat(32));
        let mut state = OutboxState::default();
        state.push(b"line");
        assert_eq!(
            OutboxState::parse(&state.to_keyring_value()).unwrap(),
            state
        );
        assert_eq!(
            OutboxState::parse(&OutboxState::default().to_keyring_value()).unwrap(),
            OutboxState::default()
        );
        for refused in [
            format!(r#"{{"v":1,"pending":0,"head":"{nonzero}"}}"#),
            format!(r#"{{"v":1,"pending":0,"head":"{zero}","extra":0}}"#),
            format!(r#"{{"v":1,"pending":1,"head":"{nonzero}","extra":0}}"#),
            format!(r#"{{"v":2,"pending":1,"head":"{nonzero}"}}"#),
            format!(r#"{{"v":1,"pending":1,"head":"{}"}}"#, "11".repeat(32)),
        ] {
            assert!(OutboxState::parse(&refused).is_err(), "{refused}");
        }
    }

    /// Every remaining line is parsed before the acknowledgement row: an
    /// unusable line refuses with the log, the outbox, and the commitment
    /// unchanged.
    #[test]
    fn an_unusable_remaining_line_refuses_the_acknowledgement_with_nothing_written() {
        let (_dir, path, store, writer) = committed_pair();
        remove_first_line(&outbox_path(&path));
        let mut file = OpenOptions::new()
            .append(true)
            .open(outbox_path(&path))
            .unwrap();
        file.write_all(b"not an audit entry\n").unwrap();
        drop(file);
        drop(writer);
        let outbox = outbox_bytes(&path);
        let log = fs::read(&path).unwrap();
        let state = store.load_outbox_state().unwrap();

        let mut writer = open_acknowledging(&path, &store);
        assert!(matches!(
            writer.acknowledge_outbox_loss("inspection", Default::default()),
            Err(WriterError::OutboxUnusable { line: 2, .. })
        ));
        assert_eq!(fs::read(&path).unwrap(), log, "no acknowledgement row");
        assert_eq!(outbox_bytes(&path), outbox);
        assert_eq!(store.load_outbox_state().unwrap(), state);
    }

    /// Only the acknowledgement writer acknowledges: a repair writer, which
    /// skips the tip-anchor check, and a checked writer refuse before reading
    /// the outbox.
    #[test]
    fn only_an_acknowledgement_writer_acknowledges_a_loss() {
        let (_dir, path, store, writer) = committed_pair();
        remove_first_line(&outbox_path(&path));
        let outbox = outbox_bytes(&path);
        let state = store.load_outbox_state().unwrap();
        let refuses = |writer: &mut AuditWriter| {
            let log = fs::read(&path).unwrap();
            let err = writer
                .acknowledge_outbox_loss("inspection", Default::default())
                .unwrap_err();
            assert!(
                matches!(&err, WriterError::Io(e) if e.kind() == io::ErrorKind::InvalidInput),
                "{err:?}"
            );
            assert_eq!(fs::read(&path).unwrap(), log, "no acknowledgement row");
            assert_eq!(outbox_bytes(&path), outbox);
            assert_eq!(store.load_outbox_state().unwrap(), state);
        };
        let mut checked = writer;
        refuses(&mut checked);
        drop(checked);
        let mut repair = AuditWriter::open_for_reanchor(path.clone(), None, store.clone()).unwrap();
        refuses(&mut repair);
    }
}
