//! Verified audit-chain reads for tests.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{AuditEntry, AuditWriter, verify_log};

/// Returns every row of the verified audit chain in chain order.
///
/// Holds the shared writer's lock across verification and all file reads,
/// so appends and rotation through that writer cannot change the verified rows.
/// Verification checks the hash chain without a chain-root HMAC key.
///
/// # Panics
///
/// Panics if the writer lock is poisoned, verification fails, a file cannot
/// be read, or a non-empty row cannot be parsed as an [`AuditEntry`].
pub fn verified_audit_entries(audit_writer: &Arc<Mutex<AuditWriter>>) -> Vec<AuditEntry> {
    parse_rows(&verified_audit_lines(audit_writer))
}

/// Returns every non-empty row of the verified audit chain as written to
/// disk, one string per row, in chain order.
///
/// Holds the shared writer's lock across verification and all file reads,
/// so appends and rotation through that writer cannot change the verified rows.
/// The rows are the file contents, not a re-serialization of parsed entries,
/// so an assertion over them also sees JSON fields that [`AuditEntry`] does
/// not model. Verification checks the hash chain without a chain-root HMAC key.
///
/// # Panics
///
/// Panics if the writer lock is poisoned, verification fails, or a file cannot
/// be read.
#[expect(
    clippy::expect_used,
    reason = "a poisoned writer lock fails the calling test"
)]
pub fn verified_audit_lines(audit_writer: &Arc<Mutex<AuditWriter>>) -> Vec<String> {
    let writer = audit_writer.lock().expect("audit writer lock");
    verified_rows_from_path(writer.path())
}

/// Returns every row of the verified audit chain at `log_path` in chain order.
///
/// Use this entry point after the writer is dropped or its process exits.
/// The caller must prevent writes and rotation throughout this call.
/// Verification checks the hash chain without a chain-root HMAC key.
///
/// # Panics
///
/// Panics if verification fails, a file cannot be read, or a non-empty row
/// cannot be parsed as an [`AuditEntry`].
pub fn verified_audit_entries_from_path(log_path: &Path) -> Vec<AuditEntry> {
    parse_rows(&verified_rows_from_path(log_path))
}

/// Returns the rotated archives of the log at `log_path`, newest first.
///
/// The list is the reader's own view of the rotation chain without the active
/// file, so a test finds an archive by the rule the lookups and `audit verify`
/// use rather than by matching file names itself.
///
/// # Panics
///
/// Panics if the audit directory cannot be listed.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "an audit directory that cannot be listed fails the calling test"
)]
pub fn rotated_archives_newest_first(log_path: &Path) -> Vec<PathBuf> {
    let mut files =
        super::reader::collect_files_newest_first(log_path).expect("audit directory must list");
    files.remove(0);
    files
}

/// Breaks the chain link between the first two rows of the newest archive of
/// the log at `log_path`, and leaves every other row as it is.
///
/// The first archived row gets another `request_id`, so the row after it no
/// longer names that row's hash. The active file and the archive's handoff
/// row keep their bytes, so a writer and its tip anchor still accept the log;
/// only a read that verifies the archive's own chain finds the break.
///
/// # Panics
///
/// Panics if the log has no archive, the newest archive holds fewer than two
/// rows, or the archive cannot be read, parsed, or written.
#[expect(
    clippy::expect_used,
    reason = "an archive that cannot be rewritten fails the calling test"
)]
pub fn break_newest_archive_link(log_path: &Path) {
    let archive = rotated_archives_newest_first(log_path)
        .into_iter()
        .next()
        .expect("the log must have an archive");
    let contents = std::fs::read_to_string(&archive).expect("the archive must be readable");
    let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
    let rows = lines.iter().filter(|line| !line.trim().is_empty()).count();
    assert!(rows >= 2, "a following row must check the changed one");
    let first = lines
        .iter_mut()
        .find(|line| !line.trim().is_empty())
        .expect("the archive holds a row");
    let mut row: serde_json::Value =
        serde_json::from_str(first).expect("the archived row must parse");
    let request_id = row["request_id"].as_str().unwrap_or_default().to_owned();
    row["request_id"] = serde_json::Value::String(format!("{request_id}-changed"));
    *first = serde_json::to_string(&row).expect("the changed row must serialize");
    let mut rewritten = lines.join("\n");
    rewritten.push('\n');
    std::fs::write(&archive, rewritten).expect("the archive must be writable");
}

/// Appends `entry` to the active file at `log_path` as a process without the
/// writer would: chained from the file's last entry, or from the hash the file
/// chains from when it holds none, with the entry tag `tag` returns for the new
/// entry's hash. Returns that hash.
///
/// The line is written through a handle of its own, so a writer holding the
/// log keeps its own view of where the file ends.
///
/// # Panics
///
/// Panics if the log cannot be read, its last entry cannot be parsed or
/// hashed, or the line cannot be written.
#[expect(
    clippy::expect_used,
    reason = "a log that cannot be extended fails the calling test"
)]
pub fn append_forged_entry(
    log_path: &Path,
    mut entry: AuditEntry,
    tag: impl FnOnce(&str) -> Option<String>,
) -> String {
    use std::io::Write as _;

    let file = std::fs::File::open(log_path).expect("the active file must open");
    let len = file.metadata().expect("the active file must stat").len();
    let tip = match super::writer::read_last_line_before(&file, len)
        .expect("the active file must be readable")
    {
        Some(line) => {
            let last: AuditEntry =
                serde_json::from_slice(&line).expect("the last entry must parse");
            let body = last
                .canonical_json_body()
                .expect("the last entry must serialize");
            super::chain::compute_entry_hash(&body, &last.previous_entry_hash)
                .expect("the last entry must hash")
        }
        None => {
            super::writer::initial_chain_seed(log_path)
                .expect("the chain seed must read")
                .hash
        }
    };
    entry.previous_entry_hash = tip;
    let body = entry
        .canonical_json_body()
        .expect("the entry must serialize");
    let hash = super::chain::compute_entry_hash(&body, &entry.previous_entry_hash)
        .expect("the entry must hash");
    entry.entry_tag = tag(&hash);
    let mut line = serde_json::to_vec(&entry).expect("the entry must serialize");
    line.push(b'\n');
    std::fs::OpenOptions::new()
        .append(true)
        .open(log_path)
        .expect("the active file must open for append")
        .write_all(&line)
        .expect("the line must be written");
    hash
}

/// The entry tag of the entry whose chain hash is `hash`, under the audit key
/// `key`, as a keyed writer computes it.
///
/// # Panics
///
/// Panics if `hash` is not an entry hash.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "a malformed hash fails the calling test"
)]
pub fn entry_tag_under(key: &[u8; 32], hash: &str) -> String {
    super::chain::compute_entry_tag(&super::chain::derive_entry_tag_key(key), hash)
        .expect("an entry hash must tag")
}

/// Verifies the chain at `log_path`, then reads the non-empty rows of every
/// verified file in verification order.
#[expect(
    clippy::expect_used,
    reason = "a chain that fails verification or cannot be read fails the calling test"
)]
fn verified_rows_from_path(log_path: &Path) -> Vec<String> {
    let verified = verify_log(log_path, None).expect("audit log must verify");
    let mut rows = Vec::new();
    for file in verified.per_file {
        let contents = std::fs::read_to_string(file.path).expect("audit log must be readable");
        rows.extend(
            contents
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned),
        );
    }
    rows
}

/// Parses verified rows into [`AuditEntry`] values, keeping their order.
#[expect(
    clippy::expect_used,
    reason = "a verified row that does not parse fails the calling test"
)]
fn parse_rows(rows: &[String]) -> Vec<AuditEntry> {
    rows.iter()
        .map(|row| serde_json::from_str(row).expect("audit row must parse"))
        .collect()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test setup and assertions panic on failure"
    )]

    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::sync::TryLockError;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::audit_log::rotation::ROTATION_THRESHOLD_BYTES;
    use crate::audit_log::writer::install_rotation_window_retry_observer;
    use crate::audit_log::{EventKind, NewToolInvocation, PolicyDecision};

    /// Upper bound for a step that completes promptly unless the code under
    /// test deadlocks.
    const PROMPT_STEP_BOUND: Duration = Duration::from_secs(10);

    fn append(writer: &Arc<Mutex<AuditWriter>>, request_id: &str) {
        writer
            .lock()
            .unwrap()
            .write_entry(AuditEntry::new_tool_invocation(NewToolInvocation::new(
                "test",
                "stellar:testnet",
                vec![],
                PolicyDecision::Allow,
                request_id,
            )))
            .unwrap();
    }

    /// Opens a writer at `path` whose chain spans one archive and the active
    /// file: a "before" row, padding up to the rotation threshold and the
    /// rotation handoff in the archive, an "after" row in the active file.
    fn rotated_writer(path: &Path) -> Arc<Mutex<AuditWriter>> {
        let writer = Arc::new(Mutex::new(
            AuditWriter::open(path.to_path_buf(), None).unwrap(),
        ));
        append(&writer, "before");
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(&vec![b'\n'; ROTATION_THRESHOLD_BYTES as usize])
            .unwrap();
        append(&writer, "after");
        writer
    }

    #[test]
    fn reads_rotated_rows_in_chain_order_with_and_without_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = rotated_writer(&path);

        let entries = verified_audit_entries(&writer);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].request_id, "before");
        assert!(matches!(
            entries[1].event_kind,
            EventKind::AuditRotationHandoff { .. }
        ));
        assert_eq!(entries[2].request_id, "after");
        drop(writer);
        assert_eq!(
            verified_audit_entries_from_path(&path)
                .iter()
                .map(|entry| &entry.request_id)
                .collect::<Vec<_>>(),
            entries
                .iter()
                .map(|entry| &entry.request_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn reads_an_empty_log() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Arc::new(Mutex::new(
            AuditWriter::open(dir.path().join("audit.jsonl"), None).unwrap(),
        ));
        assert!(verified_audit_entries(&writer).is_empty());
    }

    #[test]
    #[should_panic(expected = "audit log must verify")]
    fn refuses_an_unparseable_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));
        append(&writer, "valid");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"not JSON\n")
            .unwrap();
        verified_audit_entries(&writer);
    }

    #[test]
    #[should_panic(expected = "audit log must verify")]
    fn refuses_a_tampered_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));
        append(&writer, "original");
        append(&writer, "next");
        drop(writer);
        let contents = fs::read_to_string(&path).unwrap();
        fs::write(&path, contents.replace("original", "tampered")).unwrap();
        verified_audit_entries_from_path(&path);
    }

    #[test]
    #[should_panic(expected = "audit log must verify")]
    fn refuses_a_missing_log() {
        let dir = tempfile::tempdir().unwrap();
        verified_audit_entries_from_path(&dir.path().join("missing.jsonl"));
    }

    #[test]
    fn raw_lines_follow_rotation_order_and_parse_to_the_entries() {
        let dir = tempfile::tempdir().unwrap();
        let writer = rotated_writer(&dir.path().join("audit.jsonl"));

        let lines = verified_audit_lines(&writer);
        let entries = verified_audit_entries(&writer);
        assert_eq!(lines.len(), 3);
        let parsed: Vec<AuditEntry> = lines
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            serde_json::to_value(&entries).unwrap()
        );
        assert_eq!(parsed[0].request_id, "before");
        assert!(matches!(
            parsed[1].event_kind,
            EventKind::AuditRotationHandoff { .. }
        ));
        assert_eq!(parsed[2].request_id, "after");
    }

    /// A field the typed entry does not model survives in the raw row, which
    /// is what lets a redaction assertion over raw rows see it.
    #[test]
    fn raw_lines_keep_fields_the_typed_entry_does_not_model() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));
        append(&writer, "only");
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.starts_with('{'));
        fs::write(
            &path,
            contents.replacen('{', r#"{"unmodelled_field":"raw-only-marker","#, 1),
        )
        .unwrap();

        let lines = verified_audit_lines(&writer);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("raw-only-marker"));
        assert_eq!(verified_audit_entries(&writer)[0].request_id, "only");
    }

    #[test]
    #[should_panic(expected = "audit log must verify")]
    fn raw_lines_refuse_a_malformed_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));
        append(&writer, "valid");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"not JSON\n")
            .unwrap();
        verified_audit_lines(&writer);
    }

    #[test]
    #[should_panic(expected = "audit log must verify")]
    fn raw_lines_refuse_a_tampered_row() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));
        append(&writer, "original");
        append(&writer, "next");
        let contents = fs::read_to_string(&path).unwrap();
        fs::write(&path, contents.replace("original", "tampered")).unwrap();
        verified_audit_lines(&writer);
    }

    /// A broken archive link fails verification and leaves the active file
    /// as it was.
    #[test]
    fn a_broken_archive_link_fails_verification_and_keeps_the_active_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = rotated_writer(&path);
        let active = fs::read(&path).unwrap();
        break_newest_archive_link(&path);
        assert_eq!(fs::read(&path).unwrap(), active);
        let archive = rotated_archives_newest_first(&path).remove(0);
        assert!(matches!(
            verify_log(&path, None),
            Err(crate::audit_log::verify::VerifyError::ChainBroken { .. })
        ));
        assert!(
            fs::read_to_string(&archive)
                .unwrap()
                .contains("before-changed")
        );
        append(&writer, "still-appendable");
    }

    /// The writer lock spans verification and every file read: an append
    /// through the shared writer started while the helper verifies completes
    /// only after the helper has read its rows, so the appended row is absent
    /// from the helper's result and present in the chain afterwards.
    ///
    /// The helper is paused inside verification on its own thread: with the
    /// active file moved aside while the writer is alive, verification waits
    /// in the rotation window, and the retry observer blocks there until the
    /// test restores the file. The interleaving therefore does not depend on
    /// thread scheduling.
    #[test]
    fn holds_the_writer_lock_until_the_rows_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let moved_aside = dir.path().join("moved-aside");
        let writer = rotated_writer(&path);
        fs::rename(&path, &moved_aside).unwrap();

        let (paused_tx, paused_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel::<()>();
        let helper_writer = Arc::clone(&writer);
        let helper = thread::spawn(move || {
            let _observer = install_rotation_window_retry_observer(move |attempt| {
                if attempt == 0 {
                    paused_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                }
            });
            verified_audit_entries(&helper_writer)
        });
        paused_rx.recv_timeout(PROMPT_STEP_BOUND).unwrap();
        assert!(
            matches!(writer.try_lock(), Err(TryLockError::WouldBlock)),
            "the helper must hold the writer lock while it verifies"
        );

        let (appended_tx, appended_rx) = mpsc::channel();
        let appender_writer = Arc::clone(&writer);
        let appender = thread::spawn(move || {
            append(&appender_writer, "during");
            appended_tx.send(()).unwrap();
        });
        assert_eq!(
            appended_rx.recv_timeout(Duration::from_millis(200)),
            Err(RecvTimeoutError::Timeout),
            "an append must wait while the helper verifies"
        );

        fs::rename(&moved_aside, &path).unwrap();
        resume_tx.send(()).unwrap();
        let entries = helper.join().unwrap();
        appended_rx.recv_timeout(PROMPT_STEP_BOUND).unwrap();
        appender.join().unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].request_id, "before");
        assert!(matches!(
            entries[1].event_kind,
            EventKind::AuditRotationHandoff { .. }
        ));
        assert_eq!(entries[2].request_id, "after");
        let chain = verified_audit_entries(&writer);
        assert_eq!(chain.len(), 4);
        assert_eq!(chain[3].request_id, "during");
    }
}
