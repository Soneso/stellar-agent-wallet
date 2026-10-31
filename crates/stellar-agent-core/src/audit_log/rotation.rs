//! Rotation constants and helpers for the audit log.
//!
//! Centralises the rotation policy constants used by [`super::writer::AuditWriter`]
//! and re-exported for external consumers.
//!
//! # Rotation policy
//!
//! - **Threshold:** [`ROTATION_THRESHOLD_BYTES`], 10 MiB.  When the active
//!   log file reaches or exceeds this size, [`super::writer::AuditWriter`]
//!   writes an `AuditRotationHandoff` entry, renames the active file to an
//!   archive with a compact timestamp suffix, and opens a fresh active file.
//! - **Retention:** [`MAX_ROTATED_FILES`], 10 archived copies. Each excess
//!   archive is deleted with its `.root_hmac` sidecar after a durable
//!   `<log>.pruned` marker records the successor's chain seed. The marker
//!   retains the outgoing file's seed so an interrupted deletion still verifies.
//!   The prune runs after the new active file exists and never fails the
//!   rotation. It deletes only archives of one fully validated chain that
//!   ends at the archive just rotated: every archive is a regular file within
//!   the read budget, every entry chains from the one before it, the oldest
//!   archive chains from the seed the marker records for it or, with no
//!   marker, from the zero seed, each later archive chains from its
//!   predecessor's handoff, under a keyed writer every
//!   archive's first entry carries a chain-root tag that verifies under its
//!   key, and the just-rotated archive matches the boundaries the writer holds
//!   in memory. A planted, edited, split, unreadable, or oversized file in
//!   that range therefore stalls pruning until it is removed; a sibling that
//!   sorts after the newest archive is outside the chain, never counted, and
//!   never deleted. The prune trusts the proof it just made, and a concurrent
//!   writer of the audit directory is outside its guarantee. Each archive
//!   holds one rotation handoff, its last entry: a retried rotation renames
//!   under its pending handoff and appends no second one, and no rename
//!   replaces an existing file. The prune also stops with a
//!   warning and keeps the excess archives on a marker that does not parse,
//!   does not authenticate, or names neither boundary, a failed marker write,
//!   or a failed deletion.
//!   Past `ROTATED_FILE_CHAIN_CAP` (21) rotated files, open and verify refuse
//!   with `audit.too_many_rotated_files`.
//!   A keyed writer authenticates the marker with HMAC-SHA256; an unkeyed
//!   writer records a null tag. The marker counts pruned files.
//!
//! # Cross-file hash-chain bridge
//!
//! The last entry in the outgoing log is a
//! `AuditRotationHandoff { next_file_name }` entry.  `next_file_name` holds
//! the **archive filename** that the outgoing log was renamed to (e.g.
//! `audit.jsonl.20260429T123456789`), NOT the name of the new active file.
//! `audit verify` matches this field against the actual basename of the file
//! it reads to detect substitution attacks.
//!
//! The new active file's first entry has `previous_entry_hash` = SHA-256 of
//! that handoff entry's canonical body + its own `previous_entry_hash`.

/// Rotation threshold in bytes (10 MiB).
///
/// When the active audit log file reaches or exceeds this size, the writer
/// rotates: writes a handoff entry, renames the file, and opens a new active
/// log file.
pub const ROTATION_THRESHOLD_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum number of rotated files to retain.
///
/// When the 11th rotation occurs, the oldest rotated file (and its
/// `.root_hmac` sidecar) is deleted to keep the audit directory bounded.
pub const MAX_ROTATED_FILES: usize = 10;

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::chain::{ZERO_BLOCK_HASH, sign_chain_root, verify_chain_root};
use super::entry::AuditEntry;
use super::verify::{SIDECAR_READ_CAP, VerifyError, collect_file_chain, read_small_regular_file};
use super::writer::{hmac_sidecar_path, prune_marker_path};

/// A retained boundary and the hash its first entry chains from.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PruneSeed {
    pub file: String,
    pub initial_prev_hash: String,
}

/// Fixed field order for the authenticated prune-marker payload.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PruneMarkerData {
    pub version: u32,
    pub oldest: PruneSeed,
    pub previous: Option<PruneSeed>,
    pub pruned_files: u64,
}

/// The retention boundary, authenticated separately from each file's root.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PruneMarker {
    #[serde(flatten)]
    pub data: PruneMarkerData,
    pub tag: Option<String>,
}

/// A prune marker that names neither of its boundaries as the oldest retained
/// file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MarkerNamesNoBoundary;

/// The hash the oldest retained file `oldest`, a basename, chains from: the one
/// rule the prune and `verify_log` both read the start of the retained history
/// by, so the two never disagree on it.
///
/// Without a marker nothing was pruned, and the oldest file is the chain's
/// root, which chains from the zero seed. With one, the oldest file is a
/// boundary the marker records, and its recorded seed is the answer. A marker
/// that records no seed for the oldest file describes boundaries other than
/// the history present, so no start is chosen: the prune stops, verify fails,
/// and the operator decides (docs/maintainers/audit-log-recovery.md section
/// 11).
///
/// # Errors
///
/// [`MarkerNamesNoBoundary`] when `marker` names neither boundary as `oldest`.
pub(super) fn oldest_retained_seed<'marker>(
    marker: Option<&'marker PruneMarker>,
    oldest: &str,
) -> Result<&'marker str, MarkerNamesNoBoundary> {
    match marker {
        None => Ok(ZERO_BLOCK_HASH),
        Some(marker) => marker.seed_for(oldest).ok_or(MarkerNamesNoBoundary),
    }
}

impl PruneMarker {
    /// Returns the recorded seed of `file` when it is the marker's `oldest` or
    /// `previous` boundary, and `None` for any other basename.
    pub(super) fn seed_for(&self, file: &str) -> Option<&str> {
        std::iter::once(&self.data.oldest)
            .chain(self.data.previous.as_ref())
            .find(|seed| seed.file == file)
            .map(|seed| seed.initial_prev_hash.as_str())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut bytes = b"stellar-agent-audit-prune:v1".to_vec();
        serde_json::to_writer(&mut bytes, &self.data)?;
        Ok(bytes)
    }

    pub(super) fn verify_tag(&self, key: &[u8; 32]) -> bool {
        match (&self.tag, self.signing_bytes()) {
            (Some(tag), Ok(bytes)) => verify_chain_root(key, &bytes, tag).is_ok(),
            _ => false,
        }
    }

    pub(super) fn write(&mut self, log_path: &Path, key: Option<&[u8; 32]>) -> Result<(), String> {
        self.tag = key
            .map(|key| {
                let bytes = self.signing_bytes().map_err(|e| e.to_string())?;
                sign_chain_root(key, &bytes).map_err(|e| e.to_string())
            })
            .transpose()?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        write_sidecar_atomic(&prune_marker_path(log_path), &bytes)
    }
}

/// Reads the optional marker; size, syntax, and version failures name the
/// sidecar.
///
/// The read stops past [`SIDECAR_READ_CAP`], and a longer file is refused as
/// malformed before any of it is parsed.
pub(super) fn read_prune_marker(log_path: &Path) -> Result<Option<PruneMarker>, VerifyError> {
    let path = prune_marker_path(log_path);
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let malformed = |detail: String| VerifyError::ParseError {
        line: 1,
        detail: format!("{name}: {detail}"),
    };
    let bytes = match read_small_regular_file(&path, SIDECAR_READ_CAP) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return Err(malformed(format!(
                "the marker exceeds {SIDECAR_READ_CAP} bytes"
            )));
        }
        Err(VerifyError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let marker: PruneMarker =
        serde_json::from_slice(&bytes).map_err(|e| malformed(e.to_string()))?;
    if marker.data.version != 1 {
        return Err(malformed("unsupported prune marker version".to_owned()));
    }
    Ok(Some(marker))
}

/// Error re-signing an audit-log chain-root sidecar during audit-key rotation.
///
/// The operation that produced this error is always safe to re-run: because the
/// HMAC over a file's first entry is deterministic, a repeat run re-signs
/// already-updated sidecars to the identical tag and completes the remainder.
#[derive(Debug)]
pub enum SidecarResignError {
    /// The audit-log file chain could not be enumerated.
    Discovery(String),
    /// A specific file's chain-root sidecar could not be re-signed. `file`
    /// names the file so a re-run can be reported against it.
    File {
        /// Basename of the file whose sidecar could not be re-signed.
        file: String,
        /// Underlying cause.
        detail: String,
    },
}

impl std::fmt::Display for SidecarResignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discovery(detail) => {
                write!(f, "audit sidecar re-sign: file discovery failed: {detail}")
            }
            Self::File { file, detail } => write!(
                f,
                "audit sidecar re-sign failed for '{file}': {detail}; \
                 re-run rotate-audit-key to converge"
            ),
        }
    }
}

impl std::error::Error for SidecarResignError {}

/// Re-signs every chain-root HMAC sidecar in the audit-log file chain rooted at
/// `log_path` with `new_key`.
///
/// Each file's `.root_hmac` sidecar is the HMAC over that file's FIRST entry's
/// canonical body — the exact bytes [`sign_chain_root`] signs when the writer
/// creates the file. Each sidecar is replaced atomically via a sibling temp
/// file plus rename. The file chain is enumerated with the same
/// `collect_file_chain` discovery `verify_log` uses; a referenced-but-missing
/// rotated file is skipped (it is a chain gap `verify_log` reports separately).
///
/// # Invariant (rotate-audit-key ordering)
///
/// The chain-root sidecar's security property is that an attacker who
/// wholesale-replaces a file cannot forge the root tag without the CURRENT key.
/// This primitive MUST run AFTER the new key is persisted to the keyring.
/// Re-signing before the new key is persisted is forbidden: a crash between
/// signing and persistence would leave sidecars signed by a key that exists
/// nowhere, permanently unverifiable. Under the required order, a crash after
/// persistence but before (or during) re-signing is recoverable — re-running
/// rotate-audit-key re-signs with the already-persisted key and converges.
///
/// `rotate-audit-key` runs in this order: it checks the log's entry tags
/// under the old key, requires the anchor to cover the writer's last row,
/// which carries a tag under that key, persists the new key, switches the
/// held writer to it (which appends `audit_entry_tags_rekeyed { cause:
/// rotation }` once tags are in force), appends the key-write row,
/// reconciles the anchor, and runs this primitive LAST, so a row that
/// happens to open a new file has that file's chain root brought onto the
/// new key by the same pass. No log file is rewritten: entry tags written
/// under the old key stay, and the rekey row's own tag, under the new key,
/// starts the run the new key checks. A crash after persistence and before
/// the rekey row leaves entries tagged under the old key past the newest
/// keyed start, all of them inside the anchored prefix; the next keyed open
/// appends `audit_entry_tags_rekeyed { cause: open_repair }` for them.
///
/// The optional `<log>.pruned` marker is also re-signed under `new_key`.
/// Returns the number of sidecars re-signed, including that marker.
///
/// # Errors
///
/// [`SidecarResignError`] naming the file whose sidecar could not be re-signed.
/// The operation is safe to re-run.
pub fn resign_chain_root_sidecars(
    log_path: &Path,
    new_key: &[u8; 32],
) -> Result<usize, SidecarResignError> {
    let chain =
        collect_file_chain(log_path).map_err(|e| SidecarResignError::Discovery(e.to_string()))?;
    let mut resigned = 0usize;
    for file in chain {
        if !file.exists() {
            continue;
        }
        let file_name = file
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_owned();
        let first_entry = read_first_entry(&file).map_err(|detail| SidecarResignError::File {
            file: file_name.clone(),
            detail,
        })?;
        let body = first_entry
            .canonical_json_body()
            .map_err(|e| SidecarResignError::File {
                file: file_name.clone(),
                detail: format!("canonical body: {e}"),
            })?;
        let tag = sign_chain_root(new_key, &body).map_err(|e| SidecarResignError::File {
            file: file_name.clone(),
            detail: format!("HMAC sign: {e}"),
        })?;
        write_sidecar_atomic(&hmac_sidecar_path(&file), tag.as_bytes()).map_err(|detail| {
            SidecarResignError::File {
                file: file_name.clone(),
                detail,
            }
        })?;
        resigned += 1;
    }
    let marker_name = prune_marker_path(log_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    if let Some(mut marker) = read_prune_marker(log_path).map_err(|e| SidecarResignError::File {
        file: marker_name.clone(),
        detail: e.to_string(),
    })? {
        marker
            .write(log_path, Some(new_key))
            .map_err(|detail| SidecarResignError::File {
                file: marker_name,
                detail,
            })?;
        resigned += 1;
    }
    Ok(resigned)
}

/// Reads and parses the first entry of an audit-log file.
fn read_first_entry(file: &Path) -> Result<AuditEntry, String> {
    let content = fs::read_to_string(file).map_err(|e| format!("read: {e}"))?;
    let first_line = content
        .lines()
        .next()
        .ok_or_else(|| "log file is empty".to_owned())?;
    serde_json::from_str::<AuditEntry>(first_line).map_err(|e| format!("parse first entry: {e}"))
}

/// Atomically writes `bytes` to the sidecar via a sibling temp file plus rename,
/// mirroring the writer's `0o600` + `sync_data` durability discipline.
///
/// A stale entry at the temp path is unlinked, never followed, and the temp
/// file is then created exclusively. A symlink planted there can therefore
/// neither redirect the write nor survive to the rename; one recreated in
/// between makes the exclusive create fail.
pub(super) fn write_sidecar_atomic(sidecar: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut tmp = sidecar.to_path_buf();
    let name = tmp
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "sidecar path has no file name".to_owned())?
        .to_owned();
    tmp.set_file_name(format!("{name}.tmp"));
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("remove stale temp sidecar: {e}")),
    }
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("open temp sidecar: {e}"))?
        };
        #[cfg(not(unix))]
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| format!("open temp sidecar: {e}"))?;
        f.write_all(bytes)
            .map_err(|e| format!("write temp sidecar: {e}"))?;
        f.write_all(b"\n")
            .map_err(|e| format!("write temp sidecar newline: {e}"))?;
        f.sync_data()
            .map_err(|e| format!("sync temp sidecar: {e}"))?;
    }
    fs::rename(&tmp, sidecar).map_err(|e| format!("rename temp sidecar: {e}"))?;
    // Sync the parent directory so the rename itself is durable; without it a
    // crash can lose the replacement on some filesystems. A lost rename is
    // recoverable (re-run converges) — this narrows the window.
    #[cfg(unix)]
    if let Some(parent) = sidecar.parent() {
        fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("sync sidecar directory: {e}"))?;
    }
    Ok(())
}

/// Test-only seam that lowers the rotation threshold for one log path, so a
/// test reaches a rotation without writing 10 MiB.
///
/// Keyed by the active log path, so tests running in parallel threads never
/// see one another's threshold.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_seam {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    static THRESHOLDS: Mutex<Vec<(PathBuf, u64)>> = Mutex::new(Vec::new());

    /// Restores the default threshold for its log when dropped, also when the
    /// test holding it panics.
    #[derive(Debug)]
    #[must_use = "the threshold is restored when the guard is dropped"]
    pub struct RotationThresholdGuard {
        log_path: PathBuf,
    }

    impl Drop for RotationThresholdGuard {
        fn drop(&mut self) {
            if let Ok(mut thresholds) = THRESHOLDS.lock() {
                thresholds.retain(|(path, _)| path != &self.log_path);
            }
        }
    }

    /// Makes the writer of the log at `log_path` rotate once the active file
    /// reaches `bytes`, in place of
    /// [`ROTATION_THRESHOLD_BYTES`](super::ROTATION_THRESHOLD_BYTES), until
    /// the returned guard is dropped.
    pub fn set_rotation_threshold(log_path: &Path, bytes: u64) -> RotationThresholdGuard {
        if let Ok(mut thresholds) = THRESHOLDS.lock() {
            thresholds.retain(|(path, _)| path != log_path);
            thresholds.push((log_path.to_path_buf(), bytes));
        }
        RotationThresholdGuard {
            log_path: log_path.to_path_buf(),
        }
    }

    pub(crate) fn rotation_threshold_for(log_path: &Path) -> Option<u64> {
        let thresholds = THRESHOLDS.lock().ok()?;
        thresholds
            .iter()
            .find(|(path, _)| path == log_path)
            .map(|(_, bytes)| *bytes)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test-only"
    )]

    use std::fs;

    use tempfile::TempDir;
    use zeroize::Zeroizing;

    use super::*;
    use crate::audit_log::entry::{AuditEntry, NewToolInvocation};
    use crate::audit_log::schema::PolicyDecision;
    use crate::audit_log::verify::verify_log;
    use crate::audit_log::writer::AuditWriter;

    fn sample_entry(tool: &str) -> AuditEntry {
        AuditEntry::new_tool_invocation(NewToolInvocation::new(
            tool.to_owned(),
            "stellar:testnet",
            vec![],
            PolicyDecision::Allow,
            uuid::Uuid::new_v4().to_string(),
        ))
    }

    /// Builds a 2-file audit log (one `AuditRotationHandoff` boundary) whose
    /// per-file chain-root sidecars are signed by `key`. Each file's first entry
    /// is a real entry so the re-sign can read it. Returns the active log path.
    fn build_two_file_log(dir: &std::path::Path, key: [u8; 32]) -> std::path::PathBuf {
        let path = dir.join("audit.jsonl");
        let mut writer =
            AuditWriter::open_keyed_unanchored_for_test(path.clone(), Zeroizing::new(key)).unwrap();
        writer.write_entry(sample_entry("first")).unwrap();
        writer.force_rotate_for_test().unwrap();
        writer.write_entry(sample_entry("second")).unwrap();
        writer.write_entry(sample_entry("new_row")).unwrap();
        drop(writer);
        path
    }

    #[test]
    fn resign_then_verify_with_new_key_is_green_including_new_row() {
        let dir = TempDir::new().unwrap();
        let (key1, key2) = ([0x11u8; 32], [0x22u8; 32]);
        let path = build_two_file_log(dir.path(), key1);

        // The original key verifies green before rotation (so the old-key
        // failure asserted elsewhere is a real regression, not vacuous).
        assert!(
            verify_log(&path, Some(&key1)).unwrap().hmac_verified,
            "the freshly built log must verify with the original key"
        );

        let resigned = resign_chain_root_sidecars(&path, &key2).unwrap();
        assert_eq!(resigned, 2, "both files' sidecars must be re-signed");

        let ok = verify_log(&path, Some(&key2)).unwrap();
        assert!(ok.hmac_verified, "verify with the new key must be green");
        // Four entries: "first", the rotation handoff, "second", "new_row".
        assert_eq!(
            ok.entries_verified, 4,
            "all entries including the handoff and the new row verify"
        );
    }

    #[test]
    fn resign_makes_old_key_verify_fail() {
        let dir = TempDir::new().unwrap();
        let (key1, key2) = ([0x11u8; 32], [0x22u8; 32]);
        let path = build_two_file_log(dir.path(), key1);
        resign_chain_root_sidecars(&path, &key2).unwrap();

        // The old key is destroyed by design; verifying with it must now fail
        // on the re-signed sidecar (asserting the new-key walk is the contract).
        let result = verify_log(&path, Some(&key1));
        assert!(
            result.is_err(),
            "old-key verify must fail after re-sign: {result:?}"
        );
    }

    #[test]
    fn resign_partial_failure_reports_file_and_reruns_to_green() {
        let dir = TempDir::new().unwrap();
        let (key1, key2) = ([0x11u8; 32], [0x22u8; 32]);
        let path = build_two_file_log(dir.path(), key1);

        // Corrupt the active file's first line so re-sign fails when it reaches
        // the active (last) file — file 2 of 2 — after the archive (file 1) has
        // already been re-signed.
        let original = fs::read(&path).unwrap();
        let mut corrupted = b"not-json\n".to_vec();
        corrupted.extend_from_slice(&original);
        fs::write(&path, &corrupted).unwrap();

        let err = resign_chain_root_sidecars(&path, &key2).unwrap_err();
        match &err {
            SidecarResignError::File { file, .. } => assert!(
                file.contains("audit.jsonl"),
                "error must name the active file: {file}"
            ),
            other => panic!("expected a File error naming the active file, got {other:?}"),
        }

        // Recover: restore the active file and re-run. The primitive converges —
        // the archive re-signs to the identical (deterministic) tag and the
        // active file now succeeds.
        fs::write(&path, &original).unwrap();
        let resigned = resign_chain_root_sidecars(&path, &key2).unwrap();
        assert_eq!(resigned, 2, "re-run must re-sign both files");
        assert!(
            verify_log(&path, Some(&key2)).unwrap().hmac_verified,
            "re-run converges to a green new-key verification"
        );
    }

    /// Verifies the rotation-filename lex-sort-equals-chronological-sort invariant
    /// relied on by `collect_files_newest_first`.
    ///
    /// Generates several rotation suffixes from monotonically-increasing instants,
    /// sorts them lexicographically, and asserts the order matches chronological order.
    ///
    /// The `<YYYYMMDDTHHMMSSmmm>` suffix format produced by `writer::compact_timestamp`
    /// uses zero-padded fields, making lex == chrono for the same-day / same-year case.
    /// This test verifies the invariant with cross-second and cross-day boundaries.
    #[test]
    fn rotation_suffix_lex_sort_matches_chronological() {
        // Monotonically-increasing compact timestamp strings sampled from
        // known chronological order (not derived from SystemTime to avoid
        // a dependency on wall-clock semantics in this unit test).
        let suffixes = [
            "20260101T000000000",
            "20260101T000000001",
            "20260101T000001000",
            "20260101T010000000",
            "20260102T000000000",
            "20260201T000000000",
            "20270101T000000000",
        ];

        // The suffix list is already in chronological order. Sorting
        // lexicographically must yield the same order.
        let mut sorted = suffixes.to_vec();
        sorted.sort();

        assert_eq!(
            sorted, suffixes,
            "lexicographic sort of rotation suffixes must equal chronological order; \
             collect_files_newest_first relies on this invariant"
        );

        // Also verify that reversing the sorted list gives newest-first order
        // (the scan order used by the reader).
        let mut reversed = sorted.clone();
        reversed.reverse();
        assert_eq!(
            reversed[0],
            suffixes[suffixes.len() - 1],
            "first element after reverse must be the newest (last chronological) suffix"
        );
        assert_eq!(
            reversed[reversed.len() - 1],
            suffixes[0],
            "last element after reverse must be the oldest (first chronological) suffix"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_temp_file_never_redirects_the_marker_write() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let target = outside.path().join("victim");
        fs::write(&target, b"outside the log directory").unwrap();
        let path = dir.path().join("audit.jsonl");
        let marker_path = prune_marker_path(&path);
        std::os::unix::fs::symlink(&target, dir.path().join("audit.jsonl.pruned.tmp")).unwrap();
        let mut marker = PruneMarker {
            data: PruneMarkerData {
                version: 1,
                oldest: PruneSeed {
                    file: "audit.jsonl.20260101T000000000".to_owned(),
                    initial_prev_hash: super::super::chain::ZERO_BLOCK_HASH.to_owned(),
                },
                previous: None,
                pruned_files: 1,
            },
            tag: None,
        };
        marker.write(&path, None).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"outside the log directory");
        assert!(
            !fs::symlink_metadata(&marker_path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            read_prune_marker(&path).unwrap().unwrap().data.pruned_files,
            1
        );
    }
}
