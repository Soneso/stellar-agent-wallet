//! Rotation constants and helpers for the audit log.
//!
//! Centralises the rotation policy constants used by [`super::writer::AuditWriter`]
//! and re-exported for external consumers.
//!
//! # Rotation policy
//!
//! - **Threshold:** [`ROTATION_THRESHOLD_BYTES`] — 10 MiB.  When the active
//!   log file reaches or exceeds this size, [`super::writer::AuditWriter`]
//!   writes an `AuditRotationHandoff` entry, renames the active file to an
//!   archive with a compact timestamp suffix, and opens a fresh active file.
//! - **Retention:** [`MAX_ROTATED_FILES`] — 10 archived copies.  When the
//!   11th rotation occurs, the oldest archived file (and its `.root_hmac`
//!   sidecar) is deleted.
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

use super::chain::sign_chain_root;
use super::entry::AuditEntry;
use super::verify::collect_file_chain;
use super::writer::hmac_sidecar_path;

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
/// [`collect_file_chain`] discovery `verify_log` uses; a referenced-but-missing
/// rotated file is skipped (it is a chain gap `verify_log` reports separately).
///
/// # Invariant (rotate-audit-key ordering)
///
/// The chain-root sidecar's security property is that an attacker who
/// wholesale-replaces a file cannot forge the root tag without the CURRENT key.
/// This primitive MUST run AFTER the new key is persisted to the keyring and
/// BEFORE emitting the key-write row. Re-signing before the new key is
/// persisted is forbidden: a crash between signing and persistence would leave
/// sidecars signed by a key that exists nowhere, permanently unverifiable.
/// Under the required order, a crash after persistence but before (or during)
/// re-signing is recoverable — re-running rotate-audit-key re-signs with the
/// already-persisted key and converges.
///
/// Returns the number of sidecars re-signed.
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
        write_sidecar_atomic(&hmac_sidecar_path(&file), &tag).map_err(|detail| {
            SidecarResignError::File {
                file: file_name.clone(),
                detail,
            }
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

/// Atomically writes `tag` to the sidecar via a sibling temp file plus rename,
/// mirroring the writer's `0o600` + `sync_data` durability discipline.
fn write_sidecar_atomic(sidecar: &Path, tag: &str) -> Result<(), String> {
    let mut tmp = sidecar.to_path_buf();
    let name = tmp
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "sidecar path has no file name".to_owned())?
        .to_owned();
    tmp.set_file_name(format!("{name}.tmp"));
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| format!("open temp sidecar: {e}"))?
        };
        #[cfg(not(unix))]
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| format!("open temp sidecar: {e}"))?;
        f.write_all(tag.as_bytes())
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
        let mut writer = AuditWriter::open(path.clone(), Some(Zeroizing::new(key))).unwrap();
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
}
