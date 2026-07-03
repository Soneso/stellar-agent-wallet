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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
