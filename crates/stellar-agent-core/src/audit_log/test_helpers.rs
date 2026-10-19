//! Verified audit-chain reads for tests.

#![allow(
    clippy::expect_used,
    reason = "test helpers panic when audit verification or reading fails"
)]

use std::path::Path;
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
    let writer = audit_writer.lock().expect("audit writer lock");
    verified_audit_entries_from_path(writer.path())
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
    let verified = verify_log(log_path, None).expect("audit log must verify");
    let mut entries = Vec::new();
    for file in verified.per_file {
        let contents = std::fs::read_to_string(file.path).expect("audit log must be readable");
        for line in contents.lines().filter(|line| !line.trim().is_empty()) {
            entries.push(serde_json::from_str(line).expect("audit row must parse"));
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test setup and assertions panic on failure"
    )]

    use std::fs::{self, OpenOptions};
    use std::io::Write as _;

    use super::*;
    use crate::audit_log::rotation::ROTATION_THRESHOLD_BYTES;
    use crate::audit_log::{EventKind, NewToolInvocation, PolicyDecision};

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

    #[test]
    fn reads_rotated_rows_in_chain_order_with_and_without_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let writer = Arc::new(Mutex::new(AuditWriter::open(path.clone(), None).unwrap()));
        append(&writer, "before");
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&vec![b'\n'; ROTATION_THRESHOLD_BYTES as usize])
            .unwrap();
        append(&writer, "after");

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
}
