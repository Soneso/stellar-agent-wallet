//! Adversarial fixture: property tests for audit-log baseline reconstruction.
//!
//! Property: for any N-entry sequence of `SaSignerSetBaselined` rows with
//! distinct `(rule_id, smart_account_redacted)` pairs, `find_latest_signer_set_state`
//! always returns the MOST RECENT row for the queried pair, or `None` for an
//! unqueried pair.
//!
//! Uses `proptest` with a bounded strategy so the total row count stays manageable.
//!
//! Verifies the atomic signer-threshold-update invariant: baseline
//! reconstruction always returns the most-recent row for a queried pair.

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::reader::AuditReader;
use stellar_agent_core::audit_log::signer_set::{BaselineReason, ObservedSignerSet, SignerPubkey};
use stellar_agent_core::audit_log::writer::AuditWriter;
use stellar_agent_core::observability::RedactedStrkey;
use uuid::Uuid;

// ── Property tests ────────────────────────────────────────────────────────────

proptest::proptest! {
    /// Property: `find_latest_signer_set_state` returns the most-recent row
    /// for a queried `(rule_id, smart_account_redacted)` pair.
    ///
    /// Strategy: write between 1 and 8 baseline rows for rule_id 1 and the
    /// same `smart_account_redacted`. Assert the reader returns the last row's
    /// `threshold` value (threshold is set to the row index + 1 to distinguish rows).
    #[test]
    fn prop_most_recent_baseline_is_returned(
        row_count in 1usize..=8,
    ) {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let path = dir.path().join("audit.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None)
            .expect("AuditWriter::open must succeed");

        // Write `row_count` baseline rows for the same (rule_id=1, account_redacted).
        // Each row has `threshold = (i + 1)` so rows are distinguishable.
        for i in 0..row_count {
            let threshold = u32::try_from(i + 1).unwrap_or(1);
            let observed = ObservedSignerSet {
                signer_count: threshold,
                threshold,
                signer_ids: vec![0u32],
                signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0x11; 32] }],
            };
            let prev_tip = writer.current_chain_tip();
            let entry = AuditEntry::new_sa_signer_set_baselined(
                1,
                &observed,
                vec!["1111111111111111".to_owned()],
                0,
                BaselineReason::first_observation(),
                prev_tip,
                RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
                "stellar:testnet",
                Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).expect("write must succeed");
        }
        drop(writer);

        // Re-open the log with a fresh writer (simulates process restart).
        let writer2 = AuditWriter::open(path.clone(), None)
            .expect("re-open must succeed");
        let writer2 = std::sync::Arc::new(std::sync::Mutex::new(writer2));
        let reader = AuditReader::new(writer2, None);

        let result = reader
            .find_latest_signer_set_state(1, "CAAAA...AD2KM")
            .expect("integrity check must pass");

        let payload = result.expect("most-recent row must be present");

        // The last row written has threshold = row_count.
        let expected_threshold = u32::try_from(row_count).unwrap_or(1);
        proptest::prop_assert_eq!(
            payload.state().threshold,
            expected_threshold,
            "expected most-recent row threshold {}, got {}",
            expected_threshold,
            payload.state().threshold
        );
    }

    /// Property: `find_latest_signer_set_state` returns `None` for a pair
    /// that was never written, even if other pairs exist in the log.
    #[test]
    fn prop_unqueried_pair_returns_none(
        written_rule_id in 2u32..=10,
        written_count in 1usize..=4,
    ) {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let path = dir.path().join("audit.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None)
            .expect("AuditWriter::open must succeed");

        // Write rows for rule_id = `written_rule_id`, NOT rule_id 1.
        for _ in 0..written_count {
            let observed = ObservedSignerSet {
                signer_count: 1,
                threshold: 1,
                signer_ids: vec![0],
                signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0x22; 32] }],
            };
            let prev_tip = writer.current_chain_tip();
            let entry = AuditEntry::new_sa_signer_set_baselined(
                written_rule_id,
                &observed,
                vec!["2222222222222222".to_owned()],
                0,
                BaselineReason::first_observation(),
                prev_tip,
                RedactedStrkey::from_already_redacted("CAAAA...AD2KM"),
                "stellar:testnet",
                Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).expect("write must succeed");
        }
        drop(writer);

        let writer2 = AuditWriter::open(path.clone(), None)
            .expect("re-open must succeed");
        let writer2 = std::sync::Arc::new(std::sync::Mutex::new(writer2));
        let reader = AuditReader::new(writer2, None);

        // Query rule_id 1 — never written.
        let result = reader
            .find_latest_signer_set_state(1, "CAAAA...AD2KM")
            .expect("integrity check must pass");

        proptest::prop_assert!(
            result.is_none(),
            "unqueried rule_id 1 must return None; got: {result:?}"
        );
    }

    /// Property: `find_latest_signer_set_state` is independent per
    /// `smart_account_redacted` label; writing for account A does not populate
    /// the result for account B.
    #[test]
    fn prop_account_isolation(rows_for_a in 1usize..=5) {
        let dir = tempfile::tempdir().expect("tempdir must succeed");
        let path = dir.path().join("audit.jsonl");
        let mut writer = AuditWriter::open(path.clone(), None)
            .expect("AuditWriter::open must succeed");

        let account_a = "CAAAA...AAAAA";
        let account_b = "CBBBB...BBBBB";

        // Write rows for account A only.
        for _ in 0..rows_for_a {
            let observed = ObservedSignerSet {
                signer_count: 1,
                threshold: 1,
                signer_ids: vec![0],
                signer_pubkeys: vec![SignerPubkey::Ed25519 { pubkey: [0x33; 32] }],
            };
            let prev_tip = writer.current_chain_tip();
            let entry = AuditEntry::new_sa_signer_set_baselined(
                1,
                &observed,
                vec!["3333333333333333".to_owned()],
                0,
                BaselineReason::first_observation(),
                prev_tip,
                RedactedStrkey::from_already_redacted(account_a),
                "stellar:testnet",
                Uuid::new_v4().to_string(),
            );
            writer.write_entry(entry).expect("write must succeed");
        }
        drop(writer);

        let writer2 = AuditWriter::open(path.clone(), None)
            .expect("re-open must succeed");
        let writer2 = std::sync::Arc::new(std::sync::Mutex::new(writer2));
        // Clone the Arc before passing ownership into the first reader so
        // that reader2 can share the same underlying AuditWriter without
        // triggering a FileLocked error from a second open() call.
        let writer2_clone = std::sync::Arc::clone(&writer2);
        let reader = AuditReader::new(writer2, None);

        // Account A must be present.
        let a_result = reader
            .find_latest_signer_set_state(1, account_a)
            .expect("integrity must pass");
        proptest::prop_assert!(
            a_result.is_some(),
            "account A must have a baseline after {} writes",
            rows_for_a
        );

        // Account B was never written — must return None.
        // Reuse the same Arc-wrapped AuditWriter; opening a second writer on
        // the same path would fail with FileLocked while writer2 is alive.
        let reader2 = AuditReader::new(writer2_clone, None);
        let b_result = reader2
            .find_latest_signer_set_state(1, account_b)
            .expect("integrity must pass");
        proptest::prop_assert!(
            b_result.is_none(),
            "account B must return None (never written)"
        );
    }
}
