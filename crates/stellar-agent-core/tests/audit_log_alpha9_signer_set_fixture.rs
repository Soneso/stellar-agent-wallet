//! Reads an audit log written by the v0.1.0-alpha.9 release.
//!
//! The fixture under `tests/fixtures/audit_log_alpha9_signer_set/` holds two
//! files written by that release's writer: a rotated file with a rule-1
//! baseline, a rule-1 signer add, a rule-2 signer removal, a rule-3
//! divergence row and the rotation handoff, and the active file with a rule-1
//! threshold change and a rule-4 baseline over an External and a WebAuthn
//! signer. Every row names the account `CAAAA...AD2KM` on `stellar:testnet`.
//!
//! The log must verify, every row must re-serialize to the exact bytes on
//! disk (the chain hashes that text), and the signer-set reader must return
//! each rule's newest state as a version-1 view.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration harness treats setup failures as test failures"
)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use stellar_agent_core::audit_log::entry::AuditEntry;
use stellar_agent_core::audit_log::reader::AuditReader;
use stellar_agent_core::audit_log::schema::EventKind;
use stellar_agent_core::audit_log::signer_set::{
    ObservedSignerSet, SignerPubkey, SignerSetView, SignerSetViewPayload, account_digest,
    compute_signer_set_digest,
};
use stellar_agent_core::audit_log::verify::verify_log;
use stellar_agent_core::audit_log::writer::AuditWriter;
use tempfile::TempDir;

const ACTIVE: &str = "audit.jsonl";
const ROTATED: &str = "audit.jsonl.20260930T123459362";
const ACCOUNT_REDACTED: &str = "CAAAA...AD2KM";
const ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
const PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Copies the fixture into a fresh directory and returns it with the active
/// file's path.
fn fixture_copy() -> (TempDir, PathBuf) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("audit_log_alpha9_signer_set");
    let dir = TempDir::new().unwrap();
    for name in [ACTIVE, ROTATED] {
        std::fs::copy(source.join(name), dir.path().join(name)).unwrap();
    }
    let active = dir.path().join(ACTIVE);
    (dir, active)
}

fn ed25519(byte: u8) -> SignerPubkey {
    SignerPubkey::Ed25519 { pubkey: [byte; 32] }
}

fn v1_state(payload: &SignerSetViewPayload) -> &ObservedSignerSet {
    match payload.view() {
        SignerSetView::V1(state) => state,
        SignerSetView::V2(_) => panic!("an alpha.9 row reads as version 1, got {payload:?}"),
    }
}

#[test]
fn alpha9_log_verifies_across_both_files() {
    let (_dir, active) = fixture_copy();
    let ok = verify_log(&active, None).unwrap();
    assert_eq!(ok.entries_verified, 7);
    assert_eq!(ok.files_walked, 2);
}

#[test]
fn every_alpha9_row_re_serializes_byte_identically() {
    let (dir, _active) = fixture_copy();
    let mut rows = 0;
    for name in [ROTATED, ACTIVE] {
        let text = std::fs::read_to_string(dir.path().join(name)).unwrap();
        for (index, line) in text.lines().enumerate() {
            let entry: AuditEntry = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("{name}:{} does not parse: {e}", index + 1));
            assert_eq!(
                serde_json::to_string(&entry).unwrap(),
                line,
                "{name}:{} re-serializes differently",
                index + 1
            );
            rows += 1;
        }
    }
    assert_eq!(rows, 7);
}

#[test]
fn rotated_file_is_named_by_the_handoff_row_that_ends_it() {
    let (dir, _active) = fixture_copy();
    let text = std::fs::read_to_string(dir.path().join(ROTATED)).unwrap();
    let last = text.lines().last().unwrap();
    let entry: AuditEntry = serde_json::from_str(last).unwrap();
    match entry.event_kind {
        EventKind::AuditRotationHandoff { next_file_name } => {
            assert_eq!(next_file_name, ROTATED);
        }
        other => panic!("the rotated file ends with a handoff row, got {other:?}"),
    }
}

#[test]
fn alpha9_signer_set_state_reads_as_version_1_views() {
    let (_dir, active) = fixture_copy();
    let writer = Arc::new(Mutex::new(AuditWriter::open(active, None).unwrap()));
    let reader = AuditReader::new(writer, None);
    let digest = account_digest(PASSPHRASE, ACCOUNT);
    let view = |rule_id: u32| {
        reader
            .find_latest_signer_set_view(rule_id, ACCOUNT_REDACTED, &digest)
            .unwrap()
    };

    let rule_1 = view(1).expect("rule 1 has state");
    assert_eq!(rule_1.view().version(), 1);
    assert_eq!(
        v1_state(&rule_1),
        &ObservedSignerSet {
            signer_count: 3,
            threshold: 2,
            signer_ids: vec![0, 1, 2],
            signer_pubkeys: vec![ed25519(0x11), ed25519(0x22), ed25519(0x33)],
        },
        "rule 1 reads the active file's threshold row"
    );
    assert_eq!((rule_1.file(), rule_1.line()), (ACTIVE, 1));

    let rule_2 = view(2).expect("rule 2 has state");
    assert_eq!(
        v1_state(&rule_2),
        &ObservedSignerSet {
            signer_count: 1,
            threshold: 1,
            signer_ids: vec![0],
            signer_pubkeys: vec![ed25519(0x44)],
        },
        "rule 2 reads the rotated file's removal row"
    );
    assert_eq!((rule_2.file(), rule_2.line()), (ROTATED, 3));

    assert!(view(3).is_none(), "a divergence row is not a state row");

    let rule_4 = view(4).expect("rule 4 has state");
    let mut key_data_first16 = [0u8; 16];
    for (offset, byte) in (0x90u8..).zip(key_data_first16.iter_mut()) {
        *byte = offset;
    }
    assert_eq!(
        v1_state(&rule_4),
        &ObservedSignerSet {
            signer_count: 2,
            threshold: 2,
            signer_ids: vec![0, 1],
            signer_pubkeys: vec![
                SignerPubkey::External {
                    verifier_contract: stellar_strkey::Contract([0x88; 32])
                        .to_string()
                        .as_str()
                        .to_owned(),
                    key_data_first16,
                },
                SignerPubkey::WebAuthn {
                    credential_id_first16: [0xa5; 16],
                },
            ],
        }
    );
    assert_eq!((rule_4.file(), rule_4.line()), (ACTIVE, 2));

    for payload in [&rule_1, &rule_2, &rule_4] {
        compute_signer_set_digest(v1_state(payload)).unwrap();
    }
}
