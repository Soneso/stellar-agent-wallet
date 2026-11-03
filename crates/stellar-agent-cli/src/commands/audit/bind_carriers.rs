//! `stellar-agent audit bind-carriers --profile <NAME>`: records the
//! identities of a log's three audit lock files in the protected audit state
//! and starts a new outbox generation, with every wallet process stopped.
//!
//! A log with keyed history refuses keyed use with `audit.carriers_unbound`
//! until this verb runs once, and a log whose lock file was renamed, replaced
//! or restored refuses with `audit.carrier_replaced` until it runs again. The
//! verb takes all three lock files with one try-lock each and refuses with
//! `audit.carriers_busy` while any wallet process holds one. The committed
//! queued operator rows move to the new generation; the previous outbox file
//! is kept under the retired name the result reports. An interrupted run
//! leaves a staged generation that refuses every other open with
//! `audit.carrier_binding_incomplete`, and a rerun finishes it.
use crate::common::{profile_access::load_profile_reconciled, render};
use clap::Args;
use serde::Serialize;
use stellar_agent_core::{
    audit_log::{AuditWriter, BindingCheck, CarrierBindingReport},
    envelope::Envelope,
    error::{AuthError, WalletError},
    profile::{ResolvedProfileName, schema::Profile},
};
use stellar_agent_network::keyring::{
    KeyringTipAnchorStore, init_platform_keyring_store, keyed_audit_access,
};

/// Arguments for `audit bind-carriers`.
#[derive(Debug, Args)]
pub struct BindCarriersArgs {
    /// Profile whose audit lock files are recorded. Stop every wallet process
    /// first.
    #[arg(long)]
    pub profile: String,
}

/// The JSON result: the profile and the binding report.
#[derive(Serialize)]
struct BindingResult {
    profile: String,
    #[serde(flatten)]
    report: CarrierBindingReport,
}

/// Binds the carriers and renders the result. Returns 1 on refusal.
pub async fn run(args: &BindCarriersArgs) -> i32 {
    let result = (|| -> Result<BindingResult, WalletError> {
        let profile = load_profile_reconciled(&ResolvedProfileName::from_flag(&args.profile))
            .map_err(|error| error.to_wallet_error(&args.profile))?;
        init_platform_keyring_store()?;
        let report = bind_profile(&profile, &args.profile)?;
        Ok(BindingResult {
            profile: args.profile.clone(),
            report,
        })
    })();
    match result {
        Ok(data) => {
            render::render_json(&Envelope::ok(data));
            0
        }
        Err(error) => {
            render::render_json(&Envelope::<()>::err(&error));
            1
        }
    }
}

/// Binds the carriers of `profile`'s log. A profile without an audit key yet
/// binds through the unkeyed open, so minting the first key later needs no
/// second binding.
fn bind_profile(profile: &Profile, name: &str) -> Result<CarrierBindingReport, WalletError> {
    let opened = match keyed_audit_access(profile, name, BindingCheck::CheckOnly) {
        Ok(access) => AuditWriter::open_for_carrier_binding(profile.audit_log_path.clone(), access),
        Err(WalletError::Auth(AuthError::KeyringNotFound { .. })) => {
            AuditWriter::open_for_carrier_binding_unkeyed(
                profile.audit_log_path.clone(),
                KeyringTipAnchorStore::shared(
                    &profile.audit_log_hash_chain_key_id,
                    &profile.audit_log_path,
                ),
            )
        }
        Err(error) => return Err(error),
    };
    let mut writer = opened
        .map_err(|error| super::audit_writer_error(&error, "audit.carrier_binding_failed", name))?;
    writer
        .bind_carriers()
        .map_err(|error| super::audit_writer_error(&error, "audit.carrier_binding_failed", name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        path::{Path, PathBuf},
        sync::Arc,
    };
    use stellar_agent_core::audit_log::{
        AuditEntry, KeyedAuditAccess, OutboxState, TipAnchorStore, WriterError, outbox_path,
        tip_anchor::InMemoryTipAnchorStore,
    };
    use zeroize::Zeroizing;

    fn access(store: &Arc<InMemoryTipAnchorStore>) -> KeyedAuditAccess {
        KeyedAuditAccess::new(Zeroizing::new([0x42; 32]), store.clone())
    }
    fn fixture() -> (
        tempfile::TempDir,
        PathBuf,
        Arc<InMemoryTipAnchorStore>,
        Vec<u8>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let row = AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            "ABCDEFGHIJKLMNOPQRSTUV",
            "cli",
            "R",
        );
        let mut bytes = serde_json::to_vec(&row).unwrap();
        let mut hash = Sha256::new();
        hash.update(b"stellar-agent-outbox:v1");
        hash.update([0; 32]);
        hash.update(&bytes);
        store
            .store_outbox_state(
                0,
                &OutboxState {
                    pending: 1,
                    head: hash.finalize().into(),
                },
            )
            .unwrap();
        bytes.push(b'\n');
        std::fs::write(outbox_path(&path), &bytes).unwrap();
        (dir, path, store, bytes)
    }
    fn bind(
        path: &Path,
        store: &Arc<InMemoryTipAnchorStore>,
    ) -> Result<CarrierBindingReport, WriterError> {
        AuditWriter::open_for_carrier_binding(path.to_path_buf(), access(store))?.bind_carriers()
    }

    #[test]
    #[serial_test::serial]
    fn binding_enrolls_an_unkeyed_log_before_its_first_key() {
        stellar_agent_test_support::keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let name = "carrier-first-key";
        let mut profile = Profile::builder_testnet(name, "acct", "n-svc", "n-acct").build();
        profile.audit_log_path = dir.path().join("audit.jsonl");
        AuditWriter::open(profile.audit_log_path.clone(), None)
            .unwrap()
            .write_entry(AuditEntry::new_profile_halted(
                "fixture",
                "2026-01-01T00:00:00Z",
                None,
                "R",
            ))
            .unwrap();
        stellar_agent_network::keyring::KeyringAuditBindingStore::for_profile(name)
            .store(&stellar_agent_core::audit_log::AuditBinding::for_profile(
                &profile,
            ))
            .unwrap();
        assert_eq!(bind_profile(&profile, name).unwrap().generation, 1);
        let key = &profile.audit_log_hash_chain_key_id;
        assert!(matches!(
            stellar_agent_network::keyring::load_hmac_key_32(key),
            Err(WalletError::Auth(AuthError::KeyringNotFound { .. }))
        ));
        stellar_agent_network::keyring::rotate_keyring_secret_32(&key.service, &key.account)
            .unwrap();
        drop(
            AuditWriter::open(
                profile.audit_log_path.clone(),
                Some(keyed_audit_access(&profile, name, BindingCheck::CheckOnly).unwrap()),
            )
            .unwrap(),
        );
    }

    /// The file `name` beside the log at `path`.
    fn sibling(path: &Path, name: &str) -> PathBuf {
        path.with_file_name(name)
    }

    /// The `audit_carriers_bound` rows of the log, in order.
    fn bound_rows(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|row| row["kind"] == "audit_carriers_bound")
            .collect()
    }

    /// How many rows of the log carry `request_id`.
    fn rows_with_id(path: &Path, request_id: &str) -> usize {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap())
            .filter(|row| row.request_id == request_id)
            .count()
    }

    #[test]
    fn binding_carries_committed_rows_into_the_new_generation() {
        let (_dir, path, store, bytes) = fixture();
        let report = bind(&path, &store).unwrap();
        assert_eq!(report.generation, 1);
        assert_eq!(report.carried_rows, 1);
        assert_eq!(
            report.retired_file.as_deref(),
            Some("audit.jsonl.outbox.retired-g0")
        );
        assert_eq!(std::fs::read(outbox_path(&path)).unwrap(), bytes);
        assert_eq!(
            std::fs::read(sibling(&path, "audit.jsonl.outbox.retired-g0")).unwrap(),
            bytes
        );
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            store.load_outbox_state(0).unwrap()
        );
        let rows = bound_rows(&path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["retired_file"], "audit.jsonl.outbox.retired-g0");
        drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
        drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
        assert_eq!(rows_with_id(&path, "R"), 1);
    }

    #[test]
    fn binding_a_log_without_an_outbox_file_retires_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        let report = bind(&path, &store).unwrap();
        assert_eq!((report.generation, report.carried_rows), (1, 0));
        assert_eq!(report.retired_file, None);
        assert_eq!(
            bound_rows(&path)[0]["retired_file"],
            serde_json::Value::Null
        );
        assert!(
            store
                .load_carrier_record()
                .unwrap()
                .unwrap()
                .retired
                .unwrap()
                .file
                .is_none()
        );
    }

    #[test]
    fn binding_refuses_while_a_carrier_is_held() {
        for suffix in [".lock", ".drain.lock", ".outbox.lock"] {
            let (_dir, path, store, _bytes) = fixture();
            let carrier = PathBuf::from(format!("{}{suffix}", path.display()));
            let held =
                stellar_agent_core::audit_log::test_helpers::hold_audit_lock(&carrier).unwrap();
            let (send, receive) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || send.send(bind(&path, &store)).unwrap());
            let result = receive.recv_timeout(std::time::Duration::from_millis(500));
            drop(held);
            thread.join().unwrap();
            assert!(matches!(result.unwrap(), Err(WriterError::CarriersBusy)));
        }
    }

    #[test]
    fn binding_refuses_a_damaged_queue() {
        let (_dir, path, store, _bytes) = fixture();
        std::fs::write(outbox_path(&path), []).unwrap();
        let before = store.load_outbox_state(0).unwrap();
        assert!(matches!(
            bind(&path, &store),
            Err(WriterError::OutboxRowsMissing { .. })
        ));
        assert!(!path.exists());
        assert_eq!(store.load_carrier_record().unwrap(), None);
        assert_eq!(store.load_outbox_state(0).unwrap(), before);
        assert_eq!(store.load_outbox_state(1).unwrap(), None);
        assert!(std::fs::read(outbox_path(&path)).unwrap().is_empty());
    }

    #[test]
    fn a_crash_at_each_binding_step_leaves_a_consistent_state() {
        for step in 2..=5 {
            let (_dir, path, store, bytes) = fixture();
            let committed = store.load_outbox_state(0).unwrap();
            let mut writer =
                AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
            assert!(writer.bind_carriers_with_fault(step).is_err());
            drop(writer);
            assert_eq!(
                store.load_carrier_record().unwrap().map(|r| r.generation),
                if step < 4 { None } else { Some(1) },
                "step {step}"
            );
            assert_eq!(
                bound_rows(&path).len(),
                usize::from(step > 2),
                "step {step}"
            );
            if step < 4 {
                // Generation 0 is intact: its queue and its commitment.
                assert_eq!(std::fs::read(outbox_path(&path)).unwrap(), bytes);
                assert_eq!(store.load_outbox_state(0).unwrap(), committed);
            }
            if step < 5 {
                assert!(matches!(
                    AuditWriter::open(path.clone(), Some(access(&store))),
                    Err(WriterError::CarrierBindingIncomplete)
                ));
            }
            let rows_before = bound_rows(&path).len();
            let report = bind(&path, &store).unwrap();
            // A rerun before the record names the new generation starts the
            // binding again and records it again; after step 4 it only
            // installs the stage; after step 5 it is a new binding.
            assert_eq!(
                bound_rows(&path).len(),
                rows_before + usize::from(step != 4),
                "step {step}"
            );
            assert_eq!(
                report.generation,
                if step == 5 { 2 } else { 1 },
                "step {step}"
            );
            assert_eq!(std::fs::read(outbox_path(&path)).unwrap(), bytes);
            assert_eq!(
                std::fs::read(sibling(&path, "audit.jsonl.outbox.retired-g0")).unwrap(),
                bytes
            );
            assert_eq!(
                store
                    .load_outbox_state(report.generation)
                    .unwrap()
                    .unwrap()
                    .pending,
                1
            );
            drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
            assert!(std::fs::read(outbox_path(&path)).unwrap().is_empty());
            assert_eq!(rows_with_id(&path, "R"), 1, "step {step}");
        }
    }

    #[test]
    fn a_rerun_after_the_first_rename_installs_the_stage() {
        let (_dir, path, store, bytes) = fixture();
        let mut writer =
            AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
        assert!(writer.bind_carriers_with_fault(4).is_err());
        drop(writer);
        let retired = sibling(&path, "audit.jsonl.outbox.retired-g0");
        std::fs::rename(outbox_path(&path), &retired).unwrap();
        // A refused stale appender can leave an empty active file between the
        // two renames.
        std::fs::write(outbox_path(&path), []).unwrap();
        let report = bind(&path, &store).unwrap();
        assert_eq!(report.generation, 1);
        assert_eq!(
            report.retired_file.as_deref(),
            Some("audit.jsonl.outbox.retired-g0")
        );
        assert_eq!(std::fs::read(outbox_path(&path)).unwrap(), bytes);
        assert_eq!(std::fs::read(&retired).unwrap(), bytes);
        assert!(!sibling(&path, "audit.jsonl.outbox.retired-g0.1").exists());
    }

    #[test]
    fn a_rerun_restages_a_stage_that_does_not_hold_the_committed_rows() {
        let (_dir, path, store, bytes) = fixture();
        let mut writer =
            AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
        assert!(writer.bind_carriers_with_fault(4).is_err());
        drop(writer);
        let record = store.load_carrier_record().unwrap().unwrap();
        let staged = sibling(&path, "audit.jsonl.outbox.g1");
        std::fs::write(&staged, b"{\"damaged\":true}\n").unwrap();
        let report = bind(&path, &store).unwrap();
        assert_eq!((report.generation, report.carried_rows), (1, 1));
        assert!(!staged.exists());
        assert_eq!(std::fs::read(outbox_path(&path)).unwrap(), bytes);
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            store.load_outbox_state(0).unwrap()
        );
        assert_eq!(
            store.load_carrier_record().unwrap().unwrap().retired,
            record.retired,
            "the restaged binding keeps the retired watch it recorded"
        );
        drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
        assert_eq!(rows_with_id(&path, "R"), 1);
    }

    /// The bytes of a stage that holds no committed row.
    const DAMAGED_STAGE: &[u8] = b"{\"damaged\":true}\n";

    /// Interrupts a binding after step 4, completes the first rename of step
    /// 5 by hand, and damages the stage. Returns the retired file and the
    /// stage.
    fn damage_the_stage_after_the_first_rename(
        path: &Path,
        store: &Arc<InMemoryTipAnchorStore>,
    ) -> (PathBuf, PathBuf) {
        let mut writer =
            AuditWriter::open_for_carrier_binding(path.to_path_buf(), access(store)).unwrap();
        assert!(writer.bind_carriers_with_fault(4).is_err());
        drop(writer);
        let retired = sibling(path, "audit.jsonl.outbox.retired-g0");
        std::fs::rename(outbox_path(path), &retired).unwrap();
        let staged = sibling(path, "audit.jsonl.outbox.g1");
        std::fs::write(&staged, DAMAGED_STAGE).unwrap();
        (retired, staged)
    }

    /// Checks a completed binding of generation 1 that carried the row `R`
    /// of generation 0, kept the retired file and the retired watch, and
    /// leaves the log open to an ordinary writer.
    fn assert_bound_from_the_retired_file(
        path: &Path,
        store: &Arc<InMemoryTipAnchorStore>,
        bytes: &[u8],
        retired_watch: Option<&stellar_agent_core::audit_log::tip_anchor::RetiredOutbox>,
    ) {
        let staged = sibling(path, "audit.jsonl.outbox.g1");
        assert!(!staged.exists());
        assert_eq!(std::fs::read(outbox_path(path)).unwrap(), bytes);
        assert_eq!(
            std::fs::read(sibling(path, "audit.jsonl.outbox.retired-g0")).unwrap(),
            bytes
        );
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            store.load_outbox_state(0).unwrap()
        );
        assert_eq!(
            store
                .load_carrier_record()
                .unwrap()
                .unwrap()
                .retired
                .as_ref(),
            retired_watch
        );
        drop(AuditWriter::open(path.to_path_buf(), Some(access(store))).unwrap());
        assert_eq!(rows_with_id(path, "R"), 1);
    }

    #[test]
    fn a_damaged_stage_after_the_first_rename_is_restaged_from_the_retired_file() {
        let (_dir, path, store, bytes) = fixture();
        let (retired, staged) = damage_the_stage_after_the_first_rename(&path, &store);
        let record = store.load_carrier_record().unwrap().unwrap();
        let rows_before = bound_rows(&path).len();

        // A retired file without the committed rows refuses before anything
        // changes: the stage stays and the binding stays incomplete.
        std::fs::write(&retired, []).unwrap();
        assert!(matches!(
            bind(&path, &store),
            Err(WriterError::OutboxRowsMissing { .. })
        ));
        assert_eq!(std::fs::read(&staged).unwrap(), DAMAGED_STAGE);
        assert!(!outbox_path(&path).exists());
        assert_eq!(bound_rows(&path).len(), rows_before);
        assert_eq!(store.load_carrier_record().unwrap().unwrap(), record);
        assert!(matches!(
            AuditWriter::open(path.clone(), Some(access(&store))),
            Err(WriterError::CarrierBindingIncomplete)
        ));

        std::fs::write(&retired, &bytes).unwrap();
        let report = bind(&path, &store).unwrap();
        assert_eq!((report.generation, report.carried_rows), (1, 1));
        assert_eq!(
            report.retired_file.as_deref(),
            Some("audit.jsonl.outbox.retired-g0")
        );
        assert_eq!(bound_rows(&path).len(), rows_before + 1);
        assert_bound_from_the_retired_file(&path, &store, &bytes, record.retired.as_ref());
    }

    #[test]
    fn an_interrupted_restage_stays_incomplete_and_completes_on_the_next_rerun() {
        for step in 1..=4 {
            let (_dir, path, store, bytes) = fixture();
            let (retired, staged) = damage_the_stage_after_the_first_rename(&path, &store);
            let record = store.load_carrier_record().unwrap().unwrap();
            let mut writer =
                AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
            assert!(
                writer.bind_carriers_with_fault(step).is_err(),
                "step {step}"
            );
            drop(writer);
            assert!(staged.exists(), "step {step}");
            if step == 1 {
                assert_eq!(std::fs::read(&staged).unwrap(), DAMAGED_STAGE);
            } else {
                assert_eq!(std::fs::read(&staged).unwrap(), bytes, "step {step}");
            }
            assert_eq!(std::fs::read(&retired).unwrap(), bytes, "step {step}");
            assert!(
                matches!(
                    AuditWriter::open(path.clone(), Some(access(&store))),
                    Err(WriterError::CarrierBindingIncomplete)
                ),
                "step {step}"
            );
            let report = bind(&path, &store).unwrap();
            assert_eq!(
                (report.generation, report.carried_rows),
                (1, 1),
                "step {step}"
            );
            assert_bound_from_the_retired_file(&path, &store, &bytes, record.retired.as_ref());
        }
    }

    #[test]
    fn a_second_binding_from_generation_zero_after_a_keyring_loss_completes() {
        let (_dir, path, store, bytes) = fixture();
        let first = bind(&path, &store).unwrap();
        assert_eq!(
            first.retired_file.as_deref(),
            Some("audit.jsonl.outbox.retired-g0")
        );
        // The next keyed open drains R and leaves the outbox file empty.
        drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
        // The keyring loses the carrier record and the commitments; the anchor
        // is restored, so the next binding starts again at generation 0.
        let restored = Arc::new(InMemoryTipAnchorStore::new());
        restored.set(store.load_anchor().unwrap());
        let second = bind(&path, &restored).unwrap();
        assert_eq!(second.generation, 1);
        assert_eq!(
            second.retired_file.as_deref(),
            Some("audit.jsonl.outbox.retired-g0.1")
        );
        assert_eq!(
            std::fs::read(sibling(&path, "audit.jsonl.outbox.retired-g0")).unwrap(),
            bytes,
            "the earlier retired file is kept"
        );
        assert!(
            std::fs::read(sibling(&path, "audit.jsonl.outbox.retired-g0.1"))
                .unwrap()
                .is_empty()
        );
        let rows = bound_rows(&path);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["retired_file"], "audit.jsonl.outbox.retired-g0.1");
        drop(AuditWriter::open(path.clone(), Some(access(&restored))).unwrap());
        assert_eq!(rows_with_id(&path, "R"), 1);
    }
}
