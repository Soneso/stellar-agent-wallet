#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test assertions")]
use super::*;
use crate::audit_log::{
    AuditOutbox,
    lock::AuditWriterLock,
    outbox::{OutboxState, drain_lock_path, outbox_lock_path, outbox_path},
    test_helpers::rotated_archives_newest_first,
    tip_anchor::{CarrierRecord, InMemoryTipAnchorStore},
};
#[cfg(unix)]
use crate::audit_log::{lock::Carrier, outbox::OutboxBatch};

fn access(store: &Arc<InMemoryTipAnchorStore>) -> KeyedAuditAccess {
    KeyedAuditAccess::new(Zeroizing::new([0x42; 32]), store.clone())
}
fn row(id: &str) -> AuditEntry {
    AuditEntry::new_approval_attested(
        "PaymentSimulated",
        "stellar_pay_commit",
        None,
        "ABCDEFGHIJKLMNOPQRSTUV",
        "cli",
        id,
    )
}
fn key() -> Option<Zeroizing<[u8; 32]>> {
    Some(Zeroizing::new([0x42; 32]))
}
/// The identity of the lock file at `path`, read under its lock.
fn identity_at(path: &Path) -> crate::file_lock::FileIdentity {
    AuditWriterLock::acquire(path).unwrap().identity().unwrap()
}
/// The request ids of the log's rows, in order.
fn request_ids(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap().request_id)
        .collect()
}
fn fixture() -> (tempfile::TempDir, PathBuf, Arc<InMemoryTipAnchorStore>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    (dir, path, store)
}

#[test]
fn binding_carries_tagged_rows_byte_for_byte() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new([0x42; 32]));
    let commitment = store.load_outbox_state(1).unwrap();
    outbox.append(&row("one")).unwrap();
    outbox.append(&row("two")).unwrap();
    assert_eq!(
        store.load_outbox_state(1).unwrap(),
        commitment,
        "a keyed enqueue leaves the commitment"
    );
    let bytes = fs::read(outbox.path()).unwrap();
    assert!(bytes.starts_with(b"{\"k\":\"row\",\"g\":0,\"s\":1,"));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    let report = binding.bind_carriers().unwrap();
    // Both carried rows are the selected tagged suffix past the commitment.
    assert_eq!((report.generation, report.carried_rows), (2, 2));
    assert_eq!(
        fs::read(outbox.path()).unwrap(),
        bytes,
        "binding preserves every byte"
    );
    drop(binding);
    let _writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    let ids = request_ids(&path);
    assert_eq!(&ids[ids.len() - 2..], ["one", "two"]);
    assert_eq!(
        fs::read(outbox.path()).unwrap(),
        crate::audit_log::outbox::test_seam::generation_line(&[0x42; 32], 1)
    );
    assert_eq!(
        store
            .load_outbox_state(2)
            .unwrap()
            .map(|state| state.pending),
        Some(0)
    );
}

#[test]
fn loss_acknowledgement_appends_the_tagged_prefix() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new([0x42; 32]));
    outbox.append(&row("prefix")).unwrap();
    let prefix = fs::read(outbox.path()).unwrap();
    // A keyed enqueue commits nothing, so the fixture commits the tagged
    // legacy prefix explicitly.
    let commitment = OutboxState::over(&[&prefix[..prefix.len() - 1]]);
    store.store_outbox_state(1, &commitment).unwrap();
    let mut bytes = prefix.clone();
    bytes.extend_from_slice(&serde_json::to_vec(&row("stray")).unwrap());
    bytes.push(b'\n');
    fs::write(outbox.path(), &bytes).unwrap();
    let before = fs::read(&path).unwrap();
    let mut writer = AuditWriter::open_for_outbox_acknowledgement(
        path.clone(),
        key(),
        store.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let mut corrupt = prefix.clone();
    let tag_byte = corrupt.len() - 4;
    corrupt[tag_byte] = if corrupt[tag_byte] == b'0' {
        b'1'
    } else {
        b'0'
    };
    store
        .store_outbox_state(1, &OutboxState::over(&[&corrupt[..corrupt.len() - 1]]))
        .unwrap();
    corrupt.extend_from_slice(&bytes[prefix.len()..]);
    fs::write(outbox.path(), &corrupt).unwrap();
    assert!(
        matches!(
            writer.outbox_loss(),
            Err(WriterError::OutboxUnusable {
                line: 1,
                column: 1,
                reason: "tagged record whose tag does not verify"
            })
        ),
        "prefix validation refuses before revocation"
    );
    assert!(matches!(
        writer.acknowledge_outbox_loss("inspection", Default::default()),
        Err(WriterError::OutboxUnusable {
            line: 1,
            column: 1,
            reason: "tagged record whose tag does not verify"
        })
    ));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(outbox.path()).unwrap(), corrupt);
    store.store_outbox_state(1, &commitment).unwrap();
    fs::write(outbox.path(), &bytes).unwrap();
    let loss = writer.outbox_loss().unwrap().unwrap();
    assert_eq!((loss.expected_rows, loss.found_rows), (1, 2));
    let report = writer
        .acknowledge_outbox_loss("inspection", Default::default())
        .unwrap();
    assert_eq!((report.drained, report.discarded), (1, 1));
    assert_eq!(request_ids(&path).last().unwrap(), "prefix");
    assert!(!request_ids(&path).iter().any(|id| id == "stray"));
    assert!(fs::read(outbox.path()).unwrap().is_empty());
}

#[cfg(unix)]
fn replace(path: &Path) {
    let mut retired = path.as_os_str().to_os_string();
    retired.push(".moved");
    fs::rename(path, PathBuf::from(retired)).unwrap();
    fs::write(path, []).unwrap();
}

#[test]
fn a_fresh_log_records_generation_one() {
    let (_dir, path, store) = fixture();
    let record = store.load_carrier_record().unwrap().unwrap();
    assert_eq!(record.generation, 1);
    assert_eq!(record.retired, None);
    assert_eq!(record.writer, identity_at(&lock_sidecar_path(&path)));
    assert_eq!(record.drain, identity_at(&drain_lock_path(&path)));
    assert_eq!(record.outbox_lock, identity_at(&outbox_lock_path(&path)));
}

/// Writes a keyed log whose entries carry entry tags, rotates it twice and
/// removes the outbox file. Returns the archives, newest first.
fn rotate_a_tagged_log_twice(path: &Path) -> Vec<PathBuf> {
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let mut writer = AuditWriter::open(path.to_path_buf(), Some(access(&store))).unwrap();
    writer.write_entry(row("tagged")).unwrap();
    writer.force_rotate_for_test().unwrap();
    writer.write_entry(row("second")).unwrap();
    writer.force_rotate_for_test().unwrap();
    drop(writer);
    if outbox_path(path).exists() {
        fs::remove_file(outbox_path(path)).unwrap();
    }
    let archives = rotated_archives_newest_first(path);
    assert_eq!(archives.len(), 2);
    archives
}

/// Leaves a rotated keyed log whose history is intact: the newest archive
/// ends with the rotation handoff that records entry tags in force.
fn keep_an_intact_rotated_history(path: &Path) {
    let archives = rotate_a_tagged_log_twice(path);
    let newest = fs::read_to_string(&archives[0]).unwrap();
    let handoff: AuditEntry = serde_json::from_str(newest.lines().last().unwrap()).unwrap();
    assert!(matches!(
        handoff.event_kind,
        EventKind::AuditRotationHandoff {
            entry_tags: true,
            ..
        }
    ));
}

/// Leaves a rotated keyed log whose active segment and newest archive are
/// empty. Only the older archive holds the tagged entries: the newest
/// archive's handoff, which seeds the active segment, tells the open nothing.
fn retain_only_a_tagged_archive(path: &Path) {
    let archives = rotate_a_tagged_log_twice(path);
    assert!(
        fs::read_to_string(&archives[1])
            .unwrap()
            .contains("\"entry_tag\":\"")
    );
    fs::write(&archives[0], []).unwrap();
    fs::write(path, []).unwrap();
}

/// [`retain_only_a_tagged_archive`] with the field name of every entry tag
/// in the older archive spelled with a JSON escape, which decodes to the same
/// field.
fn escape_the_entry_tag_field_name(path: &Path) {
    retain_only_a_tagged_archive(path);
    let older = rotated_archives_newest_first(path).remove(1);
    let text = fs::read_to_string(&older).unwrap();
    let escaped = text.replace("\"entry_tag\":", "\"entry\\u005ftag\":");
    assert_ne!(escaped, text);
    assert!(!escaped.contains("\"entry_tag\""));
    fs::write(&older, escaped).unwrap();
}

#[test]
fn an_existing_log_without_a_record_refuses() {
    for history in [
        "anchor",
        "tagged active",
        "commitment",
        "outbox file",
        "rotated history",
        "retained archive",
        "escaped field name",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let store = Arc::new(InMemoryTipAnchorStore::new());
        match history {
            "anchor" => store
                .store_anchor(&TipAnchor::new(1, "00".repeat(32), 1))
                .unwrap(),
            "tagged active" => {
                let other = Arc::new(InMemoryTipAnchorStore::new());
                AuditWriter::open(path.clone(), Some(access(&other)))
                    .unwrap()
                    .write_entry(row("existing"))
                    .unwrap();
                if outbox_path(&path).exists() {
                    fs::remove_file(outbox_path(&path)).unwrap();
                }
            }
            "commitment" => store
                .store_outbox_state(0, &OutboxState::default())
                .unwrap(),
            "outbox file" => fs::write(outbox_path(&path), []).unwrap(),
            "rotated history" => keep_an_intact_rotated_history(&path),
            "retained archive" => retain_only_a_tagged_archive(&path),
            _ => escape_the_entry_tag_field_name(&path),
        }
        assert!(
            matches!(
                AuditWriter::open(path, Some(access(&store))),
                Err(WriterError::CarriersUnbound)
            ),
            "{history}"
        );
        assert_eq!(store.load_carrier_record().unwrap(), None, "{history}");
    }
}

#[test]
fn a_log_without_keyed_evidence_enrolls_at_its_first_keyed_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut unkeyed = AuditWriter::open(path.clone(), None).unwrap();
    unkeyed.write_entry(row("first")).unwrap();
    unkeyed.force_rotate_for_test().unwrap();
    unkeyed.write_entry(row("second")).unwrap();
    drop(unkeyed);
    assert_eq!(rotated_archives_newest_first(&path).len(), 1);
    let store = Arc::new(InMemoryTipAnchorStore::new());
    assert!(matches!(
        AuditWriter::open(path.clone(), Some(access(&store))),
        Err(WriterError::RetainedHistoryUnverified(
            crate::audit_log::VerifyError::HmacSidecarMissing { .. }
        ))
    ));
    let record = store.load_carrier_record().unwrap().unwrap();
    assert_eq!((record.generation, record.retired), (1, None));
    assert_eq!(record.writer, identity_at(&lock_sidecar_path(&path)));
    crate::audit_log::resign_chain_root_sidecars(&path, &[0x42; 32]).unwrap();
    drop(AuditWriter::open(path, Some(access(&store))).unwrap());
}

#[test]
fn a_recovery_open_refuses_while_a_carrier_is_held() {
    let (_dir, path, store) = fixture();
    for carrier in [
        lock_sidecar_path(&path),
        drain_lock_path(&path),
        outbox_lock_path(&path),
    ] {
        let held = AuditWriterLock::acquire(&carrier).unwrap();
        let refused = AuditWriter::open_for_reanchor(path.clone(), key(), store.clone());
        assert!(
            matches!(refused, Err(WriterError::CarriersBusy)),
            "{}",
            carrier.display()
        );
        assert!(
            refused
                .err()
                .unwrap()
                .to_string()
                .starts_with("audit.carriers_busy")
        );
        drop(held);
    }
    drop(AuditWriter::open_for_reanchor(path, key(), store).unwrap());
}

#[test]
fn a_recovery_batch_keeps_the_outbox_carrier_locked_after_its_writer_drops() {
    let (_dir, path, store) = fixture();
    let writer = AuditWriter::open_for_reanchor(path.clone(), key(), store.clone()).unwrap();
    let batch = writer.read_outbox(store.as_ref()).unwrap();
    drop(writer);
    assert!(matches!(
        AuditWriterLock::acquire(&outbox_lock_path(&path)),
        Err(WriterError::FileLocked)
    ));
    drop(batch);
    drop(AuditWriterLock::acquire(&outbox_lock_path(&path)).unwrap());
}

#[test]
fn names_beside_the_outbox_that_are_not_stages_are_kept() {
    let (_dir, path, store) = fixture();
    let archive = sidecar_path(&path, ".outbox.gz");
    let saved = sidecar_path(&path, ".outbox.g1.saved");
    fs::write(&archive, b"archive").unwrap();
    fs::write(&saved, b"saved").unwrap();
    assert!(
        crate::audit_log::carriers::staged_files(&path)
            .unwrap()
            .is_empty()
    );
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().generation, 2);
    drop(binding);
    drop(AuditWriter::open(path, Some(access(&store))).unwrap());
    assert_eq!(fs::read(&archive).unwrap(), b"archive");
    assert_eq!(fs::read(&saved).unwrap(), b"saved");
}

#[cfg(unix)]
#[test]
fn a_replaced_writer_lock_refuses_a_second_writer() {
    let (_dir, path, store) = fixture();
    let _writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    replace(&lock_sidecar_path(&path));
    assert!(matches!(
        AuditWriter::open(path, Some(access(&store))),
        Err(WriterError::CarrierReplaced {
            carrier: Carrier::Writer
        })
    ));
}

#[cfg(unix)]
#[test]
fn a_replaced_drain_lock_fails_the_probe_closed() {
    let (_dir, path, store) = fixture();
    let _writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    replace(&drain_lock_path(&path));
    assert!(matches!(
        crate::audit_log::drain_lock_is_held(&path, store.as_ref()),
        Err(WriterError::CarrierReplaced {
            carrier: Carrier::Drain
        })
    ));
}

#[cfg(unix)]
#[test]
fn a_replaced_outbox_lock_cannot_commit() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let _batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    let bytes = fs::read(outbox.path()).unwrap();
    let state = store.load_outbox_state(1).unwrap();
    replace(&outbox_lock_path(&path));
    assert!(matches!(
        outbox.append(&row("B")),
        Err(WriterError::CarrierReplaced { .. })
    ));
    assert_eq!(fs::read(outbox.path()).unwrap(), bytes);
    assert_eq!(store.load_outbox_state(1).unwrap(), state);
}

#[cfg(unix)]
#[test]
fn a_stale_drain_loses_no_committed_row() {
    let (_dir, path, store) = fixture();
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let attempted = Arc::new(std::sync::Mutex::new(None));
    let result = attempted.clone();
    let lock_path = outbox_lock_path(&path);
    writer.drain_after_snapshot = Some(Box::new(move || {
        replace(&lock_path);
        *result.lock().unwrap() = Some(outbox.append(&row("B")));
    }));
    assert_eq!(writer.drain_outbox().unwrap(), 1);
    assert!(matches!(
        attempted.lock().unwrap().take().unwrap(),
        Err(WriterError::CarrierReplaced { .. })
    ));
    let rows: Vec<AuditEntry> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(rows.iter().any(|r| r.request_id == "R"));
    assert!(!rows.iter().any(|r| r.request_id == "B"));
}

#[cfg(unix)]
#[test]
fn an_old_generation_drain_cannot_clear_the_new_queue() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().generation, 2);
    drop(binding);
    outbox.append(&row("B")).unwrap();
    let current = fs::read(outbox.path()).unwrap();
    store
        .store_outbox_state(batch.generation(), &OutboxState::default())
        .unwrap();
    batch.clear().unwrap();
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), current);
    assert!(current.windows(3).any(|part| part == b"\"B\""));
    assert!(matches!(
        outbox.append(&row("C")),
        Err(WriterError::RetiredOutboxChanged { generation: 1 })
    ));
}

/// A keyed enqueue does not watch the retired generation; the next owner
/// drain does, and refuses before delivering anything.
#[cfg(unix)]
#[test]
fn a_keyed_enqueue_defers_the_retired_watch_to_the_drain() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new([0x42; 32]));
    outbox.append(&row("R")).unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().generation, 2);
    drop(binding);
    store
        .store_outbox_state(batch.generation(), &OutboxState::default())
        .unwrap();
    drop(batch);
    outbox.append(&row("B")).unwrap();
    let queued = fs::read(outbox_path(&path)).unwrap();
    assert!(queued.windows(3).any(|part| part == b"\"B\""));
    let log = fs::read(&path).unwrap();
    assert!(matches!(
        AuditWriter::open(path.clone(), Some(access(&store))),
        Err(WriterError::RetiredOutboxChanged { generation: 1 })
    ));
    assert_eq!(fs::read(&path).unwrap(), log);
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), queued);
    assert_eq!(store.load_outbox_owner_state(2).unwrap(), None);
}

/// A binding that starts a new generation while a keyed append holds the
/// old outbox lock moves the appender's file aside. The check after the
/// sync refuses the row and truncates it back.
#[cfg(unix)]
#[test]
fn a_stale_appender_after_rebinding_refuses() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new([0x42; 32]));
    outbox.append(&row("R")).unwrap();
    let before = fs::read(outbox.path()).unwrap();
    let (hook_path, hook_store) = (path.clone(), store.clone());
    crate::audit_log::outbox::test_seam::on_admitted(outbox.path(), move || {
        replace(&outbox_lock_path(&hook_path));
        let mut binding =
            AuditWriter::open_for_carrier_binding(hook_path.clone(), access(&hook_store)).unwrap();
        assert_eq!(binding.bind_carriers().unwrap().generation, 2);
    });
    let error = outbox.append(&row("stale")).unwrap_err();
    assert!(
        matches!(
            error,
            WriterError::CarrierGenerationChanged {
                held: 1,
                current: 2
            }
        ),
        "{error:?}"
    );
    let record = store.load_carrier_record().unwrap().unwrap();
    let retired = path
        .parent()
        .unwrap()
        .join(record.retired.unwrap().file.unwrap());
    assert_eq!(
        fs::read(retired).unwrap(),
        before,
        "the refused row is truncated"
    );
    let queued = fs::read(outbox_path(&path)).unwrap();
    assert!(!queued.windows(7).any(|part| part == b"\"stale\""));
    let _writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    let ids = request_ids(&path);
    assert!(ids.iter().any(|id| id == "R"));
    assert!(!ids.iter().any(|id| id == "stale"));
}

/// Owner state of generation 0 is keyed evidence: enrollment refuses.
#[test]
fn an_owner_item_counts_as_enrollment_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    store
        .store_outbox_owner_state(
            0,
            &crate::audit_log::outbox::test_seam::owner_value(1, None),
        )
        .unwrap();
    assert!(matches!(
        AuditWriter::open(path.clone(), Some(access(&store))),
        Err(WriterError::CarriersUnbound)
    ));
    assert_eq!(store.load_carrier_record().unwrap(), None);
    assert!(!outbox_path(&path).exists());
}

#[test]
fn the_carrier_record_round_trips_and_refuses_unknown_fields() {
    let (_dir, _path, store) = fixture();
    let record = store.load_carrier_record().unwrap().unwrap();
    let wire = record.to_keyring_value().unwrap();
    assert_eq!(CarrierRecord::parse(&wire).unwrap(), record);
    let mut value: serde_json::Value = serde_json::from_str(&wire).unwrap();
    value["unknown"] = true.into();
    assert!(CarrierRecord::parse(&value.to_string()).is_err());
    let mut plain = serde_json::to_value(&record).unwrap();
    plain["unknown"] = true.into();
    assert!(serde_json::from_value::<CarrierRecord>(plain).is_err());
    value.as_object_mut().unwrap().remove("unknown");
    value["v"] = 2.into();
    assert!(CarrierRecord::parse(&value.to_string()).is_err());
}

#[cfg(unix)]
#[test]
fn a_reanchor_with_replaced_carriers_warns_without_draining_or_rebinding() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let before = fs::read(outbox.path()).unwrap();
    let record = store.load_carrier_record().unwrap();
    replace(&outbox_lock_path(&path));
    let mut writer = AuditWriter::open_for_reanchor(
        path.clone(),
        Some(Zeroizing::new([0x42; 32])),
        store.clone(),
    )
    .unwrap();
    let report = writer.reanchor().unwrap();
    assert!(
        report
            .outbox_refusal
            .unwrap()
            .starts_with("audit.carrier_replaced")
    );
    assert_eq!(fs::read(outbox.path()).unwrap(), before);
    assert_eq!(store.load_carrier_record().unwrap(), record);
}

#[cfg(unix)]
#[test]
fn acknowledging_a_retired_write_preserves_carrier_identities() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    binding.bind_carriers().unwrap();
    drop(binding);
    store
        .store_outbox_state(1, &OutboxState::default())
        .unwrap();
    batch.clear().unwrap();
    let before = store.load_carrier_record().unwrap().unwrap();
    let mut writer = AuditWriter::open_for_outbox_acknowledgement(
        path.clone(),
        Some(Zeroizing::new([0x42; 32])),
        store.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let report = writer
        .acknowledge_outbox_loss("queue inspection", RevokedCounts::default())
        .unwrap();
    assert_eq!((report.expected_rows, report.found_rows), (1, 0));
    drop(writer);
    let after = store.load_carrier_record().unwrap().unwrap();
    assert_eq!(
        (&after.writer, &after.drain, &after.outbox_lock),
        (&before.writer, &before.drain, &before.outbox_lock)
    );
    assert_eq!(
        after.retired.unwrap().state,
        OutboxState::default().to_keyring_value()
    );
    drop(AuditWriter::open(path, Some(access(&store))).unwrap());
}

/// Under owner state of the active generation, a retired write is still
/// acknowledged, and the owned queue and its commitment stay for the owner
/// drain.
#[cfg(unix)]
#[test]
fn a_retired_write_is_acknowledged_without_clearing_an_owned_queue() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    binding.bind_carriers().unwrap();
    drop(binding);
    let keyed = AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new([0x42; 32]));
    keyed.append(&row("delivered")).unwrap();
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    assert!(store.load_outbox_owner_state(2).unwrap().is_some());
    keyed.append(&row("queued")).unwrap();
    store
        .store_outbox_state(1, &OutboxState::default())
        .unwrap();
    batch.clear().unwrap();
    let queued = fs::read(outbox_path(&path)).unwrap();
    let state = store.load_outbox_state(2).unwrap();
    let mut writer = AuditWriter::open_for_outbox_acknowledgement(
        path.clone(),
        key(),
        store.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let loss = writer.outbox_loss().unwrap().unwrap();
    assert_eq!((loss.expected_rows, loss.found_rows), (1, 0));
    let report = writer
        .acknowledge_outbox_loss("queue inspection", RevokedCounts::default())
        .unwrap();
    assert_eq!(
        (
            report.expected_rows,
            report.found_rows,
            report.drained,
            report.discarded
        ),
        (1, 0, 0, 0)
    );
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), queued);
    assert_eq!(store.load_outbox_state(2).unwrap(), state);
    drop(writer);
    let record = store.load_carrier_record().unwrap().unwrap();
    assert_eq!(
        record.retired.unwrap().state,
        OutboxState::default().to_keyring_value()
    );
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    let ids = request_ids(&path);
    assert_eq!(ids.iter().filter(|id| *id == "queued").count(), 1);
    assert_eq!(ids.iter().filter(|id| *id == "delivered").count(), 1);
}

#[cfg(unix)]
#[test]
fn an_appender_paused_before_opening_the_file_refuses_a_new_generation() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let held =
        AuditWriterLock::acquire_bound(&outbox_lock_path(&path), Carrier::Outbox, store.as_ref())
            .unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    binding.bind_carriers().unwrap();
    drop(binding);
    let bytes = fs::read(outbox.path()).unwrap();
    let state = store.load_outbox_state(2).unwrap();
    assert!(matches!(
        outbox.prepare_append_locked(held),
        Err(WriterError::CarrierGenerationChanged {
            held: 1,
            current: 2
        })
    ));
    assert_eq!(fs::read(outbox.path()).unwrap(), bytes);
    assert_eq!(store.load_outbox_state(2).unwrap(), state);
}

/// Another process takes the chosen retired name after the binding records
/// it. The binding records the next free name before it moves the outbox
/// there, and then fails. The rerun finds the outbox under the recorded name
/// and installs the stage. The foreign file keeps its bytes, and no stage or
/// unnamed retired file remains.
#[test]
fn a_taken_retired_name_is_recorded_before_the_move_and_a_rerun_converges() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let queued = fs::read(outbox.path()).unwrap();
    let foreign = path.with_file_name("audit.jsonl.outbox.retired-g1");
    let taken = foreign.clone();

    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    binding.binding_before_retire = Some(Box::new(move || {
        fs::write(&taken, b"another process\n").unwrap();
    }));
    binding.binding_fail_after_retire = true;
    assert!(binding.bind_carriers().is_err());
    drop(binding);

    let record = store.load_carrier_record().unwrap().unwrap();
    assert_eq!(record.generation, 2);
    let recorded = record.retired.unwrap().file.unwrap();
    assert_eq!(recorded, "audit.jsonl.outbox.retired-g1.1");
    assert_eq!(fs::read(path.with_file_name(&recorded)).unwrap(), queued);
    assert!(!outbox_path(&path).exists());

    let mut rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    let report = rerun.bind_carriers().unwrap();
    drop(rerun);
    assert_eq!(report.generation, 2);
    assert_eq!(report.retired_file.as_deref(), Some(recorded.as_str()));
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), queued);
    assert_eq!(fs::read(path.with_file_name(&recorded)).unwrap(), queued);
    assert_eq!(fs::read(&foreign).unwrap(), b"another process\n");
    assert!(
        super::super::carriers::staged_files(&path)
            .unwrap()
            .is_empty()
    );
    let mut retired_files: Vec<String> = fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("audit.jsonl.outbox.retired"))
        .collect();
    retired_files.sort();
    assert_eq!(
        retired_files,
        ["audit.jsonl.outbox.retired-g1", recorded.as_str()],
        "the recorded file and the foreign file, nothing else"
    );
}

#[cfg(unix)]
#[test]
fn a_retired_write_during_binding_is_not_adopted() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    let recorded = store
        .load_outbox_state(1)
        .unwrap()
        .unwrap()
        .to_keyring_value();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    let retired_store = store.clone();
    binding.binding_after_snapshot = Some(Box::new(move || {
        retired_store
            .store_outbox_state(1, &OutboxState::default())
            .unwrap();
        batch.clear().unwrap();
    }));
    binding.bind_carriers().unwrap();
    drop(binding);
    assert_eq!(
        store
            .load_carrier_record()
            .unwrap()
            .unwrap()
            .retired
            .unwrap()
            .state,
        recorded
    );
    assert!(matches!(
        outbox.append(&row("B")),
        Err(WriterError::RetiredOutboxChanged { generation: 1 })
    ));
}

#[cfg(unix)]
#[test]
fn a_retained_batch_clearing_during_an_interrupted_binding_is_acknowledged() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    drop(binding);
    assert_eq!(store.load_carrier_record().unwrap().unwrap().generation, 2);

    // The holder of generation 1 resets its commitment and clears the file it
    // read, which the interrupted binding has not renamed yet.
    store
        .store_outbox_state(1, &OutboxState::default())
        .unwrap();
    batch.clear().unwrap();

    let mut rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    let report = rerun.bind_carriers().unwrap();
    assert_eq!((report.generation, report.carried_rows), (2, 1));
    drop(rerun);
    assert!(sidecar_path(&path, ".outbox.retired-g1").exists());

    let refused = AuditWriter::open(path.clone(), Some(access(&store)));
    assert!(matches!(
        refused,
        Err(WriterError::RetiredOutboxChanged { generation: 1 })
    ));
    assert!(
        refused
            .err()
            .unwrap()
            .to_string()
            .starts_with("audit.outbox_rows_missing")
    );

    let mut acknowledgement = AuditWriter::open_for_outbox_acknowledgement(
        path.clone(),
        key(),
        store.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let loss = acknowledgement
        .acknowledge_outbox_loss("retired holder", RevokedCounts::default())
        .unwrap();
    assert_eq!(
        (loss.expected_rows, loss.found_rows, loss.drained),
        (1, 0, 1)
    );
    drop(acknowledgement);
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    assert_eq!(
        request_ids(&path)
            .iter()
            .filter(|id| id.as_str() == "R")
            .count(),
        1
    );
}

#[test]
fn a_reanchor_reports_a_changed_retired_commitment_without_draining() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    AuditWriter::open_for_carrier_binding(path.clone(), access(&store))
        .unwrap()
        .bind_carriers()
        .unwrap();
    let bytes = fs::read(outbox.path()).unwrap();
    let record = store.load_carrier_record().unwrap();
    store
        .store_outbox_state(1, &OutboxState::default())
        .unwrap();
    let mut writer =
        AuditWriter::open_for_reanchor(path, Some(Zeroizing::new([0x42; 32])), store.clone())
            .unwrap();
    let report = writer.reanchor().unwrap();
    assert!(
        report
            .outbox_refusal
            .unwrap()
            .starts_with("audit.outbox_rows_missing")
    );
    assert_eq!(fs::read(outbox.path()).unwrap(), bytes);
    assert_eq!(store.load_carrier_record().unwrap(), record);
}
