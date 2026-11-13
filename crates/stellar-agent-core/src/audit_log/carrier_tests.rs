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

use crate::audit_log::outbox::test_seam::{self, Stop};

fn owned_fixture(recovery: bool) -> (tempfile::TempDir, PathBuf, Arc<InMemoryTipAnchorStore>) {
    let (dir, path, store) = fixture();
    AuditOutbox::for_log(&path, store.clone())
        .append(&row("closed-raw"))
        .unwrap();
    queue_owned(&path, &store, "closed-tagged", 1);
    if recovery {
        test_seam::arm_stop(&outbox_path(&path), Stop::OwnerStored);
        assert!(matches!(
            AuditWriter::open(path.clone(), Some(access(&store))),
            Err(WriterError::Io(_))
        ));
    } else {
        drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    }
    (dir, path, store)
}

fn queue_owned(path: &Path, store: &Arc<InMemoryTipAnchorStore>, id: &str, evidence: u8) {
    let outbox = AuditOutbox::for_log_keyed(path, store.clone(), Zeroizing::new([0x42; 32]));
    let entry = row(id);
    outbox.append(&entry).unwrap();
    if evidence == 1 {
        let bytes = fs::read(outbox.path()).unwrap();
        let mut lines = bytes
            .split_inclusive(|b| *b == b'\n')
            .map(<[u8]>::to_vec)
            .collect::<Vec<_>>();
        let value: serde_json::Value = serde_json::from_slice(lines.last().unwrap()).unwrap();
        let mut tagged = test_seam::tagged_row(
            &[0x42; 32],
            value["g"].as_u64().unwrap(),
            value["s"].as_u64().unwrap(),
            1,
            &entry,
        )
        .unwrap();
        tagged.push(b'\n');
        *lines.last_mut().unwrap() = tagged;
        fs::write(outbox.path(), lines.concat()).unwrap();
    }
}

fn owner_value(store: &InMemoryTipAnchorStore, generation: u64) -> String {
    store.load_outbox_owner_state(generation).unwrap().unwrap()
}

fn owner_json(store: &InMemoryTipAnchorStore, generation: u64) -> serde_json::Value {
    serde_json::from_str(&owner_value(store, generation)).unwrap()
}

fn acknowledge_open(
    path: &Path,
    store: &Arc<InMemoryTipAnchorStore>,
) -> Result<AuditWriter, WriterError> {
    AuditWriter::open_for_outbox_acknowledgement(
        path.to_path_buf(),
        key(),
        store.clone(),
        BindingHistory::NotRecorded,
    )
}

fn corrupt_middle(path: &Path, row_number: usize) {
    let bytes = fs::read(outbox_path(path)).unwrap();
    let mut lines = bytes
        .split_inclusive(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    lines[row_number] = b"{\"k\":\"row\"}\n".to_vec();
    fs::write(outbox_path(path), lines.concat()).unwrap();
}

fn loss_fixture() -> (tempfile::TempDir, PathBuf, Arc<InMemoryTipAnchorStore>) {
    let fixture = owned_fixture(false);
    let (_, path, store) = &fixture;
    for id in ["selected", "discarded", "after-failure"] {
        queue_owned(path, store, id, 1);
    }
    corrupt_middle(path, 2);
    fixture
}

fn count_id(path: &Path, id: &str) -> usize {
    request_ids(path)
        .iter()
        .filter(|actual| *actual == id)
        .count()
}

/// Owner watches and stages preserve their discriminator through interrupted
/// installation.
#[test]
fn owner_watch_and_stage_forms_never_cross_parse() {
    let (_dir, path, store) = owned_fixture(false);
    queue_owned(&path, &store, "selected", 0);
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    drop(binding);
    let writes = store.outbox_item_writes();
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().carried_rows, 1);
    assert_eq!(
        store.outbox_item_writes(),
        writes,
        "valid owner stage installs without an item write"
    );
    drop(binding);
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    assert_eq!(count_id(&path, "selected"), 1);
}

/// The retired watch hashes the raw owner value and counts every selected row.
#[test]
fn owner_retirement_watch_keeps_hash_and_selected_count() {
    use sha2::{Digest as _, Sha256};
    let (_dir, path, store) = owned_fixture(false);
    for id in ["one", "two", "three"] {
        queue_owned(&path, &store, id, 0);
    }
    let raw = owner_value(&store, 1);
    assert_eq!(owner_json(&store, 1)["closed"]["n"], 2);
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().carried_rows, 3);
    let record = store.load_carrier_record().unwrap().unwrap();
    assert_eq!(
        record.retired.as_ref().unwrap().state,
        format!(
            "owner:sha256:{}:3",
            crate::hex::encode(&Sha256::digest(raw.as_bytes()))
        )
    );
    store.set_outbox_failing(true, false);
    assert_eq!(
        super::super::lock::retired_changed(store.as_ref(), &record).unwrap(),
        None
    );
    store.set_outbox_failing(false, false);
    store.store_outbox_owner_state(1, "changed").unwrap();
    let change = super::super::lock::retired_changed(store.as_ref(), &record)
        .unwrap()
        .unwrap();
    assert_eq!(
        (change.loss().expected_rows, change.loss().found_rows),
        (3, 0)
    );
}

/// Binding preserves every owner field and every complete source byte.
#[test]
fn owner_binding_preserves_state_and_verbatim_rows() {
    for recovery in [false, true] {
        let (_dir, path, store) = owned_fixture(recovery);
        for id in ["one", "two"] {
            queue_owned(&path, &store, id, 1);
        }
        let raw = owner_value(&store, 1);
        let value = owner_json(&store, 1);
        assert!(value["legacy"].is_string());
        assert_eq!(value["recent"].as_array().unwrap().len(), 1);
        let source = fs::read(outbox_path(&path)).unwrap();
        let mut binding =
            AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
        let report = binding.bind_carriers().unwrap();
        assert_eq!(report.carried_rows, if recovery { 4 } else { 2 });
        assert_eq!(
            fs::read(outbox_path(&path)).unwrap(),
            source,
            "header and closed prefix stay verbatim"
        );
        assert_eq!(
            owner_value(&store, 2),
            raw,
            "all owner fields survive binding"
        );
        assert_eq!(store.load_outbox_state(2).unwrap(), None);
        drop(binding);
        drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
        for id in ["closed-raw", "closed-tagged", "one", "two"] {
            assert_eq!(count_id(&path, id), 1);
        }
    }
}

fn rotate_owned(path: &Path, store: &Arc<InMemoryTipAnchorStore>, complete: bool) {
    let mut writer = AuditWriter::open_for_key_rotation(
        path.to_path_buf(),
        key(),
        store.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    store.set_reload(Ok(Some([0x42; 32])));
    writer.fence_outbox_for_key_change().unwrap();
    if complete {
        store.set_reload(Ok(Some([0x24; 32])));
        writer
            .switch_entry_tag_key(Zeroizing::new([0x24; 32]), "rotation")
            .unwrap();
    }
    drop(writer);
    if complete {
        crate::audit_log::resign_chain_root_sidecars(path, &[0x24; 32]).unwrap();
    }
}

/// Binding carries rows under the stored key after a completed rotation.
#[test]
fn a_binding_after_a_completed_rotation_carries_the_owner_queue() {
    let (_dir, path, store) = owned_fixture(false);
    rotate_owned(&path, &store, true);
    let access = || KeyedAuditAccess::new(Zeroizing::new([0x24; 32]), store.clone());
    AuditOutbox::for_log_keyed(&path, store.clone(), Zeroizing::new([0x24; 32]))
        .append(&row("rotated"))
        .unwrap();
    let source = fs::read(outbox_path(&path)).unwrap();
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access()).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().carried_rows, 1);
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), source);
    drop(binding);
    drop(AuditWriter::open(path.clone(), Some(access())).unwrap());
    assert_eq!(count_id(&path, "rotated"), 1);
}

/// A binding stages the fence verbatim and the successor drain signs its
/// generation.
#[test]
fn a_binding_stages_a_fenced_line_and_the_successor_re_signs_it() {
    let (_dir, path, store) = owned_fixture(false);
    rotate_owned(&path, &store, false);
    let fence = test_seam::fence_line(1);
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), fence);
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    assert_eq!(
        fs::read(carriers::generation_path(&path, 2)).unwrap(),
        fence,
        "the stage retains the fence tag"
    );
    drop(binding);
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().carried_rows, 0);
    drop(binding);
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    assert_eq!(
        fs::read(outbox_path(&path)).unwrap(),
        test_seam::generation_line(&[0x42; 32], 1)
    );
}

/// Authenticating a different stage never substitutes it for the selected
/// source.
#[test]
fn owner_stage_rejects_valid_but_different_bytes() {
    for prefix in [false, true] {
        let (_dir, path, store) = owned_fixture(false);
        for id in ["one", "two"] {
            queue_owned(&path, &store, id, 0);
        }
        let source = fs::read(outbox_path(&path)).unwrap();
        let mut binding =
            AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
        assert!(binding.bind_carriers_with_fault(4).is_err());
        drop(binding);
        let mut alternate = test_seam::generation_line(&[0x42; 32], 1);
        if prefix {
            let end = source
                .iter()
                .enumerate()
                .filter(|(_, b)| **b == b'\n')
                .nth(1)
                .unwrap()
                .0
                + 1;
            alternate = source[..end].to_vec();
        } else {
            alternate.extend_from_slice(
                &test_seam::tagged_row(&[0x42; 32], 1, 1, 0, &row("alternate")).unwrap(),
            );
            alternate.push(b'\n');
        }
        fs::write(carriers::generation_path(&path, 2), alternate).unwrap();
        let mut binding =
            AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
        assert_eq!(binding.bind_carriers().unwrap().carried_rows, 2);
        assert_eq!(
            fs::read(outbox_path(&path)).unwrap(),
            source,
            "stage equals the selected source"
        );
    }
}

/// A valid legacy stage carries every byte selected from its source.
#[test]
fn legacy_stage_rejects_valid_but_different_bytes() {
    let (_dir, path, store) = fixture();
    for id in ["one", "two"] {
        queue_owned(&path, &store, id, 0);
    }
    let source = fs::read(outbox_path(&path)).unwrap();
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    drop(binding);
    let end = source.iter().position(|b| *b == b'\n').unwrap() + 1;
    fs::write(carriers::generation_path(&path, 2), &source[..end]).unwrap();
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    let report = binding.bind_carriers().unwrap();
    let installed = fs::read(outbox_path(&path)).unwrap();
    drop(binding);
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    assert_eq!(
        count_id(&path, "two"),
        1,
        "the second source row is delivered"
    );
    assert_eq!(report.carried_rows, 2);
    assert_eq!(installed, source);
}

/// A retained delivery updates the successor evidence even when stage bytes
/// match.
#[cfg(unix)]
#[test]
fn owner_stage_refreshes_a_changed_successor_item() {
    let (_dir, path, store) = owned_fixture(false);
    queue_owned(&path, &store, "retained", 1);
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    let plan = batch
        .owner_plan(store.as_ref(), Some(&[0x42; 32]))
        .unwrap()
        .unwrap();
    let source = fs::read(outbox_path(&path)).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    test_seam::arm_stop(&outbox_path(&path), Stop::OwnerStored);
    assert!(matches!(
        binding.deliver_owner_plan(batch, plan, store.as_ref(), false),
        Err(WriterError::Io(_))
    ));
    drop(binding);
    assert_eq!(count_id(&path, "retained"), 1);
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), source);
    let owner = owner_value(&store, 1);
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(binding.bind_carriers().unwrap().carried_rows, 1);
    drop(binding);
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let loss = writer
        .acknowledge_outbox_loss("retired holder", Default::default())
        .unwrap();
    assert_eq!((loss.expected_rows, loss.found_rows), (1, 0));
    drop(writer);
    drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
    assert_eq!(
        count_id(&path, "retained"),
        1,
        "the holder's row stays delivered"
    );
    assert_eq!(loss.drained, 0);
    assert_eq!(owner_value(&store, 2), owner);
}

/// An empty legacy stage requires an empty successor commitment.
#[cfg(unix)]
#[test]
fn legacy_stage_refreshes_a_changed_successor_commitment() {
    let (_dir, path, store) = fixture();
    let entry = row("R");
    AuditOutbox::for_log(&path, store.clone())
        .append(&entry)
        .unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    let successor = store.load_outbox_state(2).unwrap().unwrap();
    binding.append_checked(entry).unwrap();
    store
        .store_outbox_state(1, &OutboxState::default())
        .unwrap();
    batch.clear().unwrap();
    drop(binding);

    let mut rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(rerun.bind_carriers_with_fault(2).is_err());
    drop(rerun);
    assert!(
        fs::read(carriers::generation_path(&path, 2))
            .unwrap()
            .is_empty()
    );
    // This restores the boundary between the stage write and its state store.
    store.store_outbox_state(2, &successor).unwrap();
    let mut rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert_eq!(rerun.bind_carriers().unwrap().carried_rows, 0);
    drop(rerun);
    assert_eq!(
        store.load_outbox_state(2).unwrap(),
        Some(OutboxState::default()),
        "the empty stage refreshes the successor commitment"
    );
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let loss = writer
        .acknowledge_outbox_loss("retained holder delivery", Default::default())
        .unwrap();
    assert_eq!(
        (loss.expected_rows, loss.found_rows, loss.drained),
        (1, 0, 0)
    );
    drop(writer);
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    assert_eq!(writer.outbox_loss().unwrap(), None);
    assert_eq!(writer.drain_outbox().unwrap(), 0);
    assert_eq!(count_id(&path, "R"), 1);
}

/// Every binding boundary reselects the source and retains the captured watch.
#[test]
fn owner_binding_recovers_every_stage_boundary() {
    for boundary in 1..=6 {
        let (_dir, path, store) = owned_fixture(false);
        queue_owned(&path, &store, "selected", 0);
        let source = fs::read(outbox_path(&path)).unwrap();
        let mut binding =
            AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
        if boundary == 6 {
            binding.binding_fail_after_retire = true;
        }
        let result = if boundary == 6 {
            binding.bind_carriers()
        } else {
            binding.bind_carriers_with_fault(boundary)
        };
        assert!(result.is_err(), "boundary {boundary}");
        drop(binding);
        if boundary == 4 || boundary == 6 {
            fs::write(
                carriers::generation_path(&path, 2),
                test_seam::generation_line(&[0x42; 32], 1),
            )
            .unwrap();
        }
        if boundary == 6 {
            fs::write(outbox_path(&path), b"foreign current queue\n").unwrap();
        }
        if boundary != 5 {
            let mut binding =
                AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
            assert_eq!(
                binding.bind_carriers().unwrap().carried_rows,
                1,
                "boundary {boundary}"
            );
            assert_eq!(
                fs::read(outbox_path(&path)).unwrap(),
                source,
                "boundary {boundary}"
            );
        }
        drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
        assert_eq!(count_id(&path, "selected"), 1, "boundary {boundary}");
    }
}

/// Hard owner failures refuse the report before its caller revokes permissions.
#[test]
fn owner_loss_validates_before_revocation() {
    for case in 0..3 {
        let (_dir, path, store) = loss_fixture();
        let writer = acknowledge_open(&path, &store).unwrap();
        let expected = match case {
            0 => {
                store.store_outbox_owner_state(1, "private-marker").unwrap();
                "outbox owner state is unusable"
            }
            1 => {
                store
                    .store_outbox_owner_state(1, &test_seam::owner_value(u64::MAX, None))
                    .unwrap();
                "queue generation overflows"
            }
            _ => {
                let entry = AuditEntry::new_approval_revoked(
                    "PaymentSimulated",
                    "secret",
                    crate::approval::Surface::Cli,
                    None,
                    "forbidden",
                );
                let mut bytes = test_seam::generation_line(&[0x42; 32], 1);
                bytes.extend_from_slice(
                    &test_seam::tagged_row(&[0x42; 32], 1, 1, 0, &entry).unwrap(),
                );
                bytes.push(b'\n');
                fs::write(outbox_path(&path), bytes).unwrap();
                "audit.outbox_unusable"
            }
        };
        let log = fs::read(&path).unwrap();
        let queue = fs::read(outbox_path(&path)).unwrap();
        let writes = store.outbox_item_writes();
        let mut revoked = false;
        let result = writer.outbox_loss().inspect(|_| revoked = true);
        assert!(!revoked, "hard validation precedes the revocation sentinel");
        let error = result.unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        if case == 2 {
            assert!(matches!(
                error,
                WriterError::OutboxRowKindRefused { line: 2 }
            ));
        }
        assert_eq!(fs::read(&path).unwrap(), log);
        assert_eq!(fs::read(outbox_path(&path)).unwrap(), queue);
        assert_eq!(store.outbox_item_writes(), writes);
    }
    let (_dir, path, store) = loss_fixture();
    let refused = AuditWriter::open_for_outbox_acknowledgement(
        path,
        None,
        store,
        BindingHistory::NotRecorded,
    )
    .err()
    .unwrap();
    assert!(matches!(
        refused,
        WriterError::OutboxUnusable {
            line: 1,
            column: 1,
            reason: "tagged record without an audit key"
        }
    ));
}

/// An acknowledgement without an owner loss writes no file, item, or record.
#[test]
fn owner_acknowledgement_open_refuses_without_a_loss_before_any_write() {
    let (_dir, path, store) = owned_fixture(false);
    queue_owned(&path, &store, "clean", 0);
    let before = (
        fs::read(&path).unwrap(),
        fs::read(outbox_path(&path)).unwrap(),
        owner_value(&store, 1),
        store.load_outbox_state(1).unwrap(),
        store.load_carrier_record().unwrap(),
    );
    assert!(matches!(
        acknowledge_open(&path, &store),
        Err(WriterError::OutboxLossNotFound)
    ));
    let after = (
        fs::read(&path).unwrap(),
        fs::read(outbox_path(&path)).unwrap(),
        owner_value(&store, 1),
        store.load_outbox_state(1).unwrap(),
        store.load_carrier_record().unwrap(),
    );
    assert_eq!(after, before, "classification precedes every open write");
}

/// Selection stops at its first failure and skips the delivered recovery
/// prefix.
#[test]
fn owner_loss_keeps_only_its_authenticated_prefix() {
    for recovery in [false, true] {
        let (_dir, path, store) = owned_fixture(recovery);
        for id in ["selected", "discarded", "after-failure"] {
            queue_owned(&path, &store, id, 1);
        }
        corrupt_middle(&path, if recovery { 3 } else { 2 });
        let mut writer = acknowledge_open(&path, &store).unwrap();
        let loss = writer.outbox_loss().unwrap().unwrap();
        let expected = if recovery { (5, 3) } else { (3, 1) };
        assert_eq!(
            (loss.expected_rows, loss.found_rows),
            expected,
            "header excluded and closed prefix counted"
        );
        let report = writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .unwrap();
        assert_eq!(
            (report.drained, report.discarded),
            (1, 2),
            "only the selected run is delivered"
        );
        for id in ["closed-raw", "closed-tagged", "selected"] {
            assert_eq!(count_id(&path, id), 1, "{id}");
        }
        for id in ["discarded", "after-failure"] {
            assert_eq!(count_id(&path, id), 0, "{id}");
        }
        assert_eq!(owner_json(&store, 1)["g"], if recovery { 1 } else { 2 });
    }
}

fn broken_closed_fixture() -> (tempfile::TempDir, PathBuf, Arc<InMemoryTipAnchorStore>) {
    let fixture = owned_fixture(true);
    let (_, path, store) = &fixture;
    let queue = fs::read(outbox_path(path)).unwrap();
    let mut lines = queue
        .split_inclusive(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let mut alternate =
        test_seam::tagged_row(&[0x42; 32], 0, 2, 1, &row("alternate-closed")).unwrap();
    alternate.push(b'\n');
    lines[1] = alternate;
    fs::write(outbox_path(path), lines.concat()).unwrap();
    queue_owned(path, store, "after-closed", 1);
    fixture
}

/// An acknowledgement requires the anchor even when its selection has no rows.
#[test]
fn owner_loss_without_selected_rows_requires_the_anchor() {
    let (_dir, path, store) = broken_closed_fixture();
    let owner = owner_value(&store, 1);
    let queue = fs::read(outbox_path(&path)).unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    test_seam::arm_stop(&outbox_path(&path), Stop::AnchorChecked);
    assert!(matches!(
        writer.acknowledge_outbox_loss("inspection", Default::default()),
        Err(WriterError::Io(_))
    ));
    assert_eq!(owner_value(&store, 1), owner);
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), queue);
}

/// A broken closed commitment selects nothing and survives an interrupted
/// acknowledgement unchanged.
#[test]
fn owner_loss_discards_a_broken_closed_prefix() {
    let (_dir, path, store) = broken_closed_fixture();
    let owner = owner_value(&store, 1);
    let queue = fs::read(outbox_path(&path)).unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    assert_eq!(
        writer.outbox_loss().unwrap().unwrap(),
        crate::audit_log::outbox::OutboxLoss {
            expected_rows: 3,
            found_rows: 0
        }
    );
    test_seam::arm_stop(&outbox_path(&path), Stop::OwnerStored);
    assert!(
        writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .is_err()
    );
    assert_eq!(
        owner_value(&store, 1),
        owner,
        "the stored closed commitment stays unchanged"
    );
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), queue);
    drop(writer);
    assert!(matches!(
        AuditWriter::open(path.clone(), Some(access(&store))),
        Err(WriterError::OutboxRowsMissing {
            recorded: 2,
            found: 3
        })
    ));
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let report = writer
        .acknowledge_outbox_loss("inspection", Default::default())
        .unwrap();
    assert_eq!((report.drained, report.discarded), (0, 3));
    assert_eq!(owner_value(&store, 1), owner);
    assert_eq!(
        fs::read(outbox_path(&path)).unwrap(),
        test_seam::generation_line(&[0x42; 32], 1)
    );
    assert_eq!(count_id(&path, "after-closed"), 0);
}

/// Acknowledgement boundaries expose repeated appends before the owner store.
#[test]
fn owner_loss_recovers_every_acknowledgement_boundary() {
    for stop in [
        Stop::Acknowledged,
        Stop::AfterAppend(1),
        Stop::AnchorChecked,
        Stop::LegacyZeroed,
        Stop::OwnerStored,
        Stop::ReplacementSynced,
        Stop::Renamed,
        Stop::DirectorySynced,
    ] {
        let (_dir, path, store) = loss_fixture();
        let mut writer = acknowledge_open(&path, &store).unwrap();
        let rewritten = OutboxState::over(&[b"rewrite"]);
        store.store_outbox_state(1, &rewritten).unwrap();
        let owner = owner_value(&store, 1);
        let queue = fs::read(outbox_path(&path)).unwrap();
        test_seam::arm_stop(&outbox_path(&path), stop);
        assert!(
            matches!(
                writer.acknowledge_outbox_loss("inspection", Default::default()),
                Err(WriterError::Io(_))
            ),
            "{stop:?}"
        );
        let stored = matches!(
            stop,
            Stop::OwnerStored | Stop::ReplacementSynced | Stop::Renamed | Stop::DirectorySynced
        );
        let published = matches!(stop, Stop::Renamed | Stop::DirectorySynced);
        if !stored {
            assert_eq!(
                owner_value(&store, 1),
                owner,
                "owner store follows the anchor check: {stop:?}"
            );
        }
        if !published {
            assert_eq!(fs::read(outbox_path(&path)).unwrap(), queue, "{stop:?}");
        }
        let reset = stored || stop == Stop::LegacyZeroed;
        assert_eq!(
            store.load_outbox_state(1).unwrap(),
            Some(if reset {
                OutboxState::default()
            } else {
                rewritten
            }),
            "{stop:?}"
        );
        drop(writer);
        if published {
            drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
            assert!(matches!(
                acknowledge_open(&path, &store),
                Err(WriterError::OutboxLossNotFound)
            ));
        } else {
            assert!(AuditWriter::open(path.clone(), Some(access(&store))).is_err());
            let mut writer = acknowledge_open(&path, &store).unwrap();
            let report = writer
                .acknowledge_outbox_loss("inspection", Default::default())
                .unwrap();
            assert_eq!(report.drained, usize::from(!stored), "{stop:?}");
        }
        let repeated = matches!(
            stop,
            Stop::AfterAppend(_) | Stop::AnchorChecked | Stop::LegacyZeroed
        );
        assert_eq!(
            count_id(&path, "selected"),
            if repeated { 2 } else { 1 },
            "duplicate rows remain visible: {stop:?}"
        );
        assert_eq!(count_id(&path, "after-failure"), 0);
        assert_eq!(owner_json(&store, 1)["g"], 2);
    }
}

/// A rewrite-only header becomes clean at the v1 reset boundary.
#[test]
fn owner_loss_of_a_rewrite_only_finds_none_after_the_reset() {
    let (_dir, path, store) = owned_fixture(false);
    store
        .store_outbox_state(1, &OutboxState::over(&[b"rewrite"]))
        .unwrap();
    let owner = owner_value(&store, 1);
    let queue = fs::read(outbox_path(&path)).unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    test_seam::arm_stop(&outbox_path(&path), Stop::LegacyZeroed);
    assert!(
        writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .is_err()
    );
    assert_eq!(owner_value(&store, 1), owner);
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), queue);
    assert_eq!(
        writer.outbox_loss().unwrap(),
        None,
        "zero v1 leaves no rewrite loss"
    );
    drop(writer);
    assert!(matches!(
        acknowledge_open(&path, &store),
        Err(WriterError::OutboxLossNotFound)
    ));
}

/// Recovery after the owner store meets the same failing row and keeps its
/// generation.
#[test]
fn owner_loss_after_the_owner_store_meets_the_first_failing_line() {
    let (_dir, path, store) = loss_fixture();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    test_seam::arm_stop(&outbox_path(&path), Stop::OwnerStored);
    assert!(
        writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .is_err()
    );
    let owner = owner_value(&store, 1);
    drop(writer);
    assert!(matches!(
        AuditWriter::open(path.clone(), Some(access(&store))),
        Err(WriterError::OutboxUnusable {
            line: 3,
            column: 1,
            reason: "tagged record that does not parse"
        })
    ));
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let report = writer
        .acknowledge_outbox_loss("inspection", Default::default())
        .unwrap();
    assert_eq!((report.drained, report.discarded), (0, 2));
    assert_eq!(
        owner_value(&store, 1),
        owner,
        "recovery keeps its generation and evidence"
    );
    assert_eq!(count_id(&path, "selected"), 1);
}

/// An unidentified header advances the generation on each interrupted
/// publication attempt.
#[test]
fn owner_loss_of_an_unidentified_header_advances_the_generation() {
    let (_dir, path, store) = owned_fixture(false);
    let old = owner_json(&store, 1);
    let mut bytes = test_seam::generation_line(&[0x24; 32], 1);
    bytes.extend_from_slice(
        &test_seam::tagged_row(&[0x24; 32], 1, 1, 1, &row("discarded")).unwrap(),
    );
    bytes.push(b'\n');
    fs::write(outbox_path(&path), &bytes).unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    test_seam::arm_stop(&outbox_path(&path), Stop::OwnerStored);
    assert!(
        writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .is_err()
    );
    assert_eq!(
        owner_json(&store, 1)["g"],
        2,
        "an unidentified header advances g"
    );
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), bytes);
    drop(writer);
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let report = writer
        .acknowledge_outbox_loss("inspection", Default::default())
        .unwrap();
    assert_eq!(
        (
            report.expected_rows,
            report.found_rows,
            report.drained,
            report.discarded
        ),
        (1, 0, 0, 1)
    );
    let new = owner_json(&store, 1);
    assert_eq!(new["g"], 3);
    assert_eq!(new["closed"], old["closed"]);
    assert_eq!(new["recent"], old["recent"]);
    assert_eq!(
        fs::read(outbox_path(&path)).unwrap(),
        test_seam::generation_line(&[0x42; 32], 3)
    );
}

/// A missing or foreign header advances the owner and preserves its evidence.
#[test]
fn owner_loss_of_a_missing_or_foreign_header_advances_the_generation() {
    for foreign in [false, true] {
        for interrupted in [false, true] {
            let (_dir, path, store) = owned_fixture(false);
            for id in ["first", "second"] {
                queue_owned(&path, &store, id, 1);
                drop(AuditWriter::open(path.clone(), Some(access(&store))).unwrap());
            }
            let old = owner_json(&store, 1);
            assert_eq!(old["g"], 3);
            let mut bytes = if foreign {
                test_seam::generation_line(&[0x42; 32], 7)
            } else {
                Vec::new()
            };
            bytes.extend_from_slice(
                &test_seam::tagged_row(&[0x42; 32], 7, 1, 1, &row("discarded")).unwrap(),
            );
            bytes.push(b'\n');
            fs::write(outbox_path(&path), &bytes).unwrap();
            let mut writer = acknowledge_open(&path, &store).unwrap();
            if interrupted {
                test_seam::arm_stop(&outbox_path(&path), Stop::OwnerStored);
            }
            let result = writer.acknowledge_outbox_loss("inspection", Default::default());
            if interrupted {
                assert!(matches!(result, Err(WriterError::Io(_))));
                assert_eq!(fs::read(outbox_path(&path)).unwrap(), bytes);
            } else {
                let report = result.unwrap();
                assert_eq!(
                    (
                        report.expected_rows,
                        report.found_rows,
                        report.drained,
                        report.discarded
                    ),
                    (1, 0, 0, 1)
                );
            }
            let new = owner_json(&store, 1);
            assert_eq!(new["g"], 4, "a missing or foreign header advances g");
            assert_eq!(new["closed"], old["closed"]);
            assert_eq!(new["recent"], old["recent"]);
            assert_eq!(count_id(&path, "discarded"), 0);
        }
    }
}

/// Recent evidence includes selected rows and excludes every discarded digest.
#[test]
fn owner_loss_never_records_discarded_digests() {
    let (_dir, path, store) = owned_fixture(false);
    for id in ["selected", "discarded", "after-failure"] {
        queue_owned(&path, &store, id, 1);
    }
    let bytes = fs::read(outbox_path(&path)).unwrap();
    let lines = bytes.split(|b| *b == b'\n').collect::<Vec<_>>();
    let digest =
        |index| crate::hex::encode(&test_seam::delivered_row_digest(lines[index]).unwrap().1);
    let (selected, discarded, after) = (digest(1), digest(2), digest(3));
    let mut forged = bytes.clone();
    let header_end = lines[0].len() + 1;
    let tag_byte = header_end + lines[1].len() + 1 + lines[2].len() - 3;
    forged[tag_byte] = if forged[tag_byte] == b'0' { b'1' } else { b'0' };
    fs::write(outbox_path(&path), forged).unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    writer
        .acknowledge_outbox_loss("inspection", Default::default())
        .unwrap();
    let value = owner_json(&store, 1);
    let recent = value["recent"].as_array().unwrap();
    assert!(recent.contains(&serde_json::json!(selected)));
    assert!(
        !recent.contains(&serde_json::json!(discarded)),
        "discarded row has no evidence"
    );
    assert!(
        !recent.contains(&serde_json::json!(after)),
        "rows after failure have no evidence"
    );
}

/// A changed owner watch resets only after publication and resets its
/// selected count to zero.
#[test]
fn owner_loss_resets_the_watch_after_publication() {
    let (_dir, path, store) = owned_fixture(false);
    queue_owned(&path, &store, "selected", 0);
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    binding.bind_carriers().unwrap();
    drop(binding);
    let mut bytes = fs::read(outbox_path(&path)).unwrap();
    bytes.extend_from_slice(b"{\"k\":\"row\"}\n");
    fs::write(outbox_path(&path), bytes).unwrap();
    store.store_outbox_owner_state(1, "changed").unwrap();
    let before = store.load_carrier_record().unwrap().unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    test_seam::arm_stop(&outbox_path(&path), Stop::ReplacementSynced);
    assert!(
        writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .is_err()
    );
    assert_eq!(
        store.load_carrier_record().unwrap().unwrap(),
        before,
        "watch reset follows publication"
    );
    drop(writer);
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let report = writer
        .acknowledge_outbox_loss("inspection", Default::default())
        .unwrap();
    assert_eq!((report.drained, report.discarded), (0, 1));
    let mut expected = before;
    expected.retired.as_mut().unwrap().state = super::super::lock::owner_watch("changed", 0);
    assert_eq!(store.load_carrier_record().unwrap().unwrap(), expected);
    drop(writer);
    store.store_outbox_owner_state(1, "changed again").unwrap();
    let queue = fs::read(outbox_path(&path)).unwrap();
    let owner = owner_value(&store, 2);
    let state = store.load_outbox_state(2).unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let report = writer
        .acknowledge_outbox_loss("watch only", Default::default())
        .unwrap();
    assert_eq!(
        (
            report.expected_rows,
            report.found_rows,
            report.drained,
            report.discarded
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(fs::read(outbox_path(&path)).unwrap(), queue);
    assert_eq!(owner_value(&store, 2), owner);
    assert_eq!(store.load_outbox_state(2).unwrap(), state);
}

/// Publication under a recovery guard refuses a carrier change after syncing
/// its replacement.
#[test]
fn recovery_publication_refuses_a_changed_carrier_generation() {
    let (_dir, path, store) = loss_fixture();
    let queue = fs::read(outbox_path(&path)).unwrap();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let changed = store.clone();
    test_seam::on_replacement_synced(&outbox_path(&path), move || {
        let mut record = changed.load_carrier_record().unwrap().unwrap();
        record.generation += 1;
        changed.store_carrier_record(&record).unwrap();
    });
    assert!(matches!(
        writer.acknowledge_outbox_loss("inspection", Default::default()),
        Err(WriterError::CarrierGenerationChanged {
            held: 1,
            current: 2
        })
    ));
    assert_eq!(
        fs::read(outbox_path(&path)).unwrap(),
        queue,
        "generation check precedes rename"
    );
}

/// Production operations expose the exact static diagnostic fields.
pub(super) fn owner_diagnostic_failures() -> Vec<(WriterError, String)> {
    let mut cases = Vec::new();
    let unusable = |line, column, reason: &str| {
        format!(
            "audit.outbox_unusable: line {line} of the audit outbox is unusable ({reason} at column {column}); the outbox is left unchanged"
        )
    };
    let missing = |recorded, found| WriterError::OutboxRowsMissing { recorded, found }.to_string();
    for (replacement, expected) in [
        (
            test_seam::generation_line(&[0x42; 32], 1),
            unusable(2, 1, "generation line out of place"),
        ),
        (
            b"{\"k\":\"row\"}\n".to_vec(),
            unusable(2, 1, "tagged record that does not parse"),
        ),
        (b"raw\n".to_vec(), missing(1, 0)),
        (
            {
                let mut bytes =
                    test_seam::tagged_row(&[0x24; 32], 1, 1, 0, &row("foreign")).unwrap();
                bytes.push(b'\n');
                bytes
            },
            unusable(2, 1, "tagged record whose tag does not verify"),
        ),
        (
            {
                let mut bytes = test_seam::tagged_row(&[0x42; 32], 1, 4, 0, &row("moved")).unwrap();
                bytes.push(b'\n');
                bytes
            },
            missing(1, 4),
        ),
    ] {
        let (_dir, path, store) = owned_fixture(false);
        let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
        let mut bytes = test_seam::generation_line(&[0x42; 32], 1);
        bytes.extend_from_slice(&replacement);
        fs::write(outbox_path(&path), bytes).unwrap();
        cases.push((writer.drain_outbox().unwrap_err(), expected));
    }
    for (bytes, expected) in [
        (
            b"{\"k\":\"gen\"}\n".to_vec(),
            unusable(1, 1, "tagged record that does not parse"),
        ),
        (test_seam::generation_line(&[0x42; 32], 9), missing(0, 0)),
    ] {
        let (_dir, path, store) = owned_fixture(false);
        fs::write(outbox_path(&path), bytes).unwrap();
        cases.push((
            crate::audit_log::outbox::check_outbox_commitment(&path, store.as_ref()).unwrap_err(),
            expected,
        ));
    }
    let (_dir, path, store) = loss_fixture();
    let mut bytes = test_seam::generation_line(&[0x24; 32], 1);
    bytes.extend_from_slice(&test_seam::tagged_row(&[0x42; 32], 1, 1, 0, &row("queued")).unwrap());
    bytes.push(b'\n');
    fs::write(outbox_path(&path), bytes).unwrap();
    store.set_reload(Ok(Some([0x42; 32])));
    cases.push((
        crate::audit_log::outbox::check_outbox_commitment(&path, store.as_ref()).unwrap_err(),
        unusable(1, 1, "tagged record whose tag does not verify"),
    ));
    let (_dir, path, store) = fixture();
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    fs::write(
        outbox_path(&path),
        test_seam::generation_line(&[0x42; 32], 1),
    )
    .unwrap();
    cases.push((
        writer.drain_outbox().unwrap_err(),
        unusable(1, 1, "tagged record that does not parse"),
    ));
    drop(writer);
    let (_dir, path, store) = loss_fixture();
    cases.push((
        AuditWriter::open_for_outbox_acknowledgement(
            path.clone(),
            None,
            store.clone(),
            BindingHistory::NotRecorded,
        )
        .err()
        .unwrap(),
        unusable(1, 1, "tagged record without an audit key"),
    ));
    store
        .store_outbox_owner_state(1, &test_seam::owner_value(u64::MAX, None))
        .unwrap();
    cases.push((
        acknowledge_open(&path, &store).err().unwrap(),
        unusable(1, 1, "queue generation overflows"),
    ));
    store.store_outbox_owner_state(1, "private-marker").unwrap();
    cases.push((acknowledge_open(&path, &store).err().unwrap(), "audit.tip_anchor_unavailable: audit log tip anchor unavailable: audit tip anchor store: outbox owner state is unusable".to_owned()));
    let (_dir, path, store) = owned_fixture(false);
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    store
        .store_outbox_state(1, &OutboxState::over(&[b"rewrite"]))
        .unwrap();
    cases.push((
        writer.drain_outbox().unwrap_err(),
        unusable(1, 1, "legacy outbox state changed in the owner state"),
    ));
    drop(writer);
    let (_dir, path, store) = broken_closed_fixture();
    cases.push((
        crate::audit_log::outbox::check_outbox_commitment(&path, store.as_ref()).unwrap_err(),
        missing(2, 3),
    ));
    let (_dir, path, store) = owned_fixture(false);
    store.set_reload(Err("private-marker"));
    cases.push((crate::audit_log::outbox::check_outbox_commitment(&path, store.as_ref()).unwrap_err(), "audit.tip_anchor_unavailable: audit log tip anchor unavailable: audit tip anchor store: audit key reload failed".to_owned()));
    let (_dir, path, store) = owned_fixture(false);
    let mut record = store.load_carrier_record().unwrap().unwrap();
    for watch in ["owner:sha256:invalid:01", "private-marker"] {
        record.retired = Some(RetiredOutbox {
            generation: 0,
            state: watch.to_owned(),
            file: None,
        });
        store.store_carrier_record(&record).unwrap();
        cases.push((crate::audit_log::outbox::check_outbox_commitment(&path, store.as_ref()).unwrap_err(), "audit.tip_anchor_unavailable: audit log tip anchor unavailable: audit tip anchor store: retired outbox state is unusable".to_owned()));
    }
    let (_dir, path, store) = loss_fixture();
    let mut writer = acknowledge_open(&path, &store).unwrap();
    let changed = store.clone();
    test_seam::on_replacement_synced(&outbox_path(&path), move || {
        let mut record = changed.load_carrier_record().unwrap().unwrap();
        record.generation = 2;
        changed.store_carrier_record(&record).unwrap();
    });
    cases.push((
        writer
            .acknowledge_outbox_loss("inspection", Default::default())
            .unwrap_err(),
        WriterError::CarrierGenerationChanged {
            held: 1,
            current: 2,
        }
        .to_string(),
    ));
    drop(writer);
    let (_dir, path, store) = owned_fixture(false);
    store.set_reload(Ok(Some([0x24; 32])));
    cases.push((
        acknowledge_open(&path, &store).err().unwrap(),
        "audit.key_replaced: the audit key this writer loaded is not the profile's stored audit key; no row was written; open the log again to load the stored key".to_owned(),
    ));
    let (_dir, path, store) = owned_fixture(false);
    cases.push((
        acknowledge_open(&path, &store).err().unwrap(),
        "audit.outbox_loss_not_found: no committed outbox loss was found; nothing was acknowledged"
            .to_owned(),
    ));
    let mut rotation = AuditWriter::open_for_key_rotation(
        path.clone(),
        key(),
        store.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let mut bytes = test_seam::generation_line(&[0x42; 32], 1);
    bytes.extend_from_slice(&test_seam::tagged_row(&[0x42; 32], 1, 1, 0, &row("queued")).unwrap());
    bytes.push(b'\n');
    fs::write(outbox_path(&path), bytes).unwrap();
    cases.push((
        rotation.fence_outbox_for_key_change().unwrap_err(),
        unusable(1, 1, "queue not drained before a key change"),
    ));
    drop(rotation);
    for (line, column, reason) in [
        ("private-marker", 1, "invalid JSON"),
        ("{}", 2, "JSON that is not an audit entry"),
        ("{", 1, "truncated JSON"),
    ] {
        let (_dir, path, store) = fixture();
        let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
        fs::write(outbox_path(&path), format!("{line}\n")).unwrap();
        store
            .store_outbox_state(1, &OutboxState::over(&[line.as_bytes()]))
            .unwrap();
        cases.push((
            writer.drain_outbox().unwrap_err(),
            unusable(1, column, reason),
        ));
    }
    let (_dir, path, store) = owned_fixture(false);
    let entry = AuditEntry::new_approval_revoked(
        "PaymentSimulated",
        "secret",
        crate::approval::Surface::Cli,
        None,
        "forbidden",
    );
    let mut bytes = test_seam::generation_line(&[0x42; 32], 1);
    bytes.extend_from_slice(&test_seam::tagged_row(&[0x42; 32], 1, 1, 0, &entry).unwrap());
    bytes.push(b'\n');
    fs::write(outbox_path(&path), bytes).unwrap();
    cases.push((
        acknowledge_open(&path, &store).err().unwrap(),
        WriterError::OutboxRowKindRefused { line: 2 }.to_string(),
    ));
    let (_dir, path, store) = owned_fixture(false);
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    let mut body = row("noncanonical").canonical_json_body().unwrap();
    body.insert(1, b' ');
    use hmac::{KeyInit as _, Mac as _};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&[0x42; 32]).unwrap();
    mac.update(b"stellar-agent-outbox-row:v2");
    mac.update(&1_u64.to_be_bytes());
    mac.update(&1_u64.to_be_bytes());
    mac.update(&[0]);
    mac.update(&body);
    let mut bytes = test_seam::generation_line(&[0x42; 32], 1);
    bytes.extend_from_slice(b"{\"k\":\"row\",\"g\":1,\"s\":1,\"r\":0,\"body\":");
    bytes.extend_from_slice(&body);
    bytes.extend_from_slice(
        format!(
            ",\"tag\":\"{}\"}}\n",
            crate::hex::encode(&mac.finalize().into_bytes())
        )
        .as_bytes(),
    );
    fs::write(outbox_path(&path), bytes).unwrap();
    cases.push((
        writer.drain_outbox().unwrap_err(),
        unusable(2, 1, "tagged record that is not canonical"),
    ));
    drop(writer);
    let (_dir, path, store) = fixture();
    queue_owned(&path, &store, "tagged", 0);
    let mut bytes = fs::read(outbox_path(&path)).unwrap();
    bytes.extend_from_slice(b"raw\n");
    fs::write(outbox_path(&path), bytes).unwrap();
    cases.push((
        AuditWriter::open(path.clone(), Some(access(&store)))
            .err()
            .unwrap(),
        missing(2, 0),
    ));
    cases.push((
        AuditWriter::open_for_carrier_binding(path.clone(), access(&store))
            .err()
            .unwrap(),
        missing(2, 0),
    ));
    let (_dir, path, store) = owned_fixture(false);
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    queue_owned(&path, &store, "closed", 0);
    test_seam::arm_stop(&outbox_path(&path), Stop::OwnerStored);
    assert!(writer.drain_outbox().is_err());
    let mut bytes = test_seam::generation_line(&[0x42; 32], 1);
    bytes.extend_from_slice(b"raw\n");
    fs::write(outbox_path(&path), bytes).unwrap();
    cases.push((writer.drain_outbox().unwrap_err(), missing(1, 0)));
    drop(writer);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store = Arc::new(InMemoryTipAnchorStore::new());
    let mut writer = AuditWriter::open_with_tip_anchor(
        path.clone(),
        None,
        store.clone(),
        BindingHistory::NotRecorded,
    )
    .unwrap();
    let mut bytes = test_seam::tagged_row(&[0x42; 32], 0, 1, 0, &row("keyless")).unwrap();
    bytes.push(b'\n');
    fs::write(outbox_path(&path), bytes).unwrap();
    cases.push((
        writer.drain_outbox().unwrap_err(),
        unusable(1, 1, "tagged record without an audit key"),
    ));
    cases
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
fn an_interrupted_binding_recognizes_a_holder_delivery_before_its_clear() {
    assert_interrupted_legacy_holder_delivery(&["R"], true, false, None);
}

#[cfg(unix)]
#[test]
fn an_interrupted_binding_replays_a_holder_delivery_before_its_reset() {
    assert_interrupted_legacy_holder_delivery(&["R"], false, false, None);
}

#[cfg(unix)]
#[test]
fn an_interrupted_binding_recognizes_a_holder_delivery_after_its_clear() {
    assert_interrupted_legacy_holder_delivery(&["R"], true, true, None);
}

#[cfg(unix)]
#[test]
fn an_interrupted_binding_recognizes_two_holder_rows_before_their_clear() {
    assert_interrupted_legacy_holder_delivery(&["R", "S"], true, false, None);
}

#[cfg(unix)]
#[test]
fn an_interrupted_binding_keeps_holder_delivery_recognized_across_restage_stops() {
    for step in 2..=4 {
        assert_interrupted_legacy_holder_delivery(&["R"], true, false, Some(step));
    }
}

#[cfg(unix)]
fn assert_interrupted_legacy_holder_delivery(
    ids: &[&str],
    reset: bool,
    clear: bool,
    restage_stop: Option<u8>,
) {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    let entries = ids.iter().map(|id| row(id)).collect::<Vec<_>>();
    for entry in &entries {
        outbox.append(entry).unwrap();
    }
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    for entry in entries {
        binding.append_checked(entry).unwrap();
    }
    drop(binding);
    if reset {
        store
            .store_outbox_state(1, &OutboxState::default())
            .unwrap();
    }
    if clear {
        batch.clear().unwrap();
    } else {
        drop(batch);
    }
    let mut rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    if let Some(step) = restage_stop {
        assert!(rerun.bind_carriers_with_fault(step).is_err());
        drop(rerun);
        rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    }
    let result = rerun.bind_carriers();
    assert!(
        result.is_ok(),
        "the interrupted binding completes after the holder delivery: {result:?}"
    );
    let report = result.unwrap();
    assert_eq!(report.generation, 2);
    assert_eq!(
        report.carried_rows,
        if reset { 0 } else { ids.len() as u64 }
    );
    drop(rerun);
    assert!(!carriers::generation_path(&path, 2).exists());
    if reset {
        assert_eq!(
            store.load_outbox_state(2).unwrap(),
            Some(OutboxState::default())
        );
        assert!(matches!(
            AuditWriter::open(path.clone(), Some(access(&store))),
            Err(WriterError::RetiredOutboxChanged { generation: 1 })
        ));
        let mut writer = acknowledge_open(&path, &store).unwrap();
        let watch = writer.outbox_loss().unwrap().unwrap();
        assert_eq!(
            (watch.expected_rows, watch.found_rows),
            (ids.len() as u64, 0)
        );
        let loss = writer
            .acknowledge_outbox_loss("retained holder delivery", Default::default())
            .unwrap();
        assert_eq!(
            (loss.expected_rows, loss.found_rows, loss.drained),
            (ids.len() as u64, 0, 0)
        );
    }
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    assert_eq!(writer.outbox_loss().unwrap(), None);
    assert_eq!(writer.drain_outbox().unwrap(), 0);
    writer.write_entry(row("continued")).unwrap();
    drop(writer);
    for id in ids {
        assert_eq!(count_id(&path, id), if reset { 1 } else { 2 });
    }
    assert_eq!(count_id(&path, "continued"), 1);
}

#[cfg(unix)]
#[test]
fn an_interrupted_binding_refuses_a_source_with_only_its_prefix_delivered() {
    assert_interrupted_legacy_partial_delivery(0);
}

#[cfg(unix)]
#[test]
fn an_interrupted_binding_refuses_a_source_with_only_its_suffix_delivered() {
    assert_interrupted_legacy_partial_delivery(1);
}

#[cfg(unix)]
fn assert_interrupted_legacy_partial_delivery(delivered: usize) {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    let entries = [row("R"), row("S")];
    for entry in &entries {
        outbox.append(entry).unwrap();
    }
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    let source = fs::read(outbox.path()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    binding.append_checked(entries[delivered].clone()).unwrap();
    store
        .store_outbox_state(1, &OutboxState::default())
        .unwrap();
    drop(batch);
    drop(binding);
    let successor = store.load_outbox_state(2).unwrap();
    let mut rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(matches!(
        rerun.bind_carriers(),
        Err(WriterError::OutboxRowsMissing {
            recorded: 1,
            found: 0
        })
    ));
    drop(rerun);
    assert_eq!(fs::read(outbox.path()).unwrap(), source);
    assert_eq!(
        fs::read(carriers::generation_path(&path, 2)).unwrap(),
        source
    );
    assert_eq!(store.load_outbox_state(2).unwrap(), successor);
    assert!(matches!(
        AuditWriter::open(path.clone(), Some(access(&store))),
        Err(WriterError::CarrierBindingIncomplete)
    ));
    assert_eq!(count_id(&path, &entries[delivered].request_id), 1);
    assert_eq!(count_id(&path, &entries[1 - delivered].request_id), 0);
}

#[cfg(unix)]
#[test]
fn a_retained_batch_clearing_during_an_interrupted_binding_is_reported_as_a_loss() {
    let (_dir, path, store) = fixture();
    let outbox = AuditOutbox::for_log(&path, store.clone());
    outbox.append(&row("R")).unwrap();
    let batch = OutboxBatch::read_locked(&path, store.as_ref()).unwrap();
    replace(&outbox_lock_path(&path));
    let mut binding = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    assert!(binding.bind_carriers_with_fault(4).is_err());
    // The retained holder appends before resetting its commitment and clearing
    // the source. The binding writer supplies the log append at this boundary.
    binding.append_checked(row("R")).unwrap();
    drop(binding);
    assert_eq!(store.load_carrier_record().unwrap().unwrap().generation, 2);

    // The changed watch records the loss, and the empty source prevents a
    // second delivery of the holder's row from the interrupted stage.
    store
        .store_outbox_state(1, &OutboxState::default())
        .unwrap();
    batch.clear().unwrap();

    let mut rerun = AuditWriter::open_for_carrier_binding(path.clone(), access(&store)).unwrap();
    let report = rerun.bind_carriers().unwrap();
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
    drop(acknowledgement);
    let mut writer = AuditWriter::open(path.clone(), Some(access(&store))).unwrap();
    assert_eq!(writer.drain_outbox().unwrap(), 0);
    drop(writer);
    assert_eq!(
        request_ids(&path)
            .iter()
            .filter(|id| id.as_str() == "R")
            .count(),
        1
    );
    assert_eq!((report.generation, report.carried_rows), (2, 0));
    assert_eq!(
        (loss.expected_rows, loss.found_rows, loss.drained),
        (1, 0, 0)
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
