use super::*;

fn arm(
    cell: &'static std::thread::LocalKey<Hook>,
    hook: impl FnOnce() -> Result<(), MppError> + 'static,
) {
    cell.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

fn counters(store: &MppAuthorizationStore) -> (Option<u64>, Option<u64>) {
    (
        load_generation(&store.generation_entry).expect("committed"),
        load_intent(&store.generation_intent_entry).expect("intent"),
    )
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn seal(store: &MppAuthorizationStore, generation: u64) {
    let wire = WireStore {
        version: STORE_VERSION,
        generation,
        pruned_through: 0,
        records: Vec::new(),
    };
    let body = serde_json::to_vec(&wire).expect("body");
    let tag = compute_tag(&store.key, &body).expect("tag");
    fs::write(&store.path, [tag.as_slice(), body.as_slice()].concat()).expect("snapshot");
}

#[cfg(unix)]
fn change_lock(path: &Path, change: &str) {
    let lock_path = sibling_path(path, ".lock");
    fs::remove_file(&lock_path).expect("unlink held lock");
    match change {
        "replace" => fs::write(lock_path, b"").expect("replacement lock"),
        "symlink" => std::os::unix::fs::symlink(path, lock_path).expect("symlink lock"),
        "directory" => fs::create_dir(lock_path).expect("directory lock"),
        "unlink" => {}
        _ => unreachable!("known change"),
    }
}

#[cfg(unix)]
#[allow(
    clippy::print_stderr,
    reason = "race evidence records public digests and counters"
)]
fn boundary(label: &str, store: &MppAuthorizationStore) {
    let digest = hex::encode(Sha256::digest(fs::read(&store.path).expect("snapshot")));
    eprintln!("{label}: sha256={digest} counters={:?}", counters(store));
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn same_generation_winner_survives() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let now = 1_700_000_000;
    store.prune(now).expect("initial snapshot");
    boundary("prepare A", &store);
    let other = test_store(store.path.clone(), [7; 32]);
    let (prepared, _, _) = prepared_fixture(now).await;
    let winner =
        AuthorizationRecord::new("winner", TESTNET_PASSPHRASE, &prepared, now).expect("record");
    let id = winner.authorization_id().to_owned();
    let saved = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured = saved.clone();
    arm(&BEFORE_INTENT_WRITE, move || {
        change_lock(&other.path, "unlink");
        other.insert_prepared(winner, now).expect("B succeeds");
        boundary("B commits", &other);
        *captured.borrow_mut() = fs::read(&other.path).expect("winning snapshot");
        Ok(())
    });
    assert_eq!(
        store.prune(now).expect_err("A refuses").message(),
        concurrent_update_error().message()
    );
    boundary("A refuses", &store);
    assert_eq!(fs::read(&store.path).expect("survivor"), *saved.borrow());
    assert_eq!(counters(&store), (Some(2), Some(2)));
    assert_eq!(
        store.load(&id).expect("winner survives").authorization_id(),
        id
    );
}

#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn stale_commit_cannot_enable_rollback() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let now = 1_700_000_000;
    store.prune(now).expect("initial snapshot");
    boundary("prepare A", &store);
    let other = test_store(store.path.clone(), [7; 32]);
    let (prepared, _, _) = prepared_fixture(now).await;
    let winner =
        AuthorizationRecord::new("winner", TESTNET_PASSPHRASE, &prepared, now).expect("record");
    let id = winner.authorization_id().to_owned();
    let saved = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured = saved.clone();
    let winning = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured_winner = winning.clone();
    arm(&BEFORE_GENERATION_WRITE, move || {
        boundary("A publishes", &other);
        *captured.borrow_mut() = fs::read(&other.path).expect("A snapshot");
        change_lock(&other.path, "unlink");
        other
            .load(UNKNOWN_ID)
            .expect_err("recovery reads an empty snapshot");
        assert_eq!(counters(&other), (Some(2), Some(2)));
        boundary("B recovers A", &other);
        other.insert_prepared(winner, now).expect("B succeeds");
        boundary("B commits", &other);
        *captured_winner.borrow_mut() = fs::read(&other.path).expect("B snapshot");
        Ok(())
    });
    assert_eq!(
        store.prune(now).expect_err("A refuses").message(),
        concurrent_update_error().message()
    );
    boundary("A refuses", &store);
    assert_eq!(counters(&store), (Some(3), Some(3)));
    assert_eq!(
        fs::read(&store.path).expect("winner bytes"),
        *winning.borrow()
    );
    assert_eq!(
        store.load(&id).expect("winner survives").authorization_id(),
        id
    );
    fs::write(&store.path, &*saved.borrow()).expect("restore A snapshot");
    boundary("restore A snapshot", &store);
    for error in [
        store.load(&id).expect_err("rollback read"),
        store.prune(now).expect_err("rollback mutation"),
    ] {
        assert_eq!(error.message(), rollback_error().message());
    }
    assert_eq!(counters(&store), (Some(3), Some(3)));
}

/// A reset that loses its lock after key rotation preserves the snapshot
/// and record a second reset publishes through its own lock.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn a_reset_after_key_rotation_preserves_the_winner() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let path = directory.path().join("state");
    let key_ref = state_key_coordinates("reset-rotation-race");
    let store = MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref).expect("store");
    let now = 1_700_000_000;
    store.prune(now).expect("snapshot");
    put_raw(&store.generation_entry, "bad");
    put_raw(&store.generation_intent_entry, "5");
    fs::write(&path, b"invalid snapshot").expect("unverifiable file");
    let winner_now = now + MAX_CHALLENGE_LIFETIME_SECS + 1;
    let (prepared, _, _) = prepared_fixture(winner_now).await;
    let winner = AuthorizationRecord::new("winner", TESTNET_PASSPHRASE, &prepared, winner_now)
        .expect("record");
    let id = winner.authorization_id().to_owned();
    let saved = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured = saved.clone();
    let other_path = path.clone();
    let other_key = key_ref.clone();
    arm(&AFTER_KEY_ROTATION, move || {
        change_lock(&other_path, "replace");
        let outcome = MppAuthorizationStore::reset_at(
            other_path.clone(),
            &other_key,
            TEST_PROFILE_NAME,
            now,
            |_| Ok(()),
        )
        .expect("B discards");
        assert_eq!(outcome.carried_generation, None);
        let other =
            MppAuthorizationStore::open_for_prepare_at(other_path, &other_key).expect("B opens");
        assert_eq!(counters(&other), (Some(6), Some(6)));
        other
            .insert_prepared(winner, winner_now)
            .expect("B commits a record");
        assert_eq!(counters(&other), (Some(7), Some(7)));
        boundary("B commits after key rotation", &other);
        *captured.borrow_mut() = fs::read(&other.path).expect("winning snapshot");
        Ok(())
    });
    assert_eq!(
        MppAuthorizationStore::reset_at(path.clone(), &key_ref, TEST_PROFILE_NAME, now, |_| Ok(()))
            .expect_err("A refuses")
            .message(),
        concurrent_update_error().message()
    );
    assert_eq!(
        fs::read(&path).expect("winner snapshot survives"),
        *saved.borrow()
    );
    assert_eq!(counters(&store), (Some(7), Some(7)));
    let fresh = MppAuthorizationStore::open_for_prepare_at(path, &key_ref).expect("winner opens");
    assert_eq!(
        fresh
            .load(&id)
            .expect("winner record survives")
            .authorization_id(),
        id
    );
    boundary("A refuses after key rotation", &fresh);
}

/// Writer B runs after A reserved generation two, so B targets three. The
/// identity check before A's atomic replacement refuses A, and B's snapshot
/// and record survive.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn a_writer_after_the_reservation_keeps_its_snapshot() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let now = 1_700_000_000;
    store.prune(now).expect("initial snapshot");
    let other = test_store(store.path.clone(), [7; 32]);
    let (prepared, _, _) = prepared_fixture(now).await;
    let winner =
        AuthorizationRecord::new("winner", TESTNET_PASSPHRASE, &prepared, now).expect("record");
    let id = winner.authorization_id().to_owned();
    let saved = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured = saved.clone();
    arm(&AFTER_RESERVATION, move || {
        assert_eq!(counters(&other), (Some(1), Some(2)));
        change_lock(&other.path, "unlink");
        other.insert_prepared(winner, now).expect("B succeeds");
        assert_eq!(counters(&other), (Some(3), Some(3)));
        *captured.borrow_mut() = fs::read(&other.path).expect("winning snapshot");
        Ok(())
    });
    assert_eq!(
        store.prune(now).expect_err("A refuses").message(),
        concurrent_update_error().message()
    );
    assert_eq!(
        digest(&fs::read(&store.path).expect("survivor")),
        digest(&saved.borrow())
    );
    assert_eq!(counters(&store), (Some(3), Some(3)));
    assert_eq!(
        store.load(&id).expect("winner survives").authorization_id(),
        id
    );
}

/// Writer B commits twice after A's reservation checks pass and before A's
/// intent write. The identity check before that write refuses A, so the
/// intent keeps B's higher value and B's snapshot and record survive.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn a_writer_before_the_intent_write_keeps_its_counters() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let now = 1_700_000_000;
    store.prune(now).expect("initial snapshot");
    let other = test_store(store.path.clone(), [7; 32]);
    let (prepared, _, _) = prepared_fixture(now).await;
    let winner =
        AuthorizationRecord::new("winner", TESTNET_PASSPHRASE, &prepared, now).expect("record");
    let id = winner.authorization_id().to_owned();
    let saved = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured = saved.clone();
    arm(&AFTER_RESERVATION_CHECKS, move || {
        assert_eq!(counters(&other), (Some(1), Some(1)));
        change_lock(&other.path, "unlink");
        other.insert_prepared(winner, now).expect("B first write");
        other.prune(now).expect("B second write");
        assert_eq!(counters(&other), (Some(3), Some(3)));
        *captured.borrow_mut() = fs::read(&other.path).expect("winning snapshot");
        Ok(())
    });
    assert_eq!(
        store.prune(now).expect_err("A refuses").message(),
        concurrent_update_error().message()
    );
    assert_eq!(counters(&store), (Some(3), Some(3)));
    assert_eq!(
        digest(&fs::read(&store.path).expect("survivor")),
        digest(&saved.borrow())
    );
    assert_eq!(
        store.load(&id).expect("winner survives").authorization_id(),
        id
    );
}

/// Writer B runs after A published generation two and A's commit re-reads
/// passed. B completes A's commit and commits three. The identity check
/// before A's committed write refuses A, so the committed counter stays at
/// three and A's restored snapshot reads as rolled back.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn a_writer_before_the_committed_write_keeps_its_counters() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let now = 1_700_000_000;
    store.prune(now).expect("initial snapshot");
    let other = test_store(store.path.clone(), [7; 32]);
    let (prepared, _, _) = prepared_fixture(now).await;
    let winner =
        AuthorizationRecord::new("winner", TESTNET_PASSPHRASE, &prepared, now).expect("record");
    let id = winner.authorization_id().to_owned();
    let published = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured_publication = published.clone();
    let saved = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured = saved.clone();
    arm(&AFTER_COMMIT_CHECKS, move || {
        assert_eq!(counters(&other), (Some(1), Some(2)));
        *captured_publication.borrow_mut() = fs::read(&other.path).expect("A snapshot");
        change_lock(&other.path, "unlink");
        other.insert_prepared(winner, now).expect("B succeeds");
        assert_eq!(counters(&other), (Some(3), Some(3)));
        *captured.borrow_mut() = fs::read(&other.path).expect("winning snapshot");
        Ok(())
    });
    assert_eq!(
        store.prune(now).expect_err("A refuses").message(),
        concurrent_update_error().message()
    );
    assert_eq!(counters(&store), (Some(3), Some(3)));
    assert_eq!(
        digest(&fs::read(&store.path).expect("survivor")),
        digest(&saved.borrow())
    );
    assert_eq!(
        store.load(&id).expect("winner survives").authorization_id(),
        id
    );
    fs::write(&store.path, &*published.borrow()).expect("restore A snapshot");
    assert_eq!(
        store.load(&id).expect_err("rollback read").message(),
        rollback_error().message()
    );
}

/// A lock path replaced between the final identity check and a counter write
/// lets the write land, and the check after it reports the write as
/// unconfirmed with its own message.
#[cfg(unix)]
#[test]
#[serial_test::serial]
fn a_counter_write_that_loses_the_lock_window_is_unconfirmed() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    for committed in [false, true] {
        for change in ["replace", "unlink"] {
            let directory = TempDir::new().expect("directory");
            let store = test_store(directory.path().join("state"), [7; 32]);
            store.prune(0).expect("snapshot");
            let bytes = fs::read(&store.path).expect("snapshot");
            let path = store.path.clone();
            let lose_window = move || {
                arm(&AFTER_COUNTER_IDENTITY, move || {
                    change_lock(&path, change);
                    Ok(())
                });
                Ok(())
            };
            if committed {
                arm(&AFTER_PUBLICATION, lose_window);
            } else {
                lose_window().expect("arm");
            }
            let error = store.prune(0).expect_err("unconfirmed write");
            assert_eq!(error.code(), STATE_CODE);
            assert_eq!(
                error.message(),
                lock_window_error().message(),
                "{change} during the {} write",
                if committed { "committed" } else { "intent" }
            );
            if committed {
                assert_eq!(counters(&store), (Some(2), Some(2)));
            } else {
                assert_eq!(counters(&store), (Some(1), Some(2)));
                assert_eq!(fs::read(&store.path).expect("snapshot"), bytes);
            }
        }
    }
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn acquisition_checks_lock_identity() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    for change in ["replace", "unlink", "symlink", "directory"] {
        let directory = TempDir::new().expect("directory");
        let store = test_store(directory.path().join("state"), [7; 32]);
        let path = store.path.clone();
        arm(&AFTER_LOCK_ACQUIRED, move || {
            change_lock(&path, change);
            Ok(())
        });
        assert!(
            store.acquire_lock().is_err(),
            "acquisition refuses {change}"
        );
        assert_eq!(counters(&store), (Some(0), None));
        assert!(!store.path.exists());
    }
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn publication_rechecks_lock_identity() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    for change in ["replace", "unlink", "symlink", "directory"] {
        let directory = TempDir::new().expect("directory");
        let store = test_store(directory.path().join("state"), [7; 32]);
        store.prune(0).expect("snapshot");
        let bytes = fs::read(&store.path).expect("snapshot");
        let path = store.path.clone();
        arm(&BEFORE_PUBLICATION, move || {
            change_lock(&path, change);
            Ok(())
        });
        assert!(store.prune(0).is_err(), "publication refuses {change}");
        assert_eq!(
            fs::read(&store.path).expect("snapshot"),
            bytes,
            "publication preserves snapshot"
        );
        assert_eq!(counters(&store), (Some(1), Some(2)));
    }
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn counter_writes_recheck_lock_identity() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    for phase in ["initialize", "reserve", "commit", "recover"] {
        for change in ["replace", "unlink", "symlink", "directory"] {
            let directory = TempDir::new().expect("directory");
            let store = test_store(directory.path().join("state"), [7; 32]);
            let lock = store.acquire_lock().expect("lock");
            if phase == "initialize" {
                keyring_core::Entry::new(
                    &store.generation_entry.service,
                    &store.generation_entry.account,
                )
                .expect("entry")
                .delete_credential()
                .expect("absent counter");
            } else if phase != "reserve" {
                seal(&store, 1);
                put_raw(&store.generation_intent_entry, "1");
            }
            let before = counters(&store);
            let path = store.path.clone();
            let hook = if phase == "reserve" {
                &BEFORE_INTENT_WRITE
            } else {
                &BEFORE_GENERATION_WRITE
            };
            arm(hook, move || {
                change_lock(&path, change);
                Ok(())
            });
            let result = match phase {
                "initialize" => store.initialize_generation(&lock),
                "reserve" => store.reserve_generation(&lock, &Observed::new(Some(0), None), 1),
                "commit" => store.commit_generation(&lock, &Counter::Value(0), 1),
                "recover" => store.read_verified(&lock).map(|_| ()),
                _ => unreachable!("known phase"),
            };
            assert!(result.is_err(), "{phase} refuses {change}");
            assert_eq!(counters(&store), before, "{phase} preserves counters");
        }
    }
}

#[test]
#[serial_test::serial]
fn reservation_requires_exact_committed_and_strict_intent() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let other = test_store(store.path.clone(), [7; 32]);
    let lock = store.acquire_lock().expect("lock");
    assert!(
        other.acquire_lock().is_err(),
        "separate open descriptions conflict"
    );
    store
        .reserve_generation(&lock, &Observed::new(Some(0), None), 1)
        .expect("first reservation");
    drop(lock);
    let lock = other.acquire_lock().expect("second description");
    for proposed in [1, 0] {
        assert!(
            other
                .reserve_generation(&lock, &Observed::new(Some(0), Some(1)), proposed)
                .is_err(),
            "equal or lower intent refuses"
        );
        assert_eq!(counters(&store), (Some(0), Some(1)));
        assert!(!store.path.exists());
    }
    assert!(
        other
            .reserve_generation(&lock, &Observed::new(Some(0), None), 2)
            .is_err(),
        "stale observed intent refuses"
    );
    assert_eq!(counters(&store), (Some(0), Some(1)));
    put_raw(&store.generation_entry, "4");
    assert!(
        other
            .reserve_generation(&lock, &Observed::new(Some(0), Some(1)), 5)
            .is_err(),
        "stale expected committed refuses"
    );
    assert!(
        other
            .reserve_generation(&lock, &Observed::new(Some(4), Some(1)), 4)
            .is_err(),
        "a proposal equal to the committed counter refuses"
    );
    assert_eq!(counters(&store), (Some(4), Some(1)));
    other
        .reserve_generation(&lock, &Observed::new(Some(4), Some(1)), 5)
        .expect("exact observation with a strictly higher proposal");
    assert_eq!(counters(&store), (Some(4), Some(5)));
}

#[test]
#[serial_test::serial]
fn commit_requires_exact_committed_and_owned_intent() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let lock = store.acquire_lock().expect("lock");
    seal(&store, 2);
    let bytes = fs::read(&store.path).expect("snapshot");
    for (committed, intent, expected) in [
        (1, 2, 0),
        (5, 2, 0),
        (2, 2, 0),
        (2, 2, 2),
        (0, 3, 0),
        (0, 1, 0),
    ] {
        put_raw(&store.generation_entry, &committed.to_string());
        put_raw(&store.generation_intent_entry, &intent.to_string());
        assert!(
            store
                .commit_generation(&lock, &Counter::Value(expected), 2)
                .is_err(),
            "competing commit refuses"
        );
        assert_eq!(counters(&store), (Some(committed), Some(intent)));
        assert_eq!(fs::read(&store.path).expect("snapshot"), bytes);
    }
    put_raw(&store.generation_entry, "0");
    put_raw(&store.generation_intent_entry, "2");
    store
        .commit_generation(&lock, &Counter::Value(0), 2)
        .expect("owned commit");
    assert_eq!(counters(&store), (Some(2), Some(2)));
}

#[test]
#[serial_test::serial]
fn recovery_refuses_a_competing_counter_advance() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    seal(&store, 1);
    put_raw(&store.generation_intent_entry, "1");
    let entry = store.generation_entry.clone();
    arm(&BEFORE_GENERATION_WRITE, move || {
        put_raw(&entry, "5");
        Ok(())
    });
    assert!(
        store.read_for_test().is_err(),
        "recovery refuses the competing advance"
    );
    assert_eq!(counters(&store), (Some(5), Some(1)));
    assert_eq!(
        store.load(UNKNOWN_ID).expect_err("rollback").message(),
        rollback_error().message()
    );
}

#[test]
#[serial_test::serial]
fn reads_enforce_the_committed_high_water_mark() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    seal(&store, 1);
    put_raw(&store.generation_intent_entry, "1");
    put_raw(&store.generation_entry, "2");
    assert_eq!(
        store
            .load(UNKNOWN_ID)
            .expect_err("rollback before lookup")
            .message(),
        rollback_error().message()
    );
    assert_eq!(
        store.prune(0).expect_err("rollback mutation").message(),
        rollback_error().message()
    );
    assert_eq!(counters(&store), (Some(2), Some(1)));
    put_raw(&store.generation_entry, "1");
    assert_eq!(
        store.load(UNKNOWN_ID).expect_err("empty snapshot").code(),
        NOT_FOUND_CODE
    );
    put_raw(&store.generation_entry, "0");
    assert_eq!(
        store
            .load(UNKNOWN_ID)
            .expect_err("recovered snapshot")
            .code(),
        NOT_FOUND_CODE
    );
    assert_eq!(counters(&store), (Some(1), Some(1)));
    fs::remove_file(&store.path).expect("remove snapshot");
    assert_eq!(
        store
            .load(UNKNOWN_ID)
            .expect_err("missing snapshot")
            .message(),
        rollback_error().message()
    );
}

#[tokio::test]
#[serial_test::serial]
async fn crash_boundaries_preserve_records_and_burn_generations() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    for (hook, publishes) in [
        (&AFTER_RESERVATION, false),
        (&BEFORE_PUBLICATION, false),
        (&AFTER_PUBLICATION, true),
        (&BEFORE_GENERATION_WRITE, true),
    ] {
        let directory = TempDir::new().expect("directory");
        let store = test_store(directory.path().join("state"), [7; 32]);
        let now = 1_700_000_000;
        let (prepared, _, _) = prepared_fixture(now).await;
        let record = AuthorizationRecord::new("retained", TESTNET_PASSPHRASE, &prepared, now)
            .expect("record");
        let id = record.authorization_id().to_owned();
        store
            .insert_prepared(record, now)
            .expect("acknowledged record");
        let bytes = fs::read(&store.path).expect("snapshot");
        arm(hook, || Err(state_error()));
        assert!(store.prune(now).is_err(), "crash boundary refuses");
        assert_eq!(counters(&store), (Some(1), Some(2)));
        if !publishes {
            assert_eq!(fs::read(&store.path).expect("snapshot"), bytes);
        }
        assert_eq!(
            store
                .load(&id)
                .expect("acknowledged record survives")
                .authorization_id(),
            id
        );
        assert_eq!(counters(&store).0, Some(if publishes { 2 } else { 1 }));
        store.prune(now).expect("next generation");
        assert_eq!(
            counters(&store),
            (Some(3), Some(3)),
            "burned generation is not reused"
        );
    }
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn initialization_and_adoption_refuse_losing_handles() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    for adopt in [false, true] {
        let directory = TempDir::new().expect("directory");
        let path = directory.path().join("state");
        let key_ref = state_key_coordinates(if adopt {
            "adoption-race"
        } else {
            "initialization-race"
        });
        if adopt {
            rotate_keyring_secret_32(&key_ref.service, &key_ref.account).expect("key");
            let key = load_hmac_key_32(&key_ref).expect("key");
            let body = br#"{"version":1,"records":[]}"#;
            let tag = compute_tag(&key, body).expect("tag");
            fs::write(&path, [tag.as_slice(), body.as_slice()].concat()).expect("legacy snapshot");
        }
        let other_path = path.clone();
        let other_key = key_ref.clone();
        arm(
            if adopt {
                &BEFORE_INTENT_WRITE
            } else {
                &BEFORE_GENERATION_WRITE
            },
            move || {
                change_lock(&other_path, "unlink");
                MppAuthorizationStore::open_for_prepare_audited_at(
                    other_path,
                    &other_key,
                    TEST_PROFILE_NAME,
                    |_| Ok(()),
                )
                .expect("winning opener");
                Ok(())
            },
        );
        let error = MppAuthorizationStore::open_for_prepare_audited_at(
            path.clone(),
            &key_ref,
            TEST_PROFILE_NAME,
            |_| Ok(()),
        )
        .expect_err("losing opener");
        assert_eq!(error.message(), concurrent_update_error().message());
        let winner = MppAuthorizationStore::open_for_prepare_audited_at(
            path,
            &key_ref,
            TEST_PROFILE_NAME,
            |_| Ok(()),
        )
        .expect("winner remains readable");
        assert_eq!(
            counters(&winner),
            if adopt {
                (Some(1), Some(1))
            } else {
                (Some(0), None)
            }
        );
    }
}

/// The key mint rechecks the lock path immediately before its keyring write,
/// so a losing opener neither mints a key nor replaces the key a winner
/// minted and published under.
#[cfg(unix)]
#[test]
#[serial_test::serial]
fn the_key_mint_rechecks_lock_identity() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    for change in ["replace", "unlink", "symlink", "directory"] {
        let directory = TempDir::new().expect("directory");
        let path = directory.path().join("state");
        let key_ref = state_key_coordinates(&format!("mint-{change}"));
        let changed = path.clone();
        arm(&BEFORE_KEY_MINT, move || {
            change_lock(&changed, change);
            Ok(())
        });
        let error = MppAuthorizationStore::open_for_prepare_audited_at(
            path.clone(),
            &key_ref,
            TEST_PROFILE_NAME,
            |_| Ok(()),
        )
        .expect_err("mint refuses a changed lock path");
        assert_eq!(
            error.message(),
            concurrent_update_error().message(),
            "mint refuses {change}"
        );
        assert!(
            key_is_absent(&key_ref).expect("key lookup"),
            "no key is minted after {change}"
        );
        assert!(!path.exists());
    }
    let directory = TempDir::new().expect("directory");
    let path = directory.path().join("state");
    let key_ref = state_key_coordinates("mint-winner");
    let saved = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let captured = saved.clone();
    let winner_path = path.clone();
    let winner_ref = key_ref.clone();
    arm(&BEFORE_KEY_MINT, move || {
        change_lock(&winner_path, "unlink");
        let winner = MppAuthorizationStore::open_for_prepare_audited_at(
            winner_path.clone(),
            &winner_ref,
            TEST_PROFILE_NAME,
            |_| Ok(()),
        )
        .expect("winning opener");
        winner.prune(0).expect("winning snapshot");
        *captured.borrow_mut() = fs::read(&winner_path).expect("winning snapshot");
        Ok(())
    });
    let error = MppAuthorizationStore::open_for_prepare_audited_at(
        path.clone(),
        &key_ref,
        TEST_PROFILE_NAME,
        |_| Ok(()),
    )
    .expect_err("losing opener");
    assert_eq!(error.message(), concurrent_update_error().message());
    assert_eq!(fs::read(&path).expect("snapshot"), *saved.borrow());
    let winner = MppAuthorizationStore::open_for_prepare_audited_at(
        path,
        &key_ref,
        TEST_PROFILE_NAME,
        |_| Ok(()),
    )
    .expect("winning snapshot authenticates");
    assert_eq!(counters(&winner), (Some(1), Some(1)));
}

#[test]
#[serial_test::serial]
fn initialization_refuses_a_counter_that_appears() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let key_ref = state_key_coordinates("initialization-compare");
    let anchor = generation_entry_ref(&key_ref);
    let entry = anchor.clone();
    arm(&BEFORE_GENERATION_WRITE, move || {
        put_raw(&entry, "0");
        Ok(())
    });
    assert!(
        MppAuthorizationStore::open_for_prepare_at(directory.path().join("state"), &key_ref)
            .is_err(),
        "appearing anchor refuses"
    );
    assert_eq!(load_generation(&anchor).expect("anchor"), Some(0));
    assert!(key_is_absent(&key_ref).expect("key remains absent"));
}

#[tokio::test]
#[serial_test::serial]
async fn both_reset_paths_preserve_the_trusted_maximum() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let path = directory.path().join("state");
    let key_ref = state_key_coordinates("reset-high-water");
    let store = MppAuthorizationStore::open_for_prepare_at(path.clone(), &key_ref).expect("store");
    let now = 1_700_000_000;
    let (prepared, _, _) = prepared_fixture(now).await;
    let record =
        AuthorizationRecord::new("retained", TESTNET_PASSPHRASE, &prepared, now).expect("record");
    let id = record.authorization_id().to_owned();
    store.insert_prepared(record, now).expect("record");
    let key = load_hmac_key_32(&key_ref).expect("key");
    put_raw(&store.generation_entry, "8");
    put_raw(&store.generation_intent_entry, "11");
    let carried =
        MppAuthorizationStore::reset_at(path.clone(), &key_ref, TEST_PROFILE_NAME, now, |_| Ok(()))
            .expect("carry");
    assert_eq!(carried.carried_records, 1);
    assert_eq!(counters(&store), (Some(12), Some(12)));
    assert_eq!(*load_hmac_key_32(&key_ref).expect("key"), *key);
    assert_eq!(
        store.load(&id).expect("carried record").status(),
        AuthorizationStatus::ExpiredUnresolved
    );
    put_raw(&store.generation_intent_entry, "15");
    fs::write(&path, b"invalid snapshot").expect("tamper");
    let anchor = store.generation_entry.clone();
    let intent = store.generation_intent_entry.clone();
    arm(&BEFORE_INTENT_WRITE, move || {
        assert_eq!(
            load_generation(&anchor).expect("rotation counter"),
            Some(12)
        );
        assert_eq!(load_intent(&intent).expect("rotation intent"), Some(15));
        Ok(())
    });
    let discarded =
        MppAuthorizationStore::reset_at(path.clone(), &key_ref, TEST_PROFILE_NAME, now, |_| Ok(()))
            .expect("rotate");
    assert_eq!(discarded.carried_records, 0);
    assert_eq!(counters(&store), (Some(16), Some(16)));
    assert_ne!(*load_hmac_key_32(&key_ref).expect("key"), *key);
    assert_eq!(
        store.load(&id).expect_err("cached key refuses").message(),
        rollback_error().message()
    );
    let fresh = MppAuthorizationStore::open_for_prepare_at(path, &key_ref).expect("fresh handle");
    let wire = fresh.read_for_test().expect("fresh snapshot");
    assert!(wire.records.is_empty());
    assert_eq!(wire.pruned_through, now + MAX_CHALLENGE_LIFETIME_SECS);
}

#[cfg(windows)]
#[test]
fn held_lock_denies_delete_and_rename() {
    let directory = TempDir::new().expect("directory");
    let path = directory.path().join("state");
    let store = MppAuthorizationStore::at_path(
        path.clone(),
        [7; 32],
        KeyringEntryRef::new("lock-sharing", "generation"),
    );
    let lock = store.acquire_lock().expect("lock");
    let lock_path = sibling_path(&path, ".lock");
    assert!(
        fs::remove_file(&lock_path).is_err(),
        "delete sharing is denied"
    );
    assert!(
        fs::rename(&lock_path, directory.path().join("renamed")).is_err(),
        "rename is denied"
    );
    lock.verify_identity().expect("identity remains valid");
    drop(lock);
    fs::rename(&lock_path, directory.path().join("renamed")).expect("rename after release");
}

/// A malformed counter is observed by its exact bytes. The reservation, for
/// either counter, and the committed-counter commit refuse changed bytes and
/// proceed on identical ones.
#[test]
#[serial_test::serial]
fn malformed_counter_comparisons_require_exact_bytes() {
    stellar_agent_test_support::keyring_mock::install().expect("keyring");
    let directory = TempDir::new().expect("directory");
    let store = test_store(directory.path().join("state"), [7; 32]);
    let lock = store.acquire_lock().expect("lock");
    seal(&store, 2);
    let bytes = fs::read(&store.path).expect("snapshot");
    for (commit, intent) in [(false, false), (false, true), (true, false)] {
        for changed in [true, false] {
            put_raw(&store.generation_entry, "0");
            put_raw(&store.generation_intent_entry, "1");
            let entry_ref = if intent {
                &store.generation_intent_entry
            } else {
                &store.generation_entry
            };
            let entry =
                keyring_core::Entry::new(&entry_ref.service, &entry_ref.account).expect("entry");
            entry.set_secret(&[0xff]).expect("observed bytes");
            let expected = Observed {
                committed: Counter::read(&store.generation_entry).expect("committed"),
                intent: Counter::read(&store.generation_intent_entry).expect("intent"),
            };
            if changed {
                entry.set_secret(&[0xfe]).expect("competing bytes");
            }
            if commit {
                put_raw(&store.generation_intent_entry, "2");
            }
            let result = if commit {
                store.commit_generation(&lock, &expected.committed, 2)
            } else {
                store.reserve_generation(&lock, &expected, 2)
            };
            let written = if commit {
                &store.generation_entry
            } else {
                &store.generation_intent_entry
            };
            if changed {
                assert_eq!(
                    result.expect_err("changed bytes refuse").message(),
                    concurrent_update_error().message()
                );
                assert_eq!(entry.get_secret().expect("counter bytes"), [0xfe]);
                assert_ne!(Counter::read(written).expect("counter"), Counter::Value(2));
            } else {
                result.expect("identical bytes proceed");
                assert_eq!(Counter::read(written).expect("counter"), Counter::Value(2));
                if !intent && !commit {
                    assert_eq!(entry.get_secret().expect("counter bytes"), [0xff]);
                }
            }
            assert_eq!(fs::read(&store.path).expect("snapshot"), bytes);
        }
    }
}
