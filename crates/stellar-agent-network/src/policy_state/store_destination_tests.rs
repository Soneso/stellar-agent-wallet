const DESTINATION_LEGACY_BODY: &str = r#"{"chain_scope":{"chain":"stellar:testnet","network_passphrase_sha256":[206,224,48,45,89,132,77,50,189,202,145,92,130,3,221,68,179,63,187,126,220,25,5,30,163,122,190,223,40,236,212,114]},"version":12,"generation":7,"entries":[{"scope_specificity":1,"bucket":"native","window_secs":60,"records":[{"chain_scope":{"chain":"stellar:testnet","network_passphrase_sha256":[206,224,48,45,89,132,77,50,189,202,145,92,130,3,221,68,179,63,187,126,220,25,5,30,163,122,190,223,40,236,212,114]},"execution_bound":61000,"accounting_until_ms":121000,"admitted_window_ms":60000,"ts_ms":1000,"amount":"300","id":"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","status":"accounting_expired","tx_hash":"abababababababababababababababababababababababababababababababab","source":"GSOURCE","sequence":9,"max_time":61,"pending_since_ms":1000,"submission_ledger":1000,"operator_required":false}]},{"scope_specificity":1,"bucket":"native","window_secs":86400,"records":[{"chain_scope":{"chain":"stellar:testnet","network_passphrase_sha256":[206,224,48,45,89,132,77,50,189,202,145,92,130,3,221,68,179,63,187,126,220,25,5,30,163,122,190,223,40,236,212,114]},"admitted_window_ms":86400000,"ts_ms":1000,"amount":"40","id":"e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2","status":"pending","tx_hash":"abababababababababababababababababababababababababababababababab","source":"GSOURCE","sequence":10,"max_time":0,"pending_since_ms":1000,"submission_ledger":1000,"operator_required":false},{"ts_ms":1000,"amount":"7","id":"","status":"confirmed","tx_hash":"","source":"","sequence":0,"max_time":0,"pending_since_ms":0,"submission_ledger":0,"operator_required":false}]}],"authorizations":[{"id":"3333333333333333333333333333333333333333333333333333333333333333","profile":"intent","chain":"stellar:testnet","domain":"transaction","consumer":"cli_pay","content_digest":"56c7962e9f26b46fb66d793017822eee1603519e00a855341729cf18af15e3c4","binding":{"transaction":{"unsigned_envelope_sha256":"3131313131313131313131313131313131313131313131313131313131313131","tx_hash":"3232323232323232323232323232323232323232323232323232323232323232","source":"GSOURCE","sequence":11}},"state":"open","minted_ms":1000,"expires_ms":604801000,"policy_sequence":1,"policy_digest":"0101010101010101010101010101010101010101010101010101010101010101","approval_nonce":"intent-open","approval_expires_ms":604801000,"bindings_digest":"0202020202020202020202020202020202020202020202020202020202020202","entries_digest":"0303030303030303030303030303030303030303030303030303030303030303","reservation":"3333333333333333333333333333333333333333333333333333333333333333"},{"id":"3434343434343434343434343434343434343434343434343434343434343434","profile":"intent","chain":"stellar:testnet","domain":"soroban","consumer":"x402_create","content_digest":"f1b00da714f0136828d068f4e590ae41d9fb5c8a48c6a17d57e26ba3472470a9","binding":{"soroban":{"intent_digest":"3434343434343434343434343434343434343434343434343434343434343434"}},"state":"expired","minted_ms":1,"expires_ms":2,"settled_ms":1000,"policy_sequence":1,"policy_digest":"0101010101010101010101010101010101010101010101010101010101010101","policy_authority":{"policy_digest":"0101010101010101010101010101010101010101010101010101010101010101","policy_sequence":1,"rule_index":2,"evaluated_at_ms":1000,"governing_until_ms":604801000,"scope":{"kind":"classic"}},"bindings_digest":"0202020202020202020202020202020202020202020202020202020202020202","entries_digest":"0303030303030303030303030303030303030303030303030303030303030303"}],"holds":[{"kind":"value","authorization_id":"3333333333333333333333333333333333333333333333333333333333333333","ordinal":0,"scope_specificity":1,"bucket":"native","window_secs":60,"ts_ms":1000,"amount":"5"}],"accounting_expiries":[{"decision_id":"ea04d2a485346305476b280cb76a286baed3c8c9f17e009787d64f3f459ecb46","chain_scope":{"chain":"stellar:testnet","network_passphrase_sha256":[206,224,48,45,89,132,77,50,189,202,145,92,130,3,221,68,179,63,187,126,220,25,5,30,163,122,190,223,40,236,212,114]},"reservation_id":"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","tx_hash":"abababababababababababababababababababababababababababababababab","source":"GSOURCE","sequence":9,"max_time":61,"submission_ledger":1000,"generation":3,"disposition":"accounting_expired","observed_at_ms":121001,"accounting_until_ms":121000,"audit_acknowledged":false,"receipt_projected":false}],"signed_intents":[{"intent_id":"intent-79667c951988be5ebd0459cab17b3740b1760c626a00b90f7130e54f660af593","chain_scope":{"chain":"stellar:testnet","network_passphrase_sha256":[206,224,48,45,89,132,77,50,189,202,145,92,130,3,221,68,179,63,187,126,220,25,5,30,163,122,190,223,40,236,212,114]},"auth_address":"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF","envelope_source":"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF","envelope_sequence":1,"host_invocation_sha256":"0fa70075b4842d7358994728d5dba7bf6d1a96097a8d47c8f9e8619aa81253d7","subjects":[],"greatest_expiration_ledger":100,"purpose":"Invoke","envelope_max_ledger":100,"admitted_window_ms":60000,"legs":[{"scope_specificity":1,"bucket":"native","window_secs":60,"ts_ms":1000,"amount":"60"},{"scope_specificity":1,"bucket":"rate_limit","window_secs":60,"ts_ms":1000,"amount":"1"}],"admitted_at_ms":1000,"generation":1,"status":"Exposed","cancel_token_sha256":"6671ee70c5900cde7c80bcc619eda2cdf986367950c09541ffaa7cb47d2721ca"}]}"#;
const DESTINATION_LEGACY_DIGEST: &str =
    "4bbe1cd433fa3bdde43ccc7f9a5281155f89d81ee40e0def2a28808bcf2a129f";

#[test]
#[serial]
fn a_stale_second_process_keeps_the_destination() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use std::io::{BufRead as _, Write as _};
    const CHILD: &str = "STELLAR_AGENT_DESTINATION_WINDOW_CHILD";
    let role_dir = std::env::var_os(CHILD);
    let parent_dir = role_dir.is_none().then(|| TempDir::new().unwrap());
    let dir = role_dir
        .as_ref()
        .map(std::path::Path::new)
        .unwrap_or_else(|| parent_dir.as_ref().unwrap().path());
    let backend: std::sync::Arc<keyring_core::CredentialStore> =
        std::sync::Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            dir.join("keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(std::sync::Arc::new(
                zeroize::Zeroizing::new([7; 32]),
            )),
        ));
    keyring_core::set_default_store(backend);
    let profile = test_profile(dir, "destinations");
    let store = PersistedWindowStore::at_path(dir.join("destinations.window"));
    let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let first = destination_hold(&"a1".repeat(32), 1);
    let second = destination_hold(&"a2".repeat(32), 2);
    let mut third = destination_hold(&"a3".repeat(32), 3);
    third.destinations =
        PaymentDestinations::Single(crate::submit::destination_tests::muxed_destination(0));
    if role_dir.is_some() {
        let before = store.pending_reservations(&profile).unwrap();
        assert_eq!(before, vec![first.clone()]);
        DESTINATION_BEFORE_LOCK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(|| {
                writeln!(std::io::stdout(), "DESTINATION_READY").unwrap();
                std::io::stdout().flush().unwrap();
                let mut signal = String::new();
                std::io::stdin().read_line(&mut signal).unwrap();
            }))
        });
        store
            .record_pending(&profile, &[destination_entry(3)], &third)
            .unwrap();
        let holds = store.pending_reservations(&profile).unwrap();
        assert_eq!(holds.len(), 2);
        assert_eq!(holds[0].destinations, second.destinations);
        assert_eq!(holds[1].destinations, third.destinations);
        assert!(!store.holds_reservation(&profile, &first.id).unwrap());
        return;
    }
    store
        .record_pending(&profile, &[destination_entry(7)], &first)
        .unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "policy_state::store::tests::a_stale_second_process_keeps_the_destination",
            "--nocapture",
        ])
        .env(CHILD, dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert_ne!(
            output.read_line(&mut line).unwrap(),
            0,
            "child reaches the hook"
        );
        if line.contains("DESTINATION_READY") {
            break;
        }
    }
    store.release(&profile, &first.id).unwrap();
    clock.set(1000 + RETENTION_MS + 1);
    store
        .record_pending(&profile, &[destination_entry(9)], &second)
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"continue\n")
        .unwrap();
    assert!(child.wait().unwrap().success());
    assert_eq!(
        store.pending_reservations(&profile).unwrap(),
        vec![second, third]
    );
}

#[test]
fn a_crash_between_receipt_and_reservation_keeps_the_destination_in_a_receipt_only_hold() {
    let dir = TempDir::new().unwrap();
    let receipts = ReceiptStore::open_at(dir.path(), "destinations").unwrap();
    let hold = destination_hold(&"a1".repeat(32), 1);
    receipts
        .try_begin_to(
            &hold.id,
            &hold.tx_hash,
            &hold.source,
            hold.sequence,
            0,
            1000,
            &hold.destinations,
        )
        .unwrap();
    assert_eq!(
        reservation_from_receipt(&receipts, &hold.id, hold.chain_scope)
            .unwrap()
            .destinations,
        hold.destinations
    );
}

fn destination_hold(id: &str, sequence: i64) -> SubmissionHold {
    let mut hold = reservation(id, "GSOURCE", sequence, 1000);
    hold.destinations = crate::submit::destination_tests::destination_provenance();
    hold
}

fn destination_fixture() -> (TempDir, Profile, PersistedWindowStore) {
    keyring_mock::install().unwrap();
    let dir = TempDir::new().unwrap();
    let profile = test_profile(dir.path(), "destinations");
    let store = PersistedWindowStore::at_path(dir.path().join("destinations.window"));
    (dir, profile, store)
}

fn destination_entry(amount: i128) -> WindowEntry {
    entry(key("destinations", "native", 60), 1000, amount)
}

#[test]
#[serial]
fn reservations_carry_destinations_at_the_current_version() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    assert_eq!(WIRE_VERSION_MAX, WIRE_VERSION_TOTAL_SUMS);
    assert_eq!(
        serde_json::from_str::<StoredDestinations>("null").unwrap(),
        StoredDestinations::Null
    );
    let (_dir, profile, store) = destination_fixture();
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let hold = destination_hold(&"a1".repeat(32), 1);
    store
        .record_pending(&profile, &[destination_entry(7)], &hold)
        .unwrap();
    let wire = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(wire.version, WIRE_VERSION_DESTINATION);
    assert_eq!(WIRE_VERSION_MAX, WIRE_VERSION_TOTAL_SUMS);
    assert_eq!(
        store.pending_reservations(&profile).unwrap()[0].destinations,
        hold.destinations
    );
    assert_eq!(
        serde_json::to_value(&wire.entries[0].records[0]).unwrap()["destinations"],
        hold.destinations.to_stored().unwrap()
    );

    let (_dir, profile, store, _plan) = progress_fixture();
    let (state_key, _) = store.load_or_mint_key(&profile).unwrap();
    let gen_entry = generation_entry_ref(&profile);
    let legacy: WireFile = serde_json::from_str(DESTINATION_LEGACY_BODY).unwrap();
    assert_eq!(body_digest(&legacy).unwrap(), DESTINATION_LEGACY_DIGEST);
    assert_eq!(
        stellar_agent_core::hex::encode(&Sha256::digest(DESTINATION_LEGACY_BODY.as_bytes())),
        DESTINATION_LEGACY_DIGEST
    );
    store
        .write_atomic_raw(
            &compute_tag(state_key.as_ref(), DESTINATION_LEGACY_BODY.as_bytes()).unwrap(),
            DESTINATION_LEGACY_BODY.as_bytes(),
        )
        .unwrap();
    put_raw(
        &generation_entry_ref(&profile),
        &serde_json::to_string(&GenerationCommitment {
            generation: legacy.generation,
            body_sha256: DESTINATION_LEGACY_DIGEST.to_owned(),
        })
        .unwrap(),
    );
    let loaded = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(
        serde_json::to_string(&loaded).unwrap(),
        DESTINATION_LEGACY_BODY
    );
    assert_eq!(loaded.accounting_expiries.len(), 1);
    assert!(
        collect_pending(&loaded)
            .unwrap()
            .iter()
            .all(|hold| hold.destinations == PaymentDestinations::None)
    );
    assert_eq!(
        loaded.accounting_expiries[0].projection().destinations,
        PaymentDestinations::None
    );
    for destinations in [
        StoredDestinations::Null,
        StoredDestinations::Value(serde_json::json!({"invalid": true})),
    ] {
        for location in 0..3 {
            let mut candidate = loaded.clone();
            match location {
                0 => candidate.entries[0].records[0].destinations = destinations.clone(),
                1 => candidate.accounting_expiries[0].destinations = destinations.clone(),
                _ => {
                    candidate.authorizations[0].consumption =
                        Some(ledger::ConsumptionBinding::Transaction(ledger::SubmissionBinding {
                            destinations: destinations.clone(),
                            chain_scope: Some(hold.chain_scope),
                            fee_bump: None,
                            envelope_hash: [1; 32],
                            tx_hash: [2; 32],
                            source: hold.source.clone(),
                            sequence: hold.sequence,
                            max_time: hold.max_time,
                            pending_since_ms: hold.pending_since_ms,
                            submission_ledger: hold.submission_ledger,
                            submission_anchor: None,
                        }));
                }
            }
            assert_eq!(select_wire_version(&candidate, None), WIRE_VERSION_DESTINATION);
            assert_eq!(
                select_wire_version(&candidate, Some(WIRE_VERSION_RECOVERY_RUN)),
                WIRE_VERSION_DESTINATION
            );
        }
    }
    let entries = serde_json::to_value(&loaded.entries).unwrap();
    store.record_and_persist(&profile, &[]).unwrap();
    let unchanged = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(unchanged.version, WIRE_VERSION_TOTAL_EPOCH);
    assert_eq!(serde_json::to_value(&unchanged.entries).unwrap(), entries);
    for (committed, expected) in [
        (None, WIRE_VERSION_TOTAL_EPOCH),
        (Some(WIRE_VERSION_TOTAL_EPOCH), WIRE_VERSION_TOTAL_EPOCH),
        (Some(WIRE_VERSION_RECOVERY_RUN), WIRE_VERSION_RECOVERY_RUN),
        (Some(WIRE_VERSION_DESTINATION), WIRE_VERSION_DESTINATION),
    ] {
        assert_eq!(select_wire_version(&unchanged, committed), expected);
    }
    let mut successor = unchanged.clone();
    successor.accounting_expiries[0].destinations = (&hold.destinations).into();
    store
        .commit_generation(&state_key, &gen_entry, unchanged, successor)
        .unwrap();
    let upgraded = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(upgraded.version, WIRE_VERSION_DESTINATION);
    assert_eq!(serde_json::to_value(&upgraded.entries).unwrap(), entries);

    let capped = |wire: &WireFile| {
        let body = serde_json::to_vec(wire).unwrap();
        let mut bytes = compute_tag(state_key.as_ref(), &body).unwrap().to_vec();
        bytes.extend(body);
        DESTINATION_READER_CAP.set(Some(WIRE_VERSION_DESTINATION - 1));
        let result = store.verify_with_key(&state_key, &bytes);
        DESTINATION_READER_CAP.set(None);
        result
    };
    assert!(capped(&legacy).is_ok());
    assert!(matches!(
        capped(&upgraded),
        Err(WindowStoreError::UnsupportedVersion)
    ));
    let mut prepared = legacy.clone();
    prepared.prepared = Some(Box::new(upgraded.clone()));
    assert!(matches!(
        capped(&prepared),
        Err(WindowStoreError::UnsupportedVersion)
    ));

    let mut explicit = upgraded;
    explicit.entries[1].records[0].destinations = StoredDestinations::Null;
    let body = serde_json::to_vec(&explicit).unwrap();
    assert!(String::from_utf8_lossy(&body).contains("\"destinations\":null"));
    store
        .write_atomic_raw(&compute_tag(state_key.as_ref(), &body).unwrap(), &body)
        .unwrap();
    put_raw(
        &generation_entry_ref(&profile),
        &serde_json::to_string(&GenerationCommitment {
            generation: explicit.generation,
            body_sha256: stellar_agent_core::hex::encode(&Sha256::digest(&body)),
        })
        .unwrap(),
    );
    let loaded = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(serde_json::to_vec(&loaded).unwrap(), body);
    assert_eq!(
        reservation_destinations(&loaded, &"e2".repeat(32)),
        PaymentDestinations::None
    );
    store
        .record_and_persist(&profile, &[entry(key("intent", "rate_limit", 60), 1000, 1)])
        .unwrap();
    let rewritten = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(
        rewritten.entries[1].records[0].destinations,
        StoredDestinations::Null
    );
    let mut pruned = rewritten.clone();
    for bucket in &mut pruned.entries {
        for record in &mut bucket.records {
            record.destinations = StoredDestinations::Missing;
        }
    }
    for record in &mut pruned.accounting_expiries {
        record.destinations = StoredDestinations::Missing;
    }
    store
        .commit_generation(&state_key, &gen_entry, rewritten, pruned)
        .unwrap();
    assert_eq!(
        store.read_for_inspection(&profile).unwrap().unwrap().version,
        WIRE_VERSION_DESTINATION
    );
}

#[test]
#[serial]
fn an_unusable_destination_is_recorded_as_absent() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (_dir, profile, store) = destination_fixture();
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let mut hold = destination_hold(&"a1".repeat(32), 1);
    hold.destinations = PaymentDestinations::Single("invalid".to_owned());
    store
        .record_pending(&profile, &[destination_entry(7)], &hold)
        .unwrap();
    let wire = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(wire.entries[0].records[0].amount, 7);
    assert_eq!(
        wire.entries[0].records[0].destinations,
        StoredDestinations::Missing
    );
    assert!(
        serde_json::to_value(&wire.entries[0].records[0])
            .unwrap()
            .get("destinations")
            .is_none()
    );
    assert_eq!(
        collect_pending(&wire).unwrap()[0].destinations,
        PaymentDestinations::None
    );
}

#[test]
#[serial]
fn unusable_provenance_projects_none() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for value in [
        serde_json::json!(42),
        serde_json::json!("invalid"),
        serde_json::json!(crate::submit::destination_tests::muxed_destination(0)),
        serde_json::json!([{"operation": 0, "destination": "invalid"}]),
    ] {
        let (dir, profile, store) = destination_fixture();
        let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
        let first = destination_hold(&"a1".repeat(32), 1);
        let second = destination_hold(&"a2".repeat(32), 2);
        store
            .record_pending(&profile, &[destination_entry(7)], &first)
            .unwrap();
        store
            .record_pending(&profile, &[destination_entry(9)], &second)
            .unwrap();
        let mut wire = store.read_for_inspection(&profile).unwrap().unwrap();
        wire.entries[0].records[0].destinations = StoredDestinations::Value(value.clone());
        let mut duplicate = wire.entries[0].clone();
        duplicate.window_secs = 120;
        duplicate.records.truncate(1);
        duplicate.records[0].destinations = (&first.destinations).into();
        wire.entries.push(duplicate);
        store.seal_unchecked_for_test(&profile, &wire);
        let read = store.read_for_inspection(&profile).unwrap().unwrap();
        assert_eq!(
            read.entries[0].records[0].destinations,
            StoredDestinations::Value(value)
        );
        assert_eq!(
            reservation_destinations(&read, &first.id),
            PaymentDestinations::None
        );
        assert_eq!(
            reservation_destinations(&read, &second.id),
            second.destinations
        );
        let receipts = ReceiptStore::open_at(dir.path(), "destinations").unwrap();
        let held = collect_pending(&read)
            .unwrap()
            .into_iter()
            .find(|hold| hold.id == first.id)
            .unwrap();
        finalize_receipt(Some(&receipts), &held, ReceiptStatus::Success, Some(8)).unwrap();
        assert_eq!(
            receipts.get(&first.id).unwrap().unwrap().destinations,
            PaymentDestinations::None
        );
        store.release(&profile, &first.id).unwrap();
        clock.set(1000 + RETENTION_MS + 1);
        store.record_and_persist(&profile, &[]).unwrap();
        assert!(!store.holds_reservation(&profile, &first.id).unwrap());
        assert_eq!(
            store.pending_reservations(&profile).unwrap()[0].destinations,
            second.destinations
        );
    }
}

#[test]
#[serial]
fn every_rebuilt_receipt_keeps_its_destination() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (dir, profile, store) = destination_fixture();
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let hold = destination_hold(&"a1".repeat(32), 1);
    store
        .record_pending(&profile, &[destination_entry(7)], &hold)
        .unwrap();
    let receipts = ReceiptStore::open_at(dir.path(), "destinations").unwrap();
    for _ in 0..2 {
        let held = store.pending_reservations(&profile).unwrap().remove(0);
        finalize_receipt(Some(&receipts), &held, ReceiptStatus::Success, Some(8)).unwrap();
        assert_eq!(
            receipts.get(&hold.id).unwrap().unwrap().destinations,
            hold.destinations
        );
    }
}

#[test]
#[serial]
fn a_destination_commit_survives_every_cut() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    destination_commit_survives_cut(COMMIT_FAULT_AFTER_PREPARED);
}

#[test]
#[serial]
fn a_destination_commit_survives_every_cut_after_counter() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    destination_commit_survives_cut(COMMIT_FAULT_AFTER_COUNTER);
}

fn destination_commit_survives_cut(fault: u8) {
    let (_dir, profile, store) = destination_fixture();
    let _clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let first = destination_hold(&"a1".repeat(32), 1);
    let second = destination_hold(&"a2".repeat(32), 2);
    store
        .record_pending(&profile, &[destination_entry(7)], &first)
        .unwrap();
    let armed = arm_accounting_fault(fault);
    assert!(
        store
            .record_pending(&profile, &[destination_entry(9)], &second)
            .is_err()
    );
    drop(armed);
    let reopened = PersistedWindowStore::at_path(store.path.clone());
    let read = reopened.read_for_inspection(&profile).unwrap().unwrap();
    let holds = reopened.pending_reservations(&profile).unwrap();
    if fault == COMMIT_FAULT_AFTER_PREPARED {
        assert_eq!(holds, vec![first]);
        assert_eq!(
            read.entries[0]
                .records
                .iter()
                .map(|r| r.amount)
                .sum::<i128>(),
            7
        );
    } else {
        assert_eq!(holds.len(), 2);
        assert_eq!(holds[1].destinations, second.destinations);
        assert_eq!(
            read.entries[0]
                .records
                .iter()
                .map(|r| r.amount)
                .sum::<i128>(),
            16
        );
    }
}

#[test]
#[serial]
fn an_expiry_keeps_its_destination_across_clock_moves() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (dir, profile, store) = destination_fixture();
    let clock = crate::mainnet::clock::set_now_ms_for_test(1000);
    let mut hold = destination_hold(&"a1".repeat(32), 1);
    hold.max_time = 61;
    store
        .record_pending(&profile, &[destination_entry(7)], &hold)
        .unwrap();
    let receipts = ReceiptStore::open_at(dir.path(), "destinations").unwrap();
    receipts
        .try_begin_to(
            &hold.id,
            &hold.tx_hash,
            &hold.source,
            hold.sequence,
            hold.max_time,
            hold.submission_ledger,
            &hold.destinations,
        )
        .unwrap();
    let before = fs::read(&store.path).unwrap();
    clock.set(500);
    assert!(
        store
            .expire_accounting(&profile, Some(&receipts), &hold, 500)
            .unwrap()
            .is_none()
    );
    assert_eq!(fs::read(&store.path).unwrap(), before);
    assert_eq!(
        receipts.get(&hold.id).unwrap().unwrap().destinations,
        hold.destinations
    );
    fs::write(receipts.file_path().unwrap(), b"{}").unwrap();
    clock.set(1_000_000);
    assert!(matches!(
        store
            .expire_accounting(&profile, Some(&receipts), &hold, 1_000_000)
            .unwrap(),
        Some(Settlement::AccountingExpired { .. })
    ));
    assert_eq!(
        receipts.get(&hold.id).unwrap().unwrap().destinations,
        hold.destinations
    );
    clock.set(500);
    let reopened = PersistedWindowStore::at_path(store.path.clone());
    assert!(reopened.pending_reservations(&profile).unwrap().is_empty());
    assert_eq!(
        receipts.get(&hold.id).unwrap().unwrap().destinations,
        hold.destinations
    );
    let wire = reopened.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(wire.accounting_expiries.len(), 1);
    assert_eq!(
        wire.accounting_expiries[0].projection().destinations,
        hold.destinations
    );
    let mut invalid = serde_json::to_value(&wire).unwrap();
    invalid["accounting_expiries"][0]["unknown"] = serde_json::json!(true);
    let body = serde_json::to_vec(&invalid).unwrap();
    let (state_key, _) = store.load_or_mint_key(&profile).unwrap();
    let mut bytes = compute_tag(state_key.as_ref(), &body).unwrap().to_vec();
    bytes.extend(body);
    assert!(matches!(
        store.verify_with_key(&state_key, &bytes),
        Err(WindowStoreError::Invalid { .. })
    ));
}
