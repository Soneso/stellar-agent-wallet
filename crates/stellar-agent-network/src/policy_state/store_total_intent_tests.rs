fn total_plan(sequence: i64, entries: &[WindowEntry]) -> crate::SignedIntentPlan {
    intent_fixture_plan(sequence, 60).0.with_legs(entries)
}

#[test]
#[serial]
fn intent_total_admission_sweeps_expired_unclaimed_hold() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-expired-hold");
    f.pin(D1);
    let mut wire = version_twelve();
    let mut authorization = open_authorization(1, T);
    authorization.profile = f.name.clone();
    authorization.chain = f.profile.chain_id;
    authorization.reservation = Some(authorization.id);
    wire.authorizations.push(authorization);
    wire.holds.push(total_hold(1, 6, Some(D1)));
    f.store.seal_unchecked_for_test(&f.profile, &wire);
    assert_eq!(f.sum(D1), 6);
    let entries = [f.total(6, D1)];
    assert!(exhausted(&admit(&f.wire(), &entries)));

    let result = f
        .store
        .admit_signed_intent(&f.profile, &total_plan(1, &entries))
        .map(drop);
    assert!(
        result.is_ok(),
        "expired unclaimed hold of 6 must free capacity for intent 6 under limit 10: {result:?}"
    );
    let wire = f.wire();
    assert!(wire.holds.is_empty());
    assert_eq!(wire.signed_intents.len(), 1);
    assert_eq!(f.sum(D1), 6);
    assert_eq!(f.hydrated(D1), 6);
}

#[tokio::test]
#[serial]
async fn intent_total_recorder_routes() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for mixed in [false, true] {
        total_intent_test_helpers::assert_linked_recorder(mixed).await;
    }
    for (case, code) in [
        ("unavailable", "policy.total_epoch_unavailable"),
        ("stale", "policy.total_epoch_stale"),
        ("retired", "policy.total_epoch_retired"),
        ("exhausted", "policy.deny.total_budget_exhausted"),
        ("binding", "submission.intent_binding_mismatch"),
        ("invalid", "submission.intent_record_unavailable"),
    ] {
        assert_eq!(
            total_intent_test_helpers::recorder_refusal(case)
                .await
                .code(),
            code,
            "{case}"
        );
    }
}

#[test]
#[serial]
fn intent_total_two_process_stale_admission() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    const ROLE: &str = "STELLAR_AGENT_INTENT_TOTAL_ROLE";
    const DIRECTORY: &str = "STELLAR_AGENT_INTENT_TOTAL_DIRECTORY";
    const TEST: &str =
        "policy_state::store::tests::total_budget::intent_total_two_process_stale_admission";
    if let Ok(role) = std::env::var(ROLE) {
        use std::sync::Arc;
        let dir = PathBuf::from(std::env::var_os(DIRECTORY).unwrap());
        let backend: Arc<keyring_core::CredentialStore> =
            Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
                dir.join("intent.keyring"),
                stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                    zeroize::Zeroizing::new([7; 32]),
                )),
            ));
        keyring_core::set_default_store(backend);
        let profile = test_profile(&dir, "intent-process");
        let store = PersistedWindowStore::at_path(dir.join("intent.window"));
        let _clock = crate::mainnet::clock::set_now_ms_for_test(T);
        let key = StateKey::new("intent-process", 1, "total:native", 0);
        let total = |amount| {
            WindowEntry::new(
                key.clone(),
                T,
                amount,
                WindowLimit::Total {
                    asset: "native".into(),
                    max_stroops: 10,
                },
            )
            .with_epoch(Some(D1))
        };
        match role.as_str() {
            "setup" => {
                let lock =
                    WindowStoreLock::acquire_for(&store.path, &profile.policy_window_state_key_id)
                        .unwrap();
                pin::write_for_test(
                    &lock,
                    &PinScope::for_profile(&store.path, &profile),
                    &pin::Pin::new(1, D1, owner_of(11)).unwrap(),
                )
                .unwrap();
            }
            "commit" => {
                let _proof = store
                    .admit_signed_intent(&profile, &total_plan(1, &[total(6)]))
                    .unwrap();
            }
            "stale" => {
                let memory = PolicyStateStore::new();
                store
                    .load_into("intent-process", &profile, &memory)
                    .unwrap();
                assert_eq!(memory.query_epoch(&key, D1).unwrap().0, 0);
                fs::write(dir.join("hydrated"), b"").unwrap();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
                while !dir.join("committed").exists() {
                    assert!(std::time::Instant::now() < deadline);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                let result = store
                    .admit_signed_intent(&profile, &total_plan(2, &[total(6)]))
                    .map(drop);
                assert!(
                    exhausted(&result),
                    "fresh locked intent projection refuses 6 after 6: {result:?}"
                );
                let _proof = store
                    .admit_signed_intent(&profile, &total_plan(2, &[total(4)]))
                    .unwrap();
                let wire = store.read_for_inspection(&profile).unwrap().unwrap();
                assert_eq!(total_in_file(&wire, &key, D1).unwrap().0, 10);
                assert_eq!(wire.signed_intents.len(), 2);
            }
            _ => unreachable!(),
        }
        return;
    }
    let dir = TempDir::new().unwrap();
    let spawn = |role| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(ROLE, role)
            .env(DIRECTORY, dir.path())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let finish = |child: std::process::Child| {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };
    finish(spawn("setup"));
    let mut stale = spawn("stale");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !dir.path().join("hydrated").exists() {
        if stale.try_wait().unwrap().is_some() || std::time::Instant::now() > deadline {
            finish(stale);
            panic!("stale process does not hydrate");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    finish(spawn("commit"));
    fs::write(dir.path().join("committed"), b"").unwrap();
    finish(stale);
}

#[test]
#[serial]
fn intent_total_linked_rows_never_own_the_charge() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for mixed in [false, true] {
        let (f, plan) = closing_total_fixture(false);
        let mut entries = vec![f.total(6, D1)];
        if mixed {
            entries.push(intent_fixture_plan(1, 60).0.legs()[0].clone());
        }
        let plan = plan.with_legs(&entries);
        let exposure = f
            .store
            .admit_signed_intent(&f.profile, &plan)
            .unwrap()
            .expose();
        let id = exposure.intent_id().unwrap();
        let (_, mut envelope) = intent_fixture_plan(1, 60);
        let stellar_xdr::TransactionEnvelope::Tx(tx) = &mut envelope else {
            unreachable!()
        };
        tx.tx.cond = stellar_xdr::Preconditions::V2(stellar_xdr::PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: Some(stellar_xdr::LedgerBounds {
                min_ledger: 0,
                max_ledger: 100,
            }),
            min_seq_num: None,
            min_seq_age: stellar_xdr::Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: Default::default(),
        });
        let facts = crate::BindFacts::from_envelope(&envelope, Caip2::Testnet.network_passphrase())
            .unwrap();
        f.store
            .bind_signed_intent(&f.profile, id, &facts, &entries)
            .unwrap();
        let hold = SubmissionHold {
            destinations: Default::default(),
            chain_scope: plan.chain_scope(),
            id: facts.envelope_hash,
            tx_hash: facts.tx_hash,
            source: plan.facts.envelope_source.clone(),
            sequence: 1,
            max_time: 0,
            pending_since_ms: T,
            submission_ledger: 1,
            submission_anchor: None,
            operator_required: false,
        };
        let recorded = f
            .store
            .record_pending_linked(&f.profile, &entries, &hold, id);
        assert!(
            recorded.is_ok(),
            "total-only and mixed linked reservations succeed"
        );
        assert!(matches!(
            f.store
                .record_pending_linked(&f.profile, &entries, &hold, id),
            Err(WindowStoreError::DuplicateReservation)
        ));
        assert_eq!(f.sum(D1), 6);
        assert_eq!(f.store.total_usage(&f.profile, D1).unwrap(), native_usage(6));
        assert_eq!(f.hydrated(D1), 6);
        if mixed {
            let memory = PolicyStateStore::new();
            f.store.load_into(&f.name, &f.profile, &memory).unwrap();
            assert_eq!(
                memory
                    .query_window(&StateKey::new(&f.name, 1, "native", 60), T)
                    .unwrap(),
                (60, 1)
            );
        }
        f.clock.set(T + 1000);
        f.store
            .observe_signed_intents(&f.profile, &total_closure_witness(&plan))
            .unwrap();
        f.clock.set(T + 1001 + RETENTION_MS);
        f.authorized(&[f.windowed(1)]).unwrap();
        assert_eq!(f.sum(D1), 6);
        assert_eq!(f.store.total_usage(&f.profile, D1).unwrap(), native_usage(6));
        assert_eq!(f.hydrated(D1), 6);
        assert!(f.wire().signed_intents.is_empty());
        assert_eq!(f.wire().total_sums[0].amount, 6);
        let mut wire = f.wire();
        for bucket in &mut wire.entries {
            for row in &mut bucket.records {
                if row.signed_intent.is_some() {
                    row.status = RecordStatus::Confirmed;
                    assert!(!counted_unfinal(row), "linked rows cannot promote");
                }
            }
        }
        let mut final_linked = wire.clone();
        for bucket in &mut final_linked.entries {
            if is_total_budget_bucket(bucket) {
                for row in &mut bucket.records {
                    row.status = RecordStatus::FinalTotal;
                }
            }
        }
        fold_final_totals(&mut final_linked, T + RETENTION_MS * 3).unwrap();
        assert_eq!(
            final_linked.total_sums[0].amount, 6,
            "linked rows never fold"
        );
        prune_lifecycle(&mut wire, T + RETENTION_MS * 3);
        assert!(
            wire.entries
                .iter()
                .flat_map(|b| &b.records)
                .all(|r| r.signed_intent.is_none()),
            "linked rows follow ordinary pruning"
        );
    }
}

fn alias_total(f: &Fx, amount: i128) -> WindowEntry {
    let asset = stellar_agent_core::asset_id::CanonicalAsset::Native
        .sac_contract_id(&f.profile.network_passphrase)
        .unwrap();
    WindowEntry::new(
        StateKey::new(&f.name, 1, &format!("total:{asset}"), 0),
        T,
        amount,
        WindowLimit::Total {
            asset,
            max_stroops: 10,
        },
    )
    .with_epoch(Some(D1))
}

#[test]
#[serial]
fn intent_total_alias_batch() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-alias-batch");
    f.pin(D1);
    let refused = f
        .store
        .admit_signed_intent(
            &f.profile,
            &total_plan(1, &[f.total(6, D1), alias_total(&f, 6)]),
        )
        .map(drop);
    assert!(
        exhausted(&refused),
        "alias batch 12 exceeds 10: {refused:?}"
    );
    let _proof = f
        .store
        .admit_signed_intent(
            &f.profile,
            &total_plan(1, &[f.total(4, D1), alias_total(&f, 6)]),
        )
        .unwrap();
    assert_eq!(f.sum(D1), 10);
    assert_eq!(f.hydrated(D1), 10);
}

#[test]
#[serial]
fn intent_total_zero_and_mixed_duration() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-zero");
    f.pin(D1);
    let result = f
        .store
        .admit_signed_intent(&f.profile, &total_plan(1, &[f.total(0, D1)]));
    assert!(result.is_ok(), "zero-window total is accepted");
    assert_eq!(f.wire().signed_intents[0].admitted_window_ms, 0);
    let window = intent_fixture_plan(2, 60).0.legs()[0].clone();
    let _proof = f
        .store
        .admit_signed_intent(&f.profile, &total_plan(2, &[f.total(6, D1), window]))
        .unwrap();
    assert_eq!(f.wire().signed_intents[1].admitted_window_ms, 60_000);
    assert_eq!(f.sum(D1), 6);
}

#[test]
#[serial]
fn intent_total_non_total_epoch_preflight() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-epoch-placement");
    let before = get_raw(&f.profile.policy_window_state_key_id);
    assert_eq!(
        detail(
            f.store
                .admit_signed_intent(
                    &f.profile,
                    &total_plan(1, &[f.windowed(1).with_epoch(Some(D1))]),
                )
                .map(drop)
        ),
        "a non-total entry cannot carry an epoch"
    );
    assert_eq!(get_raw(&f.profile.policy_window_state_key_id), before);
    assert!(!f.store.path.exists());
}

#[test]
#[serial]
fn intent_total_negative_and_overflow() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-arithmetic");
    f.pin(D1);
    let key_before = get_raw(&f.profile.policy_window_state_key_id);
    assert_eq!(
        detail(
            f.store
                .admit_signed_intent(&f.profile, &total_plan(1, &[f.total(-1, D1)]))
                .map(drop)
        ),
        "a total-budget debit is negative"
    );
    assert_eq!(
        get_raw(&f.profile.policy_window_state_key_id),
        key_before,
        "negative refusal precedes key creation"
    );
    let _proof = f
        .store
        .admit_signed_intent(
            &f.profile,
            &total_plan(1, &[f.total_of(i128::MAX, i128::MAX, Some(D1))]),
        )
        .unwrap();
    let before = f.state();
    let refused = f.store.admit_signed_intent(
        &f.profile,
        &total_plan(2, &[f.total_of(1, i128::MAX, Some(D1))]),
    );
    assert!(
        matches!(refused, Err(WindowStoreError::PolicyDenied { reason })
        if *reason == stellar_agent_core::policy::DenyReason::TotalBudgetExhausted {
            asset: "native".into(), max_stroops: i128::MAX, remaining_stroops: 0,
        }),
        "an intent overflow is the governing total-budget denial"
    );
    assert_eq!(f.state(), before);
    assert_eq!(f.sum(D1), i128::MAX);
}

#[test]
#[serial]
fn intent_total_replay_epoch_and_multiset() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-replay");
    f.pin(D1);
    let plan = total_plan(1, &[f.total(2, D1), alias_total(&f, 4)]);
    let _proof = f.store.admit_signed_intent(&f.profile, &plan).unwrap();
    let reordered = total_plan(1, &[f.total(4, D1), alias_total(&f, 2)]);
    let _proof = f.store.admit_signed_intent(&f.profile, &reordered).unwrap();
    assert_eq!(f.sum(D1), 6);
    let duplicate = total_plan(1, &[f.total(2, D1), f.total(2, D1), f.total(4, D1)]);
    assert!(matches!(
        f.store.admit_signed_intent(&f.profile, &duplicate),
        Err(WindowStoreError::IntentBindingMismatch { field: "legs" })
    ));
    f.pin(D2);
    let changed = total_plan(1, &[f.total(2, D2), f.total(4, D2)]);
    assert!(matches!(
        f.store.admit_signed_intent(&f.profile, &changed),
        Err(WindowStoreError::IntentBindingMismatch { field: "legs" })
    ));
    assert_eq!(f.sum(D1), 6);
    assert_eq!(f.sum(D2), 0);
}

#[test]
#[serial]
fn intent_total_original_cancellation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-cancel-total");
    f.pin(D1);
    let proof = f
        .store
        .admit_signed_intent(&f.profile, &total_plan(1, &[f.total(6, D1)]))
        .unwrap();
    assert_eq!(f.sum(D1), 6);
    f.store.cancel_signed_intent(&f.profile, proof).unwrap();
    assert_eq!(f.sum(D1), 0);
    let _proof = f
        .store
        .admit_signed_intent(&f.profile, &total_plan(2, &[f.total(10, D1)]))
        .unwrap();
    assert_eq!(f.sum(D1), 10);
}

#[test]
#[serial]
fn intent_total_replay_invalidates_cancellation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-replay-token");
    f.pin(D1);
    let plan = total_plan(1, &[f.total(6, D1)]);
    let proof = f.store.admit_signed_intent(&f.profile, &plan).unwrap();
    let exposure = f
        .store
        .admit_signed_intent(&f.profile, &plan)
        .unwrap()
        .expose();
    f.store.cancel_signed_intent(&f.profile, proof).unwrap();
    assert_eq!(f.sum(D1), 6);
    assert!(exposure.intent_id().is_some());
    assert!(f.wire().signed_intents[0].cancel_token_sha256.is_none());
}

fn closing_total_fixture(schedule: bool) -> (Fx, crate::SignedIntentPlan) {
    let (dir, profile, store, mut plan) = progress_fixture();
    let f = Fx {
        _dir: dir,
        name: "intent".into(),
        profile,
        store,
        clock: crate::mainnet::clock::set_now_ms_for_test(T),
    };
    if schedule {
        plan.facts.purpose = Some(IntentPurpose::TimelockSchedule {
            timelock: stellar_strkey::Contract([1; 32]).to_string().to_string(),
            operation_id: [3; 32],
        });
    }
    f.pin(D1);
    (f, plan)
}

fn total_closure_witness(plan: &crate::SignedIntentPlan) -> LedgerWitnessCapability {
    let t = T + 1000;
    let mut witness = progress_witness([101, 102], t);
    if let Some(IntentPurpose::TimelockSchedule {
        timelock,
        operation_id,
    }) = &plan.facts.purpose
    {
        witness = witness.with_operation_states_for_test(
            crate::signing::ledger_witness::ScheduleProbe {
                intent_id: plan.facts.intent_id(),
                timelock: timelock.clone(),
                operation_id: *operation_id,
                expiration: 100,
                admitted_at_ms: T,
            },
            [0, 0],
            [101, 102],
            [t - 1, t],
        );
    }
    witness
}

#[test]
#[serial]
fn intent_total_closure_collection_and_reset() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for schedule in [false, true] {
        for reset in [false, true] {
            let (f, plan) = closing_total_fixture(schedule);
            let plan = plan.with_legs(&[f.total(3, D1), alias_total(&f, 3)]);
            let _proof = f
                .store
                .admit_signed_intent(&f.profile, &plan)
                .unwrap()
                .expose();
            f.clock.set(T + 1000);
            f.store
                .observe_signed_intents(&f.profile, &total_closure_witness(&plan))
                .unwrap();
            let closed = f.wire();
            assert_eq!(
                closed.signed_intents[0].expiry_observed_at_ms,
                Some(T + 1000)
            );
            assert_eq!(
                closed.signed_intents[0].schedule_terminal,
                schedule.then_some(ScheduleTerminal::Unset)
            );
            assert_eq!(f.sum(D1), 6);
            let boundary = T + 1000 + RETENTION_MS;
            f.clock.set(boundary);
            f.authorized(&[f.windowed(1)]).unwrap();
            assert_eq!(f.wire().signed_intents.len(), 1);
            assert!(matches!(
                f.store.reset_snapshot_locked(&f.profile, boundary),
                Err(WindowStoreError::SignedIntentLive { .. })
            ));
            f.clock.set(boundary + 1);
            if reset {
                put_raw(
                    &f.profile.policy_owner_key_id,
                    &stellar_agent_core::profile::owner_key::encode_owner_public_key(&owner_of(11)),
                );
                f.store
                    .reset(
                        &f.profile,
                        owner_name(&f.profile),
                        boundary + 1,
                        "collect",
                        "collect-total",
                        |row| Ok::<_, ()>(signed_by(11, row)),
                        |_, _| Ok(()),
                    )
                    .unwrap();
            } else {
                f.authorized(&[f.windowed(1)]).unwrap();
            }
            assert!(f.wire().signed_intents.is_empty());
            assert_eq!(
                f.wire().total_sums,
                vec![WireTotalSum {
                    scope_specificity: 1,
                    bucket: "total:native".into(),
                    epoch: D1,
                    amount: 6,
                    settled_until_ms: T + 1000,
                }]
            );
            for time in [T - 1, boundary + RETENTION_MS * 3] {
                f.clock.set(time);
                f.authorized(&[f.windowed(1)]).unwrap();
                assert_eq!(f.sum(D1), 6);
                assert_eq!(f.hydrated(D1), 6);
                assert!(f.wire().signed_intents.is_empty());
            }
            let continued = f
                .store
                .admit_signed_intent(&f.profile, &total_plan(2, &[f.total(4, D1)]));
            assert!(
                continued.is_ok(),
                "remaining allocation stays available after collection"
            );
            assert_eq!(f.sum(D1), 10);
            assert_eq!(f.hydrated(D1), 10);
        }
    }
}

#[test]
#[serial]
fn intent_total_collection_overflow_and_timestamp() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (f, plan) = closing_total_fixture(false);
    let plan = plan.with_legs(&[f.total(6, D1)]);
    let _proof = f.store.admit_signed_intent(&f.profile, &plan).unwrap();
    f.clock.set(T + 1000);
    f.store
        .observe_signed_intents(&f.profile, &total_closure_witness(&plan))
        .unwrap();
    let mut wire = f.wire();
    wire.total_sums.push(WireTotalSum {
        scope_specificity: 1,
        bucket: "total:native".into(),
        epoch: D1,
        amount: i128::MAX,
        settled_until_ms: T + 2000,
    });
    f.store.seal_unchecked_for_test(&f.profile, &wire);
    f.clock.set(T + 1001 + RETENTION_MS);
    let before = f.state();
    let mut audit_calls = 0;
    let result = f.store.reset(
        &f.profile,
        owner_name(&f.profile),
        T + 1001 + RETENTION_MS,
        "collect",
        "overflow-total",
        |_| Ok::<_, ()>(ResetConsent::default()),
        |_, _| {
            audit_calls += 1;
            Ok(())
        },
    );
    assert!(
        matches!(result, Err(ResetError::Store { error: WindowStoreError::Invalid { ref detail }, .. })
        if detail == "a total-budget sum overflows")
    );
    assert_eq!(audit_calls, 0);
    assert_eq!(f.state(), before);
    let snapshot = serde_json::to_value(&wire).unwrap();
    assert_eq!(
        detail(prune_stale(&mut wire, T + 1001 + RETENTION_MS)),
        "a total-budget sum overflows"
    );
    assert_eq!(serde_json::to_value(&wire).unwrap(), snapshot);
    wire.total_sums[0].amount = 1;
    prune_stale(&mut wire, T + 1001 + RETENTION_MS).unwrap();
    assert_eq!(wire.total_sums[0].amount, 7);
    assert_eq!(wire.total_sums[0].settled_until_ms, T + 2000);
}

#[test]
#[serial]
fn intent_total_collection_merges_existing_alias() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let (f, plan) = closing_total_fixture(false);
    let plan = plan.with_legs(&[f.total(3, D1), alias_total(&f, 3)]);
    let _proof = f.store.admit_signed_intent(&f.profile, &plan).unwrap();
    f.clock.set(T + 1000);
    f.store
        .observe_signed_intents(&f.profile, &total_closure_witness(&plan))
        .unwrap();
    let mut wire = f.wire();
    wire.total_sums.push(WireTotalSum {
        scope_specificity: 1,
        bucket: alias_total(&f, 1).key().bucket().to_owned(),
        epoch: D1,
        amount: 1,
        settled_until_ms: T + 2000,
    });
    prune_stale(&mut wire, T + 1001 + RETENTION_MS).unwrap();
    assert!(wire.signed_intents.is_empty());
    assert_eq!(wire.total_sums.len(), 1, "equivalent sum keys merge");
    assert_eq!(
        wire.total_sums[0].amount, 7,
        "duplicate legs retain multiplicity"
    );
    assert_eq!(wire.total_sums[0].settled_until_ms, T + 2000);
    check_snapshot(&wire).unwrap();
}

#[test]
#[serial]
fn intent_total_replay_checks_pin_and_retirement() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-pin");
    f.pin(D1);
    let plan = total_plan(1, &[f.total(6, D1)]);
    let _proof = f.store.admit_signed_intent(&f.profile, &plan).unwrap();
    f.pin(D2);
    assert_eq!(
        f.store
            .admit_signed_intent(&f.profile, &plan)
            .err()
            .map(|error| crate::signed_intent::store_refusal(error).code()),
        Some("policy.total_epoch_stale")
    );
    f.pin(D1);
    let mut wire = f.wire();
    wire.retired_total_epoch = Some(D1);
    f.store.seal_unchecked_for_test(&f.profile, &wire);
    assert_eq!(
        f.store
            .admit_signed_intent(&f.profile, &plan)
            .err()
            .map(|error| crate::signed_intent::store_refusal(error).code()),
        Some("policy.total_epoch_retired")
    );
    assert_eq!(f.sum(D1), 6);
}

/// Binding a final envelope refuses total legs sized under a digest that is
/// no longer pinned, writes nothing, and leaves the intent unbound. The same
/// legs bind once the pin names their digest again.
#[test]
#[serial]
fn intent_total_bind_checks_the_pin() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-bind-pin");
    f.pin(D1);
    let legs = [f.total(6, D1)];
    let (plan, envelope) = intent_fixture_plan(1, 60);
    let plan = plan.with_legs(&legs);
    let exposure = f
        .store
        .admit_signed_intent(&f.profile, &plan)
        .unwrap()
        .expose();
    let id = exposure.intent_id().unwrap();
    let facts =
        crate::BindFacts::from_envelope(&envelope, Caip2::Testnet.network_passphrase()).unwrap();
    let record = |f: &Fx| {
        f.wire()
            .signed_intents
            .into_iter()
            .find(|record| record.intent_id == id)
            .unwrap()
    };

    f.pin(D2);
    let before = f.state();
    assert!(matches!(
        f.store.bind_signed_intent(&f.profile, id, &facts, &legs),
        Err(WindowStoreError::TotalEpochStale)
    ));
    assert_eq!(f.state(), before, "a refused binding writes nothing");
    let unbound = record(&f);
    assert_ne!(unbound.status, SignedIntentStatus::Bound);
    assert_eq!(unbound.bound_envelope_hash, None);
    assert_eq!(f.sum(D1), 6);

    f.pin(D1);
    f.store
        .bind_signed_intent(&f.profile, id, &facts, &legs)
        .unwrap();
    let bound = record(&f);
    assert_eq!(bound.status, SignedIntentStatus::Bound);
    assert_eq!(bound.bound_envelope_hash, Some(facts.envelope_hash.clone()));
}

fn corrupt_total_intent(case: &str) {
    let f = fx("intent-corrupt");
    f.pin(D1);
    let entries = if case == "non_total_epoch" {
        vec![intent_fixture_plan(1, 60).0.legs()[0].clone()]
    } else {
        vec![f.total(6, D1)]
    };
    let _proof = f
        .store
        .admit_signed_intent(&f.profile, &total_plan(1, &entries))
        .unwrap();
    let valid = f.wire();
    for prepared in [false, true] {
        f.seal_json(&valid, |value| {
            if prepared {
                value["prepared"] = value.clone();
                value["prepared"]["generation"] = (valid.generation + 1).into();
            }
            let image = if prepared {
                &mut value["prepared"]
            } else {
                value
            };
            match case {
                "missing_epoch" => {
                    image["signed_intents"][0]["legs"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("epoch");
                }
                "non_total_epoch" => {
                    image["signed_intents"][0]["legs"][0]["epoch"] = "d1".repeat(32).into()
                }
                "duplicate" => {
                    let copy = image["signed_intents"][0].clone();
                    image["signed_intents"].as_array_mut().unwrap().push(copy);
                }
                "unknown_field" => image["signed_intents"][0]["legs"][0]["unknown"] = true.into(),
                "unknown_epoch" => image["signed_intents"][0]["legs"][0]["epoch"] = "未知".into(),
                "old_version" => image["version"] = 15.into(),
                _ => unreachable!(),
            }
        });
        let before = f.state();
        let result = f.store.read_for_inspection(&f.profile);
        assert!(
            matches!(result, Err(WindowStoreError::Invalid { .. })),
            "{case}/{prepared}: expected typed invalid state"
        );
        let error = result.unwrap_err();
        assert_eq!(
            crate::signed_intent::store_refusal(error).code(),
            "submission.intent_record_unavailable"
        );
        assert!(f.store.signed_intents(&f.name, &f.profile).is_err());
        assert!(
            f.store
                .admit_signed_intent(&f.profile, &total_plan(2, &entries))
                .is_err()
        );
        assert_eq!(f.state(), before);
    }
}

macro_rules! intent_corruption_test {
    ($name:ident, $case:literal) => {
        #[test]
        #[serial]
        fn $name() {
            let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
            let _storage_home =
                stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
            corrupt_total_intent($case);
        }
    };
}
intent_corruption_test!(intent_total_missing_epoch, "missing_epoch");
intent_corruption_test!(intent_total_non_total_epoch, "non_total_epoch");
intent_corruption_test!(intent_total_duplicate, "duplicate");
intent_corruption_test!(intent_total_unknown_field, "unknown_field");
intent_corruption_test!(intent_total_unknown_epoch, "unknown_epoch");
intent_corruption_test!(intent_total_old_version, "old_version");

#[test]
#[serial]
fn intent_total_old_non_total_lifecycle() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for version in [12, 13] {
        let (f, _) = closing_total_fixture(false);
        let (plan, envelope) = intent_fixture_plan(1, 60);
        let admitted = f.store.admit_signed_intent(&f.profile, &plan);
        assert!(admitted.is_ok(), "old non-total intent remains admissible");
        let proof = admitted.unwrap();
        let mut wire = f.wire();
        wire.version = version;
        strip_native_coverage_for_test(&mut wire);
        let bytes = serde_json::to_string(&wire.signed_intents).unwrap();
        assert!(!bytes.contains("epoch"));
        f.store.seal_unchecked_for_test(&f.profile, &wire);
        assert_eq!(
            f.store.signed_intents(&f.name, &f.profile).unwrap().len(),
            1
        );
        f.store.cancel_signed_intent(&f.profile, proof).unwrap();
        assert!(f.wire().signed_intents.is_empty());
        let mut plan = plan.with_envelope_max_ledger(100).unwrap();
        plan.facts.purpose = Some(IntentPurpose::Invoke);
        let mut envelope = envelope;
        let stellar_xdr::TransactionEnvelope::Tx(tx) = &mut envelope else {
            unreachable!()
        };
        tx.tx.cond = stellar_xdr::Preconditions::V2(stellar_xdr::PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: Some(stellar_xdr::LedgerBounds {
                min_ledger: 0,
                max_ledger: 100,
            }),
            min_seq_num: None,
            min_seq_age: stellar_xdr::Duration(0),
            min_seq_ledger_gap: 0,
            extra_signers: Default::default(),
        });
        let proof = f.store.admit_signed_intent(&f.profile, &plan).unwrap();
        let facts = crate::BindFacts::from_envelope(&envelope, Caip2::Testnet.network_passphrase())
            .unwrap();
        let id = proof.intent_id.clone().unwrap();
        f.store
            .bind_signed_intent(&f.profile, &id, &facts, plan.legs())
            .unwrap();
        assert!(matches!(
            f.store.cancel_signed_intent(&f.profile, proof),
            Err(WindowStoreError::IntentBindingMismatch {
                field: "intent_state"
            })
        ));
        f.clock.set(T + 1000);
        f.store
            .observe_signed_intents(&f.profile, &total_closure_witness(&plan))
            .unwrap();
        f.clock.set(T + 1001 + RETENTION_MS);
        f.authorized(&[f.windowed(1)]).unwrap();
        assert!(f.wire().signed_intents.is_empty());
        assert!(f.wire().total_sums.is_empty());
    }
}

#[test]
#[serial]
fn intent_total_commit_boundaries() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for (seam, scheduled) in [
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        COMMIT_FAULT_COMPACTION,
    ]
    .into_iter()
    .flat_map(|seam| [false, true].map(|scheduled| (seam, scheduled)))
    {
        let (f, plan) = closing_total_fixture(scheduled);
        f.authorized(&[f.windowed(1)]).unwrap();
        let plan = plan.with_legs(&[f.total(6, D1)]);
        let fault = arm_accounting_fault(seam);
        let result = f.store.admit_signed_intent(&f.profile, &plan);
        drop(fault);
        assert_eq!(result.is_ok(), seam == COMMIT_FAULT_COMPACTION);
        assert_eq!(
            f.sum(D1),
            if seam == COMMIT_FAULT_AFTER_PREPARED {
                0
            } else {
                6
            }
        );
        let _proof = f.store.admit_signed_intent(&f.profile, &plan).unwrap();
        assert_eq!(f.sum(D1), 6);
        f.clock.set(T + 1000);
        let fault = arm_accounting_fault(seam);
        let result = f
            .store
            .observe_signed_intents(&f.profile, &total_closure_witness(&plan));
        drop(fault);
        assert_eq!(result.is_ok(), seam == COMMIT_FAULT_COMPACTION);
        assert_eq!(
            f.wire().signed_intents[0].expiry_observed_at_ms,
            (seam != COMMIT_FAULT_AFTER_PREPARED).then_some(T + 1000)
        );
        assert_eq!(f.sum(D1), 6);
        f.store
            .observe_signed_intents(&f.profile, &total_closure_witness(&plan))
            .unwrap();
        f.clock.set(T + 1001 + RETENTION_MS);
        let fault = arm_accounting_fault(seam);
        let result = f.touch(1);
        drop(fault);
        assert_eq!(result.is_ok(), seam == COMMIT_FAULT_COMPACTION);
        for time in [T - 1, T + RETENTION_MS * 4] {
            f.clock.set(time);
            let reopened = PersistedWindowStore::at_path(f.store.path.clone());
            let wire = reopened.read_for_inspection(&f.profile).unwrap().unwrap();
            assert_eq!(wire.signed_intents.len() + wire.total_sums.len(), 1);
            assert_eq!(total_in_file(&wire, &f.total_key(), D1).unwrap().0, 6);
            f.authorized(&[f.windowed(1)]).unwrap();
            assert_eq!(f.sum(D1), 6);
        }
        assert!(f.wire().signed_intents.is_empty());
        assert_eq!(f.wire().total_sums[0].amount, 6);
    }
}

#[test]
#[serial]
fn intent_total_version_floor_and_reader() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("intent-version");
    f.pin(D1);
    let mut draft = version_twelve();
    let _ = install_intent_admission(&mut draft, &total_plan(1, &[f.total(6, D1)]), T).unwrap();
    assert_eq!(select_wire_version(&draft, Some(12)), 16);
    let proof = f
        .store
        .admit_signed_intent(&f.profile, &total_plan(1, &[f.total(6, D1)]))
        .unwrap();
    let wire = f.wire();
    assert_eq!(wire.version, WIRE_VERSION_NATIVE_COVERAGE);
    for prepared in [false, true] {
        let mut image = wire.clone();
        if prepared {
            image.version = 15;
            strip_native_coverage_for_test(&mut image);
            image.signed_intents.clear();
            let mut next = wire.clone();
            next.generation += 1;
            image.prepared = Some(Box::new(next));
        }
        f.store.seal_unchecked_for_test(&f.profile, &image);
        DESTINATION_READER_CAP.set(Some(15));
        let result = f.store.read_for_inspection(&f.profile);
        DESTINATION_READER_CAP.set(None);
        assert!(
            matches!(result, Err(WindowStoreError::UnsupportedVersion)),
            "{result:?}"
        );
    }
    f.store.seal_unchecked_for_test(&f.profile, &wire);
    f.store.cancel_signed_intent(&f.profile, proof).unwrap();
    assert_eq!(f.wire().version, WIRE_VERSION_NATIVE_COVERAGE);
    assert!(f.wire().signed_intents.is_empty());
    for version in [12, 13] {
        let g = fx("intent-upgrade");
        g.pin(D1);
        let mut old = version_twelve();
        old.version = version;
        assert!(!earlier_build(&old), "known epoch history is not retired");
        g.push_row(&mut old, 6, Some(D1));
        g.store.seal_unchecked_for_test(&g.profile, &old);
        g.authorized(&[g.total(0, D1)]).unwrap();
        assert_eq!(g.wire().version, WIRE_VERSION_NATIVE_COVERAGE);
        assert_eq!(g.wire().retired_total_epoch, None);
        assert_eq!(g.sum(D1), 6);
    }
}
