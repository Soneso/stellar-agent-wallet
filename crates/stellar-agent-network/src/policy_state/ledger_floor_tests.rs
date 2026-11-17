// Floor projection and locked admission through the durable public entries.

fn floor_seen() -> super::super::operations::WindowObservation {
    super::super::operations::WindowObservation {
        ledger: 100,
        close_time_floor_ms: T0 - 5_000,
        observed_at_ms: T0,
    }
}

fn floor_sum(
    l: &Ledger,
    seen: Option<super::super::operations::WindowObservation>,
) -> Result<u64, WindowStoreError> {
    super::super::operations::OperationStatus::new(&l.store, &l.profile)
        .floor_reserved_stroops(seen)
}

fn floor_unread<T>(result: Result<T, WindowStoreError>) -> bool {
    matches!(result, Err(WindowStoreError::PolicyDenied { reason })
        if matches!(*reason, stellar_agent_core::policy::DenyReason::AccountUnread))
}

fn seal_floor(l: &Ledger, mut wire: WireFile) {
    wire.generation += 1;
    l.store.seal_unchecked_for_test(&l.profile, &wire);
}

fn malformed_floor(error: &WindowStoreError) -> bool {
    #[cfg(feature = "mainnet-write")]
    {
        matches!(
            error,
            WindowStoreError::MainnetStateUnverifiable {
                defect: super::super::store::StateDefect::Malformed
            }
        )
    }
    #[cfg(not(feature = "mainnet-write"))]
    {
        matches!(error, WindowStoreError::Invalid { .. })
    }
}

#[test]
#[serial]
fn floor_projection_release_and_legacy_matrix() {
    use super::super::operations::{CommitId, ReleaseBound, ReleaseClass, ReleaseRow};
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    let mut request = l.request(
        tx(1),
        vec![hold(25), hold_in("other", 25), hold_in("third", 25)],
    );
    request.native_reservation = Some(NATIVE);
    let minted = l.mint(&request).unwrap();
    l.claim(&request, &minted).unwrap();
    l.consume(&request, &minted, &consumption_of(&request.binding))
        .unwrap();
    l.pin(8, [8; 32]);
    assert_eq!(
        floor_sum(&l, Some(floor_seen())).unwrap(),
        325,
        "used and old-epoch exposure counts once"
    );
    assert!(
        floor_unread(floor_sum(&l, None)),
        "the balance observation is mandatory"
    );
    let mut wire = l.wire();
    wire.authorizations[0].native_reservation = None;
    seal_floor(&l, wire);
    let bytes = l.bytes();
    assert!(
        floor_unread(floor_sum(&l, Some(floor_seen()))),
        "legacy use refuses"
    );
    assert_eq!(l.bytes(), bytes, "strict use does not rewrite history");
    assert_eq!(
        l.record(minted.id).state,
        AuthorizationState::Used,
        "lifecycle reads remain available"
    );
    let baseline = l.wire();
    for (bound, released) in [
        (ReleaseBound::Ledger(100), true),
        (ReleaseBound::Ledger(101), false),
        (ReleaseBound::CloseTime(T0 - 5_000), true),
        (ReleaseBound::CloseTime(T0 - 4_999), false),
        (ReleaseBound::Always, true),
    ] {
        let mut wire = baseline.clone();
        wire.authorizations[0].native_release = Some(ReleaseRow {
            class: ReleaseClass::Settled,
            bound,
            observed_ledger: None,
            commit_id: CommitId::from_bytes([1; 16]),
        });
        wire.last_observation = Some(super::super::operations::WindowObservation {
            ledger: 1_000,
            close_time_floor_ms: T0 + 100_000,
            observed_at_ms: T0,
        });
        seal_floor(&l, wire);
        let result = floor_sum(&l, Some(floor_seen()));
        if released {
            assert_eq!(result.unwrap(), 0, "covered release {bound:?}");
        } else {
            assert!(
                floor_unread(result),
                "newer stored observation cannot release {bound:?}"
            );
        }
    }
    for (ledger, close) in [(Some(101), None), (None, Some(T0 - 4_999))] {
        let mut wire = l.wire();
        wire.admissible_floor_ledger = ledger;
        wire.admissible_floor_close_time_ms = close;
        seal_floor(&l, wire);
        assert!(
            floor_unread(floor_sum(&l, Some(floor_seen()))),
            "pruned release coverage"
        );
    }
    let l = Ledger::new();
    l.mint(&l.request(message(1), vec![])).unwrap();
    assert_eq!(
        floor_sum(&l, Some(floor_seen())).unwrap(),
        0,
        "message has no value obligation"
    );
    let legacy = l.mint(&l.request(tx(2), vec![])).unwrap();
    assert!(floor_unread(floor_sum(&l, Some(floor_seen()))));
    l.store
        .invalidate_authorization(&l.profile, legacy.id, "unused")
        .unwrap();
    assert_eq!(l.record(legacy.id).state, AuthorizationState::Invalidated);
    let expiring = l.mint(&l.request(tx(3), vec![])).unwrap();
    l.clock.set(T0 + TTL_MS + 1);
    l.store.record_and_persist(&l.profile, &[]).unwrap();
    assert_eq!(l.record(expiring.id).state, AuthorizationState::Expired);
    assert_eq!(
        l.record(expiring.id).native_release.unwrap().bound,
        ReleaseBound::Always,
        "unused expiry proves release without inferred amounts"
    );
    assert!(
        floor_unread(floor_sum(&l, Some(floor_seen()))),
        "revocation is not release evidence"
    );
    l.clock.set(T0 + 100 * 86_400_000);
    l.store.record_and_persist(&l.profile, &[]).unwrap();
    assert!(
        l.wire().authorizations.is_empty(),
        "ended legacy records remain collectable"
    );
}

#[test]
#[serial]
fn floor_numeric_and_ambiguous_zero_refuse_only_use() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    for id in 1..=3 {
        let mut request = l.request(tx(id), vec![]);
        request.native_reservation = Some(NativeReservation {
            debit_stroops: i64::MAX,
            fee_stroops: 0,
        });
        l.mint(&request).unwrap();
        if id == 2 {
            assert_eq!(
                floor_sum(&l, Some(floor_seen())).unwrap(),
                u64::MAX - 1,
                "checked conversion boundary"
            );
        }
    }
    assert!(
        matches!(
            floor_sum(&l, Some(floor_seen())),
            Err(WindowStoreError::AccountingOverflow)
        ),
        "several valid i64 records exceed u64"
    );
    let l = Ledger::new();
    let mut request = l.request(
        DomainBinding::Soroban {
            intent_digest: [6; 32],
        },
        vec![],
    );
    request.native_reservation = Some(NativeReservation::default());
    let minted = l.mint(&request).unwrap();
    let bytes = l.bytes();
    assert!(
        floor_unread(floor_sum(&l, Some(floor_seen()))),
        "ambiguous old Soroban zero"
    );
    assert_eq!(l.bytes(), bytes);
    l.store
        .invalidate_authorization(&l.profile, minted.id, "unused")
        .unwrap();
    assert_eq!(
        l.record(minted.id).state,
        AuthorizationState::Invalidated,
        "revocation remains available"
    );
    assert!(
        floor_unread(floor_sum(&l, Some(floor_seen()))),
        "revocation alone is not release evidence"
    );
}

fn floor_request(l: &Ledger, id: u8, at: u64, balance: i64) -> MintRequest {
    let mut request = l.request(tx(id), vec![hold(50)]);
    request.native_reservation = Some(NativeReservation {
        debit_stroops: 50,
        fee_stroops: 0,
    });
    request.floor = Some(super::super::accounting::CheckedFloor::for_test(
        &request, "ledger", at, balance,
    ));
    request
}

#[test]
#[serial]
fn floor_locked_admission_rechecks_and_preserves_refusals() {
    use stellar_agent_core::policy::DenyReason;
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    let mut first = floor_request(&l, 1, T0, 100);
    first.holds.clear();
    l.mint(&first).unwrap();
    let mut request = floor_request(&l, 2, T0, 100);
    request.holds.clear();
    let before = l.bytes();
    for _ in 0..2 {
        assert!(
            matches!(l.mint(&request), Err(WindowStoreError::PolicyDenied { reason })
            if *reason == DenyReason::AccountFloorRefused { min_stroops: 20, balance_after_stroops: 0 }),
            "the locked sum prevents the second debit"
        );
        assert_eq!(
            l.bytes(),
            before,
            "floor refusal consumes no nonce or capacity"
        );
    }
    let mut funded = request.clone();
    funded.floor = Some(super::super::accounting::CheckedFloor::for_test(
        &funded, "ledger", T0, 120,
    ));
    l.mint(&funded).unwrap();
    assert_eq!(
        floor_sum(&l, Some(floor_seen())).unwrap(),
        100,
        "funding resumes once"
    );
    assert_eq!(refusal(l.mint(&funded)), MainnetPrecondition::DuplicateOpen);
    let mut repeated = under_policy(funded.clone(), T0 + APPROVAL_MS);
    repeated.floor = Some(super::super::accounting::CheckedFloor::for_test(
        &repeated, "ledger", T0, 1_000,
    ));
    assert!(
        matches!(
            l.mint(&repeated),
            Err(WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::DuplicateOpen
            })
        ),
        "policy replay with ample balance still refuses duplicate content"
    );
    for (at, expected) in [(T0 + 1, "account.unread"), (T0 - 120_001, "account.stale")] {
        let bytes = l.bytes();
        let result = l.mint(&floor_request(&l, 3, at, 1_000));
        let Err(WindowStoreError::PolicyDenied { reason }) = result else {
            panic!("expected {expected}")
        };
        assert_eq!(reason.code(), expected, "mint observation age");
        assert_eq!(l.bytes(), bytes);
    }
    l.mint(&floor_request(&l, 3, T0 - 120_000, 1_000)).unwrap();
    let mut mismatch = floor_request(&l, 4, T0, 1_000);
    mismatch.bindings.signer = [9; 32];
    assert!(
        floor_unread(l.mint(&mismatch)),
        "source binding cannot change"
    );
    let mut mismatch = floor_request(&l, 4, T0, 1_000);
    mismatch.native_reservation.as_mut().unwrap().debit_stroops = 49;
    assert!(
        floor_unread(l.mint(&mismatch)),
        "authenticated native amounts cannot change"
    );
    let mut mismatch = floor_request(&l, 4, T0, 1_000);
    mismatch.binding = tx(5);
    assert!(
        floor_unread(l.mint(&mismatch)),
        "authenticated action cannot change"
    );
}

#[test]
#[serial]
fn two_process_floor_admission_is_serial() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let child_dir = std::env::var_os("STELLAR_AGENT_COMPOSED_DIRECTORY");
    let parent_dir = child_dir.is_none().then(|| TempDir::new().unwrap());
    let dir = child_dir
        .as_ref()
        .map(std::path::Path::new)
        .unwrap_or_else(|| parent_dir.as_ref().unwrap().path());
    let l = composed::process_ledger(dir);
    if child_dir.is_some() {
        l.nonces.set(100);
        assert_eq!(
            floor_sum(&l, Some(floor_seen())).unwrap(),
            0,
            "both read zero reservations"
        );
        let request = floor_request(&l, 2, T0, 100);
        composed::handshake();
        let before = l.bytes();
        assert!(
            matches!(l.mint(&request), Err(WindowStoreError::PolicyDenied { reason })
            if matches!(*reason, stellar_agent_core::policy::DenyReason::AccountFloorRefused { balance_after_stroops: 0, .. })),
            "the second process rechecks committed exposure"
        );
        assert_eq!(l.bytes(), before, "the stale process writes nothing");
        return;
    }
    l.pin(7, [7; 32]);
    l.store.record_and_persist(&l.profile, &[hold(0)]).unwrap();
    let child = composed::child_at_boundary(
        dir,
        "floor",
        "policy_state::ledger::tests::two_process_floor_admission_is_serial",
    );
    l.mint(&floor_request(&l, 1, T0, 100)).unwrap();
    let output = composed::release_child(child);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        l.wire().authorizations.len(),
        1,
        "exactly one writer commits"
    );
    assert_eq!(floor_sum(&l, Some(floor_seen())).unwrap(), 50);
}

#[test]
#[serial]
fn floor_mint_commit_crash_matrix() {
    use super::super::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
        arm_accounting_fault,
    };
    for point in [
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        COMMIT_FAULT_COMPACTION,
    ] {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let l = Ledger::new();
        l.store.record_and_persist(&l.profile, &[hold(0)]).unwrap();
        let mut old = l.request(tx(9), vec![]);
        old.native_reservation = Some(NativeReservation {
            debit_stroops: 10,
            fee_stroops: 0,
        });
        let old_id = l.mint(&old).unwrap().id;
        l.pin(8, [8; 32]);
        let mut request = floor_request(&l, 1, T0, 100);
        request.policy_sequence = 8;
        request.policy_digest = [8; 32];
        request.floor = Some(super::super::accounting::CheckedFloor::for_test(
            &request, "ledger", T0, 100,
        ));
        {
            let _fault = arm_accounting_fault(point);
            let result = l.mint(&request);
            assert_eq!(
                result.is_ok(),
                point == COMMIT_FAULT_COMPACTION,
                "commit result at {point}"
            );
        }
        let restarted = Ledger {
            store: PersistedWindowStore::at_path(l.store.path().to_path_buf()),
            ..l
        };
        let expected = if point == COMMIT_FAULT_AFTER_PREPARED {
            10
        } else {
            60
        };
        assert_eq!(
            floor_sum(&restarted, Some(floor_seen())).unwrap(),
            expected,
            "selected committed generation at {point}"
        );
        assert_eq!(
            restarted.record(old_id).native_reservation,
            old.native_reservation,
            "prior-epoch exposure survives every boundary"
        );
        if expected == 10 {
            restarted.mint(&request).unwrap();
        }
        assert_eq!(floor_sum(&restarted, Some(floor_seen())).unwrap(), 60);
        assert_eq!(
            refusal(restarted.mint(&request)),
            MainnetPrecondition::DuplicateOpen,
            "retry at {point}"
        );
    }
}

#[test]
#[serial]
fn floor_first_image_failure_never_reads_empty() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let l = Ledger::new();
    let request = floor_request(&l, 1, T0, 100);
    {
        let _fault = super::super::store::fail_store_writes();
        assert!(matches!(l.mint(&request), Err(WindowStoreError::Io { .. })));
    }
    for error in [
        floor_sum(&l, Some(floor_seen())).unwrap_err(),
        l.mint(&request).unwrap_err(),
    ] {
        #[cfg(feature = "mainnet-write")]
        let missing = matches!(
            error,
            WindowStoreError::MainnetStateUnverifiable {
                defect: super::super::store::StateDefect::MissingFileWithGeneration
            }
        );
        #[cfg(not(feature = "mainnet-write"))]
        let missing = matches!(error, WindowStoreError::GenerationMismatch);
        assert!(
            missing,
            "a committed generation without its first image is not zero exposure: {error:?}"
        );
    }
}

#[test]
#[serial]
fn floor_capacity_sweeps_only_provably_unused_entries() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let l = Ledger::new();
    l.mint(&l.request(tx(1), vec![])).unwrap();
    l.clock.set(T0 + 1);
    for id in 2..=16 {
        let mut request = l.request(tx(id), vec![]);
        request.native_reservation = Some(NativeReservation::default());
        l.mint(&request).unwrap();
    }
    let before = l.bytes();
    assert!(matches!(
        l.mint(&floor_request(&l, 17, T0 + 1, 100)),
        Err(WindowStoreError::AuthorizationRefused {
            precondition: MainnetPrecondition::TooManyOpen
        })
    ));
    assert_eq!(
        l.bytes(),
        before,
        "capacity refusal cannot remove replay protection"
    );
    l.clock.set(T0 + TTL_MS);
    l.mint(&floor_request(&l, 17, T0 + TTL_MS, 100)).unwrap();
    assert_eq!(
        l.wire()
            .authorizations
            .iter()
            .filter(|auth| auth.state.holds())
            .count(),
        16
    );
    assert_eq!(
        floor_sum(&l, Some(floor_seen())).unwrap(),
        50,
        "committed unused expiry releases missing amounts"
    );
}

#[test]
#[serial]
fn floor_refusal_does_not_consume_durable_approval() {
    use super::super::approvals::{ApprovalState, tests::Fx};
    let mut fx = Fx::new(300_000);
    fx.open();
    fx.consent();
    let now = fx.payload.receipt.verified_at_unix_ms();
    let mut request = fx.mint_request();
    request.native_reservation = Some(NativeReservation {
        debit_stroops: 50,
        fee_stroops: 0,
    });
    request.floor = Some(super::super::accounting::CheckedFloor::for_test(
        &request,
        fx.fixture.name(),
        now,
        69,
    ));
    let before = fx.bytes();
    assert!(
        matches!(fx.store.mint_authorization(fx.fixture.profile(), &request), Err(WindowStoreError::PolicyDenied { reason })
        if matches!(*reason, stellar_agent_core::policy::DenyReason::AccountFloorRefused { .. }))
    );
    assert_eq!(
        fx.view().record.state,
        ApprovalState::Pending,
        "tentative consumption is not committed"
    );
    assert_eq!(fx.bytes(), before);
    request.floor = Some(super::super::accounting::CheckedFloor::for_test(
        &request,
        fx.fixture.name(),
        now,
        70,
    ));
    fx.store
        .mint_authorization(fx.fixture.profile(), &request)
        .unwrap();
    assert_eq!(fx.view().record.state, ApprovalState::Consumed);
}

#[test]
#[serial]
fn floor_malformed_native_shape_refuses_every_read_and_mint() {
    use hmac::{Hmac, KeyInit, Mac};
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let l = Ledger::new();
    let minted = l.mint(&floor_request(&l, 1, T0, 100)).unwrap();
    let baseline = l.bytes();
    let key = crate::keyring::load_hmac_key_32(&l.profile.policy_window_state_key_id).unwrap();
    for kind in [
        "duplicate",
        "missing fee",
        "missing debit",
        "unknown",
        "version",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&baseline[32..]).unwrap();
        match kind {
            "duplicate" => {
                let duplicate = value["authorizations"][0].clone();
                value["authorizations"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            "missing fee" | "missing debit" => {
                value["authorizations"][0]["native_reservation"]
                    .as_object_mut()
                    .unwrap()
                    .remove(if kind == "missing fee" {
                        "fee_stroops"
                    } else {
                        "debit_stroops"
                    });
            }
            "unknown" => {
                value["authorizations"][0]["native_reservation"]["extra"] = serde_json::json!(0);
            }
            "version" => {
                value["version"] = serde_json::json!(super::super::store::WIRE_VERSION_MAX + 1);
            }
            _ => unreachable!(),
        }
        let body = serde_json::to_vec(&value).unwrap();
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key.as_ref()).unwrap();
        mac.update(b"stellar-agent-policy-window/v1/body\x00");
        mac.update(&body);
        let mut bytes = mac.finalize().into_bytes().to_vec();
        bytes.extend(body);
        fs::write(l.store.path(), &bytes).unwrap();
        let errors = [
            floor_sum(&l, Some(floor_seen())).map(|_| ()).unwrap_err(),
            l.store
                .open_authorizations(&l.profile, T0)
                .map(|_| ())
                .unwrap_err(),
            l.mint(&floor_request(&l, 2, T0, 100))
                .map(|_| ())
                .unwrap_err(),
            l.store
                .invalidate_authorization(&l.profile, minted.id, "unused")
                .map(|_| ())
                .unwrap_err(),
        ];
        for error in errors {
            assert!(
                if kind == "version" {
                    matches!(error, WindowStoreError::UnsupportedVersion)
                } else {
                    malformed_floor(&error)
                },
                "{kind}: {error:?}"
            );
        }
        assert_eq!(l.bytes(), bytes, "malformed {kind} is never rewritten");
    }
}

#[test]
#[serial]
fn two_process_floor_removal_keeps_coverage() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let child_dir = std::env::var_os("STELLAR_AGENT_COMPOSED_DIRECTORY");
    let parent_dir = child_dir.is_none().then(|| TempDir::new().unwrap());
    let dir = child_dir
        .as_ref()
        .map(std::path::Path::new)
        .unwrap_or_else(|| parent_dir.as_ref().unwrap().path());
    let l = composed::process_ledger(dir);
    if child_dir.is_some() {
        l.nonces.set(100);
        assert_eq!(floor_sum(&l, Some(floor_seen())).unwrap(), 50);
        let request = floor_request(&l, 2, T0, 200);
        composed::handshake();
        let before = l.bytes();
        assert!(
            floor_unread(l.mint(&request)),
            "a stale process cannot use a pre-settlement balance after removal"
        );
        assert_eq!(l.bytes(), before);
        assert!(
            l.wire().authorizations.is_empty(),
            "removed history cannot return"
        );
        return;
    }
    l.pin(7, [7; 32]);
    let mut request = floor_request(&l, 1, T0, 200);
    request.holds.clear();
    let minted = l.mint(&request).unwrap();
    l.claim(&request, &minted).unwrap();
    l.consume(&request, &minted, &consumption_of(&request.binding))
        .unwrap();
    let mut wire = l.wire();
    wire.authorizations[0].native_release = Some(ReleaseRow {
        class: ReleaseClass::Settled,
        bound: super::super::operations::ReleaseBound::Ledger(101),
        observed_ledger: Some(101),
        commit_id: CommitId::random(),
    });
    seal_floor(&l, wire);
    let child = composed::child_at_boundary(
        dir,
        "floor-removal",
        "policy_state::ledger::tests::two_process_floor_removal_keeps_coverage",
    );
    {
        let lock =
            WindowStoreLock::acquire_for(l.store.path(), &l.profile.policy_window_state_key_id)
                .unwrap();
        let (key, _) = l.store.load_or_mint_key(&l.profile).unwrap();
        let generation = generation_entry_ref(&l.profile);
        let original = l
            .store
            .read_verified(&l.profile, &key, &generation)
            .unwrap();
        let mut next = original.clone();
        super::super::operations::remove_authorizations(&mut next, |auth| auth.id == minted.id);
        l.store
            .commit_generation(&key, &generation, original, next)
            .unwrap();
        drop(lock);
    }
    let output = composed::release_child(child);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(l.wire().admissible_floor_ledger, Some(101));
}

#[test]
#[serial]
fn floor_unlinked_retention_is_not_history_coverage() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let l = Ledger::new();
    let mut request = floor_request(&l, 1, T0, 100);
    request.holds.clear();
    let minted = l.mint(&request).unwrap();
    l.claim(&request, &minted).unwrap();
    l.consume(&request, &minted, &consumption_of(&request.binding))
        .unwrap();
    assert_eq!(floor_sum(&l, Some(floor_seen())).unwrap(), 50);
    l.clock.set(T0 + 100 * 86_400_000);
    l.store.record_and_persist(&l.profile, &[]).unwrap();
    assert!(
        l.wire()
            .authorizations
            .iter()
            .all(|auth| auth.id != minted.id),
        "unlinked history can leave retention; this image cannot establish complete exposure"
    );
}
