//! Authenticated progress, predecessor permission and independent release obligations.

use super::*;
use crate::policy_state::WireRecoveryRun;
use std::cell::RefCell;

thread_local! {
    static READS: Cell<u32> = const { Cell::new(0) };
    static AFTER_READ: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

pub(crate) fn after_read() {
    READS.set(READS.get() + 1);
    if let Some(hook) = AFTER_READ.with_borrow_mut(Option::take) {
        hook();
    }
}

pub(crate) struct ReadHook;

impl Drop for ReadHook {
    fn drop(&mut self) {
        AFTER_READ.with_borrow_mut(|hook| *hook = None);
    }
}

pub(crate) fn on_next_read(hook: impl FnOnce() + 'static) -> ReadHook {
    AFTER_READ.with_borrow_mut(|slot| *slot = Some(Box::new(hook)));
    ReadHook
}

pub(crate) fn progress(fx: &Fx, n: u8) -> SubmissionProgress {
    OperationStatus::new(&fx.store, &fx.profile)
        .submission_progress(&[n ^ 0x80; 32])
        .unwrap()
        .unwrap()
}

fn homed() -> (
    stellar_agent_test_support::StellarAgentHomeGuard,
    stellar_agent_test_support::sandbox::StateSandbox,
) {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    (
        stellar_agent_test_support::StellarAgentHomeGuard::new(home.path()),
        home,
    )
}

/// Gives every retained authorization a native hold and fills the open-authorization cap.
pub(crate) fn fill_native_capacity(fx: &mut Fx) -> i128 {
    use crate::policy_state::ledger::{MAX_OPEN_AUTHORIZATIONS, NativeReservation};
    let amounts = NativeReservation {
        debit_stroops: 25,
        fee_stroops: 5,
    };
    fx.rewrite(|wire| {
        for auth in &mut wire.authorizations {
            auth.native_reservation = Some(amounts);
        }
    });
    let count = fx
        .wire()
        .authorizations
        .iter()
        .filter(|auth| auth.state.holds())
        .count();
    for n in count..MAX_OPEN_AUTHORIZATIONS {
        let mut mint = fx.mint_request(tx(40 + u8::try_from(n).unwrap()), fx.policy(), vec![]);
        mint.native_reservation = Some(amounts);
        fx.store.mint_authorization(&fx.profile, &mint).unwrap();
    }
    assert_eq!(
        fx.wire()
            .authorizations
            .iter()
            .filter(|auth| auth.state.holds())
            .count(),
        MAX_OPEN_AUTHORIZATIONS
    );
    let extra = fx.mint_request(tx(90), fx.policy(), vec![]);
    assert!(matches!(
        fx.store.mint_authorization(&fx.profile, &extra),
        Err(WindowStoreError::AuthorizationRefused {
            precondition: MainnetPrecondition::TooManyOpen
        })
    ));
    let total = OperationStatus::new(&fx.store, &fx.profile)
        .native_reserved_stroops(None)
        .unwrap();
    assert_eq!(total, i128::try_from(MAX_OPEN_AUTHORIZATIONS).unwrap() * 30);
    total
}

#[test]
#[serial]
fn submission_progress_one_verified_image() {
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    let sending = fx.open_new(&request("order-1", canonical(1)));
    let mint = fx.mint_request(tx(1), fx.policy(), vec![]);
    let started = fx.begin_mint(&sending, &mint).unwrap();
    fx.claim(&mint, started.minted.as_ref().unwrap());
    fx.recorder()
        .expose(sending.id(), 1, &classic_exposure(1), None)
        .unwrap();
    let unknown = unknown_named(&mut fx, 2);
    let predecessor = projected_not_included(&mut fx, 3);
    let (success, _) = commit_checked(&mut fx, 4, Checked::Succeeded);
    let (failed, _) = commit_checked(&mut fx, 5, Checked::Failed);
    let expired = terminal_classic(&mut fx, 6, T0 / 1000 + 10);
    for (n, handle, state) in [
        (1, &sending, OperationState::Sending),
        (2, &unknown, OperationState::SentOutcomeUnknown),
        (3, &predecessor, OperationState::NotIncluded),
        (4, &success, OperationState::Succeeded),
        (5, &failed, OperationState::Failed),
        (6, &expired, OperationState::Expired),
    ] {
        let bytes = fs::read(fx.store.path()).unwrap();
        READS.set(0);
        let found = progress(&fx, n);
        assert_eq!(READS.get(), 1, "one authenticated acquisition");
        assert_eq!(
            found.operation.operation_id,
            handle.id(),
            "exact exposure identity"
        );
        assert_eq!(found.operation.state, state);
        assert_eq!(found.attempt, 1);
        assert_eq!(found.tx_hash, [n ^ 0x80; 32]);
        assert!(found.exposure_present);
        assert_eq!(
            fs::read(fx.store.path()).unwrap(),
            bytes,
            "query writes nothing"
        );
    }
    successor_attempt(&mut fx, &predecessor, 7, 103);
    let historical = progress(&fx, 3);
    assert_eq!((historical.attempt, historical.operation.attempts), (1, 2));
    assert_eq!(
        historical.retry_refusal.as_deref(),
        Some("operation.attempt_open")
    );
    assert_eq!(progress(&fx, 7).attempt, 2);
    let commit = commit_on(
        &mut fx,
        [7 ^ 0x80; 32],
        checked_transition(7, Checked::NotIncluded, ""),
    );
    fx.recorder()
        .acknowledge_projection(predecessor.id(), 2, commit)
        .unwrap();
    assert_eq!(
        progress(&fx, 3).retry_refusal.as_deref(),
        Some("recovery.retry_refused"),
        "an older exposed proof is not the current predecessor"
    );
    assert!(progress(&fx, 7).retry_eligible);
    assert_eq!(
        OperationStatus::new(&fx.store, &fx.profile)
            .submission_progress(&[0x42; 32])
            .unwrap(),
        None
    );
    let mint = fx.mint_request(tx(8), fx.policy(), vec![]);
    fx.store.mint_authorization(&fx.profile, &mint).unwrap();
    assert_eq!(
        OperationStatus::new(&fx.store, &fx.profile)
            .submission_progress(&[8 ^ 0x80; 32])
            .unwrap(),
        None
    );
}

#[test]
#[serial]
fn submission_progress_and_admission_share_predecessor_guards() {
    let (_guard, _home) = homed();
    for case in ["proof", "decision", "ack", "open", "terminal", "expired"] {
        let mut fx = Fx::new();
        let handle = match case {
            "open" => unknown_named(&mut fx, 1),
            "terminal" => commit_checked(&mut fx, 1, Checked::Failed).0,
            _ => projected_not_included(&mut fx, 1),
        };
        fx.rewrite(|wire| {
            let record = &mut section_mut(wire).records[0];
            let attempt = &mut record.attempts[0];
            match case {
                "proof" => {
                    attempt.not_included = None;
                    attempt.decision = None;
                }
                "decision" => attempt.decision = None,
                "ack" => attempt.decision.as_mut().unwrap().projected = false,
                "expired" => record.execution_expires_at_ms = Some(T0),
                _ => {}
            }
        });
        let before = fs::read(fx.store.path()).unwrap();
        let found = progress(&fx, 1);
        let expected = match case {
            "open" => "operation.attempt_open",
            "terminal" => "internal.unexpected_state",
            "expired" => "network.mainnet_authorization_refused",
            _ => "recovery.retry_refused",
        };
        assert!(!found.retry_eligible, "{case}: predecessor refuses");
        assert_eq!(found.retry_refusal.as_deref(), Some(expected), "{case}");
        let mint = fx.mint_request(tx(11), fx.policy(), vec![]);
        let error = fx.begin_mint(&handle, &mint).unwrap_err();
        if case == "expired" {
            assert!(matches!(
                error,
                WindowStoreError::AuthorizationRefused {
                    precondition: MainnetPrecondition::Expired
                }
            ));
        }
        assert_eq!(
            crate::operation_entry::operation_refusal(error).code(),
            expected,
            "{case}: admission parity"
        );
        assert_eq!(fs::read(fx.store.path()).unwrap(), before);
    }
    for linked in [false, true] {
        let mut fx = Fx::new();
        let handle = projected_not_included(&mut fx, 1);
        fx.rewrite(|wire| section_mut(wire).records[0].execution_expires_at_ms = None);
        assert!(
            progress(&fx, 1).retry_eligible,
            "historical absent end permits a candidate"
        );
        let approval = fx.approval();
        let next = if linked {
            link_next(&fx, &handle, 21, approval);
            begin_linked(&mut fx, &handle).unwrap()
        } else {
            let mint = fx.mint_request(tx(21), approval, vec![]);
            fx.begin_mint(&handle, &mint).unwrap()
        };
        assert_eq!(next.attempt_index, 2, "fresh Approval successor");
        assert!(fx.record(handle.id()).execution_expires_at_ms.is_some());
    }
}

#[test]
#[serial]
fn release_candidates_exclude_checked_success_without_native_release() {
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    let (handle, _) = commit_checked(&mut fx, 1, Checked::Succeeded);
    let auth = fx.record(handle.id()).attempts[0].authorization_id;
    fx.rewrite(|wire| {
        wire.authorizations
            .iter_mut()
            .find(|row| row.id == auth)
            .unwrap()
            .native_release = None
    });
    let wire = fx.wire();
    assert!(records(&wire)[0].attempts[0].decision.is_some());
    assert_eq!(fx.auth(auth).native_release, None);
    assert!(
        candidates(&fx, Some(&[1 ^ 0x80; 32])).is_empty(),
        "checked success owns the obligation"
    );
}

fn store_run(fx: &Fx, n: u8, run: &WireRecoveryRun) {
    fx.rewrite(|wire| {
        attempt_of(wire, [n ^ 0x80; 32]).recovery_run =
            Some(serde_json::from_value(serde_json::to_value(run).unwrap()).unwrap());
    });
}

#[test]
#[serial]
fn submission_progress_matches_runnability_and_clock() {
    use crate::policy_state::recovery_run::{
        RecoveryClass, RecoveryRole, RecoveryRunMethod, RecoveryRunPhase, RecoveryStage,
        RecoveryStop, RecoveryStopReason,
    };
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    for n in 1..=5 {
        unknown_due(&mut fx, n, T0);
    }
    assert_eq!(
        OperationStatus::new(&fx.store, &fx.profile)
            .runnable_snapshot(None, T0)
            .unwrap()
            .len(),
        4
    );
    for n in 1..=5 {
        assert!(
            progress(&fx, n).outcome_recoverable,
            "no oldest-four truncation in a hash query"
        );
    }
    let (released, _) = decided_attempt(&mut fx, 6);
    fx.clock.set(T0 + 66_000);
    assert!(
        progress(&fx, 6).outcome_recoverable,
        "released unknown is runnable"
    );
    assert!(!progress(&fx, 6).retry_eligible);
    let record = fx.record(released.id());
    let attempt = &record.attempts[0];
    let exposure = crate::policy_state::recovery_exposure_digest(
        released.id(),
        1,
        &attempt.exposure.as_ref().unwrap().identity,
    )
    .unwrap();
    let mut run = WireRecoveryRun {
        version: 1,
        exposure,
        phase: RecoveryRunPhase::Running,
        run_started_ms: T0,
        run_deadline_ms: T0 + 20_000,
        automatic_runs: 1,
        consecutive_stops: 0,
        stop: None,
        scan: None,
    };
    store_run(&fx, 6, &run);
    for (clock, expected) in [
        (T0 - 1, false),
        (T0, false),
        (T0 + 19_999, false),
        (T0 + 49_999, false),
        (T0 + 50_000, true),
    ] {
        fx.clock.set(clock);
        let status = OperationStatus::new(&fx.store, &fx.profile);
        let snapshot = status
            .outcome_snapshot(Some(&[6 ^ 0x80; 32]))
            .unwrap()
            .remove(0);
        let view = status
            .recovery_run_view(released.id(), 1, clock)
            .unwrap()
            .unwrap();
        let expected_from_scheduler = crate::policy_state::recovery_run::recovery_runnable(
            &view,
            snapshot.recovery_run.as_ref(),
            clock,
            &crate::policy_state::recovery_run::recovery_configuration_digest(&fx.profile),
        );
        assert_eq!(expected_from_scheduler, expected);
        assert_eq!(
            progress(&fx, 6).outcome_recoverable,
            expected,
            "clock {clock}"
        );
    }
    fx.clock.set(T0 + 66_000);
    run.automatic_runs = 16;
    run.consecutive_stops = 15;
    store_run(&fx, 6, &run);
    assert!(
        !progress(&fx, 6).outcome_recoverable,
        "sixteen runs are exhausted"
    );
    fx.rewrite(|wire| {
        attempt_of(wire, [6 ^ 0x80; 32]).recovery_run =
            Some(serde_json::from_str(r#"{"version":99}"#).unwrap())
    });
    assert!(
        !progress(&fx, 6).outcome_recoverable,
        "unusable is not absent"
    );
    assert!(
        progress(&fx, 5).outcome_recoverable,
        "unrelated attempt remains runnable"
    );

    run.version = 2;
    run.phase = RecoveryRunPhase::Stopped;
    run.automatic_runs = 1;
    run.consecutive_stops = 1;
    run.stop = Some(RecoveryStop {
        reason: RecoveryStopReason::HistoryLost,
        stage: RecoveryStage::Target,
        method: Some(RecoveryRunMethod::GetLedgers),
        roles: vec![RecoveryRole::Primary],
        ledger: Some(10),
        target: Some(90),
        stopped_at_ms: T0,
        class: RecoveryClass::Explicit,
        earliest_retry_ms: None,
    });
    run.scan = Some(crate::policy_state::recovery_scan::RecoveryScan::new(
        crate::policy_state::recovery_run::recovery_configuration_digest(&fx.profile),
        &run.exposure,
        10,
    ));
    store_run(&fx, 6, &run);
    assert!(
        OperationStatus::new(&fx.store, &fx.profile)
            .outcome_snapshot(Some(&[6 ^ 0x80; 32]))
            .unwrap()[0]
            .recovery_run
            .as_ref()
            .unwrap()
            .record()
            .is_some(),
        "valid explicit stop"
    );
    assert!(!progress(&fx, 6).outcome_recoverable);
    run.scan.as_mut().unwrap().configuration = "ab".repeat(32);
    store_run(&fx, 6, &run);
    assert!(
        progress(&fx, 6).outcome_recoverable,
        "changed configuration reopens a saved scan"
    );
    run.automatic_runs = 16;
    run.consecutive_stops = 16;
    store_run(&fx, 6, &run);
    assert!(
        !progress(&fx, 6).outcome_recoverable,
        "configuration never adds a seventeenth run"
    );
}

#[test]
#[serial]
fn submission_progress_limits() {
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    let handle = projected_not_included(&mut fx, 1);
    for end in [None, Some(u64::MAX), Some(T0 + 1), Some(T0), Some(0)] {
        fx.rewrite(|wire| section_mut(wire).records[0].execution_expires_at_ms = end);
        let expected = end.is_none_or(|end| end > T0);
        assert_eq!(progress(&fx, 1).retry_eligible, expected, "end {end:?}");
    }
    fx.rewrite(|wire| section_mut(wire).records[0].execution_expires_at_ms = Some(T0 + 1));
    fx.clock.set(T0 + 1);
    assert_eq!(
        progress(&fx, 1).retry_refusal.as_deref(),
        Some("network.mainnet_authorization_refused"),
        "exact expiry"
    );
    fx.clock.set(T0 + 86_400_000);
    assert!(
        !progress(&fx, 1).retry_eligible,
        "later clock cannot renew the fixed end"
    );
    fx.clock.set(T0);
    fx.rewrite(|wire| section_mut(wire).records[0].execution_expires_at_ms = Some(u64::MAX));
    let first = fx.record(handle.id()).attempts[0].clone();
    for count in [7, 8] {
        fx.rewrite(|wire| {
            let record = &mut section_mut(wire).records[0];
            record.attempts = (1..=count)
                .map(|index| WireAttempt {
                    index,
                    evidence: Vec::new(),
                    exposure: if index == count {
                        first.exposure.clone()
                    } else {
                        None
                    },
                    decision: if index == count {
                        first.decision.clone()
                    } else {
                        None
                    },
                    ..first.clone()
                })
                .collect();
        });
        let found = progress(&fx, 1);
        assert_eq!(found.attempt, count);
        assert_eq!(found.retry_eligible, count < 8, "attempt cap");
        if count == 8 {
            assert_eq!(
                found.retry_refusal.as_deref(),
                Some("operation.attempt_limit")
            );
            assert_eq!(
                successor_refusal(&mut fx, &handle),
                "operation.attempt_limit"
            );
        }
    }
}

#[test]
#[serial]
fn submission_progress_rejects_invalid_state() {
    let (_guard, _home) = homed();
    for case in ["duplicate", "missing", "unknown"] {
        let mut fx = Fx::new();
        unknown_named(&mut fx, 1);
        let mut wire = fx.wire();
        if case == "duplicate" {
            let copy = records(&wire)[0].clone();
            section_mut(&mut wire).records.push(copy);
            fx.store.seal_unchecked_for_test(&fx.profile, &wire);
        } else {
            let mut raw = serde_json::to_value(&wire).unwrap();
            let record = raw["operations"]["records"][0].as_object_mut().unwrap();
            if case == "missing" {
                record.remove("business_id");
            } else {
                record.insert("future_field".into(), serde_json::json!(true));
            }
            let bytes = serde_json::to_vec(&raw).unwrap();
            let (key, _) = fx.store.load_or_mint_key(&fx.profile).unwrap();
            // The normal test sealer accepts typed records only; authenticate raw malformed JSON.
            use hmac::{Hmac, KeyInit, Mac};
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_ref()).unwrap();
            mac.update(b"stellar-agent-policy-window/v1/body\x00");
            mac.update(&bytes);
            let mut sealed = mac.finalize().into_bytes().to_vec();
            sealed.extend(bytes);
            fs::write(fx.store.path(), sealed).unwrap();
        }
        let status = OperationStatus::new(&fx.store, &fx.profile);
        let expected = status.outcome_snapshot(None).unwrap_err();
        let error = status.submission_progress(&[1 ^ 0x80; 32]).unwrap_err();
        assert_eq!(
            format!("{error:?}"),
            format!("{expected:?}"),
            "{case}: same typed reader refusal"
        );
    }
}

#[test]
#[serial]
fn submission_progress_two_process_generations() {
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    #[derive(Serialize, Deserialize)]
    struct ProcessImage {
        path: std::path::PathBuf,
        profile: Profile,
        credentials: Vec<(String, String, Vec<u8>)>,
    }
    if let Some(bridge) = std::env::var_os("SUBMISSION_PROGRESS_PROCESS") {
        let bridge = std::path::PathBuf::from(bridge);
        let image: ProcessImage = serde_json::from_slice(&fs::read(&bridge).unwrap()).unwrap();
        fx.profile = image.profile;
        fx.store = PersistedWindowStore::at_path(image.path);
        for (service, account, secret) in image.credentials {
            keyring_core::Entry::new(&service, &account)
                .unwrap()
                .set_secret(&secret)
                .unwrap();
        }
        assert!(
            progress(&fx, 1).retry_eligible,
            "both processes read the predecessor"
        );
        let handle = OperationHandle::of(&records(&fx.wire())[0]);
        let mint = fx.mint_request(tx(21), fx.policy(), vec![]);
        fx.begin_mint(&handle, &mint).unwrap();
        let coordinate = generation_entry_ref(&fx.profile);
        let generation = keyring_core::Entry::new(&coordinate.service, &coordinate.account)
            .unwrap()
            .get_secret()
            .unwrap();
        fs::write(bridge.with_extension("generation"), generation).unwrap();
        return;
    }
    let handle = projected_not_included(&mut fx, 1);
    // The child has its own mock keyring. Share only this fixture's coordinates,
    // then import its protected counter before the parent's next verified read.
    let coordinates = [
        fx.profile.policy_window_state_key_id.clone(),
        generation_entry_ref(&fx.profile),
        PinScope::for_profile(fx.store.path(), &fx.profile).pin_entry_ref(),
    ];
    let credentials = coordinates
        .into_iter()
        .map(|coordinate| {
            let secret = keyring_core::Entry::new(&coordinate.service, &coordinate.account)
                .unwrap()
                .get_secret()
                .unwrap();
            (coordinate.service, coordinate.account, secret)
        })
        .collect();
    let bridge = fx._dir.path().join("progress-process.json");
    fs::write(
        &bridge,
        serde_json::to_vec(&ProcessImage {
            path: fx.store.path().to_owned(),
            profile: fx.profile.clone(),
            credentials,
        })
        .unwrap(),
    )
    .unwrap();
    let coordinate = generation_entry_ref(&fx.profile);
    let child_home = _home.path().to_owned();
    AFTER_READ.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move || {
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "policy_state::operations::tests::progress::submission_progress_two_process_generations"])
                .env("SUBMISSION_PROGRESS_PROCESS", &bridge)
                .env("STELLAR_AGENT_HOME", child_home)
                .output().unwrap();
            assert!(child.status.success(), "child: {}", String::from_utf8_lossy(&child.stdout));
            keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap()
                .set_secret(&fs::read(bridge.with_extension("generation")).unwrap()).unwrap();
        }))
    });
    READS.set(0);
    let old = progress(&fx, 1);
    assert_eq!(
        READS.get(),
        1,
        "the interleaving never mixes image generations"
    );
    assert_eq!(
        (
            old.operation.state,
            old.operation.attempts,
            old.retry_eligible
        ),
        (OperationState::NotIncluded, 1, true)
    );
    let fresh = progress(&fx, 1);
    assert_eq!(
        (fresh.operation.state, fresh.operation.attempts),
        (OperationState::Sending, 2)
    );
    assert_eq!(
        fresh.retry_refusal.as_deref(),
        Some("operation.attempt_open")
    );
    let before = fs::read(fx.store.path()).unwrap();
    assert_eq!(
        successor_refusal(&mut fx, &handle),
        "operation.attempt_open",
        "admission rereads after stale permission"
    );
    assert_eq!(fs::read(fx.store.path()).unwrap(), before);
}

#[test]
#[serial]
fn submission_progress_candidate_checks_remain_admission_only() {
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    let (handle, commit, nonce) = commit_approved(&mut fx, 1, Checked::NotIncluded);
    fx.recorder()
        .acknowledge_projection(handle.id(), 1, commit)
        .unwrap();
    assert!(
        progress(&fx, 1).retry_eligible,
        "spent predecessor approval permits a fresh candidate"
    );
    let reused = fx.mint_request(
        tx(21),
        MintAuthority::Approval {
            nonce,
            expires_at_ms: T0 + APPROVAL_MS,
        },
        vec![],
    );
    let error = fx.begin_mint(&handle, &reused).unwrap_err();
    assert!(
        matches!(
            error,
            WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::ApprovalNonceReused
            }
        ),
        "reused nonce: {error:?}"
    );
    assert!(
        progress(&fx, 1).retry_eligible,
        "unspecified candidate nonce is not certified"
    );
    link_next(&fx, &handle, 22, fx.policy());
    let coordinate = PinScope::for_profile(fx.store.path(), &fx.profile).pin_entry_ref();
    stellar_agent_test_support::keyring_mock::inject_error(
        &coordinate.service,
        &coordinate.account,
        keyring_core::Error::NoEntry,
    )
    .unwrap();
    assert!(
        progress(&fx, 1).retry_eligible,
        "progress does not read the prospective pin"
    );
    let error = begin_linked(&mut fx, &handle).unwrap_err();
    assert!(
        matches!(
            error,
            WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::PolicyPinAbsent
            }
        ),
        "missing pin: {error:?}"
    );
    repin_policy(&fx, 8, [8; 32]);
    assert!(
        progress(&fx, 1).retry_eligible,
        "hash-only progress does not certify the current pin"
    );
    let before = fs::read(fx.store.path()).unwrap();
    let error = begin_linked(&mut fx, &handle).unwrap_err();
    assert!(
        matches!(
            error,
            WindowStoreError::AuthorizationRefused {
                precondition: MainnetPrecondition::PolicyPinMismatch
            }
        ),
        "changed pin: {error:?}"
    );
    assert_eq!(fs::read(fx.store.path()).unwrap(), before);
}
