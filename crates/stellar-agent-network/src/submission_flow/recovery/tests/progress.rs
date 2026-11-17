use super::*;
use crate::policy_state::operations::tests::progress::progress;

fn homed() -> (
    Rig,
    StellarAgentHomeGuard,
    stellar_agent_test_support::sandbox::StateSandbox,
) {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let guard = StellarAgentHomeGuard::new(home.path());
    (Rig::new(), guard, home)
}

#[tokio::test]
#[serial]
async fn recovery_progress_reads_verified_attempt() {
    let (mut rig, _guard, _home) = homed();
    let (handle, _) = commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
    let unresolved = unknown_named(&mut rig.fx, 2);
    rig.fx
        .recorder()
        .record_evidence(
            unresolved.id(),
            1,
            &crate::policy_state::EvidenceInput {
                recovery: Some(crate::policy_state::RecoveryUpdate {
                    disagreements: 3,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
    let (server, client) = endpoint().await;
    let window = rig.window_bytes();
    let receipts = rig.receipt_bytes();
    let found = progress(&rig.fx, 1);
    assert_eq!(found.operation.operation_id, handle.id());
    assert_eq!((found.attempt, found.tx_hash), (1, tx_hash(1)));
    assert!(found.exposure_present && found.projection_pending);
    assert_eq!(
        found.disagreements, 0,
        "a checked agreement clears disagreements"
    );
    assert_eq!(
        progress(&rig.fx, 2).disagreements,
        3,
        "unresolved disagreements remain visible"
    );
    assert!(!found.outcome_recoverable && !found.retry_eligible);
    assert_eq!(rig.window_bytes(), window);
    assert_eq!(rig.receipt_bytes(), receipts);
    assert_eq!(requests(&server).await, 0);
    let status = rig.status(1, &client).await.unwrap();
    assert_eq!(status.progress, Some(progress(&rig.fx, 1)));
    assert!(status.progress.unwrap().retry_eligible);
    assert_eq!(requests(&server).await, 0);
}

#[tokio::test]
#[serial]
async fn recovery_progress_failed_repair_with_true_marker() {
    let (mut rig, _guard, _home) = homed();
    commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
    let (server, client) = endpoint().await;
    let first = rig.status(1, &client).await.unwrap();
    let authenticated = progress(&rig.fx, 1);
    assert!(authenticated.retry_eligible);
    assert!(!authenticated.projection_pending);
    let window = rig.window_bytes();
    let receipt = rig.receipt_bytes();
    let held = hold_receipt_lock(&rig.receipts);
    for _ in 0..2 {
        let answer = rig.status(1, &client).await.unwrap();
        let view = answer.progress.unwrap();
        assert!(
            view.projection_pending,
            "failed repair of an acknowledged decision stays visible"
        );
        assert!(
            view.retry_eligible,
            "display failure does not revoke predecessor authority"
        );
        assert_eq!(view.retry_refusal, None);
        assert_eq!(view.projection_missing_fact, None);
        assert_eq!(
            (
                answer.chain_status,
                answer.ledger,
                answer.record,
                answer.reservation,
                answer.reservation_open
            ),
            (
                first.chain_status.clone(),
                first.ledger,
                first.record.clone(),
                first.reservation.clone(),
                first.reservation_open
            )
        );
        assert_eq!(progress(&rig.fx, 1), authenticated, "overlay is not stored");
        assert_eq!(rig.window_bytes(), window);
        assert_eq!(rig.receipt_bytes(), receipt);
    }
    drop(held);
    rig.reopen();
    let later = rig.status(1, &client).await.unwrap();
    assert_eq!(
        later.progress,
        Some(authenticated),
        "later repair clears only display pending"
    );
    assert_eq!(rig.window_bytes(), window);
    assert_eq!(rig.receipt_bytes(), receipt);
    assert_eq!(
        requests(&server).await,
        0,
        "managed status adds no diagnostic RPC"
    );
}

#[tokio::test]
#[serial]
async fn recovery_progress_invalid_and_historical_records() {
    for (checked, field) in [
        (Checked::NotIncluded, "source"),
        (Checked::NotIncluded, "submission_ledger"),
        (Checked::Failed, "failure_code"),
    ] {
        let (mut rig, _guard, _home) = homed();
        let (handle, commit) = historical_without(&mut rig.fx, 1, checked, field);
        commit_checked(&mut rig.fx, 2, Checked::NotIncluded);
        let (server, client) = endpoint().await;
        let answer = rig.status(1, &client).await.unwrap();
        let view = answer.progress.unwrap();
        assert_eq!(
            view.projection_missing_fact.as_deref(),
            Some(field),
            "exact missing provenance through status"
        );
        assert!(view.projection_pending);
        assert!(!view.retry_eligible);
        let pass = rig.dispatch(&client, Some(&rig.receipts), false).await;
        assert!(matches!(pass, ReconcilePass::RecoveryFailed { .. }));
        assert!(
            progress(&rig.fx, 2).retry_eligible,
            "neighbor repairs despite missing provenance"
        );
        assert_eq!(requests(&server).await, 0);
        if field == "source" {
            rig.fx
                .recorder()
                .acknowledge_projection(handle.id(), 1, commit)
                .unwrap();
            assert_eq!(
                progress(&rig.fx, 1).retry_refusal.as_deref(),
                Some("internal.unexpected_state"),
                "absent predecessor authorization cannot admit any successor"
            );
        }
    }
    for approval in [false, true] {
        let (mut rig, _guard, _home) = homed();
        let (_, nonce) = consumed_zero_entry(&mut rig.fx, 1, approval);
        commit_on(
            &mut rig.fx,
            tx_hash(1),
            checked_transition(1, Checked::NotIncluded, ""),
        );
        assert_eq!(
            rig.decision(1).projection_identity.unwrap().approval_nonce,
            nonce
        );
        assert_eq!(progress(&rig.fx, 1).projection_missing_fact, None);
        assert!(progress(&rig.fx, 1).projection_pending);
        rig.repair(None).unwrap();
        assert!(!progress(&rig.fx, 1).projection_pending);
        rig.edit_receipts(|map| {
            map.remove(&envelope_id(1));
        });
        assert!(
            progress(&rig.fx, 1).retry_eligible,
            "receipt removal grants and revokes nothing"
        );
    }
}

#[tokio::test]
#[serial]
async fn recovery_progress_projection_crash_restart() {
    use crate::policy_state::store::{COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED};
    for seam in [
        0,
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        6,
    ] {
        let (mut rig, _guard, _home) = homed();
        commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        assert!(
            progress(&rig.fx, 1).projection_pending,
            "decision before receipt"
        );
        let accounting = accounting_state(&rig.fx.store, &rig.fx.profile).0;
        let audit = rig.audit_bytes();
        let path = rig.fx.store.path().to_owned();
        let profile = rig.fx.profile.clone();
        let replacement = on_replacement(move || {
            let store = PersistedWindowStore::at_path(path.clone());
            let view = OperationStatus::new(&store, &profile)
                .submission_progress(&tx_hash(1))
                .unwrap()
                .unwrap();
            assert!(
                view.projection_pending && !view.retry_eligible,
                "rename does not acknowledge"
            );
            if seam == 0 {
                Err(record_unavailable("restart after receipt rename"))
            } else {
                Ok(())
            }
        });
        let fault = (seam != 0).then(|| arm_accounting_fault(seam));
        let (server, client) = endpoint().await;
        let first = rig.status(1, &client).await.unwrap();
        drop(fault);
        drop(replacement);
        assert_eq!(
            first.progress.as_ref().unwrap().retry_eligible,
            seam == COMMIT_FAULT_AFTER_COUNTER || seam == 6,
            "durable acknowledgement controls eligibility"
        );
        assert_eq!(
            first.progress.unwrap().projection_pending,
            seam != 6,
            "current failed repair remains pending"
        );
        rig.reopen();
        let later = rig.status(1, &client).await.unwrap();
        let view = later.progress.unwrap();
        assert!(
            view.retry_eligible && !view.projection_pending,
            "restart completes exact acknowledgement"
        );
        assert_eq!(
            accounting_state(&rig.fx.store, &rig.fx.profile).0,
            accounting
        );
        assert_eq!(rig.audit_bytes(), audit);
        let bytes = (rig.window_bytes(), rig.receipt_bytes());
        assert_eq!(rig.status(1, &client).await.unwrap().progress, Some(view));
        assert_eq!((rig.window_bytes(), rig.receipt_bytes()), bytes);
        assert_eq!(requests(&server).await, 0);
    }
}

#[tokio::test]
#[serial]
async fn recovery_progress_reuses_status_writer() {
    for mode in ["success", "acquisition", "poisoned", "repair"] {
        let (mut rig, _guard, _home) = homed();
        commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
        rig.repair(None).unwrap();
        let expected = rig.receipt(1);
        let (server, client) = endpoint().await;
        let held = (mode == "repair").then(|| hold_receipt_lock(&rig.receipts));
        if mode == "poisoned" {
            let writer = Arc::clone(&rig.writer);
            assert!(
                std::thread::spawn(move || {
                    let _guard = writer.lock().unwrap();
                    panic!("poisoned test writer");
                })
                .join()
                .is_err()
            );
        }
        let acquired = std::cell::Cell::new(0);
        let answer = transaction_status(
            StatusRequest {
                profile: &rig.fx.profile,
                profile_name: "ops",
                tx_hash: &tx_hex(1),
                window: &rig.fx.store,
                client: &client,
                oracle: None,
                retry_recovery: false,
            },
            || Ok(rig.home.path().join("approvals")),
            || {
                acquired.set(acquired.get() + 1);
                if mode == "acquisition" {
                    Err(record_unavailable("writer unavailable"))
                } else {
                    Ok(Arc::clone(&rig.writer))
                }
            },
        )
        .await
        .unwrap();
        drop(held);
        assert_eq!(acquired.get(), 1, "{mode}: one writer acquisition");
        assert_eq!(answer.chain_status, "NOT_FOUND");
        assert_eq!(answer.record, expected);
        assert_eq!(answer.reservation, None);
        assert!(!answer.reservation_open);
        let view = answer.progress.unwrap();
        assert!(
            view.retry_eligible,
            "{mode}: persisted predecessor facts stand"
        );
        assert_eq!(
            view.projection_pending,
            mode != "success",
            "{mode}: display repair result"
        );
        assert_eq!(
            requests(&server).await,
            0,
            "{mode}: no managed diagnostic request"
        );
    }
}

#[tokio::test]
#[serial]
async fn recovery_progress_read_refusal_is_typed() {
    let (mut rig, _guard, _home) = homed();
    commit_checked(&mut rig.fx, 1, Checked::NotIncluded);
    let coordinate = rig.fx.profile.policy_window_state_key_id.clone();
    let hook = std::rc::Rc::new(std::cell::RefCell::new(None));
    let retained = std::rc::Rc::clone(&hook);
    let replacement = on_replacement(move || {
        let coordinate = coordinate.clone();
        *retained.borrow_mut() = Some(
            crate::policy_state::operations::tests::progress::on_next_read(move || {
                stellar_agent_test_support::keyring_mock::inject_error(
                    &coordinate.service,
                    &coordinate.account,
                    keyring_core::Error::NoEntry,
                )
                .unwrap();
            }),
        );
        Ok(())
    });
    let (server, client) = endpoint().await;
    let result = rig.status(1, &client).await;
    drop(replacement);
    drop(hook.borrow_mut().take());
    assert!(
        matches!(&result, Err(StatusFailure::WindowUnreadable(error)) if error.submission_code() == "submission.record_unavailable"),
        "progress read refusal is not absent success: {result:?}"
    );
    assert!(rig.projected(1), "the preceding repair completed");
    assert!(
        rig.status(1, &client)
            .await
            .unwrap()
            .progress
            .unwrap()
            .retry_eligible,
        "the transient read failure clears"
    );
    assert_eq!(requests(&server).await, 0);
}
