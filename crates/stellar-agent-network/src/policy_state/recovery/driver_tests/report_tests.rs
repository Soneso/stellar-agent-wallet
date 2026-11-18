use super::*;
use crate::policy_state::operations::tests::{Checked, commit_checked};

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn single_oversize_is_cached_terminal() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getLedgers"})))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("x".repeat(10_485_761)))
        .with_priority(1)
        .mount(&pair[0])
        .await;
    let report = fx.run(&pair).await.unwrap();
    assert!(matches!(
        report.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::ResponseTooLarge,
            next_action: RecoveryAction::Wait,
            ..
        }
    ));
    assert_eq!(
        report.attempts[0].view.class,
        Some(RecoveryClass::Automatic)
    );
    let due = report.attempts[0].view.earliest_retry_ms.unwrap();
    for (clock, reason) in [
        (NOW - 1, RecoveryReason::ClockRegression),
        (due - 1, RecoveryReason::ResponseTooLarge),
    ] {
        fx.fx.clock.set(clock);
        let replay = fx.run(&pair).await.unwrap();
        assert_eq!(replay.requests, RecoveryRequests::default());
        assert!(
            matches!(replay.attempts[0].result, RecoveryResult::NeedsEvidence { reason: seen, .. } if seen == reason)
        );
    }
    let mut run = fx.run_record(0);
    run.automatic_runs = 16;
    run.consecutive_stops = 16;
    run.stop.as_mut().unwrap().earliest_retry_ms = Some(recovery_retry_time(NOW, 15).unwrap());
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].attempts[0].recovery_run =
            Some(serde_json::from_value(serde_json::to_value(&run).unwrap()).unwrap())
    });
    fx.fx.clock.set(NOW + 86_400_000);
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let replay = fx.run(&pair).await.unwrap();
    assert_eq!(replay.requests, RecoveryRequests::default());
    assert_eq!(replay.attempts[0].reservations, Some(16));
    // An exhausted automatic stop names the explicit retry that can repair it.
    assert!(matches!(
        replay.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RetriesExhausted,
            next_action: RecoveryAction::RetryRecovery,
            ..
        }
    ));
    assert!(matches!(
        replay.attempts[0].view.state,
        RecoveryRunState::RetriesExhausted {
            last_reason: RecoveryStopReason::ResponseTooLarge
        }
    ));
    assert_eq!(
        replay.status_json().unwrap()["attempts"][0]["last_reason"],
        "ResponseTooLarge"
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn managed_status_uses_cached_result() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let mut fx = Fx::new();
    for (n, kind) in [
        (1, Checked::Succeeded),
        (2, Checked::Failed),
        (3, Checked::NotIncluded),
    ] {
        commit_checked(&mut fx, n, kind);
    }
    unknown_with(&mut fx, 4, NOW / 1000 + 60, vec![]);
    let server = endpoint(60, NOW / 1000).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let writer = crate::submission_flow::recovery::tests::writer_at(&fx.profile.audit_log_path);
    for (n, expected) in [
        (1, "SUCCESS"),
        (2, "FAILED"),
        (3, "NOT_FOUND"),
        (4, "UNKNOWN"),
    ] {
        for _ in 0..2 {
            let answer = crate::submission_flow::transaction_status(
                crate::submission_flow::StatusRequest {
                    profile: &fx.profile,
                    profile_name: "report",
                    tx_hash: &stellar_agent_core::hex::encode(&[n ^ 0x80; 32]),
                    window: &fx.store,
                    client: &client,
                    oracle: None,
                    retry_recovery: false,
                },
                || Ok(home.path().join("approvals")),
                || Ok(Arc::clone(&writer)),
            )
            .await;
            assert!(
                answer.is_ok(),
                "managed status uses cached evidence: {answer:?}"
            );
            let answer = answer.unwrap();
            assert_eq!(answer.chain_status, expected);
            let entry = &answer.recovery.attempts[0];
            assert_eq!(entry.tx_hash, [n ^ 0x80; 32]);
            if n < 4 {
                assert!(entry.settlement.as_ref().unwrap().projected);
            } else {
                assert!(matches!(
                    entry.result,
                    RecoveryResult::NeedsEvidence {
                        reason: RecoveryReason::RecoveryRequired,
                        next_action: RecoveryAction::TargetedStatus,
                        ..
                    }
                ));
            }
        }
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
    let result = crate::submission_flow::transaction_status(
        crate::submission_flow::StatusRequest {
            profile: &fx.profile,
            profile_name: "report",
            tx_hash: &"ff".repeat(32),
            window: &fx.store,
            client: &client,
            oracle: None,
            retry_recovery: false,
        },
        || Ok(home.path().join("approvals")),
        || Ok(Arc::clone(&writer)),
    )
    .await;
    assert!(matches!(
        result,
        Err(crate::submission_flow::StatusFailure::ChainQueryFailed(_))
    ));
    assert_eq!(rpc_request_count(&server, "getTransaction").await, 1);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn production_status_and_dispatch_use_outcomes() {
    use crate::submission_flow::{self, ReconcilePass, StatusRequest};
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let fx = Fixture::new(4, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
    let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
    let mut decisions = 0;
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 4 {
                decisions += 1;
                if decisions == 4 {
                    WRITE_FAULT.set((4, super::super::super::store::COMMIT_FAULT_AFTER_PREPARED));
                }
            }
        }))
    });
    let hook = Hook;
    let pass = submission_flow::reconcile_pass(
        &fx.fx.profile,
        &fx.fx.store,
        &left,
        Some(&right),
        None,
        NOW,
        || Ok(Arc::clone(&fx.writer)),
    )
    .await;
    drop(hook);
    let ReconcilePass::RecoveryFailed {
        legacy, recovery, ..
    } = &pass
    else {
        panic!("partial refusal: {pass:?}")
    };
    assert_eq!(legacy.rpc_calls, 0);
    assert_eq!(recovery.attempts.len(), 4);
    assert_eq!(recovery.evaluated, 3);
    assert_eq!(
        recovery
            .attempts
            .iter()
            .map(|a| a.operation_id)
            .collect::<Vec<_>>(),
        fx.ids
    );
    assert!(
        recovery.attempts[..3]
            .iter()
            .all(|a| matches!(a.result, RecoveryResult::NeverApplicable { .. }))
    );
    assert!(matches!(
        recovery.attempts[3].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::Running,
            ..
        }
    ));
    assert_eq!(
        recovery.refusal.as_ref().map(|r| r.code),
        Some("submission.record_unavailable")
    );
    submission_flow::finish_reconciliation(
        &fx.fx.profile,
        "report",
        &fx.fx.store,
        None,
        &pass,
        || Ok(Arc::clone(&fx.writer)),
    )
    .unwrap();
    let before = pair[0].received_requests().await.unwrap().len();
    let answer = submission_flow::transaction_status(
        StatusRequest {
            profile: &fx.fx.profile,
            profile_name: "report",
            tx_hash: &stellar_agent_core::hex::encode(&[1 ^ 0x80; 32]),
            window: &fx.fx.store,
            client: &left,
            oracle: Some(&right),
            retry_recovery: false,
        },
        || Ok(home.path().join("approvals")),
        || Ok(Arc::clone(&fx.writer)),
    )
    .await
    .unwrap();
    assert_eq!(answer.recovery.attempts[0].operation_id, fx.ids[0]);
    assert_eq!(answer.chain_status, "NOT_FOUND");
    assert_eq!(pair[0].received_requests().await.unwrap().len(), before);
    assert_eq!(recovery.attempts.len(), 4, "finishing retains every result");
    for server in &pair {
        assert_eq!(rpc_request_count(server, "sendTransaction").await, 0);
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn recovery_result_contract() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let mut fx = Fx::new();
    let mut expected = Vec::new();
    for (n, kind) in [
        (1, Checked::Succeeded),
        (2, Checked::Failed),
        (3, Checked::NotIncluded),
    ] {
        let (handle, commit) = commit_checked(&mut fx, n, kind);
        expected.push((handle.id(), commit, kind));
    }
    let server = endpoint(60, NOW / 1000).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let writer = crate::submission_flow::recovery::tests::writer_at(&fx.profile.audit_log_path);
    let before = std::fs::read(fx.store.path()).unwrap();
    for _ in 0..2 {
        let report = recover_outcomes(
            &fx.store,
            &fx.profile,
            EndpointPair::from_clients(&client, None),
            &writer,
            None,
        )
        .await
        .unwrap();
        assert_eq!(report.attempts.len(), 3);
        for (id, commit, kind) in &expected {
            let entry = report
                .attempts
                .iter()
                .find(|a| a.operation_id == *id)
                .unwrap();
            let decision = entry.settlement.as_ref().unwrap();
            assert_eq!(decision.commit_id, *commit);
            let progress = OperationStatus::new(&fx.store, &fx.profile)
                .submission_progress(&entry.tx_hash)
                .unwrap()
                .unwrap();
            assert_eq!(progress.operation.operation_id, *id);
            assert!(progress.exposure_present && progress.projection_pending);
            assert!(!progress.outcome_recoverable && !progress.retry_eligible);
            assert_eq!(decision.tx_hash, entry.tx_hash);
            match kind {
                Checked::Succeeded => assert_eq!(
                    entry.result,
                    RecoveryResult::Included {
                        status: RecoveryInclusion::Success,
                        ledger: decision.ledger.unwrap()
                    }
                ),
                Checked::Failed => assert_eq!(
                    entry.result,
                    RecoveryResult::Included {
                        status: RecoveryInclusion::Failed,
                        ledger: decision.ledger.unwrap()
                    }
                ),
                Checked::NotIncluded => assert_eq!(
                    entry.result,
                    RecoveryResult::NeverApplicable {
                        proof: decision.not_included.unwrap()
                    }
                ),
            }
        }
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
    assert_eq!(std::fs::read(fx.store.path()).unwrap(), before);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn recovery_reporting_legacy_compatibility() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let fx = Fixture::new(2, NOW / 1000 + 60);
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[1].attempts[0].recovery_run =
            Some(serde_json::from_value(json!({"unknown":true})).unwrap());
    });
    let pair = fx.pair([60, 60], NOW, 0).await;
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.evaluated, 0);
    assert_eq!(report.attempts.len(), 2);
    for entry in &report.attempts {
        let progress = OperationStatus::new(&fx.fx.store, &fx.fx.profile)
            .submission_progress(&entry.tx_hash)
            .unwrap()
            .unwrap();
        assert!(progress.exposure_present);
        assert!(!progress.outcome_recoverable && !progress.projection_pending);
    }
    assert!(matches!(
        report.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RecoveryRequired,
            ..
        }
    ));
    assert!(matches!(
        report.attempts[1].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RecordUnusable,
            next_action: RecoveryAction::EvidenceRequired,
            ..
        }
    ));
    assert!(
        report
            .attempts
            .iter()
            .all(|a| a.settlement.is_none() && a.reservations.is_none() && a.next_unread.is_none())
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
    assert_eq!(pair[0].received_requests().await.unwrap().len(), 0);
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[1].attempts[0].recovery_run =
            Some(serde_json::from_value(json!({"automatic_runs":16,"unknown":true})).unwrap());
    });
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let exhausted = fx.run(&pair).await.unwrap();
    assert_eq!(exhausted.attempts[1].reservations, Some(16));
    assert!(matches!(
        exhausted.attempts[1].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RetriesExhausted,
            ..
        }
    ));
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn identity_refusal_is_visible() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let report = recover_outcomes(
        &fx.fx.store,
        &fx.fx.profile,
        EndpointPair::from_clients(&left, None),
        &fx.writer,
        None,
    )
    .await
    .unwrap();
    assert!(matches!(
        report.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::ConfigurationRequired,
            next_action: RecoveryAction::EvidenceRequired,
            ..
        }
    ));
    for (identity, code) in [
        (
            json!({"passphrase":"wrong", "protocolVersion":23}),
            "network.endpoint_network_mismatch",
        ),
        (
            json!({"passphrase":stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
            "protocolVersion":0}),
            "network.unsupported_protocol_version",
        ),
    ] {
        let pair = fx.pair([60, 60], NOW, 0).await;
        override_answer(&pair[0], "getNetwork", identity).await;
        let error = fx.run(&pair).await.unwrap_err();
        assert_eq!(error.code(), code);
        let report = error.report().unwrap();
        assert_eq!(report.refusal.as_ref().map(|r| r.code), Some(code));
        assert_eq!(report.attempts[0].operation_id, fx.ids[0]);
        assert_eq!(report.requests.shared, 1);
        assert!(matches!(
            report.attempts[0].result,
            RecoveryResult::NeedsEvidence {
                reason: RecoveryReason::ConfigurationRequired,
                missing: Some(RecoveryFailure {
                    method: RecoveryMethod::GetNetwork,
                    ..
                }),
                next_action: RecoveryAction::EvidenceRequired,
            }
        ));
        assert!(report.attempts[0].settlement.is_none());
        assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
    }
    let pair = fx.pair([60, 60], NOW, 0).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getNetwork"})))
        .respond_with(wiremock::ResponseTemplate::new(502))
        .with_priority(1)
        .mount(&pair[0])
        .await;
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(
        report.refusal.as_ref().map(|r| r.code),
        Some("recovery.needs_evidence")
    );
    assert!(matches!(
        report.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::Transport,
            missing: Some(RecoveryFailure {
                endpoint: RecoveryEndpoint::Primary,
                method: RecoveryMethod::GetNetwork,
                ..
            }),
            next_action: RecoveryAction::Wait,
        }
    ));
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 1,
            attempt: 0
        }
    );
    assert!(report.attempts[0].settlement.is_none());
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn writer_or_store_refusal_is_visible() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    for seam in [
        super::super::super::store::COMMIT_FAULT_AFTER_PREPARED,
        super::super::super::store::COMMIT_FAULT_AFTER_COUNTER,
    ] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = fx.pair([60, 60], NOW, 0).await;
        let error = {
            let _fault = arm_write_fault(4, seam);
            fx.run(&pair).await.unwrap_err()
        };
        let report = error.report().unwrap();
        assert_eq!(
            report.refusal.as_ref().map(|r| r.code),
            Some("submission.record_unavailable")
        );
        assert!(!report.refusal.as_ref().unwrap().state_unavailable);
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 6
            }
        );
        assert_eq!(
            report.attempts[0].settlement.is_some(),
            seam == super::super::super::store::COMMIT_FAULT_AFTER_COUNTER
        );
    }
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let client = StellarRpcClient::new(&pair[0].uri()).unwrap();
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let calls = std::cell::Cell::new(0);
    let answer = crate::submission_flow::transaction_status(
        crate::submission_flow::StatusRequest {
            profile: &fx.fx.profile,
            profile_name: "report",
            tx_hash: &stellar_agent_core::hex::encode(&[1 ^ 0x80; 32]),
            window: &fx.fx.store,
            client: &client,
            oracle: None,
            retry_recovery: false,
        },
        || Ok(home.path().join("approvals")),
        || {
            calls.set(calls.get() + 1);
            Err(WalletError::Submission(
                stellar_agent_core::error::SubmissionError::RecordUnavailable {
                    detail: "writer refused".into(),
                },
            ))
        },
    )
    .await
    .unwrap();
    assert_eq!(
        answer.recovery.refusal.as_ref().map(|r| r.code),
        Some("submission.record_unavailable")
    );
    assert_eq!(answer.chain_status, "UNKNOWN");
    assert_eq!(calls.get(), 1);
    assert_eq!(pair[0].received_requests().await.unwrap().len(), 0);
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
    let writer = Arc::clone(&fx.writer);
    assert!(
        std::thread::spawn(move || {
            let _guard = writer.lock().unwrap();
            panic!("poison the writer");
        })
        .join()
        .is_err()
    );
    let pass = crate::submission_flow::reconcile_pass(
        &fx.fx.profile,
        &fx.fx.store,
        &client,
        None,
        None,
        NOW,
        || Ok(Arc::clone(&fx.writer)),
    )
    .await;
    assert!(
        matches!(&pass, crate::submission_flow::ReconcilePass::RecoveryFailed { recovery, .. }
        if recovery.refusal.as_ref().map(|r| (r.code, r.state_unavailable))
            == Some(("submission.record_unavailable", false))
            && recovery.attempts.len() == 1
            && recovery.attempts[0].settlement.is_none())
    );
    assert_eq!(pair[0].received_requests().await.unwrap().len(), 0);
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
}

/// Targeted status of `hash` through the production facade.
async fn status(
    fx: &Fixture,
    pair: &[MockServer; 2],
    home: &std::path::Path,
    hash: [u8; 32],
    retry_recovery: bool,
) -> crate::submission_flow::StatusOutcome {
    let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
    let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
    crate::submission_flow::transaction_status(
        crate::submission_flow::StatusRequest {
            profile: &fx.fx.profile,
            profile_name: "report",
            tx_hash: &stellar_agent_core::hex::encode(&hash),
            window: &fx.fx.store,
            client: &left,
            oracle: Some(&right),
            retry_recovery,
        },
        || Ok(home.join("approvals")),
        || Ok(Arc::clone(&fx.writer)),
    )
    .await
    .unwrap()
}

fn store_run(fx: &Fixture, run: &WireRecoveryRun) {
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].attempts[0].recovery_run =
            Some(serde_json::from_value(serde_json::to_value(run).unwrap()).unwrap())
    });
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn explicit_retry_starts_one_bounded_run() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    // An untimed attempt reads only its hash pair in each run.
    let fx = Fixture::new(1, 0);
    let early = fx.pair([60, 60], NOW, 0).await;
    fx.run(&early).await.unwrap();
    let mut run = fx.run_record(0);
    assert_eq!(
        run.stop.as_ref().unwrap().reason,
        RecoveryStopReason::Untimed
    );
    run.automatic_runs = 16;
    run.consecutive_stops = 16;
    run.stop.as_mut().unwrap().earliest_retry_ms = Some(recovery_retry_time(NOW, 15).unwrap());
    store_run(&fx, &run);
    let hash = [1 ^ 0x80; 32];
    let later = NOW + 86_400_000;
    // Health observations are fresh at the later clock.
    let pair = fx.pair([61, 61], later, 0).await;
    let hashes = || async { rpc_request_count(&pair[0], "getTransaction").await };
    let requests = || async {
        pair[0].received_requests().await.unwrap().len()
            + pair[1].received_requests().await.unwrap().len()
    };
    fx.fx.clock.set(later);
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    let seen = hashes().await;
    let ordinary = status(&fx, &pair, home.path(), hash, false).await;
    assert_eq!(
        requests().await,
        0,
        "ordinary status replays the exhausted stop"
    );
    assert_eq!(ordinary.chain_status, "UNKNOWN");
    assert!(matches!(
        ordinary.recovery.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RetriesExhausted,
            next_action: RecoveryAction::RetryRecovery,
            ..
        }
    ));
    // These endpoints are fresh at the earlier clock, so only the clock refuses.
    fx.fx.clock.set(NOW - 1);
    let early_hashes = rpc_request_count(&early[0], "getTransaction").await;
    status(&fx, &early, home.path(), hash, true).await;
    assert_eq!(
        rpc_request_count(&early[0], "getTransaction").await,
        early_hashes,
        "an earlier clock refuses the explicit run"
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
    fx.fx.clock.set(later);
    let retried = status(&fx, &pair, home.path(), hash, true).await;
    assert_eq!(
        hashes().await,
        seen + 1,
        "one fresh hash pair and no extra lookup"
    );
    assert_eq!(
        retried.recovery.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 2
        }
    );
    let after = fx.run_record(0);
    assert_eq!((after.automatic_runs, after.consecutive_stops), (1, 1));
    assert_eq!(
        after.stop.as_ref().unwrap().earliest_retry_ms,
        Some(later + 30_000)
    );
    assert_eq!(retried.recovery.attempts[0].reservations, Some(1));
    assert!(matches!(
        retried.recovery.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::Untimed,
            next_action: RecoveryAction::Wait,
            ..
        }
    ));
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    let sent = requests().await;
    status(&fx, &pair, home.path(), hash, false).await;
    assert_eq!(
        requests().await,
        sent,
        "an early ordinary status sends nothing"
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
    status(&fx, &pair, home.path(), hash, true).await;
    assert_eq!(hashes().await, seen + 2, "an explicit request runs early");
    assert_eq!(fx.run_record(0).automatic_runs, 1);
    let mut live = fx.run_record(0);
    live.phase = RecoveryRunPhase::Running;
    live.stop = None;
    live.run_started_ms = later;
    live.run_deadline_ms = later + 20_000;
    // The sixteenth reservation normalizes to RetriesExhausted, yet its lease is live.
    for (runs, stops) in [(1, 0), (16, 15)] {
        live.automatic_runs = runs;
        live.consecutive_stops = stops;
        store_run(&fx, &live);
        fx.fx.clock.set(later + 1);
        let bytes = std::fs::read(fx.fx.store.path()).unwrap();
        let owned = status(&fx, &pair, home.path(), hash, true).await;
        assert_eq!(
            hashes().await,
            seen + 2,
            "a live lease keeps its owner at reservation {runs}"
        );
        assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
        assert_eq!(owned.recovery.attempts[0].reservations, Some(runs));
    }
    // Past its deadline the sixteenth lease is exhausted with an interrupted cause.
    fx.fx.clock.set(later + 20_000);
    let expired = status(&fx, &pair, home.path(), hash, false).await;
    assert_eq!(
        expired.recovery.attempts[0].view.state,
        RecoveryRunState::RetriesExhausted {
            last_reason: RecoveryStopReason::Interrupted
        }
    );
    let public = expired.recovery.status_json().unwrap();
    assert_eq!(
        (
            &public["attempts"][0]["reason"],
            &public["attempts"][0]["last_reason"]
        ),
        (&json!("RetriesExhausted"), &json!("Interrupted"))
    );
    assert_eq!(hashes().await, seen + 2);
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].attempts[0].recovery_run =
            Some(serde_json::from_str("{ \"version\":99 }").unwrap());
    });
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    let unusable = status(&fx, &pair, home.path(), hash, true).await;
    assert_eq!(
        hashes().await,
        seen + 2,
        "a flag repairs no unusable record"
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
    assert!(matches!(
        unusable.recovery.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RecordUnusable,
            ..
        }
    ));
    let unmanaged = status(&fx, &pair, home.path(), [0xff; 32], true).await;
    assert_eq!(
        hashes().await,
        seen + 3,
        "an unmanaged hash keeps its lookup"
    );
    assert!(unmanaged.recovery.status_json().is_none());
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
    for server in &pair {
        assert_eq!(rpc_request_count(server, "sendTransaction").await, 0);
    }
}

/// An untimed attempt with sixteen spent reservations, the pair fresh at
/// `NOW`, the pair fresh at `NOW + 1 day`, and its hash.
async fn exhausted_attempt() -> (Fixture, [MockServer; 2], [MockServer; 2], [u8; 32]) {
    let fx = Fixture::new(1, 0);
    let early = fx.pair([60, 60], NOW, 0).await;
    fx.run(&early).await.unwrap();
    let mut run = fx.run_record(0);
    run.automatic_runs = 16;
    run.consecutive_stops = 16;
    run.stop.as_mut().unwrap().earliest_retry_ms = Some(recovery_retry_time(NOW, 15).unwrap());
    store_run(&fx, &run);
    let later = fx.pair([61, 61], NOW + 86_400_000, 0).await;
    (fx, early, later, [1 ^ 0x80; 32])
}

/// An explicit request that reads no hash, writes nothing, and reports
/// `recovery.retry_refused` beside the readable attempt result.
async fn refused_retry(
    fx: &Fixture,
    pair: &[MockServer; 2],
    home: &std::path::Path,
    hash: [u8; 32],
) -> RecoveryReport {
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    let seen = rpc_request_count(&pair[0], "getTransaction").await;
    let outcome = status(fx, pair, home, hash, true).await;
    assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, seen);
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
    assert_eq!(
        outcome
            .recovery
            .refusal
            .as_ref()
            .map(|r| (r.code, r.state_unavailable)),
        Some(("recovery.retry_refused", false)),
        "the refused explicit request carries its stable code"
    );
    assert_eq!(outcome.chain_status, "UNKNOWN");
    for server in pair {
        assert_eq!(rpc_request_count(server, "sendTransaction").await, 0);
    }
    outcome.recovery
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn explicit_retry_refuses_an_earlier_clock() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let (fx, early, _later, hash) = exhausted_attempt().await;
    fx.fx.clock.set(NOW - 1);
    let ordinary = status(&fx, &early, home.path(), hash, false).await;
    assert_eq!(
        ordinary.recovery.refusal, None,
        "an ordinary status requests no retry"
    );
    let report = refused_retry(&fx, &early, home.path(), hash).await;
    assert!(
        matches!(
            report.attempts[0].result,
            RecoveryResult::NeedsEvidence {
                reason: RecoveryReason::RetriesExhausted,
                next_action: RecoveryAction::RetryRecovery,
                ..
            }
        ),
        "the exhausted result stays readable: {:?}",
        report.attempts[0].result
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn explicit_retry_refuses_an_earlier_clock_after_a_configuration_change() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    // A HistoryLost stop with a saved scan reopens under a changed configuration.
    let mut fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = super::scan_tests::scan_pair(&fx, 34).await;
    for server in &pair {
        let mut answer = target_page(NOW / 1000);
        answer["oldestLedger"] = json!(21);
        Mock::given(method("POST"))
            .and(body_partial_json(
                json!({"method":"getLedgers","params":{"startLedger":20}}),
            ))
            .respond_with(EchoIdResponder::new(answer))
            .with_priority(1)
            .mount(server)
            .await;
    }
    fx.run(&pair).await.unwrap();
    let stored = fx.run_record(0);
    assert_eq!(
        (stored.stop.as_ref().unwrap().reason, stored.automatic_runs),
        (RecoveryStopReason::HistoryLost, 1)
    );
    assert!(stored.scan.is_some());
    fx.fx.profile.oracle_provider_url = Some("http://127.0.0.3".parse().unwrap());
    fx.fx
        .clock
        .set(stored.stop.as_ref().unwrap().stopped_at_ms - 1);
    let mut seen = Vec::new();
    for server in &pair {
        seen.push(rpc_request_count(server, "getTransaction").await);
    }
    let hash = [1 ^ 0x80; 32];
    let report = refused_retry(&fx, &pair, home.path(), hash).await;
    for (server, before) in pair.iter().zip(seen) {
        assert_eq!(
            rpc_request_count(server, "getTransaction").await,
            before,
            "a refused explicit request reads no hash"
        );
    }
    assert_eq!(fx.run_record(0).automatic_runs, 1);
    assert!(
        matches!(
            report.attempts[0].result,
            RecoveryResult::NeedsEvidence {
                reason: RecoveryReason::HistoryLost,
                ..
            }
        ),
        "the history-loss result stays readable: {:?}",
        report.attempts[0].result
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn explicit_retry_refuses_a_live_lease() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let (fx, _early, pair, hash) = exhausted_attempt().await;
    let later = NOW + 86_400_000;
    let mut live = fx.run_record(0);
    live.phase = RecoveryRunPhase::Running;
    live.stop = None;
    live.automatic_runs = 1;
    live.consecutive_stops = 0;
    live.run_started_ms = later;
    live.run_deadline_ms = later + 20_000;
    store_run(&fx, &live);
    fx.fx.clock.set(later + 1);
    let report = refused_retry(&fx, &pair, home.path(), hash).await;
    assert_eq!(report.attempts[0].view.state, RecoveryRunState::Running);
    assert!(
        matches!(
            report.attempts[0].result,
            RecoveryResult::NeedsEvidence {
                reason: RecoveryReason::Running,
                ..
            }
        ),
        "the live result stays readable: {:?}",
        report.attempts[0].result
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn explicit_retry_refuses_unusable_metadata() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let (fx, _early, pair, hash) = exhausted_attempt().await;
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].attempts[0].recovery_run =
            Some(serde_json::from_str("{ \"version\":99 }").unwrap());
    });
    fx.fx.clock.set(NOW + 86_400_000);
    let report = refused_retry(&fx, &pair, home.path(), hash).await;
    assert!(
        matches!(
            report.attempts[0].result,
            RecoveryResult::NeedsEvidence {
                reason: RecoveryReason::RecordUnusable,
                next_action: RecoveryAction::EvidenceRequired,
                ..
            }
        ),
        "the unusable result stays readable: {:?}",
        report.attempts[0].result
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn non_selectable_records_get_no_status_action() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let fx = Fixture::new(3, NOW / 1000 + 60);
    fx.fx.rewrite(|wire| {
        let records = &mut wire.operations.as_mut().unwrap().records;
        for (record, state) in records[1..]
            .iter_mut()
            .zip([OperationState::Cancelled, OperationState::Expired])
        {
            record
                .history
                .push(crate::policy_state::operations::HistoryEntry {
                    from: Some(record.state),
                    to: state,
                    at_ms: NOW,
                    evidence: None,
                });
            record.state = state;
            record.closed_at_ms = Some(NOW);
        }
    });
    let pair = fx.pair([60, 60], NOW, 0).await;
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.evaluated, 0);
    let actions: Vec<_> = report
        .attempts
        .iter()
        .map(|a| match a.result {
            RecoveryResult::NeedsEvidence {
                reason: RecoveryReason::RecoveryRequired,
                next_action,
                ..
            } => next_action,
            _ => panic!("no run and no decision: {:?}", a.result),
        })
        .collect();
    assert_eq!(
        actions,
        [
            RecoveryAction::TargetedStatus,
            RecoveryAction::EvidenceRequired,
            RecoveryAction::EvidenceRequired
        ]
    );
    assert!(
        report
            .attempts
            .iter()
            .all(|a| a.chain_status() == ("UNKNOWN", None))
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn status_recovery_projection() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let mut fx = Fx::new();
    let mut commits = Vec::new();
    for (n, kind) in [(1, Checked::Succeeded), (3, Checked::NotIncluded)] {
        commits.push(commit_checked(&mut fx, n, kind).1.to_hex());
    }
    unknown_with(&mut fx, 4, NOW / 1000 + 60, vec![]);
    let server = endpoint(60, NOW / 1000).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let writer = crate::submission_flow::recovery::tests::writer_at(&fx.profile.audit_log_path);
    let report = recover_outcomes(
        &fx.store,
        &fx.profile,
        EndpointPair::from_clients(&client, None),
        &writer,
        None,
    )
    .await
    .unwrap();
    let value = report.status_json().unwrap();
    let entry = |n: u8| {
        value["attempts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["tx_hash"] == stellar_agent_core::hex::encode(&[n ^ 0x80; 32]))
            .unwrap()
            .clone()
    };
    let success = entry(1);
    assert_eq!(
        (
            &success["result"],
            &success["status"],
            success["ledger"].is_u64()
        ),
        (&json!("Included"), &json!("Success"), true)
    );
    assert_eq!(success["settlement_commit_id"], commits[0]);
    let absent = entry(3);
    assert_eq!(absent["result"], "NeverApplicable");
    assert!(absent["proof"].is_object(), "{absent}");
    assert_eq!(absent["settlement_commit_id"], commits[1]);
    let unknown = entry(4);
    assert_eq!(unknown["settlement_commit_id"], Value::Null);
    assert_eq!(unknown["last_reason"], Value::Null);
    assert_eq!(
        (
            &unknown["result"],
            &unknown["reason"],
            &unknown["next_action"],
            &unknown["class"]
        ),
        (
            &json!("NeedsEvidence"),
            &json!("RecoveryRequired"),
            &json!("TargetedStatus"),
            &json!("automatic")
        )
    );
    assert_eq!(unknown["earliest_retry_ms"], (NOW / 1000 + 66) * 1000);
    assert_eq!(value["refusal"], Value::Null);
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn attached_report_keeps_the_refusal_shape() {
    let home = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let fx = Fx::new();
    let root = || RecoveryError::Store(WindowStoreError::Invalid { detail: "x".into() });
    let error = root().with_report(RecoveryReport::default());
    assert_eq!(error.to_string(), root().to_string());
    let pass = crate::submission_flow::ReconcilePass::RecoveryFailed {
        legacy: Default::default(),
        recovery: RecoveryReport::default(),
        error,
    };
    let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
    crate::submission_flow::finish_reconciliation(
        &fx.profile,
        "ops",
        &fx.store,
        None,
        &pass,
        || panic!("no accounting obligation needs a writer"),
    )
    .unwrap();
    drop(guard);
    let messages = format!("{:?}", warnings.seen());
    assert!(
        messages.contains("unresolved sequences stay held"),
        "{messages}"
    );
    assert!(
        !messages.contains("every sequence stays held"),
        "{messages}"
    );
}
