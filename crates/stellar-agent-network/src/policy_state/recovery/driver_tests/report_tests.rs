use super::*;
use crate::policy_state::operations::tests::{Checked, commit_checked};

#[tokio::test]
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
    assert!(matches!(
        replay.attempts[0].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RetriesExhausted,
            next_action: RecoveryAction::EvidenceRequired,
            ..
        }
    ));
    assert!(matches!(
        replay.attempts[0].view.state,
        RecoveryRunState::RetriesExhausted {
            last_reason: RecoveryStopReason::ResponseTooLarge
        }
    ));
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
}

#[tokio::test]
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
