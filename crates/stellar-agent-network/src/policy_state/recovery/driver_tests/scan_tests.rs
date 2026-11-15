use super::*;

async fn scan_pair(fx: &Fixture, end: u32) -> [MockServer; 2] {
    let pair = fx.pair([60, 60], NOW, 101).await;
    for server in &pair {
        let tip = std::sync::atomic::AtomicU32::new(61);
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getLedgers"})))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let n = body["params"]["startLedger"].as_u64().unwrap();
                assert_eq!(body["params"]["pagination"]["limit"], 1);
                let close = if n < u64::from(end) {
                    NOW / 1000 - 10
                } else {
                    NOW / 1000
                };
                let mut page = target_page(close);
                page["ledgers"][0]["sequence"] = json!(n);
                page["latestLedger"] = json!(tip.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
                wiremock::ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc":"2.0","id":body["id"],"result":page
                }))
            })
            .with_priority(2)
            .mount(server)
            .await;
    }
    pair
}

async fn starts(server: &MockServer) -> Vec<u32> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter_map(|r| {
            let value: Value = serde_json::from_slice(&r.body).unwrap();
            (value["method"] == "getLedgers")
                .then(|| u32::try_from(value["params"]["startLedger"].as_u64().unwrap()).unwrap())
        })
        .collect()
}

#[tokio::test]
#[serial]
async fn driver_scan_rejects_tip_regression_after_release_read() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    let mut page = target_page(NOW / 1000 - 10);
    page["ledgers"][0]["sequence"] = json!(20);
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({"method":"getLedgers","params":{"startLedger":20}}),
        ))
        .respond_with(EchoIdResponder::new(page))
        .with_priority(1)
        .mount(&pair[0])
        .await;
    fx.run(&pair).await.unwrap();
    let run = fx.run_record(0);
    let stop = run.stop.unwrap();
    assert_eq!(
        (stop.reason, stop.ledger, stop.roles),
        (
            RecoveryStopReason::Lagging,
            Some(20),
            vec![RecoveryRole::Primary]
        )
    );
    assert_eq!(run.scan.unwrap().next_unread, 20);
    assert_eq!(starts(&pair[0]).await, vec![60, 20]);
    assert_eq!(starts(&pair[1]).await, vec![60]);
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
}

fn next_run(fx: &Fixture) {
    fx.fx
        .clock
        .set(fx.run_record(0).stop.unwrap().earliest_retry_ms.unwrap());
}

#[tokio::test]
#[serial]
async fn driver_scan_budget_leaves_later_attempt_unreserved() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(2, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 50).await;
    let first = fx.run(&pair).await.unwrap();
    assert_eq!(
        first.evaluated, 1,
        "an exhausted call cannot reserve another attempt"
    );
    assert_eq!(
        first.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 24
        }
    );
    assert!(fx.fx.record(fx.ids[1]).attempts[0].recovery_run.is_none());
    let second = fx.run(&pair).await.unwrap();
    assert_eq!(
        second.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 6
        }
    );
    assert!(fx.fx.record(fx.ids[1]).attempts[0].decision.is_some());
    assert_eq!(fx.run_record(0).automatic_runs, 1);
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
}

#[tokio::test]
#[serial]
async fn driver_scan_crash_keeps_prefix_and_spends_run() {
    use super::super::super::store::{COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED};
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for seam in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = scan_pair(&fx, 50).await;
        let fault = arm_write_fault(3, seam);
        assert!(fx.run(&pair).await.is_err());
        drop(fault);
        let before = fx.run_record(0);
        assert_eq!(before.automatic_runs, 1);
        if seam == COMMIT_FAULT_AFTER_PREPARED {
            assert_eq!(before.phase, RecoveryRunPhase::Running);
            assert!(before.scan.is_none());
            fx.fx.clock.set(before.run_deadline_ms + 30_000);
        } else {
            assert_eq!(before.scan.unwrap().next_unread, 29);
            next_run(&fx);
        }
        let result = fx.run(&pair).await;
        assert!(
            result.is_ok(),
            "a spent reservation resumes with valid ownership"
        );
        result.unwrap();
        let after = fx.run_record(0);
        assert_eq!(after.automatic_runs, 2, "a crash spends its reservation");
        assert_eq!(
            after.scan.unwrap().next_unread,
            if seam == COMMIT_FAULT_AFTER_PREPARED {
                30
            } else {
                39
            }
        );
        assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
    }
}

#[tokio::test]
#[serial]
async fn driver_scan_resumes_prefix_and_stops_at_b() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 34).await;
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 24
        }
    );
    let first = fx.run_record(0);
    assert_eq!(
        first.stop.unwrap().reason,
        RecoveryStopReason::RequestBudget
    );
    let scan = first.scan.unwrap();
    assert_eq!(scan.next_unread, 29);
    assert_eq!(scan.end, None);
    assert_eq!(scan.preceding_close, Some(NOW / 1000 - 10));
    next_run(&fx);
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 16
        }
    );
    let second = fx.run_record(0);
    let end = second.scan.unwrap();
    assert_eq!(end.end, Some((34, NOW / 1000)));
    assert_eq!(end.next_unread, 35);
    assert_ne!(end.digest, scan.digest);
    assert_eq!(second.automatic_runs, 2);
    let stop = second.stop.unwrap();
    assert_eq!(
        (stop.reason, stop.class),
        (
            RecoveryStopReason::CoverageRequired,
            RecoveryClass::Automatic
        )
    );
    for server in &pair {
        assert_eq!(
            starts(server).await,
            [vec![60], (20..=34).collect()].concat()
        );
    }
    let record = fx.fx.record(fx.ids[0]);
    assert!(record.attempts[0].decision.is_none());
    assert_eq!(record.state, OperationState::SentOutcomeUnknown);
    assert!(
        record.attempts[0]
            .recovery
            .as_ref()
            .unwrap()
            .primary_cursor
            .is_none()
    );
}

#[tokio::test]
#[serial]
async fn driver_missing_provenance_stops_explicit() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    fx.fx.rewrite(|wire| {
        let attempt = &mut wire.operations.as_mut().unwrap().records[0].attempts[0];
        attempt.pre_exposure_ledger = None;
        attempt.recovery.get_or_insert_default().primary_cursor = Some(30);
    });
    let pair = scan_pair(&fx, 34).await;
    fx.run(&pair).await.unwrap();
    let stop = fx.run_record(0).stop.unwrap();
    assert_eq!(
        (stop.reason, stop.class, stop.earliest_retry_ms),
        (
            RecoveryStopReason::MissingProvenance,
            RecoveryClass::Explicit,
            None
        )
    );
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
    for server in &pair {
        assert_eq!(starts(server).await, vec![60]);
    }
    assert_eq!(fx.run(&pair).await.unwrap().requests.attempt, 0);
}

#[tokio::test]
#[serial]
async fn driver_scan_never_reads_after_b() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    fx.run(&pair).await.unwrap();
    assert_eq!(fx.run_record(0).scan.unwrap().end, Some((23, NOW / 1000)));
    next_run(&fx);
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.requests.attempt, 4);
    for server in &pair {
        assert_eq!(starts(server).await, vec![60, 20, 21, 22, 23]);
    }
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
}

#[tokio::test]
#[serial]
async fn driver_changed_configuration_restarts_at_p() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 34).await;
    fx.run(&pair).await.unwrap();
    let digest = fx.run_record(0).scan.unwrap().digest;
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].attempts[0]
            .recovery
            .as_mut()
            .unwrap()
            .history_incomplete = true;
    });
    next_run(&fx);
    fx.fx.profile.oracle_provider_url = Some("http://127.0.0.2".parse().unwrap());
    fx.run(&pair).await.unwrap();
    let scan = fx.run_record(0).scan.unwrap();
    assert_eq!(scan.next_unread, 30);
    assert_ne!(scan.digest, digest);
    for server in &pair {
        assert_eq!(starts(server).await[10], 20);
    }
    assert!(
        fx.fx.record(fx.ids[0]).attempts[0]
            .recovery
            .as_ref()
            .unwrap()
            .history_incomplete
    );
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
}

#[tokio::test]
#[serial]
async fn scan_stop_classes_and_configuration_reopen() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 34).await;
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
    let stop = fx.run_record(0).stop.unwrap();
    assert_eq!(
        (stop.reason, stop.class, stop.ledger, stop.roles),
        (
            RecoveryStopReason::HistoryLost,
            RecoveryClass::Explicit,
            Some(20),
            vec![RecoveryRole::Primary]
        )
    );
    assert_eq!(fx.run(&pair).await.unwrap().requests.attempt, 0);
    fx.fx.profile.oracle_provider_url = Some("http://127.0.0.3".parse().unwrap());
    assert_eq!(fx.run(&pair).await.unwrap().evaluated, 1);
    assert_eq!(fx.run_record(0).automatic_runs, 2);
    assert_eq!(fx.run(&pair).await.unwrap().requests.attempt, 0);
    assert!(
        fx.fx.record(fx.ids[0]).attempts[0]
            .recovery
            .as_ref()
            .unwrap()
            .history_incomplete
    );
}

#[tokio::test]
#[serial]
async fn driver_failed_attempt_then_deciding_attempt() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(2, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getTransaction"})))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .with_priority(1)
        .up_to_n_times(1)
        .mount(&pair[0])
        .await;
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.evaluated, 2);
    assert_eq!(
        fx.run_record(0).stop.unwrap().reason,
        RecoveryStopReason::Transport
    );
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
    assert!(
        fx.fx.record(fx.ids[1]).attempts[0].decision.is_some(),
        "later attempt decides after the failure resets"
    );
}
