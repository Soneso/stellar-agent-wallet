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
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_some());
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

fn reserved(fx: &Fixture) -> i128 {
    OperationStatus::new(&fx.fx.store, &fx.fx.profile)
        .native_reserved_stroops(None)
        .unwrap()
}

fn install_run(fx: &Fixture, run: &WireRecoveryRun) {
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].attempts[0].recovery_run =
            Some(serde_json::from_str(&serde_json::to_string(run).unwrap()).unwrap());
    });
}

async fn absent_accounts(pair: &[MockServer; 2]) {
    for server in pair {
        override_answer(
            server,
            "getLedgerEntries",
            json!({"entries":[],"latestLedger":60}),
        )
        .await;
    }
}

async fn fresh_health(pair: &[MockServer; 2]) {
    let now = super::super::super::store::now_ms().unwrap();
    for server in pair {
        Mock::given(method("POST")).and(body_partial_json(json!({"method":"getHealth"})))
            .respond_with(EchoIdResponder::new(json!({"status":"healthy","latestLedger":60,"oldestLedger":1,
                "ledgerRetentionWindow":60,"oldestLedgerCloseTime":1,"latestLedgerCloseTime":now/1000})))
            .with_priority(1).up_to_n_times(1).mount(server).await;
    }
}

#[tokio::test]
#[serial]
async fn driver_complete_history_decides_after_b() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    fx.run(&pair).await.unwrap();
    let before = fx.fx.record(fx.ids[0]);
    assert!(
        before.attempts[0].decision.is_none(),
        "pre-B hashes cannot decide"
    );
    assert_eq!(reserved(&fx), 125);
    assert_eq!(fx.run_record(0).scan.unwrap().end, Some((23, NOW / 1000)));
    for server in &pair {
        override_answer(server, "getTransaction", absence(23, NOW)).await;
    }
    next_run(&fx);
    let report = fx.run(&pair).await.unwrap();
    let after = fx.fx.record(fx.ids[0]);
    assert!(matches!(
        after.attempts[0].not_included,
        Some(NotIncludedProof::CompleteHistory { .. })
    ));
    assert_eq!(after.state, OperationState::NotIncluded);
    assert_eq!(reserved(&fx), 0, "complete history releases the debit");
    assert_eq!(
        after.attempts[0].sequence_released,
        before.attempts[0].sequence_released
    );
    assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
    assert_eq!(fx.run_record(0).consecutive_stops, 0);
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    assert_eq!(fx.run(&pair).await.unwrap().evaluated, 0);
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
}

#[tokio::test]
#[serial]
async fn driver_complete_history_requires_durable_matching_scan() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for defect in ["unfinished", "configuration", "sticky", "oldest", "latest"] {
        let mut fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = scan_pair(&fx, if defect == "unfinished" { 34 } else { 23 }).await;
        fx.run(&pair).await.unwrap();
        assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
        match defect {
            "configuration" => {
                fx.fx.profile.oracle_provider_url = Some("http://127.0.0.2".parse().unwrap())
            }
            "sticky" => fx.fx.rewrite(|wire| {
                wire.operations.as_mut().unwrap().records[0].attempts[0]
                    .recovery
                    .as_mut()
                    .unwrap()
                    .history_incomplete = true;
            }),
            "oldest" | "latest" => {
                let mut answer = absence(23, NOW);
                if defect == "oldest" {
                    answer["oldestLedger"] = json!(21);
                } else {
                    answer["latestLedger"] = json!(22);
                }
                override_answer(&pair[1], "getTransaction", answer).await;
            }
            _ => {}
        }
        next_run(&fx);
        fx.run(&pair).await.unwrap();
        assert!(
            fx.fx.record(fx.ids[0]).attempts[0].decision.is_none(),
            "{defect} keeps debit held"
        );
        assert_eq!(reserved(&fx), 125, "{defect}");
    }
}

#[tokio::test]
#[serial]
async fn driver_final_hash_follows_persisted_b() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let envelope = super::super::tests::envelope_text(100);
    fx.fx.rewrite(|wire| {
        let ExposureIdentity::Classic {
            envelope_sha256,
            receipt,
            ..
        } = &mut wire.operations.as_mut().unwrap().records[0].attempts[0]
            .exposure
            .as_mut()
            .unwrap()
            .identity
        else {
            panic!("classic")
        };
        *envelope_sha256 = Sha256::digest(&envelope).into();
        *receipt = stellar_agent_core::hex::encode(envelope_sha256);
    });
    let pair = scan_pair(&fx, 23).await;
    let durable = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for server in &pair {
        let durable = durable.clone();
        let included = json!({"status":"SUCCESS","ledger":22,"createdAt":NOW/1000-10,
            "txHash":"81".repeat(32),"envelopeXdr":envelope,
            "resultXdr":super::super::tests::result_text(true, 70),"oldestLedger":1,"latestLedger":60});
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getTransaction"})))
            .respond_with(move |request: &wiremock::Request| {
                let answer = if durable.load(std::sync::atomic::Ordering::SeqCst) {
                    included.clone()
                } else {
                    absence(60, NOW)
                };
                wiremock::Respond::respond(&EchoIdResponder::new(answer), request)
            })
            .with_priority(1)
            .mount(server)
            .await;
    }
    fx.run(&pair).await.unwrap();
    assert!(
        fx.fx.record(fx.ids[0]).attempts[0].decision.is_none(),
        "the first hash pair predates durable B"
    );
    assert_eq!(fx.run_record(0).scan.unwrap().end, Some((23, NOW / 1000)));
    durable.store(true, std::sync::atomic::Ordering::SeqCst);
    next_run(&fx);
    fx.run(&pair).await.unwrap();
    let record = fx.fx.record(fx.ids[0]);
    assert_eq!(
        record.state,
        OperationState::Succeeded,
        "post-B inclusion wins"
    );
    assert!(record.attempts[0].not_included.is_none());
    for server in &pair {
        assert_eq!(rpc_request_count(server, "getTransaction").await, 2);
    }
}

#[tokio::test]
#[serial]
async fn driver_absent_account_enters_scan() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    absent_accounts(&pair).await;
    fx.run(&pair).await.unwrap();
    assert_eq!(
        fx.run_record(0).scan.as_ref().and_then(|s| s.end),
        Some((23, NOW / 1000)),
        "paired typed absence scans"
    );
    assert_eq!(reserved(&fx), 125);
    next_run(&fx);
    fx.run(&pair).await.unwrap();
    assert!(matches!(
        fx.fx.record(fx.ids[0]).attempts[0].not_included,
        Some(NotIncludedProof::CompleteHistory { .. })
    ));
    assert_eq!(reserved(&fx), 0);
}

#[tokio::test]
#[serial]
async fn driver_one_sided_absence_keeps_stop() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for missing in 0..2 {
        for other in ["present", "failed", "regressed", "malformed"] {
            let fx = Fixture::new(1, NOW / 1000 - 10);
            let pair = scan_pair(&fx, 23).await;
            override_answer(
                &pair[missing],
                "getLedgerEntries",
                json!({"entries":[],"latestLedger":60}),
            )
            .await;
            match other {
                "failed" => {
                    Mock::given(method("POST"))
                        .and(body_partial_json(json!({"method":"getLedgerEntries"})))
                        .respond_with(wiremock::ResponseTemplate::new(500))
                        .with_priority(1)
                        .mount(&pair[1 - missing])
                        .await
                }
                "regressed" => {
                    override_answer(
                        &pair[1 - missing],
                        "getLedgerEntries",
                        account(&fx.source, 59, 101),
                    )
                    .await
                }
                "malformed" => {
                    override_answer(&pair[1 - missing], "getLedgerEntries", json!({})).await
                }
                _ => {}
            }
            fx.run(&pair).await.unwrap();
            let run = fx.run_record(0);
            assert!(run.scan.is_none(), "{missing}/{other} cannot scan");
            let expected = match (missing, other) {
                (1, "failed") => RecoveryStopReason::Transport,
                (1, "malformed") => RecoveryStopReason::MissingField,
                _ => RecoveryStopReason::AccountUnavailable,
            };
            assert_eq!(run.stop.unwrap().reason, expected, "{missing}/{other}");
            assert_eq!(reserved(&fx), 125);
            for server in &pair {
                assert_eq!(starts(server).await, vec![60]);
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn driver_health_pruning_stops_before_scan_request() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for role in 0..2 {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = scan_pair(&fx, 23).await;
        override_answer(&pair[role], "getHealth", json!({"status":"healthy","latestLedger":60,
            "oldestLedger":21,"ledgerRetentionWindow":40,"oldestLedgerCloseTime":1,"latestLedgerCloseTime":NOW/1000})).await;
        let mut page = target_page(NOW / 1000);
        page["oldestLedger"] = json!(21);
        Mock::given(method("POST"))
            .and(body_partial_json(
                json!({"method":"getLedgers","params":{"startLedger":20}}),
            ))
            .respond_with(EchoIdResponder::new(page))
            .with_priority(1)
            .mount(&pair[role])
            .await;
        fx.run(&pair).await.unwrap();
        let stop = fx.run_record(0).stop.unwrap();
        assert_eq!(
            (stop.reason, stop.ledger, stop.roles),
            (
                RecoveryStopReason::HistoryLost,
                Some(20),
                vec![if role == 0 {
                    RecoveryRole::Primary
                } else {
                    RecoveryRole::Oracle
                }]
            )
        );
        assert_eq!(
            starts(&pair[role]).await,
            vec![60],
            "health pruning sends no request at P"
        );
        assert_eq!(reserved(&fx), 125);
    }
}

#[tokio::test]
#[serial]
async fn driver_release_close_refuses_unchanged_prefix() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for close in [NOW / 1000 - 10, NOW / 1000 - 11] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        fx.fx.rewrite(|wire| {
            wire.operations.as_mut().unwrap().records[0].attempts[0].pre_exposure_ledger = Some(60)
        });
        let pair = fx.pair([60, 60], NOW, 101).await;
        for server in &pair {
            let calls = std::sync::atomic::AtomicU32::new(0);
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method":"getLedgers"})))
                .respond_with(move |request: &wiremock::Request| {
                    let close = if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        NOW / 1000
                    } else {
                        close
                    };
                    wiremock::Respond::respond(&EchoIdResponder::new(target_page(close)), request)
                })
                .with_priority(1)
                .mount(server)
                .await;
        }
        fx.run(&pair).await.unwrap();
        let raw: WireRecoveryRun = serde_json::from_value(
            serde_json::to_value(
                fx.fx.record(fx.ids[0]).attempts[0]
                    .recovery_run
                    .as_ref()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw.stop.unwrap().reason,
            RecoveryStopReason::Disagreement,
            "release close must exceed max_time"
        );
        let scan = raw.scan.unwrap();
        assert_eq!(
            (scan.next_unread, scan.preceding_close, scan.end),
            (60, None, None)
        );
        assert_eq!(reserved(&fx), 125);
    }
}

#[tokio::test]
#[serial]
async fn driver_scan_tip_regresses_between_steps() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    let mut page = target_page(NOW / 1000 - 10);
    page["ledgers"][0]["sequence"] = json!(21);
    page["latestLedger"] = json!(61);
    Mock::given(method("POST"))
        .and(body_partial_json(
            json!({"method":"getLedgers","params":{"startLedger":21}}),
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
            Some(21),
            vec![RecoveryRole::Primary]
        )
    );
    assert_eq!(run.scan.unwrap().next_unread, 21);
}

#[tokio::test]
#[serial]
async fn driver_configuration_reopen_respects_run_cap() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    override_answer(&pair[0], "getHealth", json!({"status":"healthy","latestLedger":60,
        "oldestLedger":21,"ledgerRetentionWindow":40,"oldestLedgerCloseTime":1,"latestLedgerCloseTime":NOW/1000})).await;
    fx.run(&pair).await.unwrap();
    let mut run = fx.run_record(0);
    run.automatic_runs = 16;
    run.consecutive_stops = 16;
    install_run(&fx, &run);
    fx.fx.profile.oracle_provider_url = Some("http://127.0.0.2".parse().unwrap());
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    let result = fx.run(&pair).await;
    assert!(
        result.is_ok(),
        "exhausted configuration reopen is a successful no-op: {result:?}"
    );
    assert_eq!(result.unwrap().evaluated, 0);
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
}

#[tokio::test]
#[serial]
async fn driver_history_crash_restart_is_idempotent() {
    use super::super::super::store::{COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED};
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for missing in [false, true] {
        for stage in 1..=4 {
            for seam in [COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_AFTER_COUNTER] {
                let fx = Fixture::new(1, NOW / 1000 - 10);
                let pair = scan_pair(&fx, 23).await;
                if missing {
                    absent_accounts(&pair).await;
                }
                if stage == 4 {
                    fx.run(&pair).await.unwrap();
                    next_run(&fx);
                }
                let fault = arm_write_fault(stage, seam);
                let result = fx.run(&pair).await;
                drop(fault);
                assert!(result.is_err(), "{missing}/{stage}/{seam}");
                assert_eq!(result.unwrap_err().code(), "submission.record_unavailable");
                let committed_decision = stage == 4 && seam == COMMIT_FAULT_AFTER_COUNTER;
                assert_eq!(reserved(&fx), if committed_decision { 0 } else { 125 });
                let saved = fx.fx.record(fx.ids[0]);
                let saved_runs = saved.attempts[0]
                    .recovery_run
                    .as_ref()
                    .map(|_| fx.run_record(0).automatic_runs)
                    .unwrap_or(0);
                if !committed_decision {
                    if saved_runs > 0 {
                        let run = fx.run_record(0);
                        fx.fx
                            .clock
                            .set(run.stop.and_then(|s| s.earliest_retry_ms).unwrap_or(
                                run.run_deadline_ms
                                    + super::super::super::recovery_run::recovery_backoff(
                                        run.consecutive_stops,
                                    ),
                            ));
                    }
                    fresh_health(&pair).await;
                    fx.run(&pair).await.unwrap();
                    assert_eq!(
                        fx.run_record(0).automatic_runs,
                        saved_runs + 1,
                        "crash never refunds a durable reservation"
                    );
                    if fx.fx.record(fx.ids[0]).attempts[0].decision.is_none() {
                        next_run(&fx);
                        fresh_health(&pair).await;
                        fx.run(&pair).await.unwrap();
                    }
                }
                assert!(
                    matches!(
                        fx.fx.record(fx.ids[0]).attempts[0].not_included,
                        Some(NotIncludedProof::CompleteHistory { .. })
                    ),
                    "{missing}/{stage}/{seam}"
                );
                assert_eq!(reserved(&fx), 0);
                let bytes = std::fs::read(fx.fx.store.path()).unwrap();
                assert_eq!(fx.run(&pair).await.unwrap().evaluated, 0);
                assert_eq!(
                    std::fs::read(fx.fx.store.path()).unwrap(),
                    bytes,
                    "replay has no second effect"
                );
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn driver_history_clock_restart_preserves_eligibility() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    absent_accounts(&pair).await;
    fx.run(&pair).await.unwrap();
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    fx.fx.clock.set(NOW - 1);
    assert_eq!(
        fx.run(&pair).await.unwrap().evaluated,
        0,
        "earlier clock cannot release early"
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
    assert_eq!(reserved(&fx), 125);
    let later = NOW + 86_400_000;
    fx.fx.clock.set(later);
    for server in &pair {
        override_answer(server, "getHealth", json!({"status":"healthy","latestLedger":60,"oldestLedger":1,
            "ledgerRetentionWindow":60,"oldestLedgerCloseTime":1,"latestLedgerCloseTime":later/1000})).await;
    }
    fx.run(&pair).await.unwrap();
    assert_eq!(fx.run_record(0).phase, RecoveryRunPhase::Resolved);
    assert_eq!(fx.run_record(0).automatic_runs, 2);
    assert_eq!(reserved(&fx), 0);
}

#[tokio::test]
#[serial]
async fn driver_history_stale_decision_cannot_replace_new_owner() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = scan_pair(&fx, 23).await;
    absent_accounts(&pair).await;
    fx.run(&pair).await.unwrap();
    next_run(&fx);
    let store = PersistedWindowStore::at_path(fx.fx.store.path().to_owned());
    let profile = fx.fx.profile.clone();
    let writer = fx.writer.clone();
    let winner = std::rc::Rc::new(std::cell::RefCell::new(None));
    let captured = winner.clone();
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 4 {
                let attempt = OperationStatus::new(&store, &profile)
                    .outcome_snapshot(None)
                    .unwrap()
                    .remove(0);
                let mut run = attempt
                    .recovery_run
                    .as_ref()
                    .unwrap()
                    .record()
                    .unwrap()
                    .clone();
                run.automatic_runs += 1;
                run.consecutive_stops += 1;
                run.run_started_ms += 60_000;
                run.run_deadline_ms += 60_000;
                OperationRecorder::new(&store, &profile, &mut *writer.lock().unwrap(), "new-owner")
                    .write_recovery_run(&attempt, &EvidenceInput::default(), &run, None)
                    .unwrap();
                *captured.borrow_mut() = Some(std::fs::read(store.path()).unwrap());
            }
        }))
    });
    let hook = Hook;
    let result = fx.run(&pair).await;
    drop(hook);
    assert!(result.is_err(), "stale complete-history decision refuses");
    assert_eq!(result.unwrap_err().code(), "submission.record_unavailable");
    assert_eq!(
        std::fs::read(fx.fx.store.path()).unwrap(),
        winner.borrow_mut().take().unwrap()
    );
    assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
    assert_eq!(reserved(&fx), 125);
    assert_eq!(fx.run_record(0).automatic_runs, 3);
}

#[tokio::test]
#[serial]
async fn driver_absent_account_scan_checks_arithmetic() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    fx.fx.rewrite(|wire| {
        wire.operations.as_mut().unwrap().records[0].attempts[0].pre_exposure_ledger =
            Some(u32::MAX)
    });
    let pair = fx.pair([u32::MAX, u32::MAX], NOW, 101).await;
    absent_accounts(&pair).await;
    let mut page = target_page(NOW / 1000);
    page["latestLedger"] = json!(u32::MAX);
    page["ledgers"][0]["sequence"] = json!(u32::MAX);
    for server in &pair {
        override_answer(server, "getLedgers", page.clone()).await;
    }
    fx.run(&pair).await.unwrap();
    let run: WireRecoveryRun = serde_json::from_value(
        serde_json::to_value(
            fx.fx.record(fx.ids[0]).attempts[0]
                .recovery_run
                .as_ref()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(run.stop.unwrap().reason, RecoveryStopReason::MissingField);
    let scan = run.scan.unwrap();
    assert_eq!((scan.next_unread, scan.end), (u32::MAX, None));
    assert_eq!(reserved(&fx), 125);
}

#[tokio::test]
#[serial]
async fn driver_history_operator_spelling_reuses_scan() {
    use stellar_agent_core::profile::schema::{PrimaryProviderRecord, Providers};
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fixture::new(1, NOW / 1000 - 10);
    let mut providers = Providers::default();
    providers.primary = Some(PrimaryProviderRecord::new(" ß ", "127.0.0.1"));
    fx.fx.profile.providers = Some(providers);
    let pair = scan_pair(&fx, 23).await;
    fx.run(&pair).await.unwrap();
    fx.fx
        .profile
        .providers
        .as_mut()
        .unwrap()
        .primary
        .as_mut()
        .unwrap()
        .operator = "SS".into();
    next_run(&fx);
    fx.run(&pair).await.unwrap();
    assert_eq!(
        fx.run_record(0).phase,
        RecoveryRunPhase::Resolved,
        "equivalent operator spellings reuse durable B"
    );
    for server in &pair {
        assert_eq!(starts(server).await, vec![60, 20, 21, 22, 23]);
    }
}

#[tokio::test]
#[serial]
async fn driver_history_legacy_and_unusable_records_are_isolated() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for shape in ["legacy", "missing", "unknown"] {
        let fx = Fixture::new(2, NOW / 1000 - 10);
        let pair = scan_pair(&fx, 34).await;
        fx.run(&pair).await.unwrap();
        next_run(&fx);
        fx.fx.rewrite(|wire| {
            let raw = &mut wire.operations.as_mut().unwrap().records[0].attempts[0].recovery_run;
            let mut value = serde_json::to_value(raw.as_ref().unwrap()).unwrap();
            match shape {
                "legacy" => {
                    value["version"] = json!(1);
                    value.as_object_mut().unwrap().remove("scan");
                }
                "missing" => {
                    value["scan"]
                        .as_object_mut()
                        .unwrap()
                        .remove("configuration");
                }
                _ => {
                    value["scan"]["unknown"] = json!(true);
                }
            }
            *raw = Some(serde_json::from_value(value).unwrap());
        });
        let saved = fx.fx.record(fx.ids[0]).attempts[0].recovery_run.clone();
        fx.run(&pair).await.unwrap();
        if shape == "legacy" {
            assert_eq!(
                fx.run_record(0).scan.unwrap().next_unread,
                30,
                "legacy scan starts at P"
            );
            fx.run(&pair).await.unwrap();
        } else {
            assert_eq!(fx.fx.record(fx.ids[0]).attempts[0].recovery_run, saved);
        }
        assert!(
            fx.fx.record(fx.ids[1]).attempts[0].decision.is_some(),
            "{shape} does not block another attempt"
        );
        assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
    }
}
