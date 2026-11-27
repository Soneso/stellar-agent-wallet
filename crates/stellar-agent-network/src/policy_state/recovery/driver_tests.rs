#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "independent recovery assertions"
)]

use super::tests::{endpoint, mount};
use super::*;
use crate::policy_state::operations::OperationState;
use crate::policy_state::operations::tests::{Fx, unknown_with};
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_test_support::signed_envelope::{account_id_for_seed, ledger_entries_result_for};
use stellar_agent_test_support::{EchoIdResponder, rpc_request_count};
use stellar_xdr::{ReadXdr, WriteXdr};
use wiremock::matchers::{body_partial_json, method};
use wiremock::{Mock, MockServer};

const NOW: u64 = 1_800_000_000_000;

mod report_tests;
mod scan_tests;

type WriteHook = Box<dyn FnMut(u8)>;
thread_local! {
    static WRITE_HOOK: std::cell::RefCell<Option<WriteHook>> = const { std::cell::RefCell::new(None) };
    static WRITE_FAULT: std::cell::Cell<(u8, u8)> = const { std::cell::Cell::new((0, 0)) };
    static ADVANCE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    static ALLOWANCE: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static DEADLINE_EXTENSION: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

pub(super) async fn after_attempt() {
    if let Some(duration) = ADVANCE.take() {
        tokio::time::pause();
        tokio::time::advance(duration).await;
    }
}

pub(super) fn before_fresh() {
    WRITE_HOOK.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(5);
        }
    });
}

pub(super) fn configure_budget(budget: &mut Budget) {
    if let Some(allowance) = ALLOWANCE.take() {
        budget.attempt_limit = budget.used.attempt.checked_add(allowance).unwrap();
    }
    if let Some(extension) = DEADLINE_EXTENSION.get() {
        budget.deadline = budget.deadline.checked_add(extension).unwrap();
    }
}

/// A hook that sees each native release's zero-based index and the call
/// deadline before the release starts.
type ReleaseHook = Box<dyn FnMut(usize, &mut Instant)>;
thread_local! {
    static RELEASE_HOOK: std::cell::RefCell<Option<(usize, ReleaseHook)>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn before_release(budget: &mut Budget) {
    RELEASE_HOOK.with_borrow_mut(|slot| {
        if let Some((index, hook)) = slot {
            hook(*index, &mut budget.deadline);
            *index += 1;
        }
    });
}

/// Runs `hook` before each native release on this thread until the guard drops.
pub(crate) fn on_release(hook: impl FnMut(usize, &mut Instant) + 'static) -> impl Drop {
    struct Armed;
    impl Drop for Armed {
        fn drop(&mut self) {
            RELEASE_HOOK.with_borrow_mut(|slot| *slot = None);
        }
    }
    RELEASE_HOOK.with_borrow_mut(|slot| *slot = Some((0, Box::new(hook))));
    Armed
}

/// The seam after the write's audit append, before its prepared image.
const AUDIT_APPENDED: u8 = 0xA1;

pub(super) fn before_write(
    input: &EvidenceInput,
    run: &WireRecoveryRun,
    decision: bool,
) -> Option<Box<dyn std::any::Any>> {
    let stage = if decision {
        4
    } else if run.phase == RecoveryRunPhase::Stopped {
        3
    } else if input.sequence_released.is_some() {
        2
    } else {
        1
    };
    WRITE_HOOK.with_borrow_mut(|hook| {
        if let Some(hook) = hook {
            hook(stage);
        }
    });
    let (wanted, seam) = WRITE_FAULT.get();
    (stage == wanted).then(|| -> Box<dyn std::any::Any> {
        WRITE_FAULT.set((0, 0));
        if seam == AUDIT_APPENDED {
            Box::new(super::super::store::fail_store_writes())
        } else {
            Box::new(super::super::store::arm_accounting_fault(seam))
        }
    })
}

/// Arms the store `seam` fault at the driver write of `stage` (1 reservation,
/// 2 release, 3 stop, 4 decision) until the guard drops.
pub(super) fn arm_write_fault(stage: u8, seam: u8) -> impl Drop {
    WRITE_FAULT.set((stage, seam));
    Hook
}

struct Hook;
impl Drop for Hook {
    fn drop(&mut self) {
        WRITE_HOOK.with_borrow_mut(|hook| *hook = None);
        WRITE_FAULT.set((0, 0));
    }
}

struct Fixture {
    fx: Fx,
    ids: Vec<OperationId>,
    handles: Vec<super::super::operations::OperationHandle>,
    writer: Arc<Mutex<AuditWriter>>,
    source: String,
}

impl Fixture {
    fn new(count: u8, max_time: u64) -> Self {
        Self::with_holds(count, max_time, &[])
    }

    fn with_holds(
        count: u8,
        max_time: u64,
        holds: &[stellar_agent_core::policy::v1::criteria::state_store::WindowEntry],
    ) -> Self {
        let mut fx = Fx::new();
        let handles: Vec<_> = (1..=count)
            .map(|n| {
                fx.clock.set(NOW + u64::from(n));
                unknown_with(&mut fx, n, max_time, holds.to_vec())
            })
            .collect();
        let ids = handles
            .iter()
            .map(super::super::operations::OperationHandle::id)
            .collect();
        let source = account_id_for_seed([1; 32]);
        fx.rewrite(|wire| {
            for auth in &mut wire.authorizations {
                let crate::policy_state::DomainBinding::Transaction { source: stored, .. } =
                    &mut auth.binding
                else {
                    panic!("classic")
                };
                *stored = source.clone();
                auth.native_reservation = Some(crate::policy_state::NativeReservation {
                    debit_stroops: 25,
                    fee_stroops: 100,
                });
            }
            for record in &mut wire.operations.as_mut().unwrap().records {
                record.attempts[0].pre_exposure_ledger = Some(20);
                record.attempts[0].send_by_ms = NOW;
            }
        });
        fx.clock.set(NOW);
        let writer = crate::submission_flow::recovery::tests::writer_at(&fx.profile.audit_log_path);
        Self {
            fx,
            ids,
            handles,
            writer,
            source,
        }
    }

    async fn run(&self, pair: &[MockServer; 2]) -> Result<RecoveryReport, RecoveryError> {
        let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
        let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
        recover_outcomes(
            &self.fx.store,
            &self.fx.profile,
            EndpointPair::from_clients(&left, Some(&right)),
            &self.writer,
            None,
        )
        .await
    }

    /// Targeted recovery of the first attempt with the explicit retry request.
    async fn retry(&self, pair: &[MockServer; 2]) -> Result<RecoveryReport, RecoveryError> {
        let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
        let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
        recover_outcomes_committed(
            &self.fx.store,
            &self.fx.profile,
            EndpointPair::from_clients(&left, Some(&right)),
            &self.writer,
            Some(&[1 ^ 0x80; 32]),
            true,
            &mut CommittedBatch::default(),
        )
        .await
    }

    fn run_record(&self, index: usize) -> WireRecoveryRun {
        let id = self.ids[index];
        RecoveryRunSnapshot::of(id, &self.fx.record(id).attempts[0], Some(&self.source))
            .unwrap()
            .record()
            .unwrap()
            .clone()
    }

    async fn pair(&self, tips: [u32; 2], now: u64, sequence: i64) -> [MockServer; 2] {
        let pair = [
            endpoint(tips[0], now / 1_000).await,
            endpoint(tips[1], now / 1_000).await,
        ];
        for (server, tip) in pair.iter().zip(tips) {
            mount(server, "getTransaction", absence(tip, now)).await;
            mount(
                server,
                "getLedgerEntries",
                account(&self.source, tip, sequence),
            )
            .await;
        }
        pair
    }
}

use crate::policy_state::RecoveryRunSnapshot;

fn absence(tip: u32, now: u64) -> Value {
    json!({"status":"NOT_FOUND", "oldestLedger":1, "latestLedger":tip,
        "oldestLedgerCloseTime":1, "latestLedgerCloseTime":now/1000})
}

fn account(source: &str, ledger: u32, sequence: i64) -> Value {
    let mut answer = ledger_entries_result_for(&[source]);
    let text = answer["entries"][0]["xdr"].as_str().unwrap();
    let mut data =
        stellar_xdr::LedgerEntryData::from_xdr_base64(text, stellar_xdr::Limits::none()).unwrap();
    let stellar_xdr::LedgerEntryData::Account(ref mut entry) = data else {
        panic!("account")
    };
    entry.seq_num = stellar_xdr::SequenceNumber(sequence);
    answer["entries"][0]["xdr"] = json!(data.to_xdr_base64(stellar_xdr::Limits::none()).unwrap());
    answer["latestLedger"] = json!(ledger);
    answer
}

async fn override_answer(server: &MockServer, name: &str, value: Value) {
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":name})))
        .respond_with(EchoIdResponder::new(value))
        .with_priority(1)
        .mount(server)
        .await;
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_same_call_and_saved_upper() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for tips in [[60, 60], [60, 61], [61, 60]] {
        let mut fx = Fixture::new(1, NOW / 1000 - 10);
        fx.fx
            .recorder()
            .record_evidence(
                fx.ids[0],
                1,
                &EvidenceInput {
                    recovery: Some(RecoveryUpdate {
                        primary_upper: Some(90),
                        witness_upper: Some(91),
                        ..RecoveryUpdate::default()
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let pair = fx.pair(tips, NOW, 0).await;
        let report = fx.run(&pair).await.unwrap();
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 6
            }
        );
        assert_eq!(report.evaluated, 1);
        assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
        let record = fx.fx.record(fx.ids[0]);
        assert_eq!(record.state, OperationState::NotIncluded);
        assert!(!record.state.is_terminal());
        let release = record.attempts[0].sequence_released.as_ref().unwrap();
        assert_eq!((release.primary_ledger, release.witness_ledger), (60, 60));
        assert_eq!(release.min_close_time_ms, NOW);
        assert!(!record.attempts[0].decision.as_ref().unwrap().projected);
        let raw_run =
            serde_json::to_value(record.attempts[0].recovery_run.as_ref().unwrap()).unwrap();
        assert_eq!(raw_run["phase"], "resolved");
        assert_eq!(raw_run["consecutive_stops"], 0);
        assert_eq!(
            OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                .native_reserved_stroops(None)
                .unwrap(),
            0
        );
        let run = fx.run_record(0);
        assert_eq!(
            (
                run.phase,
                run.automatic_runs,
                run.consecutive_stops,
                run.stop
            ),
            (RecoveryRunPhase::Resolved, 1, 0, None)
        );
        for server in &pair {
            let requests = server.received_requests().await.unwrap();
            let ledger = requests
                .iter()
                .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap())
                .find(|r| r["method"] == "getLedgers")
                .unwrap();
            assert_eq!(ledger["params"]["startLedger"], 60);
            assert_eq!(ledger["params"]["pagination"]["limit"], 1);
        }
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_quality_stop_then_fresh_account_pair() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    override_answer(
        &pair[1],
        "getLedgerEntries",
        json!({"latestLedger":60,"entries":[]}),
    )
    .await;
    let report = fx.run(&pair).await.unwrap();
    let stop = report.attempts[0].stop.as_ref().unwrap();
    assert_eq!(
        (
            stop.reason,
            stop.stage,
            stop.roles.clone(),
            stop.class,
            stop.earliest_retry_ms
        ),
        (
            RecoveryStopReason::AccountUnavailable,
            RecoveryStage::Account,
            vec![RecoveryRole::Oracle],
            RecoveryClass::Automatic,
            Some(NOW + 30_000)
        )
    );
    assert_eq!(fx.run_record(0).consecutive_stops, 1);
    let record = fx.fx.record(fx.ids[0]);
    assert!(record.attempts[0].decision.is_none());
    assert!(record.attempts[0].sequence_released.is_some());
    assert_eq!(
        OperationStatus::new(&fx.fx.store, &fx.fx.profile)
            .native_reserved_stroops(None)
            .unwrap(),
        125
    );
    assert!(record.attempts[0].evidence.iter().any(|r| matches!(
        r.answer,
        super::super::operations::WireEvidenceAnswer::Account {
            sequence: Some(0),
            ..
        }
    ) && r.endpoint
        == EvidenceEndpoint::Primary));
    let before = serde_json::to_vec(&record).unwrap();
    let early = fx.run(&pair).await.unwrap();
    assert_eq!(early.requests, RecoveryRequests::default());
    assert_eq!(
        serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
        before
    );
    fx.fx.clock.set(NOW + 30_000);
    let next = fx.pair([62, 63], NOW + 30_000, 0).await;
    let report = fx.run(&next).await.unwrap();
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 4
        }
    );
    assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
    assert!(report.attempts[0].stop.is_none());
    assert_eq!(
        serde_json::to_value(fx.fx.record(fx.ids[0])).unwrap()["attempts"][0]["recovery_run"]["consecutive_stops"],
        0
    );
    assert_eq!(fx.run_record(0).automatic_runs, 2);
    for server in &next {
        assert_eq!(rpc_request_count(server, "getTransaction").await, 1);
        assert_eq!(rpc_request_count(server, "getLedgerEntries").await, 1);
        assert_eq!(rpc_request_count(server, "getLedgers").await, 0);
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_hash_peer_failure_keeps_successful_side() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let mut primary = absence(60, NOW);
    primary["oldestLedger"] = json!(30);
    override_answer(&pair[0], "getTransaction", primary).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getTransaction"})))
        .respond_with(wiremock::ResponseTemplate::new(500))
        .with_priority(1)
        .mount(&pair[1])
        .await;
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 2
        }
    );
    let stop = report.attempts[0].stop.as_ref().unwrap();
    assert_eq!(
        (
            stop.reason,
            stop.stage,
            stop.roles.clone(),
            stop.earliest_retry_ms,
            stop.target
        ),
        (
            RecoveryStopReason::Transport,
            RecoveryStage::Hash,
            vec![RecoveryRole::Oracle],
            Some(NOW + 30_000),
            Some(60)
        )
    );
    let record = fx.fx.record(fx.ids[0]);
    assert_eq!(fx.run_record(0).phase, RecoveryRunPhase::Stopped);
    assert!(record.attempts[0].recovery.is_some());
    assert!(
        record.attempts[0]
            .recovery
            .as_ref()
            .unwrap()
            .history_incomplete
    );
    assert_eq!(record.attempts[0].evidence.len(), 1);
    assert_eq!(
        record.attempts[0].evidence[0].endpoint,
        EvidenceEndpoint::Primary
    );
    assert!(record.attempts[0].sequence_released.is_none());
    assert!(record.attempts[0].decision.is_none());
    assert!(fx.fx.wire().last_observation.is_some());
    assert_eq!(fx.fx.wire().last_observation.as_ref().unwrap().ledger, 60);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_untimed_matched_release_stays_automatic() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for max_time in [0, u64::MAX, u64::MAX / 1_000] {
        let mut fx = Fixture::new(1, max_time);
        let id = fx.ids[0];
        fx.fx
            .recorder()
            .record_evidence(
                id,
                1,
                &EvidenceInput {
                    sequence_released: Some(SequenceReleaseInput {
                        primary_ledger: 60,
                        witness_ledger: 60,
                        min_close_time_ms: u64::MAX,
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        for (at, earliest, spent) in [(NOW, NOW + 30_000, 1), (NOW + 30_000, NOW + 90_000, 2)] {
            fx.fx.clock.set(at);
            let pair = fx.pair([60, 60], at, 0).await;
            let report = fx.run(&pair).await.unwrap();
            assert_eq!(
                report.requests,
                RecoveryRequests {
                    shared: 4,
                    attempt: 2
                }
            );
            let stop = report.attempts[0].stop.as_ref().unwrap();
            assert_eq!(
                (stop.reason, stop.stage, stop.class, stop.earliest_retry_ms),
                (
                    RecoveryStopReason::Untimed,
                    RecoveryStage::Hash,
                    RecoveryClass::Automatic,
                    Some(earliest)
                ),
                "untimed mode with inherited release: {max_time}"
            );
            assert!(report.missing.is_none());
            assert_eq!(fx.run_record(0).automatic_runs, spent);
            assert!(fx.fx.record(id).attempts[0].decision.is_none());
            assert_eq!(
                OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                    .native_reserved_stroops(None)
                    .unwrap(),
                125
            );
            for server in &pair {
                assert_eq!(rpc_request_count(server, "getTransaction").await, 1);
                assert_eq!(rpc_request_count(server, "getLedgers").await, 0);
                assert_eq!(rpc_request_count(server, "getLedgerEntries").await, 0);
            }
        }
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_untimed_cap_and_backoff() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for max_time in [0, u64::MAX, u64::MAX / 1000] {
        let fx = Fixture::new(1, max_time);
        let mut now = NOW;
        for spent in 1..=16 {
            fx.fx.clock.set(now);
            let pair = fx.pair([60, 60], now, 0).await;
            let result = fx.run(&pair).await;
            assert!(
                result.is_ok(),
                "reservation {spent} is permitted: {result:?}"
            );
            let report = result.unwrap();
            assert_eq!(
                report.requests,
                RecoveryRequests {
                    shared: 4,
                    attempt: 2
                }
            );
            let run = fx.run_record(0);
            assert_eq!((run.automatic_runs, run.consecutive_stops), (spent, spent));
            let stop = run.stop.unwrap();
            assert_eq!(
                (stop.reason, stop.stage, stop.target),
                (RecoveryStopReason::Untimed, RecoveryStage::Hash, None)
            );
            let delay = [
                30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000, 3_600_000,
            ][usize::from(spent - 1).min(7)];
            assert_eq!(stop.earliest_retry_ms, Some(now + delay));
            now += delay;
            if spent == 16 {
                assert_eq!(
                    report.attempts[0].view.state,
                    RecoveryRunState::RetriesExhausted {
                        last_reason: RecoveryStopReason::Untimed
                    }
                );
                assert_eq!(report.attempts[0].view.earliest_retry_ms, None);
            }
        }
        fx.fx.clock.set(now);
        let pair = fx.pair([61, 61], now, 0).await;
        let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
        assert_eq!(
            fx.run(&pair).await.unwrap().requests,
            RecoveryRequests::default()
        );
        assert_eq!(
            serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
            before
        );
        assert!(pair[0].received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn stopped_attempts_do_not_starve_selection() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(5, NOW / 1000 - 6);
    let pair = fx.pair([60, 60], NOW, 0).await;
    fx.fx.clock.set(NOW - 1);
    assert_eq!(
        fx.run(&pair).await.unwrap().requests,
        RecoveryRequests::default()
    );
    assert!(pair[0].received_requests().await.unwrap().is_empty());
    fx.fx.clock.set(NOW);
    fx.fx.rewrite(|wire| {
        for record in wire.operations.as_mut().unwrap().records.iter_mut().take(4) {
            record.attempts[0].recovery_run =
                Some(serde_json::from_str("{ \"version\":99 }").unwrap());
        }
    });
    let before: Vec<_> = fx.ids[..4]
        .iter()
        .map(|id| serde_json::to_vec(&fx.fx.record(*id)).unwrap())
        .collect();
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.evaluated, 1);
    assert_eq!(report.attempts.len(), 5);
    assert_eq!(report.attempts[4].operation_id, fx.ids[4]);
    assert!(matches!(
        report.attempts[4].result,
        RecoveryResult::NeverApplicable { .. }
    ));
    assert!(report.attempts[..4].iter().all(|a| matches!(
        a.result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RecordUnusable,
            ..
        }
    )));
    let bytes = std::fs::read(fx.fx.store.path()).unwrap();
    let replay = fx.run(&pair).await.unwrap();
    assert_eq!(replay.attempts, report.attempts);
    assert_eq!(replay.requests, RecoveryRequests::default());
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), bytes);
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 6
        }
    );
    for (id, bytes) in fx.ids[..4].iter().zip(before) {
        assert_eq!(serde_json::to_vec(&fx.fx.record(*id)).unwrap(), bytes);
    }
    let client = StellarRpcClient::new(&pair[0].uri()).unwrap();
    let report = recover_outcomes(
        &fx.fx.store,
        &fx.fx.profile,
        EndpointPair::from_clients(&client, Some(&client)),
        &fx.writer,
        Some(&[1 ^ 0x80; 32]),
    )
    .await
    .unwrap();
    assert_eq!(report.requests, RecoveryRequests::default());
    assert_eq!(
        report.attempts[0].view.state,
        RecoveryRunState::Stopped(RecoveryStopReason::RecordUnusable)
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_cap_counts_completed_and_interrupted_reservations() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, 0);
    let mut now = NOW;
    for spent in 1..=16 {
        fx.fx.clock.set(now);
        let pair = fx.pair([60, 60], now, 0).await;
        let interrupted = spent % 2 == 0;
        if interrupted {
            WRITE_FAULT.set((1, super::super::store::COMMIT_FAULT_AFTER_COUNTER));
        }
        let hook = Hook;
        let result = fx.run(&pair).await;
        drop(hook);
        assert_eq!(result.is_err(), interrupted);
        assert_eq!(fx.run_record(0).automatic_runs, spent);
        assert_eq!(
            rpc_request_count(&pair[0], "getTransaction").await,
            usize::from(!interrupted)
        );
        assert_eq!(
            OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                .native_reserved_stroops(None)
                .unwrap(),
            125
        );
        let delay = [
            30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000, 3_600_000,
        ][usize::from(spent - 1).min(7)];
        now += delay + if interrupted { 20_000 } else { 0 };
    }
    let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
    for at in [fx.run_record(0).run_started_ms, now] {
        fx.fx.clock.set(at);
        let pair = fx.pair([62, 62], at, 0).await;
        let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
        let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
        let report = recover_outcomes(
            &fx.fx.store,
            &fx.fx.profile,
            EndpointPair::from_clients(&left, Some(&right)),
            &fx.writer,
            Some(&[0x81; 32]),
        )
        .await
        .unwrap();
        assert_eq!(report.requests, RecoveryRequests::default());
        assert_eq!(
            report.attempts[0].view.state,
            RecoveryRunState::RetriesExhausted {
                last_reason: RecoveryStopReason::Interrupted
            }
        );
        assert_eq!(
            serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
            before
        );
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_sixteenth_reservation_can_finish_its_decision() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let mut now = NOW;
    for spent in 1..=15 {
        fx.fx.clock.set(now);
        let pair = fx.pair([60, 60], now, 0).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getTransaction"})))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .with_priority(1)
            .mount(&pair[1])
            .await;
        let report = fx.run(&pair).await.unwrap();
        assert_eq!(report.evaluated, 1);
        assert_eq!(fx.run_record(0).automatic_runs, spent);
        assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
        now += [
            30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000, 3_600_000,
        ][usize::from(spent - 1).min(7)];
    }
    fx.fx.clock.set(now);
    let pair = fx.pair([62, 62], now, 0).await;
    let result = fx.run(&pair).await;
    assert!(
        result.is_ok(),
        "the reserved sixteenth run may finish: {result:?}"
    );
    let report = result.unwrap();
    assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
    let run = fx.run_record(0);
    assert_eq!((run.automatic_runs, run.consecutive_stops), (16, 0));
    assert_eq!(run.phase, RecoveryRunPhase::Resolved);
    assert!(run.stop.is_none());
    assert_eq!(
        OperationStatus::new(&fx.fx.store, &fx.fx.profile)
            .native_reserved_stroops(None)
            .unwrap(),
        0
    );
    let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
    assert_eq!(
        fx.run(&pair).await.unwrap().requests,
        RecoveryRequests::default()
    );
    assert_eq!(
        serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
        before
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_prefix_and_identity_are_read_only() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    for server in &pair {
        for name in ["getNetwork", "getHealth", "getTransaction"] {
            let path = fx.fx.store.path().to_owned();
            let seen = seen.clone();
            let answer = match name {
                "getNetwork" => stellar_agent_test_support::signed_envelope::get_network_result(
                    stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE,
                ),
                "getHealth" => {
                    json!({"status":"healthy","latestLedger":60,"oldestLedger":1,"ledgerRetentionWindow":60,"oldestLedgerCloseTime":1,"latestLedgerCloseTime":NOW/1000})
                }
                _ => absence(60, NOW),
            };
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method":name})))
                .respond_with(move |request: &wiremock::Request| {
                    seen.lock()
                        .unwrap()
                        .push((name, std::fs::read(&path).unwrap()));
                    wiremock::Respond::respond(&EchoIdResponder::new(answer.clone()), request)
                })
                .with_priority(1)
                .mount(server)
                .await;
        }
    }
    let result = fx.run(&pair).await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 6);
    for (name, bytes) in seen.iter() {
        if *name != "getTransaction" {
            assert_eq!(bytes, &before, "read-only {name}");
        } else {
            let wire: Value = serde_json::from_slice(&bytes[32..]).unwrap();
            assert_eq!(
                wire["operations"]["records"][0]["attempts"][0]["recovery_run"]["automatic_runs"],
                1
            );
            assert_eq!(wire["last_observation"]["ledger"], 60);
        }
    }
    drop(seen);
    result.unwrap();
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    override_answer(
        &pair[0],
        "getNetwork",
        json!({"passphrase":"wrong","protocolVersion":29}),
    )
    .await;
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    for _ in 0..2 {
        let error = fx.run(&pair).await.unwrap_err();
        assert_eq!(error.code(), "network.endpoint_network_mismatch");
        assert!(
            matches!(&error, RecoveryError::Context { source, .. } if matches!(source.as_ref(), RecoveryError::EndpointIdentity(_)))
        );
        assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
    }
    assert_eq!(rpc_request_count(&pair[0], "getNetwork").await, 2);
    assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, 0);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_commit_seams_use_verified_context() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use super::super::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
    };
    commit_seams(
        &[1, 2, 3, 4],
        &[
            COMMIT_FAULT_AFTER_PREPARED,
            COMMIT_FAULT_AFTER_COUNTER,
            COMMIT_FAULT_COMPACTION,
        ],
    )
    .await;
}

/// The reservation, release and decision writes each refuse after their audit
/// append and before their prepared image: the prior generation and run stay
/// byte-identical, and the refusal keeps the root code and verified progress.
#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_audit_append_seam_keeps_prior_generation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for stage in [1, 2, 4] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = fx.pair([60, 60], NOW, 0).await;
        let store = fx.fx.store.path().to_owned();
        let audit = fx.fx.profile.audit_log_path.clone();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(None));
        let slot = std::rc::Rc::clone(&seen);
        WRITE_HOOK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move |at| {
                if at == stage {
                    let lines =
                        std::fs::read_to_string(&audit).map_or(0, |log| log.lines().count());
                    *slot.borrow_mut() = Some((std::fs::read(&store).unwrap(), lines));
                }
            }));
        });
        WRITE_FAULT.set((stage, AUDIT_APPENDED));
        let hook = Hook;
        let result = fx.run(&pair).await;
        drop(hook);
        let (before, lines) = seen.borrow_mut().take().unwrap();
        assert_eq!(
            std::fs::read(fx.fx.store.path()).unwrap(),
            before,
            "stage {stage}"
        );
        let appended = std::fs::read_to_string(&fx.fx.profile.audit_log_path)
            .unwrap()
            .lines()
            .count();
        assert!(appended >= lines, "stage {stage}");
        let error = result.unwrap_err();
        assert_eq!(
            error.code(),
            "submission.record_unavailable",
            "stage {stage}"
        );
        let RecoveryError::Context { source, detail, .. } = error else {
            panic!("verified context required")
        };
        assert!(matches!(
            *source,
            RecoveryError::Store(WindowStoreError::Io {
                kind: std::io::ErrorKind::StorageFull
            })
        ));
        let released = usize::from(stage == 4);
        assert_eq!(
            detail,
            format!(
                "selected sequences: {released} released, {} held, 0 unavailable",
                1 - released
            ),
            "stage {stage}"
        );
        let record = fx.fx.record(fx.ids[0]);
        assert!(record.attempts[0].decision.is_none(), "stage {stage}");
        assert_eq!(
            OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                .native_reserved_stroops(None)
                .unwrap(),
            125
        );
        if stage == 1 {
            assert!(record.attempts[0].recovery_run.is_none());
            assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, 0);
        }
    }
}

async fn commit_seams(stages: &[u8], seams: &[u8]) {
    use super::super::store::{COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION};
    for &stage in stages {
        for &seam in seams {
            let fx = Fixture::new(1, if stage == 3 { 0 } else { NOW / 1000 - 10 });
            let pair = fx.pair([60, 60], NOW, 0).await;
            let before = fx.fx.wire().generation;
            WRITE_FAULT.set((stage, seam));
            let hook = Hook;
            let result = fx.run(&pair).await;
            drop(hook);
            let committed = seam != COMMIT_FAULT_AFTER_PREPARED;
            if seam == COMMIT_FAULT_COMPACTION {
                assert!(result.is_ok(), "{stage}/{seam}: {result:?}");
            } else {
                let error = result.unwrap_err();
                assert_eq!(error.code(), "submission.record_unavailable");
                let RecoveryError::Context { source, detail, .. } = error else {
                    panic!("verified context required")
                };
                assert!(matches!(
                    *source,
                    RecoveryError::Store(WindowStoreError::Io {
                        kind: std::io::ErrorKind::Interrupted
                    })
                ));
                let released = usize::from(stage == 4 || (stage == 2 && committed));
                assert!(
                    detail.starts_with(&format!(
                        "selected sequences: {released} released, {} held, 0 unavailable",
                        1 - released
                    )),
                    "{stage}/{seam}: {detail}"
                );
                assert_eq!(detail.ends_with("; decided: 1"), stage == 4 && committed);
            }
            let record = fx.fx.record(fx.ids[0]);
            assert_eq!(
                fx.fx.wire().last_observation.as_ref().map(|o| o.ledger),
                if stage == 1 && !committed {
                    None
                } else {
                    Some(60)
                }
            );
            if stage == 1 && !committed {
                assert!(record.attempts[0].recovery_run.is_none());
                assert_eq!(fx.fx.wire().generation, before);
            } else {
                assert_eq!(fx.run_record(0).automatic_runs, 1);
            }
            if stage == 1 && seam != COMMIT_FAULT_COMPACTION {
                assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, 0);
            }
            let decided =
                stage != 3 && (seam == COMMIT_FAULT_COMPACTION || (stage == 4 && committed));
            assert_eq!(record.attempts[0].decision.is_some(), decided);
            assert_eq!(
                OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                    .native_reserved_stroops(None)
                    .unwrap(),
                if decided { 0 } else { 125 }
            );
            if decided {
                assert_eq!(fx.run_record(0).phase, RecoveryRunPhase::Resolved);
                assert!(!record.attempts[0].decision.as_ref().unwrap().projected);
            }
            if stage == 3 {
                assert_eq!(
                    fx.run_record(0).phase,
                    if committed {
                        RecoveryRunPhase::Stopped
                    } else {
                        RecoveryRunPhase::Running
                    }
                );
                assert_eq!(fx.run_record(0).stop.is_some(), committed);
            }
            if stage == 3 && committed {
                assert_eq!(
                    fx.run_record(0).stop.unwrap().reason,
                    RecoveryStopReason::Untimed
                );
            }
        }
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_account_coverage_and_high_sequence() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for (ledger, sequence, reason, class) in [
        (
            60,
            101,
            RecoveryStopReason::CoverageRequired,
            RecoveryClass::Automatic,
        ),
        (
            55,
            0,
            RecoveryStopReason::AccountUnavailable,
            RecoveryClass::Automatic,
        ),
    ] {
        let mut fx = Fixture::new(1, NOW / 1000 - 10);
        fx.fx
            .recorder()
            .record_evidence(
                fx.ids[0],
                1,
                &EvidenceInput {
                    sequence_released: Some(SequenceReleaseInput {
                        primary_ledger: 60,
                        witness_ledger: 60,
                        min_close_time_ms: NOW,
                    }),
                    ..EvidenceInput::default()
                },
            )
            .unwrap();
        let pair = fx
            .pair(if sequence == 101 { [60, 60] } else { [50, 50] }, NOW, 0)
            .await;
        override_answer(
            &pair[0],
            "getLedgerEntries",
            account(&fx.source, ledger, sequence),
        )
        .await;
        override_answer(&pair[1], "getLedgerEntries", account(&fx.source, 60, 0)).await;
        let report = fx.run(&pair).await.unwrap();
        assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
        let stop = report.attempts[0].stop.as_ref().unwrap();
        assert_eq!(
            (stop.reason, stop.stage, stop.class, stop.roles.clone()),
            (
                reason,
                RecoveryStage::Account,
                class,
                vec![RecoveryRole::Primary]
            )
        );
        assert_eq!(
            stop.earliest_retry_ms,
            if class == RecoveryClass::Automatic {
                Some(NOW + 30_000)
            } else {
                None
            }
        );
        assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: if sequence == 101 { 6 } else { 4 }
            }
        );
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_partial_rows_follow_each_commit_seam() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use super::super::operations::WireEvidenceAnswer as Answer;
    use super::super::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
    };
    for method_name in [
        "getTransaction",
        "getLedgers",
        "getLedgerEntries",
        "release",
    ] {
        for seam in [
            COMMIT_FAULT_AFTER_PREPARED,
            COMMIT_FAULT_AFTER_COUNTER,
            COMMIT_FAULT_COMPACTION,
        ] {
            let fx = Fixture::new(1, NOW / 1000 - 10);
            let pair = fx.pair([60, 60], NOW, 0).await;
            let mut primary = absence(60, NOW);
            primary["oldestLedger"] = json!(30);
            override_answer(&pair[0], "getTransaction", primary).await;
            if method_name != "release" {
                Mock::given(method("POST"))
                    .and(body_partial_json(json!({"method":method_name})))
                    .respond_with(wiremock::ResponseTemplate::new(500))
                    .with_priority(1)
                    .mount(&pair[1])
                    .await;
            }
            WRITE_FAULT.set((if method_name == "release" { 2 } else { 3 }, seam));
            let hook = Hook;
            let result = fx.run(&pair).await;
            drop(hook);
            assert_eq!(
                result.is_ok(),
                seam == COMMIT_FAULT_COMPACTION,
                "{method_name}/{seam}"
            );
            let committed = seam != COMMIT_FAULT_AFTER_PREPARED;
            let record = fx.fx.record(fx.ids[0]);
            let attempt = &record.attempts[0];
            let row = attempt.evidence.iter().any(|row| {
                row.endpoint == EvidenceEndpoint::Primary
                    && matches!(
                        (&row.answer, method_name),
                        (Answer::Outcome { .. }, "getTransaction" | "release")
                            | (Answer::Ledger { .. }, "getLedgers")
                            | (Answer::Account { .. }, "getLedgerEntries")
                    )
            });
            assert_eq!(
                row, committed,
                "{method_name}/{seam}: successful-side row follows the counter"
            );
            assert_eq!(
                attempt
                    .recovery
                    .as_ref()
                    .is_some_and(|r| r.history_incomplete),
                committed || method_name == "getLedgerEntries"
            );
            assert_eq!(
                fx.fx.wire().last_observation.as_ref().map(|o| o.ledger),
                Some(60)
            );
            assert_eq!(fx.run_record(0).automatic_runs, 1);
            let decided = method_name == "release" && seam == COMMIT_FAULT_COMPACTION;
            assert_eq!(attempt.decision.is_some(), decided);
            assert_eq!(
                OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                    .native_reserved_stroops(None)
                    .unwrap(),
                if decided { 0 } else { 125 }
            );
        }
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_resolved_requires_exact_projection_before_successor() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let mut fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
    assert_eq!(
        super::super::operations::tests::successor_refusal(&mut fx.fx, &fx.handles[0]),
        "recovery.retry_refused"
    );
    let progress = crate::policy_state::operations::tests::progress::progress(&fx.fx, 1);
    assert!(progress.projection_pending && !progress.retry_eligible);
    assert!(!progress.outcome_recoverable);
    let decision = OperationStatus::new(&fx.fx.store, &fx.fx.profile)
        .committed_decisions(None)
        .unwrap()
        .remove(0);
    fx.fx
        .recorder()
        .acknowledge_projection(
            decision.operation_id,
            decision.attempt_index,
            decision.commit_id,
        )
        .unwrap();
    let progress = crate::policy_state::operations::tests::progress::progress(&fx.fx, 1);
    assert!(progress.retry_eligible && !progress.projection_pending);
    assert_eq!(
        super::super::operations::tests::successor_refusal(&mut fx.fx, &fx.handles[0]),
        "none"
    );
    assert_eq!(fx.fx.record(fx.ids[0]).attempts.len(), 2);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_source_defects_only_read_hashes() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for missing in [true, false] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        fx.fx.rewrite(|wire| {
            if missing {
                wire.authorizations.clear();
            } else {
                let crate::policy_state::DomainBinding::Transaction { source, .. } =
                    &mut wire.authorizations[0].binding
                else {
                    panic!("classic")
                };
                *source = stellar_strkey::ed25519::MuxedAccount {
                    ed25519: [1; 32],
                    id: 7,
                }
                .to_string()
                .as_str()
                .to_owned();
            }
        });
        let pair = fx.pair([60, 60], NOW, 0).await;
        let report = fx.run(&pair).await.unwrap();
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 2
            }
        );
        let stop = report.attempts[0].stop.as_ref().unwrap();
        assert_eq!(
            (
                stop.reason,
                stop.stage,
                stop.method,
                stop.class,
                stop.earliest_retry_ms
            ),
            (
                RecoveryStopReason::RecordUnusable,
                RecoveryStage::Account,
                None,
                RecoveryClass::Explicit,
                None
            )
        );
        assert!(stop.roles.is_empty());
        for server in &pair {
            assert_eq!(rpc_request_count(server, "getLedgerEntries").await, 0);
            assert_eq!(rpc_request_count(server, "getLedgers").await, 0);
        }
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_unreached_state_and_separate_causes() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for seconds in [6, 21] {
        let fx = Fixture::new(2, NOW / 1000 - 10);
        let pair = fx.pair([60, 60], NOW, 0).await;
        Mock::given(method("POST"))
            .and(body_partial_json(json!({"method":"getTransaction"})))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .with_priority(1)
            .mount(&pair[1])
            .await;
        let before = serde_json::to_vec(&fx.fx.record(fx.ids[1])).unwrap();
        ADVANCE.set(Some(Duration::from_secs(seconds)));
        let report = fx.run(&pair).await.unwrap();
        tokio::time::resume();
        assert_eq!(report.evaluated, 1);
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 2
            }
        );
        assert_eq!(report.missing.unwrap().reason, RecoveryReason::Transport);
        assert_eq!(report.attempts.len(), 2);
        assert_eq!(
            report.attempts[0].stop.as_ref().unwrap().reason,
            RecoveryStopReason::Transport
        );
        assert_eq!(
            report.attempts[1].stop.as_ref().unwrap().reason,
            if seconds == 6 {
                RecoveryStopReason::Lagging
            } else {
                RecoveryStopReason::Deadline
            }
        );
        assert_eq!(
            serde_json::to_vec(&fx.fx.record(fx.ids[1])).unwrap(),
            before
        );
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_hash_shape_refuses_without_release() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for defect in 0..8 {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = fx.pair([60, 60], NOW, 0).await;
        let mut bad = absence(60, NOW);
        match defect {
            0 => {
                bad.as_object_mut().unwrap().remove("oldestLedgerCloseTime");
            }
            1 => bad["oldestLedgerCloseTime"] = json!(0),
            2 => bad["oldestLedgerCloseTime"] = json!(NOW / 1000 + 1),
            3 => {
                bad.as_object_mut().unwrap().remove("latestLedgerCloseTime");
            }
            4 => bad["oldestLedger"] = json!(0),
            5 => bad["oldestLedger"] = json!(61),
            6 => bad["latestLedger"] = json!(59),
            _ => bad = json!([]),
        }
        override_answer(&pair[0], "getTransaction", bad).await;
        let report = fx.run(&pair).await.unwrap();
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 2
            }
        );
        let stop = report.attempts[0].stop.as_ref().unwrap();
        assert_eq!(
            (stop.reason, stop.stage, stop.class, stop.roles.clone()),
            (
                RecoveryStopReason::MissingField,
                RecoveryStage::Hash,
                RecoveryClass::Automatic,
                vec![RecoveryRole::Primary]
            )
        );
        let record = fx.fx.record(fx.ids[0]);
        assert!(record.attempts[0].sequence_released.is_none());
        assert!(record.attempts[0].decision.is_none());
    }
}

fn target_page(close: u64) -> Value {
    json!({"latestLedger":60, "latestLedgerCloseTime":NOW/1000, "oldestLedger":1,
        "oldestLedgerCloseTime":1,"cursor":"60", "ledgers":[{"sequence":60,
        "ledgerCloseTime":close.to_string(),"hash":"00".repeat(32),"headerXdr":"","metadataXdr":""}]})
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_strict_expiry_and_checked_close_conversions() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for stage in [RecoveryStage::Target, RecoveryStage::Health] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = fx.pair([60, 60], NOW, 0).await;
        let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
        let too_large = u64::MAX / 1000 + 1;
        if stage == RecoveryStage::Target {
            override_answer(&pair[0], "getLedgers", target_page(too_large)).await;
        } else {
            override_answer(&pair[0], "getHealth", json!({"status":"healthy","latestLedger":60,"oldestLedger":1,"ledgerRetentionWindow":60,"oldestLedgerCloseTime":1,"latestLedgerCloseTime":too_large})).await;
        }
        let report = fx.run(&pair).await.unwrap();
        let stop = report.attempts[0].stop.as_ref().unwrap();
        assert_eq!(
            (stop.reason, stop.stage, stop.class),
            (
                RecoveryStopReason::MissingField,
                stage,
                RecoveryClass::Automatic
            )
        );
        assert!(
            fx.fx.record(fx.ids[0]).attempts[0]
                .sequence_released
                .is_none()
        );
        if stage == RecoveryStage::Health {
            assert_eq!(report.evaluated, 0);
            assert_eq!(
                serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
                before
            );
            assert!(fx.fx.wire().last_observation.is_none());
        }
    }
    let max_time = NOW / 1000 - 6;
    let fx = Fixture::new(1, max_time);
    let pair = fx.pair([60, 60], NOW, 0).await;
    for server in &pair {
        override_answer(server, "getLedgers", target_page(max_time)).await;
    }
    let report = fx.run(&pair).await.unwrap();
    assert!(
        fx.fx.record(fx.ids[0]).attempts[0]
            .sequence_released
            .is_none()
    );
    let stop = report.attempts[0].stop.as_ref().unwrap();
    assert_eq!(
        (stop.reason, stop.stage, stop.earliest_retry_ms),
        (
            RecoveryStopReason::AwaitingExpiry,
            RecoveryStage::Target,
            Some(NOW + 30_000)
        )
    );
    assert!(
        fx.fx.record(fx.ids[0]).attempts[0]
            .sequence_released
            .is_none()
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_retention_and_fresh_target() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for health in [true, false] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = fx.pair([61, 60], NOW, 0).await;
        if health {
            override_answer(&pair[0], "getHealth", json!({"status":"healthy","latestLedger":61,"oldestLedger":61,"ledgerRetentionWindow":1,"oldestLedgerCloseTime":1,"latestLedgerCloseTime":NOW/1000})).await;
        } else {
            let mut page = target_page(NOW / 1000);
            page["oldestLedger"] = json!(61);
            override_answer(&pair[0], "getLedgers", page).await;
        }
        let report = fx.run(&pair).await.unwrap();
        assert!(
            fx.fx.record(fx.ids[0]).attempts[0]
                .sequence_released
                .is_none()
        );
        let stop = report.attempts[0].stop.as_ref().unwrap();
        assert_eq!(
            (stop.reason, stop.stage, stop.target, stop.earliest_retry_ms),
            (
                RecoveryStopReason::Lagging,
                RecoveryStage::Target,
                Some(60),
                Some(NOW + 30_000)
            )
        );
        assert!(
            fx.fx.record(fx.ids[0]).attempts[0]
                .sequence_released
                .is_none()
        );
        assert_eq!(
            rpc_request_count(&pair[0], "getLedgers").await,
            usize::from(!health)
        );
        fx.fx.clock.set(NOW + 30_000);
        let next = fx.pair([62, 63], NOW + 30_000, 0).await;
        let report = fx.run(&next).await.unwrap();
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 6
            }
        );
        let record = fx.fx.record(fx.ids[0]);
        assert_eq!(
            record.attempts[0]
                .sequence_released
                .as_ref()
                .unwrap()
                .primary_ledger,
            62
        );
        assert_eq!(record.state, OperationState::NotIncluded);
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_old_health_never_reserves() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW - 365 * 86_400_000, 0).await;
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.evaluated, 0);
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 3,
            attempt: 0
        }
    );
    assert_eq!(
        report.attempts[0].stop.as_ref().unwrap().reason,
        RecoveryStopReason::Lagging
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
}

// Both child processes use the parent's mock keyring through this loopback bridge.
// The real window and audit locks still serialize the production writers.
#[derive(Debug)]
struct ProxyStore(String);

#[derive(Debug)]
struct ProxyCredential {
    address: String,
    service: String,
    user: String,
}

/// The read bound for a bridge request the parent answers at once.
const BRIDGE_REPLY: Duration = Duration::from_secs(15);

/// The bound for a wait on the other child process: its process start under
/// an instrumented build can take longer than [`BRIDGE_REPLY`].
const PEER_WAIT: Duration = Duration::from_secs(120);

/// The extension of a race child's pass deadline: one [`PEER_WAIT`] for the
/// `ready` barrier, which the pass deadline already runs through, and one for
/// the parent's `getTransaction` responder.
const RACE_DEADLINE_EXTENSION: Duration = Duration::from_secs(240);

fn proxy(address: &str, request: &Value, read_timeout: Duration) -> Value {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream.set_read_timeout(Some(read_timeout)).unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

impl keyring_core::api::CredentialStoreApi for ProxyStore {
    fn vendor(&self) -> String {
        "recovery-test-bridge".into()
    }
    fn id(&self) -> String {
        "recovery-test-bridge".into()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn build(
        &self,
        service: &str,
        user: &str,
        _: Option<&std::collections::HashMap<&str, &str>>,
    ) -> keyring_core::Result<keyring_core::Entry> {
        Ok(keyring_core::Entry::new_with_credential(Arc::new(
            ProxyCredential {
                address: self.0.clone(),
                service: service.into(),
                user: user.into(),
            },
        )))
    }
}

impl keyring_core::api::CredentialApi for ProxyCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring_core::Result<()> {
        assert_eq!(
            proxy(
                &self.address,
                &json!({"op":"set","service":self.service,"user":self.user,"secret":secret}),
                BRIDGE_REPLY,
            ),
            true
        );
        Ok(())
    }
    fn get_secret(&self) -> keyring_core::Result<Vec<u8>> {
        let result = proxy(
            &self.address,
            &json!({"op":"get","service":self.service,"user":self.user}),
            BRIDGE_REPLY,
        );
        if result.is_null() {
            Err(keyring_core::Error::NoEntry)
        } else {
            Ok(serde_json::from_value(result).unwrap())
        }
    }
    fn delete_credential(&self) -> keyring_core::Result<()> {
        let result = proxy(
            &self.address,
            &json!({"op":"delete","service":self.service,"user":self.user}),
            BRIDGE_REPLY,
        );
        if result == true {
            Ok(())
        } else {
            Err(keyring_core::Error::NoEntry)
        }
    }
    fn get_credential(&self) -> keyring_core::Result<Option<Arc<keyring_core::api::Credential>>> {
        Ok(None)
    }
    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_process_child() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let Ok(config) = std::env::var("RECOVERY_CHILD") else {
        return;
    };
    let config: Value = serde_json::from_str(&config).unwrap();
    DEADLINE_EXTENSION.set(Some(RACE_DEADLINE_EXTENSION));
    let address = config["bridge"].as_str().unwrap().to_owned();
    keyring_core::set_default_store(Arc::new(ProxyStore(address.clone())));
    let _clock = crate::mainnet::clock::set_now_ms_for_test(NOW);
    let profile: Profile = serde_json::from_value(config["profile"].clone()).unwrap();
    let store = PersistedWindowStore::at_path(config["window"].as_str().unwrap().into());
    let audit_path = profile
        .audit_log_path
        .with_file_name(config["audit"].as_str().unwrap());
    let writer = crate::submission_flow::recovery::tests::writer_at(&audit_path);
    let bridge = address.clone();
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 1 {
                // The parent answers only when both children are ready.
                assert_eq!(proxy(&bridge, &json!({"op":"ready"}), PEER_WAIT), true);
            }
        }))
    });
    let hook = Hook;
    let left = StellarRpcClient::new(config["primary"].as_str().unwrap()).unwrap();
    let right = StellarRpcClient::new(config["oracle"].as_str().unwrap()).unwrap();
    let result = recover_outcomes(
        &store,
        &profile,
        EndpointPair::from_clients(&left, Some(&right)),
        &writer,
        None,
    )
    .await;
    drop(hook);
    let success = result.is_ok();
    if let Err(error) = result {
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(
            losing_refusal(&error).is_some(),
            "the loser refuses safely: {error:?}"
        );
    }
    assert_eq!(
        proxy(
            &address,
            &json!({"op":"done","success":success}),
            BRIDGE_REPLY
        ),
        true
    );
}

/// The safe refusal of a driver that loses the reservation race, named by
/// its rule: the stale-snapshot refusal of the exact run comparison, or the
/// window-lock refusal. Both carry the verified progress in `Context`.
fn losing_refusal(error: &RecoveryError) -> Option<&'static str> {
    let RecoveryError::Context { source, .. } = error else {
        return None;
    };
    match source.as_ref() {
        RecoveryError::Store(WindowStoreError::Invalid { detail })
            if detail == "recovery snapshot is stale" =>
        {
            Some("stale")
        }
        RecoveryError::Store(WindowStoreError::WriterLocked) => Some("locked"),
        _ => None,
    }
}

/// A reservation that cannot take the window lock returns the lock refusal
/// with verified progress, sends no attempt request and writes nothing.
#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_reservation_refuses_while_the_window_lock_is_held() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let held = std::rc::Rc::new(std::cell::RefCell::new(None));
    let slot = std::rc::Rc::clone(&held);
    let path = fx.fx.store.path().to_owned();
    let key = fx.fx.profile.policy_window_state_key_id.clone();
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 1 && slot.borrow().is_none() {
                *slot.borrow_mut() = Some(WindowStoreLock::acquire_for(&path, &key).unwrap());
            }
        }));
    });
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let hook = Hook;
    let result = fx.run(&pair).await;
    drop(hook);
    assert!(held.borrow_mut().take().is_some(), "the hook held the lock");
    let error = result.unwrap_err();
    assert_eq!(losing_refusal(&error), Some("locked"), "{error:?}");
    assert_eq!(error.code(), "submission.record_unavailable");
    let RecoveryError::Context { detail, .. } = &error else {
        unreachable!()
    };
    assert_eq!(
        detail,
        "selected sequences: 0 released, 1 held, 0 unavailable"
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
    for server in &pair {
        for name in ["getTransaction", "getLedgers", "getLedgerEntries"] {
            assert_eq!(rpc_request_count(server, name).await, 0, "{name}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(mainnet_clock)]
#[serial]
async fn driver_two_processes_race_reservation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use std::io::{BufRead, BufReader, Write};
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let stale_done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let signal = stale_done.clone();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getTransaction"})))
        .respond_with(move |request: &wiremock::Request| {
            let (lock, condition) = &*signal;
            let (seen, timeout) = condition
                .wait_timeout_while(lock.lock().unwrap(), PEER_WAIT, |seen| !*seen)
                .unwrap();
            if !*seen || timeout.timed_out() {
                return wiremock::ResponseTemplate::new(503);
            }
            wiremock::Respond::respond(&EchoIdResponder::new(absence(60, NOW)), request)
        })
        .with_priority(1)
        .mount(&pair[0])
        .await;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let credentials = keyring_core::get_default_store().unwrap();
    let server = std::thread::spawn(move || {
        let mut ready = Vec::new();
        let mut results = Vec::new();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let op = request["op"].as_str().unwrap();
            if op == "shutdown" {
                writeln!(stream, "true").unwrap();
                break;
            }
            if op == "ready" {
                ready.push(stream);
                if ready.len() == 2 {
                    for mut stream in ready.drain(..) {
                        writeln!(stream, "true").unwrap();
                    }
                }
                continue;
            }
            if op == "done" {
                let success = request["success"].as_bool().unwrap();
                results.push(success);
                if !success {
                    *stale_done.0.lock().unwrap() = true;
                    stale_done.1.notify_all();
                }
                writeln!(stream, "true").unwrap();
                continue;
            }
            let entry = credentials
                .build(
                    request["service"].as_str().unwrap(),
                    request["user"].as_str().unwrap(),
                    None,
                )
                .unwrap();
            let response = match op {
                "get" => entry
                    .get_secret()
                    .map_or(Value::Null, |secret| json!(secret)),
                "set" => {
                    entry
                        .set_secret(
                            &serde_json::from_value::<Vec<u8>>(request["secret"].clone()).unwrap(),
                        )
                        .unwrap();
                    json!(true)
                }
                "delete" => json!(entry.delete_credential().is_ok()),
                _ => panic!("unknown bridge operation"),
            };
            writeln!(stream, "{response}").unwrap();
        }
        results
    });
    let mut children = Vec::new();
    for index in 0..2 {
        let config = json!({"bridge":address, "profile":fx.fx.profile, "window":fx.fx.store.path(), "primary":pair[0].uri(), "oracle":pair[1].uri(), "audit":format!("child-{index}.jsonl")}).to_string();
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "policy_state::recovery::driver_tests::driver_process_child",
                    "--nocapture",
                ])
                .env("RECOVERY_CHILD", &config)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let output = tokio::task::spawn_blocking(move || {
        children
            .into_iter()
            .map(|child| child.wait_with_output().unwrap())
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    assert_eq!(
        proxy(&address, &json!({"op":"shutdown"}), BRIDGE_REPLY),
        true
    );
    for output in output {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let mut results = server.join().unwrap();
    results.sort();
    assert_eq!(results, [false, true]);
    assert_eq!(fx.run_record(0).automatic_runs, 1);
    assert_eq!(fx.fx.record(fx.ids[0]).state, OperationState::NotIncluded);
    assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, 1);
    assert_eq!(rpc_request_count(&pair[1], "getTransaction").await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial(mainnet_clock)]
#[serial]
async fn driver_new_owner_refuses_old_release_stop_and_decision() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    replaced_owner(&[2, 3, 5]).await;
}

async fn replaced_owner(stages: &[u8]) {
    use super::super::store::COMMIT_FAULT_AFTER_COUNTER;
    for &wanted in stages {
        let mut fx = Fixture::new(1, if wanted == 3 { 0 } else { NOW / 1000 - 10 });
        if wanted == 5 {
            fx.fx
                .recorder()
                .record_evidence(
                    fx.ids[0],
                    1,
                    &EvidenceInput {
                        sequence_released: Some(SequenceReleaseInput {
                            primary_ledger: 60,
                            witness_ledger: 60,
                            min_close_time_ms: NOW,
                        }),
                        ..EvidenceInput::default()
                    },
                )
                .unwrap();
        }
        let pair = fx.pair([60, 60], NOW, 0).await;
        let store = fx.fx.store.clone();
        let profile = fx.fx.profile.clone();
        let writer = fx.writer.clone();
        let urls = [pair[0].uri(), pair[1].uri()];
        let clock = Arc::new(Mutex::new(None));
        let saved_clock = clock.clone();
        let mut fresh_reads = 0;
        let mut injected = false;
        WRITE_HOOK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move |stage| {
                if stage == 5 {
                    fresh_reads += 1;
                }
                if injected || stage != wanted || (stage == 5 && fresh_reads != 2) {
                    return;
                }
                injected = true;
                let (store, profile, writer, urls) =
                    (store.clone(), profile.clone(), writer.clone(), urls.clone());
                let guard = std::thread::spawn(move || {
                    let guard = crate::mainnet::clock::set_now_ms_for_test(NOW + 50_000);
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap()
                        .block_on(async {
                            WRITE_FAULT.set((1, COMMIT_FAULT_AFTER_COUNTER));
                            let _hook = Hook;
                            let left = StellarRpcClient::new(&urls[0]).unwrap();
                            let right = StellarRpcClient::new(&urls[1]).unwrap();
                            let error = recover_outcomes(
                                &store,
                                &profile,
                                EndpointPair::from_clients(&left, Some(&right)),
                                &writer,
                                None,
                            )
                            .await
                            .unwrap_err();
                            assert_eq!(error.code(), "submission.record_unavailable");
                            assert!(matches!(error, RecoveryError::Context { .. }));
                        });
                    guard
                })
                .join()
                .unwrap();
                *saved_clock.lock().unwrap() = Some(guard);
            }))
        });
        let hook = Hook;
        let result = fx.run(&pair).await;
        assert!(result.is_err(), "an old owner is refused: {result:?}");
        let error = result.unwrap_err();
        drop(hook);
        assert_eq!(error.code(), "submission.record_unavailable");
        assert!(error.to_string().contains("recovery snapshot is stale"));
        let run = fx.run_record(0);
        assert_eq!(
            (run.automatic_runs, run.run_started_ms, run.phase),
            (2, NOW + 50_000, RecoveryRunPhase::Running)
        );
        assert!(fx.fx.record(fx.ids[0]).attempts[0].decision.is_none());
        assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, 1);
        drop(clock.lock().unwrap().take());
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_unrelated_write_preserves_ownership_and_fresh_generation() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for wanted in [2, 3, 5] {
        let fx = Fixture::new(2, if wanted == 3 { 0 } else { NOW / 1000 - 10 });
        let pair = fx.pair([60, 60], NOW, 0).await;
        let store = fx.fx.store.clone();
        let profile = fx.fx.profile.clone();
        let other = fx.ids[1];
        let mut written = false;
        let mut fresh_reads = 0;
        WRITE_HOOK.with_borrow_mut(|hook| {
            *hook = Some(Box::new(move |stage| {
                if stage == 5 {
                    fresh_reads += 1;
                }
                if written || stage != wanted || (stage == 5 && fresh_reads < 3) {
                    return;
                }
                written = true;
                let mut sink = super::super::operations::tests::Sink::default();
                OperationRecorder::new(&store, &profile, &mut sink, "unrelated")
                    .record_evidence(
                        other,
                        1,
                        &EvidenceInput {
                            recovery: Some(RecoveryUpdate {
                                last_outcome: Some("evidence_pending".into()),
                                ..RecoveryUpdate::default()
                            }),
                            ..EvidenceInput::default()
                        },
                    )
                    .unwrap();
            }))
        });
        let hook = Hook;
        let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
        let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
        let result = recover_outcomes(
            &fx.fx.store,
            &fx.fx.profile,
            EndpointPair::from_clients(&left, Some(&right)),
            &fx.writer,
            Some(&[1 ^ 0x80; 32]),
        )
        .await;
        assert!(
            result.is_ok(),
            "unrelated writes preserve ownership: {result:?}"
        );
        let report = result.unwrap();
        drop(hook);
        assert_eq!(report.evaluated, 1);
        assert_eq!(fx.run_record(0).automatic_runs, 1);
        assert_eq!(
            fx.fx.record(fx.ids[0]).attempts[0].decision.is_some(),
            wanted != 3
        );
        assert!(fx.fx.record(other).attempts[0].recovery_run.is_none());
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_request_budget_stops_durably() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, 0);
    let pair = fx.pair([60, 60], NOW, 0).await;
    ALLOWANCE.set(Some(0));
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 0
        }
    );
    assert_eq!(report.evaluated, 1);
    let stop = fx.run_record(0).stop.unwrap();
    assert_eq!(
        (
            stop.reason,
            stop.stage,
            stop.method,
            stop.roles,
            stop.earliest_retry_ms
        ),
        (
            RecoveryStopReason::RequestBudget,
            RecoveryStage::Lease,
            None,
            vec![],
            Some(NOW + 30_000)
        )
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_remaining_lease_bounds_pending_future() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let clock = Arc::new(Mutex::new(None));
    let changed = clock.clone();
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 1 {
                *changed.lock().unwrap() =
                    Some(crate::mainnet::clock::set_now_ms_for_test(NOW + 19_000));
            }
        }))
    });
    let hook = Hook;
    let pending = Arc::new(tokio::sync::Notify::new());
    let signal = pending.clone();
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getTransaction"})))
        .respond_with(move |request: &wiremock::Request| {
            signal.notify_one();
            wiremock::Respond::respond(&EchoIdResponder::new(absence(60, NOW)), request)
                .set_delay(Duration::from_secs(3600))
        })
        .with_priority(1)
        .mount(&pair[0])
        .await;
    let start = Instant::now();
    let (report, ()) = tokio::join!(fx.run(&pair), async {
        pending.notified().await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(1001)).await;
    });
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "the remaining one-second lease is earlier than the call deadline"
    );
    tokio::time::resume();
    drop(hook);
    let report = report.unwrap();
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 1
        }
    );
    assert_eq!(
        fx.run_record(0).stop.unwrap().reason,
        RecoveryStopReason::Deadline
    );
    assert_eq!(report.missing.unwrap().reason, RecoveryReason::Deadline);
    assert_eq!(
        report.attempts[0].view.state,
        RecoveryRunState::Stopped(RecoveryStopReason::Deadline)
    );
    drop(clock.lock().unwrap().take());
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_writer_schedule_overflow_has_store_context() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for now in [u64::MAX - 1, u64::MAX - 20_001] {
        let fx = Fixture::new(1, 0);
        fx.fx.clock.set(now);
        let pair = fx.pair([60, 60], now, 0).await;
        let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
        let error = fx.run(&pair).await.unwrap_err();
        assert_eq!(error.code(), "submission.record_unavailable");
        let RecoveryError::Context { source, detail, .. } = error else {
            panic!("store context")
        };
        assert!(
            matches!(*source, RecoveryError::Store(WindowStoreError::Invalid { detail }) if detail == "recovery_schedule_overflow")
        );
        assert!(detail.contains("0 released, 1 held, 0 unavailable"));
        assert_eq!(
            serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
            before
        );
        assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, 0);
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_clock_regression_stores_one_stable_stop() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, 0);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let saved_clock = Arc::new(Mutex::new(None));
    let changed = saved_clock.clone();
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 1 {
                *changed.lock().unwrap() =
                    Some(crate::mainnet::clock::set_now_ms_for_test(NOW - 1_000));
            }
        }))
    });
    let hook = Hook;
    fx.run(&pair).await.unwrap();
    drop(hook);
    let run = fx.run_record(0);
    let stop = run.stop.unwrap();
    assert_eq!(
        (
            stop.reason,
            stop.stage,
            stop.stopped_at_ms,
            stop.earliest_retry_ms
        ),
        (
            RecoveryStopReason::ClockRegression,
            RecoveryStage::Lease,
            NOW,
            Some(NOW + 30_000)
        )
    );
    assert_eq!((run.automatic_runs, run.consecutive_stops), (1, 1));
    let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
    assert_eq!(
        fx.run(&pair).await.unwrap().requests,
        RecoveryRequests::default()
    );
    assert_eq!(
        serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
        before
    );
    drop(saved_clock.lock().unwrap().take());
    fx.fx.clock.set(NOW + 30_000);
    let pair = fx.pair([62, 62], NOW + 30_000, 0).await;
    fx.run(&pair).await.unwrap();
    assert_eq!(
        (
            fx.run_record(0).automatic_runs,
            fx.run_record(0).consecutive_stops
        ),
        (2, 2)
    );
    assert_eq!(
        fx.run_record(0).stop.unwrap().reason,
        RecoveryStopReason::Untimed
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_prefix_quality_is_ephemeral_and_unavailable_is_unknown() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for (method_name, stage) in [
        ("getNetwork", RecoveryStage::Identity),
        ("getHealth", RecoveryStage::Health),
    ] {
        for (status, reason) in [
            (500, RecoveryStopReason::Transport),
            (429, RecoveryStopReason::RateLimited),
            (200, RecoveryStopReason::MissingField),
        ] {
            let fx = Fixture::new(1, NOW / 1000 - 10);
            let pair = fx.pair([60, 60], NOW, 0).await;
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method":method_name})))
                .respond_with(wiremock::ResponseTemplate::new(status).set_body_string("{}"))
                .with_priority(1)
                .mount(&pair[1])
                .await;
            let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
            let report = fx.run(&pair).await.unwrap();
            assert_eq!(report.evaluated, 0);
            assert_eq!(report.requests.attempt, 0);
            let stop = report.attempts[0].stop.as_ref().unwrap();
            assert_eq!(
                (
                    stop.reason,
                    stop.stage,
                    stop.class,
                    stop.roles.clone(),
                    stop.earliest_retry_ms
                ),
                (
                    reason,
                    stage,
                    RecoveryClass::Automatic,
                    vec![RecoveryRole::Oracle],
                    Some(NOW + 30_000)
                )
            );
            assert_eq!(
                serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
                before
            );
        }
    }
    let fx = Fixture::new(1, 0);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let path = fx.fx.store.path().to_owned();
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 1 {
                std::fs::write(&path, b"unreadable authenticated fixture").unwrap();
            }
        }))
    });
    let _hook = Hook;
    let error = fx.run(&pair).await.unwrap_err();
    assert_eq!(error.code(), "submission.record_unavailable");
    assert_eq!(
        error
            .report()
            .and_then(|r| r.refusal.as_ref())
            .map(|r| (r.code, r.state_unavailable)),
        Some(("submission.record_unavailable", true))
    );
    let RecoveryError::Context { detail, .. } = error else {
        panic!("store context")
    };
    assert!(
        detail.contains("0 released, 0 held, 1 unavailable"),
        "{detail}"
    );
    assert_eq!(rpc_request_count(&pair[0], "getTransaction").await, 0);
}

#[tokio::test]
async fn driver_rpc_timeout_keeps_its_exact_cause() {
    let mut budget = Budget::new();
    budget.context(
        RecoveryEndpoint::Oracle,
        RecoveryMethod::GetTransaction,
        None,
    );
    let result: Result<(), ReadFailure> = budget
        .read(false, async {
            Err(stellar_rpc_client::Error::JsonRpc(
                jsonrpsee_core::ClientError::RequestTimeout,
            ))
        })
        .await;
    assert!(matches!(
        result,
        Err(ReadFailure::Failed(RecoveryReason::Deadline))
    ));
    assert_eq!(
        budget.failure.unwrap(),
        RecoveryFailure {
            reason: RecoveryReason::Deadline,
            endpoint: RecoveryEndpoint::Oracle,
            method: RecoveryMethod::GetTransaction,
            ledger: None
        }
    );
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_oversized_utf8_prefix_is_bounded_and_read_only() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    Mock::given(method("POST"))
        .and(body_partial_json(json!({"method":"getHealth"})))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("界".repeat(4_000_000)))
        .with_priority(1)
        .mount(&pair[1])
        .await;
    let before = serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap();
    let report = fx.run(&pair).await.unwrap();
    let stop = report.attempts[0].stop.as_ref().unwrap();
    assert_eq!(
        (stop.reason, stop.stage, stop.class),
        (
            RecoveryStopReason::ResponseTooLarge,
            RecoveryStage::Health,
            RecoveryClass::Automatic
        )
    );
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 0
        }
    );
    assert_eq!(
        serde_json::to_vec(&fx.fx.record(fx.ids[0])).unwrap(),
        before
    );
    assert!(!format!("{report:?}").contains('界'));
    assert!(format!("{report:?}").len() < 2_000);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_four_timed_attempts_share_one_prefix() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(5, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let untouched = serde_json::to_vec(&fx.fx.record(fx.ids[4])).unwrap();
    // The mounted peers provide the shared observations before the attempts run.
    // Their freshness and the pass budget stay fixed while real I/O completes.
    tokio::time::pause();
    let _clock = stellar_agent_test_support::timing::ClockHold::new();
    let report = fx.run(&pair).await.unwrap();
    assert_eq!(report.evaluated, 4);
    assert!(matches!(
        report.attempts[4].result,
        RecoveryResult::NeedsEvidence {
            reason: RecoveryReason::RecoveryRequired,
            ..
        }
    ));
    assert_eq!(report.attempts.len(), 5);
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 24
        }
    );
    assert!(
        report
            .attempts
            .iter()
            .take(4)
            .all(|a| a.view.state == RecoveryRunState::Resolved)
    );
    assert_eq!(
        serde_json::to_vec(&fx.fx.record(fx.ids[4])).unwrap(),
        untouched
    );
    for server in &pair {
        assert_eq!(rpc_request_count(server, "getHealth").await, 1);
        assert_eq!(rpc_request_count(server, "getTransaction").await, 4);
        assert_eq!(rpc_request_count(server, "getLedgers").await, 4);
        assert_eq!(rpc_request_count(server, "getLedgerEntries").await, 4);
    }
}

/// The first attempt's checked decision commits, then the second attempt's
/// reservation write refuses: the call refuses, and the caller's batch keeps
/// the decision's edge beside the durable decision.
#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_batch_keeps_decision_before_later_error() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use super::super::store::COMMIT_FAULT_AFTER_PREPARED;
    let fx = Fixture::new(2, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    let mut reservations = 0;
    WRITE_HOOK.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |stage| {
            if stage == 1 {
                reservations += 1;
                if reservations == 2 {
                    WRITE_FAULT.set((1, COMMIT_FAULT_AFTER_PREPARED));
                }
            }
        }));
    });
    let hook = Hook;
    let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
    let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
    let mut committed = CommittedBatch::default();
    let result = recover_outcomes_committed(
        &fx.fx.store,
        &fx.fx.profile,
        EndpointPair::from_clients(&left, Some(&right)),
        &fx.writer,
        None,
        false,
        &mut committed,
    )
    .await;
    drop(hook);
    assert_eq!(result.unwrap_err().code(), "submission.record_unavailable");
    let decided = fx.fx.record(fx.ids[0]);
    assert!(decided.attempts[0].decision.is_some());
    assert!(fx.fx.record(fx.ids[1]).attempts[0].decision.is_none());
    let edges: Vec<_> = committed
        .into_iter()
        .map(|edge| (edge.operation_id(), edge.state(), edge.attempt_index()))
        .collect();
    assert_eq!(edges, vec![(fx.ids[0], decided.state, Some(1))]);
    assert_eq!(decided.state, OperationState::NotIncluded);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_each_peer_failure_preserves_only_successful_evidence() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use super::super::operations::WireEvidenceAnswer as Answer;
    for (method_name, stage) in [
        ("getTransaction", RecoveryStage::Hash),
        ("getLedgers", RecoveryStage::Target),
        ("getLedgerEntries", RecoveryStage::Account),
    ] {
        for defect in [2, 0, 1, 3] {
            let fx = Fixture::new(1, NOW / 1000 - 10);
            let pair = fx.pair([60, 60], NOW, 0).await;
            let mut primary = absence(60, NOW);
            primary["oldestLedger"] = json!(30);
            override_answer(&pair[0], "getTransaction", primary).await;
            let pending = Arc::new(tokio::sync::Notify::new());
            let signal = pending.clone();
            Mock::given(method("POST"))
                .and(body_partial_json(json!({"method":method_name})))
                .respond_with(move |_: &wiremock::Request| {
                    signal.notify_one();
                    match defect {
                        0 => wiremock::ResponseTemplate::new(500),
                        1 => wiremock::ResponseTemplate::new(200).set_body_string("{malformed"),
                        3 => wiremock::ResponseTemplate::new(200)
                            .set_body_string("界".repeat(4_000_000)),
                        _ => wiremock::ResponseTemplate::new(500)
                            .set_delay(Duration::from_secs(3600)),
                    }
                })
                .with_priority(1)
                .mount(&pair[1])
                .await;
            let report = if defect == 2 {
                let (report, ()) = tokio::join!(fx.run(&pair), async {
                    pending.notified().await;
                    tokio::time::pause();
                    tokio::time::advance(Duration::from_secs(21)).await;
                });
                tokio::time::resume();
                report.unwrap()
            } else {
                fx.run(&pair).await.unwrap()
            };
            let stop = report.attempts[0].stop.as_ref().unwrap();
            let reason = match defect {
                0 => RecoveryStopReason::Transport,
                1 => RecoveryStopReason::MissingField,
                3 => RecoveryStopReason::ResponseTooLarge,
                _ => RecoveryStopReason::Deadline,
            };
            assert_eq!(
                (stop.reason, stop.stage, stop.class, stop.roles.clone()),
                (
                    reason,
                    stage,
                    RecoveryClass::Automatic,
                    vec![RecoveryRole::Oracle]
                )
            );
            assert_eq!(stop.target, Some(60));
            assert_eq!(stop.earliest_retry_ms, Some(NOW + 30_000));
            let record = fx.fx.record(fx.ids[0]);
            let attempt = &record.attempts[0];
            assert!(attempt.decision.is_none());
            assert_eq!(
                attempt.sequence_released.is_some(),
                stage == RecoveryStage::Account
            );
            assert!(attempt.recovery.as_ref().unwrap().history_incomplete);
            assert!(
                attempt
                    .evidence
                    .iter()
                    .any(|r| r.endpoint == EvidenceEndpoint::Primary
                        && matches!(
                            (&r.answer, stage),
                            (Answer::Outcome { .. }, RecoveryStage::Hash)
                                | (Answer::Ledger { .. }, RecoveryStage::Target)
                                | (Answer::Account { .. }, RecoveryStage::Account)
                        ))
            );
            assert_eq!(
                OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                    .native_reserved_stroops(None)
                    .unwrap(),
                125
            );
            fx.fx.clock.set(NOW + 30_000);
            let next = fx.pair([62, 62], NOW + 30_000, 0).await;
            let report = fx.run(&next).await.unwrap();
            assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
            assert_eq!(
                report.requests,
                RecoveryRequests {
                    shared: 4,
                    attempt: if stage == RecoveryStage::Account {
                        4
                    } else {
                        6
                    }
                }
            );
            for server in &next {
                assert_eq!(rpc_request_count(server, "getTransaction").await, 1);
                assert_eq!(rpc_request_count(server, "getLedgerEntries").await, 1);
                let targets: Vec<_> = server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .map(|r| serde_json::from_slice::<Value>(&r.body).unwrap())
                    .filter(|r| r["method"] == "getLedgers")
                    .map(|r| {
                        (
                            r["params"]["startLedger"].clone(),
                            r["params"]["pagination"]["limit"].clone(),
                        )
                    })
                    .collect();
                assert_eq!(
                    targets,
                    if stage == RecoveryStage::Account {
                        Vec::new()
                    } else {
                        vec![(json!(62), json!(1))]
                    }
                );
            }
        }
    }
}

#[cfg(feature = "mainnet-write")]
#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_public_decision_then_separate_receipt_repair() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use crate::policy_state::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
    };
    receipt_seams(&[
        0,
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        COMMIT_FAULT_COMPACTION,
    ])
    .await;
}

#[cfg(feature = "mainnet-write")]
async fn receipt_seams(seams: &[u8]) {
    use crate::policy_state::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_COMPACTION, arm_accounting_fault,
    };
    for &seam in seams {
        let (fx, attempt, _) = super::tests::exposed_fixture("driver-repair").await;
        let selected = OperationStatus::new(&fx.window, &fx.profile)
            .outcome_snapshot(None)
            .unwrap()
            .remove(0);
        let ExposureIdentity::Classic { max_time, .. } = selected.exposure else {
            panic!("classic")
        };
        let due = (max_time + 6) * 1_000;
        fx.clock.set(due);
        let pair = [
            endpoint(60, due / 1_000).await,
            endpoint(60, due / 1_000).await,
        ];
        for server in &pair {
            mount(server, "getTransaction", absence(60, due)).await;
            mount(
                server,
                "getLedgerEntries",
                account(selected.account.as_deref().unwrap(), 60, 0),
            )
            .await;
        }
        let left = StellarRpcClient::new(&pair[0].uri()).unwrap();
        let right = StellarRpcClient::new(&pair[1].uri()).unwrap();
        let report = recover_outcomes(
            &fx.window,
            &fx.profile,
            EndpointPair::from_clients(&left, Some(&right)),
            &fx.writer,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 6
            }
        );
        assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
        let decision: super::super::operations::WireDecision =
            serde_json::from_value(fx.operation_record(attempt)["attempts"][0]["decision"].clone())
                .unwrap();
        assert!(!decision.projected);
        let replacement = (seam == 0).then(|| {
            crate::submission_flow::recovery::tests::on_replacement(|| {
                Err(WalletError::Submission(
                    stellar_agent_core::error::SubmissionError::RecordUnavailable {
                        detail: "injected receipt rename interruption".into(),
                    },
                ))
            })
        });
        let fault = (seam != 0).then(|| arm_accounting_fault(seam));
        let first = crate::submission_flow::recovery::repair_committed_receipts(
            &fx.window,
            &fx.profile,
            &fx.receipts,
            &fx.writer,
            None,
        );
        drop(fault);
        drop(replacement);
        assert_eq!(first.is_ok(), seam == COMMIT_FAULT_COMPACTION);
        let verified = OperationStatus::new(&fx.window, &fx.profile).committed_decisions(None);
        assert!(
            verified.is_ok(),
            "authoritative decisions remain readable: {verified:?}"
        );
        let verified = verified.unwrap();
        assert_eq!(verified.len(), 1);
        assert_eq!(
            verified[0].projected,
            seam == COMMIT_FAULT_AFTER_COUNTER || seam == COMMIT_FAULT_COMPACTION
        );
        assert_eq!(
            OperationStatus::new(&fx.window, &fx.profile)
                .recovery_run_view(attempt.operation_id, attempt.attempt_index, due)
                .unwrap()
                .unwrap()
                .state,
            RecoveryRunState::Resolved
        );
        crate::submission_flow::recovery::repair_committed_receipts(
            &fx.window,
            &fx.profile,
            &fx.receipts,
            &fx.writer,
            None,
        )
        .unwrap();
        assert!(
            OperationStatus::new(&fx.window, &fx.profile)
                .committed_decisions(None)
                .unwrap()[0]
                .projected
        );
        let before = fx.operation_record(attempt);
        crate::submission_flow::recovery::repair_committed_receipts(
            &fx.window,
            &fx.profile,
            &fx.receipts,
            &fx.writer,
            None,
        )
        .unwrap();
        assert_eq!(fx.operation_record(attempt), before);
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_inclusion_keeps_validated_fee_and_untimed_hash_only() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use stellar_agent_core::policy::v1::criteria::state_store::{
        PolicyStateStore, StateKey, WindowEntry, WindowLimit,
    };
    for (max_time, success, missing_source) in [
        (0, false, false),
        (u64::MAX, false, false),
        (u64::MAX / 1000, false, false),
        (NOW / 1000 - 10, true, false),
        (0, true, true),
    ] {
        let key = StateKey::new("driver", 0, "native", 86_400);
        let holds = vec![WindowEntry::new(
            key.clone(),
            NOW,
            100,
            WindowLimit::Amount {
                asset: "native".into(),
                window: "1d".into(),
                max_stroops: 1_000,
            },
        )];
        let fx = Fixture::with_holds(1, max_time, &holds);
        let envelope = super::tests::envelope_text(100);
        fx.fx.rewrite(|wire| {
            let exposure = &mut wire.operations.as_mut().unwrap().records[0].attempts[0]
                .exposure
                .as_mut()
                .unwrap()
                .identity;
            let ExposureIdentity::Classic {
                envelope_sha256,
                receipt,
                sequence,
                ..
            } = exposure
            else {
                panic!("classic")
            };
            *envelope_sha256 = Sha256::digest(&envelope).into();
            *receipt = stellar_agent_core::hex::encode(envelope_sha256);
            let id = receipt.clone();
            let sequence = *sequence;
            let chain_scope = wire.chain_scope;
            super::super::store::find_or_insert_bucket(&mut wire.entries, &key)
                .records
                .push(super::super::store::WireRecord {
                    chain_scope,
                    ts_ms: NOW,
                    amount: 100,
                    id,
                    status: super::super::store::RecordStatus::Pending,
                    tx_hash: "81".repeat(32),
                    source: fx.source.clone(),
                    sequence,
                    pending_since_ms: NOW,
                    ..super::super::store::WireRecord::confirmed_defaults()
                });
            if missing_source {
                wire.holds.clear();
                wire.authorizations.clear();
            }
        });
        let pair = fx.pair([60, 60], NOW, 0).await;
        if !success {
            let report = fx.run(&pair).await.unwrap();
            assert_eq!(
                report.requests,
                RecoveryRequests {
                    shared: 4,
                    attempt: 2
                }
            );
            assert_eq!(
                fx.run_record(0).stop.unwrap().reason,
                RecoveryStopReason::Untimed
            );
            fx.fx.clock.set(NOW + 30_000);
        }
        let pair = fx.pair([62, 63], NOW + 30_000, 0).await;
        let result = super::tests::result_text(success, 70);
        let answer = json!({"status":if success {"SUCCESS"} else {"FAILED"}, "ledger":40, "createdAt":NOW/1000,
            "txHash":"81".repeat(32), "envelopeXdr":envelope, "resultXdr":result, "latestLedger":60,"oldestLedger":1});
        for server in &pair {
            override_answer(server, "getTransaction", answer.clone()).await;
        }
        let report = fx.run(&pair).await.unwrap();
        assert_eq!(
            report.requests,
            RecoveryRequests {
                shared: 4,
                attempt: 2
            }
        );
        assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
        let record = fx.fx.record(fx.ids[0]);
        assert_eq!(
            record.state,
            if success {
                OperationState::Succeeded
            } else {
                OperationState::Failed
            }
        );
        assert_eq!(
            record.attempts[0].decision.as_ref().unwrap().fee_charged,
            if success { None } else { Some(70) }
        );
        let state = PolicyStateStore::new();
        fx.fx
            .store
            .load_into("driver", &fx.fx.profile, &state)
            .unwrap();
        assert_eq!(
            state.query_window(&key, NOW + 30_000).unwrap(),
            (if success { 100 } else { 70 }, 1)
        );
        assert!(record.attempts[0].sequence_released.is_none());
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_disagreements_keep_both_roles() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for stage in [RecoveryStage::Hash, RecoveryStage::Target] {
        let fx = Fixture::new(1, NOW / 1000 - 10);
        let pair = fx.pair([60, 60], NOW, 0).await;
        if stage == RecoveryStage::Hash {
            override_answer(&pair[0], "getTransaction", json!({"status":"SUCCESS"})).await;
            override_answer(&pair[1], "getTransaction", json!({"status":"FAILED"})).await;
        } else {
            override_answer(&pair[1], "getLedgers", target_page(NOW / 1000 - 1)).await;
        }
        let report = fx.run(&pair).await.unwrap();
        let stop = report.attempts[0].stop.as_ref().unwrap();
        assert_eq!(
            (
                stop.reason,
                stop.stage,
                stop.class,
                stop.roles.clone(),
                stop.earliest_retry_ms
            ),
            (
                RecoveryStopReason::Disagreement,
                stage,
                RecoveryClass::Automatic,
                vec![RecoveryRole::Primary, RecoveryRole::Oracle],
                Some(NOW + 30_000)
            )
        );
        assert!(
            fx.fx.record(fx.ids[0]).attempts[0]
                .sequence_released
                .is_none()
        );
        assert_eq!(
            OperationStatus::new(&fx.fx.store, &fx.fx.profile)
                .native_reserved_stroops(None)
                .unwrap(),
            125
        );
    }
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_release_crash_reuses_only_release_after_interruption() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    WRITE_FAULT.set((2, super::super::store::COMMIT_FAULT_AFTER_COUNTER));
    let hook = Hook;
    let error = fx.run(&pair).await.unwrap_err();
    drop(hook);
    assert!(
        error
            .to_string()
            .contains("1 released, 0 held, 0 unavailable")
    );
    let status = OperationStatus::new(&fx.fx.store, &fx.fx.profile);
    assert_eq!(status.native_reserved_stroops(None).unwrap(), 125);
    assert_eq!(fx.run_record(0).phase, RecoveryRunPhase::Running);
    for time in [NOW + 20_000, NOW + 40_000, NOW + 49_999] {
        let view = status
            .recovery_run_view(fx.ids[0], 1, time)
            .unwrap()
            .unwrap();
        assert_eq!(
            (view.state, view.earliest_retry_ms, view.effective_stops),
            (
                RecoveryRunState::Stopped(RecoveryStopReason::Interrupted),
                Some(NOW + 50_000),
                1
            )
        );
        fx.fx.clock.set(time);
        assert_eq!(
            fx.run(&pair).await.unwrap().requests,
            RecoveryRequests::default()
        );
    }
    fx.fx.clock.set(NOW + 50_000);
    let next = fx.pair([62, 63], NOW + 50_000, 0).await;
    let result = fx.run(&next).await;
    assert!(result.is_ok(), "the due restart completes: {result:?}");
    let report = result.unwrap();
    assert_eq!(
        report.requests,
        RecoveryRequests {
            shared: 4,
            attempt: 4
        }
    );
    assert_eq!(fx.run_record(0).automatic_runs, 2);
    assert_eq!(report.attempts[0].view.state, RecoveryRunState::Resolved);
    assert_eq!(status.native_reserved_stroops(None).unwrap(), 0);
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_missing_configuration_is_explicit_ephemeral() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let server = endpoint(60, NOW / 1000).await;
    let client = StellarRpcClient::new(&server.uri()).unwrap();
    let before = std::fs::read(fx.fx.store.path()).unwrap();
    let report = recover_outcomes(
        &fx.fx.store,
        &fx.fx.profile,
        EndpointPair::from_clients(&client, None),
        &fx.writer,
        None,
    )
    .await
    .unwrap();
    let stop = report.attempts[0].stop.as_ref().unwrap();
    assert_eq!(
        (
            stop.reason,
            stop.stage,
            stop.class,
            stop.earliest_retry_ms,
            stop.roles.clone()
        ),
        (
            RecoveryStopReason::ConfigurationRequired,
            RecoveryStage::Configuration,
            RecoveryClass::Explicit,
            None,
            vec![RecoveryRole::Oracle]
        )
    );
    assert_eq!(std::fs::read(fx.fx.store.path()).unwrap(), before);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
#[serial(mainnet_clock)]
#[serial]
async fn driver_store_context_reaches_unchanged_warning_adapter() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let fx = Fixture::new(1, NOW / 1000 - 10);
    let pair = fx.pair([60, 60], NOW, 0).await;
    WRITE_FAULT.set((4, super::super::store::COMMIT_FAULT_AFTER_COUNTER));
    let hook = Hook;
    let error = fx.run(&pair).await.unwrap_err();
    drop(hook);
    assert_eq!(error.code(), "submission.record_unavailable");
    assert!(
        error
            .to_string()
            .contains("selected sequences: 1 released, 0 held, 0 unavailable; decided: 1")
    );
    let pass = crate::submission_flow::ReconcilePass::RecoveryFailed {
        legacy: Default::default(),
        recovery: error.report().cloned().unwrap_or_default(),
        error,
    };
    let (warnings, guard) = stellar_agent_test_support::WarningCapture::capture(None);
    crate::submission_flow::finish_reconciliation(
        &fx.fx.profile,
        "driver",
        &fx.fx.store,
        None,
        &pass,
        || panic!("no remaining accounting obligation"),
    )
    .unwrap();
    drop(guard);
    let messages = format!("{:?}", warnings.seen());
    assert!(
        messages.contains("submission.record_unavailable"),
        "{messages}"
    );
    assert!(
        messages.contains("durable progress appears in the detail"),
        "{messages}"
    );
    assert!(messages.contains("decided: 1"), "{messages}");
}
