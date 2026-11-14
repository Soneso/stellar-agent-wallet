#![allow(clippy::unwrap_used, clippy::panic, clippy::too_many_lines)]

use super::*;
use crate::policy_state::operations::tests::{Fx, unknown_with};
use crate::policy_state::operations::{
    EvidenceInput, OperationStatus, RecoveryAttempt, RecoveryUpdate,
};
use crate::policy_state::store::{
    WIRE_VERSION_RECOVERY_RUN, WIRE_VERSION_TOTAL_EPOCH, WireFile, generation_entry_ref,
};
use serde_json::{Value, json};
use serial_test::serial;
use stellar_agent_core::policy::state_lock::WindowStoreLock;

const SOURCE: &str = "GAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPSABGM";

fn fixture() -> (Fx, OperationId, WireAttempt) {
    let mut fx = Fx::new();
    let id = unknown_with(&mut fx, 1, 10, vec![]).id();
    let attempt = fx.record(id).attempts[0].clone();
    (fx, id, attempt)
}

fn running(id: OperationId, attempt: &WireAttempt) -> Value {
    json!({
        "version":1,
        "exposure":recovery_exposure_digest(id, attempt.index, &attempt.exposure.as_ref().unwrap().identity).unwrap(),
        "phase":"running", "run_started_ms":1000, "run_deadline_ms":21000,
        "automatic_runs":1, "consecutive_stops":0
    })
}

fn stopped(id: OperationId, attempt: &WireAttempt) -> Value {
    let mut value = running(id, attempt);
    value["phase"] = json!("stopped");
    value["consecutive_stops"] = json!(1);
    value["stop"] = json!({
        "reason":"missing_field", "stage":"hash", "method":"get_transaction",
        "roles":["primary"], "ledger":null, "target":null,
        "stopped_at_ms":1000, "class":"automatic", "earliest_retry_ms":31000
    });
    value
}

fn with_raw(mut attempt: WireAttempt, raw: &str) -> WireAttempt {
    attempt.recovery_run = Some(serde_json::from_str(raw).unwrap());
    attempt
}

fn read(id: OperationId, attempt: &WireAttempt, raw: &str) -> RecoveryRunSnapshot {
    RecoveryRunSnapshot::of(id, &with_raw(attempt.clone(), raw), Some(SOURCE)).unwrap()
}

fn install(wire: &mut WireFile, id: OperationId, raw: &str) {
    wire.operations
        .as_mut()
        .unwrap()
        .records
        .iter_mut()
        .find(|r| r.id == id)
        .unwrap()
        .attempts[0]
        .recovery_run = Some(serde_json::from_str(raw).unwrap());
}

fn selected(fx: &Fx) -> RecoveryAttempt {
    OperationStatus::new(&fx.store, &fx.profile)
        .recovery_snapshot(None)
        .unwrap()
        .remove(0)
}

#[test]
#[serial]
fn run_wire_and_exposure() {
    let (fx, id, attempt) = fixture();
    let before = std::fs::read(fx.store.path()).unwrap();
    assert_eq!(fx.wire().version, WIRE_VERSION_TOTAL_EPOCH);
    let view = OperationStatus::new(&fx.store, &fx.profile)
        .recovery_run_view(id, 1, 0)
        .unwrap()
        .unwrap();
    assert_eq!(view.state, RecoveryRunState::RecoveryRequired);
    assert_eq!(view.earliest_retry_ms, Some(16000));
    assert_eq!(std::fs::read(fx.store.path()).unwrap(), before);
    let raw = running(id, &attempt).to_string();
    fx.rewrite(|wire| install(wire, id, &raw));
    assert_eq!(fx.wire().version, WIRE_VERSION_RECOVERY_RUN);
    assert!(selected(&fx).recovery_run.unwrap().record().is_some());
    fx.rewrite(|wire| wire.operations.as_mut().unwrap().records[0].attempts[0].recovery_run = None);
    assert_eq!(
        fx.wire().version,
        WIRE_VERSION_RECOVERY_RUN,
        "the committed floor survives removal"
    );
    let vector = ExposureIdentity::Classic {
        envelope_sha256: [2; 32],
        tx_hash: [3; 32],
        sequence: -7,
        max_time: 10,
        receipt: "receipt-é".into(),
    };
    assert_eq!(
        recovery_exposure_digest(OperationId::from_bytes([1; 16]), 2, &vector).unwrap(),
        "44b9d9a77bf606acb20bb68dceaceefc35d41bd6a7634aa116de4aab2263a883"
    );
    let mut future = running(id, &attempt);
    future["version"] = json!(2);
    fx.rewrite(|wire| install(wire, id, &future.to_string()));
    assert_eq!(fx.wire().version, WIRE_VERSION_RECOVERY_RUN);
    assert!(selected(&fx).recovery_run.unwrap().record().is_none());
}

#[test]
#[serial]
fn run_record_validation() {
    let (fx, id, attempt) = fixture();
    let valid = stopped(id, &attempt);
    assert!(read(id, &attempt, &valid.to_string()).record().is_some());
    let cases = [
        ("/version", json!(0)),
        ("/version", json!(2)),
        ("/automatic_runs", json!(0)),
        ("/automatic_runs", json!(17)),
        ("/automatic_runs", json!(-1)),
        ("/consecutive_stops", json!(0)),
        ("/consecutive_stops", json!(17)),
        ("/run_deadline_ms", json!(21001)),
        ("/run_started_ms", json!(u64::MAX)),
        ("/exposure", json!("A".repeat(64))),
        ("/exposure", json!("00".repeat(32))),
        ("/phase", json!("running")),
        ("/phase", json!("resolved")),
        ("/phase", json!("unknown")),
        ("/stop/reason", json!("retries_exhausted")),
        ("/stop/reason", json!("interrupted")),
        ("/stop/reason", json!("configuration_required")),
        ("/stop/reason", json!("untimed")),
        ("/stop/reason", json!("disagreement")),
        ("/stop/reason", json!("coverage_required")),
        ("/stop/reason", json!("record_unusable")),
        ("/stop/reason", json!("clock_regression")),
        ("/stop/stage", json!("record")),
        ("/stop/stage", json!("configuration")),
        ("/stop/stage", json!("identity")),
        ("/stop/stage", json!("health")),
        ("/stop/stage", json!("selection")),
        ("/stop/method", json!("get_ledgers")),
        ("/stop/method", Value::Null),
        ("/stop/roles", json!([])),
        ("/stop/roles", json!(["oracle", "primary"])),
        ("/stop/roles", json!(["primary", "primary"])),
        ("/stop/roles", json!(["primary", "oracle", "primary"])),
        ("/stop/ledger", json!(0)),
        ("/stop/target", json!(0)),
        ("/stop/stopped_at_ms", json!(999)),
        ("/stop/stopped_at_ms", json!(u64::MAX)),
        ("/stop/class", json!("explicit")),
        ("/stop/earliest_retry_ms", Value::Null),
        ("/stop/earliest_retry_ms", json!(31001)),
    ];
    for (path, bad) in cases {
        let mut row = valid.clone();
        *row.pointer_mut(path).unwrap() = bad;
        let snapshot = read(id, &attempt, &row.to_string());
        assert!(snapshot.record().is_none(), "isolates {path}: {row}");
        assert_eq!(
            normalize_recovery_run(Some(&snapshot), 10, 0, false, 99999).state,
            RecoveryRunState::Stopped(RecoveryStopReason::RecordUnusable),
            "{path}"
        );
    }
    for field in valid.as_object().unwrap().keys() {
        let mut row = valid.clone();
        row.as_object_mut().unwrap().remove(field);
        assert!(
            read(id, &attempt, &row.to_string()).record().is_none(),
            "missing {field}"
        );
    }
    for field in valid["stop"].as_object().unwrap().keys() {
        let mut row = valid.clone();
        row["stop"].as_object_mut().unwrap().remove(field);
        assert!(
            read(id, &attempt, &row.to_string()).record().is_none(),
            "missing stop {field}"
        );
    }
    let mut lease = valid.clone();
    lease["stop"]["reason"] = json!("clock_regression");
    lease["stop"]["stage"] = json!("lease");
    lease["stop"]["method"] = Value::Null;
    lease["stop"]["roles"] = json!([]);
    assert!(read(id, &attempt, &lease.to_string()).record().is_some());
    for field in ["method", "ledger", "target"] {
        let mut row = lease.clone();
        row["stop"].as_object_mut().unwrap().remove(field);
        assert!(
            read(id, &attempt, &row.to_string()).record().is_none(),
            "missing nullable {field}"
        );
    }
    let mut resolved = running(id, &attempt);
    resolved["phase"] = json!("resolved");
    assert!(
        read(id, &attempt, &resolved.to_string()).record().is_none(),
        "resolved requires decision"
    );
    let mut null_stop = running(id, &attempt);
    null_stop["stop"] = Value::Null;
    assert!(
        read(id, &attempt, &null_stop.to_string())
            .record()
            .is_none(),
        "a running stop is absent"
    );
    let mut mismatched = valid.clone();
    mismatched["consecutive_stops"] = json!(2);
    mismatched["stop"]["earliest_retry_ms"] = json!(61000);
    assert!(
        read(id, &attempt, &mismatched.to_string())
            .record()
            .is_none(),
        "stopped count matches reservations"
    );
    let mut mismatched = running(id, &attempt);
    mismatched["consecutive_stops"] = json!(1);
    assert!(
        read(id, &attempt, &mismatched.to_string())
            .record()
            .is_none(),
        "running count precedes reservation"
    );
    let mut earlier = valid.clone();
    earlier["stop"]["stopped_at_ms"] = json!(999);
    earlier["stop"]["earliest_retry_ms"] = json!(30999);
    assert!(
        read(id, &attempt, &earlier.to_string()).record().is_none(),
        "stop precedes start"
    );
    let raw = valid.to_string();
    for bad in [
        raw.replacen('{', "{\"unknown\":0,", 1),
        raw.replacen('{', "{\"version\":1,", 1),
        raw.replace("\"stop\":{", "\"stop\":{\"unknown\":0,"),
        raw.replace("\"stop\":{", "\"stop\":{\"reason\":\"missing_field\","),
        "{\"automatic_runs\":16,\"automatic_runs\":1}".into(),
    ] {
        assert!(read(id, &attempt, &bad).record().is_none());
    }
    for bad in [
        "null".into(),
        "[]".into(),
        "1".into(),
        format!("{{\"x\":\"{}\"}}", "x".repeat(1017)),
    ] {
        assert!(
            serde_json::from_str::<RawRecoveryRun>(&bad).is_err(),
            "file refusal: {bad}"
        );
    }
    let bound = format!("{{\"x\":\"{}\"}}", "x".repeat(1016));
    assert_eq!(bound.len(), 1024);
    assert!(read(id, &attempt, &bound).record().is_none());
    let outer = serde_json::to_string(&with_raw(attempt.clone(), "{}")).unwrap();
    assert!(
        serde_json::from_str::<WireAttempt>(&outer.replacen('{', "{\"recovery_run\":{},", 1))
            .is_err()
    );
    assert!(
        serde_json::from_str::<WireAttempt>(
            &outer.replace("\"recovery_run\":{}", "\"recovery_run\":null")
        )
        .is_err()
    );
    fx.rewrite(|wire| install(wire, id, &bound));
    assert!(selected(&fx).recovery_run.unwrap().record().is_none());
    assert_eq!(
        OperationStatus::new(&fx.store, &fx.profile)
            .recovery_snapshot(None)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn contextual_schedule_table() {
    use RecoveryRunMethod as M;
    use RecoveryStage as S;
    use RecoveryStopReason as R;
    for (stage, method) in [
        (S::Hash, M::GetTransaction),
        (S::Target, M::GetLedgers),
        (S::Account, M::GetLedgerEntries),
    ] {
        for reason in [
            R::MissingField,
            R::Disagreement,
            R::ResponseTooLarge,
            R::RateLimited,
            R::Transport,
            R::Lagging,
            R::Deadline,
            R::RequestBudget,
            R::AccountUnavailable,
        ] {
            let stop = RecoveryStop {
                reason,
                stage,
                method: Some(method),
                roles: vec![RecoveryRole::Primary, RecoveryRole::Oracle],
                ledger: Some(7),
                target: Some(7),
                stopped_at_ms: 1000,
                class: RecoveryClass::Automatic,
                earliest_retry_ms: Some(31000),
            };
            assert_eq!(
                classify_recovery_stop(reason, stage, Some(method), &stop.roles),
                RecoveryClass::Automatic,
                "{reason:?}/{stage:?}"
            );
            assert_eq!(stop_schedule(&stop, 0, 10).unwrap(), Some(31000));
            assert_eq!(stop.roles, [RecoveryRole::Primary, RecoveryRole::Oracle]);
        }
    }
    for (reason, stage, method, roles) in [
        (
            R::CoverageRequired,
            S::Account,
            Some(M::GetLedgerEntries),
            vec![RecoveryRole::Primary],
        ),
        (R::RecordUnusable, S::Record, None, vec![]),
        (R::ConfigurationRequired, S::Configuration, None, vec![]),
        (R::ConfigurationRequired, S::Identity, None, vec![]),
        (R::RecordUnusable, S::Account, None, vec![]),
        (R::MissingField, S::Configuration, None, vec![]),
        (R::Transport, S::Record, None, vec![]),
    ] {
        let stop = RecoveryStop {
            reason,
            stage,
            method,
            roles,
            ledger: None,
            target: None,
            stopped_at_ms: u64::MAX,
            class: RecoveryClass::Explicit,
            earliest_retry_ms: None,
        };
        assert_eq!(
            classify_recovery_stop(reason, stage, method, &stop.roles),
            RecoveryClass::Explicit
        );
        assert_eq!(stop_schedule(&stop, 0, 10).unwrap(), None);
    }
    for (reason, max_time, expected) in [
        (R::AwaitingExpiry, 100, 106000),
        (R::Untimed, 0, 31000),
        (R::ClockRegression, 10, 31000),
    ] {
        let stop = RecoveryStop {
            reason,
            stage: S::Lease,
            method: None,
            roles: vec![],
            ledger: None,
            target: None,
            stopped_at_ms: 1000,
            class: RecoveryClass::Automatic,
            earliest_retry_ms: Some(expected),
        };
        assert_eq!(stop_schedule(&stop, 0, max_time).unwrap(), Some(expected));
    }
}

#[test]
#[serial]
fn exhausted_reader() {
    let (_fx, id, attempt) = fixture();
    for count in [0_u8, 3, 15, 16, 17] {
        for phase in ["running", "stopped", "resolved"] {
            let mut row = if phase == "stopped" {
                stopped(id, &attempt)
            } else {
                running(id, &attempt)
            };
            row["automatic_runs"] = json!(count);
            row["phase"] = json!(phase);
            row["consecutive_stops"] = json!(if phase == "stopped" {
                count
            } else {
                count.saturating_sub(1)
            });
            if phase == "stopped" {
                row["stop"]["earliest_retry_ms"] =
                    json!(1000 + recovery_backoff(count.saturating_sub(1)));
            }
            let snapshot = read(id, &attempt, &row.to_string());
            for now in [0, 1000, 21000, u64::MAX] {
                let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, now);
                if count == 16 {
                    let last_reason = match phase {
                        "running" => RecoveryStopReason::Interrupted,
                        "stopped" => RecoveryStopReason::MissingField,
                        _ => RecoveryStopReason::RecordUnusable,
                    };
                    assert_eq!(
                        view.state,
                        RecoveryRunState::RetriesExhausted { last_reason }
                    );
                    assert_eq!(view.class, Some(RecoveryClass::Explicit));
                    assert_eq!(view.earliest_retry_ms, None);
                    assert_eq!(view.effective_stops, 16);
                } else if count == 0 || count == 17 || phase == "resolved" {
                    assert_eq!(
                        view.state,
                        RecoveryRunState::Stopped(RecoveryStopReason::RecordUnusable)
                    );
                } else {
                    assert!(!matches!(
                        view.state,
                        RecoveryRunState::RetriesExhausted { .. }
                    ));
                }
                assert_eq!(
                    normalize_recovery_run(Some(&snapshot), 10, 0, true, now).state,
                    RecoveryRunState::Resolved
                );
            }
        }
    }
}

#[test]
#[serial]
fn checked_schedule_arithmetic() {
    for error in [
        recovery_deadline(u64::MAX).unwrap_err(),
        recovery_retry_time(u64::MAX, 0).unwrap_err(),
    ] {
        assert!(
            matches!(&error,WindowStoreError::Invalid {detail} if detail=="recovery_schedule_overflow")
        );
        assert_eq!(
            crate::policy_state::RecoveryError::Store(error).code(),
            "submission.record_unavailable"
        );
    }
    assert_eq!(recovery_deadline(u64::MAX - 20000).unwrap(), u64::MAX);
    assert_eq!(recovery_retry_time(u64::MAX - 30000, 0).unwrap(), u64::MAX);
    assert_eq!(recovery_backoff(0), 30000);
    assert_eq!(recovery_backoff(16), 3600000);
    for max_time in [0, u64::MAX, u64::MAX - 1, u64::MAX / 1000] {
        assert_eq!(recovery_expiry(max_time), None);
        assert_eq!(
            normalize_recovery_run(None, max_time, 123, false, 0).earliest_retry_ms,
            Some(123)
        );
    }
    let (_fx, id, attempt) = fixture();
    for start in [u64::MAX, u64::MAX - 20000, u64::MAX - 49999] {
        let mut row = running(id, &attempt);
        row["run_started_ms"] = json!(start);
        row["run_deadline_ms"] = json!(start.saturating_add(20000));
        assert!(read(id, &attempt, &row.to_string()).record().is_none());
    }
    let mut retry = stopped(id, &attempt);
    retry["stop"]["stopped_at_ms"] = json!(u64::MAX);
    retry["stop"]["earliest_retry_ms"] = json!(u64::MAX);
    assert!(
        read(id, &attempt, &retry.to_string()).record().is_none(),
        "stored retry overflow isolates"
    );
    let mut deadline = stopped(id, &attempt);
    deadline["run_started_ms"] = json!(u64::MAX - 1);
    deadline["run_deadline_ms"] = json!(u64::MAX);
    deadline["stop"] = json!({"reason":"coverage_required","stage":"account","method":"get_ledger_entries",
        "roles":["primary"],"ledger":1,"target":1,"stopped_at_ms":u64::MAX,"class":"explicit","earliest_retry_ms":null});
    assert!(
        read(id, &attempt, &deadline.to_string()).record().is_none(),
        "stored deadline overflow isolates"
    );
}

#[test]
#[serial]
fn lease_and_clock_view() {
    let (_fx, id, attempt) = fixture();
    let snapshot = read(id, &attempt, &running(id, &attempt).to_string());
    for now in [21000, 50000, u64::MAX] {
        let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, now);
        assert_eq!(
            view.state,
            RecoveryRunState::Stopped(RecoveryStopReason::Interrupted)
        );
        assert_eq!(view.earliest_retry_ms, Some(51000));
        assert_eq!(view.effective_stops, 1);
    }
    let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, 999);
    assert_eq!(
        view.state,
        RecoveryRunState::Stopped(RecoveryStopReason::ClockRegression)
    );
    assert_eq!(view.earliest_retry_ms, Some(51000));
    assert_eq!(view.effective_stops, 0);
    assert_eq!(
        normalize_recovery_run(Some(&snapshot), 10, 0, false, 1000).state,
        RecoveryRunState::Running
    );
    let mut next = running(id, &attempt);
    next["automatic_runs"] = json!(2);
    next["consecutive_stops"] = json!(1);
    next["run_started_ms"] = json!(51000);
    next["run_deadline_ms"] = json!(71000);
    assert!(read(id, &attempt, &next.to_string()).record().is_some());
    let snapshot = read(id, &attempt, &stopped(id, &attempt).to_string());
    let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, 999);
    assert_eq!(view.earliest_retry_ms, Some(31000));
    assert_eq!(view.effective_stops, 1);
}

#[test]
#[serial]
fn supported_identity_surface_and_maximum_valid_run() {
    let (_fx, id, attempt) = fixture();
    let unsupported = ExposureIdentity::X402 {
        authorization_id: attempt.authorization_id,
        auth_entry_sha256: [1; 32],
        signature_expiration_ledger: 7,
    };
    assert!(
        matches!(recovery_exposure_digest(id, 1, &unsupported), Err(WindowStoreError::Invalid { detail }) if detail == "recovery_exposure_unsupported")
    );
    let row = running(id, &attempt);
    for field in 0..7 {
        let mut changed = attempt.clone();
        let mut owner = id;
        let ExposureIdentity::Classic {
            envelope_sha256,
            tx_hash,
            sequence,
            max_time,
            receipt,
        } = &mut changed.exposure.as_mut().unwrap().identity
        else {
            panic!("classic fixture")
        };
        match field {
            0 => owner = OperationId::from_bytes([0xff; 16]),
            1 => changed.index += 1,
            2 => *envelope_sha256 = [0xff; 32],
            3 => *tx_hash = [0xff; 32],
            4 => *sequence += 1,
            5 => *max_time += 1,
            _ => receipt.push('x'),
        }
        assert!(
            read(owner, &changed, &row.to_string()).record().is_none(),
            "binding field {field}"
        );
    }
    let mut invalid = stopped(id, &attempt);
    invalid["stop"] = json!({"reason":"record_unusable","stage":"account","method":null,"roles":[],"ledger":null,"target":null,"stopped_at_ms":1000,"class":"explicit","earliest_retry_ms":null});
    let raw = invalid.to_string();
    let attempt = with_raw(attempt, &raw);
    assert!(
        RecoveryRunSnapshot::of(id, &attempt, Some(SOURCE))
            .unwrap()
            .record()
            .is_none()
    );
    for account in [None, Some("Munsupported"), Some("arbitrary-é")] {
        let snapshot = RecoveryRunSnapshot::of(id, &attempt, account).unwrap();
        assert!(snapshot.record().is_some());
        let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, 0);
        assert_eq!(view.class, Some(RecoveryClass::Explicit));
        assert_eq!(view.earliest_retry_ms, None);
    }
    for (field, value) in [
        ("method", json!("get_ledger_entries")),
        ("roles", json!(["primary"])),
    ] {
        let mut bad = invalid.clone();
        bad["stop"][field] = value;
        let bad = with_raw(attempt.clone(), &bad.to_string());
        assert!(
            RecoveryRunSnapshot::of(id, &bad, None)
                .unwrap()
                .record()
                .is_none(),
            "unusable source has no account request"
        );
    }
    let mut largest = stopped(id, &attempt);
    largest["automatic_runs"] = json!(16);
    largest["consecutive_stops"] = json!(16);
    largest["run_started_ms"] = json!(u64::MAX - 3600000);
    largest["run_deadline_ms"] = json!(u64::MAX - 3580000);
    largest["stop"] = json!({"reason":"account_unavailable","stage":"account","method":"get_ledger_entries",
        "roles":["primary","oracle"],"ledger":u32::MAX,"target":u32::MAX,
        "stopped_at_ms":u64::MAX-3600000,"class":"automatic","earliest_retry_ms":u64::MAX});
    let snapshot = read(id, &attempt, &largest.to_string());
    let valid = snapshot.record().unwrap();
    assert_eq!(serde_json::to_vec(valid).unwrap().len(), 484);
    assert!(serde_json::to_vec(valid).unwrap().len() <= RECOVERY_RUN_MAX);
}

#[test]
#[serial]
fn run_decisions_preserve_bytes_and_win_over_spent_runs() {
    use crate::policy_state::operations::tests::{agreed, decide, decided_attempt};
    for count in [3, 16] {
        for phase in ["running", "stopped", "opaque"] {
            let mut fx = Fx::new();
            let (handle, _) = decided_attempt(&mut fx, 1);
            let id = handle.id();
            let attempt = fx.record(id).attempts.remove(0);
            let mut row = if phase == "stopped" {
                stopped(id, &attempt)
            } else {
                running(id, &attempt)
            };
            row["automatic_runs"] = json!(count);
            row["consecutive_stops"] = json!(if phase == "stopped" { count } else { count - 1 });
            if phase == "stopped" {
                row["stop"]["earliest_retry_ms"] = json!(1000 + recovery_backoff(count - 1));
            }
            let raw = if phase == "opaque" {
                "{ \"version\":99 }".to_owned()
            } else {
                row.to_string()
            };
            fx.rewrite(|wire| install(wire, id, &raw));
            let snapshot = OperationStatus::new(&fx.store, &fx.profile)
                .outcome_snapshot(None)
                .unwrap()
                .remove(0);
            let decision = decide(
                &snapshot,
                crate::policy_state::DecidedTransition::Succeeded(agreed(1, "SUCCESS")),
            );
            let first = fx.recorder().commit_decision(&decision).unwrap();
            assert_eq!(fx.recorder().commit_decision(&decision).unwrap(), first);
            assert_eq!(
                fx.record(id).attempts[0]
                    .recovery_run
                    .as_ref()
                    .unwrap()
                    .0
                    .get(),
                raw
            );
            let view = OperationStatus::new(&fx.store, &fx.profile)
                .recovery_run_view(id, 1, 0)
                .unwrap()
                .unwrap();
            assert_eq!(view.state, RecoveryRunState::Resolved);
            assert_eq!(view.earliest_retry_ms, None);
            let resolved_attempt = fx.record(id).attempts[0].clone();
            let mut resolved = running(id, &resolved_attempt);
            resolved["phase"] = json!("resolved");
            assert!(
                read(id, &resolved_attempt, &resolved.to_string())
                    .record()
                    .is_some()
            );
            for (field, value) in [
                ("consecutive_stops", json!(1)),
                ("automatic_runs", json!(0)),
                ("stop", stopped(id, &resolved_attempt)["stop"].clone()),
            ] {
                let mut bad = resolved.clone();
                bad[field] = value;
                assert!(
                    read(id, &resolved_attempt, &bad.to_string())
                        .record()
                        .is_none(),
                    "resolved shape {field}"
                );
            }
            assert_eq!(
                OperationStatus::new(&fx.store, &fx.profile)
                    .list_since(0)
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}

#[test]
#[serial]
fn opaque_generation_and_stale_snapshot() {
    use crate::policy_state::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
        arm_accounting_fault,
    };
    for seam in [
        0,
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        COMMIT_FAULT_COMPACTION,
    ] {
        let (mut fx, id, attempt) = fixture();
        let other = unknown_with(&mut fx, 2, 10, vec![]).id();
        let old = "{ \"version\" : 99, \"duplicate\": 1, \"duplicate\":2 }";
        let new = "{  \"version\" : 98, \"duplicate\": 1, \"duplicate\":2 }";
        fx.rewrite(|wire| install(wire, id, old));
        let lock =
            WindowStoreLock::acquire_for(fx.store.path(), &fx.profile.policy_window_state_key_id)
                .unwrap();
        let (key, _) = fx.store.load_or_mint_key(&fx.profile).unwrap();
        let original = fx.wire();
        let mut next = original.clone();
        install(&mut next, id, new);
        let write_fault = (seam == 0).then(crate::policy_state::store::fail_store_writes);
        let fault = arm_accounting_fault(seam);
        let result =
            fx.store
                .commit_generation(&key, &generation_entry_ref(&fx.profile), original, next);
        drop(fault);
        drop(write_fault);
        drop(lock);
        assert_eq!(result.is_ok(), seam == COMMIT_FAULT_COMPACTION);
        let expected = if seam == 0 || seam == COMMIT_FAULT_AFTER_PREPARED {
            old
        } else {
            new
        };
        let reopened =
            crate::policy_state::PersistedWindowStore::at_path(fx.store.path().to_owned());
        let reopened_attempt = OperationStatus::new(&reopened, &fx.profile)
            .recovery_snapshot(None)
            .unwrap()
            .into_iter()
            .find(|row| row.operation_id == id)
            .unwrap();
        assert_eq!(reopened_attempt.recovery_run.unwrap().raw.0.get(), expected);
        assert_eq!(
            fx.record(id).attempts[0]
                .recovery_run
                .as_ref()
                .unwrap()
                .0
                .get(),
            expected
        );
        fx.rewrite(|wire| {
            wire.operations
                .as_mut()
                .unwrap()
                .records
                .iter_mut()
                .find(|record| record.id == other)
                .unwrap()
                .updated_at_ms += 1
        });
        assert_eq!(
            fx.record(id).attempts[0]
                .recovery_run
                .as_ref()
                .unwrap()
                .0
                .get(),
            expected
        );
        assert!(read(id, &attempt, expected).record().is_none());
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .recovery_snapshot(None)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            OperationStatus::new(&fx.store, &fx.profile)
                .recovery_run_view(other, 1, 0)
                .unwrap()
                .unwrap()
                .state,
            RecoveryRunState::RecoveryRequired
        );
    }
    let (fx, id, attempt) = fixture();
    let first = running(id, &attempt).to_string();
    fx.rewrite(|wire| install(wire, id, &first));
    let mut next = running(id, &attempt);
    next["run_started_ms"] = json!(2000);
    next["run_deadline_ms"] = json!(22000);
    let store = &fx.store;
    let profile = &fx.profile;
    let barrier = std::sync::Barrier::new(2);
    let barrier = &barrier;
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            let snapshot = OperationStatus::new(store, profile)
                .recovery_snapshot(None)
                .unwrap();
            assert_eq!(snapshot.len(), 1);
            barrier.wait();
            let _lock =
                WindowStoreLock::acquire_for(store.path(), &profile.policy_window_state_key_id)
                    .unwrap();
            let (key, _) = store.load_or_mint_key(profile).unwrap();
            let gen_entry = generation_entry_ref(profile);
            let original = store.read_verified(profile, &key, &gen_entry).unwrap();
            let mut candidate = original.clone();
            install(&mut candidate, id, &next.to_string());
            store
                .commit_generation(&key, &gen_entry, original, candidate)
                .unwrap();
            drop(_lock);
            sent.send(()).unwrap();
        });
        let reader=scope.spawn(move || {
            let snapshot=OperationStatus::new(store,profile).recovery_snapshot(None).unwrap().remove(0);
            barrier.wait();
            received.recv().unwrap();
            let mut sink=crate::policy_state::operations::tests::Sink::default();
            let error=crate::policy_state::OperationRecorder::new(store,profile,&mut sink,"stale-reader")
                .record_evidence(id,1,&EvidenceInput {expected_attempt:Some(snapshot),recovery:Some(RecoveryUpdate {last_outcome:Some("stale".into()),..RecoveryUpdate::default()}),..EvidenceInput::default()}).unwrap_err();
            assert!(matches!(error,WindowStoreError::Invalid {detail} if detail=="recovery snapshot is stale"));
        });
        writer.join().unwrap();
        reader.join().unwrap();
    });
    for (left, right) in [("{\"v\":2}", "{ \"v\":2}"), ("{\"v\":2}", "{\"v\":3}")] {
        assert_ne!(read(id, &attempt, left), read(id, &attempt, right));
    }
    assert_eq!(
        read(id, &attempt, &first),
        read(id, &attempt, &format!("{{  {}", &first[1..]))
    );
}

#[test]
#[serial]
fn run_snapshot_each_field_refuses_stale_evidence() {
    let (mut fx, id, attempt) = fixture();
    fx.rewrite(|wire| install(wire, id, &stopped(id, &attempt).to_string()));
    let snapshot = selected(&fx);
    for field in 0..17 {
        let mut expected = snapshot.clone();
        let run = expected
            .recovery_run
            .as_mut()
            .unwrap()
            .run
            .as_mut()
            .unwrap();
        match field {
            0 => run.version = 2,
            1 => run.exposure.push('0'),
            2 => run.phase = RecoveryRunPhase::Running,
            3 => run.run_started_ms += 1,
            4 => run.run_deadline_ms += 1,
            5 => run.automatic_runs += 1,
            6 => run.consecutive_stops += 1,
            7 => run.stop = None,
            n => {
                let stop = run.stop.as_mut().unwrap();
                match n {
                    8 => stop.reason = RecoveryStopReason::Transport,
                    9 => stop.stage = RecoveryStage::Account,
                    10 => stop.method = Some(RecoveryRunMethod::GetLedgers),
                    11 => stop.roles = vec![RecoveryRole::Oracle],
                    12 => stop.ledger = Some(1),
                    13 => stop.target = Some(1),
                    14 => stop.stopped_at_ms += 1,
                    15 => stop.class = RecoveryClass::Explicit,
                    _ => stop.earliest_retry_ms = Some(31001),
                }
            }
        }
        let error = fx
            .recorder()
            .record_evidence(
                id,
                1,
                &EvidenceInput {
                    expected_attempt: Some(expected),
                    recovery: Some(RecoveryUpdate::default()),
                    ..EvidenceInput::default()
                },
            )
            .unwrap_err();
        assert!(
            matches!(error,WindowStoreError::Invalid {detail} if detail=="recovery snapshot is stale"),
            "field {field}"
        );
    }
    assert_eq!(selected(&fx), snapshot);
    fx.rewrite(|wire| install(wire, id, "{\"version\":99}"));
    let snapshot = selected(&fx);
    fx.rewrite(|wire| install(wire, id, "{ \"version\":99}"));
    let error = fx
        .recorder()
        .record_evidence(
            id,
            1,
            &EvidenceInput {
                expected_attempt: Some(snapshot),
                ..EvidenceInput::default()
            },
        )
        .unwrap_err();
    assert!(
        matches!(error,WindowStoreError::Invalid {detail} if detail=="recovery snapshot is stale")
    );
}

#[test]
#[serial]
fn typed_safe_refusal() {
    let (_fx, id, attempt) = fixture();
    for secret in ["é".repeat(400), "🔐".repeat(400), "\\\"".repeat(400)] {
        let raw = serde_json::to_string(&secret).unwrap();
        let error = serde_json::from_str::<RawRecoveryRun>(&raw).unwrap_err();
        assert!(error.to_string().len() < 128);
        assert!(!error.to_string().contains(&secret));
    }
    let snapshot = read(
        id,
        &attempt,
        "{\"version\":99,\"provider\":\"private-provider-answer\"}",
    );
    assert!(!format!("{snapshot:?}").contains("private-provider-answer"));
    let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, 0);
    assert_eq!(
        view.state,
        RecoveryRunState::Stopped(RecoveryStopReason::RecordUnusable)
    );
    assert_eq!(view.class, Some(RecoveryClass::Explicit));
    assert_eq!(view.earliest_retry_ms, None);
    let error = crate::policy_state::RecoveryError::Store(recovery_deadline(u64::MAX).unwrap_err());
    assert_eq!(error.code(), "submission.record_unavailable");
}

#[test]
#[serial]
fn run_context_contract() {
    let (_fx, id, attempt) = fixture();
    for (stage, method) in [
        ("hash", "get_transaction"),
        ("target", "get_ledgers"),
        ("account", "get_ledger_entries"),
    ] {
        let mut row = stopped(id, &attempt);
        row["stop"]["stage"] = json!(stage);
        row["stop"]["method"] = json!(method);
        if stage != "hash" {
            row["stop"]["target"] = json!(7);
        }
        assert!(
            read(id, &attempt, &row.to_string()).record().is_some(),
            "valid {stage}"
        );
        for wrong in [
            Value::Null,
            json!("get_transaction"),
            json!("get_ledgers"),
            json!("get_ledger_entries"),
        ] {
            if wrong == json!(method) {
                continue;
            }
            let mut bad = row.clone();
            bad["stop"]["method"] = wrong;
            assert!(
                read(id, &attempt, &bad.to_string()).record().is_none(),
                "method matches {stage}"
            );
        }
        if stage != "hash" {
            let mut bad = row.clone();
            bad["stop"]["target"] = Value::Null;
            assert!(
                read(id, &attempt, &bad.to_string()).record().is_none(),
                "target required at {stage}"
            );
        }
        row["stop"]["reason"] = json!("disagreement");
        row["stop"]["roles"] = json!(["primary", "oracle"]);
        assert!(read(id, &attempt, &row.to_string()).record().is_some());
        row["stop"]["reason"] = json!("account_unavailable");
        assert_eq!(
            read(id, &attempt, &row.to_string()).record().is_some(),
            stage == "account"
        );
        if stage == "account" {
            row["stop"]["reason"] = json!("coverage_required");
            row["stop"]["class"] = json!("explicit");
            row["stop"]["earliest_retry_ms"] = Value::Null;
            let snapshot = read(id, &attempt, &row.to_string());
            assert!(snapshot.record().is_some());
            let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, 0);
            assert_eq!(
                view.state,
                RecoveryRunState::Stopped(RecoveryStopReason::CoverageRequired)
            );
            assert_eq!(view.earliest_retry_ms, None);
            row["stop"]
                .as_object_mut()
                .unwrap()
                .remove("earliest_retry_ms");
            assert!(
                read(id, &attempt, &row.to_string()).record().is_none(),
                "explicit nullable time is required"
            );
        }
    }
    for reason in ["deadline", "request_budget", "clock_regression"] {
        let mut row = stopped(id, &attempt);
        row["stop"]["reason"] = json!(reason);
        row["stop"]["stage"] = json!("lease");
        row["stop"]["method"] = Value::Null;
        row["stop"]["roles"] = json!([]);
        assert!(read(id, &attempt, &row.to_string()).record().is_some());
        for (field, value) in [
            ("method", json!("get_transaction")),
            ("roles", json!(["primary"])),
        ] {
            let mut bad = row.clone();
            bad["stop"][field] = value;
            assert!(
                read(id, &attempt, &bad.to_string()).record().is_none(),
                "lease stop has no request context"
            );
        }
    }
    let mut untimed = attempt.clone();
    let ExposureIdentity::Classic { max_time, .. } =
        &mut untimed.exposure.as_mut().unwrap().identity
    else {
        panic!("classic fixture")
    };
    *max_time = 0;
    let mut row = stopped(id, &untimed);
    row["stop"]["reason"] = json!("untimed");
    row["stop"]["roles"] = json!(["primary", "oracle"]);
    assert!(read(id, &untimed, &row.to_string()).record().is_some());
    row["stop"]["target"] = json!(7);
    assert!(
        read(id, &untimed, &row.to_string()).record().is_none(),
        "untimed runs have no target"
    );
    let mut row = stopped(id, &attempt);
    row["stop"]["reason"] = json!("awaiting_expiry");
    row["stop"]["stage"] = json!("target");
    row["stop"]["method"] = json!("get_ledgers");
    row["stop"]["roles"] = json!(["primary", "oracle"]);
    row["stop"]["target"] = json!(7);
    assert!(read(id, &attempt, &row.to_string()).record().is_some());
    row["stop"]["roles"] = json!(["primary"]);
    assert!(
        read(id, &attempt, &row.to_string()).record().is_none(),
        "awaiting expiry retains both roles"
    );
}

#[test]
#[serial]
fn valid_run_generation_seams() {
    use crate::policy_state::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
        arm_accounting_fault,
    };
    for seam in [
        0,
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        COMMIT_FAULT_COMPACTION,
    ] {
        let (fx, id, attempt) = fixture();
        let old = running(id, &attempt).to_string();
        let mut candidate = running(id, &attempt);
        candidate["automatic_runs"] = json!(2);
        candidate["consecutive_stops"] = json!(1);
        let new = candidate.to_string();
        fx.rewrite(|wire| install(wire, id, &old));
        let lock =
            WindowStoreLock::acquire_for(fx.store.path(), &fx.profile.policy_window_state_key_id)
                .unwrap();
        let (key, _) = fx.store.load_or_mint_key(&fx.profile).unwrap();
        let original = fx.wire();
        let mut next = original.clone();
        install(&mut next, id, &new);
        let write_fault = (seam == 0).then(crate::policy_state::store::fail_store_writes);
        let fault = arm_accounting_fault(seam);
        let result =
            fx.store
                .commit_generation(&key, &generation_entry_ref(&fx.profile), original, next);
        drop(fault);
        drop(write_fault);
        drop(lock);
        assert_eq!(result.is_ok(), seam == COMMIT_FAULT_COMPACTION);
        let committed = seam == COMMIT_FAULT_AFTER_COUNTER || seam == COMMIT_FAULT_COMPACTION;
        let expected = if committed { &new } else { &old };
        for _ in 0..2 {
            let reopened =
                crate::policy_state::PersistedWindowStore::at_path(fx.store.path().to_owned());
            let snapshot = OperationStatus::new(&reopened, &fx.profile)
                .recovery_snapshot(None)
                .unwrap()
                .remove(0)
                .recovery_run
                .unwrap();
            assert_eq!(snapshot.raw.0.get(), expected);
            assert_eq!(
                snapshot.record().unwrap().automatic_runs,
                if committed { 2 } else { 1 }
            );
            let view = normalize_recovery_run(Some(&snapshot), 10, 0, false, u64::MAX);
            assert_eq!(
                view.state,
                RecoveryRunState::Stopped(RecoveryStopReason::Interrupted)
            );
            assert_eq!(
                view.earliest_retry_ms,
                Some(if committed { 81000 } else { 51000 })
            );
            assert_eq!(view.effective_stops, if committed { 2 } else { 1 });
        }
    }
}

#[test]
#[serial]
fn isolated_run_preserves_expiry_and_clear_lifecycle() {
    use crate::policy_state::operations::{ClearForm, OperationState, TransitionEvidence};
    let (mut fx, id, _) = fixture();
    let raw = "{ \"version\":99,\"automatic_runs\":2 }";
    fx.rewrite(|wire| install(wire, id, raw));
    let auth_id = fx.record(id).attempts[0].authorization_id;
    let later = crate::mainnet::clock::now_ms().unwrap() + 8 * 86400000;
    fx.clock.set(later);
    fx.recorder().expire_due(later).unwrap();
    assert_eq!(fx.record(id).state, OperationState::SentOutcomeUnknown);
    assert!(
        fx.wire()
            .authorizations
            .iter()
            .find(|auth| auth.id == auth_id)
            .unwrap()
            .native_release
            .is_none()
    );
    assert_eq!(
        OperationStatus::new(&fx.store, &fx.profile)
            .list_since(0)
            .unwrap()
            .len(),
        1
    );
    let before = fx.wire().generation;
    let refused = fx
        .recorder()
        .transition(
            id,
            Some(1),
            OperationState::Cancelled,
            &TransitionEvidence::default(),
        )
        .unwrap_err();
    assert!(matches!(refused, WindowStoreError::UnexpectedState { .. }));
    assert_eq!(fx.wire().generation, before);
    fx.recorder()
        .transition(
            id,
            Some(1),
            OperationState::Cancelled,
            &TransitionEvidence {
                clear: Some(ClearForm::Timed),
                ..TransitionEvidence::default()
            },
        )
        .unwrap();
    assert_eq!(fx.record(id).state, OperationState::Cancelled);
    assert!(
        fx.wire()
            .authorizations
            .iter()
            .find(|auth| auth.id == auth_id)
            .unwrap()
            .native_release
            .is_some()
    );
    assert_eq!(
        fx.record(id).attempts[0]
            .recovery_run
            .as_ref()
            .unwrap()
            .0
            .get(),
        raw
    );
    fx.clock.set(later + 8 * 86400000);
    fx.store.record_and_persist(&fx.profile, &[]).unwrap();
    assert!(
        fx.wire()
            .operations
            .as_ref()
            .unwrap()
            .records
            .iter()
            .all(|record| record.id != id)
    );
}

#[test]
#[serial]
fn isolated_run_preserves_approval_revocation() {
    use crate::policy_state::approvals::{ApprovalState, tests::Fx as ApprovalFx};
    use crate::policy_state::operations::{
        AttemptAuthorization, AttemptEnvelope, AttemptRequest, BusinessId, LookupOutcome,
        OperationRecorder,
    };
    let mut fx = ApprovalFx::new(300000);
    fx.open();
    fx.consent();
    let mint = fx.mint_request();
    let mut recorder = OperationRecorder::new(
        &fx.store,
        fx.fixture.profile(),
        &mut fx.rows,
        "revocation-reader",
    );
    let LookupOutcome::Resumable(handle) = recorder
        .lookup(&BusinessId::parse("order-1").unwrap())
        .unwrap()
        .unwrap()
    else {
        panic!("consented operation resumes")
    };
    recorder
        .begin_attempt(
            &handle,
            &AttemptRequest {
                envelope: Some(AttemptEnvelope {
                    xdr: "AAAA".into(),
                    unsigned_envelope_sha256: [1; 32],
                }),
                authorization: AttemptAuthorization::Mint(Box::new(mint)),
                send_by_ms: u64::MAX,
            },
        )
        .unwrap();
    let profile = fx.fixture.profile();
    let lock =
        WindowStoreLock::acquire_for(fx.store.path(), &profile.policy_window_state_key_id).unwrap();
    let (key, _) = fx.store.load_or_mint_key(profile).unwrap();
    let original = fx.wire();
    let mut candidate = original.clone();
    let raw = "{ \"version\":99 }";
    install(&mut candidate, fx.operation, raw);
    fx.store
        .commit_generation(&key, &generation_entry_ref(profile), original, candidate)
        .unwrap();
    drop(lock);
    let id = fx.id();
    let before = fx.wire().operations.unwrap().records[0].clone();
    assert_eq!(
        fx.recorder().revoke(id).unwrap().record.state,
        ApprovalState::Revoked
    );
    let after = fx.wire().operations.unwrap().records[0].clone();
    assert_eq!(after, before);
    assert_eq!(
        after.attempts[0].recovery_run.as_ref().unwrap().0.get(),
        raw
    );
    let bytes = fx.bytes();
    fx.recorder().revoke(id).unwrap();
    assert_eq!(fx.bytes(), bytes);
    assert_eq!(
        OperationStatus::new(&fx.store, fx.fixture.profile())
            .list_since(0)
            .unwrap()
            .len(),
        1
    );
    let pending = fx.fixture.payment(300000);
    let nonce = pending.approval_nonce.clone();
    let now = pending.created_at_unix_ms;
    let mut inbox = stellar_agent_core::approval::store::PendingApprovalStore::open(
        fx.store.path().with_extension("inbox"),
    )
    .unwrap();
    inbox.insert(pending, now).unwrap();
    assert!(inbox.reject(&nonce, now, 300000).unwrap());
    assert!(matches!(
        inbox.get(&nonce).unwrap().kind,
        stellar_agent_core::approval::store::ApprovalKind::Rejected { .. }
    ));
    assert_eq!(fx.bytes(), bytes);
}
