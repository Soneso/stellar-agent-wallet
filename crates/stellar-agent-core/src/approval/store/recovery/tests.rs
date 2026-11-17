#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use super::*;
use crate::approval::{AttestedApprover, ConsumedOutcome, mainnet_fixtures::MainnetConsentFixture};
use crate::policy::ApprovalRequest;

const START: u64 = 1_800_000_000_000;
const END: u64 = START + 1_001;
const RETAIN: u64 = START + 10_000;

fn envelope() -> String {
    crate::approval::fixtures::payment_envelope(
        &stellar_strkey::ed25519::PublicKey([3; 32]).to_string(),
        crate::approval::mainnet_fixtures::ALLOWED_DESTINATION,
        "XLM",
        1_000_000,
        Some("é"),
        177,
        101,
    )
}

fn queue(
    store: &mut PendingApprovalStore,
    policy: &VerifiedPolicy,
    now: u64,
) -> Result<PendingApproval, ApprovalError> {
    store.recover_payment(
        PaymentRecoveryContext {
            profile: "recovery",
            chain: Caip2::Mainnet,
            policy,
            operation: Some(([7; 16], RETAIN)),
        },
        &envelope(),
        "1000".to_owned(),
        now,
        now + 1_001,
        now,
        &ApprovalRequest::new("review".to_owned(), 600),
    )
}

#[test]
#[serial_test::serial]
fn payment_recovery_preserves_consent_and_each_key_component() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let path = fixture.store_path();
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let first = queue(&mut store, &policy, START).unwrap();
    store
        .record_attestation_at(
            &first.approval_nonce,
            [9; 32],
            AttestedApprover::Local,
            START,
        )
        .unwrap();
    let original = serde_json::to_value(store.get(&first.approval_nonce).unwrap()).unwrap();
    drop(store);
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let recovered = queue(&mut store, &policy, START + 100).unwrap();
    assert_eq!(
        serde_json::to_value(&recovered).unwrap(),
        original,
        "original consent bytes"
    );
    assert_eq!(store.len(), 1);
    assert_eq!(store.payment_recovery.len(), 1);
    let original_key = store.payment_recovery[0].key.clone();
    for component in 0..5 {
        store.payment_recovery[0].key = original_key.clone();
        match component {
            0 => store.payment_recovery[0].key.profile = "another".to_owned(),
            1 => {
                store.payment_recovery[0].key.chain = Caip2::Testnet;
                store.payment_recovery[0].key.operation = None;
                store.payment_recovery[0].retain_until = END;
            }
            2 => store.payment_recovery[0].key.operation = Some([8; 16]),
            3 => store.payment_recovery[0].key.policy_digest[0] ^= 1,
            4 => store.payment_recovery[0].key.policy_sequence += 1,
            _ => unreachable!(),
        }
        let next = queue(&mut store, &policy, START).unwrap();
        assert_ne!(
            next.approval_nonce, first.approval_nonce,
            "component {component}"
        );
        store
            .entries
            .retain(|e| e.approval_nonce == first.approval_nonce);
        store.payment_recovery.truncate(1);
        store.payment_recovery[0].retain_until = RETAIN;
    }
    store.payment_recovery[0].key = original_key;
    let mut other_envelope = envelope();
    use stellar_xdr::{ReadXdr, WriteXdr};
    let mut tx = stellar_xdr::TransactionEnvelope::from_xdr_base64(
        &other_envelope,
        stellar_xdr::Limits::none(),
    )
    .unwrap();
    if let stellar_xdr::TransactionEnvelope::Tx(ref mut v1) = tx {
        v1.tx.seq_num.0 += 1;
    }
    other_envelope = tx.to_xdr_base64(stellar_xdr::Limits::none()).unwrap();
    let second = store
        .recover_payment(
            PaymentRecoveryContext {
                profile: "recovery",
                chain: Caip2::Mainnet,
                policy: &policy,
                operation: Some(([7; 16], RETAIN)),
            },
            &other_envelope,
            "1000".to_owned(),
            START,
            END,
            START,
            &ApprovalRequest::new("review".to_owned(), 600),
        )
        .unwrap();
    assert_ne!(
        second.approval_nonce, first.approval_nonce,
        "envelope subject"
    );
    // A matching request succeeds even when all other slots are occupied.
    while store.entries.len() < super::super::MAX_PENDING_APPROVALS {
        let mut entry = first.clone();
        entry.approval_nonce = format!("capacity{:014}", store.entries.len());
        store.entries.push(entry);
    }
    let at_capacity = queue(&mut store, &policy, START).unwrap();
    assert_eq!(at_capacity.approval_nonce, first.approval_nonce);
    assert_eq!(store.len(), super::super::MAX_PENDING_APPROVALS);
    store.entries.push(store.entries[2].clone());
    assert_eq!(
        store.retained_count(),
        super::super::MAX_PENDING_APPROVALS,
        "one slot per retained nonce"
    );
    store.entries.pop();
    store.remove(&first.approval_nonce).unwrap();
    assert_eq!(store.len(), super::super::MAX_PENDING_APPROVALS - 1);
    let mut fresh = first;
    fresh.approval_nonce = "fresh00000000000000000".to_owned();
    assert!(
        matches!(
            store.insert(fresh, START),
            Err(ApprovalError::PendingStoreFull { .. })
        ),
        "collected bindings still consume capacity"
    );
    store.gc_expired(RETAIN).unwrap();
    assert_eq!(
        store.retained_count(),
        0,
        "ended retention releases capacity"
    );
}

#[test]
#[serial_test::serial]
fn payment_recovery_process_exit_preserves_atomic_pair() {
    use super::super::persist_test_seam::{self, Step};
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    if let Ok(path) = std::env::var("PAYMENT_RECOVERY_CHILD_PATH") {
        let path = std::path::PathBuf::from(path);
        let step = match std::env::var("PAYMENT_RECOVERY_CRASH").unwrap().as_str() {
            "temporary" => Step::TemporarySynced,
            "rename" => Step::Renamed,
            "file" => Step::FileSynced,
            "directory" => Step::DirectorySynced,
            _ => panic!("known persistence boundary"),
        };
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        persist_test_seam::on_step(&path, step, || std::process::exit(81));
        queue(&mut store, &policy, START).unwrap();
        panic!("the selected persistence boundary exits");
    }
    for step in ["temporary", "rename", "file", "directory"] {
        let path = fixture.home().join(format!("{step}.toml"));
        let store = PendingApprovalStore::open(path.clone()).unwrap();
        store.persist().unwrap();
        drop(store);
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact").arg("approval::store::recovery::tests::payment_recovery_process_exit_preserves_atomic_pair")
            .env("PAYMENT_RECOVERY_CHILD_PATH", &path).env("PAYMENT_RECOVERY_CRASH", step)
            .output().unwrap();
        assert_eq!(child.status.code(), Some(81), "child reaches {step}");
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let old_or_new = if step == "temporary" { 0 } else { 1 };
        assert_eq!(store.len(), old_or_new, "payload at {step}");
        assert_eq!(
            store.payment_recovery.len(),
            old_or_new,
            "binding at {step}"
        );
        let original_nonce = store.payment_recovery.first().map(|b| b.nonce.clone());
        let recovered = queue(&mut store, &policy, START).unwrap();
        if let Some(nonce) = original_nonce {
            assert_eq!(recovered.approval_nonce, nonce, "post-rename recovery");
        }
        drop(store);
        let store = PendingApprovalStore::open(path).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.payment_recovery.len(), 1);
    }
}

#[test]
#[serial_test::serial]
fn payment_recovery_terminal_writers_and_backward_clock_refuse() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    for mode in [
        "expired",
        "rejected",
        "consumed",
        "collected",
        "attest-expired",
    ] {
        let path = fixture.home().join(format!("{mode}.toml"));
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let first = queue(&mut store, &policy, START).unwrap();
        match mode {
            "expired" => assert!(matches!(
                queue(&mut store, &policy, END),
                Err(ApprovalError::Expired)
            )),
            "attest-expired" => assert!(matches!(
                store.record_attestation_at(
                    &first.approval_nonce,
                    [9; 32],
                    AttestedApprover::Local,
                    END
                ),
                Err(ApprovalError::Expired)
            )),
            "rejected" => {
                store.reject(&first.approval_nonce, START + 1, 300).unwrap();
            }
            "consumed" => {
                store
                    .consume(
                        &first.approval_nonce,
                        &"ab".repeat(32),
                        ConsumedOutcome::Unknown,
                    )
                    .unwrap();
                store.gc_expired_and_consumed(START + 1).unwrap();
            }
            "collected" => {
                store.remove(&first.approval_nonce).unwrap();
            }
            _ => unreachable!(),
        }
        drop(store);
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let retry = queue(&mut store, &policy, START);
        assert!(
            retry.is_err(),
            "{mode}: terminal retry never queues a replacement"
        );
        let check = store.check_payment_recovery(&first.approval_nonce);
        assert!(check.is_err(), "{mode}: read-only status remains terminal");
        for error in [retry.unwrap_err(), check.unwrap_err()] {
            assert!(
                match mode {
                    "rejected" => matches!(error, ApprovalError::Rejected),
                    "consumed" => matches!(error, ApprovalError::Consumed),
                    _ => matches!(error, ApprovalError::Expired),
                },
                "{mode}: {error:?}"
            );
        }
        assert_eq!(store.payment_recovery.len(), 1);
        assert_eq!(store.payment_recovery[0].nonce, first.approval_nonce);
        assert_eq!(store.payment_recovery[0].expires, END);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // Every ordinary writer carries the binding into its replacement.
        let mut unrelated = first.clone();
        unrelated.approval_nonce = "unrelated00000000000000".to_owned();
        store.insert(unrelated, START).unwrap();
        store.gc_expired(END).unwrap();
        drop(store);
        let store = PendingApprovalStore::open(path).unwrap();
        assert_eq!(
            store.payment_recovery.len(),
            1,
            "{mode}: binding survives writers"
        );
        assert!(store.get(&first.approval_nonce).is_none());
        assert!(store.check_payment_recovery(&first.approval_nonce).is_err());
    }
}

#[test]
#[serial_test::serial]
fn payment_recovery_attestation_checks_recorded_expiry() {
    use crate::approval::{attest, user_id::ApproverIdentity};
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let now = crate::timefmt::now_unix_ms().unwrap();
    let path = fixture.store_path();
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let entry = store
        .recover_payment(
            PaymentRecoveryContext {
                profile: "recovery",
                chain: Caip2::Mainnet,
                policy: &policy,
                operation: Some(([7; 16], now + 120_000)),
            },
            &envelope(),
            "1000".to_owned(),
            now,
            now + 60_000,
            now,
            &ApprovalRequest::new("review".to_owned(), 60),
        )
        .unwrap();
    let identity = ApproverIdentity::OsUid("1000".to_owned());
    assert!(attest::load_and_validate_entry(&store, &entry.approval_nonce, &identity, &[]).is_ok());
    let presence = fixture.presence(&entry, &policy);
    let approver = AttestedApprover::MainnetPasskey {
        credential_id_b64url: presence.credential_id_b64url(),
    };
    let receipt = presence.into_parts().receipt;
    assert!(matches!(
        store.record_mainnet_attestation_at(
            &entry.approval_nonce,
            [9; 32],
            approver,
            receipt,
            None,
            now + 60_000
        ),
        Err(ApprovalError::Expired)
    ));
    drop(store);
    let store = PendingApprovalStore::open(path).unwrap();
    let loaded = attest::load_and_validate_entry(&store, &entry.approval_nonce, &identity, &[]);
    assert!(
        loaded.is_err(),
        "attestation load refuses recorded expiry despite earlier clock"
    );
    assert_eq!(loaded.unwrap_err().code(), "approval.expired");
    let checked = attest::refuse_unless_still_pending(&store, &entry, now);
    assert!(
        checked.is_err(),
        "final pending recheck refuses recorded expiry despite earlier clock"
    );
    assert_eq!(checked.unwrap_err().code(), "approval.expired");
}

#[test]
#[serial_test::serial]
fn payment_recovery_schema_refuses_ambiguous_or_missing_facts() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let path = fixture.store_path();
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    queue(&mut store, &policy, START).unwrap();
    drop(store);
    let original = std::fs::read_to_string(&path).unwrap();
    for case in [0, 1, 2, 6, 7, 8, 9] {
        let mut file: toml::Value = toml::from_str(&original).unwrap();
        match case {
            0 => {
                let duplicate = file["payment_recovery"][0].clone();
                file["payment_recovery"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            1 => {
                file["payment_recovery"][0]
                    .as_table_mut()
                    .unwrap()
                    .remove("expires");
            }
            2 => file["payment_recovery"][0]["nonce"] = "bad".into(),
            6 => {
                file["payment_recovery"][0]["key"]["operation"] = toml::Value::Array(vec![0.into()])
            }
            7 => file["payment_recovery"][0]["retain_until"] = (START as i64).into(),
            8 => {
                let mut duplicate = file["payment_recovery"][0].clone();
                duplicate["nonce"] = "B".repeat(22).into();
                file["payment_recovery"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
                let mut payload = file["pending"][0].clone();
                payload["approval_nonce"] = "B".repeat(22).into();
                file["pending"].as_array_mut().unwrap().push(payload);
            }
            9 => {
                let mut duplicate = file["payment_recovery"][0].clone();
                duplicate["key"]["profile"] = "another".into();
                file["payment_recovery"]
                    .as_array_mut()
                    .unwrap()
                    .push(duplicate);
            }
            _ => unreachable!(),
        }
        std::fs::write(&path, toml::to_string(&file).unwrap()).unwrap();
        assert!(
            matches!(
                PendingApprovalStore::open(path.clone()),
                Err(ApprovalError::InvalidEntry { .. })
            ),
            "schema case {case}"
        );
    }
}

/// A binding whose created, expires, or subject link to its payload fails,
/// or whose active payload is missing, opens with the store. Only its own
/// payment refuses; listing, rejection, collection, and other approvals work.
#[test]
#[serial_test::serial]
fn payment_recovery_link_failure_refuses_only_its_payment() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let path = fixture.store_path();
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let first = queue(&mut store, &policy, START).unwrap();
    drop(store);
    let original = std::fs::read_to_string(&path).unwrap();
    for case in ["created", "expires", "subject", "missing payload"] {
        let mut file: toml::Value = toml::from_str(&original).unwrap();
        match case {
            "created" => file["payment_recovery"][0]["created"] = (START as i64 + 1).into(),
            "expires" => file["payment_recovery"][0]["expires"] = (END as i64 + 1).into(),
            "subject" => file["payment_recovery"][0]["key"]["subject"][0] = 44.into(),
            "missing payload" => file["pending"].as_array_mut().unwrap().clear(),
            _ => unreachable!(),
        }
        std::fs::write(&path, toml::to_string(&file).unwrap()).unwrap();
        let mut store = PendingApprovalStore::open(path.clone())
            .unwrap_or_else(|e| panic!("{case}: the store opens despite one broken link: {e}"));
        assert!(
            matches!(
                store.check_payment_recovery(&first.approval_nonce),
                Err(ApprovalError::RecoveryInconsistent)
            ),
            "{case}: use refuses"
        );
        if case != "subject" {
            assert!(
                matches!(
                    queue(&mut store, &policy, START),
                    Err(ApprovalError::RecoveryInconsistent)
                ),
                "{case}: retry refuses"
            );
        }
        let listed = store.snapshot(START).len();
        assert_eq!(listed, store.len(), "{case}: list");
        const UNRELATED: &str = "unrelated0000000000000";
        let mut unrelated = first.clone();
        unrelated.approval_nonce = UNRELATED.to_owned();
        store.insert(unrelated, START).unwrap();
        store.check_payment_recovery(UNRELATED).unwrap();
        if case != "missing payload" {
            store.reject(&first.approval_nonce, START + 1, 300).unwrap();
        }
        store.gc_expired(START + 2).unwrap();
        drop(store);
        let store = PendingApprovalStore::open(path.clone())
            .unwrap_or_else(|e| panic!("{case}: the store reopens after its writers: {e}"));
        assert!(
            store.get(UNRELATED).is_some(),
            "{case}: other approvals persist"
        );
    }
}

/// The clock-aware check persists an observed expiry before it refuses, keeps
/// recorded terminal states under an earlier clock, refuses a broken link
/// before any write, and passes unindexed entries unchanged.
#[test]
#[serial_test::serial]
fn payment_recovery_check_at_persists_expiry_and_keeps_terminal_state() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    for case in ["expired", "rejected", "broken link"] {
        let path = fixture.home().join(format!("check-at-{case}.toml"));
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let first = queue(&mut store, &policy, START).unwrap();
        let live = std::fs::read(&path).unwrap();
        store
            .check_payment_recovery_at(&first.approval_nonce, END - 1)
            .unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            live,
            "a live check writes nothing"
        );
        match case {
            "expired" => assert!(matches!(
                store.check_payment_recovery_at(&first.approval_nonce, END),
                Err(ApprovalError::Expired)
            )),
            "rejected" => {
                store.reject(&first.approval_nonce, START + 1, 300).unwrap();
            }
            "broken link" => {
                let mut file: toml::Value =
                    toml::from_str(&String::from_utf8(live).unwrap()).unwrap();
                file["payment_recovery"][0]["created"] = (START as i64 + 1).into();
                std::fs::write(&path, toml::to_string(&file).unwrap()).unwrap();
            }
            _ => unreachable!(),
        }
        drop(store);
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let stored = std::fs::read(&path).unwrap();
        for now in [START, END] {
            let error = store
                .check_payment_recovery_at(&first.approval_nonce, now)
                .unwrap_err();
            assert!(
                match case {
                    "expired" => matches!(error, ApprovalError::Expired),
                    "rejected" => matches!(error, ApprovalError::Rejected),
                    _ => matches!(error, ApprovalError::RecoveryInconsistent),
                },
                "{case} at {now}: {error:?}"
            );
        }
        if case == "expired" {
            assert!(
                matches!(
                    store.check_payment_recovery(&first.approval_nonce),
                    Err(ApprovalError::Expired)
                ),
                "the observed expiry persists"
            );
        }
        if case == "broken link" {
            assert_eq!(
                std::fs::read(&path).unwrap(),
                stored,
                "a broken link refuses before any write"
            );
        }
        const UNRELATED: &str = "unrelated0000000000000";
        let mut unrelated = first.clone();
        unrelated.approval_nonce = UNRELATED.to_owned();
        store.insert(unrelated, START).unwrap();
        store.check_payment_recovery_at(UNRELATED, END + 1).unwrap();
    }
}

/// A queue call with an explicit chain, operation, and interval.
fn queue_with(
    store: &mut PendingApprovalStore,
    policy: &VerifiedPolicy,
    chain: Caip2,
    operation: Option<([u8; 16], u64)>,
    (created, expires, now): (u64, u64, u64),
) -> Result<PendingApproval, ApprovalError> {
    store.recover_payment(
        PaymentRecoveryContext {
            profile: "recovery",
            chain,
            policy,
            operation,
        },
        &envelope(),
        "1000".to_owned(),
        created,
        expires,
        now,
        &ApprovalRequest::new("review".to_owned(), 600),
    )
}

/// An off-mainnet binding is retained only for its approval interval: a
/// retry after that end, with no other store traffic, receives fresh consent,
/// and the same write drops the old binding and its expired payload.
#[test]
#[serial_test::serial]
fn payment_recovery_off_mainnet_retry_after_retention_gets_fresh_consent() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let path = fixture.store_path();
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let first = queue_with(
        &mut store,
        &policy,
        Caip2::Testnet,
        None,
        (START, END, START),
    )
    .unwrap();
    drop(store);
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let retry = queue_with(
        &mut store,
        &policy,
        Caip2::Testnet,
        None,
        (END, END + 1_001, END),
    );
    let fresh = retry.expect("retry after retention end gets fresh consent");
    assert_ne!(fresh.approval_nonce, first.approval_nonce);
    drop(store);
    let store = PendingApprovalStore::open(path).unwrap();
    assert!(
        store.get(&first.approval_nonce).is_none(),
        "expired payload"
    );
    assert_eq!(store.len(), 1);
    assert_eq!(store.payment_recovery.len(), 1);
    assert_eq!(store.payment_recovery[0].nonce, fresh.approval_nonce);
}

/// A rejected off-mainnet binding whose tombstone outlives its retention meets
/// a retry at the retention end. A full store refuses the retry without a write,
/// so the old binding stays; with one free slot, a process exit after the
/// durable write leaves the fresh consent. Neither case leaves zero bindings.
#[test]
#[serial_test::serial]
fn payment_recovery_capacity_refusal_keeps_old_binding_or_fresh_consent() {
    use super::super::persist_test_seam::{self, Step};
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    if let Ok(path) = std::env::var("PAYMENT_RECOVERY_CAPACITY_PATH") {
        let path = std::path::PathBuf::from(path);
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        persist_test_seam::on_step(&path, Step::DirectorySynced, || std::process::exit(81));
        let retry = queue_with(
            &mut store,
            &policy,
            Caip2::Testnet,
            None,
            (END, END + 1_001, END),
        );
        assert!(
            matches!(retry, Err(ApprovalError::PendingStoreFull { .. })),
            "a retry that writes exits at the durable write: {retry:?}"
        );
        std::process::exit(82);
    }
    for (case, free) in [("full", 0), ("one free slot", 1)] {
        let path = fixture.home().join(format!("capacity-{free}.toml"));
        let mut store = PendingApprovalStore::open(path.clone()).unwrap();
        let first = queue_with(
            &mut store,
            &policy,
            Caip2::Testnet,
            None,
            (START, END, START),
        )
        .unwrap();
        store
            .reject(&first.approval_nonce, START + 1, RETAIN - START)
            .unwrap();
        while store.entries.len() < super::super::MAX_PENDING_APPROVALS - free {
            let mut entry = first.clone();
            entry.approval_nonce = format!("capacity{:014}", store.entries.len());
            entry.expires_at_unix_ms = RETAIN;
            store.entries.push(entry);
        }
        store.persist().unwrap();
        drop(store);
        let before = std::fs::read(&path).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("approval::store::recovery::tests::payment_recovery_capacity_refusal_keeps_old_binding_or_fresh_consent")
            .env("PAYMENT_RECOVERY_CAPACITY_PATH", &path)
            .output()
            .unwrap();
        let code = child.status.code();
        assert!(
            matches!(code, Some(81 | 82)),
            "{case}: child reaches the durable write or the refusal: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        let store = PendingApprovalStore::open(path.clone()).unwrap();
        assert_eq!(
            store.payment_recovery.len(),
            1,
            "{case}: the old binding or the fresh consent survives; child exit {code:?}"
        );
        let survivor = &store.payment_recovery[0].nonce;
        if free == 0 {
            assert_eq!(code, Some(82), "{case}: the refusal writes nothing");
            assert_eq!(survivor, &first.approval_nonce, "{case}: old binding");
            assert_eq!(std::fs::read(&path).unwrap(), before, "{case}: file bytes");
        } else {
            assert_eq!(
                code,
                Some(81),
                "{case}: the retry reaches the durable write"
            );
            assert_ne!(survivor, &first.approval_nonce, "{case}: fresh binding");
            assert!(store.get(survivor).is_some(), "{case}: fresh payload");
        }
    }
}

/// An active binding refuses a retry whose clock precedes the binding's
/// creation, and a retry whose own captured end has passed.
#[test]
#[serial_test::serial]
fn payment_recovery_retry_interval_refuses_on_reuse() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let operation = Some(([7; 16], RETAIN));
    queue_with(
        &mut store,
        &policy,
        Caip2::Mainnet,
        operation,
        (START, END, START),
    )
    .unwrap();
    let before = START - 1;
    assert!(
        matches!(
            queue_with(
                &mut store,
                &policy,
                Caip2::Mainnet,
                operation,
                (before, before + 1_001, before)
            ),
            Err(ApprovalError::Expired)
        ),
        "a clock before the binding's creation"
    );
    assert!(
        matches!(
            queue_with(
                &mut store,
                &policy,
                Caip2::Mainnet,
                operation,
                (START, START + 100, START + 100)
            ),
            Err(ApprovalError::Expired)
        ),
        "the retry's own end has passed"
    );
    assert_eq!(store.payment_recovery.len(), 1);
    assert_eq!(store.len(), 1);
}

/// Collecting a rejected payload keeps the binding's rejection: a retry and
/// the read-only check still answer `Rejected`.
#[test]
#[serial_test::serial]
fn payment_recovery_remove_after_reject_keeps_rejection() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let path = fixture.store_path();
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let first = queue(&mut store, &policy, START).unwrap();
    store.reject(&first.approval_nonce, START + 1, 300).unwrap();
    assert!(store.remove(&first.approval_nonce).unwrap());
    drop(store);
    let mut store = PendingApprovalStore::open(path).unwrap();
    assert!(store.get(&first.approval_nonce).is_none());
    assert!(
        matches!(
            queue(&mut store, &policy, START + 2),
            Err(ApprovalError::Rejected)
        ),
        "removal keeps the terminal rejection"
    );
    assert!(matches!(
        store.check_payment_recovery(&first.approval_nonce),
        Err(ApprovalError::Rejected)
    ));
}

#[test]
#[serial_test::serial]
fn payment_recovery_survives_unrelated_inbox_writers() {
    use super::super::{AssertionInput, RegistrationInput};
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let legacy_path = fixture.home().join("legacy.toml");
    std::fs::write(
        &legacy_path,
        include_str!("../../inbox_vectors/base_inbox.toml"),
    )
    .unwrap();
    let legacy = PendingApprovalStore::open(legacy_path).unwrap();
    assert_eq!(legacy.len(), 40, "literal pre-change kinds remain readable");
    assert!(
        legacy.payment_recovery.is_empty(),
        "legacy entries gain no guessed binding"
    );
    let entries: Vec<_> = [34, 35, 24, 30]
        .into_iter()
        .map(|index| {
            legacy
                .get(&format!("baseinboxnonce{index:08}"))
                .unwrap()
                .clone()
        })
        .collect();
    drop(legacy);
    let now = crate::timefmt::now_unix_ms().unwrap();
    let path = fixture.home().join("mixed.toml");
    let mut store = PendingApprovalStore::open(path.clone()).unwrap();
    let original = store
        .recover_payment(
            PaymentRecoveryContext {
                profile: "recovery",
                chain: Caip2::Mainnet,
                policy: &policy,
                operation: Some(([7; 16], now + 120_000)),
            },
            &envelope(),
            "1000".to_owned(),
            now,
            now + 60_000,
            now,
            &ApprovalRequest::new("review".to_owned(), 60),
        )
        .unwrap();
    let binding = serde_json::to_value(&store.payment_recovery).unwrap();
    for (writer, mut entry) in entries.into_iter().enumerate() {
        entry.created_at_unix_ms = now;
        entry.expires_at_unix_ms = now + 120_000;
        let nonce = entry.approval_nonce.clone();
        store.insert(entry, now).unwrap();
        match writer {
            0 => store
                .record_passkey_assertion(
                    &nonce,
                    AssertionInput {
                        credential_id: vec![0xAB; 32],
                        authenticator_data: vec![0xCD; 37],
                        client_data_json: vec![0xEF; 50],
                        signature_compact: vec![0x30; 64],
                    },
                )
                .unwrap(),
            1 => {
                let mut public_key = vec![0; 65];
                public_key[0] = 4;
                let input = RegistrationInput::new(
                    vec![0xAB; 32],
                    public_key,
                    None,
                    vec!["internal".to_owned()],
                )
                .unwrap();
                store.record_passkey_registration(&nonce, input).unwrap();
            }
            2 => store
                .record_trustline_clawback_opt_in_attestation(
                    &nonce,
                    [9; 32],
                    AttestedApprover::Local,
                )
                .unwrap(),
            3 => store
                .record_rule_proposal_attestation(&nonce, [9; 32], AttestedApprover::Local)
                .unwrap(),
            _ => unreachable!(),
        }
        drop(store);
        store = PendingApprovalStore::open(path.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&store.payment_recovery).unwrap(),
            binding,
            "writer {writer}: unrelated writer keeps recovery binding"
        );
        assert_eq!(
            serde_json::to_value(store.get(&original.approval_nonce).unwrap()).unwrap(),
            serde_json::to_value(&original).unwrap(),
            "writer {writer}: original payment consent stays unchanged"
        );
    }
}

/// A built payment entry binds with its own nonce and signed interval, so
/// the recovery path later reuses exactly that entry. A second entry for the
/// same key refuses while the first binding is retained, and nothing changes.
#[test]
#[serial_test::serial]
fn payment_binding_of_a_built_entry_keeps_one_entry_per_key() {
    let fixture = MainnetConsentFixture::new("recovery");
    let policy = fixture.current_policy();
    let mut store = PendingApprovalStore::open(fixture.store_path()).unwrap();
    let context = PaymentRecoveryContext {
        profile: "recovery",
        chain: Caip2::Mainnet,
        policy: &policy,
        operation: Some(([7; 16], RETAIN)),
    };
    let built = || {
        PendingApproval::new_payment_pending_until(
            envelope(),
            "1000".to_owned(),
            START,
            END,
            START,
            Some("review".to_owned()),
        )
        .unwrap()
    };
    let entry = built();
    let elapsed = store.bind_payment(context, entry.clone(), END);
    assert!(
        matches!(elapsed, Err(ApprovalError::Expired)),
        "an entry whose signed interval has ended refuses, as recovery does: {elapsed:?}"
    );
    assert!(store.payment_recovery.is_empty() && store.snapshot(START).is_empty());
    let bound = store.bind_payment(context, entry.clone(), START).unwrap();
    assert_eq!(bound.approval_nonce, entry.approval_nonce);
    store.check_payment_recovery(&entry.approval_nonce).unwrap();
    let reused = queue(&mut store, &policy, START).unwrap();
    assert_eq!(
        reused.approval_nonce, entry.approval_nonce,
        "recovery reuses the bound entry"
    );
    let before = serde_json::to_value(&store.payment_recovery).unwrap();
    let refused = store.bind_payment(context, built(), START + 1);
    assert!(
        matches!(refused, Err(ApprovalError::RecoveryInconsistent)),
        "a retained binding refuses a second entry: {refused:?}"
    );
    assert_eq!(
        serde_json::to_value(&store.payment_recovery).unwrap(),
        before
    );
    assert_eq!(store.snapshot(START + 1).len(), 1);
}
