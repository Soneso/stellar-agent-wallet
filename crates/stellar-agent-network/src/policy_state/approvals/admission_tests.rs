#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::Arc;

use serial_test::serial;
use stellar_agent_core::approval::{
    ConsentAudit, ConsentAuthorization, PendingApprovalStore, Surface,
    attest::attest_and_persist_with_row, mainnet_fixtures::ATTESTATION_KEY,
};
use stellar_agent_core::audit_log::{
    AuditEntry, AuditWriter, KeyedAuditAccess, MAX_EVIDENCE_ENTRIES,
    test_helpers::seed_reserved_evidence, tip_anchor::InMemoryTipAnchorStore,
};
use zeroize::Zeroizing;

use super::super::store::commit_faults::{
    COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
};
use super::tests::{Fx, Rows};
use super::*;
use crate::mainnet::clock::set_now_ms_for_test;
use crate::operation_entry::{
    ConsentAdmission, commit_consent, consent_completion, operation_refusal, publication_completion,
};

const KEY: [u8; 32] = [42; 32];

/// A keyed audit log of the fixture home, its writer and its outbox.
struct Evidence {
    path: PathBuf,
    anchors: Arc<InMemoryTipAnchorStore>,
    writer: AuditWriter,
    outbox: AuditOutbox,
}

fn evidence(fx: &Fx, file: &str) -> Evidence {
    let path = fx.fixture.home().join(file);
    let anchors = Arc::new(InMemoryTipAnchorStore::new());
    let writer = AuditWriter::open(
        path.clone(),
        Some(KeyedAuditAccess::new(Zeroizing::new(KEY), anchors.clone())),
    )
    .unwrap();
    let outbox = AuditOutbox::for_log_keyed(&path, anchors.clone(), Zeroizing::new(KEY));
    Evidence {
        path,
        anchors,
        writer,
        outbox,
    }
}

/// The conservative deadline of the fixture record.
fn deadline(fx: &Fx) -> u64 {
    fx.facts.waiting_expires_at_ms + fx.facts.rule_ttl_ms.min(APPROVAL_EXECUTION_MAX_MS)
}

/// Admits `facts` for the fixture operation, opening through a recorder of
/// its own.
fn admit<T>(
    fx: &Fx,
    evidence: &mut Evidence,
    facts: &PendingApprovalFacts,
    present: impl FnOnce(&WireApproval, &EvidenceReservation) -> Result<T, WalletError>,
) -> Result<T, WalletError> {
    let mut rows = Rows::default();
    let operation = fx.operation;
    ConsentAdmission {
        store: &fx.store,
        profile: fx.fixture.profile(),
        writer: &mut evidence.writer,
        outbox: &evidence.outbox,
    }
    .admit(
        operation,
        facts,
        |_, facts| {
            ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut rows, "open")
                .open_pending(operation, facts, PolicyDecision::RequireApproval)
                .map_err(operation_refusal)
        },
        present,
    )
}

/// Reacquires the exact authenticated deadline and rejects another deadline.
fn retained(fx: &Fx, evidence: &Evidence) -> bool {
    evidence
        .outbox
        .reserve_evidence(fx.id(), deadline(fx), fx.witness.consent_at_ms())
        .is_ok()
        && evidence
            .outbox
            .reserve_evidence(fx.id(), deadline(fx) + 1, fx.witness.consent_at_ms())
            .is_err()
}

type FailedCommitHook = (PathBuf, Box<dyn FnOnce()>);
thread_local! {
    static FAILED_COMMIT: std::cell::RefCell<Option<FailedCommitHook>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn after_failed_commit(path: &std::path::Path) {
    let hook = FAILED_COMMIT.with_borrow_mut(|hook| {
        if hook.as_ref().is_some_and(|(expected, _)| expected == path) {
            hook.take()
        } else {
            None
        }
    });
    if let Some((_, call)) = hook {
        call();
    }
}

struct FailedCommitGuard;
impl Drop for FailedCommitGuard {
    fn drop(&mut self) {
        FAILED_COMMIT.with_borrow_mut(|hook| *hook = None);
    }
}

#[test]
#[serial]
fn failed_publication_reread_requires_complete_match() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new(300_000);
    fx.open();
    let profile = fx.fixture.profile().clone();
    let path = fx.store.path().to_owned();
    let first = PendingApprovalStore::open(fx.fixture.home().join("first.toml")).unwrap();
    let witness = consent_completion(
        &first,
        &fx.store,
        fx.fixture.profile(),
        fx.fixture.name(),
        &fx.facts.nonce,
        &fx.fixture.current_policy(),
        ConsentRow::Written,
        &fx.fixture.authority().admit().unwrap(),
    )
    .unwrap()
    .into_witness();
    drop(first);
    let payload = fx.payload.clone();
    let id = fx.id();
    FAILED_COMMIT.with_borrow_mut(|hook| {
        *hook = Some((
            path.clone(),
            Box::new(move || {
                let window = PersistedWindowStore::at_path(path);
                let mut rows = Rows::default();
                ApprovalRecorder::new(&window, &profile, &mut rows, "competitor")
                    .record_consent(id, &witness, &payload)
                    .unwrap();
            }),
        ))
    });
    let _hook = FailedCommitGuard;
    let _fault = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
    let result =
        ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "publication")
            .record_consent_with_delivery(
                id,
                &fx.witness,
                &fx.payload,
                ConsentDeliveryV1::direct_anchored(id),
            );
    assert!(
        result.is_err(),
        "a same-receipt legacy competitor is not the attempted publication"
    );
    assert!(matches!(
        result.unwrap_err(),
        WindowStoreError::Io {
            kind: std::io::ErrorKind::Interrupted
        }
    ));
    let committed = fx.view().record.consent.unwrap();
    assert_eq!(
        committed.receipt_sha256,
        fx.witness.presence_receipt_digest()
    );
    assert_eq!(committed.delivery, None);
}

#[test]
#[serial]
fn admission_retains_the_exact_execution_allowance() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for ttl in [300_000, 3_600_000] {
        let fx = Fx::new(ttl);
        let mut evidence = evidence(&fx, "deadline.log");
        admit(&fx, &mut evidence, &fx.facts, |_, _| Ok(())).unwrap();
        assert!(
            evidence
                .outbox
                .reserve_evidence(fx.id(), deadline(&fx), fx.witness.consent_at_ms())
                .is_ok(),
            "the exact authenticated conservative deadline must reacquire"
        );
        let others: Vec<_> = (0..MAX_EVIDENCE_ENTRIES - 1)
            .map(|i| {
                let mut id = [0xee; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                id
            })
            .collect();
        seed_reserved_evidence(
            &evidence.path,
            evidence.anchors.as_ref(),
            &KEY,
            &others,
            u64::MAX,
        )
        .unwrap();
        for at in [
            fx.facts.waiting_expires_at_ms,
            fx.facts.waiting_expires_at_ms + 1,
            deadline(&fx) - 1,
        ] {
            evidence.outbox.advance_evidence_floor(at).unwrap();
            assert_eq!(
                evidence
                    .outbox
                    .reserve_evidence([0xaa; 32], u64::MAX, at)
                    .unwrap_err()
                    .code(),
                "approval.evidence_capacity",
                "the slot survives the waiting window"
            );
            assert!(
                evidence
                    .outbox
                    .reserve_evidence(fx.id(), deadline(&fx), 0)
                    .is_ok(),
                "a reversed clock keeps the conservative slot"
            );
        }
        evidence
            .outbox
            .advance_evidence_floor(deadline(&fx))
            .unwrap();
        assert!(
            evidence
                .outbox
                .reserve_evidence([0xaa; 32], u64::MAX, 0)
                .is_ok(),
            "the exclusive deadline frees the slot"
        );
        assert!(
            evidence
                .outbox
                .reserve_evidence(fx.id(), deadline(&fx), 0)
                .is_err(),
            "expired evidence cannot return"
        );
    }
}

#[test]
#[serial]
fn publication_survives_compaction_failure() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for queued in [false, true] {
        let mut fx = Fx::new(300_000);
        fx.open();
        let mut evidence = evidence(&fx, "compaction.log");
        let (inbox, reference) = strict_inbox(&fx, &mut evidence, "strict.toml", queued);
        let before = std::fs::read(&evidence.path).unwrap();
        let fault =
            super::super::store::arm_accounting_fault(super::super::store::COMMIT_FAULT_COMPACTION);
        let published = publish(&fx, &inbox).unwrap();
        drop(fault);
        let bytes = fx.bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("\"prepared\""));
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        let selected = ApprovalStatus::new(&reopened, fx.fixture.profile())
            .view(fx.id())
            .unwrap()
            .unwrap();
        assert_eq!(
            selected, published,
            "the counter selects the exact committed publication"
        );
        assert_eq!(
            selected.record.consent.unwrap().payload.unwrap().outbox_row,
            reference
        );
        assert_eq!(
            std::fs::read(&evidence.path).unwrap(),
            before,
            "recovery appends no row"
        );
    }
}

#[test]
#[serial]
fn publication_has_capacity_headroom() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for queued in [false, true] {
        let mut fx = Fx::new(300_000);
        fx.open();
        let mut evidence = evidence(&fx, "headroom.log");
        let (inbox, reference) = strict_inbox(&fx, &mut evidence, "strict.toml", queued);
        let others: Vec<_> = (0..MAX_EVIDENCE_ENTRIES - 1)
            .map(|i| {
                let mut id = [0xee; 32];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                id
            })
            .collect();
        seed_reserved_evidence(
            &evidence.path,
            evidence.anchors.as_ref(),
            &KEY,
            &others,
            u64::MAX,
        )
        .unwrap();
        let now = fx.witness.consent_at_ms();
        let chain = fx.fixture.profile().chain_id;
        fx.edit(|wire| {
            use super::super::store::{WireBucket, WireRecord};
            wire.entries.push(WireBucket {
                scope_specificity: 0,
                bucket: String::new(),
                window_secs: 60,
                records: vec![WireRecord {
                    ts_ms: now,
                    amount: 1,
                    chain_scope: Some(super::super::ChainScope::for_chain(chain)),
                    ..WireRecord::confirmed_defaults()
                }],
            });
            let padding = FILE_THRESHOLD - serialized_len(wire);
            wire.entries.last_mut().unwrap().bucket = "p".repeat(padding);
        });
        let retained_accounting = serde_json::to_value(&fx.wire().entries).unwrap();
        assert!(serialized_len(&fx.wire()) >= FILE_THRESHOLD);
        assert!(
            ConsentAdmission::reacquire(
                &fx.store,
                fx.fixture.profile(),
                fx.operation,
                &fx.facts,
                &evidence.outbox
            )
            .is_ok(),
            "existing admission succeeds at capacity"
        );
        let retained = evidence.outbox.evidence().unwrap();
        let published = publish(&fx, &inbox).unwrap();
        assert_eq!(
            serde_json::to_value(&fx.wire().entries).unwrap(),
            retained_accounting,
            "completion at the admission threshold retains accounting"
        );
        assert_eq!(
            published
                .record
                .consent
                .unwrap()
                .payload
                .unwrap()
                .outbox_row,
            reference
        );
        assert_eq!(
            evidence
                .outbox
                .reserve_evidence([0xaa; 32], u64::MAX, 0)
                .unwrap_err()
                .code(),
            "approval.evidence_capacity"
        );
        assert_eq!(
            evidence.outbox.evidence().unwrap(),
            retained,
            "completion preserves every other slot"
        );
    }
}

#[test]
#[serial]
fn routed_admission_refuses_pins_and_orphans() {
    use stellar_agent_core::audit_log::TipAnchorStore;
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for mode in ["pin", "v1", "missing"] {
        let mut fx = Fx::new(300_000);
        fx.open();
        let mut evidence = evidence(&fx, "unready.log");
        evidence
            .outbox
            .append_queued(&AuditEntry::new_approval_attested(
                "PaymentSimulated",
                "stellar_pay_commit",
                None,
                "legacy",
                "cli",
                "legacy",
            ))
            .unwrap();
        evidence.writer.drain_outbox().unwrap();
        let v1 = evidence
            .anchors
            .load_outbox_owner_state(1)
            .unwrap()
            .unwrap();
        evidence.writer.initialize_consent_evidence().unwrap();
        assert!(
            evidence
                .writer
                .outbox_evidence()
                .unwrap()
                .unwrap()
                .holds_migration_pins()
        );
        if mode == "v1" {
            evidence.anchors.store_outbox_owner_state(1, &v1).unwrap();
        }
        if mode == "missing" {
            let missing = Arc::new(InMemoryTipAnchorStore::new());
            missing
                .store_carrier_record(&evidence.anchors.load_carrier_record().unwrap().unwrap())
                .unwrap();
            evidence.anchors = missing;
            evidence.outbox = AuditOutbox::for_log_keyed(
                &evidence.path,
                evidence.anchors.clone(),
                Zeroizing::new(KEY),
            );
        }
        let slots = || {
            [".evidence.0", ".evidence.1"].map(|suffix| {
                let mut path = evidence.outbox.path().as_os_str().to_owned();
                path.push(suffix);
                std::fs::read(PathBuf::from(path)).unwrap()
            })
        };
        let before = slots();
        let owner = evidence.anchors.load_outbox_owner_state(1).unwrap();
        let error = ConsentAdmission::reacquire(
            &fx.store,
            fx.fixture.profile(),
            fx.operation,
            &fx.facts,
            &evidence.outbox,
        )
        .unwrap_err();
        assert_eq!(
            error.code(),
            "audit.outbox_evidence_unusable",
            "{mode} admission refuses"
        );
        assert_eq!(slots(), before, "a refusal preserves selected image bytes");
        assert_eq!(evidence.anchors.load_outbox_owner_state(1).unwrap(), owner);
        assert!(fx.view().record.consent.is_none());
    }
}

/// A queued append under `reservation`, standing in for a request that
/// presents a queued sink.
fn queued_row(outbox: &AuditOutbox, reservation: &EvidenceReservation) -> OutboxRowRef {
    outbox
        .clone()
        .with_evidence_reservation(reservation.clone())
        .append_queued(&AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            "admitted",
            "cli",
            "admitted",
        ))
        .unwrap()
}

/// Admission refuses while the owner scope is unproven, before it opens a
/// record, initializes evidence or presents anything. A fresh scope is
/// ready from stored state: admission initializes the owner before the
/// first reservation, and a second admission reuses both.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn producer_admission_requires_scope_readiness() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for queued in [false, true] {
        let fx = Fx::new(300_000);
        let mut evidence = evidence(&fx, "admission.log");
        let outbox = evidence.outbox.clone();
        let presented = Cell::new(0);
        let present = |_: &WireApproval, reservation: &EvidenceReservation| {
            presented.set(presented.get() + 1);
            Ok(queued.then(|| queued_row(&outbox, reservation)))
        };
        let unreadable = UnreadableSiblingProfile::plant();
        let refused = admit(&fx, &mut evidence, &fx.facts.clone(), present).unwrap_err();
        assert_eq!(refused.code(), "audit.outbox_evidence_unusable");
        assert!(
            refused
                .to_string()
                .contains("owner scope shared or unreadable")
        );
        assert_eq!(presented.get(), 0);
        assert_eq!(evidence.writer.outbox_evidence().unwrap(), None);
        let status = ApprovalStatus::new(&fx.store, fx.fixture.profile());
        assert_eq!(status.find_by_operation(fx.operation).unwrap(), None);

        drop(unreadable);
        for attempt in 1..=2 {
            let presented = Cell::new(0);
            let reference = admit(
                &fx,
                &mut evidence,
                &fx.facts.clone(),
                |record, reservation| {
                    assert_eq!(record.nonce, fx.facts.nonce);
                    presented.set(presented.get() + 1);
                    Ok((queued && attempt == 1).then(|| queued_row(&outbox, reservation)))
                },
            )
            .unwrap();
            assert_eq!(presented.get(), 1, "attempt {attempt}");
            assert_eq!(reference.is_some(), queued && attempt == 1);
            assert!(retained(&fx, &evidence));
        }
        assert!(evidence.writer.outbox_evidence().unwrap().is_some());
    }
}

/// Reservation follows the committed open and precedes presentation. A
/// full owner scope refuses with `approval.evidence_capacity` before the
/// request is presented, for either sink, and keeps the pending record.
/// The same facts reuse one slot; any other fact, an expired deadline and
/// an absent record refuse. Presentation runs outside the window lock.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn reserve_before_request_and_without_window_lock() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let others: Vec<[u8; 32]> = (0..u32::try_from(MAX_EVIDENCE_ENTRIES).unwrap())
        .map(|index: u32| {
            let mut identity = [0xee; 32];
            identity[..4].copy_from_slice(&index.to_be_bytes());
            identity
        })
        .collect();
    for queued in [false, true] {
        let fx = Fx::new(300_000);
        let mut evidence = evidence(&fx, "capacity.log");
        evidence.writer.initialize_consent_evidence().unwrap();
        seed_reserved_evidence(
            &evidence.path,
            evidence.anchors.as_ref(),
            &KEY,
            &others,
            u64::MAX,
        )
        .unwrap();
        let presented = Cell::new(0);
        let outbox = evidence.outbox.clone();
        let refused = admit(&fx, &mut evidence, &fx.facts.clone(), |_, reservation| {
            presented.set(presented.get() + 1);
            Ok(queued.then(|| queued_row(&outbox, reservation)))
        })
        .unwrap_err();
        assert_eq!(
            refused.code(),
            "approval.evidence_capacity",
            "queued {queued}"
        );
        assert_eq!(presented.get(), 0);
        let view = ApprovalStatus::new(&fx.store, fx.fixture.profile())
            .find_by_operation(fx.operation)
            .unwrap()
            .unwrap();
        assert_eq!(view.record.facts(), fx.facts);
    }

    let fx = Fx::new(300_000);
    let mut evidence = evidence(&fx, "one-slot.log");
    evidence.writer.initialize_consent_evidence().unwrap();
    seed_reserved_evidence(
        &evidence.path,
        evidence.anchors.as_ref(),
        &KEY,
        &others[..MAX_EVIDENCE_ENTRIES - 1],
        u64::MAX,
    )
    .unwrap();
    let profile = fx.fixture.profile();
    let window = || {
        WindowStoreLock::acquire_for(fx.store.path(), &profile.policy_window_state_key_id).is_ok()
    };
    for _ in 0..2 {
        assert!(admit(&fx, &mut evidence, &fx.facts.clone(), |_, _| Ok(window())).unwrap());
    }
    assert!(retained(&fx, &evidence));

    let mut rows = Rows::default();
    let mut recorder = ApprovalRecorder::new(&fx.store, profile, &mut rows, "reserve");
    let mut changed: Vec<(&str, OperationId, PendingApprovalFacts)> = Vec::new();
    let mut change = |name, edit: &dyn Fn(&mut PendingApprovalFacts)| {
        let mut facts = fx.facts.clone();
        edit(&mut facts);
        changed.push((name, fx.operation, facts));
    };
    change("nonce", &|f| f.nonce.push('x'));
    change("kind", &|f| f.kind = ApprovedKind::Claim);
    change("convention", &|f| {
        f.subject_kind = SubjectKind::IntentDigest
    });
    change("subject", &|f| f.subject[0] ^= 1);
    change("intent", &|f| f.intent_digest[0] ^= 1);
    change("clocks", &|f| {
        f.created_at_ms -= 1_000;
        f.waiting_expires_at_ms -= 1_000;
    });
    change("ttl", &|f| {
        f.rule_ttl_ms += 1_000;
        f.waiting_expires_at_ms += 1_000;
    });
    let mut operation = *fx.operation.as_bytes();
    operation[0] ^= 1;
    changed.push((
        "operation",
        OperationId::from_bytes(operation),
        fx.facts.clone(),
    ));
    for (name, operation, facts) in changed {
        assert_eq!(
            recorder
                .reserve_consent_evidence(operation, &facts, &evidence.outbox)
                .unwrap_err()
                .code(),
            "internal.unexpected_state",
            "{name}"
        );
    }
    let _later = set_now_ms_for_test(deadline(&fx));
    assert_eq!(
        recorder
            .reserve_consent_evidence(fx.operation, &fx.facts, &evidence.outbox)
            .unwrap_err()
            .code(),
        "audit.outbox_evidence_unusable"
    );
}

/// A retry keeps the committed identity: its stored nonce, signed clocks,
/// subject and lifetime govern, never the retry's own facts. A competing
/// open commits the winner, which admission then reserves. A refused
/// presentation, such as lost inbox material, keeps the record and slot.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn producer_linkage_and_retry_are_fact_bound() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fx::new(300_000);
    let mut evidence = evidence(&fx, "linkage.log");
    let mut retry = fx.facts.clone();
    retry.nonce.push('r');
    retry.created_at_ms += 1_000;
    retry.waiting_expires_at_ms += 1_000;

    // The winner commits inside the loser's open, which then conflicts.
    let mut rows = Rows::default();
    let profile = fx.fixture.profile();
    let mut opens = 0;
    let record = ConsentAdmission {
        store: &fx.store,
        profile,
        writer: &mut evidence.writer,
        outbox: &evidence.outbox,
    }
    .admit(
        fx.operation,
        &retry,
        |_, candidate| {
            opens += 1;
            let mut recorder = ApprovalRecorder::new(&fx.store, profile, &mut rows, "race");
            recorder
                .open_pending(fx.operation, &fx.facts, PolicyDecision::RequireApproval)
                .unwrap();
            recorder
                .open_pending(fx.operation, candidate, PolicyDecision::RequireApproval)
                .map_err(operation_refusal)
        },
        |record, _| Ok(record.clone()),
    )
    .unwrap();
    assert_eq!(opens, 1);
    assert_eq!(record.facts(), fx.facts);
    assert_eq!(record.operation_id, fx.operation);
    assert!(retained(&fx, &evidence));

    let lost = admit(&fx, &mut evidence, &retry, |_, _| -> Result<(), _> {
        Err(WalletError::Approval(
            stellar_agent_core::error::ApprovalFailure::NotFound {
                detail: "the inbox entry is gone".to_owned(),
            },
        ))
    })
    .unwrap_err();
    assert_eq!(lost.code(), "approval.not_found");
    assert!(retained(&fx, &evidence));
    let again = admit(&fx, &mut evidence, &retry, |record, _| Ok(record.clone())).unwrap();
    assert_eq!(again, record);
    let status = ApprovalStatus::new(&fx.store, profile);
    assert_eq!(status.find_by_nonce(&retry.nonce).unwrap(), None);
    assert_eq!(
        status
            .find_by_nonce(&fx.facts.nonce)
            .unwrap()
            .unwrap()
            .record,
        record
    );
}

/// A strict consent of the fixture entry into the inbox `file`, through the
/// anchored writer or the keyed outbox under a reservation.
fn strict_inbox(
    fx: &Fx,
    evidence: &mut Evidence,
    file: &str,
    queued: bool,
) -> (PendingApprovalStore, Option<OutboxRowRef>) {
    let policy = fx.fixture.current_policy();
    let mut inbox = PendingApprovalStore::open(fx.fixture.home().join(file)).unwrap();
    inbox
        .insert(fx.entry.clone(), fx.entry.created_at_unix_ms)
        .unwrap();
    evidence.writer.initialize_consent_evidence().unwrap();
    let reserved = evidence.outbox.clone().with_evidence_reservation(
        evidence
            .outbox
            .reserve_evidence(fx.id(), deadline(fx), fx.witness.consent_at_ms())
            .unwrap(),
    );
    let audit = if queued {
        ConsentAudit::Outbox(&reserved)
    } else {
        ConsentAudit::Writer(&mut evidence.writer)
    };
    let (_, reference) = attest_and_persist_with_row(
        &mut inbox,
        &fx.entry,
        &ATTESTATION_KEY,
        &fx.fixture.binding(),
        Surface::Cli,
        audit,
        ConsentAuthorization::Mainnet {
            presence: fx.fixture.presence(&fx.entry, &policy),
            policy: &policy,
        },
        |_, _| Err("unsupported test grant".to_owned()),
    )
    .unwrap();
    (inbox, reference)
}

fn publish(fx: &Fx, inbox: &PendingApprovalStore) -> Result<ApprovalView, WalletError> {
    let completion = publication_completion(
        inbox,
        &fx.store,
        fx.fixture.profile(),
        fx.fixture.name(),
        &fx.facts.nonce,
        &fx.fixture.current_policy(),
    )?;
    commit_consent(&fx.store, fx.fixture.profile(), &completion)
}

/// A published consent commits the verified handoff's sink with the exact
/// returned reference, survives restart and repeats unchanged. A commit
/// stopped before its counter exposes no success; one stopped after it
/// succeeds only from the authenticated reread. A released payload and a
/// compatibility entry without a handoff refuse.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn publication_commits_receipt_reference_and_provenance() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for queued in [false, true] {
        let mut fx = Fx::new(300_000);
        fx.open();
        let mut evidence = evidence(&fx, "publication.log");
        let (inbox, reference) = strict_inbox(&fx, &mut evidence, "strict.toml", queued);
        assert_eq!(reference.is_some(), queued);

        let compatible = PendingApprovalStore::open(fx.fixture.home().join("first.toml")).unwrap();
        assert_eq!(
            publish(&fx, &compatible).unwrap_err().code(),
            "approval.attestation_invalid"
        );
        {
            let _fault = arm_accounting_fault(COMMIT_FAULT_AFTER_PREPARED);
            assert!(publish(&fx, &inbox).is_err(), "queued {queued}");
        }
        assert_eq!(fx.view().record.consent, None);
        let published = {
            let _fault = arm_accounting_fault(COMMIT_FAULT_AFTER_COUNTER);
            publish(&fx, &inbox).unwrap()
        };
        let consent = published.record.consent.clone().unwrap();
        let expected = if queued {
            ConsentDeliveryV1::queued(fx.id())
        } else {
            ConsentDeliveryV1::direct_anchored(fx.id())
        };
        assert_eq!(consent.delivery, Some(expected.clone()));
        let payload = consent.payload.unwrap();
        assert_eq!(payload.outbox_row, reference);
        assert_eq!(
            payload.row_provenance,
            (!queued).then_some(RowProvenance::Written)
        );
        let reopened = PersistedWindowStore::at_path(fx.store.path().to_owned());
        assert_eq!(
            ApprovalStatus::new(&reopened, fx.fixture.profile())
                .view(fx.id())
                .unwrap(),
            Some(published.clone())
        );
        let committed = fx.bytes();
        assert_eq!(publish(&fx, &inbox).unwrap(), published);
        assert_eq!(fx.bytes(), committed);

        let compatibility = consent_completion(
            &inbox,
            &fx.store,
            fx.fixture.profile(),
            fx.fixture.name(),
            &fx.facts.nonce,
            &fx.fixture.current_policy(),
            ConsentRow::Recovered,
            &fx.fixture.authority().admit().unwrap(),
        )
        .unwrap();
        assert!(commit_consent(&fx.store, fx.fixture.profile(), &compatibility).is_ok());
        assert_eq!(fx.bytes(), committed);

        let _later = set_now_ms_for_test(consent.execution_expires_at_ms);
        fx.edit(|_| {});
        let released = fx.bytes();
        let retained = fx.view().record.consent.unwrap();
        assert_eq!(retained.payload, None);
        assert_eq!(retained.delivery, Some(expected));
        assert!(publish(&fx, &inbox).is_err());
        assert_eq!(fx.bytes(), released);
    }
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn publication_refuses_mismatched_witness() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new(300_000);
    fx.open();
    let mut evidence = evidence(&fx, "publication.log");
    let (inbox, _) = strict_inbox(&fx, &mut evidence, "strict.toml", false);
    let published = publish(&fx, &inbox).unwrap();
    drop(inbox);
    let consent = published.record.consent.unwrap();
    let payload = consent.payload.unwrap();
    let delivery = consent.delivery.unwrap();
    assert_ne!(fx.witness.presence_receipt_digest(), consent.receipt_sha256);
    let committed = fx.bytes();
    let mut recorder =
        ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "publication");
    let legacy = recorder
        .record_consent(published.record.id, &fx.witness, &payload)
        .unwrap_err();
    let stronger =
        recorder.record_consent_with_delivery(published.record.id, &fx.witness, &payload, delivery);
    assert!(
        stronger.is_err(),
        "the stronger recorder must preserve the mismatched-witness refusal"
    );
    assert_eq!(stronger.unwrap_err().to_string(), legacy.to_string());
    assert_eq!(fx.bytes(), committed);
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn publication_refuses_revoked_retry() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new(300_000);
    fx.open();
    let mut evidence = evidence(&fx, "publication.log");
    let (inbox, _) = strict_inbox(&fx, &mut evidence, "strict.toml", false);
    let published = publish(&fx, &inbox).unwrap();
    let id = published.record.id;
    let revoked = fx.recorder().revoke(id).unwrap();
    assert_eq!(revoked.record.state, ApprovalState::Revoked);
    let now = now_ms().unwrap();
    assert!(now < revoked.record.waiting_expires_at_ms);
    assert!(
        now < revoked
            .record
            .consent
            .as_ref()
            .unwrap()
            .execution_expires_at_ms
    );
    let completion = publication_completion(
        &inbox,
        &fx.store,
        fx.fixture.profile(),
        fx.fixture.name(),
        &fx.facts.nonce,
        &fx.fixture.current_policy(),
    )
    .unwrap();
    let compatibility = consent_completion(
        &inbox,
        &fx.store,
        fx.fixture.profile(),
        fx.fixture.name(),
        &fx.facts.nonce,
        &fx.fixture.current_policy(),
        ConsentRow::Recovered,
        &fx.fixture.authority().admit().unwrap(),
    )
    .unwrap();
    drop(inbox);
    let committed = fx.bytes();
    // Both paths refuse a revoked record, also the compatibility repeat of
    // the receipt the record already holds.
    for (path, completion) in [
        ("integrated", &completion),
        ("compatibility", &compatibility),
    ] {
        assert_eq!(
            commit_consent(&fx.store, fx.fixture.profile(), completion)
                .unwrap_err()
                .code(),
            "approval.revoked",
            "{path}"
        );
    }
    assert_eq!(fx.bytes(), committed);
}

/// The maintainer protocol states each commit point of admission and
/// publication once, states the readiness proof and its refusals, and keeps
/// queued reporting immediate.
#[test]
fn publication_protocol_documents_commit_points() {
    let recovery = include_str!("../../../../../docs/maintainers/audit-log-recovery.md");
    let internals = include_str!("../../../../../docs/maintainers/security-internals.md");
    for sentence in [
        "An integrated request is presented only after its committed pending record holds a reservation.",
        "Admission requires a readiness proof of the whole owner scope from stored state, then explicit owner initialization, then the reservation.",
        "It refuses with `live grant without delivery facts` while the verified window holds a live consent of an enforced kind without delivery facts.",
        "Readiness refuses with `owner scope shared or unreadable` when a sibling profile names an audit scope coordinate, or a profile file or the profiles directory cannot be read.",
        "Such a grant ends at its execution expiry against the greater of wall time and the evidence floor, or at the end of its operation.",
        "Readiness takes no window lock and writes nothing to the window, so a concurrent older binary on the same store can still record such a grant.",
        "Any other pin keeps refusing admission with `unresolved migration pin`, and no command clears it, so a migrated scope with an unmatched pin stays blocked.",
        "A grant held only in the inbox, without a window record, is outside the proof and refuses at use for an enforced kind.",
        "Integrated consent succeeds only after the window commit holds the receipt, the authenticated sink, and the exact queued reference.",
        "Recovery takes the sink only from a verified handoff, and a `written` or `recovered` row never becomes direct anchoring.",
        "Queued success reports `audit.outbox_queued` at once and never waits for delivery.",
        "When enabled, they reserve before inbox insertion, summary display, and presence.",
        "It releases the writer, inbox, and admission before the window commit, and returns a witness or success only after that commit.",
        "A crash after the consent row but before inbox persistence leaves no authenticated grant.",
        "A present Queued row and a Delivered row cannot be retargeted to a different consent digest.",
        "When enabled, the challenge precheck reacquires the record's reservation before either challenge form is issued.",
        "Every inbox response that shows a value attestation verifies the handoff under policy admission and shows it only after the window commit.",
        "When enabled, an MCP producer opens or selects the committed record and reserves before it stores the inbox entry or returns an approval block.",
        "The x402 payment capability is enabled, so both x402 tools reserve, publish, and consume through the integrated route.",
        "A retry reacquires the committed record's slot before it returns the linked approval block, so a full scope still answers the retry.",
        "A crash between the reservation and the inbox insert leaves a reserved record without an entry, and a retry refuses with `approval.not_found`.",
    ] {
        assert_eq!(recovery.matches(sentence).count(), 1, "{sentence}");
        assert!(sentence.split_whitespace().count() < 35, "{sentence}");
    }
    for rule in [
        "reserve before ceremony",
        "All four production kind capabilities are enabled",
        "stellar-agent-consent-publication:v1",
    ] {
        assert!(recovery.contains(rule), "{rule}");
    }
    assert!(internals.contains("in the replacement that stores the blob and receipt"));
    assert!(
        internals
            .contains("capabilities are enabled: payment, claim, trustline, and x402 payment.")
    );
    assert!(internals.contains("takes the sink only from a verified"));
    assert!(internals.contains("reserves before its challenge and again before its row"));
    assert!(
        internals
            .contains("enabled producer reserves the committed record's slot before it stores")
    );
}
