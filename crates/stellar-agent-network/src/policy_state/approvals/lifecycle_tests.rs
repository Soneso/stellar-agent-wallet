//! Release of ended consent evidence and the fresh evidence floor at every
//! Approval mint and use.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serial_test::serial;
use stellar_agent_core::audit_log::{AuditEntry, AuditWriter, outbox::outbox_path};
use stellar_agent_core::policy::state_lock::{WindowStoreLock, lock_requests};

use super::super::ledger::{
    ClaimExpect, ConsumeExpect, ConsumptionBinding, DomainBinding, MintedRecord,
};
use super::super::operations::{
    AttemptAuthorization, AttemptEnvelope, AttemptRequest, BusinessId, LookupOutcome,
    OperationRecorder, OperationState, WireTombstone,
};
use super::tests::{Fx, Rows};
use super::*;
use crate::mainnet::MainnetConsumer;
use crate::operation_entry::ConsentAdmission;

/// Stores the audit key of `profile`, which every profile with integrated
/// consent holds.
pub(crate) fn store_audit_key(profile: &Profile) {
    let coordinate = &profile.audit_log_hash_chain_key_id;
    let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap();
    if entry.get_password().is_err() {
        entry
            .set_password(&URL_SAFE_NO_PAD.encode([4_u8; 32]))
            .unwrap();
    }
}

/// The keyed writer and outbox of `profile`'s audit log, with its consent
/// evidence initialized.
pub(crate) fn keyed_evidence(profile: &Profile, name: &str) -> (AuditWriter, AuditOutbox) {
    store_audit_key(profile);
    let access = crate::keyring::keyed_audit_access(profile, name, BindingCheck::Enforce).unwrap();
    let mut writer = AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap();
    writer.initialize_consent_evidence().unwrap();
    let outbox = consent_evidence_outbox(profile, name, BindingCheck::Enforce).unwrap();
    (writer, outbox)
}

/// Advances the persistent floor of `profile` through a separate outbox, as
/// another process does.
pub(crate) fn advance_floor(profile: &Profile, name: &str, to: u64) {
    consent_evidence_outbox(profile, name, BindingCheck::Enforce)
        .unwrap()
        .advance_evidence_floor(to)
        .unwrap();
}

/// Overwrites both evidence slots of `profile` with bytes no owner wrote.
pub(crate) fn corrupt_evidence(profile: &Profile) {
    for suffix in [".evidence.0", ".evidence.1"] {
        let mut path = outbox_path(&profile.audit_log_path).into_os_string();
        path.push(suffix);
        std::fs::write(path, b"not an evidence image").unwrap();
    }
}

/// Opens the fixture record, reserves its evidence, and publishes its
/// consent with a Delivered queued row or strict direct provenance.
fn publish(
    fx: &mut Fx,
    writer: &mut AuditWriter,
    outbox: &AuditOutbox,
    queued: bool,
) -> Option<OutboxRowRef> {
    fx.open();
    let facts = fx.facts.clone();
    let operation = fx.operation;
    let reservation = fx
        .recorder()
        .reserve_consent_evidence(operation, &facts, outbox)
        .unwrap();
    let (reference, delivery) = if queued {
        let row = AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            &facts.nonce,
            "cli",
            "lifecycle",
        );
        let reference = outbox
            .clone()
            .with_evidence_reservation(reservation)
            .append_queued(&row)
            .unwrap();
        writer.drain_outbox().unwrap();
        (Some(reference), ConsentDeliveryV1::queued(fx.id()))
    } else {
        (None, ConsentDeliveryV1::direct_anchored(fx.id()))
    };
    record_consent_with_row_for_test(
        &mut ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "publish"),
        operation,
        &facts,
        &fx.witness,
        &fx.payload,
        reference,
        delivery,
    )
    .unwrap();
    reference
}

fn holds(outbox: &AuditOutbox, id: &[u8; 32]) -> bool {
    outbox.evidence().unwrap().unwrap().holds_record(id)
}

fn refused(result: Result<impl std::fmt::Debug, WindowStoreError>) -> MainnetPrecondition {
    match result {
        Err(WindowStoreError::AuthorizationRefused { precondition }) => precondition,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// Mints for the fixture operation's first attempt, consuming the approval,
/// and then commits `end` for that attempt when one is given.
fn attempt(fx: &mut Fx, end: Option<OperationState>) {
    let request = fx.mint_request();
    let operation = fx.operation;
    let mut recorder =
        OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "attempt");
    let Some(LookupOutcome::Resumable(handle)) = recorder
        .lookup(&BusinessId::parse("order-1").unwrap())
        .unwrap()
    else {
        panic!("live operation");
    };
    recorder
        .begin_attempt(
            &handle,
            &AttemptRequest {
                envelope: Some(AttemptEnvelope {
                    xdr: "AAAA".to_owned(),
                    unsigned_envelope_sha256: [1; 32],
                }),
                authorization: AttemptAuthorization::Mint(Box::new(request)),
                send_by_ms: u64::MAX,
            },
        )
        .unwrap();
    if let Some(state) = end {
        recorder
            .transition(
                operation,
                Some(1),
                state,
                &super::super::operations::TransitionEvidence::default(),
            )
            .unwrap();
    }
}

/// Replaces the fixture operation with its tombstone.
fn tombstone(fx: &mut Fx) {
    let now = fx.witness.consent_at_ms();
    fx.edit(|wire| {
        let section = wire.operations.as_mut().unwrap();
        let op = section.records.remove(0);
        section.tombstones.push(WireTombstone {
            id: op.id,
            business_id: op.business_id,
            state: OperationState::NotSent,
            result: op.result,
            intent_digest: op.intent.intent_digest(),
            slot_kind: op.intent.kind(),
            closed_at_ms: now,
        });
    });
}

#[test]
#[serial]
fn release_authority_follows_terminal_operation_states() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new(300_000);
    fx.open();
    fx.consent();
    let request = fx.mint_request();
    fx.store
        .mint_authorization(fx.fixture.profile(), &request)
        .unwrap();
    let consumed = fx.wire();
    let record = &records(&consumed)[0];
    assert_eq!(record.state, ApprovalState::Consumed);
    assert!(
        !record_ended(&consumed, record),
        "consumption is not final use"
    );
    for (state, ended) in [
        (OperationState::Succeeded, true),
        (OperationState::Failed, true),
        (OperationState::NotSent, true),
        (OperationState::PayloadReleased, true),
        (OperationState::Expired, true),
        (OperationState::Cancelled, true),
        (OperationState::NotIncluded, false),
        (OperationState::SentOutcomeUnknown, false),
        (OperationState::Sending, false),
        (OperationState::Authorized, false),
    ] {
        let mut wire = consumed.clone();
        wire.operations.as_mut().unwrap().records[0].state = state;
        assert_eq!(record_ended(&wire, &records(&wire)[0]), ended, "{state:?}");
    }
}

#[test]
#[serial]
fn terminal_release_requires_committed_authority() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for case in [
        "consumed",
        "missing",
        "forged",
        "not_sent",
        "tombstone",
        "revoked",
        "revoked_consumed",
    ] {
        let mut fx = Fx::new(300_000);
        let _enabled =
            ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
        let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), fx.fixture.name());
        let reference = publish(&mut fx, &mut writer, &outbox, true).unwrap();
        let id = fx.id();
        if case != "revoked" {
            attempt(
                &mut fx,
                (case == "not_sent").then_some(OperationState::NotSent),
            );
            assert_eq!(fx.view().record.state, ApprovalState::Consumed);
        }
        let ended = match case {
            "consumed" => false,
            "missing" => {
                fx.edit(|wire| wire.approvals = None);
                false
            }
            "forged" => {
                let mut bytes = fx.bytes();
                let last = bytes.len() - 2;
                bytes[last] ^= 1;
                std::fs::write(fx.store.path(), bytes).unwrap();
                false
            }
            "not_sent" => true,
            "tombstone" => {
                tombstone(&mut fx);
                true
            }
            _ => {
                fx.recorder().revoke(id).unwrap();
                true
            }
        };
        let window = fx.bytes();
        let released = release_ended_consent_evidence(&fx.store, fx.fixture.profile(), &outbox, id);
        assert_eq!(fx.bytes(), window, "{case}: release writes no window state");
        if ended {
            released.unwrap();
            assert!(!holds(&outbox, &id), "{case}: ended authority releases");
        } else {
            let code = released.unwrap_err().code();
            if case == "forged" {
                assert_ne!(code, "internal.unexpected_state", "{case}");
            } else {
                assert_eq!(code, "internal.unexpected_state", "{case}");
            }
            assert!(
                outbox
                    .evidence()
                    .unwrap()
                    .unwrap()
                    .contains_delivered(&id, &reference),
                "{case}: a live or unproven grant keeps its Delivered proof"
            );
        }
    }
}

#[test]
#[serial]
fn failed_release_keeps_the_committed_revocation() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new(300_000);
    let _enabled = ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
    let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), fx.fixture.name());
    publish(&mut fx, &mut writer, &outbox, false);
    let id = fx.id();
    fx.recorder().revoke(id).unwrap();
    let window = fx.bytes();
    let unkeyed = AuditOutbox::for_log(
        &fx.fixture.profile().audit_log_path,
        Arc::new(stellar_agent_core::audit_log::tip_anchor::InMemoryTipAnchorStore::new()),
    );
    assert!(release_ended_consent_evidence(&fx.store, fx.fixture.profile(), &unkeyed, id).is_err());
    assert_eq!(fx.bytes(), window, "a failed release keeps the revocation");
    assert_eq!(fx.view().record.state, ApprovalState::Revoked);
    assert!(holds(&outbox, &id));
    release_ended_consent_evidence(&fx.store, fx.fixture.profile(), &outbox, id).unwrap();
    assert!(!holds(&outbox, &id), "a later call retries the release");
}

#[test]
#[serial]
fn release_retries_after_terminal_commit() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for queued in [false, true] {
        let mut fx = Fx::new(300_000);
        let name = fx.fixture.name().to_owned();
        let _enabled = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::Payment);
        let _ready = ConsentEvidenceInventoryGuard::new(&name);
        let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), &name);
        publish(&mut fx, &mut writer, &outbox, queued);
        let id = fx.id();
        let request = fx.mint_request();
        fx.store
            .mint_authorization(fx.fixture.profile(), &request)
            .unwrap();
        let other = [0xee; 32];
        outbox
            .reserve_evidence(other, u64::MAX, fx.witness.consent_at_ms())
            .unwrap();
        // The process ends after the terminal commit and before any release.
        fx.recorder().revoke(id).unwrap();
        assert!(holds(&outbox, &id), "the terminal commit alone keeps proof");
        let held = WindowStoreLock::acquire_for(
            fx.store.path(),
            &fx.fixture.profile().policy_window_state_key_id,
        )
        .unwrap();
        let requests = Arc::new(Mutex::new(0_usize));
        let observed = {
            let requests = Arc::clone(&requests);
            lock_requests::observe(move |_| *requests.lock().unwrap() += 1)
        };
        let facts = fx.facts.clone();
        let admitted = ConsentAdmission {
            store: &fx.store,
            profile: fx.fixture.profile(),
            writer: &mut writer,
            outbox: &outbox,
        }
        .admit(
            fx.operation,
            &facts,
            |_, _| panic!("the committed record is reused"),
            |_, _| Ok(()),
        );
        drop(observed);
        drop(held);
        assert_eq!(
            admitted.unwrap_err().code(),
            "internal.unexpected_state",
            "a revoked record admits no new request"
        );
        assert_eq!(
            *requests.lock().unwrap(),
            0,
            "release takes no window lock while another holder owns it"
        );
        assert!(
            !holds(&outbox, &id),
            "the next admission releases the ended identity"
        );
        assert!(
            holds(&outbox, &other),
            "release names exactly that identity"
        );
        assert_eq!(
            consent_evidence_maintenance(&fx.store, fx.fixture.profile()).unwrap(),
            0,
            "a repeated sweep has nothing left to release"
        );
    }
}

#[test]
#[serial]
fn maintenance_keeps_live_outcomes_and_reads_nothing_unenforced() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    {
        let mut fx = Fx::new(300_000);
        let enabled =
            ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
        let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), fx.fixture.name());
        let reference = publish(&mut fx, &mut writer, &outbox, true).unwrap();
        let id = fx.id();
        attempt(&mut fx, None);
        assert_eq!(
            consent_evidence_maintenance(&fx.store, fx.fixture.profile()).unwrap(),
            0,
            "a live consumed attempt keeps proof"
        );
        assert!(
            outbox
                .evidence()
                .unwrap()
                .unwrap()
                .contains_delivered(&id, &reference)
        );
        tombstone(&mut fx);
        drop(enabled);
        assert_eq!(
            consent_evidence_maintenance(&fx.store, fx.fixture.profile()).unwrap(),
            0,
            "an unenforced profile releases nothing"
        );
        assert!(holds(&outbox, &id));
        let _enabled =
            ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
        assert_eq!(
            consent_evidence_maintenance(&fx.store, fx.fixture.profile()).unwrap(),
            1
        );
    }
    // Without enforcement, maintenance reads no keyring entry at all.
    let fx = Fx::new(300_000);
    assert_eq!(
        consent_evidence_maintenance(&fx.store, fx.fixture.profile()).unwrap(),
        0
    );
    let _enabled = ConsentEvidenceEnforcementGuard::new(fx.fixture.name(), ApprovedKind::Payment);
    assert!(
        consent_evidence_maintenance(&fx.store, fx.fixture.profile()).is_err(),
        "an enforced profile without its audit key refuses"
    );
}

#[test]
#[serial]
fn consent_floor_uses_current_authenticated_scope() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fx::new(300_000);
    let (profile, name) = (fx.fixture.profile(), fx.fixture.name());
    assert!(
        consent_evidence_time_floor(profile, name).is_err(),
        "a missing audit key refuses"
    );
    store_audit_key(profile);
    assert!(
        consent_evidence_time_floor(profile, name)
            .unwrap_err()
            .to_string()
            .contains("audit.carriers_unbound"),
        "a log without enrolled carriers refuses"
    );
    let access = crate::keyring::keyed_audit_access(profile, name, BindingCheck::Enforce).unwrap();
    let mut writer = AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap();
    assert_eq!(
        consent_evidence_time_floor(profile, name).unwrap(),
        0,
        "an enrolled log without an owner reads as zero"
    );
    writer.initialize_consent_evidence().unwrap();
    assert_eq!(consent_evidence_time_floor(profile, name).unwrap(), 0);
    for to in [1_000, 2_000] {
        advance_floor(profile, name, to);
        assert_eq!(
            consent_evidence_time_floor(profile, name).unwrap(),
            to,
            "each read sees the floor another instance committed"
        );
    }
    corrupt_evidence(profile);
    assert_eq!(
        consent_evidence_time_floor(profile, name)
            .unwrap_err()
            .code(),
        "audit.outbox_evidence_unusable",
        "an image no owner wrote refuses"
    );
    // Slots without an owner are orphans, never a zero floor.
    drop(writer);
    let orphan = Fx::new(300_000);
    let (profile, name) = (orphan.fixture.profile(), orphan.fixture.name());
    store_audit_key(profile);
    let access = crate::keyring::keyed_audit_access(profile, name, BindingCheck::Enforce).unwrap();
    let _writer = AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap();
    corrupt_evidence(profile);
    assert_eq!(
        consent_evidence_time_floor(profile, name)
            .unwrap_err()
            .code(),
        "audit.outbox_evidence_unusable",
        "slots without an owner never read as zero"
    );
}

#[test]
#[serial]
fn mint_refreshes_floor_after_validation() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for (queued, offset, mints) in [
        (false, -1, true),
        (false, 0, false),
        (true, 0, false),
        (true, 1, false),
    ] {
        let mut fx = Fx::new(300_000);
        let name = fx.fixture.name().to_owned();
        let _enabled = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::Payment);
        let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), &name);
        publish(&mut fx, &mut writer, &outbox, queued);
        let floor = consent_evidence_time_floor(fx.fixture.profile(), &name).unwrap();
        require_consent_evidence_time(&fx.witness, floor).unwrap();
        let end = fx.witness.execution_expires_at_ms();
        advance_floor(
            fx.fixture.profile(),
            &name,
            end.checked_add_signed(offset).unwrap(),
        );
        // The wall clock stays at consent time, behind the floor.
        fx.clock.set(fx.witness.consent_at_ms());
        let request = fx.mint_request();
        let public = fx.store.mint_authorization(fx.fixture.profile(), &request);
        let mut rows = Rows::default();
        let mut recorder =
            OperationRecorder::new(&fx.store, fx.fixture.profile(), &mut rows, "held");
        let Some(LookupOutcome::Resumable(handle)) = recorder
            .lookup(&BusinessId::parse("order-1").unwrap())
            .unwrap()
        else {
            panic!("live operation");
        };
        let mut held_request = request.clone();
        // The attempt carries the operation's signed envelope.
        held_request.binding = DomainBinding::Transaction {
            unsigned_envelope_sha256: [1; 32],
            tx_hash: [4; 32],
            source: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".to_owned(),
            sequence: 2,
        };
        let held = recorder.begin_attempt(
            &handle,
            &AttemptRequest {
                envelope: Some(AttemptEnvelope {
                    xdr: "AAAA".to_owned(),
                    unsigned_envelope_sha256: [1; 32],
                }),
                authorization: AttemptAuthorization::Mint(Box::new(held_request)),
                send_by_ms: u64::MAX,
            },
        );
        if mints {
            public.unwrap();
            held.unwrap();
        } else {
            assert_eq!(
                refused(public),
                MainnetPrecondition::ApprovalExpired,
                "the public mint decides at the fresh floor"
            );
            assert!(
                matches!(
                    held,
                    Err(WindowStoreError::AuthorizationRefused {
                        precondition: MainnetPrecondition::ApprovalExpired
                    })
                ),
                "the held mint decides at the fresh floor: {held:?}"
            );
            let wire = fx.wire();
            assert!(wire.authorizations.is_empty(), "no authorization exists");
            assert_eq!(
                records(&wire)[0].state,
                ApprovalState::Pending,
                "a refused mint consumes nothing"
            );
        }
    }
    // An unenforced kind keeps wall time and reads no evidence.
    let mut fx = Fx::new(300_000);
    fx.open();
    fx.consent();
    store_audit_key(fx.fixture.profile());
    let _ = keyed_evidence(fx.fixture.profile(), fx.fixture.name());
    advance_floor(
        fx.fixture.profile(),
        fx.fixture.name(),
        fx.witness.execution_expires_at_ms() + 1,
    );
    corrupt_evidence(fx.fixture.profile());
    let request = fx.mint_request();
    fx.store
        .mint_authorization(fx.fixture.profile(), &request)
        .unwrap();
    // A continuation mint under a consumed parent decides at the fresh floor.
    continuation_after_floor(-1).unwrap();
    for offset in [0, 1] {
        assert_eq!(
            refused(continuation_after_floor(offset)),
            MainnetPrecondition::ApprovalExpired,
            "the continuation mint at the record cap plus {offset} decides at the fresh floor"
        );
    }
}

/// An x402 submission mint under a consumed Soroban parent after another
/// actor moves the floor to the record cap plus `offset`, with the wall
/// clock at consent time.
fn continuation_after_floor(offset: i64) -> Result<MintedRecord, WindowStoreError> {
    use crate::mainnet::{AuditFacts, RecomputedFacts};
    let mut fx = Fx::x402(300_000);
    let name = fx.fixture.name().to_owned();
    let _enabled = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::X402Payment);
    let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), &name);
    publish(&mut fx, &mut writer, &outbox, true);
    let mut request = fx.mint_request();
    request.consumer = MainnetConsumer::X402Create;
    request.binding = DomainBinding::Soroban {
        intent_digest: fx.facts.intent_digest,
    };
    let parent = fx
        .store
        .mint_authorization(fx.fixture.profile(), &request)
        .unwrap();
    let audit = AuditFacts {
        log_path_digest: [1; 32],
        segment: [2; 32],
        anchored_count: 1,
    };
    let expect = ConsumeExpect::new(
        name.clone(),
        request.chain,
        request.consumer,
        request.binding.clone(),
        request.policy_sequence,
        request.policy_digest,
        request.authority.clone(),
        None,
        parent.bindings_digest,
        audit,
        &RecomputedFacts {
            content_digest: request.binding.content_digest(),
            entries_digest: crate::mainnet::digest::entries_digest(&[]),
            audit,
        },
    );
    fx.store
        .consume_authorization(
            fx.fixture.profile(),
            parent.id,
            &expect,
            &ConsumptionBinding::RetainedIntent {
                intent_digest: fx.facts.intent_digest,
            },
        )
        .unwrap();
    let cap = record_cap(&fx.wire().approvals, &fx.facts.nonce).unwrap();
    advance_floor(
        fx.fixture.profile(),
        &name,
        cap.checked_add_signed(offset).unwrap(),
    );
    fx.clock.set(fx.witness.consent_at_ms());
    request.parent = Some(parent.id);
    request.operation = None;
    request.binding = DomainBinding::X402Submit {
        final_envelope_sha256: [8; 32],
        root_invocation_digest: [9; 32],
    };
    let before = fx.bytes();
    let minted = fx.store.mint_authorization(fx.fixture.profile(), &request);
    if minted.is_err() {
        assert_eq!(
            fx.bytes(),
            before,
            "a refused continuation mint writes nothing"
        );
    }
    minted
}

#[test]
fn lifecycle_protocol_states_activation_limits() {
    let recovery = include_str!("../../../../../docs/maintainers/audit-log-recovery.md");
    for sentence in [
        "Release follows authenticated revocation or final operation termination, outside the policy-window lock.",
        "First consumption and a missing approval record do not authorize release; retryable consumed grants retain their proof.",
        "`approve revoke --id` releases its grant at once; integrated admission, each recovery pass, and each CLI revocation release every retained ended grant, so a failed or deferred release retries.",
        "Every Approval mint, claim, consumption, and signing expiry check of an enforced kind uses the greater of wall time and the evidence floor, read fresh for that decision.",
        "A floor that cannot be read refuses as a storage error, never as expiry.",
        "Unresolved pins and incomplete producer integration block activation; initialization remains explicit.",
        "Populations exceeding capacity require an authenticated migration before activation.",
    ] {
        assert_eq!(recovery.matches(sentence).count(), 1, "{sentence}");
        assert!(sentence.split_whitespace().count() < 35, "{sentence}");
    }
}

/// A claim or consumption under a minted x402 authorization after another
/// actor moves the floor to its expiry plus `offset`.
fn use_after_floor(
    step: &str,
    offset: i64,
    enforced: bool,
    broken: bool,
) -> Result<(), WindowStoreError> {
    let mut fx = Fx::x402(300_000);
    let name = fx.fixture.name().to_owned();
    let enabled = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::X402Payment);
    let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), &name);
    publish(&mut fx, &mut writer, &outbox, true);
    let mut request = fx.mint_request();
    request.consumer = MainnetConsumer::X402Create;
    request.binding = DomainBinding::Soroban {
        intent_digest: fx.facts.intent_digest,
    };
    let minted = fx
        .store
        .mint_authorization(fx.fixture.profile(), &request)
        .unwrap();
    advance_floor(
        fx.fixture.profile(),
        &name,
        minted.expires_at_ms.checked_add_signed(offset).unwrap(),
    );
    if broken {
        corrupt_evidence(fx.fixture.profile());
    }
    if !enforced {
        drop(enabled);
    }
    let before = fx.bytes();
    let result = if step == "claim" {
        fx.store
            .claim_authorization(
                fx.fixture.profile(),
                minted.id,
                &ClaimExpect {
                    operation: request.operation,
                    intent_digest: request.intent_digest,
                    predecessor: request.predecessor,
                    domain: request.binding.domain(),
                    consumer: request.consumer,
                    bindings_digest: minted.bindings_digest,
                    policy_sequence: request.policy_sequence,
                    policy_digest: request.policy_digest,
                    authority: request.authority.clone(),
                },
            )
            .map(|_| ())
    } else {
        use crate::mainnet::{AuditFacts, RecomputedFacts};
        let audit = AuditFacts {
            log_path_digest: [1; 32],
            segment: [2; 32],
            anchored_count: 1,
        };
        let expect = ConsumeExpect::new(
            name.clone(),
            request.chain,
            request.consumer,
            request.binding.clone(),
            request.policy_sequence,
            request.policy_digest,
            request.authority.clone(),
            None,
            minted.bindings_digest,
            audit,
            &RecomputedFacts {
                content_digest: request.binding.content_digest(),
                entries_digest: crate::mainnet::digest::entries_digest(&[]),
                audit,
            },
        );
        fx.store
            .consume_authorization(
                fx.fixture.profile(),
                minted.id,
                &expect,
                &ConsumptionBinding::RetainedIntent {
                    intent_digest: fx.facts.intent_digest,
                },
            )
            .map(|_| ())
    };
    if result.is_err() {
        assert_eq!(fx.bytes(), before, "a refused use writes nothing");
    }
    result
}

#[test]
#[serial]
fn issued_authorization_cannot_outlive_the_floor() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for (step, expired) in [
        ("claim", MainnetPrecondition::Expired),
        ("consume", MainnetPrecondition::NotOpen),
    ] {
        use_after_floor(step, -1, true, false).unwrap();
        for offset in [0, 1] {
            let used = use_after_floor(step, offset, true, false);
            assert!(
                matches!(
                    &used,
                    Err(WindowStoreError::AuthorizationRefused { precondition }) if *precondition == expired
                ),
                "{step} at the expiry plus {offset} refuses {expired:?}: {used:?}"
            );
        }
        use_after_floor(step, 1, false, false).unwrap();
        let broken = use_after_floor(step, -1, true, true).unwrap_err();
        assert!(
            matches!(broken, WindowStoreError::Keyring { .. }),
            "{step}: an unreadable floor is a storage error, never expiry: {broken:?}"
        );
    }
}
