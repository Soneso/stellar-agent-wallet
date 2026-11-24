//! The owner-scope readiness proof that integrated admission runs first, and
//! the exact adoption of migration pins before a reservation.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serial_test::serial;
use stellar_agent_core::audit_log::{
    AuditEntry, AuditWriter, MAX_EVIDENCE_ENTRIES, test_helpers::seed_reserved_evidence,
};
use stellar_agent_core::policy::state_lock::{WindowStoreLock, lock_requests};
use stellar_agent_core::profile::{loader::save_to_dir, schema::default_profile_dir};

use super::super::operations::OperationState;
use super::lifecycle_tests::{advance_floor, attempt, keyed_evidence, publish, store_audit_key};
use super::tests::{Fx, Rows};
use super::*;
use crate::operation_entry::{ConsentAdmission, operation_refusal};

/// Admits the fixture request, opening its record when none is committed.
/// Only an admitted request is presented.
fn admit(fx: &Fx, writer: &mut AuditWriter, outbox: &AuditOutbox) -> Result<(), WalletError> {
    let mut rows = Rows::default();
    let presented = Cell::new(0_u8);
    let result = ConsentAdmission {
        store: &fx.store,
        profile: fx.fixture.profile(),
        writer,
        outbox,
    }
    .admit(
        fx.operation,
        &fx.facts,
        |_, facts| {
            ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut rows, "open")
                .open_pending(fx.operation, facts, PolicyDecision::RequireApproval)
                .map_err(operation_refusal)
        },
        |_, _| {
            presented.set(presented.get() + 1);
            Ok(())
        },
    );
    assert_eq!(presented.get(), u8::from(result.is_ok()));
    result
}

/// The readiness proof of the fixture profile.
fn ready(fx: &Fx, outbox: &AuditOutbox) -> Result<(), WalletError> {
    require_consent_evidence_inventory(&fx.store, fx.fixture.profile(), outbox)
}

fn assert_unready(result: Result<(), WalletError>, reason: &str) {
    let error = result.unwrap_err();
    assert_eq!(error.code(), "audit.outbox_evidence_unusable", "{reason}");
    assert!(error.to_string().contains(reason), "{reason}: {error}");
}

/// Saves the fixture profile, changed by `edit`, as the sibling profile
/// `sibling` in the profiles directory.
fn sibling(fx: &Fx, edit: impl FnOnce(&mut Profile)) -> PathBuf {
    let mut profile = fx.fixture.profile().clone();
    edit(&mut profile);
    save_to_dir("sibling", &profile, &default_profile_dir().unwrap()).unwrap()
}

/// Makes the profiles directory `dir` unlistable and returns its restore.
/// Mode `0o300` keeps the selected file readable, so the unlistable
/// directory is the only finding. A process that lists the directory despite
/// its mode, or a platform without modes, gets a file in the directory's
/// place instead.
fn unlistable(dir: &Path) -> Box<dyn FnOnce()> {
    let dir = dir.to_owned();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&dir).unwrap().permissions();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o300)).unwrap();
        if std::fs::read_dir(&dir).is_err() {
            return Box::new(move || std::fs::set_permissions(&dir, mode).unwrap());
        }
        std::fs::set_permissions(&dir, mode).unwrap();
    }
    let moved = dir.with_extension("moved");
    std::fs::rename(&dir, &moved).unwrap();
    std::fs::write(&dir, "obstruction").unwrap();
    Box::new(move || {
        std::fs::remove_file(&dir).unwrap();
        std::fs::rename(&moved, &dir).unwrap();
    })
}

/// A sibling naming the scope's audit coordinates, in either letter case,
/// an unreadable sibling file, an unlistable profiles directory and an
/// unparsable selected profile file refuse readiness before admission
/// opens, initializes or presents anything, again on a repeat. A sibling
/// with the same audit key under another log path has its own scope, and a
/// scope of one profile is ready.
#[test]
#[serial]
fn readiness_enumerates_the_scope() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let fx = Fx::new(300_000);
    store_audit_key(fx.fixture.profile());
    let access = crate::keyring::keyed_audit_access(
        fx.fixture.profile(),
        fx.fixture.name(),
        BindingCheck::Enforce,
    )
    .unwrap();
    let mut writer =
        AuditWriter::open(fx.fixture.profile().audit_log_path.clone(), Some(access)).unwrap();
    let outbox = consent_evidence_outbox(
        fx.fixture.profile(),
        fx.fixture.name(),
        BindingCheck::Enforce,
    )
    .unwrap();
    let dir = default_profile_dir().unwrap();
    let selected = dir.join(format!("{}.toml", fx.fixture.name()));
    assert!(selected.is_file(), "the fixture saves the selected profile");
    let remove = |path: PathBuf| -> Box<dyn FnOnce()> {
        Box::new(move || std::fs::remove_file(path).unwrap())
    };
    for case in ["shared", "folded", "unreadable", "unlistable", "unparsable"] {
        let restore = match case {
            "shared" => remove(sibling(&fx, |_| {})),
            "folded" => remove(sibling(&fx, |p| {
                let key = &mut p.audit_log_hash_chain_key_id;
                key.service = key.service.to_ascii_uppercase();
                key.account = key.account.to_ascii_uppercase();
            })),
            "unreadable" => {
                let path = dir.join("sibling.toml");
                std::fs::write(&path, "chain_id = [").unwrap();
                remove(path)
            }
            "unlistable" => unlistable(&dir),
            _ => {
                let (path, saved) = (selected.clone(), std::fs::read(&selected).unwrap());
                std::fs::write(&path, "chain_id = [").unwrap();
                Box::new(move || std::fs::write(path, saved).unwrap())
            }
        };
        let window = fx.bytes();
        for _ in 0..2 {
            let result = admit(&fx, &mut writer, &outbox);
            assert!(result.is_err(), "{case}: readiness refuses");
            assert_unready(result, "owner scope shared or unreadable");
        }
        assert_eq!(fx.bytes(), window, "{case}: readiness writes nothing");
        assert_eq!(writer.outbox_evidence().unwrap(), None, "{case}");
        assert_eq!(
            ApprovalStatus::new(&fx.store, fx.fixture.profile())
                .find_by_operation(fx.operation)
                .unwrap(),
            None,
            "{case}: no record opens"
        );
        restore();
    }
    let planted = sibling(&fx, |p| {
        p.audit_log_path = p.audit_log_path.with_file_name("sibling.jsonl");
    });
    admit(&fx, &mut writer, &outbox).expect("another log path is another scope");
    std::fs::remove_file(planted).unwrap();
    admit(&fx, &mut writer, &outbox).expect("a scope of one profile is ready");
}

/// Integrated grants, pending, direct, queued or consumed, leave the scope
/// ready. A live consent of an enforced kind without delivery facts refuses
/// without a window lock or a write, until revocation, the end of its
/// operation, or its execution expiry at the greater of wall time and the
/// evidence floor ends it. A reversed clock keeps it live. The record keeps
/// its view and revocation. A live Claim consent without delivery facts
/// leaves the scope ready while a test opt-out leaves Claim unenforced, and
/// refuses once Claim enforces. On the compiled kind list, a live Claim
/// consent without delivery facts refuses admission of a Payment request in
/// its scope and writes nothing. A window that fails authentication refuses.
#[test]
#[serial]
fn migration_readiness_preserves_all_live_grants() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for grant in ["pending", "direct", "queued", "consumed"] {
        let mut fx = Fx::new(300_000);
        let name = fx.fixture.name().to_owned();
        let _enabled = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::Payment);
        let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), &name);
        if grant == "pending" {
            admit(&fx, &mut writer, &outbox).unwrap();
        } else {
            publish(&mut fx, &mut writer, &outbox, grant != "direct");
        }
        if grant == "consumed" {
            attempt(&mut fx, None);
            assert_eq!(fx.view().record.state, ApprovalState::Consumed);
        }
        let (window, evidence) = (fx.bytes(), outbox.evidence().unwrap());
        for _ in 0..2 {
            ready(&fx, &outbox).unwrap_or_else(|e| panic!("{grant}: {e}"));
        }
        assert_eq!((fx.bytes(), outbox.evidence().unwrap()), (window, evidence));
        admit(&fx, &mut writer, &outbox).unwrap_or_else(|e| panic!("{grant}: {e}"));
    }

    for end in ["clock", "revoked", "terminal"] {
        let mut fx = Fx::new(300_000);
        let name = fx.fixture.name().to_owned();
        let mut enabled = Some(ConsentEvidenceEnforcementGuard::new(
            &name,
            ApprovedKind::Payment,
        ));
        let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), &name);
        fx.open();
        let legacy = fx.consent().record.consent.unwrap();
        assert_eq!(legacy.delivery, None);
        let (window, evidence) = (fx.bytes(), outbox.evidence().unwrap());
        for _ in 0..2 {
            assert_unready(
                admit(&fx, &mut writer, &outbox),
                "live grant without delivery facts",
            );
        }
        assert_eq!((fx.bytes(), outbox.evidence().unwrap()), (window, evidence));
        let id = fx.id();
        match end {
            "clock" => {
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
                assert_unready(ready(&fx, &outbox), "live grant without delivery facts");
                drop(observed);
                drop(held);
                assert_eq!(
                    *requests.lock().unwrap(),
                    0,
                    "readiness takes no window lock"
                );
                let expiry = legacy.execution_expires_at_ms;
                fx.clock.set(expiry - 1);
                assert_unready(ready(&fx, &outbox), "live grant without delivery facts");
                for at in [expiry, expiry + 1] {
                    fx.clock.set(at);
                    ready(&fx, &outbox).unwrap();
                }
                fx.clock.set(legacy.consent_at_ms);
                assert_unready(ready(&fx, &outbox), "live grant without delivery facts");
                advance_floor(fx.fixture.profile(), &name, expiry);
                ready(&fx, &outbox).expect("the evidence floor ends the grant");
            }
            "revoked" => {
                fx.recorder().revoke(id).unwrap();
                ready(&fx, &outbox).expect("revocation ends the grant");
                assert_eq!(fx.view().record.state, ApprovalState::Revoked);
            }
            _ => {
                drop(enabled.take());
                attempt(&mut fx, Some(OperationState::NotSent));
                enabled = Some(ConsentEvidenceEnforcementGuard::new(
                    &name,
                    ApprovedKind::Payment,
                ));
                ready(&fx, &outbox).expect("a terminal operation ends the grant");
            }
        }
        assert_eq!(fx.view().record.id, id, "{end}: the record stays listed");
        drop(enabled);
    }

    {
        let mut fx = Fx::new(300_000);
        let name = fx.fixture.name().to_owned();
        let _enabled = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::Payment);
        let (_, outbox) = keyed_evidence(fx.fixture.profile(), &name);
        fx.open();
        fx.consent();
        fx.edit(|wire| wire.approvals.as_mut().unwrap().records[0].kind = ApprovedKind::Claim);
        let legacy = fx.view().record;
        assert_eq!(legacy.kind, ApprovedKind::Claim);
        assert_eq!(legacy.consent.unwrap().delivery, None);
        let _claim_opt_out = ConsentEvidenceDisableGuard::new(&name, ApprovedKind::Claim);
        let (window, evidence) = (fx.bytes(), outbox.evidence().unwrap());
        for _ in 0..2 {
            ready(&fx, &outbox).expect("an unenforced Claim grant leaves the scope ready");
        }
        assert_eq!((fx.bytes(), outbox.evidence().unwrap()), (window, evidence));
        let _claim = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::Claim);
        assert_unready(ready(&fx, &outbox), "live grant without delivery facts");
    }

    {
        let mut fx = Fx::new(300_000);
        fx.unpublished = None;
        let name = fx.fixture.name().to_owned();
        assert!(
            delivery_enforced(&name, ApprovedKind::Claim)
                && delivery_enforced(&name, ApprovedKind::Payment),
            "the compiled kind list decides both kinds"
        );
        let (mut writer, outbox) = keyed_evidence(fx.fixture.profile(), &name);
        fx.open();
        fx.consent();
        fx.edit(|wire| wire.approvals.as_mut().unwrap().records[0].kind = ApprovedKind::Claim);
        let legacy = fx.view().record;
        assert_eq!(legacy.kind, ApprovedKind::Claim);
        assert_eq!(legacy.consent.unwrap().delivery, None);
        assert_eq!(fx.facts.kind, ApprovedKind::Payment, "a payment request");
        let (window, evidence) = (fx.bytes(), outbox.evidence().unwrap());
        for _ in 0..2 {
            assert_unready(
                admit(&fx, &mut writer, &outbox),
                "live grant without delivery facts",
            );
        }
        assert_eq!((fx.bytes(), outbox.evidence().unwrap()), (window, evidence));
    }

    let fx = Fx::new(300_000);
    let (_, outbox) = keyed_evidence(fx.fixture.profile(), fx.fixture.name());
    let mut bytes = fx.bytes();
    let last = bytes.len() - 2;
    bytes[last] ^= 1;
    std::fs::write(fx.store.path(), bytes).unwrap();
    let error = ready(&fx, &outbox).unwrap_err();
    assert_eq!(error.code(), "submission.record_unavailable", "{error}");
}

/// The evidence of a log whose v1 owner kept one queued row, initialized so
/// that the row's digest is a migration pin, with the reference of that row.
fn pinned_scope(fx: &Fx) -> (AuditWriter, AuditOutbox, OutboxRowRef) {
    let (profile, name) = (fx.fixture.profile(), fx.fixture.name());
    store_audit_key(profile);
    let access = crate::keyring::keyed_audit_access(profile, name, BindingCheck::Enforce).unwrap();
    let mut writer = AuditWriter::open(profile.audit_log_path.clone(), Some(access)).unwrap();
    let outbox = consent_evidence_outbox(profile, name, BindingCheck::Enforce).unwrap();
    let reference = outbox
        .append_queued(&AuditEntry::new_approval_attested(
            "PaymentSimulated",
            "stellar_pay_commit",
            None,
            &fx.facts.nonce,
            "cli",
            "v1",
        ))
        .unwrap();
    writer.drain_outbox().unwrap();
    writer.initialize_consent_evidence().unwrap();
    let evidence = outbox.evidence().unwrap().unwrap();
    assert!(evidence.holds_migration_pin(&reference));
    (writer, outbox, reference)
}

/// Reserves every free slot of `fx`'s scope with foreign identities.
fn fill(fx: &Fx, free: usize) {
    let (key, anchor) = crate::keyring::keyed_audit_access(
        fx.fixture.profile(),
        fx.fixture.name(),
        BindingCheck::Enforce,
    )
    .unwrap()
    .into_parts();
    let foreign: Vec<_> = (0..free)
        .map(|i| {
            let mut identity = [0xee; 32];
            identity[..8].copy_from_slice(&(i as u64).to_be_bytes());
            identity
        })
        .collect();
    seed_reserved_evidence(
        &fx.fixture.profile().audit_log_path,
        anchor.as_ref(),
        &key,
        &foreign,
        u64::MAX,
    )
    .unwrap();
}

/// At full capacity, the migration pin of a live grant's exact queued
/// reference becomes that grant's Delivered evidence under its conservative
/// deadline, occupancy unchanged, and the reservation proceeds; a repeat
/// returns the same reservation. A pin of another digest, an identity that
/// holds other evidence, an ended grant, and a grant of a kind that does not
/// enforce adopt nothing, and the pin keeps refusing admission. Every kind is
/// listed, so the unenforced grant is a Claim grant under a test opt-out. A
/// live grant whose conservative deadline overflows refuses with `expiry
/// overflow` and adopts nothing.
#[test]
#[serial]
fn exact_pin_adoption_at_capacity() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    for case in [
        "exact",
        "unmatched",
        "conflict",
        "ended",
        "unenforced",
        "overflow",
    ] {
        let mut fx = Fx::new(300_000);
        let name = fx.fixture.name().to_owned();
        let _enabled = ConsentEvidenceEnforcementGuard::new(&name, ApprovedKind::Payment);
        let (_writer, outbox, pinned) = pinned_scope(&fx);
        let reference = if case == "unmatched" {
            fx.reference("other.log")
        } else {
            pinned
        };
        let (operation, facts, id) = (fx.operation, fx.facts.clone(), fx.id());
        record_consent_with_row_for_test(
            &mut ApprovalRecorder::new(&fx.store, fx.fixture.profile(), &mut fx.rows, "legacy"),
            operation,
            &facts,
            &fx.witness,
            &fx.payload,
            Some(reference),
            ConsentDeliveryV1::queued(id),
        )
        .unwrap();
        let deadline =
            EvidenceReservation::deadline(facts.waiting_expires_at_ms, facts.rule_ttl_ms).unwrap();
        if case == "conflict" {
            outbox
                .reserve_evidence(fx.id(), deadline + 1, fx.witness.consent_at_ms())
                .unwrap();
        }
        let _claim_opt_out = (case == "unenforced").then(|| {
            fx.edit(|wire| wire.approvals.as_mut().unwrap().records[0].kind = ApprovedKind::Claim);
            ConsentEvidenceDisableGuard::new(&name, ApprovedKind::Claim)
        });
        if case == "ended" {
            let consent = fx.view().record.consent.unwrap();
            fx.clock.set(consent.execution_expires_at_ms);
        }
        if case == "overflow" {
            // Consistent waiting and consent clocks that end at the top of
            // the clock, so only the conservative deadline overflows.
            fx.edit(|wire| {
                let record = &mut wire.approvals.as_mut().unwrap().records[0];
                record.created_at_ms = u64::MAX - record.rule_ttl_ms;
                record.waiting_expires_at_ms = u64::MAX;
                let consent = record.consent.as_mut().unwrap();
                let at = record.created_at_ms;
                consent.consent_at_ms = at;
                consent.execution_expires_at_ms = u64::MAX;
                let payload = consent.payload.as_mut().unwrap();
                let mut receipt = serde_json::to_value(&payload.receipt).unwrap();
                receipt["verified_at_unix_ms"] = serde_json::json!(at);
                payload.receipt = serde_json::from_value(receipt).unwrap();
                consent.receipt_sha256 = payload.receipt.digest().unwrap();
            });
        }
        fill(
            &fx,
            MAX_EVIDENCE_ENTRIES - 1 - usize::from(case == "conflict"),
        );
        let reacquire = || {
            ConsentAdmission::reacquire(&fx.store, fx.fixture.profile(), operation, &facts, &outbox)
        };
        let full = || {
            outbox
                .reserve_evidence([0xaa; 32], u64::MAX, fx.witness.consent_at_ms())
                .unwrap_err()
                .code()
                == "approval.evidence_capacity"
        };
        assert!(full(), "{case}: the scope is full before adoption");
        if case == "exact" {
            for _ in 0..2 {
                reacquire().expect("the adopted pin admits its grant");
                let evidence = outbox.evidence().unwrap().unwrap();
                assert!(evidence.contains_delivered(&fx.id(), &pinned));
                assert!(!evidence.holds_migration_pins());
                assert!(full(), "adoption keeps occupancy");
            }
            assert!(
                outbox
                    .reserve_evidence(fx.id(), deadline, fx.witness.consent_at_ms())
                    .is_ok(),
                "the adopted record holds the exact conservative deadline"
            );
        } else {
            let before = outbox.evidence().unwrap();
            let error = reacquire().expect_err(case);
            assert_eq!(error.code(), "audit.outbox_evidence_unusable", "{case}");
            let reason = match case {
                "conflict" => "conflicting reservation",
                "overflow" => "expiry overflow",
                _ => "unresolved migration pin",
            };
            assert!(error.to_string().contains(reason), "{case}: {error}");
            assert_eq!(outbox.evidence().unwrap(), before, "{case}: the pin stays");
            assert!(before.unwrap().holds_migration_pin(&pinned), "{case}");
        }
    }
}
