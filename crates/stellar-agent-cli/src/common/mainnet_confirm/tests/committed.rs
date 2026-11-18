//! The durable check of a committed consent: the presented proof against
//! the committed record, the request and the admitted operation.

use super::*;
use stellar_agent_core::approval::witness::ApprovedKind;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::policy_state::ApprovalRecorder;
use stellar_agent_network::policy_state::approvals::facade_calls;

const SPENT: &str = "this approval was already spent on a submission";
const OTHER_OPERATION: &str = "this approval belongs to another operation";

/// Revokes the durable record that names `nonce`.
pub(crate) fn revoke(profile: &Profile, name: &str, nonce: &str) {
    let store = PersistedWindowStore::for_profile(name);
    let id = ApprovalStatus::new(&store, profile)
        .find_by_nonce(nonce)
        .unwrap()
        .unwrap()
        .record
        .id;
    ApprovalRecorder::new(&store, profile, &mut NoRows, "revoke-fixture")
        .revoke(id)
        .unwrap();
}

/// Records a submission receipt that names `nonce`, as a send under it does.
pub(crate) fn hold_receipt(name: &str, nonce: &str) {
    ReceiptStore::open(name)
        .unwrap()
        .begin_submission_with_approval(
            &"ab".repeat(32),
            &"cd".repeat(32),
            "GSOURCE",
            2,
            u64::MAX,
            1,
            Some(nonce),
        )
        .unwrap();
}

/// The authenticated facade calls on `name`'s window-state file so far.
fn window_calls(name: &str) -> usize {
    facade_calls::count(
        &stellar_agent_core::profile::schema::default_policy_window_state_path_for(name),
    )
}

/// The check of a payment summary of `envelope` under `operation`.
fn check<'a>(operation: &'a OperationHandle, envelope: &str) -> CommitCheck<'a> {
    CommitCheck {
        operation,
        expected: ApprovalExpectation {
            kind: ApprovedKind::Payment,
            subject: approval_subject_classic(envelope),
        },
        intent: None,
    }
}

/// What the action between commit and check does.
#[derive(Clone, Copy, Debug)]
enum AfterCommit {
    Revoke,
    HoldReceipt,
    CollectAndLockInbox,
}

/// Both the fresh and the recovered completion verify the committed record
/// again. A revocation or a receipt after the commit refuses with its own
/// code and no witness; a receipt refuses before any durable read. Collecting
/// the inbox entry and holding the inbox lock after the commit changes
/// nothing, because the check reads no inbox.
#[tokio::test]
#[serial_test::serial]
async fn cli_commit_rechecks_durable_consent() {
    for recovered in [false, true] {
        for action in [
            AfterCommit::Revoke,
            AfterCommit::HoldReceipt,
            AfterCommit::CollectAndLockInbox,
        ] {
            let label = format!("committed-{recovered}-{action:?}").to_lowercase();
            let (fixture, context, envelope) = confirmation_fixture(&label);
            let _presence = driver::install(driver::fixture_credential());
            let handle = prepared_operation(&context, "committed", &envelope);
            if recovered {
                crash_after_attestation(&fixture, &context, &envelope, &handle).await;
            }
            let profile = context.profile().clone();
            let name = context.profile_name().to_owned();
            let store_path = fixture.store_path();
            let held = std::rc::Rc::new(std::cell::RefCell::new(None));
            let calls_at_hook = std::rc::Rc::new(std::cell::Cell::new(None));
            let (slot, at_hook) = (held.clone(), calls_at_hook.clone());
            let _hook = commit_test::after_commit(&name.clone(), move |nonce| {
                match action {
                    AfterCommit::Revoke => revoke(&profile, &name, nonce),
                    AfterCommit::HoldReceipt => hold_receipt(&name, nonce),
                    AfterCommit::CollectAndLockInbox => {
                        let mut inbox = PendingApprovalStore::open(store_path).unwrap();
                        assert!(inbox.remove(nonce).unwrap());
                        *slot.borrow_mut() = Some(inbox);
                    }
                }
                at_hook.set(Some(window_calls(&name)));
            });
            let result = durable(&fixture, &context, &envelope, &handle, 300_000).await;
            let calls_after = window_calls(context.profile_name());
            drop(held.borrow_mut().take());
            let record = durable_record(&context, &handle).unwrap();
            assert!(record.consent.is_some(), "{label}: the consent committed");
            match action {
                AfterCommit::Revoke => {
                    let error = result.unwrap_err();
                    assert_eq!(error.code(), "approval.revoked", "{label}");
                    assert!(
                        error.to_string().contains("this approval has been revoked"),
                        "{label}: {error}"
                    );
                }
                AfterCommit::HoldReceipt => {
                    let error = result.unwrap_err();
                    assert_eq!(error.code(), "approval.consumed", "{label}");
                    assert!(error.to_string().contains(SPENT), "{label}: {error}");
                    assert_eq!(
                        Some(calls_after),
                        calls_at_hook.get(),
                        "{label}: the receipt refuses before any durable read"
                    );
                }
                AfterCommit::CollectAndLockInbox => {
                    let witness = result.unwrap();
                    assert_eq!(witness.nonce(), record.nonce, "{label}");
                    assert!(
                        inbox(&fixture).is_empty(),
                        "{label}: the entry stays collected"
                    );
                }
            }
        }
    }
}

/// The check binds the presented bytes, the requested subject and the
/// admitted operation, never the record's own copies: another admitted
/// operation is a spent approval, and a forged proof, a valid proof of
/// another record, another subject and an unknown nonce each refuse.
#[tokio::test]
#[serial_test::serial]
async fn committed_check_binds_the_request_and_operation() {
    let (fixture, context, envelope) = confirmation_fixture("committed-binding");
    let _presence = driver::install(driver::fixture_credential());
    let policy = fixture.current_policy();
    let first = prepared_operation(&context, "committed-first", &envelope);
    let other = stellar_agent_test_support::SignedTestEnvelope::builder([8; 32])
        .unsigned()
        .sequence(3)
        .amount_stroops(19)
        .build();
    let other = other.envelope_xdr();
    let second = prepared_operation(&context, "committed-second", other);
    let witness = durable(&fixture, &context, &envelope, &first, 300_000)
        .await
        .unwrap();
    let foreign = durable(&fixture, &context, other, &second, 300_000)
        .await
        .unwrap();
    let pending = pending_store(&fixture);
    let presented = persisted_attestation(&pending, witness.nonce()).unwrap();
    let foreign_proof = persisted_attestation(&pending, foreign.nonce()).unwrap();
    drop(pending);
    let nonce = witness.nonce();

    let verified = verify_committed(
        &context,
        &policy,
        nonce,
        &presented,
        &check(&first, &envelope),
    )
    .unwrap();
    assert_eq!(verified.nonce(), nonce);
    assert_eq!(verified.consent_at_ms(), witness.consent_at_ms());
    assert_eq!(
        verified.execution_expires_at_ms(),
        witness.execution_expires_at_ms()
    );

    let error = verify_committed(
        &context,
        &policy,
        nonce,
        &presented,
        &check(&second, &envelope),
    )
    .unwrap_err();
    assert_eq!(error.code(), "approval.consumed");
    assert!(error.to_string().contains(OTHER_OPERATION), "{error}");
    assert!(!error.to_string().contains(SPENT), "{error}");
    assert!(!error.to_string().contains(nonce), "{error}");

    let mut forged = presented;
    forged[0] ^= 1;
    for (label, proof) in [("forged", forged), ("foreign", foreign_proof)] {
        let error = verify_committed(&context, &policy, nonce, &proof, &check(&first, &envelope))
            .unwrap_err();
        assert_eq!(error.code(), "approval.attestation_invalid", "{label}");
        assert!(
            error
                .to_string()
                .contains("the attestation does not verify"),
            "{label}: {error}"
        );
    }

    let error =
        verify_committed(&context, &policy, nonce, &presented, &check(&first, other)).unwrap_err();
    assert_eq!(error.code(), "approval.attestation_invalid");
    assert!(
        error
            .to_string()
            .contains("the approval approves another transaction"),
        "{error}"
    );

    let error = verify_committed(
        &context,
        &policy,
        "no-such-nonce",
        &presented,
        &check(&first, &envelope),
    )
    .unwrap_err();
    assert_eq!(error.code(), "approval.not_found");
    assert!(
        error
            .to_string()
            .contains("no durable approval record for that nonce"),
        "{error}"
    );
}

/// Under a kind that enforces delivery the check decides at the evidence
/// floor: a floor raised to the signed waiting expiry after the commit
/// refuses as expired although the wall clock is earlier.
#[tokio::test]
#[serial_test::serial]
async fn committed_check_decides_at_the_evidence_floor() {
    use stellar_agent_network::policy_state::approvals::ConsentEvidenceEnforcementGuard;
    let (fixture, context, envelope) = confirmation_fixture("committed-floor");
    let _enabled =
        ConsentEvidenceEnforcementGuard::new(context.profile_name(), ApprovedKind::Payment);
    let _presence = driver::install(driver::fixture_credential());
    let handle = prepared_operation(&context, "committed-floor", &envelope);
    let profile = context.profile().clone();
    let name = context.profile_name().to_owned();
    let _hook = commit_test::after_commit(&name.clone(), move |nonce| {
        let store = PersistedWindowStore::for_profile(&name);
        let record = ApprovalStatus::new(&store, &profile)
            .find_by_nonce(nonce)
            .unwrap()
            .unwrap()
            .record;
        assert!(clock_now().unwrap() < record.waiting_expires_at_ms);
        consent_outbox(&profile, &name)
            .unwrap()
            .advance_evidence_floor(record.waiting_expires_at_ms)
            .unwrap();
    });
    let error = durable(&fixture, &context, &envelope, &handle, 300_000)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "approval.expired");
    assert!(
        error
            .to_string()
            .contains("the approval is outside its lifetime"),
        "{error}"
    );
}

/// An attested inbox entry without a durable record never completes:
/// `approval.not_found`, with a message that names neither the nonce nor a
/// resolver precondition, and the record store stays without a record.
#[tokio::test]
#[serial_test::serial]
async fn consented_entry_without_a_record_refuses_not_found() {
    let (fixture, context, envelope) = confirmation_fixture("committed-no-record");
    let _presence = driver::install(driver::fixture_credential());
    let summary =
        MainnetWriteSummary::from_envelope(&envelope, MainnetConsumer::CliPay, 500).unwrap();
    let witness = confirm(&fixture, &context, &summary).await.unwrap();
    let nonce = witness.nonce().to_owned();
    assert!(inbox(&fixture)[0].attestation_blob_b64.is_some());
    let handle = prepared_operation(&context, "committed-no-record", &envelope);
    let admission = MainnetApprovalAuthority::for_profile(context.profile_name())
        .unwrap()
        .admit()
        .unwrap();
    let error = commit_durable(
        pending_store(&fixture),
        &context,
        &fixture.current_policy(),
        &nonce,
        ConsentRow::Recovered,
        admission,
        false,
        &check(&handle, &envelope),
    )
    .unwrap_err();
    assert_eq!(error.code(), "approval.not_found");
    let message = error.to_string();
    assert!(!message.contains(&nonce), "{message}");
    assert!(
        !message.to_lowercase().contains("precondition"),
        "{message}"
    );
    assert!(!message.contains("not_found"), "{message}");
    let rendered = render_authority_refusal("pay", AuthorityRefusal::Gate(error));
    let rendered = serde_json::to_value(&rendered).unwrap();
    assert_eq!(rendered["ok"], false, "{rendered}");
    assert_eq!(
        rendered["error"]["code"], "approval.not_found",
        "{rendered}"
    );
    let store = PersistedWindowStore::for_profile(context.profile_name());
    assert!(
        ApprovalStatus::new(&store, context.profile())
            .find_by_nonce(&nonce)
            .unwrap()
            .is_none()
    );
}

/// A live approval its own operation consumed at the mint, with no receipt,
/// passes the committed-consent check; another admitted operation refuses it
/// as spent.
#[tokio::test]
#[serial_test::serial]
async fn a_consumed_approval_of_its_own_operation_passes_the_check() {
    claim_authority_resolves("committed-consumed-claim", true, |minted| {
        use stellar_agent_core::approval::witness::ApprovalDisposition;
        let Minted {
            fixture,
            context,
            policy,
            operation,
            envelope,
            witness,
        } = minted;
        let nonce = witness.unwrap().nonce();
        let store = PersistedWindowStore::for_profile(context.profile_name());
        let facts = ApprovalStatus::new(&store, context.profile())
            .facts_by_nonce(nonce)
            .unwrap()
            .unwrap();
        assert_eq!(facts.record().disposition, ApprovalDisposition::Consumed);
        assert!(
            ReceiptStore::open(context.profile_name())
                .unwrap()
                .find_by_approval_nonce(nonce)
                .unwrap()
                .is_none(),
            "no receipt names the nonce"
        );
        let presented = persisted_attestation(&pending_store(fixture), nonce).unwrap();
        let expected = ApprovalExpectation {
            kind: ApprovedKind::Claim,
            subject: approval_subject_classic(envelope),
        };
        let own = CommitCheck {
            operation,
            expected,
            intent: None,
        };
        let verified = verify_committed(context, policy, nonce, &presented, &own).unwrap();
        assert_eq!(verified.nonce(), nonce);
        let other = prepared_operation(context, "claim-authority-other", envelope);
        let error = verify_committed(
            context,
            policy,
            nonce,
            &presented,
            &CommitCheck {
                operation: &other,
                expected,
                intent: None,
            },
        )
        .unwrap_err();
        assert_eq!(error.code(), "approval.consumed");
        assert!(error.to_string().contains(OTHER_OPERATION), "{error}");
    })
    .await;
}

/// The committed record named by `nonce` in profile `name`.
fn committed_record(
    profile: &Profile,
    name: &str,
    nonce: &str,
) -> stellar_agent_network::policy_state::WireApproval {
    let store = PersistedWindowStore::for_profile(name);
    ApprovalStatus::new(&store, profile)
        .find_by_nonce(nonce)
        .unwrap()
        .unwrap()
        .record
}

/// The check refuses a committed consent whose payload the record released.
/// Reaching the execution end on the store clock releases the payload in the
/// read image, so the check refuses as expired and names the execution
/// window, while the wall clock is still inside the signed lifetime.
#[tokio::test]
#[serial_test::serial]
async fn committed_check_refuses_a_released_payload() {
    let (fixture, context, envelope) = confirmation_fixture("committed-released");
    let _presence = driver::install(driver::fixture_credential());
    let handle = prepared_operation(&context, "committed-released", &envelope);
    let profile = context.profile().clone();
    let name = context.profile_name().to_owned();
    let clock = std::rc::Rc::new(std::cell::RefCell::new(None));
    let held = clock.clone();
    let _hook = commit_test::after_commit(&name.clone(), move |nonce| {
        let end = committed_record(&profile, &name, nonce)
            .consent
            .unwrap()
            .execution_expires_at_ms;
        *held.borrow_mut() = Some(stellar_agent_network::mainnet::clock::set_now_ms_for_test(
            end,
        ));
        let released = committed_record(&profile, &name, nonce).consent.unwrap();
        assert_eq!(
            released.payload, None,
            "the read image releases the payload"
        );
    });
    let error = durable(&fixture, &context, &envelope, &handle, 300_000)
        .await
        .unwrap_err();
    drop(clock.borrow_mut().take());
    assert_eq!(error.code(), "approval.expired");
    assert_eq!(
        error.to_string(),
        "the approval is outside its execution window"
    );
}

/// The signed waiting expiry bounds the check on the wall clock: one
/// millisecond before it the consent verifies; at it and one millisecond
/// after it the check refuses as expired. Consent comes 60 seconds after
/// creation, so the execution window still runs past the waiting expiry.
#[tokio::test]
#[serial_test::serial]
async fn committed_check_holds_the_lifetime_boundary() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    for offset in [-1_i64, 0, 1] {
        let label = format!("committed-boundary-{}", offset + 1);
        let (fixture, context, envelope) = confirmation_fixture(&label);
        let time = Arc::new(AtomicU64::new(clock_now().unwrap()));
        let read = time.clone();
        let _clock = stellar_agent_core::timefmt::test_clock::install(Arc::new(
            stellar_agent_core::timefmt::MockClock::new(move || Ok(read.load(Ordering::SeqCst))),
        ));
        let waited = time.clone();
        let mut answer = driver::fixture_credential();
        let _presence = driver::install(Box::new(move |ceremony| {
            waited.fetch_add(60_000, Ordering::SeqCst);
            answer(ceremony)
        }));
        let handle = prepared_operation(&context, "committed-boundary", &envelope);
        let profile = context.profile().clone();
        let name = context.profile_name().to_owned();
        let _hook = commit_test::after_commit(&name.clone(), move |nonce| {
            let record = committed_record(&profile, &name, nonce);
            assert!(record.consent.unwrap().execution_expires_at_ms > record.waiting_expires_at_ms);
            let expiry = record.waiting_expires_at_ms;
            time.store(expiry.checked_add_signed(offset).unwrap(), Ordering::SeqCst);
        });
        let result = durable(&fixture, &context, &envelope, &handle, 300_000).await;
        if offset < 0 {
            result.unwrap();
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.code(), "approval.expired", "{label}");
            assert_eq!(
                error.to_string(),
                "the approval is outside its lifetime",
                "{label}"
            );
        }
    }
}

/// The canonical intent case, which calls the confirmation directly; the
/// source scans read this module as test code.
#[cfg(test)]
mod intent {
    use super::*;

    /// A canonical intent consent verifies under the fresh decision: a decision
    /// of another policy digest refuses after the commit with
    /// `approval.attestation_invalid`, although the consent committed.
    #[tokio::test]
    #[serial_test::serial]
    async fn committed_intent_refuses_another_policy_decision() {
        use super::super::canonical_consent_tests::staged;
        use stellar_agent_core::approval::MemoFact;
        let (fixture, context, _) = confirmation_fixture("committed-intent");
        let _presence = driver::install(driver::fixture_credential());
        let (_, summary, handle) = staged(&fixture, &context, 0, MemoFact::None, 0);
        let policy = fixture.current_policy();
        let mut digest = policy.digest();
        digest[0] ^= 1;
        let other = MainnetDecision::for_test(
            Decision::RequireApproval(stellar_agent_core::policy::ApprovalRequest::new(
                "fixture".to_owned(),
                120,
            )),
            None,
            digest,
            policy.sequence(),
            7,
            context.profile_name(),
            context.chain().caip2_str(),
            1_900_000_000_000,
            120_000,
            stellar_agent_core::mainnet::decision::AuthorityScope::Classic,
        );
        let error = confirm_mainnet_write(
            &summary,
            ConfirmDecision::RequireApproval { ttl_ms: 120_000 },
            &context,
            &policy,
            &fixture.store_path(),
            Some(&handle),
            PolicyDecision::RequireApproval,
            &other,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "approval.attestation_invalid");
        assert_eq!(
            error.to_string(),
            "the decision does not govern this approval"
        );
        assert!(durable_record(&context, &handle).unwrap().consent.is_some());
    }
}
