#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test fixtures and assertions"
)]

use super::super::tests::Fx;
use super::*;
use serial_test::serial;

fn inspect(fx: &Fx, now: u64) -> Result<Value, WalletError> {
    ApprovalStatusSnapshot::read(&fx.store, fx.fixture.profile(), fx.fixture.name(), now)
        .unwrap()
        .inspect(&fx.facts.nonce, &fx.fixture.home().join("absent.toml"))
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn approval_status_durable_lifecycle_and_clock_views() {
    for consumed in [false, true] {
        let mut fx = Fx::new(300_000);
        let record = fx.open().record;
        assert_eq!(
            inspect(&fx, record.created_at_ms).unwrap()["state"],
            "pending"
        );
        let consent = fx.consent().record.consent.unwrap();
        let before = fx.bytes();
        assert_eq!(
            inspect(&fx, consent.execution_expires_at_ms).unwrap()["state"],
            "expired",
            "expiry uses the supplied exclusive boundary"
        );
        let restored = inspect(&fx, consent.consent_at_ms).unwrap();
        assert_eq!(
            restored["state"], "attested",
            "observational expiry has no durable watermark"
        );
        assert_eq!(restored["verification"]["valid"], true);
        assert_eq!(
            fx.bytes(),
            before,
            "status persists no expiry or collection"
        );
        if consumed {
            use operations::{
                AttemptAuthorization, AttemptEnvelope, AttemptRequest, BusinessId,
                ExposureIdentity, LookupOutcome, OperationRecorder,
            };
            let request = fx.mint_request();
            let mut recorder = OperationRecorder::new(
                &fx.store,
                fx.fixture.profile(),
                &mut fx.rows,
                "status-attempt",
            );
            let Some(LookupOutcome::Resumable(handle)) = recorder
                .lookup(&BusinessId::parse("order-1").unwrap())
                .unwrap()
            else {
                panic!("resumable")
            };
            let started = recorder
                .begin_attempt(
                    &handle,
                    &AttemptRequest {
                        envelope: Some(AttemptEnvelope {
                            xdr: "AAAA".into(),
                            unsigned_envelope_sha256: [1; 32],
                        }),
                        authorization: AttemptAuthorization::Mint(Box::new(request.clone())),
                        send_by_ms: consent.execution_expires_at_ms,
                    },
                )
                .unwrap();
            let minted = started.minted.unwrap();
            fx.store
                .claim_authorization(
                    fx.fixture.profile(),
                    minted.id,
                    &crate::policy_state::ClaimExpect {
                        operation: request.operation,
                        intent_digest: request.intent_digest,
                        predecessor: request.predecessor,
                        domain: request.binding.domain(),
                        consumer: request.consumer,
                        bindings_digest: minted.bindings_digest,
                        policy_sequence: request.policy_sequence,
                        policy_digest: request.policy_digest,
                        authority: request.authority,
                    },
                )
                .unwrap();
            recorder
                .expose(
                    fx.operation,
                    1,
                    &ExposureIdentity::Classic {
                        envelope_sha256: [3; 32],
                        tx_hash: [2; 32],
                        sequence: 1,
                        max_time: consent.execution_expires_at_ms / 1000,
                        receipt: "status-receipt".into(),
                    },
                    Some(100),
                )
                .unwrap();
            let view = inspect(&fx, consent.consent_at_ms).unwrap();
            assert_eq!(
                view["open_attempt"], 1,
                "open attempt comes from the linked operation"
            );
            assert_eq!(
                view["tx_hash"],
                "02".repeat(32),
                "consumed approval retains its exposed transaction hash"
            );
            assert_eq!(view["outcome"], "unknown");
            let mut recorder = OperationRecorder::new(
                &fx.store,
                fx.fixture.profile(),
                &mut fx.rows,
                "status-result",
            );
            recorder
                .transition(
                    fx.operation,
                    Some(1),
                    operations::OperationState::SentOutcomeUnknown,
                    &operations::TransitionEvidence::default(),
                )
                .unwrap();
            recorder
                .transition(
                    fx.operation,
                    Some(1),
                    operations::OperationState::Succeeded,
                    &operations::TransitionEvidence {
                        result: Some(operations::OperationResult {
                            tx_hash: Some([2; 32]),
                            ledger: Some(101),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .unwrap();
            let view = inspect(&fx, consent.consent_at_ms).unwrap();
            assert_eq!(
                view["outcome"], "confirmed",
                "stored terminal result supplies the consumed outcome"
            );
            assert!(
                view.get("open_attempt").is_none(),
                "terminal operations have no open attempt"
            );
        } else {
            let id = fx.id();
            fx.recorder().revoke(id).unwrap();
        }
        let state = if consumed { "consumed" } else { "revoked" };
        let before = fx.bytes();
        for now in [0, consent.execution_expires_at_ms] {
            let view = inspect(&fx, now).unwrap();
            assert_eq!(
                view["state"], state,
                "durable tombstones precede expiry and rollback"
            );
            assert_eq!(view["verification"]["reason"], state);
            assert!(view.get("subject_digest").is_none());
        }
        assert_eq!(
            inspect(&fx, u64::MAX).unwrap_err().code(),
            "approval.unknown",
            "collected durable records are unknown"
        );
        assert_eq!(fx.bytes(), before);
    }
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn approval_status_duplicate_durable_identity_refuses() {
    let mut fx = Fx::new(300_000);
    fx.open();
    let mut wire = fx.wire();
    let records = &mut wire.approvals.as_mut().unwrap().records;
    records.push(records[0].clone());
    fx.store
        .seal_unchecked_for_test(fx.fixture.profile(), &wire);
    let result =
        ApprovalStatusSnapshot::read(&fx.store, fx.fixture.profile(), fx.fixture.name(), 0);
    assert!(
        result.is_err(),
        "duplicate durable identity refuses the whole authenticated image"
    );
    assert_eq!(
        status_read_error(&result.err().unwrap()).code(),
        "submission.record_unavailable"
    );
}
