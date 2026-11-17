//! Status selection and the stored operation projection.

use super::progress::{READS, homed};
use super::*;

fn view(fx: &Fx, id: OperationId) -> OperationProjection {
    OperationStatus::new(&fx.store, &fx.profile)
        .projection(&id)
        .unwrap()
        .unwrap()
}

fn select(
    fx: &Fx,
    tx_hash: Option<[u8; 32]>,
    business_id: Option<&str>,
) -> Result<StatusTarget, &'static str> {
    let hash = tx_hash.map(|hash| stellar_agent_core::hex::encode(&hash));
    let selectors = StatusSelectors::parse(hash.as_deref(), business_id).unwrap();
    OperationStatus::new(&fx.store, &fx.profile)
        .select(&selectors)
        .unwrap()
        .map_err(|error| error.code())
}

fn hex(n: u8) -> Option<String> {
    Some(stellar_agent_core::hex::encode(&[n ^ 0x80; 32]))
}

/// Every stored shape projects its state, attempts and identity from one
/// image, with null identity before exposure, the x402 digest without a
/// transaction hash, decision ledgers on the deciding transition, the
/// bucket hold, and a tombstone's empty attempts. No amount is serialized
/// and nothing is written.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn operation_projection_state_matrix() {
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    let prepared = fx.open_new(&request("prepared", canonical(1)));
    let opened = view(&fx, prepared.id());
    assert_eq!(opened.state, OperationState::Prepared);
    assert!(opened.attempts.is_empty());
    assert_eq!(
        opened.last_transition,
        Some(TransitionProjection {
            kind: OperationState::Prepared,
            at_ms: T0,
            ledger_primary: None,
            ledger_witness: None,
        }),
        "the opening transition"
    );
    assert_eq!(opened.hold, Some(HoldProjection { held: false }));

    let crashed = fx.open_new(&request("pre-exposure", canonical(2)));
    let mint = fx.operation_mint_request(&crashed, tx(2), fx.policy(), vec![hold(10)]);
    fx.begin_mint(&crashed, &mint).unwrap();
    let before = view(&fx, crashed.id());
    assert_eq!(before.state, OperationState::Sending);
    assert_eq!(
        before.attempts,
        vec![AttemptProjection {
            index: 1,
            state: OperationState::Sending,
            tx_hash: None,
            sequence: None,
            max_time: None,
            auth_entry_sha256: None,
        }],
        "an unexposed attempt has null identity"
    );
    assert_eq!(
        before.hold,
        Some(HoldProjection { held: true }),
        "the bucket hold"
    );

    let x402 = x402_exposed(&mut fx, 3, OperationState::SentOutcomeUnknown);
    let paid = view(&fx, x402.id());
    let attempt = &paid.attempts[0];
    assert_eq!(attempt.tx_hash, None, "x402 has no transaction hash");
    assert!(
        attempt.auth_entry_sha256.is_some(),
        "x402 shows its entry digest"
    );
    assert_eq!((attempt.sequence, attempt.max_time), (None, None));

    let (succeeded, _) = commit_checked(&mut fx, 4, Checked::Succeeded);
    let decided = view(&fx, succeeded.id());
    assert_eq!(
        decided.attempts[0],
        AttemptProjection {
            index: 1,
            state: OperationState::Succeeded,
            tx_hash: Some([4 ^ 0x80; 32]),
            sequence: Some(104),
            max_time: Some(T0 / 1000 + 60),
            auth_entry_sha256: None,
        }
    );
    let transition = decided.last_transition.clone().unwrap();
    assert_eq!(transition.kind, OperationState::Succeeded);
    assert!(
        transition.ledger_primary.is_some() && transition.ledger_witness.is_some(),
        "the deciding transition names both ledgers: {transition:?}"
    );

    let predecessor = projected_not_included(&mut fx, 5);
    successor_attempt(&mut fx, &predecessor, 6, 106);
    let retried = view(&fx, predecessor.id());
    assert_eq!(
        retried
            .attempts
            .iter()
            .map(|attempt| (attempt.index, attempt.state, attempt.tx_hash))
            .collect::<Vec<_>>(),
        vec![
            (1, OperationState::NotIncluded, Some([5 ^ 0x80; 32])),
            (2, OperationState::SentOutcomeUnknown, Some([6 ^ 0x80; 32])),
        ]
    );

    let json = serde_json::to_string(&decided).unwrap();
    for word in ["amount", "stroops", "debit", "fee"] {
        assert!(!json.contains(word), "no amount key: {json}");
    }
    let bytes = fs::read(fx.store.path()).unwrap();
    fx.rewrite(|wire| {
        let section = wire.operations.as_mut().unwrap();
        let at = section
            .records
            .iter()
            .position(|record| record.id == succeeded.id())
            .unwrap();
        let record = section.records.remove(at);
        section.tombstones.push(record.tombstone());
    });
    let compacted = view(&fx, succeeded.id());
    assert_eq!(
        compacted,
        OperationProjection {
            business_id: decided.business_id.clone(),
            state: OperationState::Succeeded,
            compacted: true,
            attempts: Vec::new(),
            last_transition: None,
            hold: None,
            approval: None,
            result: decided.result.clone(),
        },
        "a tombstone keeps state and result with no attempts"
    );
    let after = fs::read(fx.store.path()).unwrap();
    view(&fx, succeeded.id());
    assert_eq!(
        fs::read(fx.store.path()).unwrap(),
        after,
        "projection writes nothing"
    );
    assert_ne!(bytes, after);
}

/// An operation parked by a durable approval names the approval by its
/// public nonce, and the view at a later clock reports it expired.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn operation_projection_awaiting_approval() {
    let mut fx = super::super::super::approvals::tests::Fx::new(300_000);
    let opened = fx.open();
    let status = OperationStatus::new(&fx.store, fx.fixture.profile());
    let parked = status.projection(&fx.operation).unwrap().unwrap();
    assert_eq!(parked.state, OperationState::AwaitingApproval);
    assert_eq!(
        parked.approval,
        Some(ApprovalLink {
            id: opened.record.nonce.clone(),
            state: "pending",
        })
    );
    fx.clock.set(opened.record.waiting_expires_at_ms);
    assert_eq!(
        status
            .projection(&fx.operation)
            .unwrap()
            .unwrap()
            .approval
            .unwrap()
            .state,
        "expired",
        "the exclusive waiting boundary"
    );
}

/// The selectors resolve from one read: a business id targets its latest
/// exposed hash, a hash of an earlier attempt agrees with its business id, a
/// hash of another operation refuses, an unknown or differently cased id is
/// unknown, a hash alone finds its operation or none, and an operation
/// without an exposed hash or a tombstone targets no hash.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn status_selection_matrix() {
    let (_guard, _home) = homed();
    let mut fx = Fx::new();
    let retried = projected_not_included(&mut fx, 1);
    successor_attempt(&mut fx, &retried, 2, 102);
    let other = unknown_named(&mut fx, 3);
    let prepared = fx.open_new(&request("prepared", canonical(4)));
    let (done, _) = commit_checked(&mut fx, 5, Checked::Succeeded);
    let business =
        |handle: &OperationHandle| fx.record(handle.id()).business_id.as_str().to_owned();
    let (retried_id, other_id, done_id) = (business(&retried), business(&other), business(&done));
    fx.rewrite(|wire| {
        let section = wire.operations.as_mut().unwrap();
        let at = section
            .records
            .iter()
            .position(|r| r.id == done.id())
            .unwrap();
        let record = section.records.remove(at);
        section.tombstones.push(record.tombstone());
    });

    READS.set(0);
    let latest = select(&fx, None, Some(&retried_id)).unwrap();
    assert_eq!(READS.get(), 1, "one authenticated read");
    assert_eq!(
        latest,
        StatusTarget {
            operation_id: Some(retried.id()),
            tx_hash: hex(2),
        },
        "the latest exposed attempt"
    );
    assert_eq!(
        select(&fx, Some([1 ^ 0x80; 32]), Some(&retried_id)).unwrap(),
        StatusTarget {
            operation_id: Some(retried.id()),
            tx_hash: hex(1),
        },
        "an earlier retained attempt agrees"
    );
    assert_eq!(
        select(&fx, Some([3 ^ 0x80; 32]), Some(&retried_id)),
        Err("validation.usage_error"),
        "another operation's hash"
    );
    assert_eq!(
        select(&fx, None, Some(&other_id.to_uppercase())),
        Err("operation.unknown"),
        "business ids are case-sensitive"
    );
    assert_eq!(
        select(&fx, None, Some("never-opened")),
        Err("operation.unknown")
    );
    assert_eq!(
        select(&fx, Some([3 ^ 0x80; 32]), None)
            .unwrap()
            .operation_id,
        Some(other.id())
    );
    assert_eq!(
        select(&fx, Some([0x42; 32]), None).unwrap(),
        StatusTarget {
            operation_id: None,
            tx_hash: Some(stellar_agent_core::hex::encode(&[0x42; 32])),
        },
        "an unrecorded hash keeps its lookup"
    );
    assert_eq!(
        select(&fx, None, Some("prepared")).unwrap(),
        StatusTarget {
            operation_id: Some(prepared.id()),
            tx_hash: None,
        },
        "no exposed hash, no network target"
    );
    assert_eq!(
        select(&fx, None, Some(&done_id)).unwrap(),
        StatusTarget {
            operation_id: Some(done.id()),
            tx_hash: None,
        },
        "a tombstone keeps no attempt to recover"
    );
    assert_eq!(
        select(&fx, Some([5 ^ 0x80; 32]), Some(&done_id))
            .unwrap()
            .tx_hash,
        hex(5),
        "a tombstone's result hash agrees"
    );

    for (hash, id, code) in [
        (None, None, "validation.usage_error"),
        (None, Some(""), "validation.business_id_required"),
        (None, Some("has space"), "validation.business_id_invalid"),
        (None, Some("é"), "validation.business_id_invalid"),
    ] {
        assert_eq!(
            StatusSelectors::parse(hash, id).unwrap_err().code(),
            code,
            "{id:?}"
        );
    }
}
