// Unlisted-recipient admission on the mainnet mint. Included by the ledger
// tests; it uses their `Ledger` fixture.

use crate::policy_state::store::commit_faults::{
    COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, arm_accounting_fault,
};
use stellar_agent_core::policy::DenyReason;

/// The unattended allowance of the fixture's unlisted budget, per day.
const ALLOWANCE: i128 = 10;
/// The fixture's total budget.
const TOTAL: i128 = 100;

/// An unlisted entry of `amount` in `bucket` at `ts_ms`.
fn unlisted_at(bucket: &str, ts_ms: u64, amount: i128) -> WindowEntry {
    WindowEntry::new(
        state_key(bucket),
        ts_ms,
        amount,
        WindowLimit::Unlisted {
            asset: "native".to_owned(),
            window: "1d".to_owned(),
            max_stroops: ALLOWANCE,
        },
    )
}

fn unlisted(amount: i128) -> WindowEntry {
    unlisted_at("unlisted:native", T0, amount)
}

fn total(amount: i128) -> WindowEntry {
    WindowEntry::new(
        StateKey::new("ledger", 1, "total:native", 0),
        T0,
        amount,
        WindowLimit::Total {
            asset: "native".to_owned(),
            max_stroops: TOTAL,
        },
    )
    .with_epoch(Some([7; 32]))
}

/// The holds of one unlisted payment: its allowance, the amount cap, and
/// the total budget.
fn payment(amount: i128) -> Vec<WindowEntry> {
    vec![unlisted(amount), hold(amount), total(amount)]
}

/// The amount the stored holds reserve in `bucket`.
fn held(l: &Ledger, bucket: &str) -> i128 {
    l.wire()
        .holds
        .iter()
        .filter(|h| h.bucket == bucket)
        .map(|h| h.amount)
        .sum()
}

/// The amounts held in the unlisted, amount, and total buckets.
fn held_everywhere(l: &Ledger) -> [i128; 3] {
    [
        held(l, "unlisted:native"),
        held(l, "native"),
        held(l, "total:native"),
    ]
}

fn policy(l: &Ledger, binding: DomainBinding, holds: Vec<WindowEntry>) -> MintRequest {
    under_policy(l.request(binding, holds), T0 + APPROVAL_MS)
}

fn approval_required<T>(result: Result<T, WindowStoreError>) -> bool {
    matches!(
        result.err(),
        Some(WindowStoreError::UnlistedApprovalRequired)
    )
}

fn denied_by<T>(result: Result<T, WindowStoreError>, reason: fn(&DenyReason) -> bool) -> bool {
    match result.err() {
        Some(WindowStoreError::PolicyDenied { reason: denial }) => reason(&denial),
        _ => false,
    }
}

/// A verified approval lets a mint pass the spent allowance, holding the
/// full debit in every bucket; a policy authority gets approval-needed with
/// nothing written; and an approval never lifts a per-period cap or the
/// total budget.
#[test]
#[serial]
fn approved_unlisted_spend_is_counted_and_never_bypasses_hard_caps() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::with_approvals();
    l.mint(&policy(&l, tx(1), payment(6))).unwrap();
    assert_eq!(held_everywhere(&l), [6, 6, 6]);

    let before = l.bytes();
    assert!(approval_required(l.mint(&policy(&l, tx(2), payment(6)))));
    assert_eq!(l.bytes(), before, "approval-needed writes nothing");

    let approved = l.approved(tx(2), payment(6));
    let minted = l.mint(&approved).unwrap();
    assert_eq!(held_everywhere(&l), [12, 12, 12]);
    assert_eq!(
        l.record(minted.id).approval_nonce.as_ref(),
        Some(approved.authority.nonce())
    );

    // The amount cap of 1000 and the total budget of 100 still refuse.
    let over_cap = l.approved(tx(3), vec![unlisted(1), hold(CAP - 11), total(1)]);
    let over_total = l.approved(tx(4), payment(TOTAL - 11));
    let before = l.bytes();
    assert!(denied_by(l.mint(&over_cap), |r| matches!(
        r,
        DenyReason::PerPeriodCapExceeded { .. }
    )));
    assert!(denied_by(l.mint(&over_total), |r| matches!(
        r,
        DenyReason::TotalBudgetExhausted { .. }
    )));
    assert_eq!(l.bytes(), before, "a hard-cap refusal writes nothing");

    // The refused approval stays unused and mints once its holds fit.
    let mut retry = l.request(tx(4), payment(TOTAL - 12));
    retry.authority = over_total.authority.clone();
    retry.approval_operation = over_total.approval_operation;
    l.mint(&retry).unwrap();
    assert_eq!(held_everywhere(&l), [TOTAL, TOTAL, TOTAL]);
}

/// Two handles on one store: both start from the same file, the first mints
/// 6 of the allowance of 10, and the second's policy mint of 6 finds the
/// allowance spent under the lock. The window lock is the only lock the
/// mint takes; no approval is obtained under it.
#[test]
#[serial]
fn unlisted_stale_allow_loses_to_approval_requirement() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    let second = PersistedWindowStore::at_path(l.store.path().to_path_buf());
    let first = policy(&l, tx(1), payment(6));
    let stale = policy(&l, tx(2), payment(6));
    l.mint(&first).unwrap();
    assert!(approval_required(
        second.mint_authorization(&l.profile, &stale)
    ));
    assert_eq!(held_everywhere(&l), [6, 6, 6]);
    assert_eq!(l.wire().authorizations.len(), 1);
}

/// Repeats: the nonce of a successful approved mint refuses a second use
/// with one hold kept; an approval-needed refusal repeats unchanged; a new
/// approval then mints once.
#[test]
#[serial]
fn approved_unlisted_replay() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::with_approvals();
    let approved = l.approved(tx(1), payment(12));
    l.mint(&approved).unwrap();
    let mut replay = l.request(tx(2), payment(1));
    replay.authority = approved.authority.clone();
    assert_eq!(
        refusal(l.mint(&replay)),
        MainnetPrecondition::ApprovalNonceReused
    );
    assert_eq!(held_everywhere(&l), [12, 12, 12]);

    let needs = policy(&l, tx(3), payment(1));
    let before = l.bytes();
    for _ in 0..2 {
        assert!(approval_required(l.mint(&needs)));
        assert_eq!(l.bytes(), before);
    }
    l.mint(&l.approved(tx(3), payment(1))).unwrap();
    assert_eq!(held_everywhere(&l), [13, 13, 13]);
}

/// The store at its open-authorization limit: expired authorizations are
/// swept and an approved over-allowance mint is admitted. At sixteen live
/// ones it refuses without consuming the approval, and an approval-needed
/// refusal takes no capacity.
#[test]
#[serial]
fn approved_unlisted_mint_at_capacity() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::with_approvals();
    l.mint(&policy(&l, tx(1), payment(ALLOWANCE))).unwrap();
    for n in 0..15u8 {
        l.mint(&l.request(message(n), vec![])).unwrap();
    }
    l.clock.set(T0 + TTL_MS);
    let live: Vec<MintedRecord> = (15..30u8)
        .map(|n| l.mint(&l.request(message(n), vec![])).unwrap())
        .collect();
    let approved = l.approved(tx(2), payment(ALLOWANCE + 1));
    l.mint(&approved).unwrap();
    assert_eq!(
        held(&l, "unlisted:native"),
        ALLOWANCE + 1,
        "the expired holds are released"
    );

    let open = || {
        l.wire()
            .authorizations
            .iter()
            .filter(|a| a.state.holds())
            .count()
    };
    assert_eq!(open(), MAX_OPEN_AUTHORIZATIONS);
    l.store
        .invalidate_authorization(&l.profile, live[0].id, "make room")
        .unwrap();
    assert!(approval_required(l.mint(&policy(
        &l,
        tx(3),
        payment(ALLOWANCE)
    ))));
    assert_eq!(
        open(),
        MAX_OPEN_AUTHORIZATIONS - 1,
        "approval-needed takes no capacity"
    );
    l.mint(&l.approved(tx(4), payment(ALLOWANCE))).unwrap();
    let full = l.approved(tx(5), payment(1));
    assert_eq!(refusal(l.mint(&full)), MainnetPrecondition::TooManyOpen);
    l.store
        .invalidate_authorization(&l.profile, live[1].id, "make room")
        .unwrap();
    l.mint(&full).unwrap();
}

/// A crash at each durable write of the approved mint, then a restart:
/// before the counter the old image wins and a retry mints once; after it
/// the new image wins and a retry refuses as a duplicate. The hold, the
/// authorization and the approval's use share one generation.
#[test]
#[serial]
fn approved_unlisted_mint_crash_matrix() {
    for point in [
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        crate::policy_state::store::COMMIT_FAULT_COMPACTION,
    ] {
        let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _storage_home =
            stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
        let l = Ledger::with_approvals();
        l.mint(&policy(&l, tx(1), payment(6))).unwrap();
        let approved = l.approved(tx(2), payment(6));
        {
            let _fault = arm_accounting_fault(point);
            let result = l.mint(&approved);
            if point == crate::policy_state::store::COMMIT_FAULT_COMPACTION {
                assert!(
                    result.is_ok(),
                    "optional compaction retains the committed result"
                );
            } else {
                assert!(
                    matches!(result, Err(WindowStoreError::Io { .. })),
                    "{point}"
                );
            }
        }
        let restarted = Ledger {
            store: PersistedWindowStore::at_path(l.store.path().to_path_buf()),
            ..l
        };
        let mut replay = restarted.request(tx(3), payment(1));
        replay.authority = approved.authority.clone();
        if point == COMMIT_FAULT_AFTER_PREPARED {
            assert_eq!(held_everywhere(&restarted), [6, 6, 6], "{point}");
            assert_eq!(restarted.wire().authorizations.len(), 1, "{point}");
            restarted.mint(&approved).unwrap();
        }
        assert_eq!(held_everywhere(&restarted), [12, 12, 12], "{point}");
        assert_eq!(restarted.wire().authorizations.len(), 2, "{point}");
        assert_eq!(
            refusal(restarted.mint(&approved)),
            MainnetPrecondition::DuplicateOpen,
            "{point}"
        );
        assert_eq!(
            refusal(restarted.mint(&replay)),
            MainnetPrecondition::ApprovalNonceReused,
            "{point}"
        );
    }
}

/// Rows a build stored under two spellings of one asset, one of them the
/// classic text of an earlier build, count in the bucket the evaluation
/// keys. Their stored bytes stay unchanged on read and hydration.
#[test]
#[serial]
fn unlisted_legacy_rows_keep_lifecycle() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    let classic = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".to_owned();
    let contract = stellar_agent_core::asset_id::CanonicalAsset::parse_threshold_key(&classic)
        .unwrap()
        .sac_contract_id(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
        .unwrap();
    let legacy = format!("unlisted:{classic}");
    let canonical = format!("unlisted:{contract}");
    l.store
        .record_and_persist(&l.profile, &[unlisted_at(&legacy, T0, 5)])
        .unwrap();
    let stored = l.bytes();
    let memory = PolicyStateStore::new();
    l.store.load_into("ledger", &l.profile, &memory).unwrap();
    assert_eq!(l.bytes(), stored, "hydration rewrites nothing");
    assert_eq!(
        memory.query_window(&state_key(&canonical), T0).unwrap(),
        (5, 1)
    );
    assert!(approval_required(l.mint(&policy(
        &l,
        tx(1),
        vec![unlisted_at(&canonical, T0, 6)]
    ))));
    l.mint(&policy(&l, tx(1), vec![unlisted_at(&canonical, T0, 5)]))
        .unwrap();
    assert!(l.wire().entries.iter().any(|b| b.bucket == legacy));
    l.pin(8, [8; 32]);
    let mut resigned = policy(&l, tx(2), vec![unlisted_at(&legacy, T0, 1)]);
    resigned.policy_sequence = 8;
    resigned.policy_digest = [8; 32];
    if let MintAuthority::Policy(authority) = &mut resigned.authority {
        authority.policy_sequence = 8;
        authority.policy_digest = [8; 32];
    }
    assert!(
        approval_required(l.mint(&resigned)),
        "re-signing an alias does not refill rolling allowance"
    );
    let id = l.wire().authorizations[0].id;
    l.store
        .invalidate_authorization(&l.profile, id, "unused")
        .unwrap();
    assert_eq!(
        l.record(id).state,
        AuthorizationState::Invalidated,
        "legacy alias keeps revocation"
    );
    l.mint(&resigned).unwrap();
}

#[test]
#[serial]
fn unlisted_pending_future_skew_refuses_admission() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let l = Ledger::new();
    sealed_reservation(&l, &[5]);
    l.clock.set(T0 - 3_600_000);
    let request = l.request(
        tx(1),
        vec![unlisted_at("unlisted:native", T0 - 3_600_000, 0)],
    );
    let before = l.bytes();
    assert!(
        denied_by(l.mint(&request), |reason| matches!(
            reason,
            DenyReason::EvaluationError { .. }
        )),
        "pending future timestamps refuse before allowance admission"
    );
    assert_eq!(l.bytes(), before);
    l.clock.set(T0);
    let mut refreshed = request;
    refreshed.holds = vec![unlisted(0)];
    l.mint(&refreshed).unwrap();
}

#[test]
#[serial]
fn unlisted_malformed_file_admission_refuses() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let l = Ledger::new();
    l.mint(&policy(&l, tx(1), vec![unlisted(1)])).unwrap();
    let mut wire = l.wire();
    wire.authorizations.push(wire.authorizations[0].clone());
    seal_floor(&l, wire);
    let bytes = l.bytes();
    assert!(
        malformed_floor(&l.mint(&policy(&l, tx(2), vec![unlisted(1)])).unwrap_err()),
        "duplicate authorization refuses admission"
    );
    assert_eq!(l.bytes(), bytes);
}

#[test]
#[serial]
fn unlisted_descriptor_and_engine_key_share_durable_bucket() {
    use stellar_agent_core::policy::v1::criteria::Criterion;
    use stellar_agent_core::policy::v1::criteria::counterparty_allowlist::{
        CounterpartyAllowlistCriterion, CounterpartyKind, UnlistedBudget, UnlistedMode,
    };
    use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let l = Ledger::new();
    let classic = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    let criterion = CounterpartyAllowlistCriterion::new(vec![CounterpartyKind::GAccount], vec![])
        .with_unlisted(UnlistedMode::Budget(UnlistedBudget::new(
            classic.to_owned(),
            10,
            10,
            Window::parse("1d").unwrap(),
        )));
    let described = criterion
        .descriptors()
        .into_iter()
        .find_map(|descriptor| descriptor.state_key("ledger"))
        .unwrap();
    let canonical = format!(
        "unlisted:{}",
        stellar_agent_core::policy::v1::asset_equivalence::total_budget_identity(
            classic,
            Caip2::Mainnet.network_passphrase()
        )
    );
    l.store
        .record_and_persist(&l.profile, &[unlisted_at(&canonical, T0, 6)])
        .unwrap();
    assert!(
        approval_required(l.mint(&policy(
            &l,
            tx(1),
            vec![unlisted_at(described.bucket(), T0, 5)]
        ))),
        "descriptor and canonical engine key spend the same allowance"
    );
}

/// Rows under two spellings across a restart with the clock earlier than
/// the newest row and far past the window: confirmed rows count until the
/// window passes, and the allowance then admits unattended payments again.
#[test]
#[serial]
fn unlisted_canonical_window_under_clock_shift() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    let native_sac = stellar_agent_core::asset_id::CanonicalAsset::Native
        .sac_contract_id(stellar_agent_core::profile::caip2::MAINNET_PASSPHRASE)
        .unwrap();
    l.store
        .record_and_persist(
            &l.profile,
            &[
                unlisted_at("unlisted:native", T0, 3),
                unlisted_at(&format!("unlisted:{native_sac}"), T0 + 1_000, 4),
            ],
        )
        .unwrap();
    let hydrated = |now| {
        let memory = PolicyStateStore::new();
        l.store.load_into("ledger", &l.profile, &memory).unwrap();
        memory
            .query_window(&state_key("unlisted:native"), now)
            .unwrap()
    };
    assert!(approval_required(l.mint(&policy(
        &l,
        tx(1),
        vec![unlisted_at("unlisted:native", T0, 4)]
    ))));
    l.clock.set(T0 - 3_600_000);
    assert_eq!(hydrated(T0 - 3_600_000), (7, 2));
    let later = T0 + 2 * 86_400_000;
    l.clock.set(later);
    assert_eq!(hydrated(later), (0, 0));
    l.mint(&under_policy(
        l.request(
            tx(2),
            vec![unlisted_at("unlisted:native", later, ALLOWANCE)],
        ),
        later + APPROVAL_MS,
    ))
    .unwrap();
}

/// Unrepresentable or negative unlisted sums refuse typed before any write:
/// stored rows, holds and a batch at i128 bounds, and a negative stored
/// amount. A zero debit adds no amount.
#[test]
#[serial]
fn unlisted_store_sums_refuse() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::with_approvals();
    let overflow = |result: Result<MintedRecord, WindowStoreError>| {
        matches!(result, Err(WindowStoreError::AccountingOverflow))
    };
    // A batch whose two entries overflow.
    let batch = l.approved(tx(1), vec![unlisted(i128::MAX), unlisted(1)]);
    assert!(overflow(l.mint(&batch)));
    // A held amount at i128::MAX and one stroop more.
    l.mint(&l.approved(tx(2), vec![unlisted(i128::MAX)]))
        .unwrap();
    let more = l.approved(tx(3), vec![unlisted(1)]);
    let before = l.bytes();
    assert!(overflow(l.mint(&more)));
    assert!(approval_required(l.mint(&policy(
        &l,
        tx(4),
        vec![unlisted(0)]
    ))));
    assert_eq!(l.bytes(), before);

    let n = Ledger::new();
    n.store
        .record_and_persist(&n.profile, &[unlisted(-1)])
        .unwrap();
    let before = n.bytes();
    assert!(matches!(
        n.mint(&n.request(tx(1), vec![unlisted(1)])),
        Err(WindowStoreError::AccountingInvalid)
    ));
    assert_eq!(n.bytes(), before);
    // Hydration keeps the negative row, and a query of its bucket refuses.
    let memory = PolicyStateStore::new();
    n.store.load_into("ledger", &n.profile, &memory).unwrap();
    assert!(matches!(
        memory.query_window(&state_key("unlisted:native"), T0),
        Err(stellar_agent_core::policy::v1::criteria::state_store::StateStoreError::NegativeAmount)
    ));
}

/// Seals a file whose one reservation `r` holds `amounts` as pending rows of
/// the unlisted bucket under a one-hour window, which a day window counts as
/// one id total.
fn sealed_reservation(l: &Ledger, amounts: &[i128]) {
    l.store.record_and_persist(&l.profile, &[hold(1)]).unwrap();
    let mut wire = l.wire();
    let hour = StateKey::new("ledger", 1, "unlisted:native", 3_600);
    find_or_insert_bucket(&mut wire.entries, &hour)
        .records
        .extend(amounts.iter().map(|amount| WireRecord {
            id: "r".to_owned(),
            amount: *amount,
            status: RecordStatus::Pending,
            ts_ms: T0,
            chain_scope: Some(crate::policy_state::ChainScope::for_chain(Caip2::Mainnet)),
            ..WireRecord::confirmed_defaults()
        }));
    wire.generation += 1;
    l.store.seal_unchecked_for_test(&l.profile, &wire);
}

/// A negative row among one reservation's rows under another window refuses
/// typed, though the reservation's total is positive.
#[test]
#[serial]
fn unlisted_hidden_negative_row_refuses() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    sealed_reservation(&l, &[5, -3]);
    let before = l.bytes();
    assert!(matches!(
        l.mint(&policy(&l, tx(1), vec![unlisted(1)])),
        Err(WindowStoreError::AccountingInvalid)
    ));
    assert_eq!(l.bytes(), before);
}

/// One reservation's rows under another window that overflow their sum
/// refuse typed, even for a zero debit under approval.
#[test]
#[serial]
fn unlisted_overflowing_reservation_sum_refuses() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let l = Ledger::new();
    sealed_reservation(&l, &[i128::MAX, 1]);
    let before = l.bytes();
    assert!(matches!(
        l.mint(&l.request(tx(1), vec![unlisted(0)])),
        Err(WindowStoreError::AccountingOverflow)
    ));
    assert_eq!(l.bytes(), before);
}
