/// Commits the window's first write early enough that the native coverage
/// marker it establishes covers every observation within the 120 s age bound
/// at `T0`, then returns the clock to `T0`.
fn cover(fx: &Fx) {
    fx.clock
        .set(T0 - 125_000 - super::super::store::ESTABLISHMENT_ALLOWANCE_MS);
    fx.store.record_and_persist(&fx.profile, &[]).unwrap();
    fx.clock.set(T0);
}

fn observed_floor_sum(fx: &Fx) -> Result<u64, WindowStoreError> {
    OperationStatus::new(&fx.store, &fx.profile).floor_reserved_stroops(Some(WindowObservation {
        ledger: 100,
        close_time_floor_ms: T0 - 5_000,
        observed_at_ms: T0,
    }))
}

#[test]
#[serial]
fn floor_non_native_zero_requires_bound_provenance() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    cover(&fx);
    let mut intent = x402_intent("100");
    intent.payer = stellar_strkey::ed25519::PublicKey([2; 32])
        .to_string()
        .to_string();
    intent.asset = stellar_strkey::Contract([3; 32]).to_string().to_string();
    let open = request(
        "floor-zero",
        IntentSlot::X402 {
            intent_digest: [6; 32],
            intent,
        },
    );
    let handle = fx.open_new(&open);
    let mut mint = fx.mint_request(soroban(6), fx.fresh_policy(), vec![]);
    mint.native_reservation = Some(super::super::ledger::NativeReservation::default());
    fx.begin_mint(&handle, &mint).unwrap();
    let before = fs::read(fx.store.path()).unwrap();
    assert_eq!(
        observed_floor_sum(&fx).unwrap(),
        0,
        "bound non-native zero is quantifiable"
    );
    assert_eq!(fs::read(fx.store.path()).unwrap(), before);
    fx.rewrite(|wire| {
        let IntentSlot::X402 { intent, .. } =
            &mut wire.operations.as_mut().unwrap().records[0].intent
        else {
            panic!("x402")
        };
        intent.asset = stellar_agent_core::asset_id::CanonicalAsset::Native
            .sac_contract_id(Caip2::Mainnet.network_passphrase())
            .unwrap();
    });
    assert!(
        matches!(observed_floor_sum(&fx), Err(WindowStoreError::PolicyDenied { reason })
        if matches!(*reason, stellar_agent_core::policy::DenyReason::AccountUnread)),
        "native SAC zero remains ambiguous"
    );
}

#[test]
#[serial]
fn floor_operation_commit_and_audit_matrix() {
    use super::super::store::{
        COMMIT_FAULT_AFTER_COUNTER, COMMIT_FAULT_AFTER_PREPARED, COMMIT_FAULT_COMPACTION,
        arm_accounting_fault,
    };
    for point in [
        0,
        255,
        COMMIT_FAULT_AFTER_PREPARED,
        COMMIT_FAULT_AFTER_COUNTER,
        COMMIT_FAULT_COMPACTION,
    ] {
        let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
        let mut fx = Fx::new();
        cover(&fx);
        let open = request("floor-operation", canonical(1));
        let handle = fx.open_new(&open);
        let mut mint =
            fx.operation_mint_request(&handle, tx(1), fx.fresh_policy(), vec![hold(50)]);
        mint.native_reservation = Some(super::super::ledger::NativeReservation {
            debit_stroops: 50,
            fee_stroops: 0,
        });
        mint.floor = Some(super::super::accounting::CheckedFloor::for_test(
            &mint, "ops", T0, 100,
        ));
        let before = fs::read(fx.store.path()).unwrap();
        let audit_before = fx.sink.entries.len();
        fx.sink.fail = point == 0;
        let result = {
            let _write_failure = (point == 255).then(super::super::store::fail_store_writes);
            let _fault = (point != 0 && point != 255).then(|| arm_accounting_fault(point));
            fx.begin_mint(&handle, &mint)
        };
        assert_eq!(
            result.is_ok(),
            point == COMMIT_FAULT_COMPACTION,
            "returned authorization at {point}"
        );
        assert_eq!(
            fx.sink.entries.len(),
            audit_before + 2 * usize::from(point != 0),
            "the mint and operation audit entries precede the prepared image"
        );
        if point == 255 {
            assert!(matches!(result, Err(WindowStoreError::Io { .. })));
            assert_eq!(
                fs::read(fx.store.path()).unwrap(),
                before,
                "failure after audit preserves the prior image"
            );
        }
        if point == 0 {
            assert!(matches!(
                result,
                Err(WindowStoreError::AuditAppendFailed { .. })
            ));
            assert_eq!(
                fs::read(fx.store.path()).unwrap(),
                before,
                "audit failure commits nothing"
            );
        }
        let committed = point == COMMIT_FAULT_AFTER_COUNTER || point == COMMIT_FAULT_COMPACTION;
        assert_eq!(
            observed_floor_sum(&fx).unwrap(),
            if committed { 50 } else { 0 },
            "operation generation at {point}"
        );
        assert_eq!(
            fx.record(handle.id()).attempts.len(),
            usize::from(committed)
        );
        if !committed {
            fx.sink.fail = false;
            fx.begin_mint(&handle, &mint).unwrap();
        }
        assert_eq!(observed_floor_sum(&fx).unwrap(), 50, "retry reserves once");
        match fx.open(&open).unwrap() {
            OpenOutcome::Replay(replay) => assert_eq!(
                replay.operation_id,
                handle.id(),
                "same business identity is retained"
            ),
            other => panic!("expected retained sending operation, got {other:?}"),
        }
        assert_eq!(fx.wire().authorizations.len(), 1);
    }
}

#[test]
#[serial]
fn floor_operation_refusal_leaves_audit_and_attempt_unchanged() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    cover(&fx);
    let handle = fx.open_new(&request("floor-refusal", canonical(1)));
    let mut mint = fx.operation_mint_request(&handle, tx(1), fx.fresh_policy(), vec![hold(50)]);
    mint.native_reservation = Some(super::super::ledger::NativeReservation {
        debit_stroops: 50,
        fee_stroops: 0,
    });
    mint.floor = Some(super::super::accounting::CheckedFloor::for_test(
        &mint, "ops", T0, 69,
    ));
    let before = fs::read(fx.store.path()).unwrap();
    let audit = fx.sink.entries.len();
    for _ in 0..2 {
        let result = fx.begin_mint(&handle, &mint);
        assert!(
            matches!(result, Err(WindowStoreError::PolicyDenied { reason })
            if matches!(*reason, stellar_agent_core::policy::DenyReason::AccountFloorRefused { balance_after_stroops: 19, .. })),
            "operation floor refusal"
        );
        assert_eq!(fx.sink.entries.len(), audit);
        assert_eq!(fs::read(fx.store.path()).unwrap(), before);
    }
    mint.floor = Some(super::super::accounting::CheckedFloor::for_test(
        &mint, "ops", T0, 70,
    ));
    fx.begin_mint(&handle, &mint).unwrap();
    assert_eq!(observed_floor_sum(&fx).unwrap(), 50);
    let before = fs::read(fx.store.path()).unwrap();
    assert!(matches!(
        fx.open(&request("floor-refusal", canonical(2))),
        Ok(OpenOutcome::Conflict)
    ));
    assert_eq!(
        fs::read(fx.store.path()).unwrap(),
        before,
        "a different intent cannot replace the retained business identity"
    );
}

#[test]
#[serial]
fn floor_duplicate_operation_identity_refuses() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    let open = request("floor-identity", canonical(1));
    fx.open_new(&open);
    let mut wire = fx.wire();
    let mut duplicate = records(&wire)[0].clone();
    duplicate.business_id = BusinessId::parse("different-business").unwrap();
    wire.operations.as_mut().unwrap().records.push(duplicate);
    wire.generation += 1;
    fx.store.seal_unchecked_for_test(&fx.profile, &wire);
    let before = fs::read(fx.store.path()).unwrap();
    for error in [
        observed_floor_sum(&fx).unwrap_err(),
        fx.open(&open).unwrap_err(),
    ] {
        #[cfg(feature = "mainnet-write")]
        let malformed = matches!(
            error,
            WindowStoreError::MainnetStateUnverifiable {
                defect: super::super::store::StateDefect::Malformed
            }
        );
        #[cfg(not(feature = "mainnet-write"))]
        let malformed = matches!(error, WindowStoreError::Invalid { .. });
        assert!(
            malformed,
            "duplicate operation id refuses every lookup: {error:?}"
        );
    }
    assert_eq!(fs::read(fx.store.path()).unwrap(), before);
}
