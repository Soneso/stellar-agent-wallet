// ── committed usage ──────────────────────────────────────────────

/// One scope-1 native usage item of `used` stroops.
fn native_usage(used: i128) -> Vec<TotalUsage> {
    vec![TotalUsage {
        scope_specificity: 1,
        bucket: "total:native".to_owned(),
        used_stroops: used,
    }]
}

/// A version 16 snapshot of the testnet fixture network at generation 1.
fn usage_wire() -> WireFile {
    WireFile {
        version: WIRE_VERSION_TOTAL_INTENTS,
        ..version_twelve()
    }
}

/// The file bytes, the committed counter, and the window key.
fn usage_state(f: &Fx) -> (Option<Vec<u8>>, Option<String>, Option<String>) {
    let (file, counter) = f.state();
    (
        file,
        counter,
        get_raw(&f.profile.policy_window_state_key_id),
    )
}

/// A settled sum of 3, a row of 2, a persisted hold of 1, and a closed
/// intent of 2 give 8 for native. A later clock keeps the unswept expired
/// hold; only the committed sweep removes it, giving 7. An issued asset's
/// settled sum of 4 reports under its own contract bucket. Another scope and
/// digest stay apart.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn total_usage_counts_every_persisted_source() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("usage-sources");
    f.pin(D1);
    let issuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    let issued_contract = stellar_agent_core::asset_id::CanonicalAsset::Classic {
        code: "USDC".to_owned(),
        issuer: issuer.to_owned(),
    }
    .sac_contract_id(&f.profile.network_passphrase)
    .unwrap();
    let issued = format!("total:{issued_contract}");
    let mut wire = usage_wire();
    wire.total_sums.push(WireTotalSum {
        scope_specificity: 1,
        bucket: "total:native".to_owned(),
        epoch: D1,
        amount: 3,
        settled_until_ms: T - 10,
    });
    wire.total_sums.push(WireTotalSum {
        scope_specificity: 1,
        bucket: format!("total:USDC:{issuer}"),
        epoch: D1,
        amount: 4,
        settled_until_ms: T - 10,
    });
    f.push_row(&mut wire, 2, Some(D1));
    f.push_row(&mut wire, 5, Some(D2));
    f.push_final(&mut wire, 9, "total:native", 9, D1);
    let mut holder = open_authorization(1, T + 10);
    holder.reservation = Some(holder.id);
    holder.chain = Caip2::Testnet;
    holder.profile = f.name.clone();
    wire.authorizations.push(holder);
    wire.holds.push(total_hold(1, 1, Some(D1)));
    total_intent_test_helpers::append_closed_intent(&mut wire, D1, 2, T - 5);
    f.store.seal_unchecked_for_test(&f.profile, &wire);
    let usage = |scope_specificity: u8, bucket: &str, used_stroops: i128| TotalUsage {
        scope_specificity,
        bucket: bucket.to_owned(),
        used_stroops,
    };
    let expected = vec![
        usage(1, &issued, 4),
        usage(1, "total:native", 8),
        usage(9, "total:native", 9),
    ];
    assert_eq!(f.store.total_usage(&f.profile, D1).unwrap(), expected);
    let before = usage_state(&f);
    f.clock.set(T + 1_000_000);
    assert_eq!(
        f.store.total_usage(&f.profile, D1).unwrap(),
        expected,
        "an unswept expired hold still counts"
    );
    assert_eq!(usage_state(&f), before, "the read commits no sweep");
    let mut swept = f.wire();
    assert!(ledger::sweep_expired(&mut swept, T + 1_000_000));
    swept.generation += 1;
    f.store.seal_unchecked_for_test(&f.profile, &swept);
    let expected = vec![
        usage(1, &issued, 4),
        usage(1, "total:native", 7),
        usage(9, "total:native", 9),
    ];
    assert_eq!(f.store.total_usage(&f.profile, D1).unwrap(), expected);
}

/// A crash between the prepared write and the counter write leaves both
/// images; usage reads the committed side, and the successor once the
/// counter names it, so one debit counts exactly once.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn total_usage_reads_the_committed_side() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    for (seam, expected) in [
        (COMMIT_FAULT_AFTER_PREPARED, 6),
        (COMMIT_FAULT_AFTER_COUNTER, 10),
        (COMMIT_FAULT_COMPACTION, 10),
    ] {
        let f = fx(&format!("usage-seam-{seam}"));
        f.pin(D1);
        f.authorized(&[f.total(6, D1)]).unwrap();
        let fault = arm_accounting_fault(seam);
        let result = f
            .store
            .admit_signed_intent(&f.profile, &total_plan(1, &[f.total(4, D1)]))
            .map(drop);
        drop(fault);
        assert_eq!(result.is_ok(), seam == COMMIT_FAULT_COMPACTION, "{seam}");
        assert_eq!(
            f.store.total_usage(&f.profile, D1).unwrap(),
            native_usage(expected),
            "seam {seam}"
        );
    }
}

/// A sum that overflows reports no use, typed, never zero.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn total_usage_overflow_is_unavailable() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let f = fx("usage-overflow");
    f.pin(D1);
    let mut wire = usage_wire();
    f.push_row(&mut wire, i128::MAX, Some(D1));
    f.push_row(&mut wire, 1, Some(D1));
    f.store.seal_unchecked_for_test(&f.profile, &wire);
    let error = f.store.total_usage(&f.profile, D1).unwrap_err();
    assert!(
        matches!(
            &error,
            TotalUsageError::Unavailable(WindowStoreError::Invalid { detail })
                if detail == "a total-budget sum overflows"
        ),
        "{error:?}"
    );
    assert_eq!(error.code(), "policy.window_state_unverifiable");
}

/// Unknown history never reads as zero: no pin, a missing lock, another
/// pinned digest, an earlier build's history, a retired digest, and corrupt
/// bytes each refuse typed. Only a pin with no store reports no use. No read
/// creates or changes a file, a key, or the counter.
#[test]
#[serial(mainnet_clock)]
#[serial]
fn total_usage_refuses_unknown_history() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let code = |f: &Fx| {
        let before = usage_state(f);
        let listing: Vec<_> = fs::read_dir(f.store.path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        let result = f.store.total_usage(&f.profile, D1);
        assert_eq!(usage_state(f), before);
        let after: Vec<_> = fs::read_dir(f.store.path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(after, listing);
        result.map_err(|error| error.code())
    };
    let f = fx("usage-absent");
    assert_eq!(code(&f), Err("policy.pin_absent"));
    f.pin(D1);
    assert_eq!(code(&f), Ok(Vec::new()), "a pin with no store has no use");
    fs::remove_file(stellar_agent_core::policy::state_lock::window_lock_path(
        &f.store.path,
        &f.profile.policy_window_state_key_id,
    ))
    .unwrap();
    assert_eq!(code(&f), Err("policy.pin_absent"), "a missing lock");

    let f = fx("usage-stale");
    f.pin(D2);
    f.store.seal_unchecked_for_test(&f.profile, &usage_wire());
    assert_eq!(code(&f), Err("policy.total_epoch_stale"));

    let f = fx("usage-legacy");
    f.pin(D1);
    f.earlier_build_file();
    assert_eq!(code(&f), Err("policy.total_epoch_retired"));

    let f = fx("usage-retired");
    f.pin(D1);
    let mut wire = usage_wire();
    wire.retired_total_epoch = Some(D1);
    f.store.seal_unchecked_for_test(&f.profile, &wire);
    assert_eq!(code(&f), Err("policy.total_epoch_retired"));

    let f = fx("usage-corrupt");
    f.pin(D1);
    f.store.seal_unchecked_for_test(&f.profile, &usage_wire());
    fs::write(&f.store.path, b"{").unwrap();
    assert_eq!(code(&f), Err("policy.window_state_unverifiable"));
    assert!(matches!(
        f.store.total_usage(&f.profile, D1),
        Err(TotalUsageError::State(_))
    ));
}

/// Each failure class keeps its own code: the chain codes, the pin and lock
/// codes, and `policy.window_state_unverifiable` for a keyring or I/O failure
/// of the authenticated read.
#[test]
fn total_usage_codes_name_each_failure_class() {
    use stellar_agent_core::policy::PolicyError;
    for (error, code) in [
        (
            TotalUsageError::State(WindowStoreError::ChainMismatch),
            "policy.window_chain_mismatch",
        ),
        (
            TotalUsageError::State(WindowStoreError::ChainUnverifiable),
            "policy.window_chain_unverifiable",
        ),
        (
            TotalUsageError::Policy(PolicyError::PinUnusable {
                detail: "unreadable".to_owned(),
            }),
            "policy.pin_unusable",
        ),
        (
            TotalUsageError::Policy(PolicyError::StateLockIo {
                kind: std::io::ErrorKind::PermissionDenied,
            }),
            "policy.state_lock_io",
        ),
        (
            TotalUsageError::State(WindowStoreError::Keyring {
                detail: "unavailable".to_owned(),
            }),
            "policy.window_state_unverifiable",
        ),
        (
            TotalUsageError::State(WindowStoreError::Io {
                kind: std::io::ErrorKind::PermissionDenied,
            }),
            "policy.window_state_unverifiable",
        ),
    ] {
        assert_eq!(error.code(), code, "{error:?}");
    }
}
