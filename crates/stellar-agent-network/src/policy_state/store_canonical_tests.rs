#[test]
#[serial(mainnet_clock)]
#[serial]
fn canonical_wire_compatibility_and_lifecycle() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let legacy: WireFile = serde_json::from_str(DESTINATION_LEGACY_BODY).unwrap();
    assert_eq!(
        serde_json::to_string(&legacy).unwrap(),
        DESTINATION_LEGACY_BODY,
        "legacy vector stays byte-identical"
    );
    assert!(
        legacy
            .authorizations
            .iter()
            .all(|auth| auth.intent_digest.is_none() && auth.predecessor.is_none())
    );
    let (_dir, profile, store, clock) = operation_store();
    let old = store.mint_authorization(&profile, &policy_mint(1)).unwrap();
    let mut original = store.read_for_inspection(&profile).unwrap().unwrap();
    let legacy_bytes = serde_json::to_vec(&original.authorizations[0]).unwrap();
    original.version = WIRE_VERSION_TOTAL_INTENTS;
    strip_native_coverage_for_test(&mut original);
    store.seal_unchecked_for_test(&profile, &original);
    let mut audit = OperationRows::default();
    let handle = open_operation(&store, &profile, &mut audit, "canonical", 2);
    let mut mint = policy_mint(2);
    mint.intent_digest = Some([2; 32]);
    mint.operation = Some(operations::OperationLink {
        operation_id: handle.id(),
        attempt_index: 1,
    });
    let minted = store.mint_authorization(&profile, &mint).unwrap();
    let wire = store.read_for_inspection(&profile).unwrap().unwrap();
    assert_eq!(
        wire.version, WIRE_VERSION_NATIVE_COVERAGE,
        "a canonical mint carries the native coverage marker"
    );
    let mut unmarked = wire.clone();
    strip_native_coverage_for_test(&mut unmarked);
    assert_eq!(
        select_wire_version(&unmarked, Some(WIRE_VERSION_TOTAL_INTENTS)),
        WIRE_VERSION_CANONICAL_LINEAGE,
        "canonical mint selects version 17"
    );
    assert_eq!(
        serde_json::to_vec(
            wire.authorizations
                .iter()
                .find(|auth| auth.id == old.id)
                .unwrap()
        )
        .unwrap(),
        legacy_bytes,
        "legacy authorization stays byte-identical after commit"
    );
    let auth = wire
        .authorizations
        .iter()
        .find(|auth| auth.id == minted.id)
        .unwrap();
    assert_eq!(auth.intent_digest, Some([2; 32]));
    assert_eq!(auth.predecessor, None, "missing predecessor is absent");
    let encoded = serde_json::to_string(auth).unwrap();
    assert!(!encoded.contains("predecessor"));
    let malformed = |error: WindowStoreError| {
        #[cfg(feature = "mainnet-write")]
        {
            matches!(
                error,
                WindowStoreError::MainnetStateUnverifiable {
                    defect: StateDefect::Malformed
                }
            )
        }
        #[cfg(not(feature = "mainnet-write"))]
        {
            matches!(error, WindowStoreError::Invalid { .. })
        }
    };
    for field in ["intent_digest", "predecessor"] {
        let mut earlier = wire.clone();
        earlier.version = WIRE_VERSION_TOTAL_INTENTS;
        strip_native_coverage_for_test(&mut earlier);
        let auth = earlier
            .authorizations
            .iter_mut()
            .find(|auth| auth.id == minted.id)
            .unwrap();
        auth.intent_digest = (field == "intent_digest").then_some([2; 32]);
        auth.predecessor = (field == "predecessor").then_some(old.id);
        assert!(
            matches!(
                check_snapshot(&earlier),
                Err(WindowStoreError::Invalid { .. })
            ),
            "version gate returns Invalid for {field}"
        );
        store.seal_unchecked_for_test(&profile, &earlier);
        assert!(
            malformed(store.read_for_inspection(&profile).unwrap_err()),
            "version 16 refuses {field}"
        );
    }
    for field in ["intent_digest", "predecessor", "unknown"] {
        let extra = match field {
            "intent_digest" => format!("\"intent_digest\":\"{}\",", "02".repeat(32)),
            "predecessor" => format!(
                "\"predecessor\":\"{}\",\"predecessor\":\"{}\",",
                old.id.to_hex(),
                old.id.to_hex()
            ),
            _ => "\"unknown_lineage\":true,".to_owned(),
        };
        let changed = encoded.replacen('{', &format!("{{{extra}"), 1);
        let raw = serde_json::to_string(&wire)
            .unwrap()
            .replace(&encoded, &changed);
        let (key, _) = store.load_or_mint_key(&profile).unwrap();
        store
            .write_atomic_raw(
                &compute_tag(key.as_ref(), raw.as_bytes()).unwrap(),
                raw.as_bytes(),
            )
            .unwrap();
        assert!(
            malformed(store.read_for_inspection(&profile).unwrap_err()),
            "duplicate or unknown lineage refuses: {field}"
        );
    }
    store.seal_unchecked_for_test(&profile, &wire);
    clock.set(now_ms().unwrap() + 20 * 86_400_000);
    operations::OperationRecorder::new(&store, &profile, &mut audit, "expire")
        .expire_due(now_ms().unwrap())
        .unwrap();
    clock.set(now_ms().unwrap() + 20 * 86_400_000);
    store.record_and_persist(&profile, &[]).unwrap();
    let collected = store.read_for_inspection(&profile).unwrap().unwrap();
    assert!(
        collected.authorizations.is_empty(),
        "expired authorizations are collected"
    );
    assert_eq!(
        collected.version, WIRE_VERSION_NATIVE_COVERAGE,
        "collection retains the version floor"
    );
    let mut unmarked = collected.clone();
    strip_native_coverage_for_test(&mut unmarked);
    assert_eq!(
        select_wire_version(&unmarked, Some(WIRE_VERSION_CANONICAL_LINEAGE)),
        WIRE_VERSION_CANONICAL_LINEAGE,
        "collection retains the version floor"
    );
}
