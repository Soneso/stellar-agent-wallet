#[cfg(feature = "mainnet-write")]
pub(crate) fn edit_canonical_fixture(store: &PersistedWindowStore, profile: &Profile, case: &str) {
    let mut wire = store.read_for_inspection(profile).unwrap().unwrap();
    let operation = &mut wire.operations.as_mut().unwrap().records[0];
    let approval = &mut wire.approvals.as_mut().unwrap().records[0];
    match case {
        "malformed" => {
            if let IntentSlot::Canonical { intent, .. } = &mut operation.intent {
                *intent = serde_json::json!({"bad": true});
            }
        }
        "digest" => {
            if let IntentSlot::Canonical { intent, .. } = &mut operation.intent {
                intent["payload"]["pay"]["amount_stroops"] = serde_json::json!("11");
            }
        }
        "unconsented" => approval.consent = None,
        "released" => approval.consent.as_mut().unwrap().payload = None,
        "envelope" => {
            approval.subject_kind =
                stellar_agent_core::approval::subject::SubjectKind::EnvelopeText;
            approval
                .consent
                .as_mut()
                .unwrap()
                .payload
                .as_mut()
                .unwrap()
                .challenge_subject = None;
        }
        _ => panic!("unknown fixture edit"),
    }
    store.seal_unchecked_for_test(profile, &wire);
}

#[cfg(feature = "mainnet-write")]
fn process_keyring(
    path: &std::path::Path,
) -> stellar_agent_test_support::keyring_mock::DefaultStoreGuard {
    use std::sync::Arc;
    stellar_agent_test_support::keyring_mock::DefaultStoreGuard::install(Arc::new(
        stellar_agent_headless_keyring::store::HeadlessStore::new(
            path.to_owned(),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new([7; 32]),
            )),
        ),
    ))
}

#[cfg(feature = "mainnet-write")]
pub(crate) fn revoke_in_child_if_requested() -> bool {
    let Ok(path) = std::env::var("STELLAR_AGENT_CANONICAL_REVOKE_TEST") else {
        return false;
    };
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let _keyring = process_keyring(std::path::Path::new(value["keyring"].as_str().unwrap()));
    let profile: Profile = serde_json::from_value(value["profile"].clone()).unwrap();
    let store =
        PersistedWindowStore::at_path(std::path::PathBuf::from(value["store"].as_str().unwrap()));
    let _clock = set_now_ms_for_test(value["now"].as_u64().unwrap());
    let id: [u8; 32] = serde_json::from_value(value["id"].clone()).unwrap();
    super::super::approvals::ApprovalRecorder::new(
        &store,
        &profile,
        &mut Sink::default(),
        "child-revoke",
    )
    .revoke(id)
    .unwrap();
    true
}

#[cfg(feature = "mainnet-write")]
pub(crate) fn revoke_in_other_process(
    store: &PersistedWindowStore,
    profile: &Profile,
    id: [u8; 32],
    test: &str,
) -> stellar_agent_test_support::keyring_mock::DefaultStoreGuard {
    let keys: Vec<_> = [&profile.policy_window_state_key_id, &generation_entry_ref(profile)]
        .into_iter().map(|key| serde_json::json!({
            "service": key.service, "account": key.account,
            "value": keyring_core::Entry::new(&key.service, &key.account).unwrap().get_password().unwrap(),
        })).collect();
    let path = store.path().with_extension("child.json");
    let backend = store.path().with_extension("keyring");
    let keyring = process_keyring(&backend);
    for key in &keys {
        keyring_core::Entry::new(
            key["service"].as_str().unwrap(),
            key["account"].as_str().unwrap(),
        )
        .unwrap()
        .set_password(key["value"].as_str().unwrap())
        .unwrap();
    }
    fs::write(&path, serde_json::to_vec(&serde_json::json!({
            "keyring": backend, "profile": profile, "store": store.path(), "now": now_ms().unwrap(), "id": id,
    })).unwrap()).unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test.split_once("::").unwrap().1, "--nocapture"])
        .env("STELLAR_AGENT_CANONICAL_REVOKE_TEST", path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "revoker process: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    keyring
}

#[test]
#[serial(mainnet_clock)]
#[serial]
fn canonical_mint_binds_the_previous_attempt() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    let handle = projected_not_included(&mut fx, 1);
    let previous = fx.record(handle.id()).attempts[0].authorization_id;
    let mut mint = fx.mint_request(tx(2), fx.policy(), vec![]);
    mint.operation = Some(OperationLink {
        operation_id: handle.id(),
        attempt_index: 2,
    });
    mint.intent_digest = Some(handle.intent().intent_digest());
    mint.predecessor = Some(previous);
    for case in ["digest", "predecessor", "predecessor-without-digest"] {
        let mut wrong = mint.clone();
        let expected = if case == "digest" {
            wrong.intent_digest = Some([0xff; 32]);
            MainnetPrecondition::IntentDivergence
        } else if case == "predecessor-without-digest" {
            wrong.intent_digest = None;
            MainnetPrecondition::IntentMismatch
        } else {
            wrong.predecessor = Some(AuthorizationId::from_bytes([0xff; 32]));
            MainnetPrecondition::PredecessorMismatch
        };
        let bytes = file_bytes(&fx);
        for _ in 0..2 {
            assert!(
                matches!(fx.begin_mint(&handle, &wrong),
                Err(WindowStoreError::AuthorizationRefused { precondition }) if precondition == expected),
                "lineage refusal: {case}"
            );
            assert_eq!(file_bytes(&fx), bytes, "refused lineage writes nothing");
        }
    }
    // The checked lineage mints only inside the attempt's begin.
    let bytes = file_bytes(&fx);
    assert!(matches!(
        fx.store.mint_authorization(&fx.profile, &mint),
        Err(WindowStoreError::AuthorizationRefused {
            precondition: MainnetPrecondition::IntentMismatch
        })
    ));
    assert_eq!(file_bytes(&fx), bytes);
    let started = fx.begin_mint(&handle, &mint).unwrap();
    assert_eq!(started.attempt_index, 2);
    let minted = fx.auth(started.authorization_id);
    assert_eq!(minted.predecessor, Some(previous), "the successor names the prior attempt");
    assert_eq!(minted.intent_digest, mint.intent_digest);
    for (name, slot) in [
        ("first-canonical", canonical(3)),
        ("first-envelope", envelope(3, 3, 0)),
    ] {
        let handle = fx.open_new(&request(name, slot));
        let mut wrong = fx.mint_request(tx(3), fx.policy(), vec![]);
        wrong.operation = Some(OperationLink {
            operation_id: handle.id(),
            attempt_index: 1,
        });
        wrong.intent_digest = Some(handle.intent().intent_digest());
        wrong.predecessor = Some(previous);
        let expected = if matches!(handle.intent(), IntentSlot::Canonical { .. }) {
            MainnetPrecondition::PredecessorMismatch
        } else {
            MainnetPrecondition::IntentMismatch
        };
        assert!(matches!(fx.begin_mint(&handle, &wrong),
            Err(WindowStoreError::AuthorizationRefused { precondition }) if precondition == expected));
        fx.recorder()
            .transition(
                handle.id(),
                None,
                OperationState::Expired,
                &TransitionEvidence::default(),
            )
            .unwrap();
    }
}

/// On the begin path, a mint whose intent digest differs from the stored
/// canonical intent refuses with `intent_divergence`, which
/// `operation_refusal` renders as `simulation.divergence`; a predecessor
/// mismatch keeps `network.mainnet_authorization_refused`. Neither writes.
#[test]
#[serial]
fn canonical_divergence_renders_at_the_begin_exit() {
    let sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(sandbox.path());
    let mut fx = Fx::new();
    let handle = projected_not_included(&mut fx, 1);
    let mint = fx.operation_mint_request(&handle, tx(2), fx.policy(), vec![]);
    let mut diverged = mint.clone();
    diverged.intent_digest = Some([0xd1; 32]);
    let mut stale = mint;
    stale.predecessor = Some(AuthorizationId::from_bytes([0xd2; 32]));
    for (request, precondition, code) in [
        (
            diverged,
            MainnetPrecondition::IntentDivergence,
            "simulation.divergence",
        ),
        (
            stale,
            MainnetPrecondition::PredecessorMismatch,
            "network.mainnet_authorization_refused",
        ),
    ] {
        let bytes = file_bytes(&fx);
        let refused = fx.begin_mint(&handle, &request).unwrap_err();
        assert!(
            matches!(&refused, WindowStoreError::AuthorizationRefused { precondition: p } if *p == precondition),
            "{refused:?}"
        );
        assert_eq!(crate::operation_entry::operation_refusal(refused).code(), code);
        assert_eq!(file_bytes(&fx), bytes);
    }
}
