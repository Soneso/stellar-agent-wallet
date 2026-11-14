//! Shared policy construction and signed fee precedence.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail loudly"
)]

use ed25519_dalek::SigningKey;
use serial_test::serial;
use stellar_agent_core::{
    policy::v1::{
        canonical::canonical_bytes,
        signature::{digest, sign},
        verified::OwnerKeySource,
    },
    profile::{
        loader,
        name::ProfileNameSource,
        schema::{Profile, default_policy_dir, default_profile_dir, mainnet_enablement_entry_ref},
    },
};
use stellar_agent_network::policy_engine::{ProfileSelection, build_policy_engine};
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};
const FULL: &str = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml");
const V1: &str = "version = 1\nscope = \"profile:operator\"\n[[rules]]\n\
    match = {tool = \"stellar_balances\", chain = \"*\"}\ncriteria = []\ndecision = \"allow\"\n";
fn profile(mainnet: bool) -> Profile {
    if mainnet {
        Profile::builder_mainnet_named(
            "operator",
            "https://rpc.example.invalid",
            "s",
            "a",
            "n",
            "a",
        )
        .build()
    } else {
        Profile::builder_testnet_named("operator", "s", "a", "n", "a").build()
    }
}
fn flag_selection(profile_dir: &std::path::Path) -> ProfileSelection<'_> {
    ProfileSelection {
        name: "operator",
        source: ProfileNameSource::Flag,
        profile_dir,
    }
}
fn write_policy(raw: &str) -> [u8; 32] {
    let key = SigningKey::from_bytes(&[11; 32]);
    let pk = key.verifying_key().to_bytes();
    let signature = sign(&digest(&canonical_bytes(raw).unwrap()), &key);
    let dir = default_policy_dir().unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("operator.toml"),
        format!(
            "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
            stellar_strkey::ed25519::PublicKey(pk),
            stellar_agent_core::hex::encode(&signature)
        ),
    )
    .unwrap();
    pk
}
#[test]
#[serial]
fn noop_has_no_proofs_and_v1_is_verified() {
    keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(dir.path());
    let mut profile = profile(false);
    assert!(
        stellar_agent_core::profile::owner_key::read_enrolled_owner(&profile)
            .unwrap()
            .is_none()
    );
    profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::Noop;
    let pk = write_policy(V1);
    let noop = build_policy_engine(
        &profile,
        None,
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .unwrap();
    assert!(noop.verified.is_none());
    assert!(noop.enablement.is_none());
    profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::V1;
    let pk = write_policy(V1);
    let v1 = build_policy_engine(
        &profile,
        None,
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .unwrap();
    let verified = v1.verified.unwrap();
    assert_eq!(verified.sequence(), 0);
    let concrete: std::sync::Arc<dyn stellar_agent_core::policy::PolicyEngine> = verified.engine();
    assert!(std::sync::Arc::ptr_eq(&v1.engine, &concrete));
    assert!(v1.enablement.is_none());
}

#[test]
#[serial]
fn unsigned_engine_selection_refuses_before_payment() {
    use stellar_agent_core::{policy::PolicyError, profile::schema::PolicyEngineKind};
    use stellar_agent_network::policy_engine::PolicyEngineBuildError;
    keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(dir.path());
    let mut profile = profile(false);
    let body = V1
        .replace("version = 1", "version = 2\nsequence = 1")
        .replace("stellar_balances", "stellar_pay")
        .replace(
            "criteria = []",
            "criteria = [{kind = \"per_tx_cap\", asset = \"native\", max_stroops = \"1\"}]",
        );
    let pk = write_policy(&body);
    let entry = &profile.policy_owner_key_id;
    keyring_core::Entry::new(&entry.service, &entry.account)
        .unwrap()
        .set_password(&stellar_agent_core::profile::owner_key::encode_owner_public_key(&pk))
        .unwrap();
    build_policy_engine(
        &profile,
        None,
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .unwrap();
    profile.policy.engine = PolicyEngineKind::Noop;
    let error = build_policy_engine(
        &profile,
        None,
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .err()
    .unwrap();
    assert!(matches!(
        error,
        PolicyEngineBuildError::Policy(PolicyError::EngineSelectionUnsigned { selection: "noop" })
    ));
    assert!(error.to_string().contains("engine selection"));
    let path =
        stellar_agent_core::profile::schema::default_policy_window_state_path_for("operator");
    assert!(!path.exists());
    write_policy(&body.replace("sequence = 1", "sequence = 2\nengine = \"noop\""));
    let built = build_policy_engine(
        &profile,
        None,
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .unwrap();
    assert!(built.verified.is_none());
    assert!(built.enablement.is_none());
}

#[test]
#[serial]
fn engine_selection_refuses_unreadable_owner_state() {
    for malformed in [false, true] {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        let mut profile = profile(false);
        profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::Noop;
        let pin = stellar_agent_core::profile::schema::policy_pin_entry_ref(
            &profile.policy_window_state_key_id,
        );
        assert!(
            !stellar_agent_core::profile::schema::default_policy_window_state_path_for("operator")
                .parent()
                .unwrap()
                .exists()
        );
        if malformed {
            keyring_core::Entry::new(&pin.service, &pin.account)
                .unwrap()
                .set_password("malformed pin")
                .unwrap();
        } else {
            keyring_mock::inject_error(
                &pin.service,
                &pin.account,
                keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("locked pin"))),
            )
            .unwrap();
        }
        assert!(
            build_policy_engine(
                &profile,
                None,
                "operator",
                None,
                [0; 32],
                OwnerKeySource::Keyring
            )
            .is_err()
        );
    }
    for failure in 0..3 {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        let mut profile = profile(false);
        profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::Noop;
        let entry = &profile.policy_owner_key_id;
        if failure == 0 {
            keyring_core::Entry::new(&entry.service, &entry.account)
                .unwrap()
                .set_password("invalid owner")
                .unwrap();
        } else {
            keyring_mock::inject_error(
                &entry.service,
                &entry.account,
                if failure == 1 {
                    keyring_core::Error::NoDefaultStore
                } else {
                    keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("locked")))
                },
            )
            .unwrap();
        }
        let error = build_policy_engine(
            &profile,
            None,
            "operator",
            None,
            [0; 32],
            OwnerKeySource::Keyring,
        )
        .err()
        .unwrap();
        assert!(
            matches!(
                error,
                stellar_agent_network::policy_engine::PolicyEngineBuildError::OwnerKeyring(_)
            ),
            "{error}"
        );
    }
}

#[test]
#[serial]
fn engine_authorization_keeps_unrelated_behavior() {
    const EXPECTED: &str = r#"version = 1
scope = "profile:operator"

[[rules]]
match = { tool = "stellar_balances", chain = "*" }
criteria = []
decision = "allow"
"#;
    assert_eq!(
        String::from_utf8(canonical_bytes(V1).unwrap()).unwrap(),
        EXPECTED
    );
    noop_has_no_proofs_and_v1_is_verified();
    for mainnet in [false, true] {
        keyring_mock::install().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let _home = StellarAgentHomeGuard::new(dir.path());
        let mut profile = profile(mainnet);
        profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::Noop;
        let pk = write_policy(&V1.replace(
            "version = 1",
            "version = 2\nsequence = 1\nengine = \"noop\"",
        ));
        let entry = &profile.policy_owner_key_id;
        keyring_core::Entry::new(&entry.service, &entry.account)
            .unwrap()
            .set_password(&stellar_agent_core::profile::owner_key::encode_owner_public_key(&pk))
            .unwrap();
        let built = build_policy_engine(
            &profile,
            None,
            "operator",
            None,
            pk,
            OwnerKeySource::Keyring,
        )
        .unwrap();
        assert!(built.verified.is_none());
        assert!(built.enablement.is_none());
        let destructive = stellar_agent_core::policy::ToolDescriptor::from_registration(
            &stellar_agent_core::policy::McpToolRegistration {
                name: "stellar_pay",
                destructive_hint: true,
                read_only_hint: false,
                chain_id_required: false,
                value_kind: stellar_agent_core::policy::ToolValueKind::ReadOnly,
            },
        );
        let decision = built.engine.evaluate(
            &destructive,
            &serde_json::Value::Null,
            &profile,
            None,
            None,
            None,
            None,
            None,
            1_800_000_000_000,
        );
        if mainnet {
            assert!(matches!(
                decision,
                Err(stellar_agent_core::policy::PolicyError::NotImplemented)
            ));
        } else {
            assert_eq!(
                decision.unwrap(),
                stellar_agent_core::policy::Decision::Allow
            );
        }
        let path = default_policy_dir().unwrap().join("operator.toml");
        for malformed in ["", "version = 2\nengine = \"noop\"\n"] {
            std::fs::write(&path, malformed).unwrap();
            assert!(
                build_policy_engine(
                    &profile,
                    None,
                    "operator",
                    None,
                    pk,
                    OwnerKeySource::Keyring
                )
                .is_err()
            );
        }
    }
}
#[test]
#[serial]
fn mainnet_v1_and_v2_without_table_have_no_enablement() {
    keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(dir.path());
    let profile = profile(true);
    let mut doc = FULL.parse::<toml_edit::DocumentMut>().unwrap();
    doc.remove("mainnet");
    for body in [V1, &doc.to_string()] {
        let pk = write_policy(body);
        let built = build_policy_engine(
            &profile,
            Some(flag_selection(dir.path())),
            "operator",
            None,
            pk,
            OwnerKeySource::Keyring,
        )
        .unwrap();
        assert!(built.verified.is_some());
        assert!(built.enablement.is_none());
    }
}
#[test]
#[serial]
fn enabled_mainnet_verifies_and_bad_binding_refuses() {
    use sha2::Digest as _;
    keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(dir.path());
    let profile = profile(true);
    let profile_dir = default_profile_dir().unwrap();
    loader::save_to_dir("operator", &profile, &profile_dir).unwrap();
    let nonce = "installation-nonce";
    let nonce_hash = stellar_agent_core::hex::encode(&sha2::Sha256::digest(nonce.as_bytes()));
    let pk = write_policy(&FULL.replace(&"0".repeat(64), &nonce_hash));
    // `profile enable-mainnet` pins the verified policy before it stores the
    // nonce: a load without a selection advances the absent pin.
    build_policy_engine(
        &profile,
        None,
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .unwrap();
    let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
    let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap();
    entry.set_password(nonce).unwrap();
    let built = build_policy_engine(
        &profile,
        Some(flag_selection(&profile_dir)),
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .unwrap();
    assert_eq!(built.enablement.is_some(), cfg!(feature = "mainnet-write"));
    entry.set_password("changed").unwrap();
    assert_eq!(
        build_policy_engine(
            &profile,
            Some(flag_selection(&profile_dir)),
            "operator",
            None,
            pk,
            OwnerKeySource::Keyring,
        )
        .is_err(),
        cfg!(feature = "mainnet-write")
    );
    let legacy = build_policy_engine(
        &profile,
        None,
        "operator",
        None,
        pk,
        OwnerKeySource::Keyring,
    )
    .unwrap();
    assert!(legacy.enablement.is_none());
}
/// An installation that holds an enablement nonce but no pin: the engine
/// refuses with `policy.pin_absent`, with and without a selection, and writes
/// no pin.
#[test]
#[serial]
fn a_stored_nonce_without_a_pin_refuses_and_writes_no_pin() {
    use sha2::Digest as _;
    use stellar_agent_core::policy::{
        PolicyError, pin::PinState, v1::verified::read_pin_without_creating,
    };
    use stellar_agent_network::policy_engine::PolicyEngineBuildError;
    keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(dir.path());
    let profile = profile(true);
    let profile_dir = default_profile_dir().unwrap();
    loader::save_to_dir("operator", &profile, &profile_dir).unwrap();
    let nonce = "installation-nonce";
    let nonce_hash = stellar_agent_core::hex::encode(&sha2::Sha256::digest(nonce.as_bytes()));
    let pk = write_policy(&FULL.replace(&"0".repeat(64), &nonce_hash));
    let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(nonce)
        .unwrap();
    let window =
        stellar_agent_core::profile::schema::default_policy_window_state_path_for("operator");
    for selection in [None, Some(flag_selection(&profile_dir))] {
        let selected = selection.is_some();
        let error = build_policy_engine(
            &profile,
            selection,
            "operator",
            None,
            pk,
            OwnerKeySource::Keyring,
        )
        .err()
        .unwrap();
        assert!(
            matches!(
                error,
                PolicyEngineBuildError::Policy(PolicyError::PinAbsent)
            ),
            "{selected}: {error}"
        );
        assert_eq!(
            read_pin_without_creating(&window, &profile).unwrap(),
            PinState::Absent,
            "{selected}"
        );
    }
}
#[test]
#[serial_test::serial]
fn signed_fee_cap_precedence() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use stellar_agent_core::error::FeeSource;
    use stellar_agent_network::fees::check_classic_fee_cap_signed;
    let mut profile = profile(true);
    for (configured, signed, cap) in [
        (None, Some(100), 100),
        (Some(100), None, 100),
        (Some(200), Some(100), 100),
        (Some(100), Some(200), 100),
        (Some(100), Some(100), 100),
    ] {
        profile.classic_max_fee_per_op_stroops = configured;
        assert!(
            check_classic_fee_cap_signed(cap, FeeSource::ProfileDefault, &profile, signed).is_ok()
        );
        assert!(
            check_classic_fee_cap_signed(cap + 1, FeeSource::ProfileDefault, &profile, signed)
                .is_err()
        );
    }
    profile.classic_max_fee_per_op_stroops = None;
    assert!(check_classic_fee_cap_signed(100, FeeSource::ProfileDefault, &profile, None).is_err());
}
#[test]
#[serial_test::serial]
fn signed_fee_cap_warns_when_profile_is_higher() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    let mut profile = profile(true);
    profile.classic_max_fee_per_op_stroops = Some(200);
    let capture = stellar_agent_test_support::CaptureWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    assert!(
        stellar_agent_network::fees::check_classic_fee_cap_signed(
            100,
            stellar_agent_core::error::FeeSource::ProfileDefault,
            &profile,
            Some(100)
        )
        .is_ok()
    );
    let output = capture.captured_str();
    assert!(
        output.contains("WARN") && output.contains("profile classic fee cap exceeds signed cap"),
        "{output}"
    );
}
#[test]
#[serial]
fn persisted_store_retries_contention_and_refuses_a_held_lock() {
    let storage_sandbox = stellar_agent_test_support::sandbox::StateSandbox::new().unwrap();
    let _storage_home =
        stellar_agent_test_support::StellarAgentHomeGuard::new(storage_sandbox.path());
    use stellar_agent_core::policy::state_lock::WindowStoreLock;
    use stellar_agent_network::policy_state::{PersistedWindowStore, WindowStoreError};
    keyring_mock::install().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.window");
    let profile = profile(false);
    let held = WindowStoreLock::acquire_for(&path, &profile.policy_window_state_key_id).unwrap();
    let store = PersistedWindowStore::at_path(path.clone());
    std::thread::scope(|scope| {
        scope.spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(25));
            drop(held);
        });
        store.record_and_persist(&profile, &[]).unwrap();
    });
    let _held = WindowStoreLock::acquire_for(&path, &profile.policy_window_state_key_id).unwrap();
    let start = std::time::Instant::now();
    assert!(matches!(
        store.record_and_persist(&profile, &[]),
        Err(WindowStoreError::WriterLocked)
    ));
    assert!(start.elapsed() >= std::time::Duration::from_millis(100));
}
