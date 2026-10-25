//! MCP startup policy construction: the advisory, typed policy causes, the
//! installation binding of a selected startup, and the closed mainnet
//! read-only tool set.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    reason = "test fixtures fail loudly"
)]

use ed25519_dalek::SigningKey;
use serial_test::serial;
use stellar_agent_core::{
    policy::{
        McpToolRegistration,
        v1::{
            canonical::canonical_bytes,
            mainnet_minimum::MAINNET_READ_ONLY_TOOLS,
            signature::{digest, sign},
        },
    },
    profile::schema::{KeyringEntryRef, Profile, default_policy_dir},
};
use stellar_agent_mcp::server::WalletServer;
use stellar_agent_test_support::{CaptureWriter, StellarAgentHomeGuard, keyring_mock};

#[test]
fn mainnet_read_only_tools_match_registry_both_directions() {
    use std::collections::BTreeSet;
    let mut registry: BTreeSet<&str> = inventory::iter::<McpToolRegistration>
        .into_iter()
        .filter(|r| r.read_only_hint)
        .map(|r| r.name)
        .collect();
    registry.insert("stellar_transaction_status");
    assert_eq!(registry, MAINNET_READ_ONLY_TOOLS.iter().copied().collect());
    assert!(!registry.contains("stellar_sep43_sign_message"));
    assert!(!registry.contains("stellar_sep53_sign_message"));
}

#[test]
#[serial]
fn startup_advisory_is_emitted_only_when_transaction_status_is_unmatched() {
    keyring_mock::install().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    let dir = default_policy_dir().unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    let key = SigningKey::from_bytes(&[11; 32]);
    let pk = key.verifying_key().to_bytes();
    let coordinate = KeyringEntryRef::default_owner_key("operator");
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&stellar_strkey::ed25519::PublicKey(pk).to_string())
        .unwrap();
    for (tool, warning) in [
        ("stellar_balances", true),
        ("stellar_transaction_status", false),
        ("*", false),
    ] {
        let body = format!(
            "version = 1\nscope = \"profile:operator\"\n[[rules]]\n\
                match = {{tool = \"{tool}\", chain = \"*\"}}\ncriteria = []\n\
                decision = \"allow\"\n"
        );
        let signature = sign(&digest(&canonical_bytes(&body).unwrap()), &key);
        std::fs::write(
            dir.join("operator.toml"),
            format!(
                "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(pk),
                stellar_agent_core::hex::encode(&signature)
            ),
        )
        .unwrap();
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        WalletServer::new(Profile::builder_testnet_named("operator", "s", "a", "n", "a").build())
            .unwrap();
        assert_eq!(
            capture
                .captured_str()
                .matches("policy.transaction_status_unmatched")
                .count(),
            usize::from(warning)
        );
    }
}
#[test]
#[serial]
fn policy_failure_preserves_typed_cause_and_wire_code() {
    use stellar_agent_core::policy::{BuildRegistryError, PolicyError};
    keyring_mock::install().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    let dir = default_policy_dir().unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    let key = SigningKey::from_bytes(&[11; 32]);
    let pk = key.verifying_key().to_bytes();
    let coordinate = KeyringEntryRef::default_owner_key("operator");
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&stellar_strkey::ed25519::PublicKey(pk).to_string())
        .unwrap();
    let profile = Profile::builder_testnet_named("operator", "s", "a", "n", "a").build();
    for sequence in [2, 1] {
        let body = format!(
            "version = 2\nscope = \"profile:operator\"\nsequence = {sequence}\n[[rules]]\n\
                match = {{tool = \"stellar_balances\", chain = \"*\"}}\ncriteria = []\n\
                decision = \"allow\"\n"
        );
        let signature = sign(&digest(&canonical_bytes(&body).unwrap()), &key);
        std::fs::write(
            dir.join("operator.toml"),
            format!(
                "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
                stellar_strkey::ed25519::PublicKey(pk),
                stellar_agent_core::hex::encode(&signature)
            ),
        )
        .unwrap();
        let result = WalletServer::new(profile.clone());
        if sequence == 2 {
            assert!(result.is_ok());
        } else {
            let Err(error) = result else {
                panic!("rollback accepted")
            };
            assert!(matches!(
                &error,
                BuildRegistryError::PolicyFileLoadFailed {
                    source: PolicyError::SequenceRollback,
                    ..
                }
            ));
            let BuildRegistryError::PolicyFileLoadFailed { source, .. } = error else {
                unreachable!()
            };
            assert_eq!(source.wire_code(), "policy.sequence_rollback");
        }
    }
}
#[test]
#[serial]
fn noop_does_not_require_an_owner_namespace() {
    keyring_mock::install().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    let mut profile = Profile::builder_testnet_named("operator", "s", "a", "n", "a").build();
    profile.policy.engine = stellar_agent_core::profile::schema::PolicyEngineKind::Noop;
    profile.policy_owner_key_id.service = "unrelated-service".into();
    assert!(WalletServer::new(profile).is_ok());
}
/// The startup builder passes the operator's selection, so a mainnet policy
/// bound to another installation nonce, or a name not selected by flag,
/// refuses in a `mainnet-write` build. Construction without a selection does
/// not verify the binding.
#[test]
#[serial]
fn selected_startup_verifies_the_installation_binding() {
    use sha2::Digest as _;
    use stellar_agent_core::{
        audit_log::BindingCheck,
        error::ValidationError,
        policy::BuildRegistryError,
        profile::{
            name::ProfileNameSource,
            schema::{default_profile_dir, mainnet_enablement_entry_ref},
        },
    };
    use stellar_agent_mcp::transport::{build_selected_server, build_server};
    keyring_mock::install().unwrap();
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    let profile = Profile::builder_mainnet_named(
        "operator",
        "https://rpc.example.invalid",
        "s",
        "a",
        "n",
        "a",
    )
    .build();
    stellar_agent_core::profile::loader::save_to_dir(
        "operator",
        &profile,
        &default_profile_dir().unwrap(),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[11; 32]);
    let pk = key.verifying_key().to_bytes();
    let owner = KeyringEntryRef::default_owner_key("operator");
    keyring_core::Entry::new(&owner.service, &owner.account)
        .unwrap()
        .set_password(&stellar_strkey::ed25519::PublicKey(pk).to_string())
        .unwrap();
    let nonce = "installation-nonce";
    let body = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml").replace(
        &"0".repeat(64),
        &stellar_agent_core::hex::encode(&sha2::Sha256::digest(nonce.as_bytes())),
    );
    let signature = sign(&digest(&canonical_bytes(&body).unwrap()), &key);
    let dir = default_policy_dir().unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("operator.toml"),
        format!(
            "{body}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
            stellar_strkey::ed25519::PublicKey(pk),
            stellar_agent_core::hex::encode(&signature)
        ),
    )
    .unwrap();
    let coordinate = mainnet_enablement_entry_ref(&profile.policy_window_state_key_id);
    let entry = keyring_core::Entry::new(&coordinate.service, &coordinate.account).unwrap();
    entry.set_password(nonce).unwrap();
    let selected = |source| build_selected_server(profile.clone(), source, BindingCheck::Enforce);
    let refusal = |binding| {
        BuildRegistryError::PolicyEngineError {
            detail: ValidationError::MainnetEnablementInvalid { binding }.to_string(),
        }
        .to_string()
    };
    assert!(selected(ProfileNameSource::Flag).is_ok());
    let by_env = selected(ProfileNameSource::Env);
    assert_eq!(by_env.is_err(), cfg!(feature = "mainnet-write"));
    if let Err(error) = by_env {
        assert_eq!(error.to_string(), refusal("source"));
    }
    entry.set_password("changed").unwrap();
    let rebound = selected(ProfileNameSource::Flag);
    assert_eq!(rebound.is_err(), cfg!(feature = "mainnet-write"));
    if let Err(error) = rebound {
        assert_eq!(error.to_string(), refusal("nonce_digest"));
    }
    assert!(build_server(profile, BindingCheck::Enforce).is_ok());
}
