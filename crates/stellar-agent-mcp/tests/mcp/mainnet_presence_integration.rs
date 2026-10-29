//! A mainnet MCP server starts only on an owner-signed policy that lists at
//! least one approval credential.
//!
//! Mainnet consent requires a verified assertion from an approval credential
//! in the owner-signed policy, so a mainnet policy without
//! `mainnet.approval_credentials` is incomplete: the server, read-only or
//! enabled for writes, refuses to start on it and names the missing
//! requirement. The same body signed again with a credential starts.
//!
//! The fixture writes what a mainnet profile holds on disk: the owner key in
//! the mock keyring, the profile, and a version 2 policy signed by a fixed
//! owner seed. No endpoint is contacted at startup.
//!
//! The mock keyring and the data root are process-global, so the test is
//! `#[serial]`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; a failed setup step fails the test loudly"
)]

use serial_test::serial;
use stellar_agent_core::audit_log::BindingCheck;
use stellar_agent_core::policy::v1::{
    canonical::canonical_bytes,
    signature::{digest, sign},
};
use stellar_agent_core::profile::loader::save_to_dir;
use stellar_agent_core::profile::schema::{
    KeyringEntryRef, Profile, default_policy_dir, default_profile_dir,
};
use stellar_agent_mcp::transport::build_server;
use stellar_agent_test_support::{StellarAgentHomeGuard, keyring_mock};

/// The seed of the policy owner.
const OWNER_SEED: [u8; 32] = [11; 32];

fn put(entry: &KeyringEntryRef, value: &str) {
    keyring_core::Entry::new(&entry.service, &entry.account)
        .unwrap()
        .set_password(value)
        .unwrap();
}

/// The mainnet profile `operator`, saved with its owner key enrolled.
fn saved_profile(home: &std::path::Path) -> Profile {
    let mut profile = Profile::builder_mainnet_named(
        "operator",
        "https://rpc.example.invalid",
        "stellar-agent-signer-operator",
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "stellar-agent-nonce-operator",
        "default",
    )
    .build();
    profile.audit_log_path = home.join("audit.jsonl");
    let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
    let owner_g = stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()).to_string();
    put(&profile.policy_owner_key_id, &owner_g);
    put(&KeyringEntryRef::default_owner_key("operator"), &owner_g);
    for key in [
        &profile.policy_window_state_key_id,
        &profile.audit_log_hash_chain_key_id,
        &profile.attestation_key_id,
        &profile.mcp_nonce_key_alias,
    ] {
        stellar_agent_network::keyring::rotate_keyring_secret_32(&key.service, &key.account)
            .unwrap();
    }
    save_to_dir("operator", &profile, &default_profile_dir().unwrap()).unwrap();
    profile
}

/// Signs `raw` with the owner seed and installs it as the profile's policy.
fn install_policy(raw: &str) {
    let owner = ed25519_dalek::SigningKey::from_bytes(&OWNER_SEED);
    let signature = sign(&digest(&canonical_bytes(raw).unwrap()), &owner);
    let directory = default_policy_dir().unwrap();
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("operator.toml"),
        format!(
            "{raw}\n[signature]\nowner_id = \"{}\"\nsig = \"{}\"\n",
            stellar_strkey::ed25519::PublicKey(owner.verifying_key().to_bytes()),
            stellar_agent_core::hex::encode(&signature)
        ),
    )
    .unwrap();
}

/// The fixture policy with its `approval_credentials` list removed.
fn without_credentials(raw: &str) -> String {
    let start = raw.find("approval_credentials = [").unwrap();
    let end = start + raw[start..].find("]\n").unwrap() + 2;
    format!("{}{}", &raw[..start], &raw[end..])
}

/// A mainnet policy without approval credentials stops the server with the
/// named requirement; the same body with its credential starts.
#[test]
#[serial]
fn mainnet_presence_requires_approval_credentials_at_startup() {
    let home = tempfile::tempdir().unwrap();
    let _home = StellarAgentHomeGuard::new(home.path());
    keyring_mock::install().expect("mock keyring store init");
    let profile = saved_profile(home.path());
    let raw = include_str!("../../../stellar-agent-core/tests/fixtures/policy-v2.toml");
    let bare = without_credentials(raw);
    assert!(!bare.contains("approval_credentials"));

    install_policy(&bare);
    let Err(error) = build_server(profile.clone(), BindingCheck::Enforce) else {
        panic!("a mainnet policy without approval credentials must not start a server")
    };
    let rendered = error.to_string();
    assert!(
        rendered.contains("policy.mainnet_minimum_unmet: requirement=approval_credentials"),
        "the refusal names the requirement: {rendered}"
    );

    install_policy(raw);
    build_server(profile, BindingCheck::Enforce)
        .expect("the policy with its approval credential starts");
}
