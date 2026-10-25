//! A fresh V1 profile run through the order `profile init` prints records its
//! audit binding and owner key in their stored forms, and
//! `audit verify --profile` then passes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use serde_json::Value;
use stellar_agent_core::audit_log::AuditBinding;
use stellar_agent_core::profile::owner_key::encode_owner_public_key;
use stellar_agent_core::profile::schema::{KeyringEntryRef, signer_identity_entry_ref};
use stellar_agent_core::profile::signer_identity::SignerIdentityRecord;
use stellar_agent_network::keyring::KeyringAuditBindingStore;

use crate::v1_ceremony::{IsolatedHome, Keypair, policy_document, policy_rule};

const PROFILE: &str = "ceremony";
const SIGNER_SEED: [u8; 32] = [0x11; 32];
const OWNER_SEED: [u8; 32] = [0x22; 32];

#[test]
#[serial_test::serial]
fn a_fresh_v1_profile_through_inits_order_passes_audit_verify() {
    let home = IsolatedHome::new();

    let init = home.init_profile(PROFILE, &[]);
    let steps: Vec<String> = init["data"]["next_steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step.as_str().unwrap().to_owned())
        .collect();
    let order = [
        "rotate-audit-key",
        "enroll-signer",
        "rotate-nonce-key",
        "enroll-owner-key",
        "rotate-attestation-key",
        "`policies/ceremony.toml`",
        "sign-policy",
    ];
    assert_eq!(steps.len(), order.len(), "{steps:?}");
    for (step, verb) in steps.iter().zip(order) {
        assert!(
            step.contains(verb),
            "init prints {verb} at this position: {steps:?}"
        );
    }

    let signer = Keypair::from_seed(SIGNER_SEED);
    let owner = Keypair::from_seed(OWNER_SEED);
    home.enroll_keys(PROFILE, &signer, &owner);
    home.write_policy(
        PROFILE,
        &policy_document(PROFILE, &[policy_rule("stellar_pay", "*", "[]", "allow")]),
    );
    home.sign_policy(PROFILE, &owner);

    let profile = home.load_profile(PROFILE);
    let rows: Vec<Value> = std::fs::read_to_string(&profile.audit_log_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        rows.iter().any(|row| {
            row["kind"] == "keyring_key_written" && row["key_purpose"] == "mcp_signer_seed"
        }),
        "the first signer enrollment writes its audit row"
    );
    assert!(
        rows.iter().any(|row| {
            row["kind"] == "signer_identity_enrolled"
                && row["keyring_entry"] == "enrolled-identity"
                && row["role"] == "agent"
        }),
        "the enrollment records its identity record"
    );
    let log_path = profile.audit_log_path.display().to_string();
    let verified = home.run_ok(&["audit", "verify", "--profile", PROFILE, &log_path], &[]);
    assert_eq!(verified["ok"], true, "{verified}");

    // The stored forms, read through the same headless store.
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.keyring_path(),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(home.headless_key()),
            )),
        ));
    keyring_core::set_default_store(store);
    assert!(
        KeyringAuditBindingStore::for_profile(PROFILE)
            .load_raw()
            .unwrap()
            == Some(AuditBinding::for_profile(&profile).to_keyring_value()),
        "the first keyed use records the binding from the profile file"
    );
    let owner_entry = KeyringEntryRef::default_owner_key(PROFILE);
    let owner_bytes = SigningKey::from_bytes(&OWNER_SEED)
        .verifying_key()
        .to_bytes();
    assert!(
        keyring_core::Entry::new(&owner_entry.service, &owner_entry.account)
            .unwrap()
            .get_password()
            .unwrap()
            == encode_owner_public_key(&owner_bytes),
        "enroll-owner-key stores the G-strkey"
    );
    let identity = signer_identity_entry_ref(&profile.mcp_signer_default);
    let signer_bytes = SigningKey::from_bytes(&SIGNER_SEED)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        keyring_core::Entry::new(&identity.service, &identity.account)
            .unwrap()
            .get_password()
            .unwrap(),
        SignerIdentityRecord::agent(signer_bytes).render(),
        "enroll-signer stores the identity record beside the seed"
    );
}
