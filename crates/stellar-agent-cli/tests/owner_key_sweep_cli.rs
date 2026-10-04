//! The first V1 policy engine build in a CLI process rewrites the older-form
//! owner entry of every other profile in the profile directory as a G-strkey.
//!
//! Driven as a subprocess of the real binary, because the rewrite runs once
//! per process. The keyring is the headless backend, so no child process
//! reaches the login keychain.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::owner_key::encode_owner_public_key;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};

const HEADLESS_KEY: [u8; 32] = [0x4c; 32];
const DESTINATION: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";

/// Registers the headless store the child process opens under `home`.
fn install_store(home: &Path) {
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(HEADLESS_KEY),
            )),
        ));
    keyring_core::set_default_store(store);
}

fn put(entry_ref: &KeyringEntryRef, value: &str) {
    keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .unwrap()
        .set_password(value)
        .unwrap();
}

fn stored(entry_ref: &KeyringEntryRef) -> Option<String> {
    keyring_core::Entry::new(&entry_ref.service, &entry_ref.account)
        .unwrap()
        .get_password()
        .ok()
}

/// A V1 `pay --sign-only` for one profile builds the policy engine before any
/// request, and the build rewrites another profile's older-form owner entry.
/// The verb then refuses for want of a signed policy, after the rewrite.
#[test]
fn a_v1_engine_build_rewrites_another_profiles_older_form_owner_entry() {
    let home = tempfile::tempdir().unwrap();
    install_store(home.path());
    let profiles = home.path().join("profiles");

    let built = Profile::builder_testnet_named("sweep-a", "s", "a", "n", "a")
        .rpc_url("http://127.0.0.1:9")
        .audit_log_path(home.path().join("audit").join("sweep-a.jsonl"))
        .build();
    assert_eq!(
        built.policy.engine,
        stellar_agent_core::profile::schema::PolicyEngineKind::V1
    );
    save_new_to_dir("sweep-a", &built, &profiles).unwrap();
    put(
        &KeyringEntryRef::default_owner_key("sweep-a"),
        &encode_owner_public_key(&[0x61; 32]),
    );

    let other = Profile::builder_testnet_named("sweep-b", "s", "b", "n", "b")
        .audit_log_path(home.path().join("audit").join("sweep-b.jsonl"))
        .with_noop_engine()
        .build();
    save_new_to_dir("sweep-b", &other, &profiles).unwrap();
    let other_owner = KeyringEntryRef::default_owner_key("sweep-b");
    put(&other_owner, &URL_SAFE_NO_PAD.encode([0x62; 32]));

    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args([
            "pay",
            DESTINATION,
            "1 XLM",
            "--sign-only",
            "AAAAAA==",
            "--profile",
            "sweep-a",
        ])
        .env("STELLAR_AGENT_HOME", home.path())
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_TEST_OWNER_PUBKEY_FILE")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        stdout.contains("policy.engine_unavailable"),
        "the verb reaches the engine build and refuses at the policy load: \
         stdout={stdout} stderr={stderr}"
    );
    assert!(
        stored(&other_owner) == Some(encode_owner_public_key(&[0x62; 32])),
        "the first V1 engine build rewrites another profile's older-form owner entry"
    );
}
