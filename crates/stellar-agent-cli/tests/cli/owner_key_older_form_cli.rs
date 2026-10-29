//! Engine builds preserve sibling owner entries and refuse older base64.

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

#[test]
#[serial_test::serial]
fn an_engine_build_leaves_another_profiles_older_form_entry() {
    let home = tempfile::tempdir().unwrap();
    install_store(home.path());
    let profiles = home.path().join("profiles");

    let built = Profile::builder_testnet_named("owner-a", "s", "a", "n", "a")
        .rpc_url("http://127.0.0.1:9")
        .audit_log_path(home.path().join("audit").join("owner-a.jsonl"))
        .build();
    assert_eq!(
        built.policy.engine,
        stellar_agent_core::profile::schema::PolicyEngineKind::V1
    );
    save_new_to_dir("owner-a", &built, &profiles).unwrap();
    put(
        &KeyringEntryRef::default_owner_key("owner-a"),
        &encode_owner_public_key(&[0x61; 32]),
    );

    let other = Profile::builder_testnet_named("owner-b", "s", "b", "n", "b")
        .audit_log_path(home.path().join("audit").join("owner-b.jsonl"))
        .build();
    save_new_to_dir("owner-b", &other, &profiles).unwrap();
    let other_owner = KeyringEntryRef::default_owner_key("owner-b");
    put(&other_owner, &URL_SAFE_NO_PAD.encode([0x62; 32]));

    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args([
            "pay",
            DESTINATION,
            "1 XLM",
            "--sign-only",
            "AAAAAA==",
            "--profile",
            "owner-a",
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
        stored(&other_owner) == Some(URL_SAFE_NO_PAD.encode([0x62; 32])),
        "the sibling entry stays byte-identical"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args([
            "pay",
            DESTINATION,
            "1 XLM",
            "--sign-only",
            "AAAAAA==",
            "--profile",
            "owner-b",
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout.contains("older base64 form"), "{stdout}");
    assert!(
        stdout.contains("enroll-owner-key --profile owner-b --force"),
        "{stdout}"
    );
    assert_eq!(
        stored(&other_owner),
        Some(URL_SAFE_NO_PAD.encode([0x62; 32]))
    );
}
