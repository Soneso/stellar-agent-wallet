//! Key-scope refusals retain their wire code across CLI rendering paths.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::path::Path;
use std::process::Command;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};

const ACCOUNT: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

fn shared_home(mainnet: bool) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    for name in ["alice", "bob"] {
        let signer = KeyringEntryRef::default_signer(name);
        let nonce = KeyringEntryRef::default_nonce(name);
        let mut profile = if mainnet {
            Profile::builder_mainnet_named(
                name,
                "https://rpc.example",
                &signer.service,
                &signer.account,
                &nonce.service,
                &nonce.account,
            )
        } else {
            Profile::builder_testnet_named(
                name,
                &signer.service,
                &signer.account,
                &nonce.service,
                &nonce.account,
            )
        }
        .with_noop_engine()
        .audit_log_path(home.path().join(format!("{name}.jsonl")))
        .build();
        profile.attestation_key_id = KeyringEntryRef::default_attestation_key("alice");
        stellar_agent_core::profile::loader::save_to_dir(
            name,
            &profile,
            &home.path().join("profiles"),
        )
        .unwrap();
    }
    home
}

fn run(home: &Path, args: &[&str]) -> (i32, serde_json::Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
        )
        .env("STELLAR_AGENT_LOG", "info")
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let value =
        serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("{e}: {text} {stderr}"));
    (output.status.code().unwrap(), value, stderr)
}

#[test]
fn shared_entry_refusal_reaches_typed_and_raw_envelopes() {
    let home = shared_home(true);
    for args in [
        vec![
            "profile",
            "reset-window-state",
            "alice",
            "--reason",
            "repair",
        ],
        vec![
            "trustline",
            "--profile",
            "alice",
            "--from",
            ACCOUNT,
            "--asset",
            "USDC",
        ],
    ] {
        let (code, value, stderr) = run(home.path(), &args);
        assert_eq!(code, 1, "{value} {stderr}");
        assert_eq!(
            value["error"]["code"], "profile.key_scope_conflict",
            "{value}"
        );
        let message = value["error"]["message"].as_str().unwrap();
        for part in [
            "attestation_key_id",
            "stellar-agent-attestation-alice/default",
            "bob",
            "correct that profile's file",
        ] {
            assert!(message.contains(part), "{message}");
        }
    }
}

#[test]
fn profile_show_displays_a_mainnet_document_with_a_shared_entry() {
    let home = shared_home(true);
    let (code, value, stderr) = run(home.path(), &["profile", "show", "alice"]);
    assert_eq!(code, 0, "{value} {stderr}");
    assert_eq!(value["ok"], true);
}

#[test]
fn testnet_rotation_runs_with_the_key_scope_warning() {
    let home = shared_home(false);
    let (code, value, stderr) = run(
        home.path(),
        &["profile", "rotate-counterparty-key", "alice"],
    );
    assert_eq!(code, 0, "{value} {stderr}");
    assert_eq!(value["ok"], true);
    assert!(stderr.contains("profile.key_scope"), "{stderr}");
    assert!(stderr.contains("attestation_key_id"), "{stderr}");
}
