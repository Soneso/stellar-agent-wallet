//! A fresh V1 profile run through the order `profile init` prints records its
//! audit binding and owner key in their stored forms, and
//! `audit verify --profile` then passes.

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
use ed25519_dalek::SigningKey;
use serde_json::Value;
use stellar_agent_core::audit_log::AuditBinding;
use stellar_agent_core::profile::owner_key::encode_owner_public_key;
use stellar_agent_core::profile::schema::KeyringEntryRef;
use stellar_agent_network::keyring::KeyringAuditBindingStore;

const PROFILE: &str = "ceremony";
const HEADLESS_KEY: [u8; 32] = [0x5d; 32];
const SIGNER_ENV: &str = "CEREMONY_SIGNER_SECRET";
const OWNER_ENV: &str = "CEREMONY_OWNER_SECRET";

fn cli(home: &Path, args: &[&str], secret: Option<(&str, &str)>) -> (i32, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove(SIGNER_ENV)
        .env_remove(OWNER_ENV);
    if let Some((var, value)) = secret {
        command.env(var, value);
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("{args:?}: no JSON envelope; stdout={stdout} stderr={stderr}"));
    let envelope: Value = serde_json::from_str(line).unwrap();
    let code = output.status.code().unwrap();
    assert_eq!(code, 0, "{args:?} failed: {envelope} stderr={stderr}");
    (code, envelope)
}

fn keypair(seed: u8) -> (String, String) {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let secret = stellar_strkey::ed25519::PrivateKey([seed; 32])
        .as_unredacted()
        .to_string()
        .to_string();
    let public = stellar_strkey::ed25519::PublicKey(signing.verifying_key().to_bytes())
        .to_string()
        .to_string();
    (secret, public)
}

#[test]
fn a_fresh_v1_profile_through_inits_order_passes_audit_verify() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();

    let (_, init) = cli(home, &["profile", "init", "--profile", PROFILE], None);
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

    cli(home, &["profile", "rotate-audit-key", PROFILE], None);
    let (signer_secret, signer_public) = keypair(0x11);
    cli(
        home,
        &[
            "profile",
            "enroll-signer",
            "--profile",
            PROFILE,
            "--secret-env",
            SIGNER_ENV,
            "--expected-address",
            &signer_public,
        ],
        Some((SIGNER_ENV, &signer_secret)),
    );
    cli(home, &["profile", "rotate-nonce-key", PROFILE], None);
    let (owner_secret, owner_public) = keypair(0x22);
    cli(
        home,
        &[
            "profile",
            "enroll-owner-key",
            "--profile",
            PROFILE,
            "--secret-env",
            OWNER_ENV,
            "--expected-address",
            &owner_public,
        ],
        Some((OWNER_ENV, &owner_secret)),
    );
    cli(home, &["profile", "rotate-attestation-key", PROFILE], None);
    let policies = home.join("policies");
    std::fs::create_dir_all(&policies).unwrap();
    std::fs::write(
        policies.join(format!("{PROFILE}.toml")),
        format!(
            "version = 1\nscope = \"profile:{PROFILE}\"\n\n[[rules]]\nmatch = {{ tool = \
             \"stellar_pay\", chain = \"*\" }}\ncriteria = []\ndecision = \"allow\"\n"
        ),
    )
    .unwrap();
    cli(
        home,
        &[
            "profile",
            "sign-policy",
            "--profile",
            PROFILE,
            "--secret-env",
            OWNER_ENV,
        ],
        Some((OWNER_ENV, &owner_secret)),
    );

    let profile =
        stellar_agent_core::profile::loader::load_from_dir(PROFILE, &home.join("profiles"), None)
            .unwrap();
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
    let log_path = profile.audit_log_path.display().to_string();
    let (_, verified) = cli(
        home,
        &["audit", "verify", "--profile", PROFILE, &log_path],
        None,
    );
    assert_eq!(verified["ok"], true, "{verified}");

    // The stored forms, read through the same headless store.
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(HEADLESS_KEY),
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
    let owner = KeyringEntryRef::default_owner_key(PROFILE);
    let owner_bytes = SigningKey::from_bytes(&[0x22; 32])
        .verifying_key()
        .to_bytes();
    assert!(
        keyring_core::Entry::new(&owner.service, &owner.account)
            .unwrap()
            .get_password()
            .unwrap()
            == encode_owner_public_key(&owner_bytes),
        "enroll-owner-key stores the G-strkey"
    );
}
