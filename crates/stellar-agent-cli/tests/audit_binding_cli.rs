//! The audit binding on the CLI surface. A smart-account verb whose profile
//! names a log other than its recorded binding exits 1 with
//! `audit.log_binding_changed`. It sends nothing to the RPC and creates
//! nothing at the repointed path.

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
use serial_test::serial;
use stellar_agent_core::audit_log::AuditBinding;
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::schema::Profile;
use stellar_agent_network::keyring::KeyringAuditBindingStore;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const HEADLESS_KEY: [u8; 32] = [0x4b; 32];
const ACCOUNT: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// Saves a persisted testnet profile whose binding was recorded for
/// `<home>/audit/<name>.jsonl` and which names `<home>/repointed/<name>.jsonl`.
fn repointed_profile(home: &Path, name: &str, rpc_url: &str) -> std::path::PathBuf {
    let store: Arc<keyring_core::CredentialStore> =
        Arc::new(stellar_agent_headless_keyring::store::HeadlessStore::new(
            home.join("headless-keyring").join("store.keyring"),
            stellar_agent_headless_keyring::crypto::ProtectionMode::EnvKey(Arc::new(
                zeroize::Zeroizing::new(HEADLESS_KEY),
            )),
        ));
    keyring_core::set_default_store(store);
    let mut profile = Profile::builder_testnet_named(name, "s", "a", "n", "a")
        .rpc_url(rpc_url)
        .audit_log_path(home.join("audit").join(format!("{name}.jsonl")))
        .with_noop_engine()
        .build();
    let coordinate = &profile.audit_log_hash_chain_key_id;
    keyring_core::Entry::new(&coordinate.service, &coordinate.account)
        .unwrap()
        .set_password(&URL_SAFE_NO_PAD.encode([0x2c; 32]))
        .unwrap();
    KeyringAuditBindingStore::for_profile(name)
        .store(&AuditBinding::for_profile(&profile))
        .unwrap();
    let repointed = home.join("repointed");
    profile.audit_log_path = repointed.join(format!("{name}.jsonl"));
    save_new_to_dir(name, &profile, &home.join("profiles")).unwrap();
    repointed
}

fn run(home: &Path, args: &[&str]) -> (i32, serde_json::Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
        )
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON envelope; stdout={stdout} stderr={stderr}"));
    (
        output.status.code().unwrap(),
        serde_json::from_str(line).unwrap(),
        stderr,
    )
}

async fn silent_rpc() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    server
}

/// A signing smart-account verb refuses before its signer loads and before
/// any request.
#[tokio::test]
#[serial]
async fn a_signing_smart_account_verb_refuses_a_changed_binding_and_sends_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let rpc = silent_rpc().await;
    let name = "binding-sign";
    let repointed = repointed_profile(dir.path(), name, &rpc.uri());
    let (code, envelope, stderr) = run(
        dir.path(),
        &[
            "smart-account",
            "rules",
            "set-name",
            "--account",
            ACCOUNT,
            "--rule-id",
            "1",
            "--name",
            "renamed",
            "--profile",
            name,
        ],
    );
    assert_eq!(code, 1, "{envelope} {stderr}");
    assert_eq!(
        envelope["error"]["code"], "audit.log_binding_changed",
        "{envelope}"
    );
    assert!(
        rpc.received_requests().await.unwrap().is_empty(),
        "nothing is sent"
    );
    assert!(
        !repointed.exists(),
        "nothing is created at the repointed path"
    );
}

/// A read-only smart-account verb exits 1 with the binding code and creates
/// nothing at the repointed path.
#[tokio::test]
#[serial]
async fn a_read_only_smart_account_verb_refuses_a_changed_binding_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let rpc = silent_rpc().await;
    let name = "binding-read";
    let repointed = repointed_profile(dir.path(), name, &rpc.uri());
    let (code, envelope, stderr) = run(
        dir.path(),
        &[
            "smart-account",
            "list-rules",
            "--account",
            ACCOUNT,
            "--profile",
            name,
        ],
    );
    assert_eq!(code, 1, "{envelope} {stderr}");
    assert_eq!(
        envelope["error"]["code"], "audit.log_binding_changed",
        "{envelope}"
    );
    assert!(
        rpc.received_requests().await.unwrap().is_empty(),
        "nothing is sent"
    );
    assert!(
        !repointed.exists(),
        "nothing is created at the repointed path"
    );
}
