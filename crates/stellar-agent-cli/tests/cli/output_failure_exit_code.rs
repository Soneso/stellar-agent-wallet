//! A command whose JSON envelope cannot be written to stdout exits `1` and
//! names the output failure on stderr, so a script never reads exit `0`
//! without the envelope.
//!
//! The failing stdout is a pipe whose read end is closed before the binary
//! starts, so every write fails with a broken pipe. The standard library
//! treats a closed or read-only stdout descriptor (`EBADF`) as a successful
//! write, so that descriptor cannot exercise the failure path.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; assertions panic on violation"
)]

use std::process::{Command, Output, Stdio};

use serde_json::Value;

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Runs `stellar-agent profile list` against an isolated home with `stdout`
/// as its standard output. `profile list` renders through the shared JSON
/// renderer and needs no network.
fn profile_list(stdout: Stdio) -> Output {
    let home = tempfile::tempdir().expect("temp home");
    stellar_agent_test_support::sandbox::mark_sandbox(home.path()).expect("mark fixture directory");
    Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["profile", "list"])
        .env("STELLAR_AGENT_HOME", home.path())
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .expect("binary runs")
}

#[test]
fn an_envelope_that_cannot_be_written_exits_one_and_names_the_failure() {
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let output = profile_list(Stdio::from(writer));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("stellar-agent: writing the command output failed: ")),
        "stderr must name the output failure: {stderr}"
    );
}

/// A draft edit whose envelope cannot be written exits `1` after the replace,
/// and the policy file holds the complete change.
#[test]
#[serial_test::serial]
fn draft_output_failure_exits_1() {
    let guard_home = tempfile::tempdir().expect("temporary home");
    let _guard_home = stellar_agent_test_support::StellarAgentHomeGuard::new(guard_home.path());
    use stellar_agent_core::profile::loader::save_new_to_dir;
    use stellar_agent_core::profile::schema::Profile;

    const NAME: &str = "output-draft";
    const RECIPIENT: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
    let home = tempfile::tempdir().expect("temp home");
    let _child_home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
    let profile = Profile::builder_testnet_named(NAME, "s", "a", "n", "a")
        .audit_log_path(home.path().join("audit").join(format!("{NAME}.jsonl")))
        .build();
    save_new_to_dir(NAME, &profile, &home.path().join("profiles")).expect("profile saved");
    let policies = home.path().join("policies");
    std::fs::create_dir_all(&policies).expect("policy directory");
    let path = policies.join(format!("{NAME}.toml"));
    let draft = format!(
        "version = 2\nscope = \"profile:{NAME}\"\nsequence = 1\n\n[[rules]]\nmatch = {{ tool = \
         \"stellar_pay\", chain = \"*\" }}\ncriteria = [{{ kind = \"counterparty_allowlist\", \
         kinds = [\"G_ACCOUNT\"], allowlist = [] }}]\ndecision = \"allow\"\n"
    );
    std::fs::write(&path, &draft).expect("draft written");

    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args([
            "profile",
            "policy",
            "add-counterparty",
            "--profile",
            NAME,
            "--recipient",
            RECIPIENT,
        ])
        .env("STELLAR_AGENT_HOME", home.path())
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .expect("binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("stellar-agent: writing the command output failed: ")),
        "stderr must name the output failure: {stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "Next: stellar-agent profile sign-policy --profile {NAME} --secret-env <VAR>"
        )),
        "{stderr}"
    );
    let written = std::fs::read_to_string(&path).expect("policy readable");
    assert_eq!(
        written,
        draft.replace("allowlist = []", &format!("allowlist = [\"{RECIPIENT}\"]"))
    );
}

#[test]
fn a_delivered_envelope_exits_zero() {
    let output = profile_list(Stdio::piped());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={stdout} stderr={stderr}"
    );
    let mut documents = serde_json::Deserializer::from_str(&stdout).into_iter::<Value>();
    let envelope = documents
        .next()
        .expect("stdout holds an envelope")
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout}"));
    assert!(
        documents.next().is_none(),
        "stdout holds exactly one envelope: {stdout}"
    );
    assert_eq!(envelope["ok"], true, "{envelope}");
    assert!(stderr.is_empty(), "{stderr}");
}
