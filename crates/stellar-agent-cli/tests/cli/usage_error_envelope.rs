//! An argument the parser refuses ends the `stellar-agent` binary with one
//! `validation.usage_error` envelope on stdout, exit `1`, and nothing on
//! stderr; `--help` and `--version` still print their text and exit `0`.
//!
//! Each run gets its own `STELLAR_AGENT_HOME` and the headless keyring
//! backend, so no run reads the operator's profiles or keychain.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test-only; assertions panic on violation"
)]

use std::process::{Command, Output};

use serde_json::Value;

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Runs the binary with `args` against an isolated home.
fn run(args: &[&str]) -> Output {
    let home = tempfile::tempdir().expect("temp home");
    Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home.path())
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .output()
        .expect("binary runs")
}

/// Asserts `output` is a usage refusal: exit `1`, empty stderr, and stdout
/// holding exactly one `validation.usage_error` envelope. Returns the
/// envelope's message.
fn assert_usage_error(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(stderr.is_empty(), "nothing on stderr: {stderr}");
    let mut documents = serde_json::Deserializer::from_str(&stdout).into_iter::<Value>();
    let envelope = documents
        .next()
        .expect("stdout holds a JSON envelope")
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout}"));
    assert!(
        documents.next().is_none(),
        "stdout holds exactly one envelope: {stdout}"
    );
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(
        envelope["error"]["code"], "validation.usage_error",
        "{envelope}"
    );
    let message = envelope["error"]["message"]
        .as_str()
        .expect("string message")
        .to_owned();
    assert!(!message.starts_with("error:"), "{message}");
    assert_eq!(message, message.trim(), "the message is trimmed");
    message
}

#[test]
fn an_unknown_flag_is_one_usage_error_envelope() {
    let message = assert_usage_error(&run(&["balances", "--bogus-flag"]));
    assert_eq!(
        message,
        "command-line arguments are not valid; run the command with --help for the accepted arguments"
    );
    assert!(!message.contains("--bogus-flag"));
}

#[test]
fn balances_without_account_is_a_usage_error() {
    let message = assert_usage_error(&run(&["balances"]));
    assert!(message.contains("--account"), "{message}");
}

#[test]
fn help_and_version_print_their_text_and_exit_zero() {
    for (flag, expected) in [
        ("--help", "Usage: stellar-agent"),
        ("--version", "stellar-agent "),
    ] {
        let output = run(&[flag]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(output.status.code(), Some(0), "{flag}: {stdout}");
        assert!(stdout.contains(expected), "{flag}: {stdout}");
        assert!(
            serde_json::from_str::<Value>(stdout.trim()).is_err(),
            "{flag} prints text, not an envelope: {stdout}"
        );
        assert!(output.stderr.is_empty(), "{flag}");
    }
}

#[test]
fn usage_diagnostic_marker_is_not_echoed() {
    let marker = "CREDMARKER7";
    for args in [
        vec!["smart-account", "list-rules", "--max-scan-id", marker],
        vec!["balances", "--CREDMARKER7"],
        vec!["CREDMARKER7"],
        vec!["balances", "--account", marker, "--output", marker],
        vec![
            "profile",
            "init",
            "--profile",
            "fixture",
            "--rpc-url",
            "https://CREDMARKER7@example.invalid",
        ],
    ] {
        let output = run(&args);
        let message = assert_usage_error(&output);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(marker));
        assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
        let envelope: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert!(!envelope.to_string().contains(marker));
        assert!(!message.contains(marker));
        for flag in ["--max-scan-id", "--rpc-url"] {
            if args.contains(&flag) {
                assert!(message.contains(flag));
            }
        }
    }
}

#[test]
fn friendbot_refused_url_marker_is_not_echoed() {
    let output = run(&[
        "friendbot",
        "--account",
        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
        "--friendbot-url",
        "CREDMARKER7",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["error"]["code"], "network.rpc_unreachable");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("the friendbot endpoint")
    );
    for text in [
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ] {
        assert!(!text.contains("CREDMARKER7"));
    }
    assert!(!envelope.to_string().contains("CREDMARKER7"));
}

#[test]
fn credentials_missing_name_marker_is_not_echoed() {
    let output = run(&["credentials", "show", "CREDMARKER7"]);
    assert_eq!(output.status.code(), Some(1));
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["error"]["code"], "credentials.not_found");
    assert_eq!(
        envelope["error"]["message"],
        "the requested credential was not found"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("CREDMARKER7"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("CREDMARKER7"));
    assert!(!envelope.to_string().contains("CREDMARKER7"));
}

#[test]
fn credentials_registry_marker_is_not_echoed() {
    let home = tempfile::tempdir().expect("test home");
    std::fs::create_dir_all(home.path().join("passkeys")).expect("passkeys directory");
    std::fs::write(
        home.path().join("passkeys/default.toml"),
        "credentials = CREDMARKER7 here\n",
    )
    .expect("registry fixture");
    for args in [
        vec!["credentials", "list"],
        vec!["credentials", "show", "fixture"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
            .args(args)
            .env("STELLAR_AGENT_HOME", home.path())
            .env_remove("STELLAR_AGENT_PROFILE")
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
            .output()
            .expect("binary runs");
        assert_eq!(output.status.code(), Some(1));
        let envelope: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
        assert_eq!(
            envelope["error"]["code"],
            "credentials.registry_parse_failed"
        );
        assert!(
            envelope["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not valid TOML: line 1, column")
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("CREDMARKER7"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("CREDMARKER7"));
        assert!(!envelope.to_string().contains("CREDMARKER7"));
    }
}

#[test]
fn profile_migration_refusal_omits_the_requested_name() {
    let home = tempfile::tempdir().expect("test home");
    std::fs::create_dir_all(home.path().join("profiles")).expect("profiles directory");
    std::fs::write(
        home.path().join("profiles/CREDMARKER7.toml"),
        "version = 987654321\n",
    )
    .expect("profile fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["profile", "migrate", "--profile", "CREDMARKER7"])
        .env("STELLAR_AGENT_HOME", home.path())
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .output()
        .expect("binary runs");
    assert_eq!(output.status.code(), Some(1));
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["error"]["code"], "internal.unexpected_state");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("migration failed:")
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("CREDMARKER7"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("CREDMARKER7"));
}
