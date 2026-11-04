//! Rejected CLI values stay out of output and logs.
#![allow(clippy::expect_used, reason = "test assertions")]

use serde_json::Value;
use std::process::{Command, Output};
use stellar_agent_test_support::rejected_value::{CREDENTIAL_MARKER, assert_no_marker_in_text};

const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn run(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .env("STELLAR_AGENT_LOG", "trace")
        .output()
        .expect("CLI executes")
}
fn assert_refusal(output: &Output, code: &str, message: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert_no_marker_in_text(&String::from_utf8_lossy(&output.stdout), CREDENTIAL_MARKER);
    assert_no_marker_in_text(&String::from_utf8_lossy(&output.stderr), CREDENTIAL_MARKER);
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"]["code"], code);
    assert_eq!(envelope["error"]["message"], message);
}
#[test]
fn rejected_input_cli_install() {
    let home = tempfile::tempdir().expect("home");
    let publisher = stellar_strkey::ed25519::PublicKey([1; 32]).to_string();
    let signature = "0".repeat(128);
    let invalid_signature = format!("CREDMARKER7{}", "0".repeat(117));
    for (package, signature, message) in [
        (
            "CREDMARKER7",
            signature.as_str(),
            "invalid package spec: expected '<name>@<version>'",
        ),
        (
            "test@1.0.0",
            invalid_signature.as_str(),
            "signature must be 128 hex chars (64 bytes)",
        ),
    ] {
        assert_refusal(
            &run(
                home.path(),
                &[
                    "toolsets",
                    "install",
                    package,
                    "--file",
                    "unused.tar.gz",
                    "--shasum",
                    &"0".repeat(64),
                    "--signature",
                    signature,
                    "--publisher",
                    &publisher,
                ],
            ),
            "toolsets.install_failed",
            message,
        );
    }
    let attestation = home.path().join("attestation.json");
    std::fs::write(
        &attestation,
        r#"{"package":"test","version":"1.0.0","capabilities":"CREDMARKER7"}"#,
    )
    .expect("invalid attestation fixture");
    assert_refusal(
        &run(
            home.path(),
            &[
                "toolsets",
                "install",
                "test@1.0.0",
                "--file",
                "unused.tar.gz",
                "--shasum",
                &"0".repeat(64),
                "--signature",
                &signature,
                "--publisher",
                &publisher,
                "--attestation-file",
                attestation.to_str().expect("UTF-8 fixture path"),
            ],
        ),
        "toolsets.install_failed",
        "attestation file must be valid attestation JSON; parse failed at line 1, column 64",
    );
}
#[test]
fn rejected_input_cli_friendbot_network() {
    let home = tempfile::tempdir().expect("home");
    assert_refusal(
        &run(
            home.path(),
            &[
                "friendbot",
                "--account",
                &stellar_strkey::ed25519::PublicKey([1; 32]).to_string(),
                "--network",
                "CREDMARKER7",
            ],
        ),
        "validation.usage_error",
        "the argument value is not valid: --network; run the command with --help for the accepted arguments",
    );
}
#[test]
fn rejected_input_cli_policy_and_context() {
    use stellar_agent_core::profile::{loader::save_to_dir, schema::Profile};
    let home = tempfile::tempdir().expect("home");
    let name = "marker-test";
    let profile = Profile::builder_testnet_named(name, "signer", "account", "nonce", "account")
        .with_noop_engine()
        .audit_log_path(home.path().join("audit.jsonl"))
        .build();
    save_to_dir(name, &profile, &home.path().join("profiles")).expect("profile fixture");
    std::fs::create_dir_all(home.path().join("policies")).expect("policy directory");
    std::fs::write(
        home.path().join("policies/marker-test.toml"),
        "CREDMARKER7 = [",
    )
    .expect("policy fixture");
    assert_refusal(
        &run(home.path(), &["counterparty", "warm-up", "--profile", name]),
        "internal.unexpected_state",
        "unexpected internal state: policy body must be valid TOML; syntax error at line 1, column 16",
    );
    assert_refusal(
        &run(
            home.path(),
            &[
                "smart-account",
                "rules",
                "create",
                "--profile",
                name,
                "--account",
                "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                "--name",
                "test",
                "--signer-delegated",
                &stellar_strkey::ed25519::PublicKey([1; 32]).to_string(),
                "--signer-secret-env",
                "UNUSED_SIGNER_SECRET",
                "--context",
                "CREDMARKER7",
            ],
        ),
        "validation.config_invalid",
        "configuration invalid for '--context': unknown context; accepted --context forms: 'default' (or omit the flag), 'call-contract:<C-strkey>', 'create-contract:<64-hex-wasm-hash>'",
    );
}
