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
