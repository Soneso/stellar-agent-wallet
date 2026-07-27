//! `--profile` values that are not safe path components are refused before the
//! profile path is built.
//!
//! The refusal lives in the profile loader, at the join, not at the call site:
//! most subcommands pass an operator-supplied name straight to the loader, so a
//! guard that each caller had to remember would not hold. This drives the
//! release BINARY (`env!("CARGO_BIN_EXE_stellar-agent")`) through `profile
//! show`, which is the shortest path from a `--profile` value to
//! `<profile_dir>/<name>.toml`.
//!
//! `approve list` and `approve gc` are the exception the loader cannot cover:
//! they build the approval path directly and never load a profile, so they
//! carry their own guard. `gc` WRITES, so an unguarded traversal there creates
//! a file and a lock outside the data root; both are pinned below.
//!
//! The assertion is on the wire code, not merely on the exit code: a traversal
//! name resolves to a file that does not exist, so a run WITHOUT the loader
//! guard would still exit 1 — with `validation.profile_not_found` instead of
//! `validation.config_invalid`. Only the code distinguishes "refused before
//! the join" from "looked for it and did not find it".

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; refusal is asserted via panic-on-violation"
)]

use std::process::Command;

use serde_json::Value;

/// Runs `stellar-agent profile show --profile <name>` and returns
/// `(exit_code, parsed_stdout_json)`.
fn run_show(profile: &str) -> (i32, Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args(["profile", "show", "--profile", profile])
        // Never touch the login keychain: the refusal happens before any
        // keyring access, and this keeps the subprocess hermetic regardless.
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            "dGVzdC1oZWFkbGVzcy1rZXktbm90LXVzZWQtYnktc2hvdw",
        )
        .output()
        .expect("stellar-agent binary must run");

    let code = output.status.code().expect("process must exit with a code");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let json: Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be a single JSON envelope");
    (code, json)
}

#[test]
fn parent_directory_traversal_is_refused_as_an_invalid_name() {
    let (code, json) = run_show("../../../etc/passwd");
    assert_eq!(code, 1, "a traversal profile name must exit 1");
    assert_eq!(
        json["error"]["code"], "validation.config_invalid",
        "a traversal name must be refused as an invalid name, not reported as a \
         missing profile: {json}"
    );
}

#[test]
fn a_bare_path_separator_is_refused_as_an_invalid_name() {
    let (code, json) = run_show("nested/profile");
    assert_eq!(code, 1, "a name with a path separator must exit 1");
    assert_eq!(
        json["error"]["code"], "validation.config_invalid",
        "a name carrying a path separator must be refused as an invalid name: {json}"
    );
}

#[test]
fn an_ordinary_missing_name_is_still_reported_as_not_found() {
    // The guard must not swallow the ordinary case: a well-formed name that has
    // no profile file keeps its own, more useful refusal.
    let (code, json) = run_show("__issue105_absent_profile_name__");
    assert_eq!(code, 1, "a missing profile must exit 1");
    assert_eq!(
        json["error"]["code"], "validation.profile_not_found",
        "a well-formed but absent name must still be profile_not_found: {json}"
    );
}

/// Runs an `approve` subcommand and returns `(exit_code, parsed_stdout_json)`.
///
/// `approve list` and `approve gc` join the approval directory themselves, so
/// the loader guard never runs for them; these pin their call-site guards.
fn run_approve(subcommand: &str, profile: &str) -> (i32, Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args(["approve", subcommand, "--profile", profile])
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            "dGVzdC1oZWFkbGVzcy1rZXktbm90LXVzZWQtYnktc2hvdw",
        )
        .output()
        .expect("stellar-agent binary must run");

    let code = output.status.code().expect("process must exit with a code");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let json: Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be a single JSON envelope");
    (code, json)
}

#[test]
fn approve_list_refuses_a_traversal_profile_name() {
    let (code, json) = run_approve("list", "../../../tmp/escape");
    assert_eq!(code, 1, "a traversal name must be refused: {json}");
    assert_eq!(
        json["error"]["code"], "validation.config_invalid",
        "the refusal must name the profile as the invalid input: {json}"
    );
}

#[test]
fn approve_gc_refuses_a_traversal_profile_name_before_writing() {
    let (code, json) = run_approve("gc", "../../../tmp/escape");
    assert_eq!(code, 1, "a traversal name must be refused: {json}");
    assert_eq!(
        json["error"]["code"], "validation.config_invalid",
        "the refusal must name the profile as the invalid input: {json}"
    );
}
