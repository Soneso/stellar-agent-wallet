//! `profile init` refuses a Windows reserved device name and a name beginning
//! with `-`, through the release BINARY.
//!
//! `init` is the verb that creates the file, so it is where an unusable name
//! has to be stopped: `<profile_dir>/NUL.toml` opens the NUL device on Windows
//! rather than a file, and a profile called `-x` cannot be named back to the
//! wallet in any of the commands `init` itself prints as next steps.
//!
//! The refusal is asserted on the wire code, not only on the exit code. A
//! refused `init` and a failed one both exit 1; only the code says the name was
//! rejected before any filesystem access. The code asserted here is the one
//! `init` emits for every unsafe name (`validation.address_invalid`,
//! `init.rs`'s first-stage refusal) — aligning that code with the rest of the
//! configuration family is tracked separately as #119, so this pins what the
//! binary emits today rather than what it should emit.
//!
//! The `=` form of the flag is used throughout: clap refuses `--profile -x`
//! with `unexpected argument '-x' found` before the command runs, so only
//! `--profile=-x` carries such a value through to the validator.
//!
//! Every run gets its own `STELLAR_AGENT_HOME`, so a run that did NOT refuse
//! would leave its file inside the temp directory the test then asserts is
//! empty, rather than in the operator's profile directory.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; refusal is asserted via panic-on-violation"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
/// A refused `init` never reads or writes a credential; the backend exists so
/// no child process can reach the login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Runs `stellar-agent profile init --profile=<name>` against an isolated home
/// and returns `(exit_code, parsed_stdout_json)`.
fn run_init(home: &Path, profile: &str) -> (i32, Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args([
            "profile",
            "init",
            "--engine",
            "noop",
            &format!("--profile={profile}"),
        ])
        .env("STELLAR_AGENT_HOME", home)
        // An ambient value in the developer's shell must not select the profile.
        .env_remove("STELLAR_AGENT_PROFILE")
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .output()
        .expect("stellar-agent binary must run");

    let code = output.status.code().expect("process must exit with a code");
    let stdout = String::from_utf8(output.stdout).expect("stdout must be UTF-8");
    let json: Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be a single JSON envelope");
    (code, json)
}

/// Asserts `init` refused `profile` as an invalid name and wrote nothing.
fn assert_refused(profile: &str, expected_reason: &str) {
    let home = tempfile::tempdir().expect("temp home");
    let (code, json) = run_init(home.path(), profile);

    assert_eq!(code, 1, "an unusable profile name must exit 1: {json}");
    assert_eq!(
        json["error"]["code"], "validation.address_invalid",
        "an unusable profile name must be refused as an invalid name: {json}"
    );
    let message = json["error"]["message"]
        .as_str()
        .expect("the envelope must carry an error message");
    assert!(
        message.contains(expected_reason),
        "the refusal must state why the name is unusable: {message}"
    );

    let profiles = home.path().join("profiles");
    let written: Vec<_> = std::fs::read_dir(&profiles)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    assert!(
        written.is_empty(),
        "a refused init must write no profile file, found: {written:?}"
    );
}

#[test]
fn a_windows_reserved_device_name_is_refused() {
    assert_refused("NUL", "must not be the Windows reserved device name 'NUL'");
}

#[test]
fn a_lowercase_windows_reserved_device_name_is_refused() {
    assert_refused(
        "com1",
        "must not be the Windows reserved device name 'COM1'",
    );
}

#[test]
fn a_windows_reserved_device_name_with_an_extension_is_refused() {
    assert_refused(
        "nul.toml",
        "must not be the Windows reserved device name 'NUL'",
    );
}

#[test]
fn a_windows_reserved_device_name_with_a_trailing_space_is_refused() {
    // Windows ignores trailing spaces when resolving a name, so `"nul "` opens
    // the device just as `"nul"` does.
    assert_refused("nul ", "must not be the Windows reserved device name 'NUL'");
}

#[test]
fn a_windows_reserved_device_name_with_a_space_before_the_extension_is_refused() {
    // NT truncates at the first `.` and only then strips trailing spaces, so
    // `nul .toml` opens the device even though the name ends in a letter.
    assert_refused(
        "nul .toml",
        "must not be the Windows reserved device name 'NUL'",
    );
}

#[test]
fn a_leading_dash_name_is_refused() {
    assert_refused("-x", "must not begin with '-'");
}

#[test]
fn a_name_that_only_resembles_a_device_is_still_created() {
    // The guard must not swallow the ordinary case: `COM0` is not a Windows
    // device, and a dash away from the first character is not a flag.
    let home = tempfile::tempdir().expect("temp home");
    for profile in ["COM0", "smoke-fp2"] {
        let (code, json) = run_init(home.path(), profile);
        assert_eq!(code, 0, "'{profile}' must remain a usable name: {json}");
        assert_eq!(json["data"]["profile"], profile, "{json}");
        assert!(
            home.path()
                .join("profiles")
                .join(format!("{profile}.toml"))
                .exists(),
            "'{profile}' must have been written to <profiles>/{profile}.toml"
        );
    }
}
