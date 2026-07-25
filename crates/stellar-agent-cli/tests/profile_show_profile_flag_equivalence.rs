//! Command-level equivalence of `profile show <NAME>` and
//! `profile show --profile <NAME>`.
//!
//! The two forms resolve the same profile through the same code path, so their
//! stdout envelopes must be byte-identical once the only non-deterministic
//! field — `request_id` (see `stellar-agent-core`'s `envelope.rs`) — is
//! removed. Driven through the release BINARY
//! (`env!("CARGO_BIN_EXE_stellar-agent")`) so the assertion covers real clap
//! dispatch, not a re-implementation of it.
//!
//! The invocation targets a profile name that cannot exist, so both forms take
//! the `validation.profile_not_found` error path: network-free, keyring-free,
//! and side-effect-free. The headless keyring backend is set defensively so the
//! subprocess can never reach the login keychain even if the resolution path
//! changed.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; equivalence is asserted via panic-on-violation"
)]

use std::process::Command;

use serde_json::Value;

/// A profile name that cannot exist on any host, so both invocations resolve to
/// the same `validation.profile_not_found` outcome deterministically.
const MISSING_PROFILE: &str = "__issue66_show_equivalence_missing_profile__";

/// Runs `stellar-agent profile show` with the supplied trailing arguments and
/// returns `(exit_code, parsed_stdout_json)`.
fn run_show(extra_args: &[&str]) -> (i32, Value) {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let output = Command::new(bin_path)
        .args(["profile", "show"])
        .args(extra_args)
        // Never touch the login keychain: force the headless backend. `show`
        // does not reach the keyring for a missing profile, but this keeps the
        // subprocess hermetic regardless.
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

/// Removes the non-deterministic `request_id` so two envelopes are comparable.
fn strip_request_id(mut envelope: Value) -> Value {
    if let Some(object) = envelope.as_object_mut() {
        object.remove("request_id");
    }
    envelope
}

#[test]
fn show_positional_and_profile_flag_produce_the_same_envelope() {
    let (positional_code, positional_json) = run_show(&[MISSING_PROFILE]);
    let (flag_code, flag_json) = run_show(&["--profile", MISSING_PROFILE]);

    // Both forms are the missing-profile error path.
    assert_eq!(positional_code, 1, "positional form must exit 1");
    assert_eq!(flag_code, 1, "flag form must exit 1");
    assert_eq!(
        positional_json["error"]["code"], "validation.profile_not_found",
        "positional form must resolve to the profile-not-found error"
    );

    // The envelopes are identical once request_id is stripped: proof that
    // `--profile <NAME>` reaches the same code path as the positional `<NAME>`.
    assert_eq!(
        strip_request_id(positional_json),
        strip_request_id(flag_json),
        "the two invocations must produce the same stdout envelope after \
         stripping request_id"
    );
}
