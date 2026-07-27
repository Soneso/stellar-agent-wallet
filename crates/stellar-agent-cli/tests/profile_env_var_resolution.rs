//! `--profile` beats `STELLAR_AGENT_PROFILE`, which beats `"default"` — pinned
//! per verb family through the release BINARY.
//!
//! `docs/cli-reference/index.md` documents that order for every command. A
//! subcommand whose `--profile` carries a clap `default_value` can never
//! observe the environment variable, because clap has already substituted the
//! literal, so this order is only real if each verb takes an `Option<String>`
//! and resolves it. Driving `env!("CARGO_BIN_EXE_stellar-agent")` as a
//! subprocess is what makes the assertion cover real clap dispatch rather than
//! a re-implementation of it.
//!
//! # What each test observes
//!
//! Every test asserts the profile that was actually LOADED, never the exit
//! code — a run that ignores the variable also exits 1, just for a different
//! reason.
//!
//! - `trustline` trusts `profile.rpc_url`, so two fixtures carrying distinct
//!   unreachable endpoints name the loaded profile in the RPC-failure message.
//! - `counterparty list` echoes the resolved name in its success envelope.
//! - `pool list` refuses an uninitialised pool only once the profile loads, so
//!   the wire code distinguishes "loaded the named profile" from "looked for
//!   `default`".
//! - `profile init` writes `<profiles>/<name>.toml`, so the created path is
//!   the observation.
//! - The startup advisory (pre-dispatch, in `main.rs`) resolves an audit-log
//!   path per profile; an unreadable log at that path makes it name the path
//!   in a `warn!` on stderr.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` redirects every data-root-derived path and is set on
//! CHILD processes only, never on the test process. Profile fixtures are
//! written in-process through `stellar-agent-core`'s own loader, so no test
//! depends on a host profile directory. The headless keyring backend is forced
//! on every child so no run can reach the login keychain.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only; resolution order is asserted via panic-on-violation"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};

/// Profile named only by `STELLAR_AGENT_PROFILE` in every test below.
const ENV_PROFILE: &str = "i113-env-profile";
/// Profile named only by `--profile` in the precedence tests.
const FLAG_PROFILE: &str = "i113-flag-profile";

/// Unreachable endpoint of [`ENV_PROFILE`]. Only the scheme, host, and port
/// survive `redact_url_authority`, so the port is the discriminator.
const ENV_PROFILE_RPC: &str = "http://127.0.0.1:9/i113-env";
/// Unreachable endpoint of [`FLAG_PROFILE`].
const FLAG_PROFILE_RPC: &str = "http://127.0.0.1:19/i113-flag";
/// Unreachable endpoint of the `default` fixture, present so that a run which
/// silently fell back to `"default"` is distinguishable from one that refused.
const DEFAULT_PROFILE_RPC: &str = "http://127.0.0.1:29/i113-default";

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
/// The suite never reads or writes a credential through it; it exists so the
/// backend initialises without a login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// A funded-looking G-strkey; `trustline` validates the form before any RPC
/// call, and the account is never fetched successfully because every fixture
/// endpoint is unreachable.
const SOURCE_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// Writes a `noop`-engine testnet profile fixture into `<home>/profiles`.
///
/// The audit-log path is pinned inside `home` as well, so a child process can
/// never append to a host audit log.
fn write_profile(home: &Path, name: &str, rpc_url: &str) {
    let signer = KeyringEntryRef::default_signer(name);
    let nonce = KeyringEntryRef::default_nonce(name);
    let profile = Profile::builder_testnet_named(
        name,
        &signer.service,
        &signer.account,
        &nonce.service,
        &nonce.account,
    )
    .rpc_url(rpc_url.to_owned())
    .audit_log_path(home.join("audit").join(format!("{name}.jsonl")))
    .with_noop_engine()
    .build();

    save_new_to_dir(name, &profile, &home.join("profiles")).expect("fixture profile must persist");
}

/// Output of one child invocation.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    /// Parses stdout as the single JSON envelope every command emits.
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "stdout must be a single JSON envelope ({e}); stdout={} stderr={}",
                self.stdout, self.stderr
            )
        })
    }
}

/// Spawns the CLI with `STELLAR_AGENT_HOME` pointed at `home` and an optional
/// `STELLAR_AGENT_PROFILE` value, and returns the captured output.
fn run_cli(home: &Path, env_profile: Option<&str>, args: &[&str]) -> Run {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let mut command = Command::new(bin_path);
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        // Force the headless backend: no run in this suite may reach the OS
        // login keychain.
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY);
    match env_profile {
        Some(name) => command.env("STELLAR_AGENT_PROFILE", name),
        None => command.env_remove("STELLAR_AGENT_PROFILE"),
    };

    let output = command.output().expect("stellar-agent binary must run");
    Run {
        code: output.status.code().expect("process must exit with a code"),
        stdout: String::from_utf8(output.stdout).expect("stdout must be UTF-8"),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Creates a temp home carrying the `default`, env-named, and flag-named
/// fixtures.
fn home_with_all_fixtures() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), "default", DEFAULT_PROFILE_RPC);
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC);
    write_profile(home.path(), FLAG_PROFILE, FLAG_PROFILE_RPC);
    home
}

// ─────────────────────────────────────────────────────────────────────────────
// STELLAR_AGENT_HOME reaches the child (precondition for every test below)
// ─────────────────────────────────────────────────────────────────────────────

/// The redirected data root is the one the child reads.
///
/// If this fails, every other assertion in this file would be reading the
/// host's real profile directory, so it is pinned first rather than assumed.
#[test]
fn the_child_process_reads_the_redirected_data_root() {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC);

    let run = run_cli(
        home.path(),
        None,
        &["profile", "show", "--profile", ENV_PROFILE],
    );
    assert_eq!(
        run.code, 0,
        "the fixture written into the redirected home must load; stdout={} stderr={}",
        run.stdout, run.stderr
    );
    assert_eq!(
        run.json()["data"]["rpc_url"],
        ENV_PROFILE_RPC,
        "the loaded profile must be the fixture, not a host profile of the same name"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// trustline — the endpoint discriminator
// ─────────────────────────────────────────────────────────────────────────────

/// Runs `trustline` against a fixture profile and returns the run.
///
/// `USDC` resolves through the testnet pin table, so the command reaches the
/// source-account fetch and fails against the fixture's unreachable endpoint —
/// which is exactly the observation: the failure message names the endpoint,
/// and therefore the profile.
fn run_trustline(home: &Path, env_profile: Option<&str>, extra: &[&str]) -> Run {
    let mut args = vec!["trustline", "--from", SOURCE_G, "--asset", "USDC"];
    args.extend_from_slice(extra);
    run_cli(home, env_profile, &args)
}

#[test]
fn trustline_loads_the_profile_named_by_the_environment_variable() {
    let home = home_with_all_fixtures();

    let run = run_trustline(home.path(), Some(ENV_PROFILE), &[]);
    let json = run.json();
    let message = json.to_string();

    assert_eq!(
        run.code, 1,
        "an unreachable endpoint must exit 1: {message}"
    );
    assert!(
        message.contains("127.0.0.1:9"),
        "the variable must select the profile whose endpoint is {ENV_PROFILE_RPC}: {message}"
    );
    assert!(
        !message.contains("127.0.0.1:29"),
        "the `default` fixture must not be loaded when the variable names a profile: {message}"
    );
}

#[test]
fn trustline_profile_flag_beats_the_environment_variable() {
    let home = home_with_all_fixtures();

    let run = run_trustline(home.path(), Some(ENV_PROFILE), &["--profile", FLAG_PROFILE]);
    let message = run.json().to_string();

    assert!(
        message.contains("127.0.0.1:19"),
        "`--profile` must win over the variable: {message}"
    );
    assert!(
        !message.contains("127.0.0.1:9"),
        "the variable's profile must not be loaded when the flag names one: {message}"
    );
}

#[test]
fn trustline_falls_back_to_default_when_neither_input_is_supplied() {
    let home = home_with_all_fixtures();

    let run = run_trustline(home.path(), None, &[]);
    let message = run.json().to_string();

    assert!(
        message.contains("127.0.0.1:29"),
        "with no flag and no variable the `default` profile must load: {message}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// counterparty list — the resolved name is echoed in the envelope
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn counterparty_list_uses_the_profile_named_by_the_environment_variable() {
    let home = home_with_all_fixtures();

    let run = run_cli(home.path(), Some(ENV_PROFILE), &["counterparty", "list"]);
    let json = run.json();

    assert_eq!(
        run.code, 0,
        "listing an empty cache succeeds; stdout={} stderr={}",
        run.stdout, run.stderr
    );
    assert_eq!(
        json["data"]["profile"], ENV_PROFILE,
        "the listed cache must belong to the profile the variable names: {json}"
    );
}

#[test]
fn counterparty_list_profile_flag_beats_the_environment_variable() {
    let home = home_with_all_fixtures();

    let run = run_cli(
        home.path(),
        Some(ENV_PROFILE),
        &["counterparty", "list", "--profile", FLAG_PROFILE],
    );

    assert_eq!(
        run.json()["data"]["profile"],
        FLAG_PROFILE,
        "`--profile` must win over the variable"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// pool list — the manual `.unwrap_or("default")` shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pool_list_uses_the_profile_named_by_the_environment_variable() {
    let home = tempfile::tempdir().expect("temp home");
    // Only the env-named profile exists: a run that resolved `"default"` would
    // refuse with `validation.profile_not_found` instead of reaching the
    // pool-not-initialised refusal, which is what distinguishes the two.
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC);

    let run = run_cli(home.path(), Some(ENV_PROFILE), &["pool", "list"]);
    let json = run.json();

    assert_eq!(run.code, 1, "an uninitialised pool exits 1: {json}");
    assert_eq!(
        json["error"]["code"], "internal.unexpected_state",
        "the variable's profile must load and refuse on the pool config, not on the \
         profile lookup: {json}"
    );
    assert!(
        json["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("pool.not_initialised")),
        "the refusal must be the pool-not-initialised one: {json}"
    );
}

#[test]
fn pool_list_profile_flag_beats_the_environment_variable() {
    let home = tempfile::tempdir().expect("temp home");
    // Only the flag-named profile exists, so a run that honoured the variable
    // over the flag would refuse with `validation.profile_not_found`.
    write_profile(home.path(), FLAG_PROFILE, FLAG_PROFILE_RPC);

    let run = run_cli(
        home.path(),
        Some(ENV_PROFILE),
        &["pool", "list", "--profile", FLAG_PROFILE],
    );
    let json = run.json();

    assert_eq!(
        json["error"]["code"], "internal.unexpected_state",
        "`--profile` must win over the variable: {json}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// profile init — the created file is the observation
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn profile_init_creates_the_profile_named_by_the_environment_variable() {
    let home = tempfile::tempdir().expect("temp home");

    let run = run_cli(
        home.path(),
        Some(ENV_PROFILE),
        &["profile", "init", "--engine", "noop"],
    );
    let json = run.json();

    assert_eq!(
        run.code, 0,
        "init on a clean home must succeed; stdout={} stderr={}",
        run.stdout, run.stderr
    );
    assert_eq!(
        json["data"]["profile"], ENV_PROFILE,
        "init must create the profile the variable names: {json}"
    );
    assert!(
        home.path()
            .join("profiles")
            .join(format!("{ENV_PROFILE}.toml"))
            .exists(),
        "the created file must be <profiles>/{ENV_PROFILE}.toml"
    );
    assert!(
        !home.path().join("profiles").join("default.toml").exists(),
        "no `default.toml` may be created when the variable names a profile"
    );
}

#[test]
fn profile_init_profile_flag_beats_the_environment_variable() {
    let home = tempfile::tempdir().expect("temp home");

    let run = run_cli(
        home.path(),
        Some(ENV_PROFILE),
        &[
            "profile",
            "init",
            "--engine",
            "noop",
            "--profile",
            FLAG_PROFILE,
        ],
    );

    assert_eq!(run.code, 0, "init must succeed; stderr={}", run.stderr);
    assert!(
        home.path()
            .join("profiles")
            .join(format!("{FLAG_PROFILE}.toml"))
            .exists(),
        "`--profile` must win over the variable"
    );
    assert!(
        !home
            .path()
            .join("profiles")
            .join(format!("{ENV_PROFILE}.toml"))
            .exists(),
        "the variable's profile must not be created when the flag names one"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Startup advisory (main.rs, pre-dispatch)
// ─────────────────────────────────────────────────────────────────────────────

/// Writes an audit log the advisory cannot open, so its skip-`warn!` names the
/// path — and therefore the profile the advisory resolved.
///
/// The advisory short-circuits on an absent or empty file, so the fixture must
/// exist and be non-empty; its content is not a valid hash-chained log, which
/// is what makes the open fail loudly instead of silently succeeding.
fn write_unreadable_audit_log(home: &Path, profile: &str) {
    let dir = home.join("audit");
    std::fs::create_dir_all(&dir).expect("audit dir");
    std::fs::write(
        dir.join(format!("{profile}.jsonl")),
        b"not-a-hash-chained-audit-row\n",
    )
    .expect("audit fixture");
}

#[test]
fn startup_advisory_scans_the_audit_log_of_the_environment_variable_profile() {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC);
    write_unreadable_audit_log(home.path(), ENV_PROFILE);
    write_unreadable_audit_log(home.path(), "default");

    // `counterparty list` resolves the variable, so the advisory must too.
    let run = run_cli(home.path(), Some(ENV_PROFILE), &["counterparty", "list"]);

    assert!(
        run.stderr.contains(&format!("{ENV_PROFILE}.jsonl")),
        "the advisory must scan the audit log of the profile the variable names; \
         stderr={}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("default.jsonl"),
        "the advisory must not fall back to `default` when the variable names a \
         profile; stderr={}",
        run.stderr
    );
}

#[test]
fn startup_advisory_profile_flag_beats_the_environment_variable() {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), FLAG_PROFILE, FLAG_PROFILE_RPC);
    write_unreadable_audit_log(home.path(), FLAG_PROFILE);
    write_unreadable_audit_log(home.path(), ENV_PROFILE);

    let run = run_cli(
        home.path(),
        Some(ENV_PROFILE),
        &["counterparty", "list", "--profile", FLAG_PROFILE],
    );

    assert!(
        run.stderr.contains(&format!("{FLAG_PROFILE}.jsonl")),
        "`--profile` must select the advisory's audit log; stderr={}",
        run.stderr
    );
    assert!(
        !run.stderr.contains(&format!("{ENV_PROFILE}.jsonl")),
        "the variable must not select the advisory's audit log when the flag names a \
         profile; stderr={}",
        run.stderr
    );
}

/// The advisory scans the log the COMMAND writes, not the one the environment
/// variable names, for a verb whose `--profile` carries a clap default.
///
/// `pay` audits under the literal `"default"` regardless of the variable
/// (`pay.rs`'s field is a `String` with `default_value = "default"`, and its
/// value-audit rows are keyed on that name). An advisory that resolved the
/// variable independently would open — and append advisory rows to — an
/// unrelated profile's audit log.
#[test]
fn startup_advisory_follows_a_defaulted_verb_rather_than_the_environment_variable() {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC);
    write_unreadable_audit_log(home.path(), ENV_PROFILE);
    write_unreadable_audit_log(home.path(), "default");

    let run = run_cli(
        home.path(),
        Some(ENV_PROFILE),
        &[
            "pay",
            "--source",
            SOURCE_G,
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            "1",
            "--build-only",
        ],
    );

    assert!(
        run.stderr.contains("default.jsonl"),
        "the advisory must scan the log `pay` itself uses; stderr={}",
        run.stderr
    );
    assert!(
        !run.stderr.contains(&format!("{ENV_PROFILE}.jsonl")),
        "the advisory must not resolve the variable independently of the verb; \
         stderr={}",
        run.stderr
    );
}
