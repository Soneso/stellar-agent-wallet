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
//! - `pay`, `claim`, and `accounts create` receive one unreachable
//!   `--rpc-url` in every run, so the endpoint does not discriminate the
//!   profile for them. They are pinned on the per-profile
//!   audit-log path the startup advisory opens. That is the advisory's
//!   resolution of the verb's own parsed `--profile` value
//!   (`main.rs`'s `profile_flag`), not the verb's own load, so it observes
//!   the same clap field and the same resolver one step earlier. The verb's
//!   own resolution is pinned separately, on the refusal it emits, in
//!   `profile_provenance_refusal.rs`.
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
use stellar_agent_test_support::ConnectionCounter;

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

/// An unreachable loopback endpoint. This suite runs in the offline gate, so
/// no child may reach a live endpoint.
const UNREACHABLE_RPC: &str = "http://127.0.0.1:9";

/// The unreachable loopback endpoint for a mainnet profile file, which the
/// loader accepts only as `https://`.
const UNREACHABLE_HTTPS_RPC: &str = "https://127.0.0.1:9";

/// Writes a `noop`-engine testnet profile fixture into `<home>/profiles`.
///
/// The audit-log path is pinned inside `home` as well, so a child process can
/// never append to a host audit log.
fn write_profile(home: &Path, name: &str, rpc_url: &str, secondary_rpc_url: Option<&str>) {
    let signer = KeyringEntryRef::default_signer(name);
    let nonce = KeyringEntryRef::default_nonce(name);
    let mut profile = Profile::builder_testnet_named(
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

    profile.secondary_rpc_url = secondary_rpc_url.map(str::to_owned);

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
    run_cli_with_env(home, env_profile, args, &[])
}

fn run_cli_with_env(
    home: &Path,
    env_profile: Option<&str>,
    args: &[&str],
    overlay: &[(&str, &str)],
) -> Run {
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

    command
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL")
        .env_remove("STELLAR_AGENT_ORACLE_PROVIDER_URL")
        .env_remove("STELLAR_AGENT_MCP_SIGNER_DEFAULT")
        .env_remove("FLAG_RULES_UNSET_SEED");
    for (name, value) in overlay {
        command.env(name, value);
    }
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
    write_profile(home.path(), "default", DEFAULT_PROFILE_RPC, None);
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC, None);
    write_profile(home.path(), FLAG_PROFILE, FLAG_PROFILE_RPC, None);
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
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC, None);

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
        "http://127.0.0.1:9",
        "the loaded profile must be the fixture, not a host profile of the same name"
    );
}

#[test]
fn profile_show_redacts_every_url_component_with_credentials() {
    let home = tempfile::tempdir().expect("temp home");
    write_profile(
        home.path(),
        "redacted",
        "http://user:SENTINEL-CRED@127.0.0.1:9/SENTINEL-PATH?k=SENTINEL-QUERY",
        Some(
            "http://user:SENTINEL-SECONDARY@127.0.0.1:19/SENTINEL-SECONDARY-PATH?k=SENTINEL-SECONDARY-QUERY",
        ),
    );
    let run = run_cli(
        home.path(),
        None,
        &["profile", "show", "--profile", "redacted"],
    );
    assert_eq!(run.code, 0, "{} {}", run.stdout, run.stderr);
    assert!(!run.stdout.contains("SENTINEL"), "{}", run.stdout);
    assert_eq!(run.json()["data"]["rpc_url"], "http://127.0.0.1:9");
    assert_eq!(
        run.json()["data"]["secondary_rpc_url"],
        "http://127.0.0.1:19"
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
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC, None);

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
    write_profile(home.path(), FLAG_PROFILE, FLAG_PROFILE_RPC, None);

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
    write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC, None);
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
    write_profile(home.path(), FLAG_PROFILE, FLAG_PROFILE_RPC, None);
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

// ─────────────────────────────────────────────────────────────────────────────
// pay / claim / accounts create — the audit-log path is the observation
// ─────────────────────────────────────────────────────────────────────────────
//
// Every run of these three receives the same unreachable `--rpc-url`, so the
// endpoint discriminator used above does not apply to them.
// Their audit surface is keyed on the resolved profile name
// (`commands/value_audit.rs`), and the startup advisory opens that same
// per-profile audit-log path by running the verb's own parsed `--profile`
// value through the same resolver (`main.rs`'s `profile_flag`) — so an
// unreadable log at `<name>.jsonl` names the profile that field resolves to.
// What this pins is the clap field plus the resolver; the verb's own load of
// that name is pinned on its refusal in `profile_provenance_refusal.rs`.

/// The argument vector for each moved verb, minus any profile selector.
///
/// Every one is refused or fails on the endpoint long after the advisory has
/// run; the advisory's `warn!` is the observation, not the exit code.
const MOVED_VERB_ARGS: &[(&str, &[&str])] = &[
    (
        "pay",
        &[
            "pay",
            "--source",
            SOURCE_G,
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            "1 XLM",
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
    ),
    (
        "claim",
        &[
            "claim",
            "000000000000000000000000000000000000000000000000000000000000000000000000",
            "--source",
            SOURCE_G,
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
    ),
    (
        "accounts create",
        &[
            "accounts",
            "create",
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            "--sponsor",
            SOURCE_G,
            "--starting-balance",
            "1 XLM",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
    ),
];

/// Asserts the child failed on the loopback endpoint it was given, which is
/// also the proof that it reached no live endpoint.
fn assert_reached_only_the_unreachable_endpoint(run: &Run, verb: &str) {
    let json = run.json();
    let message = json["error"]["message"].as_str().unwrap_or_default();
    assert_eq!(
        json["error"]["code"], "network.rpc_unreachable",
        "`{verb}` must fail on the endpoint it was handed, not reach a live one: {json}"
    );
    assert!(
        message.contains("127.0.0.1:9"),
        "`{verb}` must contact only the unreachable loopback endpoint: {message}"
    );
}

#[test]
fn the_moved_verbs_audit_under_the_profile_named_by_the_environment_variable() {
    for (verb, argv) in MOVED_VERB_ARGS {
        let home = tempfile::tempdir().expect("temp home");
        write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC, None);
        write_profile(home.path(), "default", DEFAULT_PROFILE_RPC, None);
        write_unreadable_audit_log(home.path(), ENV_PROFILE);
        write_unreadable_audit_log(home.path(), "default");

        let run = run_cli(home.path(), Some(ENV_PROFILE), argv);

        assert_reached_only_the_unreachable_endpoint(&run, verb);
        assert!(
            run.stderr.contains(&format!("{ENV_PROFILE}.jsonl")),
            "`{verb}` must audit under the profile the variable names; stderr={}",
            run.stderr
        );
        assert!(
            !run.stderr.contains("default.jsonl"),
            "`{verb}` must not fall back to `default` when the variable names a \
             profile; stderr={}",
            run.stderr
        );
    }
}

#[test]
fn the_moved_verbs_let_the_profile_flag_beat_the_environment_variable() {
    for (verb, argv) in MOVED_VERB_ARGS {
        let home = tempfile::tempdir().expect("temp home");
        write_profile(home.path(), ENV_PROFILE, ENV_PROFILE_RPC, None);
        write_profile(home.path(), FLAG_PROFILE, FLAG_PROFILE_RPC, None);
        write_unreadable_audit_log(home.path(), ENV_PROFILE);
        write_unreadable_audit_log(home.path(), FLAG_PROFILE);

        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", FLAG_PROFILE]);
        let run = run_cli(home.path(), Some(ENV_PROFILE), &args);

        assert_reached_only_the_unreachable_endpoint(&run, verb);
        assert!(
            run.stderr.contains(&format!("{FLAG_PROFILE}.jsonl")),
            "`{verb}`: `--profile` must win over the variable; stderr={}",
            run.stderr
        );
        assert!(
            !run.stderr.contains(&format!("{ENV_PROFILE}.jsonl")),
            "`{verb}`: the variable's profile must not be audited when the flag names \
             one; stderr={}",
            run.stderr
        );
    }
}

/// Writes a `noop`-engine mainnet profile fixture whose `rpc_url` is `rpc_url`.
///
/// A caller that expects the profile to load passes an `https://` URL, because
/// the loader refuses a plaintext mainnet endpoint. A caller that asserts no
/// endpoint contact passes a
/// [`ConnectionCounter`]'s URL and checks its count: a plaintext HTTP mock
/// records no request for a TLS attempt.
fn write_mainnet_profile(home: &Path, name: &str, rpc_url: &str) {
    let profile = Profile::builder_mainnet_named(name, rpc_url, "s", "a", "n", "a")
        .audit_log_path(home.join("audit").join(format!("{name}.jsonl")))
        .with_noop_engine()
        .build();
    save_new_to_dir(name, &profile, &home.join("profiles")).unwrap();
}

/// Starts a [`ConnectionCounter`] for an endpoint no child may contact.
fn connection_counter() -> ConnectionCounter {
    ConnectionCounter::start().expect("loopback connection counter")
}

/// Asserts that no child connected to `counter`.
fn assert_no_contact(counter: &ConnectionCounter) {
    assert_eq!(
        counter.accepted().expect("connection count"),
        0,
        "no connection may reach the profile's endpoint"
    );
}

/// Removes the `rpc_url` line from a written profile file, as an operator who
/// never set one would leave it.
fn remove_rpc_url(home: &Path, name: &str) {
    let path = home.join("profiles").join(format!("{name}.toml"));
    let toml = std::fs::read_to_string(&path).unwrap();
    let stripped: Vec<&str> = toml
        .lines()
        .filter(|line| !line.starts_with("rpc_url"))
        .collect();
    assert_ne!(
        stripped.len(),
        toml.lines().count(),
        "the fixture must carry an rpc_url line to remove"
    );
    std::fs::write(&path, stripped.join("\n")).unwrap();
}

#[test]
fn chain_id_environment_overlay_refuses_testnet_profile() {
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), "testnet", UNREACHABLE_RPC, None);
    let run = run_cli_with_env(
        home.path(),
        None,
        &["profile", "show", "--profile", "testnet"],
        &[("STELLAR_AGENT_CHAIN_ID", "stellar:mainnet")],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "profile.non_overlayable_field");
}

/// Trust-root overlays are refused on a testnet profile, naming the key.
#[test]
fn trust_root_environment_overlays_refuse_testnet_profile() {
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), "testnet", UNREACHABLE_RPC, None);
    for (variable, value, key) in [
        (
            "STELLAR_AGENT_AUDIT_LOG_PATH",
            "/tmp/overlay-audit.jsonl",
            "audit_log_path",
        ),
        (
            "STELLAR_AGENT_ATTESTATION_KEY_ID",
            "{service=\"x\",account=\"y\"}",
            "attestation_key_id",
        ),
    ] {
        let run = run_cli_with_env(
            home.path(),
            None,
            &["profile", "show", "--profile", "testnet"],
            &[(variable, value)],
        );
        assert_eq!(run.code, 1, "{variable}: {} {}", run.stdout, run.stderr);
        let json = run.json();
        assert_eq!(json["error"]["code"], "profile.non_overlayable_field");
        assert!(
            json["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(key)),
            "{variable} must name {key}: {json}"
        );
    }
}

#[test]
fn rpc_environment_overlay_refuses_mainnet_profile() {
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", UNREACHABLE_HTTPS_RPC);
    let run = run_cli_with_env(
        home.path(),
        None,
        &["profile", "show", "--profile", "mainnet"],
        &[("STELLAR_AGENT_RPC_URL", "https://overlay.example")],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "profile.non_overlayable_field");
}

#[test]
fn trustline_mainnet_rpc_overlay_refuses_before_endpoint_contact() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = connection_counter();
    let overlay_url = endpoint.https_uri();
    write_mainnet_profile(home.path(), "mainnet", &overlay_url);
    let run = run_cli_with_env(
        home.path(),
        None,
        &[
            "trustline",
            "--from",
            SOURCE_G,
            "--asset",
            "USDC",
            "--profile",
            "mainnet",
        ],
        &[("STELLAR_AGENT_RPC_URL", &overlay_url)],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "profile.non_overlayable_field");
    assert_no_contact(&endpoint);
}

#[test]
fn trustline_mainnet_environment_refuses_before_endpoint_contact() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = connection_counter();
    write_mainnet_profile(home.path(), "mainnet", &endpoint.https_uri());
    let run = run_trustline(home.path(), Some("mainnet"), &[]);
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(
        run.json()["error"]["code"],
        "profile.mainnet_requires_explicit_profile"
    );
    assert_no_contact(&endpoint);
}

/// A mainnet profile file without `rpc_url` refuses with the typed code on
/// `trustline`, whose other load failures report
/// `trustline.profile_load_failed`.
#[test]
fn trustline_mainnet_profile_without_rpc_url_reports_the_typed_code() {
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", UNREACHABLE_HTTPS_RPC);
    remove_rpc_url(home.path(), "mainnet");
    let run = run_trustline(home.path(), None, &["--profile", "mainnet"]);
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(
        run.json()["error"]["code"],
        "validation.mainnet_rpc_url_required"
    );
}

#[test]
fn trustline_mainnet_flag_passes_selection() {
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", UNREACHABLE_HTTPS_RPC);
    let run = run_trustline(home.path(), Some("mainnet"), &["--profile", "mainnet"]);
    assert_ne!(
        run.json()["error"]["code"],
        "profile.mainnet_requires_explicit_profile",
        "{}",
        run.stdout
    );
}

fn assert_registration_environment_refuses(verb: &str, extra: &[&str]) {
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", UNREACHABLE_HTTPS_RPC);
    let registry = home.path().join("networks.toml");
    let mut args = vec!["smart-account", verb];
    args.extend_from_slice(extra);
    let run = run_cli_with_env(
        home.path(),
        Some("mainnet"),
        &args,
        &[(
            stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            registry.to_str().unwrap(),
        )],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(
        run.json()["error"]["code"],
        "profile.mainnet_requires_explicit_profile"
    );
    assert!(!registry.exists(), "refusal must precede registry writes");
}

#[test]
fn register_multicall_mainnet_environment_refuses_without_registry_write() {
    assert_registration_environment_refuses(
        "register-multicall",
        &[
            "--address",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--wasm-sha256",
            stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256,
        ],
    );
}

#[test]
fn unregister_multicall_mainnet_environment_refuses_without_registry_write() {
    assert_registration_environment_refuses("unregister-multicall", &[]);
}

#[test]
fn protected_secondary_and_signer_environment_overlays_refuse_mainnet() {
    for (variable, value) in [
        (
            "STELLAR_AGENT_SECONDARY_RPC_URL",
            "https://secondary.example",
        ),
        ("STELLAR_AGENT_MCP_SIGNER_DEFAULT", "x"),
    ] {
        let home = tempfile::tempdir().unwrap();
        write_mainnet_profile(home.path(), "mainnet", UNREACHABLE_HTTPS_RPC);
        let run = run_cli_with_env(
            home.path(),
            None,
            &["profile", "show", "--profile", "mainnet"],
            &[(variable, value)],
        );
        assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
        assert_eq!(run.json()["error"]["code"], "profile.non_overlayable_field");
    }
}

/// `STELLAR_AGENT_ORACLE_PROVIDER_URL` is refused on a mainnet profile, for a
/// value different from the file's and for an equal one.
#[test]
fn oracle_environment_overlay_refuses_mainnet_profile() {
    let file_oracle = "https://oracle.example.invalid/";
    for overlay in ["https://overlay.example.invalid/", file_oracle] {
        let home = tempfile::tempdir().unwrap();
        let mut profile =
            Profile::builder_mainnet_named("mainnet", UNREACHABLE_HTTPS_RPC, "s", "a", "n", "a")
                .audit_log_path(home.path().join("audit").join("mainnet.jsonl"))
                .with_noop_engine()
                .build();
        profile.oracle_provider_url = Some(file_oracle.parse().unwrap());
        save_new_to_dir("mainnet", &profile, &home.path().join("profiles")).unwrap();
        let run = run_cli_with_env(
            home.path(),
            None,
            &["profile", "show", "--profile", "mainnet"],
            &[("STELLAR_AGENT_ORACLE_PROVIDER_URL", overlay)],
        );
        assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
        assert_eq!(run.json()["error"]["code"], "profile.non_overlayable_field");
    }
}

/// The testnet control: the same variable applies to a testnet profile.
#[test]
fn oracle_environment_overlay_applies_to_testnet_profile() {
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), "testnet", UNREACHABLE_RPC, None);
    let run = run_cli_with_env(
        home.path(),
        None,
        &["profile", "show", "--profile", "testnet"],
        &[(
            "STELLAR_AGENT_ORACLE_PROVIDER_URL",
            "https://overlay.example.invalid/",
        )],
    );
    assert_eq!(run.code, 0, "{} {}", run.stdout, run.stderr);
    assert_eq!(
        run.json()["data"]["oracle_provider_url"],
        "https://overlay.example.invalid"
    );
}

fn pay_base() -> Vec<&'static str> {
    vec![
        "pay",
        SOURCE_G,
        "1 XLM",
        "--source",
        SOURCE_G,
        "--build-only",
    ]
}

/// A mainnet profile file whose `rpc_url` is plaintext refuses to load:
/// `profile show` and a raw-code value verb both report
/// `validation.config_invalid`, and nothing contacts the endpoint.
#[test]
fn plaintext_mainnet_endpoint_refuses_on_show_and_on_a_value_verb() {
    let counter = connection_counter();
    let plaintext = counter.https_uri().replacen("https://", "http://", 1);
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", &plaintext);
    let mut pay = pay_base();
    pay.extend(["--profile", "mainnet"]);
    for args in [vec!["profile", "show", "--profile", "mainnet"], pay] {
        let run = run_cli(home.path(), None, &args);
        assert_eq!(run.code, 1, "{args:?}: {} {}", run.stdout, run.stderr);
        assert_eq!(
            run.json()["error"]["code"],
            "validation.config_invalid",
            "{args:?}: {}",
            run.stdout
        );
    }
    assert_no_contact(&counter);
}

#[test]
fn mainnet_profile_flags_refuse_before_endpoint_contact() {
    let rpc = connection_counter();
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", &rpc.https_uri());
    for (flags, code) in [
        (
            vec!["--rpc-url".to_owned(), rpc.https_uri()],
            "profile.non_overlayable_field",
        ),
        (
            vec!["--network".to_owned(), "testnet".to_owned()],
            "profile.network_flag_mismatch",
        ),
        (vec![], "network.mainnet_write_forbidden"),
    ] {
        let mut args = pay_base();
        args.extend(["--profile", "mainnet"]);
        args.extend(flags.iter().map(String::as_str));
        let run = run_cli(home.path(), None, &args);
        assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
        assert_eq!(run.json()["error"]["code"], code);
    }
    assert_no_contact(&rpc);
}

#[tokio::test]
async fn mainnet_flag_on_zero_config_refuses_before_endpoint_contact() {
    let rpc = wiremock::MockServer::start().await;
    let home = tempfile::tempdir().unwrap();
    let endpoint = rpc.uri();
    let mut args = pay_base();
    args.extend(["--network", "mainnet", "--rpc-url", &endpoint]);
    let run = run_cli(home.path(), None, &args);
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "profile.network_flag_mismatch");
    assert!(rpc.received_requests().await.unwrap().is_empty());
}

#[test]
fn mainnet_signers_list_rpc_flag_refuses_before_endpoint_contact() {
    let rpc = connection_counter();
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", &rpc.https_uri());
    let run = run_cli(
        home.path(),
        None,
        &[
            "smart-account",
            "signers",
            "list",
            "--rule-id",
            "0",
            "--account",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "--profile",
            "mainnet",
            "--rpc-url",
            &rpc.https_uri(),
        ],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "profile.non_overlayable_field");
    assert_no_contact(&rpc);
}

#[test]
fn fees_stats_mainnet_equal_rpc_flag_refuses() {
    let home = tempfile::tempdir().unwrap();
    let endpoint = "https://mainnet.sorobanrpc.com";
    write_mainnet_profile(home.path(), "mainnet", endpoint);
    let run = run_cli(
        home.path(),
        None,
        &[
            "fees",
            "stats",
            "--profile",
            "mainnet",
            "--rpc-url",
            endpoint,
        ],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "profile.non_overlayable_field");
}

/// A credentialed `--rpc-url` is a usage error: exit `1` with one
/// `validation.usage_error` envelope, and neither stream echoes the userinfo.
#[test]
fn credentialed_rpc_flag_is_a_usage_error_without_echoing_credentials() {
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", UNREACHABLE_HTTPS_RPC);
    let mut args = pay_base();
    args.extend([
        "--profile",
        "mainnet",
        "--rpc-url",
        "https://user:SENTINEL@rpc.example",
    ]);
    let run = run_cli(home.path(), None, &args);
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "validation.usage_error");
    assert!(run.stderr.is_empty(), "{}", run.stderr);
    for stream in [&run.stdout, &run.stderr] {
        assert!(!stream.contains("SENTINEL"), "{stream}");
        assert!(!stream.contains("user"), "{stream}");
    }
}

#[test]
fn registration_profile_load_failures_leave_the_registry_absent() {
    for verb in ["register-multicall", "unregister-multicall"] {
        for malformed in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let registry = home.path().join("networks.toml");
            if malformed {
                std::fs::create_dir_all(home.path().join("profiles")).unwrap();
                std::fs::write(home.path().join("profiles/broken.toml"), "not = [toml").unwrap();
            }
            let mut args = vec!["smart-account", verb, "--profile", "broken"];
            if verb == "register-multicall" {
                args.extend([
                    "--address",
                    "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
                    "--wasm-sha256",
                    stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256,
                ]);
            }
            let run = run_cli_with_env(
                home.path(),
                None,
                &args,
                &[(
                    stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
                    registry.to_str().unwrap(),
                )],
            );
            assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
            assert_eq!(
                run.json()["error"]["code"],
                if malformed {
                    "validation.config_invalid"
                } else {
                    "validation.profile_not_found"
                }
            );
            assert!(!registry.exists());
        }
    }
}

fn multicall_base() -> Vec<&'static str> {
    vec![
        "smart-account",
        "multicall",
        "--smart-account",
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
        "--rule-id",
        "0",
        "--signer-secret-env",
        "FLAG_RULES_UNSET_SEED",
        "--invocation",
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM:noop:[]",
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Structural mainnet refusal on every guarded path
// ─────────────────────────────────────────────────────────────────────────────

/// A smart-account C-strkey every guarded verb accepts as an argument.
const ACCOUNT_C: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

/// A seed variable the harness removes from every child.
const UNSET_SEED: &str = "FLAG_RULES_UNSET_SEED";

/// A 64-character hex value for hash, operation id, and salt arguments.
const HEX_64: &str = "0101010101010101010101010101010101010101010101010101010101010101";

/// The code the structural refusal emits on the transaction verbs.
const MAINNET_WRITE_FORBIDDEN: &str = "network.mainnet_write_forbidden";

/// One guarded verb. It holds the name a failing row reports and its argv,
/// which carries the required arguments and no profile, network, or endpoint
/// flag. It also holds the code its structural refusal emits on a mainnet
/// profile, and whether the command takes `--network` and `--rpc-url`.
struct GuardedVerb {
    name: &'static str,
    argv: Vec<String>,
    mainnet_code: &'static str,
    takes_network_flags: bool,
}

fn guarded(name: &'static str, argv: &[&str]) -> GuardedVerb {
    GuardedVerb {
        name,
        argv: argv.iter().map(|arg| (*arg).to_owned()).collect(),
        mainnet_code: MAINNET_WRITE_FORBIDDEN,
        takes_network_flags: true,
    }
}

/// A guarded verb that reads its network from the profile alone and takes
/// neither `--network` nor `--rpc-url`.
fn guarded_profile_only(name: &'static str, argv: &[&str]) -> GuardedVerb {
    GuardedVerb {
        takes_network_flags: false,
        ..guarded(name, argv)
    }
}

/// Every path with a structural mainnet refusal. `endpoint` is the URL of the
/// counter the table observes; the friendbot arm takes it as its faucet URL as
/// well.
///
/// The friendbot row passes a malformed new account. The network layer
/// refuses mainnet with the same code as the CLI, and the CLI refusal precedes
/// the account validation, so the expected code identifies the CLI refusal.
fn guarded_verbs(endpoint: &str) -> Vec<GuardedVerb> {
    let seed = UNSET_SEED;
    let friendbot_url = format!("{endpoint}/friendbot");
    let mut verbs = vec![
        guarded(
            "pay",
            &[
                "pay",
                SOURCE_G,
                "1 XLM",
                "--source",
                SOURCE_G,
                "--secret-env",
                seed,
            ],
        ),
        guarded(
            "claim",
            &[
                "claim",
                "000000000000000000000000000000000000000000000000000000000000000000000000",
                "--source",
                SOURCE_G,
                "--secret-env",
                seed,
            ],
        ),
        guarded(
            "accounts create (sponsored)",
            &[
                "accounts",
                "create",
                "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
                "--sponsor",
                SOURCE_G,
                "--starting-balance",
                "1 XLM",
                "--secret-env",
                seed,
            ],
        ),
        GuardedVerb {
            mainnet_code: "network.friendbot_mainnet_forbidden",
            ..guarded(
                "accounts create --fund-with-friendbot",
                &[
                    "accounts",
                    "create",
                    "not-a-g-strkey",
                    "--fund-with-friendbot",
                    "--friendbot-url",
                    friendbot_url.as_str(),
                ],
            )
        },
        guarded(
            "accounts deploy-c",
            &[
                "accounts",
                "deploy-c",
                "--deployer-secret-env",
                seed,
                "--initial-signer",
                SOURCE_G,
            ],
        ),
        guarded(
            "smart-account deploy-policy",
            &[
                "smart-account",
                "deploy-policy",
                "--kind",
                "simple-threshold",
                "--deployer-secret-env",
                seed,
            ],
        ),
    ];
    for verb in [
        "deploy-ed25519-verifier",
        "deploy-spending-limit-policy",
        "deploy-webauthn-verifier",
    ] {
        verbs.push(GuardedVerb {
            name: verb,
            argv: ["smart-account", verb, "--deployer-secret-env", seed]
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect(),
            mainnet_code: MAINNET_WRITE_FORBIDDEN,
            takes_network_flags: true,
        });
    }
    let rule_verbs: [(&'static str, &[&str]); 16] = [
        ("signers list", &["signers", "list", "--rule-id", "0"]),
        ("signers refresh", &["signers", "refresh", "--rule-id", "0"]),
        (
            "signers add",
            &[
                "signers",
                "add",
                "--rule-id",
                "0",
                "--signer-delegated",
                SOURCE_G,
            ],
        ),
        (
            "signers remove",
            &["signers", "remove", "--rule-id", "0", "--signer-id", "0"],
        ),
        (
            "signers set-threshold",
            &[
                "signers",
                "set-threshold",
                "--rule-id",
                "0",
                "--new-threshold",
                "1",
            ],
        ),
        (
            "signers set-weighted-threshold",
            &[
                "signers",
                "set-weighted-threshold",
                "--rule-id",
                "0",
                "--new-threshold",
                "1",
            ],
        ),
        (
            "signers set-signer-weight",
            &[
                "signers",
                "set-signer-weight",
                "--rule-id",
                "0",
                "--new-weight",
                "1",
                "--signer-delegated",
                SOURCE_G,
            ],
        ),
        (
            "signers batch-add",
            &["signers", "batch-add", "--rule-id", "0"],
        ),
        ("rules create", &["rules", "create", "--name", "guarded"]),
        (
            "rules set-name",
            &["rules", "set-name", "--rule-id", "0", "--name", "guarded"],
        ),
        (
            "rules set-valid-until",
            &[
                "rules",
                "set-valid-until",
                "--rule-id",
                "0",
                "--valid-until",
                "none",
            ],
        ),
        ("rules delete", &["rules", "delete", "--rule-id", "0"]),
        (
            "rules verify-pins",
            &["rules", "verify-pins", "--rule-id", "0"],
        ),
        (
            "rules add-policy",
            &["rules", "add-policy", "--rule-id", "0"],
        ),
        (
            "rules remove-policy",
            &[
                "rules",
                "remove-policy",
                "--rule-id",
                "0",
                "--policy-id",
                "0",
            ],
        ),
        (
            "rules set-spending-limit",
            &[
                "rules",
                "set-spending-limit",
                "--rule-id",
                "0",
                "--limit",
                "1",
            ],
        ),
    ];
    for (name, tail) in rule_verbs {
        let mut argv = vec!["smart-account".to_owned()];
        argv.extend(tail.iter().map(|arg| (*arg).to_owned()));
        argv.extend(
            ["--account", ACCOUNT_C, "--signer-secret-env", seed]
                .iter()
                .map(|arg| (*arg).to_owned()),
        );
        verbs.push(GuardedVerb {
            name,
            argv,
            mainnet_code: MAINNET_WRITE_FORBIDDEN,
            takes_network_flags: true,
        });
    }
    verbs.extend([
        guarded(
            "smart-account execute",
            &[
                "smart-account",
                "execute",
                "--account",
                ACCOUNT_C,
                "--contract",
                ACCOUNT_C,
                "--function",
                "noop",
                "--auth-rule-id",
                "0",
                "--rule-signer-ed25519-secret-env",
                seed,
                "--signer-secret-env",
                seed,
            ],
        ),
        guarded(
            "smart-account migrate-verifier",
            &[
                "smart-account",
                "migrate-verifier",
                "--account",
                ACCOUNT_C,
                "--from",
                HEX_64,
                "--to",
                ACCOUNT_C,
                "--signer-secret-env",
                seed,
            ],
        ),
        guarded(
            "smart-account timelock schedule",
            &[
                "smart-account",
                "timelock",
                "schedule",
                "--timelock",
                ACCOUNT_C,
                "--target",
                ACCOUNT_C,
                "--function",
                "upgrade",
                "--delay-ledgers",
                "1",
                "--signer-secret-env",
                seed,
            ],
        ),
        guarded(
            "smart-account timelock cancel",
            &[
                "smart-account",
                "timelock",
                "cancel",
                "--timelock",
                ACCOUNT_C,
                "--operation-id",
                HEX_64,
                "--signer-secret-env",
                seed,
            ],
        ),
        guarded(
            "smart-account timelock execute",
            &[
                "smart-account",
                "timelock",
                "execute",
                "--timelock",
                ACCOUNT_C,
                "--target",
                ACCOUNT_C,
                "--function",
                "upgrade",
                "--operation-id",
                HEX_64,
                "--salt",
                HEX_64,
                "--signer-secret-env",
                seed,
            ],
        ),
        GuardedVerb {
            name: "smart-account multicall",
            argv: multicall_base()
                .iter()
                .map(|arg| (*arg).to_owned())
                .collect(),
            mainnet_code: MAINNET_WRITE_FORBIDDEN,
            takes_network_flags: true,
        },
        guarded_profile_only(
            "vault deposit",
            &[
                "vault",
                "deposit",
                "--vault",
                ACCOUNT_C,
                "--from",
                ACCOUNT_C,
                "--amounts-desired",
                "1",
                "--amounts-min",
                "0",
            ],
        ),
        guarded_profile_only(
            "vault withdraw",
            &[
                "vault",
                "withdraw",
                "--vault",
                ACCOUNT_C,
                "--from",
                ACCOUNT_C,
                "--shares",
                "1",
                "--min-amounts-out",
                "0",
            ],
        ),
        guarded_profile_only(
            "trade",
            &[
                "trade",
                "--from",
                ACCOUNT_C,
                "--amount-in",
                "1",
                "--amount-out-min",
                "0",
                "--path",
                "native",
                "--path",
                "native",
            ],
        ),
        guarded_profile_only(
            "trustline",
            &["trustline", "--from", SOURCE_G, "--asset", "USDC"],
        ),
        guarded_profile_only("pool init", &["pool", "init", "--size", "1"]),
    ]);
    verbs
}

/// Runs every guarded verb with `extra` appended and collects each row whose
/// exit code, envelope code, or endpoint contact differs from the
/// expectation. A row for which `expected_code` answers `None` is not run.
///
/// Contact is observed at the TCP level: a mainnet profile file carries an
/// `https://` endpoint, and a plaintext HTTP mock records no request for a TLS
/// attempt.
fn guarded_table_failures(
    home: &Path,
    endpoint: &ConnectionCounter,
    extra: &[String],
    expected_code: impl Fn(&GuardedVerb) -> Option<&'static str>,
) -> Vec<String> {
    let mut failures = Vec::new();
    let verbs = guarded_verbs(&endpoint.https_uri());
    assert_eq!(verbs.len(), 36, "the table covers every guarded path");
    for verb in &verbs {
        let Some(expected) = expected_code(verb) else {
            continue;
        };
        let mut args = verb.argv.clone();
        args.extend(extra.iter().cloned());
        let before = endpoint.accepted().expect("connection count");
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = run_cli(home, None, &argv);
        let requests = endpoint.accepted().expect("connection count") - before;
        let code = serde_json::from_str::<Value>(run.stdout.trim())
            .ok()
            .and_then(|json| json["error"]["code"].as_str().map(str::to_owned));
        if run.code != 1 || code.as_deref() != Some(expected) || requests != 0 {
            failures.push(format!(
                "`{}`: exit {}, code {code:?} (expected {expected}), {requests} connection(s); \
                 stdout={} stderr={}",
                verb.name,
                run.code,
                run.stdout.trim(),
                run.stderr.lines().last().unwrap_or_default()
            ));
        }
    }
    failures
}

/// Every guarded path refuses a persisted mainnet profile with its structural
/// code, and no connection reaches the profile's endpoint. No seed variable
/// is set, and every later stage on these paths reports a different code.
#[test]
fn every_guarded_path_refuses_a_mainnet_profile_before_endpoint_contact() {
    let endpoint = connection_counter();
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", &endpoint.https_uri());
    let failures = guarded_table_failures(
        home.path(),
        &endpoint,
        &["--profile".to_owned(), "mainnet".to_owned()],
        |verb| Some(verb.mainnet_code),
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every guarded path that takes `--network` and `--rpc-url` refuses
/// `--network mainnet` on the zero-config testnet profile with
/// `profile.network_flag_mismatch`. `--rpc-url` names the counter, so the
/// zero-connection assertion observes the endpoint the command is given. The
/// rows marked `takes_network_flags: false` accept neither flag.
#[test]
fn every_guarded_path_refuses_a_mainnet_flag_without_a_profile() {
    let endpoint = connection_counter();
    let home = tempfile::tempdir().unwrap();
    let failures = guarded_table_failures(
        home.path(),
        &endpoint,
        &[
            "--network".to_owned(),
            "mainnet".to_owned(),
            "--rpc-url".to_owned(),
            endpoint.https_uri(),
        ],
        |verb| {
            verb.takes_network_flags
                .then_some("profile.network_flag_mismatch")
        },
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `smart-account list-rules` has no structural refusal; a mainnet profile
/// named only by the environment variable is refused at selection, before
/// any connection reaches the profile's endpoint.
#[test]
fn list_rules_refuses_a_mainnet_profile_named_by_the_environment() {
    let endpoint = connection_counter();
    let home = tempfile::tempdir().unwrap();
    write_mainnet_profile(home.path(), "mainnet", &endpoint.https_uri());
    let run = run_cli(
        home.path(),
        Some("mainnet"),
        &["smart-account", "list-rules", "--account", ACCOUNT_C],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(
        run.json()["error"]["code"],
        "profile.mainnet_requires_explicit_profile"
    );
    assert_no_contact(&endpoint);
}

#[tokio::test]
async fn multicall_secondary_flag_reaches_writer_without_rpc_contact() {
    let rpc = wiremock::MockServer::start().await;
    let home = tempfile::tempdir().unwrap();
    write_profile(home.path(), "testnet", &rpc.uri(), None);
    let registry = home.path().join("networks.toml");
    std::fs::write(&registry, format!("[multicall.testnet]\nnetwork_passphrase = \"Test SDF Network ; September 2015\"\naddress = \"CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM\"\nwasm_sha256 = \"{}\"\n", stellar_agent_smart_account::multicall::MULTICALL_WASM_SHA256)).unwrap();
    let endpoint = rpc.uri();
    let mut args = multicall_base();
    args.extend(["--profile", "testnet", "--secondary-rpc-url", &endpoint]);
    let run = run_cli_with_env(
        home.path(),
        None,
        &args,
        &[(
            stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            registry.to_str().unwrap(),
        )],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    let json = run.json();
    let code = json["error"]["code"].as_str().unwrap();
    assert!(
        [
            "audit.chain_key_unavailable",
            "validation.secret_env_not_set"
        ]
        .contains(&code),
        "{json}"
    );
    assert!(rpc.received_requests().await.unwrap().is_empty());
}

#[test]
fn multicall_registry_error_precedes_writer_and_signer() {
    let home = tempfile::tempdir().unwrap();
    write_profile(
        home.path(),
        "testnet",
        UNREACHABLE_RPC,
        Some("https://secondary.example"),
    );
    let registry = home.path().join("unreadable-registry");
    std::fs::create_dir(&registry).unwrap();
    let mut args = multicall_base();
    args.extend(["--profile", "testnet"]);
    let run = run_cli_with_env(
        home.path(),
        None,
        &args,
        &[(
            stellar_agent_smart_account::verifiers::STELLAR_AGENT_NETWORKS_TOML_ENV,
            registry.to_str().unwrap(),
        )],
    );
    assert_eq!(run.code, 1, "{} {}", run.stdout, run.stderr);
    assert_eq!(run.json()["error"]["code"], "io.multicall_registry_load");
}
