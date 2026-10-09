//! A profile the operator NAMED but never authored is refused; an unnamed one
//! still synthesizes — pinned per verb through the release BINARY.
//!
//! `pay`, `claim`, and `accounts create` resolve a profile that need not
//! exist: with no name given and no `default.toml`, an in-memory `Noop`-engine
//! testnet profile stands in so the documented zero-config quickstart works.
//! The substitution is bounded to that case alone. It must not stand in for a
//! profile the operator NAMED, because the stand-in is a testnet,
//! no-policy-engine configuration: a mistyped `--profile`, or a stale
//! `STELLAR_AGENT_PROFILE` in a shell rc or a CI job, would otherwise sign and
//! submit under a gate the operator never chose.
//!
//! The rule is keyed on where the name came from, never on the name itself.
//! `--profile default` on a host with no `default.toml` is a NAMED profile and
//! must refuse; a string comparison against `"default"` would pass every other
//! test in this file and get exactly that case wrong, so it is pinned here.
//!
//! # What each test observes
//!
//! The wire code and the profile named in the refusal message, not the exit
//! code: a run that synthesized and then failed on the unreachable endpoint
//! also exits 1. `network.rpc_unreachable` means the run got past profile
//! resolution — that is what the zero-config pins assert.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` redirects every data-root-derived path and is set on
//! CHILD processes only. Every home here is empty of profiles unless a test
//! writes one, and `--rpc-url` points at an unreachable port so no run reaches
//! a network.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only; the refusal contract is asserted via panic-on-violation"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use stellar_agent_core::profile::loader::save_new_to_dir;
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};

/// A profile name no fixture ever writes.
const ABSENT_PROFILE: &str = "i112-never-authored";

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend,
/// so no child can reach the OS login keychain.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Unreachable endpoint: every run that gets PAST profile resolution fails
/// here, which is what distinguishes "synthesized and proceeded" from
/// "refused".
const UNREACHABLE_RPC: &str = "http://127.0.0.1:9";

const SOURCE_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const DEST_G: &str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
const BALANCE_ID_HEX72: &str =
    "000000000000000000000000000000000000000000000000000000000000000000000000";

/// Output of one child invocation.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim()).unwrap_or_else(|e| {
            panic!(
                "stdout must be a single JSON envelope ({e}); stdout={} stderr={}",
                self.stdout, self.stderr
            )
        })
    }

    fn code_field(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    fn message_field(&self) -> String {
        self.json()["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }
}

fn run_cli(home: &Path, env_profile: Option<&str>, args: &[&str]) -> Run {
    let bin_path = env!("CARGO_BIN_EXE_stellar-agent");
    let mut command = Command::new(bin_path);
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
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

/// The three verbs backed by the synthesis fallback, with the arguments they
/// need to reach the profile-resolution step.
///
/// Each one validates its own operands first, so an argument shape that
/// refused earlier would make these tests pass without ever exercising the
/// resolution — hence real strkeys, a well-formed balance id, and a parseable
/// amount.
const SYNTHESIS_BACKED_VERBS: &[(&str, &[&str])] = &[
    (
        "pay",
        &[
            "pay",
            "--source",
            SOURCE_G,
            DEST_G,
            "1",
            "--build-only",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
    ),
    (
        "claim",
        &[
            "claim",
            BALANCE_ID_HEX72,
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
            DEST_G,
            "--sponsor",
            SOURCE_G,
            "--starting-balance",
            "1 XLM",
            "--rpc-url",
            UNREACHABLE_RPC,
        ],
    ),
];

/// Writes a `noop`-engine testnet profile fixture into `<home>/profiles`.
fn write_profile(home: &Path, name: &str) {
    let signer = KeyringEntryRef::default_signer(name);
    let nonce = KeyringEntryRef::default_nonce(name);
    let profile = Profile::builder_testnet_named(
        name,
        &signer.service,
        &signer.account,
        &nonce.service,
        &nonce.account,
    )
    .rpc_url("http://127.0.0.1:29/i112-fixture".to_owned())
    .audit_log_path(home.join("audit").join(format!("{name}.jsonl")))
    .with_noop_engine()
    .build();

    save_new_to_dir(name, &profile, &home.join("profiles")).expect("fixture profile must persist");
}

/// Asserts a run refused at profile resolution, naming `profile`.
fn assert_refused_naming(run: &Run, verb: &str, profile: &str) {
    assert_eq!(
        run.code, 1,
        "`{verb}` must exit 1 for a named-but-missing profile; stdout={} stderr={}",
        run.stdout, run.stderr
    );
    assert_eq!(
        run.code_field(),
        "profile.load_failed",
        "`{verb}` must refuse at profile resolution, not proceed; stdout={}",
        run.stdout
    );
    assert!(
        run.message_field().contains(profile),
        "`{verb}`: the refusal must name the profile the operator asked for \
         ({profile}); message={}",
        run.message_field()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A NAMED, never-authored profile refuses
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn a_profile_named_by_the_flag_that_has_no_file_is_refused() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        let home = tempfile::tempdir().expect("temp home");
        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", ABSENT_PROFILE]);

        let run = run_cli(home.path(), None, &args);
        assert_refused_naming(&run, verb, ABSENT_PROFILE);
    }
}

#[test]
fn a_profile_named_by_the_environment_variable_that_has_no_file_is_refused() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        let home = tempfile::tempdir().expect("temp home");

        let run = run_cli(home.path(), Some(ABSENT_PROFILE), argv);
        assert_refused_naming(&run, verb, ABSENT_PROFILE);
    }
}

/// `--profile default` on a host with no `default.toml` refuses.
///
/// The resolved name is byte-identical to the fallback, so this case separates
/// a provenance check from a string comparison: only the provenance knows the
/// operator named it.
#[test]
fn an_explicitly_named_default_with_no_file_is_refused() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        let home = tempfile::tempdir().expect("temp home");
        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", "default"]);

        let run = run_cli(home.path(), None, &args);
        assert_refused_naming(&run, verb, "default");
    }
}

/// `STELLAR_AGENT_PROFILE=default` refuses for the same reason: the variable
/// is an explicit input, whatever value it carries.
#[test]
fn a_default_named_by_the_environment_variable_with_no_file_is_refused() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        let home = tempfile::tempdir().expect("temp home");

        let run = run_cli(home.path(), Some("default"), argv);
        assert_refused_naming(&run, verb, "default");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The zero-config invariant survives
// ─────────────────────────────────────────────────────────────────────────────

/// No `--profile`, no `STELLAR_AGENT_PROFILE`, no `default.toml`: the run
/// still synthesizes and proceeds.
///
/// The observation is that the failure is the unreachable ENDPOINT, i.e. the
/// run got past profile resolution. If this ever becomes
/// `profile.load_failed`, the documented first-run quickstart is broken.
#[test]
fn no_profile_named_and_no_default_file_still_synthesizes() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        let home = tempfile::tempdir().expect("temp home");

        let run = run_cli(home.path(), None, argv);
        assert_ne!(
            run.code_field(),
            "profile.load_failed",
            "`{verb}` must still synthesize when no profile was named; stdout={}",
            run.stdout
        );
        assert_eq!(
            run.code_field(),
            "network.rpc_unreachable",
            "`{verb}` must reach the endpoint, proving profile resolution succeeded; \
             stdout={}",
            run.stdout
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The composed chain: environment resolution (#113) plus the refusal (#112)
// ─────────────────────────────────────────────────────────────────────────────

/// A stale `STELLAR_AGENT_PROFILE` on a host with no `default.toml` refuses
/// rather than signing under a synthesized permissive profile.
///
/// This is the composed contract: the variable is read (so the name is the
/// stale one, not `default`) AND an explicitly named profile is never
/// synthesized. Either half alone leaves the run proceeding to the network
/// with the policy gate disabled. The other profile in the home is what makes
/// the refusal meaningful: the installation is working, only the variable is
/// stale.
#[test]
fn a_stale_environment_variable_refuses_instead_of_synthesizing() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        let home = tempfile::tempdir().expect("temp home");
        write_profile(home.path(), "i112-the-real-profile");

        let run = run_cli(home.path(), Some(ABSENT_PROFILE), argv);
        assert_refused_naming(&run, verb, ABSENT_PROFILE);
        assert!(
            !run.stdout.contains("i112-the-real-profile"),
            "`{verb}` must not silently fall back to another profile in the home; \
             stdout={}",
            run.stdout
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Precedence, observed on the verb's OWN resolution
// ─────────────────────────────────────────────────────────────────────────────

/// `--profile` beats `STELLAR_AGENT_PROFILE` at the verb's own load, in both
/// directions.
///
/// The audit-path pins in `profile_env_var_resolution.rs` observe the startup
/// advisory, which resolves the same clap field one step earlier. This one
/// observes the verb itself: the refusal is emitted by the load inside the
/// command, so the profile it names is the profile the command would have
/// signed under.
#[test]
fn the_flag_beats_the_variable_at_the_verbs_own_load() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        // The flag names an absent profile, the variable names one that
        // exists: the flag must win, so the run refuses naming the flag's.
        let home = tempfile::tempdir().expect("temp home");
        write_profile(home.path(), "i112-present");
        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", ABSENT_PROFILE]);

        let run = run_cli(home.path(), Some("i112-present"), &args);
        assert_refused_naming(&run, verb, ABSENT_PROFILE);
        assert!(
            !run.message_field().contains("i112-present"),
            "`{verb}`: the variable's profile must not be the one loaded when the flag \
             names another; message={}",
            run.message_field()
        );

        // The mirror image: the flag names one that exists, the variable an
        // absent one. The flag must win again, so the run loads and proceeds.
        let home = tempfile::tempdir().expect("temp home");
        write_profile(home.path(), "i112-present");
        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", "i112-present"]);

        let run = run_cli(home.path(), Some(ABSENT_PROFILE), &args);
        assert_eq!(
            run.code_field(),
            "network.rpc_unreachable",
            "`{verb}`: the flag's existing profile must win over the variable's absent \
             one and the run must proceed; stdout={} stderr={}",
            run.stdout,
            run.stderr
        );
    }
}

/// A profile that DOES exist is loaded, not refused — the control that keeps
/// every assertion above from passing for the wrong reason (a blanket refusal
/// of every profile would satisfy them all).
#[test]
fn a_named_profile_with_a_file_is_loaded() {
    for (verb, argv) in SYNTHESIS_BACKED_VERBS {
        let home = tempfile::tempdir().expect("temp home");
        write_profile(home.path(), "i112-present");
        let mut args = argv.to_vec();
        args.extend_from_slice(&["--profile", "i112-present"]);

        let run = run_cli(home.path(), None, &args);
        assert_eq!(
            run.code_field(),
            "network.rpc_unreachable",
            "`{verb}` must load the named profile that exists and reach the endpoint; \
             stdout={} stderr={}",
            run.stdout,
            run.stderr
        );
    }
}
