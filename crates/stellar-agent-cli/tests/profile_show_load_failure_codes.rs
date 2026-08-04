//! One malformed profile draws one wire code, whichever verb reads it.
//!
//! `profile show` is the sole exemption from the profile-access choke point:
//! it exists to DISPLAY a profile that other verbs refuse, so it loads
//! directly. That exemption is about reconciliation, not about error
//! classification — an out-of-bounds field in an operator-authored TOML is the
//! operator's to repair no matter which verb reports it.
//!
//! `internal.unexpected_state` is the code that claims the wallet is broken.
//! Rendering an operator-correctable profile fault under it sends an operator
//! to the issue tracker over a file they could have edited, and it is what
//! `show`'s catch-all did for every load failure except `NotFound` and
//! `InvalidName`.
//!
//! # What these tests observe
//!
//! The wire `error.code` from the release BINARY, for the same profile
//! directory, across two verbs: `profile show` (direct load) and
//! `counterparty list` (choke point). Asserting the two AGREE is the point —
//! either code alone could drift without the other noticing.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` redirects every data-root-derived path and is set on
//! CHILD processes only. The headless keyring backend is forced on every child
//! so no run can reach the login keychain.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test-only; classification is asserted via panic-on-violation"
)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use stellar_agent_core::profile::loader::{MIRRORED_UPPER_BOUND_MAX_SCAN_ID, save_new_to_dir};
use stellar_agent_core::profile::schema::{KeyringEntryRef, Profile};

const PROFILE: &str = "i124-bounds-profile";

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Writes a valid `noop`-engine testnet profile fixture into `<home>/profiles`
/// and returns the path of the written TOML.
fn write_profile(home: &Path, name: &str) -> std::path::PathBuf {
    let signer = KeyringEntryRef::default_signer(name);
    let nonce = KeyringEntryRef::default_nonce(name);
    let profile = Profile::builder_testnet_named(
        name,
        &signer.service,
        &signer.account,
        &nonce.service,
        &nonce.account,
    )
    .audit_log_path(home.join("audit").join(format!("{name}.jsonl")))
    .with_noop_engine()
    .build();
    let dir = home.join("profiles");
    std::fs::create_dir_all(&dir).expect("profiles dir");
    save_new_to_dir(name, &profile, &dir).expect("fixture profile writes");
    dir.join(format!("{name}.toml"))
}

struct Run {
    code: i32,
    stdout: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", self.stdout))
    }

    fn error_code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("no error.code in {}", self.stdout))
            .to_owned()
    }
}

fn run_cli(home: &Path, args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .env_remove("STELLAR_AGENT_PROFILE")
        .output()
        .expect("binary runs");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
    }
}

/// Inserts a top-level key into a written profile TOML.
///
/// The bound violations cannot be produced through `Profile`'s builder — the
/// builder's own validation refuses them — so the fixture is written valid and
/// then edited, which is exactly how an operator produces one.
///
/// The key goes at the HEAD of the file. A top-level key appended after the
/// first `[table]` header belongs to that table under TOML's own rules, so the
/// loader would never see it and the fixture would silently load clean.
fn prepend_key_to_toml(path: &Path, line: &str) {
    let toml = std::fs::read_to_string(path).expect("fixture reads");
    std::fs::write(path, format!("{line}\n{toml}")).expect("fixture rewrites");
}

/// An out-of-bounds scan-id cap is `validation.config_invalid`, not an
/// internal error, and `profile show` says the same thing every other verb
/// does.
#[test]
fn out_of_bounds_scan_id_is_operator_correctable_on_both_surfaces() {
    let home = tempfile::tempdir().expect("temp home");
    let toml = write_profile(home.path(), PROFILE);
    prepend_key_to_toml(
        &toml,
        &format!(
            "smart_account_max_context_rule_scan_id = {}",
            MIRRORED_UPPER_BOUND_MAX_SCAN_ID + 1
        ),
    );

    let show = run_cli(home.path(), &["profile", "show", PROFILE]);
    let choke = run_cli(home.path(), &["counterparty", "list", "--profile", PROFILE]);

    assert_eq!(show.code, 1, "show exits 1: {}", show.stdout);
    assert_eq!(
        show.error_code(),
        "validation.config_invalid",
        "an out-of-bounds cap in an operator-authored TOML is the operator's to \
         repair, not a wallet defect: {}",
        show.stdout
    );
    assert_eq!(
        show.error_code(),
        choke.error_code(),
        "one malformed profile must draw one code; show said {} and the choke \
         point said {}",
        show.error_code(),
        choke.error_code()
    );
}

/// The same for an out-of-bounds horizon cap — a second variant reaching the
/// same catch-all, so the fix is not special-cased to one field.
#[test]
fn out_of_bounds_horizon_is_operator_correctable_on_both_surfaces() {
    let home = tempfile::tempdir().expect("temp home");
    let toml = write_profile(home.path(), PROFILE);
    prepend_key_to_toml(&toml, "session_rule_max_horizon_ledgers = 10001");

    let show = run_cli(home.path(), &["profile", "show", PROFILE]);
    let choke = run_cli(home.path(), &["counterparty", "list", "--profile", PROFILE]);

    assert_eq!(
        show.error_code(),
        "validation.config_invalid",
        "expected an operator-correctable code: {}",
        show.stdout
    );
    assert_eq!(show.error_code(), choke.error_code(), "surfaces must agree");
}

/// A profile that does not exist stays `validation.profile_not_found` on both
/// surfaces. The classification change must not swallow the missing-file case
/// into the generic config code.
#[test]
fn a_missing_profile_is_still_not_found_on_both_surfaces() {
    let home = tempfile::tempdir().expect("temp home");
    std::fs::create_dir_all(home.path().join("profiles")).expect("profiles dir");

    let show = run_cli(home.path(), &["profile", "show", "i124-absent"]);
    let choke = run_cli(
        home.path(),
        &["counterparty", "list", "--profile", "i124-absent"],
    );

    assert_eq!(
        show.error_code(),
        "validation.profile_not_found",
        "a missing profile is not a config error: {}",
        show.stdout
    );
    assert_eq!(show.error_code(), choke.error_code(), "surfaces must agree");
}

/// A path-bearing load failure is redacted on the same terms by both surfaces.
///
/// `MissingPolicySection`'s `Display` embeds the path it read, and `show`
/// formats the loader error into its envelope. Both surfaces run the message
/// through `redact_path_in_message`, so whatever that redactor does, they do
/// identically — the failure this pins is `show` skipping the redactor that the
/// choke point applies.
///
/// Note what this does NOT assert: that no absolute path appears. The redactor
/// strips the OS home prefix, and a `STELLAR_AGENT_HOME` pointed outside the
/// home directory — as this fixture's temp dir is, and as a service-account
/// deployment would be — is not covered by it. That gap is pre-existing, is
/// identical on both surfaces, and is out of scope here.
#[test]
fn a_path_bearing_load_failure_is_redacted_identically_on_both_surfaces() {
    let home = tempfile::tempdir().expect("temp home");
    let toml = write_profile(home.path(), PROFILE);
    // Remove the required [policy] section to reach `MissingPolicySection`,
    // whose Display is the one carrying a path.
    let text = std::fs::read_to_string(&toml).expect("fixture reads");
    let stripped: String = text
        .lines()
        .filter(|l| !l.starts_with("[policy]") && !l.starts_with("engine"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&toml, stripped).expect("fixture rewrites");

    let show = run_cli(home.path(), &["profile", "show", PROFILE]);
    let choke = run_cli(home.path(), &["counterparty", "list", "--profile", PROFILE]);

    assert_eq!(
        show.error_code(),
        "validation.config_invalid",
        "a missing [policy] section is the operator's to repair: {}",
        show.stdout
    );

    // The real home, not the fixture's STELLAR_AGENT_HOME: this is the prefix
    // `redact_path_in_message` strips, and neither surface may render it.
    if let Some(real_home) = std::env::var_os("HOME") {
        let real_home = real_home.to_string_lossy().into_owned();
        assert!(
            !show.stdout.contains(&real_home),
            "show rendered the OS home prefix: {}",
            show.stdout
        );
    }

    // Whatever the redactor leaves, both surfaces must leave the same. `show`
    // skipping the redactor entirely is the failure this catches.
    let leaks_in = |s: &str| s.contains("/profiles/");
    assert_eq!(
        leaks_in(&show.stdout),
        leaks_in(&choke.stdout),
        "surfaces redact differently; show={} choke={}",
        show.stdout,
        choke.stdout
    );
}
