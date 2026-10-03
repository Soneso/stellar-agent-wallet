//! `profile migrate` reports a refused v1 file under the loader's validation
//! codes, through the release BINARY, and leaves the file as it was.
//!
//! A v1 mainnet file without `rpc_url` has no endpoint to migrate to, because
//! mainnet has no default endpoint. A v1 mainnet file whose endpoint breaks
//! the endpoint rule cannot become a v2 profile the loader accepts. Both are
//! the operator's to repair in the file, so neither may surface as
//! `internal.unexpected_state`.
//!
//! # Hermetic fixtures
//!
//! `STELLAR_AGENT_HOME` redirects every data-root-derived path and is set on
//! CHILD processes only. The headless keyring backend is forced on every child
//! so no run can reach the login keychain.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; refusals are asserted via panic-on-violation"
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// A throwaway 32-byte URL-safe base64 key for the headless keyring backend.
const HEADLESS_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

/// Sentinel URLs whose every component must stay out of the envelope.
const SENTINEL_HTTP: &str =
    "http://SENTINEL-USER:SENTINEL-PASS@sentinel-host.invalid/SENTINEL-PATH?k=SENTINEL-QUERY";
const SENTINEL_HTTPS: &str =
    "https://SENTINEL-USER:SENTINEL-PASS@sentinel-host.invalid/SENTINEL-PATH?k=SENTINEL-QUERY";

/// Writes a v1 profile on `chain_id` with an optional `rpc_url` into
/// `<home>/profiles` and returns its path.
fn write_v1_profile(home: &Path, name: &str, chain_id: &str, rpc_url: Option<&str>) -> PathBuf {
    let rpc_line = rpc_url.map_or_else(String::new, |url| format!("rpc_url = \"{url}\"\n"));
    let toml = format!(
        "version = 1\nchain_id = \"{chain_id}\"\n{rpc_line}\n\
         [mcp_signer_default]\nservice = \"stellar-agent-signer-{name}\"\naccount = \"default\"\n\n\
         [mcp_nonce_key_alias]\nservice = \"stellar-agent-nonce-{name}\"\naccount = \"default\"\n"
    );
    let dir = home.join("profiles");
    std::fs::create_dir_all(&dir).expect("profiles dir");
    let path = dir.join(format!("{name}.toml"));
    std::fs::write(&path, toml).expect("v1 fixture writes");
    path
}

/// Runs `stellar-agent profile migrate <name>` and returns the exit code and
/// stdout.
fn run_migrate(home: &Path, name: &str) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_stellar-agent"))
        .args(["profile", "migrate", name])
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env("STELLAR_AGENT_HEADLESS_KEYRING_KEY", HEADLESS_KEY)
        .env_remove("STELLAR_AGENT_PROFILE")
        .output()
        .expect("binary runs");
    (
        output.status.code().expect("process exits with a code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

fn error_code(stdout: &str) -> String {
    let json: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout}"));
    json["error"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("no error.code in {stdout}"))
        .to_owned()
}

/// Each refused v1 mainnet file exits 1 with its validation code, stays
/// byte-identical, and no part of its endpoint URL reaches stdout.
#[test]
fn refused_v1_mainnet_files_report_validation_codes_and_stay_unchanged() {
    for (rpc_url, expected) in [
        (None, "validation.mainnet_rpc_url_required"),
        (Some(SENTINEL_HTTP), "validation.config_invalid"),
        (Some(SENTINEL_HTTPS), "validation.config_invalid"),
    ] {
        let home = tempfile::tempdir().expect("temp home");
        let path = write_v1_profile(home.path(), "treasury", "stellar:mainnet", rpc_url);
        let before = std::fs::read(&path).expect("fixture reads");

        let (code, stdout) = run_migrate(home.path(), "treasury");

        assert_eq!(code, 1, "{rpc_url:?}: {stdout}");
        assert_eq!(error_code(&stdout), expected, "{rpc_url:?}: {stdout}");
        assert!(
            !stdout.to_ascii_lowercase().contains("sentinel"),
            "{rpc_url:?}: the envelope must name no part of the URL: {stdout}"
        );
        assert_eq!(
            std::fs::read(&path).expect("fixture reads"),
            before,
            "{rpc_url:?}: a refused migration must leave the v1 file byte-identical"
        );
    }
}

/// A profile with no file reports `validation.profile_not_found`.
#[test]
fn a_missing_profile_reports_not_found() {
    let home = tempfile::tempdir().expect("temp home");
    std::fs::create_dir_all(home.path().join("profiles")).expect("profiles dir");

    let (code, stdout) = run_migrate(home.path(), "never-written");

    assert_eq!(code, 1, "{stdout}");
    assert_eq!(
        error_code(&stdout),
        "validation.profile_not_found",
        "{stdout}"
    );
}

/// The control: a v1 mainnet file with an HTTPS endpoint migrates.
#[test]
fn a_v1_mainnet_file_with_an_https_endpoint_migrates() {
    let home = tempfile::tempdir().expect("temp home");
    let path = write_v1_profile(
        home.path(),
        "treasury",
        "stellar:mainnet",
        Some("https://rpc.example.invalid"),
    );

    let (code, stdout) = run_migrate(home.path(), "treasury");

    assert_eq!(code, 0, "{stdout}");
    let migrated = std::fs::read_to_string(&path).expect("migrated file reads");
    assert!(migrated.contains("version = 2"), "{migrated}");
    assert!(
        migrated.contains("rpc_url = \"https://rpc.example.invalid\""),
        "{migrated}"
    );
}
