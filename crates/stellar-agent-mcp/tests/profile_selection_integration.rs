//! Per-invocation profile selection, driven through the real binary.
//!
//! Parse-level unit tests live next to the parser in `main.rs`. These are the
//! process-level pins, and they are required rather than redundant: a parser
//! test cannot observe whether `main` wires the parsed value into the profile
//! load, so these drive the real binary end to end.
//!
//! # Test isolation
//!
//! Each test gets a `STELLAR_AGENT_HOME` temp directory holding the profile
//! files it needs. `default_profile_dir()` honours that variable under
//! `cfg(any(test, feature = "test-helpers"))`, which this crate's
//! `stellar-agent-core` dev-dependency enables for the binary built into the
//! test profile. Release builds never read it, so the operator's real profile
//! directory is unreachable from here.
//!
//! `STELLAR_AGENT_PROFILE` is explicitly removed unless a test sets it, so an
//! ambient value in the developer's shell cannot change what is asserted.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test-only; panics acceptable in integration tests"
)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Output, Stdio};

use stellar_agent_core::profile::caip2::{MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};

/// A profile name for which no file is ever written.
const MISSING_PROFILE: &str = "__issue105_missing_profile__";

fn mcp_binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_stellar-agent-mcp"))
}

/// A minimal, valid version-2 profile TOML with the Noop policy engine.
///
/// `owner_profile` is the profile name the keyring coordinates are derived
/// from. It equals `name` for every profile `stellar-agent profile init`
/// writes; the reconciliation test passes a different value to reproduce a
/// profile file copied from another profile.
fn noop_profile_toml(owner_profile: &str, chain_id: &str, rpc_url: &str) -> String {
    format!(
        r#"
version = 2
chain_id = "{chain_id}"
rpc_url = "{rpc_url}"

[mcp_signer_default]
service = "stellar-agent-signer-{owner_profile}"
account = "init"

[mcp_nonce_key_alias]
service = "stellar-agent-nonce-{owner_profile}"
account = "default"

[audit_log_hash_chain_key_id]
service = "stellar-agent-audit-{owner_profile}"
account = "default"

[policy_owner_key_id]
service = "stellar-agent-owner-{owner_profile}"
account = "default"

[attestation_key_id]
service = "stellar-agent-attestation-{owner_profile}"
account = "default"

[counterparty_cache_key_id]
service = "stellar-agent-counterparty-{owner_profile}"
account = "default"

[policy]
engine = "noop"
"#
    )
}

/// An isolated `STELLAR_AGENT_HOME` with a `profiles/` directory.
struct ProfileHome {
    dir: tempfile::TempDir,
}

impl ProfileHome {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("profiles")).unwrap();
        Self { dir }
    }

    /// Writes `<home>/profiles/<name>.toml`.
    fn write_profile(&self, name: &str, contents: &str) -> &Self {
        std::fs::write(
            self.dir
                .path()
                .join("profiles")
                .join(format!("{name}.toml")),
            contents,
        )
        .unwrap();
        self
    }

    /// Builds a `Command` for the MCP binary bound to this home directory.
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(mcp_binary());
        command
            .args(args)
            .env("STELLAR_AGENT_HOME", self.dir.path())
            // An ambient value in the developer's shell must not leak in.
            .env_remove("STELLAR_AGENT_PROFILE")
            // Keep the subprocess away from the login keychain. A Noop profile
            // never reads a key, but the store is still registered at startup.
            .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
            .env(
                "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
                "dGVzdC1oZWFkbGVzcy1rZXktbm90LXVzZWQtaGVyZQ",
            );
        command
    }
}

/// Runs the binary with one `initialize` request on stdin and waits for exit.
///
/// Used by the refusal tests: a server that refused to start exits before
/// reading stdin and writes nothing to stdout, while a server that started
/// answers the request and then exits cleanly at EOF. Either way the process
/// terminates, so there is nothing to time out on.
fn run_with_initialize(mut command: Command) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stellar-agent-mcp binary must spawn");
    {
        let mut stdin = child.stdin.take().expect("child stdin must be piped");
        writeln!(
            stdin,
            r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"test-client","version":"0.1.0"}}}}}}"#
        )
        .expect("write to child stdin must succeed");
    }
    child.wait_with_output().expect("child must exit")
}

/// Asserts the process refused to start with the expected exit code and no
/// MCP response.
///
/// The codes are a contract: `2` is a usage refusal decided before any startup
/// step (unparseable argv, unusable profile name), `1` is every later startup
/// refusal. Pinning them keeps a usage error from silently becoming a runtime
/// error or the reverse.
fn assert_refused_with(output: &Output, expected_code: i32) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(
        output.status.code(),
        Some(expected_code),
        "unexpected exit code.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a refused startup must serve no MCP response, got stdout: {stdout}"
    );
    stderr
}

/// Asserts the process refused to start: non-zero exit and no MCP response.
fn assert_refused(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "the server must exit non-zero.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a refused startup must serve no MCP response, got stdout: {stdout}"
    );
    stderr
}

/// A live server bound to a profile home, driven over stdio.
struct McpSession {
    child: std::process::Child,
    writer: std::io::BufWriter<std::process::ChildStdin>,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpSession {
    fn start(mut command: Command) -> Self {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("stellar-agent-mcp binary must spawn");
        let writer =
            std::io::BufWriter::new(child.stdin.take().expect("child stdin must be piped"));
        let reader = BufReader::new(child.stdout.take().expect("child stdout must be piped"));
        Self {
            child,
            writer,
            reader,
        }
    }

    fn call(&mut self, message: &serde_json::Value) -> serde_json::Value {
        let line = serde_json::to_string(message).expect("json serialisation");
        writeln!(self.writer, "{line}").expect("write to child stdin must succeed");
        self.writer.flush().expect("flush must succeed");
        let mut response = String::new();
        self.reader
            .read_line(&mut response)
            .expect("server must write a response line");
        assert!(
            !response.trim().is_empty(),
            "server must respond with a non-empty JSON-RPC message"
        );
        serde_json::from_str(response.trim()).expect("server must respond with valid JSON-RPC")
    }

    /// Completes the handshake and returns the active network passphrase the
    /// server reports, which is derived from the loaded profile's `chain_id`.
    fn active_network_passphrase(&mut self) -> String {
        let init = self.call(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "0.1.0" }
            }
        }));
        assert!(
            init["result"]["capabilities"]["tools"].is_object(),
            "initialize must succeed: {init}"
        );

        let called = self.call(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "stellar_sep43_get_network", "arguments": {} }
        }));
        let text = called["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("getNetwork must return text content: {called}"));
        let envelope: serde_json::Value =
            serde_json::from_str(text).expect("getNetwork content must be a JSON envelope");
        envelope["data"]["networkPassphrase"]
            .as_str()
            .unwrap_or_else(|| panic!("getNetwork must report a passphrase: {envelope}"))
            .to_owned()
    }
}

impl Drop for McpSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// D1 / D2 — selection and the no-fallback rule for a named profile
// ─────────────────────────────────────────────────────────────────────────────

/// The success path: `--profile <name>` serves THAT profile, not `default`.
#[test]
fn profile_flag_serves_the_named_profile() {
    let home = ProfileHome::new();
    home.write_profile(
        "default",
        &noop_profile_toml(
            "default",
            "stellar:testnet",
            "https://testnet.example.invalid",
        ),
    )
    .write_profile(
        "alice",
        &noop_profile_toml(
            "alice",
            "stellar:mainnet",
            "https://mainnet.example.invalid",
        ),
    );

    let mut session = McpSession::start(home.command(&["--profile", "alice"]));
    assert_eq!(
        session.active_network_passphrase(),
        MAINNET_PASSPHRASE,
        "the server must serve alice's network, not default's"
    );
}

/// `--profile=<name>` selects the same profile as the two-token form.
#[test]
fn profile_equals_form_serves_the_named_profile() {
    let home = ProfileHome::new();
    home.write_profile(
        "default",
        &noop_profile_toml(
            "default",
            "stellar:testnet",
            "https://testnet.example.invalid",
        ),
    )
    .write_profile(
        "alice",
        &noop_profile_toml(
            "alice",
            "stellar:mainnet",
            "https://mainnet.example.invalid",
        ),
    );

    let mut session = McpSession::start(home.command(&["--profile=alice"]));
    assert_eq!(session.active_network_passphrase(), MAINNET_PASSPHRASE);
}

/// `STELLAR_AGENT_PROFILE` selects the profile FILE and overlays no field.
///
/// The variable sits inside the loader's `STELLAR_AGENT_` figment prefix, so it
/// is also visible to the field-overlay layer. Asserting that the served
/// configuration is exactly the named file's — including the network, which the
/// two profiles differ on — is what distinguishes "selected the file" from
/// "selected the file and also wrote something into it".
#[test]
fn environment_variable_selects_the_profile_file() {
    let home = ProfileHome::new();
    home.write_profile(
        "default",
        &noop_profile_toml(
            "default",
            "stellar:testnet",
            "https://testnet.example.invalid",
        ),
    )
    .write_profile(
        "alice",
        &noop_profile_toml(
            "alice",
            "stellar:mainnet",
            "https://mainnet.example.invalid",
        ),
    );

    let mut command = home.command(&[]);
    command.env("STELLAR_AGENT_PROFILE", "alice");
    let mut session = McpSession::start(command);
    assert_eq!(session.active_network_passphrase(), MAINNET_PASSPHRASE);
}

/// The flag wins over the environment variable.
#[test]
fn profile_flag_beats_the_environment_variable() {
    let home = ProfileHome::new();
    home.write_profile(
        "default",
        &noop_profile_toml(
            "default",
            "stellar:testnet",
            "https://testnet.example.invalid",
        ),
    )
    .write_profile(
        "alice",
        &noop_profile_toml(
            "alice",
            "stellar:mainnet",
            "https://mainnet.example.invalid",
        ),
    );

    let mut command = home.command(&["--profile", "default"]);
    command.env("STELLAR_AGENT_PROFILE", "alice");
    let mut session = McpSession::start(command);
    assert_eq!(
        session.active_network_passphrase(),
        TESTNET_PASSPHRASE,
        "the flag must win over the environment variable"
    );
}

/// With no name given and no profile file, the first-run fallback still applies.
///
/// This is the control for the two refusals below: they are meaningful only
/// because the fallback genuinely exists for the unnamed case.
#[test]
fn no_name_and_no_profile_file_falls_back_to_the_synthesised_testnet_profile() {
    let home = ProfileHome::new();
    let mut session = McpSession::start(home.command(&[]));
    assert_eq!(session.active_network_passphrase(), TESTNET_PASSPHRASE);
}

/// A profile named through the flag is never replaced by the fallback.
#[test]
fn named_but_missing_profile_refuses_instead_of_falling_back() {
    let home = ProfileHome::new();
    let output = run_with_initialize(home.command(&["--profile", MISSING_PROFILE]));
    let stderr = assert_refused_with(&output, 1);
    assert!(
        stderr.contains(MISSING_PROFILE),
        "the refusal must name the profile: {stderr}"
    );
    assert!(
        stderr.contains("profiles") && stderr.contains(".toml"),
        "the refusal must name the path searched: {stderr}"
    );
    assert!(
        stderr.contains("profile init"),
        "the refusal must name the command that creates it: {stderr}"
    );
}

/// A profile named through the environment variable is never replaced either.
#[test]
fn environment_named_but_missing_profile_refuses_instead_of_falling_back() {
    let home = ProfileHome::new();
    let mut command = home.command(&[]);
    command.env("STELLAR_AGENT_PROFILE", MISSING_PROFILE);
    let stderr = assert_refused_with(&run_with_initialize(command), 1);
    assert!(
        stderr.contains(MISSING_PROFILE),
        "the refusal must name the profile: {stderr}"
    );
    assert!(
        stderr.contains("STELLAR_AGENT_PROFILE"),
        "the refusal must say the name came from the environment: {stderr}"
    );
}

/// `--profile default` on a host with no `default.toml` refuses.
///
/// The case that separates a provenance-carrying resolver from one that
/// compares the resolved name to `"default"`: under a string comparison this
/// invocation takes the first-run branch and silently serves a synthesised
/// testnet Noop profile.
#[test]
fn explicitly_named_default_profile_refuses_when_absent() {
    let home = ProfileHome::new();
    let stderr = assert_refused(&run_with_initialize(
        home.command(&["--profile", "default"]),
    ));
    assert!(
        stderr.contains("profile init"),
        "the refusal must name the command that creates it: {stderr}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// D4 — argument parsing
// ─────────────────────────────────────────────────────────────────────────────

/// A traversal profile name is refused at step 0, before any file is opened.
///
/// This is the **D4** pin — the step-0 validation in the binary. The loader-side
/// guard has its own pins in `stellar-agent-core` and `stellar-agent-cli`;
/// removing the loader guard would not fail this test, because the binary
/// refuses before the loader is reached.
#[test]
fn traversal_profile_name_is_refused() {
    let home = ProfileHome::new();
    let stderr = assert_refused_with(
        &run_with_initialize(home.command(&["--profile", "../../etc/passwd"])),
        2,
    );
    assert!(
        stderr.contains("not a valid profile name"),
        "the refusal must say the name is invalid: {stderr}"
    );
}

/// An unrecognised flag is refused rather than ignored.
#[test]
fn unknown_flag_is_refused() {
    let home = ProfileHome::new();
    let output = run_with_initialize(home.command(&["--profil", "mainnet-prod"]));
    let stderr = assert_refused_with(&output, 2);
    assert!(
        stderr.contains("unrecognised argument '--profil'"),
        "the refusal must quote the offending token: {stderr}"
    );
    assert!(
        stderr.contains("--profile <NAME>"),
        "the refusal must print the accepted flags: {stderr}"
    );
}

/// `--help` documents the flag and the environment variable, and exits 0.
#[test]
fn help_documents_profile_selection() {
    let home = ProfileHome::new();
    let output = home
        .command(&["--help"])
        .stdin(Stdio::null())
        .output()
        .expect("binary must run");
    assert!(output.status.success(), "--help must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert!(
        stdout.contains("--profile <NAME>"),
        "--help must document the flag: {stdout}"
    );
    assert!(
        stdout.contains("STELLAR_AGENT_PROFILE"),
        "--help must document the environment variable: {stdout}"
    );
    assert!(
        !stdout.contains("Takes no arguments"),
        "--help must not claim the binary takes no arguments: {stdout}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// D6 — the selected name must match the profile's own name
// ─────────────────────────────────────────────────────────────────────────────

/// A profile file copied from another profile refuses to serve under the new
/// name, on a **Noop** profile.
///
/// The engine matters: the name derivation the server uses for per-profile
/// state runs for every engine, but the V1 policy-engine construction — where
/// an engine-coupled version of this check would sit — returns early for Noop.
/// A Noop profile is also what the getting-started flow recommends, so this is
/// the common case rather than an edge one.
#[test]
fn noop_profile_copied_from_another_profile_refuses_to_serve_under_the_new_name() {
    let home = ProfileHome::new();
    // `alice.toml` whose keyring coordinates still name `default`: exactly what
    // copying `default.toml` to `alice.toml` produces.
    home.write_profile(
        "alice",
        &noop_profile_toml(
            "default",
            "stellar:testnet",
            "https://testnet.example.invalid",
        ),
    );

    let stderr = assert_refused(&run_with_initialize(home.command(&["--profile", "alice"])));
    assert!(
        stderr.contains("alice") && stderr.contains("stellar-agent-owner-default"),
        "the refusal must name the selected profile and the offending field: {stderr}"
    );
    assert!(
        stderr.contains("profile init --profile alice"),
        "the refusal must name the recovery command: {stderr}"
    );
}

/// A profile whose owner-key coordinate carries no derivable name refuses.
///
/// The approval-store derivation resolves an absent prefix to the literal
/// `default`, so treating it as a match would write another profile's
/// approvals under this one.
#[test]
fn profile_without_a_derivable_owner_key_name_refuses() {
    let home = ProfileHome::new();
    let toml = noop_profile_toml(
        "alice",
        "stellar:testnet",
        "https://testnet.example.invalid",
    )
    .replace("stellar-agent-owner-alice", "hand-written-owner-service");
    home.write_profile("alice", &toml);

    let stderr = assert_refused(&run_with_initialize(home.command(&["--profile", "alice"])));
    assert!(
        stderr.contains("hand-written-owner-service"),
        "the refusal must quote the offending policy_owner_key_id.service: {stderr}"
    );
}
