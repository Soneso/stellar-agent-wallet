//! The CLI rows of the release proof matrix and the runner that reaches them.
//!
//! [`CLI_PROOF_ROWS`] names every verb that submits through the mainnet write
//! pipeline, with the source file of its call, and [`invocation`] gives each
//! row one testnet argv. [`run_in`] runs the real binary in an isolated home
//! under the headless keyring backend, with every overlay that selects
//! another profile, endpoint or secret removed.
//!
//! The guard below proves each argv passes argument parsing and reaches the
//! profile load; tests of a matrix claim build on the same rows, argvs and
//! runner.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions"
)]

use std::path::Path;
use std::process::{Command, Output};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
use stellar_agent_core::audit_log::outbox::OUTBOX_LOCK_WAIT_ENV;
use stellar_agent_core::profile::loader::ProfileLoadError;

/// One CLI row of the proof matrix.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CliProofRow {
    /// The row id the matrix names.
    pub(crate) id: &'static str,
    /// The verb, as its words on the command line.
    pub(crate) verb: &'static str,
    /// The repository path of the source file that submits for the verb.
    pub(crate) source: &'static str,
}

/// Every CLI verb that submits through the mainnet write pipeline.
pub(crate) const CLI_PROOF_ROWS: &[CliProofRow] = &[
    CliProofRow {
        id: "cli.pay",
        verb: "pay",
        source: "crates/stellar-agent-cli/src/commands/pay.rs",
    },
    CliProofRow {
        id: "cli.claim",
        verb: "claim",
        source: "crates/stellar-agent-cli/src/commands/claim.rs",
    },
    CliProofRow {
        id: "cli.trustline",
        verb: "trustline",
        source: "crates/stellar-agent-cli/src/commands/trustline.rs",
    },
    CliProofRow {
        id: "cli.accounts_create",
        verb: "accounts create",
        source: "crates/stellar-agent-cli/src/commands/accounts/create.rs",
    },
];

/// The profile every argv names.
pub(crate) const PROFILE: &str = "proof-rows";

/// The headless keyring key of every child.
const HEADLESS_KEY: [u8; 32] = [0x5c; 32];

/// A classic account address, the source of every row.
pub(crate) const ACCOUNT_G: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";

/// A second classic account address, for the account a creation names.
pub(crate) const NEW_ACCOUNT_G: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

/// The secret variable every signer-source flag names. No child has it set.
pub(crate) const UNSET_SECRET_ENV: &str = "STELLAR_AGENT_PROOF_ROWS_UNSET_SECRET";

/// A 32-byte hex value for the claimable balance id.
const HEX32: &str = "0101010101010101010101010101010101010101010101010101010101010101";

/// The testnet argv of `row`'s one invocation, naming [`PROFILE`].
///
/// # Panics
///
/// Panics if `row` names a verb without an invocation.
pub(crate) fn invocation(row: &CliProofRow) -> Vec<String> {
    let balance_id = format!("00000000{HEX32}");
    let asset = format!("USDC:{ACCOUNT_G}");
    let args: Vec<&str> = match row.verb {
        "pay" => vec![
            "pay",
            ACCOUNT_G,
            "1 XLM",
            "--profile",
            PROFILE,
            "--source",
            ACCOUNT_G,
            "--secret-env",
            UNSET_SECRET_ENV,
        ],
        "claim" => vec![
            "claim",
            &balance_id,
            "--profile",
            PROFILE,
            "--source",
            ACCOUNT_G,
            "--secret-env",
            UNSET_SECRET_ENV,
        ],
        "trustline" => vec![
            "trustline",
            "--profile",
            PROFILE,
            "--from",
            ACCOUNT_G,
            "--asset",
            &asset,
        ],
        "accounts create" => vec![
            "accounts",
            "create",
            NEW_ACCOUNT_G,
            "--profile",
            PROFILE,
            "--sponsor",
            ACCOUNT_G,
            "--secret-env",
            UNSET_SECRET_ENV,
            "--starting-balance",
            "1",
        ],
        other => panic!("no invocation for {other}"),
    };
    args.into_iter().map(str::to_owned).collect()
}

/// Output of one child invocation.
pub(crate) struct Run {
    pub(crate) code: i32,
    pub(crate) envelope: Value,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl Run {
    fn from_output(output: &Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let envelope = stdout
            .lines()
            .rev()
            .find(|line| line.trim_start().starts_with('{'))
            .and_then(|line| serde_json::from_str(line).ok())
            .unwrap_or(Value::Null);
        Self {
            code: output.status.code().expect("process must exit with a code"),
            envelope,
            stdout,
            stderr,
        }
    }

    /// The error code of the envelope, if any.
    pub(crate) fn error_code(&self) -> Option<&str> {
        self.envelope["error"]["code"].as_str()
    }

    pub(crate) fn describe(&self) -> String {
        format!(
            "exit {}; stdout={}; stderr={}",
            self.code,
            self.stdout.trim(),
            self.stderr.trim()
        )
    }
}

/// The binary in `home` with `args`, under the headless backend and with
/// every overlay that selects another profile, endpoint or secret removed.
pub(crate) fn command_in(home: &Path, args: &[String]) -> Command {
    stellar_agent_test_support::sandbox::mark_sandbox(home).expect("mark fixture directory");
    let mut command = Command::new(env!("CARGO_BIN_EXE_stellar-agent"));
    command
        .args(args)
        .env("STELLAR_AGENT_HOME", home)
        .env("STELLAR_AGENT_KEYRING_BACKEND", "headless-env")
        .env(
            "STELLAR_AGENT_HEADLESS_KEYRING_KEY",
            URL_SAFE_NO_PAD.encode(HEADLESS_KEY),
        )
        .env_remove(UNSET_SECRET_ENV)
        .env_remove("STELLAR_AGENT_PROFILE")
        .env_remove("STELLAR_AGENT_CHAIN_ID")
        .env_remove("STELLAR_AGENT_RPC_URL")
        .env_remove("STELLAR_AGENT_SECONDARY_RPC_URL")
        .env_remove("STELLAR_AGENT_ORACLE_PROVIDER_URL")
        .env_remove("STELLAR_AGENT_MCP_SIGNER_DEFAULT")
        .env_remove(OUTBOX_LOCK_WAIT_ENV);
    command
}

/// Runs the binary in `home` with `args` and collects its output.
pub(crate) fn run_in(home: &Path, args: &[String]) -> Run {
    let output = command_in(home, args)
        .output()
        .expect("stellar-agent binary must run");
    Run::from_output(&output)
}

/// The profile-load code `row`'s verb renders: `trustline` keeps its own
/// code, and the other verbs render the shared one.
fn profile_load_code(row: &CliProofRow) -> &'static str {
    match row.verb {
        "trustline" => "trustline.profile_load_failed",
        _ => "profile.load_failed",
    }
}

/// The message a verb renders for a profile the home does not hold: the
/// loader's not-found refusal, whose validation code is
/// `validation.profile_not_found`.
fn profile_not_found_message() -> String {
    let not_found = ProfileLoadError::NotFound;
    assert_eq!(
        not_found.to_validation_error().code(),
        "validation.profile_not_found"
    );
    format!("the requested profile failed to load: {not_found}")
}

/// Each row's argv passes argument parsing and reaches the profile load: in
/// a home without the named profile, every row exits nonzero with the
/// loader's not-found refusal under exactly its verb's profile-load code, so
/// an argv that fails parsing with `validation.usage_error` fails the guard.
#[test]
fn every_cli_proof_row_reaches_the_profile_load() {
    let home = tempfile::tempdir().unwrap();
    let message = profile_not_found_message();
    let mut failures = Vec::new();
    for row in CLI_PROOF_ROWS {
        let run = run_in(home.path(), &invocation(row));
        let reached = run.code != 0
            && run.error_code() == Some(profile_load_code(row))
            && run.envelope["error"]["message"].as_str() == Some(message.as_str());
        if !reached {
            failures.push(format!("{} ({}): {}", row.id, row.verb, run.describe()));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every `mpp` subcommand with the arguments that pass its parsing, after
/// `--profile`.
const MPP_SUBCOMMANDS: &[(&str, &[&str])] = &[
    ("charge authorize", &["--input-stdin"]),
    (
        "authorization status",
        &["--authorization-id", "proof-rows"],
    ),
    (
        "receipt record",
        &[
            "--authorization-id",
            "proof-rows",
            "--transport",
            "http",
            "--receipt-stdin",
        ],
    ),
    (
        "settlement reconcile",
        &["--authorization-id", "proof-rows", "--reference-stdin"],
    ),
    ("state prune", &["--reason-stdin"]),
];

/// The subcommands the help of `words` lists, without `help`.
fn listed_subcommands(home: &Path, words: &[String]) -> Vec<String> {
    let mut args = words.to_vec();
    args.push("--help".to_owned());
    let run = run_in(home, &args);
    assert_eq!(run.code, 0, "{words:?} --help: {}", run.describe());
    run.stdout
        .lines()
        .skip_while(|line| line.trim_end() != "Commands:")
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| *name != "help")
        .map(str::to_owned)
        .collect()
}

/// The leaf subcommands under `words`, each as its words joined by spaces.
fn leaf_subcommands(home: &Path, words: &[String]) -> std::collections::BTreeSet<String> {
    let children = listed_subcommands(home, words);
    if children.is_empty() {
        return std::iter::once(words.join(" ")).collect();
    }
    children
        .into_iter()
        .flat_map(|child| {
            let mut path = words.to_vec();
            path.push(child);
            leaf_subcommands(home, &path)
        })
        .collect()
}

/// Every `mpp` subcommand the CLI exposes refuses a mainnet profile with
/// `mpp.network_forbidden` before it contacts the profile's endpoint.
#[test]
fn every_mpp_subcommand_refuses_a_mainnet_profile_before_any_connection() {
    use stellar_agent_core::profile::loader::save_new_to_dir;
    use stellar_agent_core::profile::schema::Profile;

    let home = tempfile::tempdir().unwrap();
    let exposed = leaf_subcommands(home.path(), &["mpp".to_owned()]);
    let listed: std::collections::BTreeSet<String> = MPP_SUBCOMMANDS
        .iter()
        .map(|(words, _)| format!("mpp {words}"))
        .collect();
    assert_eq!(
        exposed, listed,
        "the mpp subcommands the CLI exposes and the table differ"
    );

    let counter = stellar_agent_test_support::ConnectionCounter::start().unwrap();
    let profile = Profile::builder_mainnet_named(PROFILE, counter.https_uri(), "s", "a", "n", "a")
        .audit_log_path(home.path().join("audit").join(format!("{PROFILE}.jsonl")))
        .with_noop_engine()
        .build();
    save_new_to_dir(PROFILE, &profile, &home.path().join("profiles")).unwrap();

    let forbidden = stellar_agent_mpp::MppErrorCode::NetworkForbidden.as_str();
    let mut failures = Vec::new();
    for (words, extra) in MPP_SUBCOMMANDS {
        let args: Vec<String> = std::iter::once("mpp")
            .chain(words.split(' '))
            .chain(["--profile", PROFILE])
            .chain(extra.iter().copied())
            .map(str::to_owned)
            .collect();
        let run = run_in(home.path(), &args);
        if run.code != 1 || run.error_code() != Some(forbidden) {
            failures.push(format!("mpp {words}: {}", run.describe()));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(
        counter.accepted().unwrap(),
        0,
        "no mpp subcommand may contact the profile's endpoint"
    );
}

/// The release proof matrix, read from beside its checker.
const MATRIX: &str = include_str!("../../../../.github/scripts/proof-matrix.toml");

/// The CLI crate's path from the repository root.
const CLI_CRATE: &str = "crates/stellar-agent-cli";

fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("source directory reads") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The production lines of a source file: up to the first top-level
/// `#[cfg(test)]` line that gates a `mod`, without `//` comment lines.
fn production_lines(source: &str) -> Vec<&str> {
    let all: Vec<&str> = source.lines().collect();
    let end = all
        .windows(2)
        .position(|pair| pair[0] == "#[cfg(test)]" && pair[1].starts_with("mod "))
        .unwrap_or(all.len());
    all[..end]
        .iter()
        .copied()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect()
}

/// The repository paths of the CLI source files whose production code calls
/// the mainnet write pipeline; the file that defines it is no caller.
fn mainnet_write_callers() -> std::collections::BTreeSet<String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    collect_rs_files(&manifest.join("src"), &mut files);
    files
        .into_iter()
        .filter(|path| {
            let source = std::fs::read_to_string(path).expect("source file reads");
            production_lines(&source).iter().any(|line| {
                line.contains("authorize_and_submit(") && !line.contains("fn authorize_and_submit(")
            })
        })
        .map(|path| {
            let relative = path
                .strip_prefix(manifest)
                .expect("path under the crate")
                .to_string_lossy()
                .replace('\\', "/");
            format!("{CLI_CRATE}/{relative}")
        })
        .collect()
}

/// [`CLI_PROOF_ROWS`] equals the CLI rows of the matrix, and their sources are
/// the production files that call the mainnet write pipeline.
#[test]
fn cli_proof_rows_match_the_mainnet_write_callers() {
    use std::collections::BTreeSet;

    let matrix: toml::Table = toml::from_str(MATRIX).expect("the matrix parses");
    let text = |entry: &toml::Table, field: &str| -> String {
        entry
            .get(field)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("matrix row without {field}: {entry:?}"))
            .to_owned()
    };
    let matrix_rows: BTreeSet<(String, String, String)> = matrix["row"]
        .as_array()
        .expect("the matrix holds [[row]] entries")
        .iter()
        .map(|row| row.as_table().expect("a row is a table"))
        .filter(|row| row.get("surface").and_then(toml::Value::as_str) == Some("cli"))
        .map(|row| (text(row, "id"), text(row, "name"), text(row, "source")))
        .collect();
    let table_rows: BTreeSet<(String, String, String)> = CLI_PROOF_ROWS
        .iter()
        .map(|row| {
            (
                row.id.to_owned(),
                row.verb.to_owned(),
                row.source.to_owned(),
            )
        })
        .collect();
    assert_eq!(
        table_rows.len(),
        CLI_PROOF_ROWS.len(),
        "the table names a row twice"
    );
    assert_eq!(
        table_rows, matrix_rows,
        "the table and the matrix rows differ"
    );

    let sources: BTreeSet<String> = CLI_PROOF_ROWS
        .iter()
        .map(|row| row.source.to_owned())
        .collect();
    let callers = mainnet_write_callers();
    let without_row: Vec<&String> = callers.difference(&sources).collect();
    let without_caller: Vec<&String> = sources.difference(&callers).collect();
    assert!(
        without_row.is_empty() && without_caller.is_empty(),
        "callers without a row: {without_row:?}; rows whose source calls nothing: \
         {without_caller:?}"
    );
}
