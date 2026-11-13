//! CLI binary for the Stellar agent wallet.
//!
//! Installed as `stellar-agent` on PATH; discovered as `stellar agent ...` by
//! the incumbent `stellar-cli` via the external-binary plugin convention.
//!
//! # Subcommands
//!
//! Run `stellar-agent --help` for the current authoritative subcommand list.
//!
//! # Non-goals
//!
//! - Command-line parsing internals: see `crate::commands` submodules.
//! - Rendering internals: see `crate::render` submodules.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod advisory;
mod commands;
pub mod common;
mod process_hardening;
mod render;
mod role;
#[cfg(test)]
mod test_rpc;

use std::sync::{Arc, LazyLock, Mutex};

use clap::{Parser, Subcommand};
use stellar_agent_core::audit_log::AuditWriter;
use stellar_agent_core::observability;

use crate::common::resolve_profile_name;

/// Version value clap prints after the binary name: the package version, then
/// core's build-state marker on its own line. Built once at runtime because
/// clap takes a `&'static str` and `concat!` accepts only literals.
static VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{}\n{}",
        env!("CARGO_PKG_VERSION"),
        stellar_agent_core::build_info::MAINNET_WRITE_MARKER
    )
});

/// Stellar agent wallet command-line interface.
///
/// A self-custodial, autonomous Stellar wallet that operates without a
/// central server. Outputs JSON by default for scripting.
#[derive(Debug, Parser)]
#[command(
    name = "stellar-agent",
    author,
    version = VERSION.as_str(),
    about = "Self-custodial Stellar agent wallet CLI",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the MCP stdio server.
    Mcp(commands::mcp::McpArgs),

    /// Wallet-owned approval spine — interactive y/n for pending approvals.
    ///
    /// Provides:
    /// - `approve --id <nonce> --profile <name>`: read a pending approval from the store,
    ///   render a wallet-controlled summary, prompt y/n, and on approval
    ///   compute and record the HMAC attestation blob.
    /// - `approve --id <nonce> --profile <name> --yes`: non-interactive auto-approve.
    ///   Bypasses the tty prompt; use only in trusted automation flows.
    /// - `approve gc`: evict all expired pending approvals for a profile.
    Approve(commands::approve::ApproveArgs),

    /// Submission-record subcommand group.
    ///
    /// Provides:
    /// - `tx status <HASH>`: reconcile one submitted transaction against the
    ///   chain and record a reported success. This is the way out of
    ///   `submission.tx_timeout`.
    /// - `tx receipt clear <ENVELOPE_HASH> --acknowledge`: close a submission
    ///   record after reconciling it against the chain.
    Tx(commands::tx::TxArgs),

    /// Audit-log management subcommand group.
    ///
    /// Provides:
    /// - `audit verify <log-path>` — walk the hash-chained audit log at
    ///   `<log-path>` and verify the chain integrity from the oldest rotated
    ///   file to the current active file.
    Audit(commands::audit::AuditArgs),

    /// Account-management subcommand group.
    ///
    /// Currently provides:
    /// - `accounts create` — create a new Stellar account on-chain via
    ///   sponsored `CreateAccount` op or Friendbot (testnet only).
    /// - `accounts deploy-c` — deploy a new OZ smart-account (C-account)
    ///   contract instance via Soroban `CreateContractV2`.
    Accounts(commands::accounts::AccountsArgs),

    /// Display native XLM and trustline balances for an account.
    ///
    /// Uses the Stellar RPC endpoint (not Horizon).
    Balances(commands::balances::BalancesArgs),

    /// Counterparty-resolution cache management.
    ///
    /// Provides:
    /// - `counterparty list [--profile <name>]` — list cached stellar.toml
    ///   bindings for the profile (home domain + expiry timestamps).
    /// - `counterparty refresh <home-domain> [--profile <name>]` — force-fetch
    ///   `https://<home-domain>/.well-known/stellar.toml`, HMAC-protect it, and
    ///   write to the per-profile cache.
    Counterparty(commands::counterparty::CounterpartyArgs),

    /// Fund a testnet or futurenet account via the Stellar Friendbot endpoint.
    ///
    /// Structurally refuses mainnet (returns error
    /// `network.friendbot_mainnet_forbidden` before any HTTP call is issued).
    Friendbot(commands::friendbot::FriendbotArgs),

    /// Fee statistics and classic fee selection helpers.
    Fees(commands::fees::FeesArgs),

    /// Send a payment from source to destination.
    ///
    /// Enforces SEP-29 memo-required destinations. On mainnet only the full
    /// pipeline runs, under the mainnet authorization; the staged modes, and
    /// every mainnet run of a build without `mainnet-write`, refuse with
    /// `network.mainnet_write_forbidden` before any RPC call.
    /// Supports three-stage pipeline: `--build-only`, `--sign-only <xdr>`,
    /// `--submit-only <xdr>`. Default: build → sign → submit atomically.
    Pay(Box<commands::pay::PayArgs>),

    /// Testnet-only sponsored Machine Payments Protocol charges.
    Mpp(commands::mpp::MppArgs),

    /// Channel-account pool subcommand group.
    ///
    /// Provides:
    /// - `pool init --size N [--profile P]` — fund N channel accounts via
    ///   one CAP-33 sponsored-reserve sandwich. `--size` must be 1..=19.
    /// - `pool list [--profile P]` — list channels + cached seq / status.
    /// - `pool status [--profile P]` — utilisation: free / in-flight / total.
    Pool(commands::pool::PoolArgs),

    /// Profile-management subcommand group.
    ///
    /// Provides:
    /// - `profile list` — list known profile names.
    /// - `profile show <name>` — print a profile's resolved configuration.
    /// - `profile migrate <name>` — migrate a profile schema to the current
    ///   version.
    /// - `profile enroll-signer` — import the MCP signer seed into the
    ///   profile's keyring entry.
    /// - `profile enroll-owner-key` — enroll the policy-file owner ed25519
    ///   PUBLIC key into the profile's keyring entry.
    /// - `profile sign-policy` — sign a V1 policy file with the owner key.
    /// - `profile rotate-nonce-key <name>` — rotate the HMAC nonce key.
    /// - `profile rotate-attestation-key <name>` — rotate the approval-spine
    ///   attestation HMAC key.
    /// - `profile rotate-audit-key <name>` — rotate the hash-chain audit-log
    ///   chain-root HMAC key.
    /// - `profile rotate-counterparty-key <name>` — rotate the stellar.toml
    ///   cache-integrity HMAC key.
    Profile(commands::profile::ProfileArgs),

    /// WebAuthn passkey credential lifecycle.
    ///
    /// Provides:
    /// - `credentials add-passkey <name>` — register a new WebAuthn passkey
    ///   via browser handoff. Opens the OS default browser to the wallet-owned
    ///   bridge registration URL and polls until the ceremony completes.
    /// - `credentials list [--profile <name>]` — list registered passkeys.
    ///   Redacts `credential_id`.
    /// - `credentials delete <name> [--yes]` — delete a named passkey.
    /// - `credentials show <name>` — show credential metadata (no secret
    ///   material).
    Credentials(commands::credentials::CredentialsArgs),

    /// Deposit or withdraw from a DeFindex vault.
    ///
    /// Enforces the ordered trust gate: vault WASM-hash pin, upgradable-flag
    /// check, role disclosure.  Signs and submits via the wallet's
    /// smart-account.
    Vault(commands::vault::VaultArgs),

    /// Swap tokens via the Soroswap ROUTER-DIRECT path.
    ///
    /// Enforces the ordered trust gate: venue allowlist, router WASM-hash pin,
    /// on-chain slippage re-verify.  Requires absolute `amount_out_min` (not a
    /// percent).  Signs and submits via the wallet's smart-account.
    Trade(commands::trade::TradeArgs),

    /// Create or remove a Stellar classic trustline (`ChangeTrust`).
    ///
    /// Enforces the full ordered trust gate before signing:
    /// operator policy evaluation, denomination resolver (USDT refusal +
    /// known-lookalike denylist + pinned-issuer-mismatch + unpinned-bare-code),
    /// live issuer-flag fetch (an issuer read error refuses),
    /// wallet-controlled clawback opt-in check, and preview disclosure.
    Trustline(commands::trustline::TrustlineArgs),

    /// Claim a Stellar claimable balance (`ClaimClaimableBalance`).
    ///
    /// Fetches the on-chain `ClaimableBalanceEntry`, renders a typed preview,
    /// then enforces the claim guards before signing: claimant membership,
    /// predicate satisfaction, non-native trustline state, and native-XLM fee
    /// affordability. On mainnet only the full pipeline runs, under the
    /// mainnet authorization; the staged modes, and every mainnet run of a
    /// build without `mainnet-write`, refuse with
    /// `network.mainnet_write_forbidden` before any RPC call. Supports the
    /// three-stage pipeline: `--build-only`, `--sign-only <xdr>`,
    /// `--submit-only <xdr>`. Default: build → sign → submit atomically.
    Claim(Box<commands::claim::ClaimArgs>),

    /// Toolset install and uninstall.
    ///
    /// Provides:
    /// - `toolsets install <pkg>@<version> --file <path> --shasum <hex>
    ///   --signature <hex> --publisher <G-strkey> [--force] [--allow-downgrade]`
    ///   — install a toolset from a signed `.tar.gz` package with cryptographic
    ///   provenance verification (hash + ed25519 signature + trust set).
    /// - `toolsets uninstall <pkg>` — remove an installed toolset.
    ///
    /// No MCP tool or capability registration at install time.
    Toolsets(commands::toolsets::ToolsetsArgs),

    /// Smart-account administration (alias `sa`).
    ///
    /// Operates against a deployed OpenZeppelin smart-account contract:
    /// context-rule and signer-set lifecycle, multicall-router bundle
    /// submission, verifier deployment/migration, and upgrade-timelock
    /// operations.
    ///
    /// Verbs:
    /// - `smart-account rules <create | get | set-name | set-valid-until |
    ///   delete | add-policy | remove-policy | list>` — context-rule lifecycle.
    /// - `smart-account signers <list | refresh | add | remove |
    ///   set-threshold>` — signer-set lifecycle.
    /// - `smart-account multicall` — submit a batched invocation bundle.
    /// - `smart-account deploy-webauthn-verifier` — deploy the OZ
    ///   WebAuthn-verifier WASM and record its address.
    /// - `smart-account deploy-ed25519-verifier` — deploy the OZ
    ///   Ed25519-verifier WASM and record its address.
    /// - `smart-account deploy-spending-limit-policy` — deploy the OZ
    ///   spending-limit-policy WASM (per-network singleton) and record its
    ///   address.
    /// - `smart-account migrate-verifier` — plan/execute External-signer
    ///   verifier migration.
    /// - `smart-account list-verifiers` — enumerate the verifier allowlist.
    /// - `smart-account list-rules` — alias for `smart-account rules list`.
    /// - `smart-account register-multicall` / `unregister-multicall` — manage
    ///   the local multicall-router registry.
    /// - `smart-account timelock <schedule | cancel | execute | list-pending>`
    ///   — OZ upgrade-timelock operations.
    ///
    /// All write subcommands invoke `Signer::sign_auth_digest` exclusively
    /// and structurally refuse mainnet.
    #[command(visible_alias = "sa")]
    SmartAccount(commands::smart_account::SmartAccountArgs),
}

impl Commands {
    /// The profile name the selected subcommand operates on, before the
    /// environment-variable and `"default"` fall-through.
    ///
    /// `Some(name)` is a name the subcommand itself will use — an explicit
    /// `--profile` or a positional `<NAME>`. `None` means the subcommand
    /// supplied nothing, so [`resolve_profile_name`] falls through exactly as
    /// the subcommand does.
    ///
    /// Feeding this to [`resolve_profile_name`] is what makes the startup
    /// advisory's profile equal the command's own: both sides consume the same
    /// parsed value through the same resolver.
    fn profile_flag(&self) -> Option<&str> {
        match self {
            Self::Mcp(_) => None,
            Self::Approve(a) => a.profile_flag(),
            Self::Audit(a) => a.profile_flag(),
            Self::Tx(a) => a.profile_flag(),
            Self::Accounts(a) => a.profile_flag(),
            Self::Counterparty(a) => a.profile_flag(),
            Self::Fees(a) => a.profile_flag(),
            Self::Pay(a) => a.profile.as_deref(),
            Self::Mpp(a) => a.profile_flag(),
            Self::Pool(a) => a.profile_flag(),
            Self::Profile(a) => a.profile_flag(),
            Self::Credentials(a) => a.profile_flag(),
            Self::Vault(a) => a.profile_flag(),
            Self::Trade(a) => a.profile.as_deref(),
            Self::Trustline(a) => a.profile.as_deref(),
            Self::Claim(a) => a.profile.as_deref(),
            Self::Toolsets(a) => a.profile_flag(),
            Self::SmartAccount(a) => a.profile_flag(),
            // No profile selector: `balances` targets an account through
            // `--rpc-url`, `friendbot` funds one through a funding endpoint.
            Self::Balances(_) | Self::Friendbot(_) => None,
        }
    }
}

/// Selects the process role before either role initializes its runtime.
///
/// The tool hardens while still single-threaded and exits if hardening fails.
fn main() {
    match role::select(&std::env::args_os().collect::<Vec<_>>(), cfg!(windows)) {
        role::Role::Server { skip, display_name } => {
            stellar_agent_mcp::entry::run_server_process(display_name, std::env::args().skip(skip))
        }
        role::Role::Tool => std::process::exit(process_hardening::guarded_start(
            process_hardening::harden_process,
            run,
        )),
    }
}

/// Builds the multi-thread runtime and runs [`async_main`] on it, returning
/// the command's exit code.
///
/// The runtime is shut down without waiting for its remaining tasks, so a
/// task still blocked on a terminal or socket read does not hold the exit.
fn run() -> i32 {
    stellar_agent_core::test_trace::record("runtime");
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => {
            let exit_code = runtime.block_on(async_main());
            runtime.shutdown_background();
            exit_code
        }
        Err(err) => {
            common::render::render_json(&stellar_agent_core::envelope::Envelope::<()>::err_raw(
                "wallet.runtime_unavailable",
                format!("the async runtime could not be started ({err}); the command did not run"),
            ));
            1
        }
    }
}

/// Runs the parsed command and returns its exit code.
async fn async_main() -> i32 {
    // Install the subscriber first so any subsequent `tracing::*` call
    // participates in the redaction pipeline.
    let init_result = observability::init_subscriber(None);

    if let Err(err) = &init_result {
        // Subscriber install failed; emit a plain fallback to stderr before
        // exiting. Using `eprintln!` here rather than `tracing::error!` is
        // deliberate: without an installed subscriber, `tracing::error!`
        // would silently drop the event.
        #[allow(clippy::print_stderr)]
        {
            eprintln!("stellar-agent: subscriber init failed ({err}); continuing without logs");
        }
    }

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return report_parse_error(&error),
    };

    // ── Startup advisory ────────────────────────────────────────────────────
    //
    // Scans the local audit log for context rules referencing revoked or retired
    // verifier wasm hashes (VERIFIER_ALLOWLIST). Non-fatal — errors are logged
    // at warn level; CLI startup is never aborted.
    //
    // Profile name: the name the parsed subcommand itself operates on, run
    // through the same resolver the subcommand uses. The advisory therefore
    // scans the audit log of the profile the command uses.
    //
    // `profile init` and `profile enable-mainnet` skip the scan. Each shows
    // its spending preview on stderr before its first write. The scan may
    // append an audit row and write to stderr ahead of that preview.
    //
    // `run_startup_advisory` accepts no `StellarRpcClient`: the advisory scan is
    // strictly local and issues no network calls.
    let _ = startup_advisory_for(&cli.command, |path, open_writer| {
        advisory::run_startup_advisory(path, open_writer)
    });

    match cli.command {
        Commands::Mcp(_) => {
            common::render::render_json(&stellar_agent_core::envelope::Envelope::<()>::err_raw(
                "validation.usage_error",
                "use stellar-agent mcp serve [--profile <NAME>]",
            ));
            1
        }
        Commands::Vault(args) => commands::vault::run(&args).await,
        Commands::Trade(args) => commands::trade::run(&args).await,
        Commands::Trustline(args) => commands::trustline::run(&args).await,
        Commands::Claim(args) => commands::claim::run(&args).await,
        Commands::Approve(args) => commands::approve::dispatch(args).await,
        Commands::Audit(args) => commands::audit::run(&args).await,
        Commands::Tx(args) => commands::tx::run(&args).await,
        Commands::Accounts(args) => commands::accounts::run(&args).await,
        Commands::Balances(args) => commands::balances::run(&args).await,
        Commands::Counterparty(args) => commands::counterparty::run(&args).await,
        Commands::Credentials(args) => commands::credentials::run(&args).await,
        Commands::Fees(args) => commands::fees::run(&args).await,
        Commands::Friendbot(args) => commands::friendbot::run(&args).await,
        Commands::Pay(args) => commands::pay::run(&args).await,
        Commands::Mpp(args) => commands::mpp::run(args).await,
        Commands::Pool(args) => commands::pool::run(&args).await,
        Commands::Profile(args) => commands::profile::run(&args).await,
        Commands::Toolsets(args) => commands::toolsets::run(&args).await,
        Commands::SmartAccount(args) => commands::smart_account::run(&args).await,
    }
}

/// Reports an argument-parsing outcome that ends the process and returns the
/// exit code.
///
/// `--help` and `--version` print their text to stdout through clap and exit
/// `0`. Every other parse failure prints one `validation.usage_error` error
/// envelope on stdout and exits `1`, the code of every other error, so a
/// script sees one envelope for every invocation and nothing on stderr.
fn report_parse_error(error: &clap::Error) -> i32 {
    use clap::error::ErrorKind;
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => error.exit(),
        _ => {
            common::render::render_json(&usage_error_envelope(error));
            1
        }
    }
}

/// Builds a usage refusal from the error class and schema-defined argument names.
/// Parser renderings and rejected values never enter the envelope.
fn usage_error_envelope(error: &clap::Error) -> stellar_agent_core::envelope::Envelope<()> {
    use clap::CommandFactory;
    use clap::error::{ContextKind, ContextValue, ErrorKind};

    // Match the parser's argument context against the schema before using it.
    // Unknown flags and subcommands are caller input, even in this context.
    let reported = match error.get(ContextKind::InvalidArg) {
        Some(ContextValue::String(name)) => vec![name.as_str()],
        Some(ContextValue::Strings(names)) => names.iter().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    let mut command = Cli::command();
    command.build();
    let names: Vec<String> = reported
        .into_iter()
        .filter_map(|name| schema_argument_name(&command, name))
        .collect();
    let message = if names.is_empty() {
        "command-line arguments are not valid; run the command with --help for the accepted arguments".to_owned()
    } else {
        let class = match error.kind() {
            ErrorKind::MissingRequiredArgument => "a required argument is missing",
            ErrorKind::ArgumentConflict => "arguments conflict",
            ErrorKind::TooManyValues => "too many values",
            ErrorKind::TooFewValues | ErrorKind::WrongNumberOfValues => {
                "the number of values is not valid"
            }
            ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
                "the argument value is not valid"
            }
            _ => "command-line arguments are not valid",
        };
        format!(
            "{class}: {}; run the command with --help for the accepted arguments",
            names.join(", ")
        )
    };
    stellar_agent_core::envelope::Envelope::<()>::err_raw("validation.usage_error", message)
}

/// Returns only a name defined by the command schema, never the supplied text.
fn schema_argument_name(command: &clap::Command, reported: &str) -> Option<String> {
    for argument in command.get_arguments() {
        if reported == argument.to_string()
            || argument
                .get_long()
                .is_some_and(|long| reported == format!("--{long}"))
        {
            return Some(argument.get_long().map_or_else(
                || argument.get_id().as_str().to_owned(),
                |long| format!("--{long}"),
            ));
        }
    }
    command
        .get_subcommands()
        .find_map(|subcommand| schema_argument_name(subcommand, reported))
}

/// Loads the selected profile locally before scanning its configured audit log.
///
/// A profile-load failure skips the advisory silently: subcommand dispatch
/// owns every refusal, and the commands that need no profile (`profile init`
/// on a fresh installation, the vault verbs) run without a profile on disk.
/// The skip is recorded at `debug!` only, so stderr carries one report per
/// failure and none for a profile that does not exist yet.
fn run_profile_startup_advisory(
    profile_flag: Option<&str>,
    scan: impl FnOnce(
        &std::path::Path,
        Box<dyn FnOnce() -> Result<Arc<Mutex<AuditWriter>>, String> + '_>,
    ) -> advisory::AdvisoryResult,
) -> advisory::AdvisoryResult {
    let resolved = resolve_profile_name(profile_flag);
    match common::profile_access::load_profile_reconciled(&resolved) {
        Ok(profile) => scan(
            &profile.audit_log_path,
            Box::new(|| {
                commands::value_audit::open_best_effort_audit_writer(
                    &profile,
                    &resolved.name,
                    common::profile_access::ProfileOrigin::Persisted,
                )
                .map(|writer| Arc::new(Mutex::new(writer)))
                .map_err(|error| error.to_string())
            }),
        ),
        Err(error) => {
            tracing::debug!(
                code = error.code(),
                "startup advisory: profile not loaded; advisory skipped"
            );
            advisory::AdvisoryResult::default()
        }
    }
}

/// Whether `command` skips the startup advisory.
///
/// `profile init` and `profile enable-mainnet` write their spending preview
/// to stderr before their first write. An advisory scan ahead of them could
/// write an audit row and stderr text first, so both skip it.
fn defers_startup_advisory(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Profile(args)
            if matches!(
                args.subcommand,
                commands::profile::ProfileSubcommand::Init(_)
                    | commands::profile::ProfileSubcommand::EnableMainnet(_)
            )
    )
}

/// Runs the startup advisory for `command`: nothing for a command that
/// defers it (see [`defers_startup_advisory`]), and otherwise the scan of the
/// audit log of the profile the command operates on.
fn startup_advisory_for(
    command: &Commands,
    scan: impl FnOnce(
        &std::path::Path,
        Box<dyn FnOnce() -> Result<Arc<Mutex<AuditWriter>>, String> + '_>,
    ) -> advisory::AdvisoryResult,
) -> advisory::AdvisoryResult {
    if defers_startup_advisory(command) {
        return advisory::AdvisoryResult::default();
    }
    run_profile_startup_advisory(command.profile_flag(), scan)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only")]

    use super::*;

    /// The release proof matrix, read from beside its checker.
    const PROOF_MATRIX: &str = include_str!("../../../.github/scripts/proof-matrix.toml");

    /// Every CLI name of the release proof matrix, a row's verb or an excluded
    /// entry's, is a subcommand path of the CLI's definition.
    #[test]
    fn every_proof_matrix_cli_name_is_a_subcommand() {
        use clap::CommandFactory as _;

        let matrix: toml::Table = toml::from_str(PROOF_MATRIX).expect("the matrix parses");
        let mut names = Vec::new();
        for table in ["row", "excluded"] {
            let entries = matrix
                .get(table)
                .and_then(toml::Value::as_array)
                .expect("the matrix holds the table");
            for entry in entries {
                if entry.get("surface").and_then(toml::Value::as_str) == Some("cli") {
                    let name = entry.get("name").and_then(toml::Value::as_str);
                    names.push(name.expect("a CLI entry has a name").to_owned());
                }
            }
        }
        assert!(!names.is_empty(), "the matrix names CLI entries");
        let cli = Cli::command();
        let unknown: Vec<&String> = names
            .iter()
            .filter(|name| {
                let mut command = &cli;
                for word in name.split(' ') {
                    match command.find_subcommand(word) {
                        Some(subcommand) => command = subcommand,
                        None => return true,
                    }
                }
                false
            })
            .collect();
        assert!(
            unknown.is_empty(),
            "matrix CLI names that are no subcommand: {unknown:?}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn startup_refusal_log_omits_the_requested_profile() {
        use stellar_agent_test_support::log_capture::{CaptureWriter, inert_dispatcher};
        let home = tempfile::tempdir().expect("test home");
        let _home = stellar_agent_test_support::StellarAgentHomeGuard::new(home.path());
        let capture = CaptureWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        let _inert = inert_dispatcher();
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            run_profile_startup_advisory(Some("CREDMARKER7"), |_, _| {
                unreachable!("an absent profile cannot be scanned")
            });
        });
        let logs = capture.captured_str();
        assert!(logs.contains("startup advisory: profile not loaded; advisory skipped"));
        assert!(logs.contains("code="));
        assert!(!logs.contains("CREDMARKER7"));
        assert!(!logs.contains("profile="));
    }

    #[test]
    fn startup_advisory_writer_failure_keeps_stderr() {
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--exact",
                "advisory::tests::advisory_writer_open_failure_warns_once_and_keeps_findings",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("run advisory failure fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(lines.len(), 2, "{stderr}");
        for (line, byte) in lines.iter().zip(["ab", "cd"]) {
            assert_eq!(
                *line,
                format!(
                    "[advisory] rule 4 references revoked verifier {}; \
                     run 'stellar-agent smart-account migrate-verifier' to remediate",
                    byte.repeat(32),
                )
            );
        }
    }

    #[test]
    fn startup_advisory_production_writer_failure_keeps_stderr() {
        let output = common::test_support::child_command(
            "advisory::tests::startup_advisory_production_open_failure_warns_once_and_keeps_findings",
            &[],
        )
            .arg("--exact")
            .output()
            .expect("run production advisory failure fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stdout}\n{stderr}");
        assert!(stdout.contains("test result: ok. 1 passed"), "{stdout}");
        assert_eq!(
            stderr.trim_end(),
            format!(
                "[advisory] rule 4 references revoked verifier {}; \
                 run 'stellar-agent smart-account migrate-verifier' to remediate",
                "ab".repeat(32),
            ),
        );
    }

    /// Parses an argument vector the way `main` does and returns the profile
    /// the startup advisory would scan.
    fn advisory_profile_flag(argv: &[&str]) -> Option<String> {
        let cli = Cli::try_parse_from(argv).expect("argv must parse");
        cli.command.profile_flag().map(str::to_owned)
    }

    /// A verb that resolves the environment variable reports no flag when none
    /// was given, so the advisory falls through exactly as the command does.
    #[test]
    fn a_resolving_verb_reports_its_flag_or_nothing() {
        assert_eq!(
            advisory_profile_flag(&[
                "stellar-agent",
                "trustline",
                "--from",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                "--asset",
                "USDC",
            ]),
            None,
            "no flag means fall through to STELLAR_AGENT_PROFILE, then \"default\""
        );
        assert_eq!(
            advisory_profile_flag(&[
                "stellar-agent",
                "trustline",
                "--from",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                "--asset",
                "USDC",
                "--profile",
                "alice",
            ]),
            Some("alice".to_owned())
        );
    }

    /// The value-moving verbs report no flag when none was given, so the
    /// advisory falls through to `STELLAR_AGENT_PROFILE` exactly as they do.
    ///
    /// No CLI verb carries a clap default on its profile selector
    /// (`tests/cli/profile_flag_discipline.rs` enforces that), so a `Some(..)`
    /// here would mean the advisory scans a different profile's audit log
    /// than the command it precedes.
    #[test]
    fn the_value_moving_verbs_report_their_flag_or_nothing() {
        let pay_without_flag = &[
            "stellar-agent",
            "pay",
            "--source",
            "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
            "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            "1",
        ];
        assert_eq!(
            advisory_profile_flag(pay_without_flag),
            None,
            "`pay` resolves the environment variable, so an absent flag must fall through"
        );
        assert_eq!(
            advisory_profile_flag(&[
                "stellar-agent",
                "pay",
                "--profile",
                "alice",
                "--source",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
                "1",
            ]),
            Some("alice".to_owned())
        );
        assert_eq!(
            advisory_profile_flag(&[
                "stellar-agent",
                "claim",
                "--source",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                &"0".repeat(72),
            ]),
            None,
            "`claim` resolves the environment variable, so an absent flag must fall through"
        );
        assert_eq!(
            advisory_profile_flag(&[
                "stellar-agent",
                "accounts",
                "create",
                "--fund-with-friendbot",
                "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
            ]),
            None,
            "`accounts create` resolves the environment variable, so an absent flag must \
             fall through"
        );
    }

    /// A positional-or-flag verb reports the name it was given in either form.
    #[test]
    fn a_positional_verb_reports_its_effective_name() {
        assert_eq!(
            advisory_profile_flag(&["stellar-agent", "profile", "show", "alice"]),
            Some("alice".to_owned())
        );
        assert_eq!(
            advisory_profile_flag(&["stellar-agent", "profile", "show", "--profile", "alice"]),
            Some("alice".to_owned())
        );
    }

    /// A verb with no profile selector reports none rather than a literal.
    #[test]
    fn a_profile_less_verb_reports_nothing() {
        assert_eq!(
            advisory_profile_flag(&[
                "stellar-agent",
                "balances",
                "--account",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
            ]),
            None
        );
    }

    /// A trailing `--` guards its operands: a value after it is a positional of
    /// the subcommand, never the advisory's profile.
    #[test]
    fn an_operand_after_the_separator_is_not_a_profile_name() {
        assert_eq!(
            advisory_profile_flag(&["stellar-agent", "profile", "show", "--", "alice"]),
            Some("alice".to_owned()),
            "`alice` here is the positional NAME, which IS the profile"
        );
        assert_eq!(
            advisory_profile_flag(&["stellar-agent", "counterparty", "evict", "--", "circle.com",]),
            None,
            "an operand that is not a profile selector must not be read as one"
        );
    }
}
