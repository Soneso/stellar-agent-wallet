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
mod render;

use clap::{Parser, Subcommand};
use stellar_agent_core::observability;
use stellar_agent_core::profile::schema::default_audit_log_path_for;

use crate::common::resolve_profile_name;

/// Stellar agent wallet command-line interface.
///
/// A self-custodial, autonomous Stellar wallet that operates without a
/// central server. Outputs JSON by default for scripting.
#[derive(Debug, Parser)]
#[command(
    name = "stellar-agent",
    author,
    version,
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
    /// Wallet-owned approval spine — interactive y/n for pending approvals.
    ///
    /// Provides:
    /// - `approve --id <nonce>` — read a pending approval from the store,
    ///   render a wallet-controlled summary, prompt y/n, and on approval
    ///   compute and record the HMAC attestation blob.
    /// - `approve --id <nonce> --yes` — non-interactive auto-approve.
    ///   Bypasses the tty prompt; use only in trusted automation flows.
    /// - `approve gc` — evict all expired pending approvals for a profile.
    Approve(commands::approve::ApproveArgs),

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
    /// Enforces SEP-29 memo-required destinations. Structurally refuses mainnet
    /// (returns `network.mainnet_write_forbidden` before any RPC call).
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

    /// Supply, borrow, repay, or withdraw from a Blend lending pool.
    ///
    /// Enforces the ordered trust gate: pool WASM-hash pin, Reflector oracle
    /// allowlist, oracle staleness check.  Signs and submits via the wallet's
    /// smart-account.
    Lend(commands::lend::LendArgs),

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
    /// live issuer-flag fetch (fail-closed on fetch failure),
    /// wallet-controlled clawback opt-in check, and preview disclosure.
    Trustline(commands::trustline::TrustlineArgs),

    /// Claim a Stellar claimable balance (`ClaimClaimableBalance`).
    ///
    /// Fetches the on-chain `ClaimableBalanceEntry`, renders a typed preview,
    /// then enforces the claim guards before signing: claimant membership,
    /// predicate satisfaction, non-native trustline state, and native-XLM fee
    /// affordability. Structurally refuses mainnet (returns
    /// `network.mainnet_write_forbidden` before any RPC call). Supports the
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
    /// `--profile`, a positional `<NAME>`, or a clap default the subcommand
    /// carries. `None` means the subcommand supplied nothing, so
    /// [`resolve_profile_name`] falls through exactly as the subcommand does.
    ///
    /// Feeding this to [`resolve_profile_name`] is what makes the startup
    /// advisory's profile equal the command's own: both sides consume the same
    /// parsed value through the same resolver, including for the verbs that
    /// carry a clap default and therefore never consult the environment.
    fn profile_flag(&self) -> Option<&str> {
        match self {
            Self::Approve(a) => a.profile_flag(),
            Self::Audit(a) => a.profile_flag(),
            Self::Accounts(a) => a.profile_flag(),
            Self::Counterparty(a) => a.profile_flag(),
            Self::Fees(a) => a.profile_flag(),
            Self::Pay(a) => Some(a.profile.as_str()),
            Self::Mpp(a) => a.profile_flag(),
            Self::Pool(a) => a.profile_flag(),
            Self::Profile(a) => a.profile_flag(),
            Self::Credentials(a) => a.profile_flag(),
            Self::Lend(a) => a.profile.as_deref(),
            Self::Vault(a) => a.profile_flag(),
            Self::Trade(a) => a.profile.as_deref(),
            Self::Trustline(a) => a.profile.as_deref(),
            Self::Claim(a) => Some(a.profile.as_str()),
            Self::Toolsets(a) => a.profile_flag(),
            Self::SmartAccount(a) => a.profile_flag(),
            // No profile selector: `balances` targets an account through
            // `--rpc-url`, `friendbot` funds one through a funding endpoint.
            Self::Balances(_) | Self::Friendbot(_) => None,
        }
    }
}

#[tokio::main]
async fn main() {
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

    let cli = Cli::parse();

    // ── Startup advisory ────────────────────────────────────────────────────
    //
    // Scans the local audit log for context rules referencing revoked or retired
    // verifier wasm hashes (VERIFIER_ALLOWLIST). Non-fatal — errors are logged
    // at warn level; CLI startup is never aborted.
    //
    // Profile name: the name the parsed subcommand itself operates on, run
    // through the same resolver the subcommand uses. The advisory therefore
    // scans the audit log of the profile the command uses — including for the
    // verbs that carry a clap default and never consult the environment.
    //
    // `run_startup_advisory` accepts no `StellarRpcClient`: the advisory scan is
    // strictly local and issues no network calls.
    {
        let profile_name = resolve_profile_name(cli.command.profile_flag()).name;
        // Reads the per-profile DEFAULT location without loading the profile.
        // A profile with an explicit non-default audit_log_path is outside the
        // advisory's scan; the per-command audit machinery always uses the
        // loaded profile's configured path.
        let audit_log_path = default_audit_log_path_for(&profile_name);
        let _ = advisory::run_startup_advisory(&audit_log_path);
    }

    let exit_code = match cli.command {
        Commands::Lend(args) => commands::lend::run(&args).await,
        Commands::Vault(args) => commands::vault::run(&args).await,
        Commands::Trade(args) => commands::trade::run(&args).await,
        Commands::Trustline(args) => commands::trustline::run(&args).await,
        Commands::Claim(args) => commands::claim::run(&args).await,
        Commands::Approve(args) => commands::approve::dispatch(args).await,
        Commands::Audit(args) => commands::audit::run(&args).await,
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
    };

    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test-only")]

    use super::*;

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

    /// A verb carrying a clap default reports that default, so the advisory
    /// scans the log the command writes rather than the one the environment
    /// variable names.
    #[test]
    fn a_defaulted_verb_reports_its_clap_default_not_an_absent_flag() {
        assert_eq!(
            advisory_profile_flag(&[
                "stellar-agent",
                "pay",
                "--source",
                "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5",
                "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
                "1",
            ]),
            Some("default".to_owned()),
            "`pay` audits under its clap default, so the advisory must scan that \
             profile's log even when STELLAR_AGENT_PROFILE names another"
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
