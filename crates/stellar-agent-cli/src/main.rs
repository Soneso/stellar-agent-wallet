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

/// Extracts the effective profile name from raw CLI arguments before clap parsing.
///
/// Scans `std::env::args()` for `--profile <NAME>` and returns `NAME` when
/// found. Falls back to `"default"` when absent. This mirrors the per-subcommand
/// `resolve_profile_name` logic without re-parsing the full command tree.
///
/// Used exclusively by the startup advisory pre-dispatch hook to resolve the
/// audit-log path before clap consumes the argument vector.
fn extract_profile_name_from_env_args() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "--profile"
            && let Some(name) = iter.peek()
            && !name.starts_with('-')
        {
            return (*name).clone();
        }
        // Handle `--profile=NAME` form.
        if let Some(name) = arg.strip_prefix("--profile=")
            && !name.is_empty()
        {
            return name.to_owned();
        }
    }
    "default".to_owned()
}

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

    /// Channel-account pool subcommand group.
    ///
    /// Provides:
    /// - `pool init --size N [--profile P]` — fund N channel accounts via
    ///   one CAP-33 sponsored-reserve sandwich. `--size` must be 1..=33.
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
    /// - `profile rotate-nonce-key <name>` — rotate the HMAC nonce key.
    /// - `profile rotate-owner-key <name>` — rotate the policy-file owner
    ///   ed25519 key.
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

    /// Wallet-side smart-account orchestration.
    ///
    /// Provides:
    /// - `wallet rules create` — install a new context rule via OZ
    ///   `add_context_rule`.
    /// - `wallet rules get <id>` — read a single rule by id (read-only).
    /// - `wallet rules set-name <id> <name>` — rename via OZ
    ///   `update_context_rule_name`.
    /// - `wallet rules set-valid-until <id> <ledger | none>` — change expiry
    ///   via OZ `update_context_rule_valid_until` (`none` = permanent).
    /// - `wallet rules delete <id>` — remove via OZ `remove_context_rule`.
    ///
    /// All write subcommands invoke `Signer::sign_auth_digest` exclusively
    /// and structurally refuse mainnet.
    Wallet(commands::wallet::WalletArgs),
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
    // Profile name: extracted from the first `--profile <NAME>` occurrence in
    // the raw CLI args, or "default" when absent. This mirrors the per-subcommand
    // `resolve_profile_name` logic without re-parsing the full command tree.
    //
    // `run_startup_advisory` accepts no `StellarRpcClient`: the advisory scan is
    // strictly local and issues no network calls.
    {
        let profile_name = extract_profile_name_from_env_args();
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
        Commands::Pool(args) => commands::pool::run(&args).await,
        Commands::Profile(args) => commands::profile::run(&args).await,
        Commands::Toolsets(args) => commands::toolsets::run(&args).await,
        Commands::Wallet(args) => commands::wallet::run(&args).await,
    };

    std::process::exit(exit_code);
}
