//! `stellar-agent accounts` subcommand group.
//!
//! Parent module for all account-management subcommands. Currently contains:
//!
//! - [`create`] — create a new Stellar account on-chain via sponsored
//!   `CreateAccount` op or via Friendbot (testnet only).
//! - [`deploy_c`] — deploy a new OpenZeppelin smart-account (C-account)
//!   contract instance via Soroban `CreateContractV2`.
//!
//! # Dispatch
//!
//! [`AccountsArgs`] is a `clap` [`Args`] struct with a nested [`AccountsSubcommand`]
//! enum. The top-level [`crate::main`] function routes `Commands::Accounts(args)`
//! to [`run`], which delegates to the appropriate subcommand handler.

pub mod create;
pub mod deploy_c;

use clap::{Args, Subcommand};

/// Arguments for the `accounts` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct AccountsArgs {
    /// The accounts subcommand to run.
    #[command(subcommand)]
    pub subcommand: AccountsSubcommand,
}

/// Subcommands of `stellar-agent accounts`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum AccountsSubcommand {
    /// Create a new Stellar account on-chain.
    ///
    /// Supports two mutually-exclusive modes:
    ///
    /// **Sponsored mode** (`--sponsor` + signer + `--starting-balance`): submits
    /// a `CreateAccount` op signed by the sponsor account. Testnet only.
    ///
    /// **Friendbot mode** (`--fund-with-friendbot`): funds the account via the
    /// Stellar Friendbot HTTP endpoint. Testnet only; structurally refused on
    /// mainnet.
    Create(Box<create::CreateArgs>),

    /// Deploy a new OpenZeppelin smart-account (C-account) contract instance.
    ///
    /// Deploys via Soroban `CreateContractV2` using the vendored OZ
    /// `multisig-account-example` WASM. The deployer pays the deployment fee
    /// and signs the transaction's source-account credentials.
    ///
    /// Two mutually-exclusive deployer modes:
    /// - `--deployer-secret-env <VAR>` — deployer S-strkey from environment variable.
    /// - `--sign-with-ledger` — Ledger hardware wallet.
    ///
    /// Use `--dry-run` to derive the C-strkey without network access.
    ///
    /// Testnet only (mainnet structurally refused).
    DeployC(Box<deploy_c::DeployCArgs>),
}

/// Runs the `accounts` subcommand group.
///
/// Dispatches to the appropriate subcommand handler.
///
/// Returns an exit code: `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn run(args: &AccountsArgs) -> i32 {
    match &args.subcommand {
        AccountsSubcommand::Create(create_args) => create::run(create_args).await,
        AccountsSubcommand::DeployC(args) => deploy_c::run(args).await,
    }
}
