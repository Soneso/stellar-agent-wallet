//! Channel-account pool CLI subcommand group.
//!
//! Provides:
//! - `pool init --size N [--profile P]` — build and submit the CAP-33
//!   sponsored-reserve sandwich for N channels.
//! - `pool list [--profile P]` — list channels with cached sequence + status.
//! - `pool status [--profile P]` — utilisation: free/in-flight/total.
//!
//! JSON output by default.

pub mod init;
pub mod list;
pub mod status;

use clap::{Args, Subcommand};

/// `stellar-agent pool ...` command group.
#[derive(Debug, Args)]
pub struct PoolArgs {
    /// Pool subcommand.
    #[command(subcommand)]
    pub command: PoolSubcommand,
}

/// Pool subcommands.
#[derive(Debug, Subcommand)]
pub enum PoolSubcommand {
    /// Initialise the channel-account pool.
    ///
    /// Funds N channel accounts on-chain via a single CAP-33
    /// sponsored-reserve sandwich transaction.
    ///
    /// Channel accounts derive deterministically from the pool master seed
    /// at `m/44'/148'/1'` through `m/44'/148'/N'`.
    ///
    /// Rejects `--size 0` and `--size > 19`: the funder plus N channel
    /// signatures must fit the 20-signature cap on the sandwich envelope
    /// (`ChannelPool::MAX_SIZE`).
    Init(init::PoolInitArgs),

    /// List all channels in the pool with cached sequence numbers and status.
    ///
    /// Reads the pool configuration from the profile and displays each
    /// channel's public key, BIP-44 index, cached sequence, and in-flight
    /// status.
    List(list::PoolListArgs),

    /// Display pool utilisation (free / in-flight / total).
    ///
    /// Returns a JSON summary of pool utilisation for the current profile.
    Status(status::PoolStatusArgs),
}

/// Dispatches the pool command group.
///
/// # Exit codes
///
/// - `0` on success.
/// - `1` on any error.
pub async fn run(args: &PoolArgs) -> i32 {
    match &args.command {
        PoolSubcommand::Init(init_args) => init::run(init_args).await,
        PoolSubcommand::List(list_args) => list::run(list_args).await,
        PoolSubcommand::Status(status_args) => status::run(status_args).await,
    }
}
