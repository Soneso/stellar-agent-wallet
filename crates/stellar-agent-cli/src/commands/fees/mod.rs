//! Fee-related CLI subcommands.

pub mod stats;

use clap::{Args, Subcommand};

/// `stellar-agent fees ...` command group.
#[derive(Debug, Args)]
pub struct FeesArgs {
    /// Fee subcommand.
    #[command(subcommand)]
    pub command: FeesSubcommand,
}

/// Fee subcommands.
#[derive(Debug, Subcommand)]
pub enum FeesSubcommand {
    /// Fetch Stellar RPC fee statistics.
    Stats(stats::FeesStatsArgs),
}

/// Dispatches the fee command group.
pub async fn run(args: &FeesArgs) -> i32 {
    match &args.command {
        FeesSubcommand::Stats(stats_args) => stats::run(stats_args).await,
    }
}
