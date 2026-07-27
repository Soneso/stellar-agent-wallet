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

impl FeesArgs {
    /// The profile name this invocation operates on, as the selected subcommand
    /// resolves it.
    ///
    /// `None` means the subcommand supplied no name, so
    /// [`resolve_profile_name`](crate::common::resolve_profile_name) falls through
    /// to `STELLAR_AGENT_PROFILE` and then `"default"` — the same fall-through the
    /// subcommand itself performs. The startup advisory consumes this so it scans
    /// the audit log of the profile the command uses.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.command {
            FeesSubcommand::Stats(a) => a.profile.as_deref(),
        }
    }
}
