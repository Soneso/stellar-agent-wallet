//! Toolset management CLI subcommand group.
//!
//! Install / uninstall:
//!
//! - `toolsets install <pkg>@<version> --shasum <hex> [--force] [--allow-downgrade]`
//!   — install a toolset from a local `.tar.gz` file.
//! - `toolsets uninstall <pkg>` — uninstall a toolset.
//!
//! List / run:
//!
//! - `toolsets list` — enumerate installed toolsets + their declared actions (JSON).
//! - `toolsets run <name> <action>` — run the four-part capability enforcement check
//!   and report the resolved trusted tool name.  Note: the binary subcommand is
//!   `toolsets run` (plural `toolsets`), not `toolset run`.
//!
//! JSON output by default.

pub mod install;
pub mod list;
pub mod run;
pub mod uninstall;

use clap::{Args, Subcommand};

/// `stellar-agent toolsets ...` command group.
#[derive(Debug, Args)]
pub struct ToolsetsArgs {
    /// Toolset subcommand.
    #[command(subcommand)]
    pub command: ToolsetsSubcommand,
}

/// Toolsets subcommands.
#[derive(Debug, Subcommand)]
pub enum ToolsetsSubcommand {
    /// Install a toolset from a signed `.tar.gz` package.
    ///
    /// The package path, version, shasum, signature, and publisher key must all
    /// be provided.  The publisher key must be present in the configured
    /// trust set.
    Install(install::ToolsetInstallArgs),

    /// List all installed toolsets and their declared actions (JSON output).
    ///
    /// Enumerates installed toolset pin records and their capability-derived
    /// action lists.  This is the canonical scriptable enumeration (not
    /// parsed from `--help` text).  Uninstall removes a toolset from the list
    /// without recompiling the binary.
    List(list::ToolsetListArgs),

    /// Invoke a toolset action through the four-part capability enforcement check.
    ///
    /// Resolves the action to a trusted registry tool via the capability→tool
    /// matrix, verifies the toolset's declared capabilities, and applies the
    /// `allowed_tools` intersective narrowing.  Returns the resolved trusted
    /// tool name on success.
    ///
    /// The enforcement check is ADDITIVE: operator policy + chain gates of the
    /// routed tool also apply.
    Run(run::ToolsetRunArgs),

    /// Uninstall a previously-installed toolset.
    ///
    /// Removes the toolset directory and pin record.  Refuses if the toolset is
    /// not installed.
    Uninstall(uninstall::ToolsetUninstallArgs),
}

/// Dispatches the toolsets command group.
///
/// # Exit codes
///
/// - `0` on success.
/// - `1` on any error.
pub async fn run(args: &ToolsetsArgs) -> i32 {
    match &args.command {
        ToolsetsSubcommand::Install(install_args) => install::run(install_args).await,
        ToolsetsSubcommand::List(list_args) => list::run(list_args).await,
        ToolsetsSubcommand::Run(run_args) => run::run(run_args).await,
        ToolsetsSubcommand::Uninstall(uninstall_args) => uninstall::run(uninstall_args).await,
    }
}
