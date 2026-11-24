//! Help schema for the MCP server route selected before CLI startup.

use clap::{Args, Subcommand};

/// MCP server commands.
#[derive(Debug, Args)]
pub struct McpArgs {
    /// Server operation.
    #[command(subcommand)]
    pub command: Option<McpCommand>,
}

/// Operations exposed in CLI help.
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Serve MCP over standard input and standard output.
    Serve {
        /// Profile to serve.
        #[arg(long)]
        profile: Option<String>,
    },
}
