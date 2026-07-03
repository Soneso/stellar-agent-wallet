//! `stellar-agent audit` subcommand group.
//!
//! Parent module for audit-log management subcommands.  Provides:
//!
//! - [`verify`] — walk a hash-chained audit log file and verify the chain
//!   integrity from the oldest rotated file to the current active file.
//!
//! # Dispatch
//!
//! [`AuditArgs`] is a `clap` [`Args`] struct with a nested [`AuditSubcommand`]
//! enum.  The top-level [`crate::main`] function routes `Commands::Audit(args)`
//! to [`run`], which delegates to the appropriate subcommand handler.

pub mod verify;

use clap::{Args, Subcommand};

/// Arguments for the `audit` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct AuditArgs {
    /// The audit subcommand to run.
    #[command(subcommand)]
    pub subcommand: AuditSubcommand,
}

/// Subcommands of `stellar-agent audit`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum AuditSubcommand {
    /// Verify the integrity of a hash-chained audit log file.
    ///
    /// Walks the log at `<log-path>` and verifies that every entry's
    /// `previous_entry_hash` matches the SHA-256 of the prior entry's
    /// canonical body.  Follows rotation manifests (cross-file chain bridges)
    /// automatically.
    ///
    /// Exits 0 on success; exits 1 on any integrity violation or I/O error.
    Verify(verify::VerifyArgs),
}

/// Runs the `audit` subcommand group.
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
pub async fn run(args: &AuditArgs) -> i32 {
    match &args.subcommand {
        AuditSubcommand::Verify(a) => verify::run(a).await,
    }
}
