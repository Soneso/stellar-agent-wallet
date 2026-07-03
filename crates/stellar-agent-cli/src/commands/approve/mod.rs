//! `stellar-agent approve` subcommand group.
//!
//! Wallet-owned approval spine — CLI half.
//!
//! Provides:
//! - `stellar-agent approve --id <approval-nonce>` — interactive y/n for a
//!   pending approval.  Computes the HMAC attestation and writes back to the
//!   pending-approvals store.
//! - `stellar-agent approve --id <approval-nonce> --yes` — non-interactive
//!   auto-approve for scripting and tests.  Bypasses the tty prompt; use only
//!   in trusted automation flows.
//! - `stellar-agent approve gc` — evict expired pending approvals.
//! - `stellar-agent approve gc --profile <name>` — per-profile gc.
//! - `stellar-agent approve list` — enumerate pending approvals (read-only).
//! - `stellar-agent approve serve` — local web UI for the pending-approval
//!   queue (loopback HTTP; approve/reject in a browser).
//!
//! # Dispatch
//!
//! [`ApproveArgs`] is a `clap` [`Args`] struct with:
//!
//! - A flattened [`run::RunArgs`] for the bare `approve --id <nonce>` form.
//! - An optional nested [`ApproveSubcommand`] for subcommands (`gc`, `list`,
//!   `serve`).
//!
//! When `subcommand` is `None`, the `run` path is taken and `--id` is required.
//! When `subcommand` is `Some(...)`, the matching subcommand path is taken and
//! `--id` is ignored.
//!
//! # UX forms
//!
//! ```text
//! stellar-agent approve --id ABCnonce
//! stellar-agent approve --id ABCnonce --yes
//! stellar-agent approve gc
//! stellar-agent approve gc --profile <name>
//! stellar-agent approve list
//! stellar-agent approve list --profile <name> --output table
//! stellar-agent approve serve
//! stellar-agent approve serve --profile <name> --port 7823
//! ```
//!
//! This is the CLI user-tty half of the wallet-owned approval spine.

mod common;
pub mod gc;
pub mod list;
pub mod run;
pub mod serve;

use clap::{Args, Subcommand};

/// Arguments for the `approve` subcommand group.
///
/// Accepts either:
/// - A bare `approve --id <nonce>` invocation (interactive or `--yes`
///   non-interactive), or
/// - A nested `gc`, `list`, or `serve` subcommand.
///
/// The flattened [`run::RunArgs`] supplies `--id` and `--yes` for the
/// bare-form path.  `--id` is required in the bare form; it is silently
/// ignored when a subcommand is present.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct ApproveArgs {
    /// Optional nested subcommand (`gc`, `list`, or `serve`).
    ///
    /// When `None`, the `approve --id <nonce>` run path is taken and
    /// `--id` from the flattened [`run::RunArgs`] is required.
    #[command(subcommand)]
    pub subcommand: Option<ApproveSubcommand>,

    /// Flattened run arguments (`--id`, `--profile`, `--yes`).
    ///
    /// Active when `subcommand` is `None`.
    #[command(flatten)]
    pub run: run::RunArgs,
}

/// Subcommands of `stellar-agent approve`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum ApproveSubcommand {
    /// Garbage-collect expired pending approvals.
    ///
    /// Removes entries whose TTL has elapsed from the pending-approvals store.
    /// On success prints a JSON envelope with the count of evicted entries.
    Gc(gc::GcArgs),

    /// Enumerate pending approvals.
    ///
    /// Read-only: opens the store, renders a redacted snapshot, and exits.
    /// Performs no keyring access and no network calls.
    List(list::ListArgs),

    /// Serve a local web UI for the pending-approval queue.
    ///
    /// Binds a loopback HTTP server so the operator can review and
    /// approve/reject pending approvals in a browser. Runs until Ctrl-C.
    Serve(serve::ServeArgs),
}

/// Runs the `approve` subcommand group.
///
/// Dispatches to [`gc::run`], [`list::run`], or [`serve::run`] when the
/// matching subcommand is present, or to [`run::run`] for the bare
/// `approve --id <nonce>` form.
///
/// Returns `0` on success, `1` on any error.
///
/// # Errors
///
/// Never returns `Err` — errors are captured into the exit code.
///
/// # Panics
///
/// Never panics.
pub async fn dispatch(args: ApproveArgs) -> i32 {
    match args.subcommand {
        Some(ApproveSubcommand::Gc(gc_args)) => gc::run(gc_args).await,
        Some(ApproveSubcommand::List(list_args)) => list::run(list_args).await,
        Some(ApproveSubcommand::Serve(serve_args)) => serve::run(serve_args).await,
        None => run::run(args.run).await,
    }
}
