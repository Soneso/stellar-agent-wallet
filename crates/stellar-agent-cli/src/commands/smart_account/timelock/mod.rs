//! `stellar-agent smart-account timelock` subcommand group — OZ upgrade timelock.
//!
//! Wraps the off-chain production primitives in
//! `stellar_agent_smart_account::timelock` as CLI verbs for the operator.
//!
//! # Subcommands
//!
//! - [`schedule`] — schedule a timelock operation (proposer role required).
//! - [`cancel`] — cancel a pending operation (canceller role required).
//! - [`execute`] — execute a ready operation (executor role required or open-execution).
//! - [`list_pending`] — list pending operations from the audit log + dual-RPC state.
//!
//! # Dispatch
//!
//! [`TimelockArgs`] is a `clap` [`Args`] struct with a nested [`TimelockSubcommand`]
//! enum. The parent [`super::run`] routes `SmartAccountSubcommand::Timelock(args)` to
//! [`run`], which delegates to the appropriate subcommand handler.
//!
//! # Reference
//!
//! OZ `stellar-governance v0.7.1` `Timelock` trait.

pub mod cancel;
pub mod execute;
pub mod list_pending;
pub mod schedule;

use clap::{Args, Subcommand};

/// Arguments for the `smart-account timelock` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct TimelockArgs {
    /// The `timelock` subcommand to run.
    #[command(subcommand)]
    pub subcommand: TimelockSubcommand,
}

/// Subcommands of `stellar-agent smart-account timelock`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum TimelockSubcommand {
    /// Schedule a timelock operation on the OZ timelock contract.
    ///
    /// Builds and submits a `Timelock::schedule` transaction. The signer must
    /// hold `PROPOSER_ROLE` on the timelock contract. The operation_id salt
    /// is derived non-deterministically (`sha256(request_id || timestamp_nanos)`)
    /// so the salt cannot be predicted before scheduling.
    ///
    /// On success, prints the `operation_id_full_hex` needed for `cancel`/`execute`.
    ///
    /// Emits `SaTimelockScheduled` audit row on success.
    #[command(name = "schedule")]
    Schedule(Box<schedule::ScheduleArgs>),

    /// Cancel a pending timelock operation.
    ///
    /// Submits a `Timelock::cancel` transaction. The signer must hold
    /// `CANCELLER_ROLE` on the timelock contract.
    ///
    /// Cross-confirms the `OperationCancelled` event before returning,
    /// ensuring event-emission integrity.
    ///
    /// Emits `SaTimelockCancelled` audit row on success.
    #[command(name = "cancel")]
    Cancel(Box<cancel::CancelArgs>),

    /// Execute a ready timelock operation.
    ///
    /// Performs a pre-flight dual-RPC `get_operation_state` check
    /// (guards against the ready-window race) before submitting.
    /// Fail-CLOSED if the operation is not `Ready`.
    ///
    /// The signer must hold `EXECUTOR_ROLE` (or open-execution mode must
    /// be enabled on the timelock contract).
    ///
    /// Emits `SaTimelockExecuted` audit row on success.
    #[command(name = "execute")]
    Execute(Box<execute::ExecuteArgs>),

    /// List pending timelock operations for a timelock contract.
    ///
    /// Reads the local audit log for scheduled operations that have no
    /// corresponding cancel or execute row, then cross-confirms each
    /// candidate's state via dual-RPC `get_operation_state` query.
    ///
    /// Read-only: no signing required.
    #[command(name = "list-pending")]
    ListPending(list_pending::ListPendingArgs),
}

/// Runs the `smart-account timelock` subcommand group.
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
pub async fn run(args: &TimelockArgs) -> i32 {
    match &args.subcommand {
        TimelockSubcommand::Schedule(a) => schedule::run(a).await,
        TimelockSubcommand::Cancel(a) => cancel::run(a).await,
        TimelockSubcommand::Execute(a) => execute::run(a).await,
        TimelockSubcommand::ListPending(a) => list_pending::run(a).await,
    }
}
