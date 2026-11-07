//! `stellar-agent tx` subcommand group: reconciling and clearing recorded
//! submissions.
//!
//! Every value-moving verb records its submission before the transaction is
//! sent, so a submission whose outcome never came back leaves a receipt and a
//! spending-window reservation behind. This group is how those are resolved:
//!
//! - [`status`] asks the chain what became of one transaction and records the
//!   answer as a report. This is the way out of `submission.tx_timeout`.
//! - [`receipt`]: close a submission record after reconciling it against the chain.

pub mod receipt;
pub mod status;

use clap::{Args, Subcommand};

/// Arguments for the `tx` subcommand group.
#[derive(Debug, Args)]
#[non_exhaustive]
pub struct TxArgs {
    /// The tx subcommand to run.
    #[command(subcommand)]
    pub subcommand: TxSubcommand,
}

/// Subcommands of `stellar-agent tx`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum TxSubcommand {
    /// Reconcile one submitted transaction against the chain.
    ///
    /// Asks the endpoint what became of `<HASH>` and records a reported
    /// success on the receipt, unless the receipt of an untimed hold already
    /// records another network answer. A reported success writes no submitted
    /// row. A reported failure preserves the existing receipt status, and so
    /// does a missing transaction while the endpoint retains the submission's
    /// ledger. Beyond that retention, a missing transaction marks a pending or
    /// ambiguous receipt ambiguous. No reported answer releases the
    /// spending-window reservation. The reservation ends with the outcome
    /// unknown once its accounting horizon has passed, which owes one
    /// `submission_accounting_expired` audit event.
    ///
    /// Exits 0 when the lookup completes, whatever the chain reported; exits 1
    /// when the record or the endpoint could not be reached.
    Status(status::StatusArgs),

    /// Operator actions on a recorded submission.
    Receipt(receipt::ReceiptArgs),
}

/// Runs the `tx` subcommand group.
///
/// Returns an exit code: `0` on success, `1` on any error.
pub async fn run(args: &TxArgs) -> i32 {
    match &args.subcommand {
        TxSubcommand::Status(a) => status::run(a).await,
        TxSubcommand::Receipt(a) => receipt::run(a).await,
    }
}

impl TxArgs {
    /// The profile name this invocation operates on, as the selected
    /// subcommand resolves it.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.subcommand {
            TxSubcommand::Status(a) => a.profile.as_deref(),
            TxSubcommand::Receipt(a) => a.profile_flag(),
        }
    }
}
