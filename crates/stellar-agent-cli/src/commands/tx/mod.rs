//! `stellar-agent tx` subcommand group: reconciling and clearing recorded
//! submissions.
//!
//! Every value-moving verb records its submission before the transaction is
//! sent, so a submission whose outcome never came back leaves a receipt and a
//! spending-window reservation behind. This group is how those are settled:
//!
//! - [`status`] asks the chain what became of one transaction and settles the
//!   wallet's record of it. This is the way out of `submission.tx_timeout`.
//! - [`receipt`] is the operator's last resort for the two states
//!   reconciliation cannot settle.

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
    /// Asks the endpoint what became of `<HASH>` and settles the wallet's
    /// record of it: a confirmed transaction records its spend and its
    /// value-action row, and one that can no longer apply releases its
    /// spending-window reservation.
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
