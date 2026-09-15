//! `stellar-agent audit` subcommand group.
//!
//! Parent module for audit-log management subcommands.  Provides:
//!
//! - [`verify`] — walk a hash-chained audit log file and verify the chain
//!   integrity from the oldest rotated file to the current active file.
//! - [`reanchor`] — move the log's keyring-held tip anchor to its current tip
//!   after an operator-acknowledged rollback.
//!
//! # Dispatch
//!
//! [`AuditArgs`] is a `clap` [`Args`] struct with a nested [`AuditSubcommand`]
//! enum.  The top-level [`crate::main`] function routes `Commands::Audit(args)`
//! to [`run`], which delegates to the appropriate subcommand handler.

pub mod reanchor;
pub mod verify;

use clap::{Args, Subcommand};
use stellar_agent_core::audit_log::WriterError;
use stellar_agent_core::error::{InternalError, ValidationError, WalletError};

/// Maps an audit-writer failure onto the CLI envelope model.
///
/// Two conditions are operator-actionable and get the codes the documentation
/// names for them, rather than being flattened into the caller's generic
/// failure code:
///
/// - A held writer lock is `audit.writer_locked`. The audit writer is
///   process-exclusive, so a running MCP server makes every verb that needs the
///   writer refuse; the operator stops the server and retries. The skill's
///   troubleshooting table keys on codes, so an agent can only recognise this
///   if the code reaches the envelope.
/// - A tip-anchor mismatch is `audit.tip_anchor_mismatch`, the same code the
///   value-verb pre-flight emits, so one refusal reads the same wherever it
///   comes from.
///
/// Everything else carries `fallback_code`, the caller's own label for "this
/// verb could not use the audit writer".
///
/// Detail strings follow the CLI's sub-code convention: the detail begins with
/// the code, and the `WriterError` `Display` is appended only where it does not
/// already repeat it.
pub(crate) fn audit_writer_error(
    e: &WriterError,
    fallback_code: &str,
    profile_name: &str,
) -> WalletError {
    match e {
        WriterError::FileLocked => WalletError::Internal(InternalError::UnexpectedState {
            detail: "audit.writer_locked: the audit log's writer lock is held by another \
                     process; stop the running stellar-agent-mcp server and retry"
                .to_owned(),
        }),
        WriterError::TipAnchorMismatch { reason, .. } => {
            WalletError::Validation(ValidationError::AuditTipAnchorMismatch {
                profile: profile_name.to_owned(),
                reason: (*reason).to_owned(),
            })
        }
        // Variants whose own Display already leads with an `audit.*` code carry
        // it through unchanged; prefixing the caller's fallback would put two
        // codes in one detail and an agent matching on the first would read the
        // wrong one.
        WriterError::RotationBridgeUnusable { .. } => {
            WalletError::Internal(InternalError::UnexpectedState {
                detail: e.to_string(),
            })
        }
        _ => WalletError::Internal(InternalError::UnexpectedState {
            detail: format!("{fallback_code}: {e}"),
        }),
    }
}

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

    /// Move the audit log's keyring-held tip anchor to the log's current tip.
    ///
    /// The way out of an `audit.tip_anchor_mismatch` refusal, which fires when
    /// the active log no longer contains the anchored chain tip. Requires
    /// `--acknowledge-rollback`: moving the anchor accepts the log as it now
    /// stands, and the verb cannot tell a restored backup from tampering.
    ///
    /// Exits 0 on success; exits 1 without the acknowledgement and on any
    /// failure.
    Reanchor(reanchor::ReanchorArgs),
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
        AuditSubcommand::Reanchor(a) => reanchor::run(a).await,
    }
}

impl AuditArgs {
    /// The profile name this invocation operates on, as the selected subcommand
    /// resolves it.
    ///
    /// `None` means the subcommand supplied no name, so
    /// [`resolve_profile_name`](crate::common::resolve_profile_name) falls through
    /// to `STELLAR_AGENT_PROFILE` and then `"default"` — the same fall-through the
    /// subcommand itself performs. The startup advisory consumes this so it scans
    /// the audit log of the profile the command uses.
    pub(crate) fn profile_flag(&self) -> Option<&str> {
        match &self.subcommand {
            AuditSubcommand::Verify(a) => a.profile.as_deref(),
            AuditSubcommand::Reanchor(a) => Some(a.profile.as_str()),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "test-only")]
    use super::*;

    #[test]
    fn a_held_writer_lock_carries_the_documented_code() {
        let err = audit_writer_error(&WriterError::FileLocked, "audit.reanchor_failed", "default");
        assert!(
            err.message().contains("audit.writer_locked"),
            "a held lock must name the code the docs and the skill key on: {}",
            err.message()
        );
        assert!(
            !err.message().contains("audit.reanchor_failed"),
            "the generic fallback must not mask it: {}",
            err.message()
        );
    }

    #[test]
    fn a_tip_anchor_mismatch_keeps_the_pre_flight_wire_code() {
        let err = audit_writer_error(
            &WriterError::TipAnchorMismatch {
                expected_count: 12,
                expected_offset: 3400,
                actual_len: 2600,
                reason: "test",
            },
            "audit.reanchor_failed",
            "acme",
        );
        assert_eq!(err.code(), "audit.tip_anchor_mismatch");
    }

    #[test]
    fn a_variant_with_its_own_code_does_not_get_a_second_one() {
        let err = audit_writer_error(
            &WriterError::RotationBridgeUnusable {
                archive_name: "audit.jsonl.20260913T120000000".to_owned(),
                reason: "test",
            },
            "audit.reanchor_failed",
            "default",
        );
        assert!(
            err.message().contains("audit.rotation_bridge_unusable"),
            "message: {}",
            err.message()
        );
        assert!(
            !err.message().contains("audit.reanchor_failed"),
            "two codes in one detail: {}",
            err.message()
        );
    }

    #[test]
    fn other_failures_carry_the_callers_fallback_code() {
        let err = audit_writer_error(
            &WriterError::TipAnchorUnavailable,
            "audit.writer_unavailable",
            "default",
        );
        assert!(
            err.message().contains("audit.writer_unavailable"),
            "message: {}",
            err.message()
        );
    }
}
