//! Shared helpers for the `approve` subcommand group.

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::error::{InternalError, WalletError};

/// Maps an [`ApprovalError`] from opening the pending-approval store onto a
/// [`WalletError`] carrying a distinct `approval.*` detail code per failure
/// class.
///
/// Shared by every `approve` subcommand (`--id`, `gc`, `list`, `serve`) that
/// opens the store via `open_with_retry`, so the store-open failure mapping
/// lives in one place instead of being copied per command.
pub(super) fn approval_store_open_error(e: &ApprovalError) -> WalletError {
    let code = match e {
        ApprovalError::Permission { .. } => "approval.permission_denied",
        ApprovalError::InvalidNonceLength { .. } => "approval.invalid_nonce_length",
        ApprovalError::WriterLocked => "approval.writer_locked",
        _ => "approval.store_open_failed",
    };
    WalletError::Internal(InternalError::UnexpectedState {
        detail: format!("{code}: {e}"),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;

    #[test]
    fn permission_error_uses_distinct_code() {
        let err = approval_store_open_error(&ApprovalError::Permission {
            detail: "approval dir mode is too permissive".to_owned(),
        });
        assert!(err.message().contains("approval.permission_denied"));
    }

    #[test]
    fn invalid_nonce_length_error_uses_distinct_code() {
        let err = approval_store_open_error(&ApprovalError::InvalidNonceLength {
            expected: 22,
            actual: 10,
        });
        assert!(err.message().contains("approval.invalid_nonce_length"));
    }

    #[test]
    fn writer_locked_error_uses_distinct_code() {
        let err = approval_store_open_error(&ApprovalError::WriterLocked);
        assert!(err.message().contains("approval.writer_locked"));
    }

    #[test]
    fn other_errors_use_generic_code() {
        let err = approval_store_open_error(&ApprovalError::NotFound);
        assert!(err.message().contains("approval.store_open_failed"));
    }
}
