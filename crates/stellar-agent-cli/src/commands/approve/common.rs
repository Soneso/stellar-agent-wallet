//! Shared helpers for the `approve` subcommand group.

use std::path::PathBuf;

use stellar_agent_core::approval::error::ApprovalError;
use stellar_agent_core::error::{ApprovalFailure, WalletError};
use stellar_agent_core::profile::schema::default_approval_dir;

/// Resolves the approval directory or returns its approval-specific refusal.
pub(super) fn approval_store_dir() -> Result<PathBuf, WalletError> {
    default_approval_dir().map_err(|_| {
        WalletError::Approval(ApprovalFailure::StoreDirError {
            detail: "could not determine approval store directory".to_owned(),
        })
    })
}

/// Maps an [`ApprovalError`] from opening the pending-approval store onto a
/// [`WalletError::Approval`] carrying a distinct wire code per failure class.
///
/// The `approve`, `approve gc`, and `approve list` paths
/// share this mapping for store-open failures from `open_with_retry`.
pub(super) fn approval_store_open_error(e: &ApprovalError) -> WalletError {
    let detail = e.to_string();
    WalletError::Approval(match e {
        ApprovalError::Permission { .. } => ApprovalFailure::PermissionDenied { detail },
        ApprovalError::InvalidNonceLength { .. } => ApprovalFailure::InvalidNonceLength { detail },
        ApprovalError::WriterLocked => ApprovalFailure::WriterLocked {
            detail: "approval store is locked by another writer".to_owned(),
        },
        _ => ApprovalFailure::StoreOpenFailed { detail },
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
        assert_eq!(err.code(), "approval.permission_denied");
    }

    #[test]
    fn invalid_nonce_length_error_uses_distinct_code() {
        let err = approval_store_open_error(&ApprovalError::InvalidNonceLength {
            expected: 22,
            actual: 10,
        });
        assert_eq!(err.code(), "approval.invalid_nonce_length");
    }

    #[test]
    fn writer_locked_error_uses_distinct_code() {
        let err = approval_store_open_error(&ApprovalError::WriterLocked);
        assert_eq!(err.code(), "approval.writer_locked");
        assert_eq!(err.message(), "approval store is locked by another writer");
    }

    #[test]
    fn other_errors_use_generic_code() {
        let err = approval_store_open_error(&ApprovalError::NotFound);
        assert_eq!(err.code(), "approval.store_open_failed");
    }
}
