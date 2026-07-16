//! Stable, redacted MPP errors.

use thiserror::Error;

/// Stable MPP error code used by CLI and MCP adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MppErrorCode {
    /// An input exceeded a named bound.
    InputTooLarge,
    /// A challenge was malformed.
    ChallengeInvalid,
    /// More than one supported challenge remained after selection.
    ChallengeAmbiguous,
    /// A challenge was expired or too close to expiry.
    ChallengeExpired,
    /// A challenge did not bind to its request context.
    ChallengeMismatch,
    /// The payment method is unsupported.
    UnsupportedMethod,
    /// The payment intent is unsupported.
    UnsupportedIntent,
    /// The requested payment mode is unsupported.
    UnsupportedMode,
    /// The selected network is forbidden.
    NetworkForbidden,
    /// Approval is required before authorization.
    ApprovalRequired,
    /// Approval was invalid or expired.
    ApprovalInvalid,
    /// This authorization has already been consumed.
    AuthorizationReplayed,
    /// Authorization outcome cannot safely be retried.
    AuthorizationIndeterminate,
    /// Durable authorization state was unavailable.
    StateUnavailable,
    /// Transaction simulation failed validation.
    SimulationFailed,
    /// Authorization signing failed.
    SigningFailed,
    /// The constructed credential exceeded its bound.
    CredentialTooLarge,
    /// A receipt was malformed.
    ReceiptInvalid,
    /// A receipt contradicted a previously recorded receipt.
    ReceiptConflict,
    /// Ledger reconciliation could not establish an outcome.
    ReconciliationUnavailable,
}

impl MppErrorCode {
    /// Returns the stable dotted wire code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputTooLarge => "mpp.input_too_large",
            Self::ChallengeInvalid => "mpp.challenge_invalid",
            Self::ChallengeAmbiguous => "mpp.challenge_ambiguous",
            Self::ChallengeExpired => "mpp.challenge_expired",
            Self::ChallengeMismatch => "mpp.challenge_mismatch",
            Self::UnsupportedMethod => "mpp.unsupported_method",
            Self::UnsupportedIntent => "mpp.unsupported_intent",
            Self::UnsupportedMode => "mpp.unsupported_mode",
            Self::NetworkForbidden => "mpp.network_forbidden",
            Self::ApprovalRequired => "mpp.approval_required",
            Self::ApprovalInvalid => "mpp.approval_invalid",
            Self::AuthorizationReplayed => "mpp.authorization_replayed",
            Self::AuthorizationIndeterminate => "mpp.authorization_indeterminate",
            Self::StateUnavailable => "mpp.state_unavailable",
            Self::SimulationFailed => "mpp.simulation_failed",
            Self::SigningFailed => "mpp.signing_failed",
            Self::CredentialTooLarge => "mpp.credential_too_large",
            Self::ReceiptInvalid => "mpp.receipt_invalid",
            Self::ReceiptConflict => "mpp.receipt_conflict",
            Self::ReconciliationUnavailable => "mpp.reconciliation_unavailable",
        }
    }
}

/// Bounded error returned by the MPP library.
#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct MppError {
    code: &'static str,
    message: &'static str,
}

impl MppError {
    /// Creates a redacted error from a stable code and static message.
    #[must_use]
    pub const fn new(code: MppErrorCode, message: &'static str) -> Self {
        Self {
            code: code.as_str(),
            message,
        }
    }

    /// Returns the stable dotted wire code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the bounded, redacted diagnostic.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_code_has_a_stable_mpp_wire_name() {
        let cases = [
            (MppErrorCode::InputTooLarge, "mpp.input_too_large"),
            (MppErrorCode::ChallengeInvalid, "mpp.challenge_invalid"),
            (MppErrorCode::ChallengeAmbiguous, "mpp.challenge_ambiguous"),
            (MppErrorCode::ChallengeExpired, "mpp.challenge_expired"),
            (MppErrorCode::ChallengeMismatch, "mpp.challenge_mismatch"),
            (MppErrorCode::UnsupportedMethod, "mpp.unsupported_method"),
            (MppErrorCode::UnsupportedIntent, "mpp.unsupported_intent"),
            (MppErrorCode::UnsupportedMode, "mpp.unsupported_mode"),
            (MppErrorCode::NetworkForbidden, "mpp.network_forbidden"),
            (MppErrorCode::ApprovalRequired, "mpp.approval_required"),
            (MppErrorCode::ApprovalInvalid, "mpp.approval_invalid"),
            (
                MppErrorCode::AuthorizationReplayed,
                "mpp.authorization_replayed",
            ),
            (
                MppErrorCode::AuthorizationIndeterminate,
                "mpp.authorization_indeterminate",
            ),
            (MppErrorCode::StateUnavailable, "mpp.state_unavailable"),
            (MppErrorCode::SimulationFailed, "mpp.simulation_failed"),
            (MppErrorCode::SigningFailed, "mpp.signing_failed"),
            (MppErrorCode::CredentialTooLarge, "mpp.credential_too_large"),
            (MppErrorCode::ReceiptInvalid, "mpp.receipt_invalid"),
            (MppErrorCode::ReceiptConflict, "mpp.receipt_conflict"),
            (
                MppErrorCode::ReconciliationUnavailable,
                "mpp.reconciliation_unavailable",
            ),
        ];
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
        }
        let error = MppError::new(MppErrorCode::SigningFailed, "redacted");
        assert_eq!(error.code(), "mpp.signing_failed");
        assert_eq!(error.message(), "redacted");
        assert_eq!(error.to_string(), "mpp.signing_failed: redacted");
    }
}
