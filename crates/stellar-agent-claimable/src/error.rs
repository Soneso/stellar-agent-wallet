//! Claimable-balance error type.
//!
//! All public-facing errors from this crate are expressed as [`ClaimError`]
//! variants. Underlying network, XDR-decode, and address/asset validation
//! failures propagate from [`stellar_agent_core::error::WalletError`] via the
//! [`ClaimError::Wallet`] variant.

use thiserror::Error;

/// Errors produced while normalizing, fetching, or evaluating claimable
/// balances.
///
/// `#[non_exhaustive]` because new error cases may be added as the claim
/// verb's guard surface evolves.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClaimError {
    /// The supplied balance-id string could not be normalized to a 32-byte
    /// claimable-balance hash.
    ///
    /// Returned by [`crate::id::BalanceId::parse`] when the input is not a
    /// valid `B...` strkey, canonical 72-hex id (with the `00000000` V0
    /// discriminant prefix), or bare 64-hex hash.
    #[error("claim.invalid_balance_id: {detail}")]
    InvalidBalanceId {
        /// Human-readable reason. Never echoes secret material — the
        /// balance id is public information, but the message describes the
        /// rejection reason abstractly rather than echoing the raw input.
        detail: String,
    },

    /// No `ClaimableBalanceEntry` exists on-ledger for the given id.
    #[error(
        "claim.balance_not_found: no claimable balance exists for this id; \
         it may already have been claimed, or the id may be incorrect"
    )]
    BalanceNotFound,

    /// The queried account does not appear as a claimant on the entry.
    #[error("claim.not_claimant: {account} does not appear as a claimant on this balance")]
    NotClaimant {
        /// The account G-strkey that was checked.
        account: String,
    },

    /// The matched claimant's predicate does not currently evaluate to
    /// satisfied.
    #[error("claim.predicate_not_satisfied: {hint}")]
    PredicateNotSatisfied {
        /// Human-readable description of the claimability window, e.g.
        /// `"claimable once unix time reaches 1750000000"`
        /// or `"this balance is not currently claimable"` when no window
        /// bound is exactly derivable.
        hint: String,
    },

    /// The matched claimant's predicate uses a form the evaluator refuses to
    /// evaluate: `BeforeRelativeTime` (out-of-protocol-contract for a stored
    /// entry — stellar-core normalizes relative predicates to absolute ones
    /// at entry-creation time per CAP-23), `Not` with no inner predicate,
    /// an `And`/`Or` with fewer than 2 sub-predicates, or nesting beyond the
    /// evaluator's explicit recursion bound.
    #[error("claim.predicate_unsupported: {detail}")]
    PredicateUnsupported {
        /// Human-readable reason the predicate was refused.
        detail: String,
    },

    /// The claiming account has no trustline for the balance's non-native
    /// asset.
    #[error(
        "claim.trustline_missing: no trustline for {code}:{issuer}; run the trustline verb first"
    )]
    TrustlineMissing {
        /// The asset code.
        code: String,
        /// The asset issuer G-strkey.
        issuer: String,
    },

    /// A trustline exists but the issuer has not authorized it (covers
    /// `AUTH_REQUIRED` assets whose trustline is unauthorized or
    /// authorized-to-maintain-liabilities-only).
    #[error(
        "claim.trustline_not_authorized: the issuer has not authorized this account to hold {code}:{issuer}"
    )]
    TrustlineNotAuthorized {
        /// The asset code.
        code: String,
        /// The asset issuer G-strkey.
        issuer: String,
    },

    /// Claiming the balance would exceed the trustline's limit.
    #[error(
        "claim.trustline_limit: claiming {amount_stroops} stroops of {code}:{issuer} would exceed \
         the trustline limit ({headroom_stroops} stroops of headroom remain)"
    )]
    TrustlineLimit {
        /// The asset code.
        code: String,
        /// The asset issuer G-strkey.
        issuer: String,
        /// The amount that would be claimed, in stroops.
        amount_stroops: i64,
        /// The remaining headroom (`limit - balance`) on the trustline, in
        /// stroops. May be negative if the existing balance already exceeds
        /// the limit (should not occur on a valid trustline, but reported
        /// as-is for diagnostics).
        headroom_stroops: i64,
    },

    /// An underlying network, XDR-decode, or address/asset validation error
    /// propagated from `stellar-agent-network` / `stellar-agent-core`.
    #[error("claim.wallet_error: {0}")]
    Wallet(#[from] stellar_agent_core::error::WalletError),
}

impl ClaimError {
    /// Returns the stable wire error code for this error.
    ///
    /// Codes follow the `claim.*` family. The [`ClaimError::Wallet`]
    /// passthrough variant delegates to the wrapped
    /// [`stellar_agent_core::error::WalletError::code`], preserving that
    /// error's own `network.*` / `protocol.*` / `validation.*` code.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_claimable::error::ClaimError;
    ///
    /// let err = ClaimError::BalanceNotFound;
    /// assert_eq!(err.code(), "claim.balance_not_found");
    /// ```
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidBalanceId { .. } => "claim.invalid_balance_id",
            Self::BalanceNotFound => "claim.balance_not_found",
            Self::NotClaimant { .. } => "claim.not_claimant",
            Self::PredicateNotSatisfied { .. } => "claim.predicate_not_satisfied",
            Self::PredicateUnsupported { .. } => "claim.predicate_unsupported",
            Self::TrustlineMissing { .. } => "claim.trustline_missing",
            Self::TrustlineNotAuthorized { .. } => "claim.trustline_not_authorized",
            Self::TrustlineLimit { .. } => "claim.trustline_limit",
            Self::Wallet(e) => e.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use stellar_agent_core::error::{NetworkError, WalletError};

    use super::*;

    #[test]
    fn code_covers_every_direct_variant() {
        assert_eq!(
            ClaimError::InvalidBalanceId {
                detail: "x".to_owned()
            }
            .code(),
            "claim.invalid_balance_id"
        );
        assert_eq!(
            ClaimError::BalanceNotFound.code(),
            "claim.balance_not_found"
        );
        assert_eq!(
            ClaimError::NotClaimant {
                account: "GABC".to_owned()
            }
            .code(),
            "claim.not_claimant"
        );
        assert_eq!(
            ClaimError::PredicateNotSatisfied {
                hint: "x".to_owned()
            }
            .code(),
            "claim.predicate_not_satisfied"
        );
        assert_eq!(
            ClaimError::PredicateUnsupported {
                detail: "x".to_owned()
            }
            .code(),
            "claim.predicate_unsupported"
        );
        assert_eq!(
            ClaimError::TrustlineMissing {
                code: "USDC".to_owned(),
                issuer: "GABC".to_owned()
            }
            .code(),
            "claim.trustline_missing"
        );
        assert_eq!(
            ClaimError::TrustlineNotAuthorized {
                code: "USDC".to_owned(),
                issuer: "GABC".to_owned()
            }
            .code(),
            "claim.trustline_not_authorized"
        );
        assert_eq!(
            ClaimError::TrustlineLimit {
                code: "USDC".to_owned(),
                issuer: "GABC".to_owned(),
                amount_stroops: 100,
                headroom_stroops: 50,
            }
            .code(),
            "claim.trustline_limit"
        );
    }

    #[test]
    fn wallet_passthrough_delegates_code() {
        let err = ClaimError::from(WalletError::Network(NetworkError::AccountNotFound {
            account_id: "GABC".to_owned(),
        }));
        assert_eq!(err.code(), "network.account_not_found");
    }

    #[test]
    fn display_messages_are_prefixed_with_code() {
        let err = ClaimError::BalanceNotFound;
        assert!(format!("{err}").starts_with("claim.balance_not_found"));
    }
}
