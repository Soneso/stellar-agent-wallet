//! Observed operating-balance floor criterion.
//!
//! [`BalanceFloorCriterion`] refuses a call that would leave the operating
//! account's native balance below an absolute floor:
//!
//! ```toml
//! { kind = "balance_floor", min_stroops = "20000000" }
//! ```
//!
//! # Logic
//!
//! ```text
//! after = balance - effective_reservations - (native_debit + fee)
//! if after < min_stroops → DenyReason::AccountFloorRefused
//! ```
//!
//! The balance comes from a live account read the caller supplies as an
//! [`crate::policy::v1::FloorInput`]: the observed account and the native
//! reservations of the profile's open authorizations. A missing view,
//! observation, reservation sum, or balance refuses with
//! [`DenyReason::AccountUnread`]; an observation older than 120 seconds
//! refuses with [`DenyReason::AccountStale`]. The debit and the fee are
//! resolved as `minimum_reserve` resolves them.
//!
//! `minimum_reserve` adds a margin to the protocol reserve; this floor is
//! absolute. A provisional evaluation skips the check, and the strict
//! evaluation before signing applies it.

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::criteria::minimum_reserve::{
    AmountOutcome, extract_amount_stroops, extract_total_fee_stroops,
};
use crate::policy::v1::value::{ValueGate, classify_value};
use crate::policy::{DenyReason, PolicyError};

/// The oldest account observation the floor admits, in milliseconds.
pub const MAX_OBSERVATION_AGE_MS: u64 = 120_000;

/// Refuses a call that would leave the observed operating balance below a
/// signed floor.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::Criterion;
/// use stellar_agent_core::policy::v1::criteria::balance_floor::BalanceFloorCriterion;
///
/// let criterion = BalanceFloorCriterion::new(20_000_000);
/// assert_eq!(criterion.kind(), "balance_floor");
/// assert_eq!(criterion.min_stroops(), 20_000_000);
/// ```
#[derive(Debug, Clone)]
pub struct BalanceFloorCriterion {
    min_stroops: i128,
}

impl BalanceFloorCriterion {
    /// Constructs a floor of `min_stroops` native stroops.
    #[must_use]
    pub fn new(min_stroops: i128) -> Self {
        Self { min_stroops }
    }

    /// Returns the floor in stroops.
    #[must_use]
    pub fn min_stroops(&self) -> i128 {
        self.min_stroops
    }
}

impl Criterion for BalanceFloorCriterion {
    fn kind(&self) -> &'static str {
        "balance_floor"
    }

    /// Checks the observed balance after reservations, the native debit, and
    /// the fee against the floor. Equality passes.
    ///
    /// Returns `Ok(None)` without reading the account when the evaluation is
    /// provisional.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when a native debit
    /// leg carries no resolvable amount. The observation's age is measured at
    /// the evaluation instant `ctx.now_ms`.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        if ctx.provisional {
            return Ok(None);
        }
        if let ValueGate::Deny(reason) = classify_value(ctx) {
            return Ok(Some(reason));
        }
        let Some(view) = ctx.account_view else {
            return Ok(Some(DenyReason::AccountUnread));
        };
        let Some(observation) = view.observation() else {
            return Ok(Some(DenyReason::AccountUnread));
        };
        let Some(reservations) = view.effective_native_reservations_stroops() else {
            return Ok(Some(DenyReason::AccountUnread));
        };
        let Ok(balance) = view.balance_stroops() else {
            return Ok(Some(DenyReason::AccountUnread));
        };

        let age_ms = ctx.now_ms.saturating_sub(observation.observed_at_ms);
        if age_ms > MAX_OBSERVATION_AGE_MS {
            return Ok(Some(DenyReason::AccountStale { age_ms }));
        }

        let debit = match extract_amount_stroops(ctx)? {
            AmountOutcome::Debit(amount) => amount,
            AmountOutcome::Deny(reason) => return Ok(Some(reason)),
        };
        let fee = i128::from(extract_total_fee_stroops(ctx));
        let balance_after_stroops = i128::from(balance)
            .saturating_sub(i128::from(reservations))
            .saturating_sub(debit.saturating_add(fee));
        if balance_after_stroops < self.min_stroops {
            return Ok(Some(DenyReason::AccountFloorRefused {
                min_stroops: self.min_stroops,
                balance_after_stroops,
            }));
        }
        Ok(None)
    }
}
