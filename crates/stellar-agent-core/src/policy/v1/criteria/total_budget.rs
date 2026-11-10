//! Non-renewing total budget criterion.
//!
//! [`TotalBudgetCriterion`] bounds the debits of one asset over the whole life
//! of a signed policy:
//!
//! ```toml
//! { kind = "total_budget", asset = "native", max_stroops = "200000000" }
//! ```
//!
//! The allocation never renews with time. Its epoch is the digest of the
//! signed policy ([`EvalContext::policy_digest`]): entries count against the
//! policy that sized them, regardless of their age, and a re-signed policy
//! starts another allocation at zero. The criterion is accepted in version 2
//! documents and on `allow` rules only.
//!
//! An engine built outside the verified loader carries an all-zero digest.
//! Every evaluation, sizing, and recording under a rule with this criterion
//! then fails with [`PolicyError::CriterionEvaluationFailed`], so no
//! allocation accrues under an unidentified epoch.

use crate::policy::v1::EvalContext;
use crate::policy::v1::asset_equivalence::assets_equivalent;
use crate::policy::v1::bundle::{BundleStateOverlay, InnerOpDescriptor};
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::criteria::per_period_cap::system_time_to_ms;
use crate::policy::v1::criteria::per_tx_cap::{AssetDebitSum, asset_debit_sum};
use crate::policy::v1::criteria::state_store::{StateKey, WindowEntry, WindowLimit};
use crate::policy::v1::value::{ValueClass, asset_normalise};
use crate::policy::{DenyReason, PolicyError};

/// Refuses a call that would exceed the policy's total allocation of an asset.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::Criterion;
/// use stellar_agent_core::policy::v1::criteria::total_budget::TotalBudgetCriterion;
///
/// let criterion = TotalBudgetCriterion::new("native".into(), 200_000_000);
/// assert_eq!(criterion.kind(), "total_budget");
/// assert_eq!(criterion.max_stroops(), 200_000_000);
/// ```
#[derive(Debug, Clone)]
pub struct TotalBudgetCriterion {
    asset: String,
    max_stroops: i128,
}

impl TotalBudgetCriterion {
    /// Constructs a total allocation of `max_stroops` in `asset`.
    #[must_use]
    pub fn new(asset: String, max_stroops: i128) -> Self {
        Self { asset, max_stroops }
    }

    /// Returns the configured asset identifier.
    #[must_use]
    pub fn asset(&self) -> &str {
        &self.asset
    }

    /// Returns the total allocation in stroops.
    #[must_use]
    pub fn max_stroops(&self) -> i128 {
        self.max_stroops
    }

    /// The bucket of this asset's allocation. Its window is zero: the bucket
    /// never ages out.
    fn state_key(&self, profile_name: &str) -> StateKey {
        StateKey::new(
            profile_name,
            1,
            &format!("total:{}", asset_normalise(&self.asset)),
            0,
        )
    }

    fn window_limit(&self) -> WindowLimit {
        WindowLimit::Total {
            asset: self.asset.clone(),
            max_stroops: self.max_stroops,
        }
    }
}

/// Returns the policy digest of `ctx`, refusing an all-zero digest.
fn epoch(ctx: &EvalContext<'_>) -> Result<[u8; 32], PolicyError> {
    if ctx.policy_digest == [0; 32] {
        return Err(PolicyError::CriterionEvaluationFailed {
            detail: "total_budget requires a verified policy digest".to_owned(),
        });
    }
    Ok(ctx.policy_digest)
}

impl Criterion for TotalBudgetCriterion {
    fn kind(&self) -> &'static str {
        "total_budget"
    }

    fn windowed(&self) -> bool {
        true
    }

    fn records_bundle_inners(&self) -> bool {
        true
    }

    /// Refuses with [`DenyReason::TotalBudgetExhausted`] when the call's debit
    /// in the configured asset, added to the allocation already used in this
    /// policy's epoch and to the earlier inners of a bundle, exceeds
    /// `max_stroops`. Equality passes.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] for an all-zero
    /// policy digest, whatever the call, an unresolvable debit, or a
    /// state-store failure.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let epoch = epoch(ctx)?;
        let attempted = match asset_debit_sum(ctx, &self.asset, self.kind())? {
            AssetDebitSum::NotApplicable => return Ok(None),
            AssetDebitSum::Deny(reason) => return Ok(Some(reason)),
            AssetDebitSum::Amount(sum) => sum,
        };
        let state_key = self.state_key(ctx.profile_name);
        let (recorded, _) = ctx
            .state_store
            .query_epoch(&state_key, epoch)
            .map_err(|e| PolicyError::CriterionEvaluationFailed {
                detail: format!("total_budget: state store error: {e}"),
            })?;
        let used = recorded.saturating_add(
            ctx.bundle
                .map(|view| view.overlay.get(&state_key))
                .unwrap_or(0),
        );
        if used.saturating_add(attempted) > self.max_stroops {
            return Ok(Some(DenyReason::TotalBudgetExhausted {
                asset: self.asset.clone(),
                max_stroops: self.max_stroops,
                remaining_stroops: self.max_stroops.saturating_sub(used).max(0),
            }));
        }
        Ok(None)
    }

    /// Accumulates an inner transfer in the configured asset into the bundle
    /// overlay, under the key the evaluation reads.
    fn accumulate_overlay(
        &self,
        ctx: &EvalContext<'_>,
        inner: &InnerOpDescriptor,
        overlay: &mut BundleStateOverlay,
    ) {
        let InnerOpDescriptor::TokenTransfer { asset, amount, .. } = inner else {
            return;
        };
        if !assets_equivalent(
            &asset_normalise(asset),
            &asset_normalise(&self.asset),
            &ctx.profile.network_passphrase,
        ) {
            return;
        }
        overlay.accumulate(self.state_key(ctx.profile_name), *amount);
    }

    /// Records the confirmed debit against this policy's epoch.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] under an all-zero
    /// policy digest, whatever the call, or on a clock or state-store failure.
    fn record_confirmed(&self, ctx: &EvalContext<'_>) -> Result<Vec<WindowEntry>, PolicyError> {
        let epoch = epoch(ctx)?;
        let now_ms = system_time_to_ms()?;
        let entry = self.size(ctx, now_ms)?;
        if let Some(entry) = &entry {
            ctx.state_store
                .append_epoch(entry.key(), entry.timestamp_ms(), entry.amount(), epoch)
                .map_err(|error| PolicyError::CriterionEvaluationFailed {
                    detail: format!("total_budget: record_confirmed state store error: {error}"),
                })?;
        }
        Ok(entry.into_iter().collect())
    }

    /// Sizes the call's debit in the configured asset as an entry whose epoch
    /// is the policy digest.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] under an all-zero
    /// policy digest, whatever the call.
    fn size(&self, ctx: &EvalContext<'_>, now_ms: u64) -> Result<Option<WindowEntry>, PolicyError> {
        let epoch = epoch(ctx)?;
        let ValueClass::Value(effects) = &ctx.value else {
            return Ok(None);
        };
        let criterion_asset = asset_normalise(&self.asset);
        let mut matched = false;
        let mut sum: i128 = 0;
        for leg in effects.legs() {
            if !leg.kind.carries_debit() {
                continue;
            }
            let Some(leg_asset) = leg.asset.as_deref() else {
                continue;
            };
            if !assets_equivalent(leg_asset, &criterion_asset, &ctx.profile.network_passphrase) {
                continue;
            }
            let Some(amount) = leg.amount else {
                continue;
            };
            matched = true;
            sum = sum.saturating_add(amount);
        }
        if !matched {
            return Ok(None);
        }
        Ok(Some(
            WindowEntry::new(
                self.state_key(ctx.profile_name),
                now_ms,
                sum,
                self.window_limit(),
            )
            .with_epoch(Some(epoch)),
        ))
    }
}
