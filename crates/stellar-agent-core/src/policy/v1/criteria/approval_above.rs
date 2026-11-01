//! Per-transaction approval threshold in stroops for one asset.
//!
//! ```toml
//! { kind = "approval_above", asset = "native", max_stroops = 500_0000000 }
//! ```
//!
//! The loader accepts this criterion only on `allow` rules, with a positive
//! threshold below every `per_tx_cap` on the same asset in that rule.

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::criteria::per_tx_cap::{AssetDebitSum, asset_debit_sum};
use crate::policy::v1::loader::DEFAULT_APPROVAL_TTL_SECONDS;
use crate::policy::{ApprovalRequest, Decision, DenyReason, PolicyError};

/// Requests approval when a call exceeds the configured asset threshold.
///
/// Amount extraction and fail-closed value checks are shared with
/// [`super::PerTxCapCriterion`]. An amount equal to the threshold passes.
#[derive(Debug, Clone)]
pub struct ApprovalAboveCriterion {
    pub(in crate::policy::v1) asset: String,
    pub(in crate::policy::v1) max_stroops: i128,
}

impl ApprovalAboveCriterion {
    /// Constructs an approval threshold in the same units as `per_tx_cap`.
    ///
    /// `asset` is `"native"` for XLM or `"CODE:Gissuer"` for a credit asset.
    /// The policy loader validates that `max_stroops` is positive.
    #[must_use]
    pub fn new(asset: String, max_stroops: i128) -> Self {
        Self { asset, max_stroops }
    }
}

impl Criterion for ApprovalAboveCriterion {
    fn kind(&self) -> &'static str {
        "approval_above"
    }

    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let sum = match asset_debit_sum(ctx, &self.asset, self.kind())? {
            AssetDebitSum::NotApplicable => return Ok(None),
            AssetDebitSum::Deny(reason) => return Ok(Some(reason)),
            AssetDebitSum::Amount(sum) => sum,
        };
        Ok(
            (sum > self.max_stroops).then(|| DenyReason::ApprovalAboveExceeded {
                asset: self.asset.clone(),
                max_stroops: self.max_stroops,
                attempted_stroops: sum,
            }),
        )
    }

    fn evaluate_decision(&self, ctx: &EvalContext<'_>) -> Result<Decision, PolicyError> {
        Ok(match self.evaluate(ctx)? {
            None => Decision::Allow,
            Some(DenyReason::ApprovalAboveExceeded {
                asset,
                max_stroops,
                attempted_stroops,
            }) => Decision::RequireApproval(
                ApprovalRequest::new(String::new(), DEFAULT_APPROVAL_TTL_SECONDS).with_reason(
                    format!(
                        "approval_above: {attempted_stroops} stroops of {asset} exceeds threshold {max_stroops} stroops"
                    ),
                ),
            ),
            Some(reason) => Decision::Deny(reason),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test assertions")]

    use super::*;
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::v1::value::derive_value_class;
    use crate::policy::{McpToolRegistration, ToolDescriptor, ToolValueKind};
    use crate::profile::schema::Profile;

    #[test]
    fn deny_only_threshold_and_decision_escalation_agree() {
        let criterion = ApprovalAboveCriterion::new("native".into(), 100);
        let tool = ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_pay",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: ToolValueKind::MovesValue,
        });
        let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
        let store = PolicyStateStore::new();
        for amount in [25, 100, 150] {
            let args = serde_json::json!({"asset": "native", "amount_stroops": amount.to_string()});
            let ctx = EvalContext {
                tool: &tool,
                args: &args,
                profile_name: "alice",
                profile: &profile,
                value: derive_value_class(&tool.name, &args),
                account_view: None,
                identity_view: None,
                quorum: None,
                counterparty_cache: None,
                sep10_sessions: None,
                sep45_sessions: None,
                state_store: &store,
                bundle: None,
            };
            if amount <= 100 {
                assert_eq!(criterion.evaluate(&ctx).unwrap(), None);
                assert_eq!(criterion.evaluate_decision(&ctx).unwrap(), Decision::Allow);
            } else {
                let reason = DenyReason::ApprovalAboveExceeded {
                    asset: "native".into(),
                    max_stroops: 100,
                    attempted_stroops: amount,
                };
                assert_eq!(criterion.evaluate(&ctx).unwrap(), Some(reason.clone()));
                assert_eq!(reason.code(), "approval_above_exceeded");
                assert_eq!(
                    criterion.evaluate_decision(&ctx).unwrap(),
                    Decision::RequireApproval(
                        ApprovalRequest::new(String::new(), DEFAULT_APPROVAL_TTL_SECONDS)
                            .with_reason(
                            "approval_above: 150 stroops of native exceeds threshold 100 stroops"
                                .into()
                        )
                    )
                );
            }
        }
    }
}
