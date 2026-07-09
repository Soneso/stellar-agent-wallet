//! Bundle aggregate amount cap criterion.
//!
//! [`BundleAggregateCapCriterion`] enforces that the total amount transferred
//! across all [`crate::policy::v1::bundle::InnerOpDescriptor::TokenTransfer`]
//! inners in a multicall bundle does not exceed a configured maximum.
//!
//! The cap can be asset-specific (`asset = Some("USDC:G…")`) or cross-asset
//! (`asset = None`).  When cross-asset, all `TokenTransfer` inners contribute
//! to the sum regardless of their asset.
//!
//! # Generic-inner coupling
//!
//! This criterion sums only [`InnerOpDescriptor::TokenTransfer`] inners; a
//! [`InnerOpDescriptor::Generic`] inner contributes zero to the sum. A rule
//! carrying this criterion therefore implicitly enforces
//! [`crate::policy::v1::criteria::restrict_bundle_to_recognised_kinds::RestrictBundleToRecognisedKindsCriterion`]'s
//! Generic-rejection check at evaluation time
//! ([`crate::policy::v1::PolicyEngineV1::evaluate_bundle`]), independent of
//! whether that criterion is configured on the rule. This guarantees that a
//! bundle cannot bypass the cap by crafting an invocation whose ABI shape
//! decodes as `Generic` but whose on-chain effect is a token transfer.
//!
//! # Overflow safety
//!
//! The running sum uses `i128::checked_add`.  Overflow returns
//! [`crate::policy::PolicyError::CriterionEvaluationFailed`] rather than
//! panicking or silently wrapping.
//!
//! # TOML shape
//!
//! ```toml
//! # Asset-specific cap (USDC only):
//! { kind = "bundle_aggregate_cap", asset = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", max_amount = "50000000000" }
//!
//! # Cross-asset cap (all TokenTransfer inners):
//! { kind = "bundle_aggregate_cap", max_amount = "100000000000" }
//! ```
//!
//! `max_amount` is serialised as a decimal string because it is `i128` and TOML
//! integers are limited to i64 range.
//!
//! # Single-tx path
//!
//! When `ctx.bundle` is `None`, the criterion passes unconditionally.

use crate::policy::v1::EvalContext;
use crate::policy::v1::bundle::InnerOpDescriptor;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

/// Bundle aggregate amount cap criterion.
///
/// Sums `TokenTransfer.amount` across all matching inners.  Returns
/// [`DenyReason::BundleAggregateCapExceeded`] when the sum exceeds `max_amount`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::bundle_aggregate_cap::BundleAggregateCapCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let c = BundleAggregateCapCriterion {
///     asset: Some("USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN".into()),
///     max_amount: 100_000_000_000_i128,
/// };
/// assert_eq!(c.kind(), "bundle_aggregate_cap");
/// ```
#[derive(Debug)]
pub struct BundleAggregateCapCriterion {
    /// Asset filter.  `Some("CODE:GISSUER")` — only that asset contributes to
    /// the sum.  `None` — all `TokenTransfer` inners contribute (cross-asset).
    pub asset: Option<String>,
    /// Maximum aggregate transfer amount (`i128`; same scale as
    /// [`InnerOpDescriptor::TokenTransfer::amount`]).
    pub max_amount: i128,
}

impl Criterion for BundleAggregateCapCriterion {
    fn kind(&self) -> &'static str {
        "bundle_aggregate_cap"
    }

    /// Returns `true` — this criterion sums across all inners and must run once
    /// at bundle-level with the full bundle available.  It is skipped at
    /// per-inner evaluation; its `evaluate` already short-circuits with
    /// `Ok(None)` when `ctx.bundle` is `None`.
    fn is_bundle_level(&self) -> bool {
        true
    }

    /// Evaluates the bundle aggregate cap.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` — `ctx.bundle` is `None` (single-tx), or the sum of
    ///   matching `TokenTransfer` amounts does not exceed `max_amount`.
    /// - `Ok(Some(DenyReason::BundleAggregateCapExceeded { .. }))` — the sum
    ///   exceeds `max_amount`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] if the running `i128`
    /// sum overflows (checked_add overflow).
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let Some(view) = ctx.bundle else {
            // Single-tx path: criterion does not apply.
            return Ok(None);
        };

        let mut sum: Option<i128> = Some(0);
        for descriptor in view.inners {
            if let InnerOpDescriptor::TokenTransfer { asset, amount, .. } = descriptor {
                // Apply asset filter: if `self.asset` is Some("X"), skip inners
                // whose asset does not match.  None = cross-asset (match all).
                let matches_asset = self
                    .asset
                    .as_deref()
                    .is_none_or(|configured_asset| configured_asset == asset.as_str());

                if matches_asset {
                    sum = sum.and_then(|s| s.checked_add(*amount));
                }
            }
        }

        match sum {
            None => Err(PolicyError::CriterionEvaluationFailed {
                detail: "bundle_aggregate_cap: i128 sum overflow".into(),
            }),
            Some(s) if s > self.max_amount => Ok(Some(DenyReason::BundleAggregateCapExceeded {
                asset: self.asset.clone(),
                max: self.max_amount,
                sum: s,
            })),
            _ => Ok(None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    use super::*;
    use crate::policy::v1::bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor};
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::{DenyReason, McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    const USDC_ASSET: &str = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
    const EURC_ASSET: &str = "EURC:GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP";
    // Canonical valid ed25519 G-strkeys from envelope_decode.rs fixtures.
    const ADDR_FROM: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const ADDR_TO: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "stellar_multicall",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    fn token_transfer(asset: &str, amount: i128) -> InnerOpDescriptor {
        InnerOpDescriptor::TokenTransfer {
            asset: asset.to_owned(),
            from: ADDR_FROM.to_owned(),
            to: ADDR_TO.to_owned(),
            amount,
        }
    }

    fn make_ctx_with_bundle<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        args: &'a serde_json::Value,
        store: &'a PolicyStateStore,
        view: Option<&'a BundleView<'a>>,
    ) -> EvalContext<'a> {
        EvalContext {
            tool,
            args,
            profile_name: "alice",
            profile,
            value: crate::policy::v1::value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: store,
            bundle: view,
        }
    }

    /// Bundle with sum under cap passes.
    #[test]
    fn sum_under_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![
            token_transfer(USDC_ASSET, 30_000_000_000),
            token_transfer(USDC_ASSET, 20_000_000_000),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = BundleAggregateCapCriterion {
            asset: Some(USDC_ASSET.into()),
            max_amount: 100_000_000_000,
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "sum=50_000_000_000 vs cap=100_000_000_000 must pass"
        );
    }

    /// Bundle with sum exactly at cap passes (strict > boundary).
    #[test]
    fn sum_exactly_at_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![token_transfer(USDC_ASSET, 100_000_000_000)];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = BundleAggregateCapCriterion {
            asset: Some(USDC_ASSET.into()),
            max_amount: 100_000_000_000,
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "sum == max_amount must be allowed"
        );
    }

    /// Bundle with sum over cap denies.
    #[test]
    fn sum_over_cap_denies() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![
            token_transfer(USDC_ASSET, 60_000_000_000),
            token_transfer(USDC_ASSET, 60_000_000_000),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = BundleAggregateCapCriterion {
            asset: Some(USDC_ASSET.into()),
            max_amount: 100_000_000_000,
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::BundleAggregateCapExceeded { sum, .. }) if sum == 120_000_000_000),
            "sum=120_000_000_000 vs cap=100_000_000_000 must deny"
        );
    }

    /// Asset filter: different asset is not counted.
    #[test]
    fn asset_filter_excludes_other_assets() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![
            token_transfer(USDC_ASSET, 200_000_000_000), // way over cap
            token_transfer(EURC_ASSET, 1_000),           // different asset
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        // Cap configured only for EURC.
        let criterion = BundleAggregateCapCriterion {
            asset: Some(EURC_ASSET.into()),
            max_amount: 100_000_000_000,
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "USDC inners must not count toward EURC cap"
        );
    }

    /// Cross-asset cap (None) sums all TokenTransfer inners.
    #[test]
    fn cross_asset_cap_sums_all_transfer_inners() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![
            token_transfer(USDC_ASSET, 60_000_000_000),
            token_transfer(EURC_ASSET, 60_000_000_000),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = BundleAggregateCapCriterion {
            asset: None, // cross-asset
            max_amount: 100_000_000_000,
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::BundleAggregateCapExceeded { asset: None, .. })
            ),
            "cross-asset sum=120_000_000_000 must deny"
        );
    }

    /// Single-tx path (bundle=None) passes unconditionally.
    #[test]
    fn single_tx_bundle_none_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let criterion = BundleAggregateCapCriterion {
            asset: None,
            max_amount: 0, // cap=0 — would deny any real bundle
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, None);
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "bundle=None must always pass"
        );
    }

    /// Generic inners are not counted toward the cap.
    #[test]
    fn generic_inners_not_counted() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![InnerOpDescriptor::Generic {
            target: "CSTRKEY".into(),
            fn_name: "unknown".into(),
        }];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = BundleAggregateCapCriterion {
            asset: None,
            max_amount: 0, // would deny if Generic counted
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        assert!(
            criterion.evaluate(&ctx).unwrap().is_none(),
            "Generic inners must not be counted toward aggregate cap"
        );
    }

    /// i128 overflow in sum returns CriterionEvaluationFailed.
    #[test]
    fn i128_overflow_returns_criterion_evaluation_failed() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let args = serde_json::Value::Null;
        let inners = vec![
            token_transfer(USDC_ASSET, i128::MAX),
            token_transfer(USDC_ASSET, 1),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let criterion = BundleAggregateCapCriterion {
            asset: Some(USDC_ASSET.into()),
            max_amount: i128::MAX,
        };

        let ctx = make_ctx_with_bundle(&tool, &profile, &args, &store, Some(&view));
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { ref detail }) if detail.contains("overflow")),
            "i128 overflow must return CriterionEvaluationFailed, got {result:?}"
        );
    }
}
