//! Bundle-aware per-transaction amount cap criterion.
//!
//! `BundlePerTxCapCriterion` enforces that each individual `TokenTransfer`
//! inner within a multicall bundle does not exceed a configured maximum in
//! stroops for a given asset.
//!
//! This criterion is **bundle-level** (`is_bundle_level() = true`): it runs once
//! with the full `BundleView` available and inspects all `TokenTransfer` inners
//! in the bundle.
//!
//! # Why a separate criterion variant instead of extending `PerTxCapCriterion`
//!
//! Additive new variant: existing `per_tx_cap` rules against `stellar_pay` are
//! unaffected.  Operators who want per-inner caps under multicall explicitly
//! install `bundle_per_tx_cap`.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "bundle_per_tx_cap", asset = "native", max_stroops = 1_000_000_000 }
//! ```
//!
//! # Generic-inner coupling
//!
//! This criterion inspects only [`InnerOpDescriptor::TokenTransfer`] inners; a
//! [`InnerOpDescriptor::Generic`] inner is not checked against the cap. A rule
//! carrying this criterion therefore implicitly enforces
//! [`crate::policy::v1::criteria::restrict_bundle_to_recognised_kinds::RestrictBundleToRecognisedKindsCriterion`]'s
//! Generic-rejection check at evaluation time
//! ([`crate::policy::v1::PolicyEngineV1::evaluate_bundle`]), independent of
//! whether that criterion is configured on the rule, so a bundle cannot bypass
//! the cap with an invocation whose ABI shape decodes as `Generic` but whose
//! on-chain effect is a token transfer.
//!
//! # Single-tx path
//!
//! When `ctx.bundle` is `None`, the criterion passes unconditionally.

use crate::policy::v1::EvalContext;
use crate::policy::v1::bundle::InnerOpDescriptor;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::value::asset_normalise;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// BundlePerTxCapCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Bundle-aware per-inner transaction amount cap criterion.
///
/// Checks that each `TokenTransfer` inner in the bundle does not exceed
/// `max_stroops` for the configured asset.  Returns
/// [`DenyReason::BundleDenied`] wrapping [`DenyReason::PerTxCapExceeded`] at
/// the first offending inner.
///
/// # Bundle semantics
///
/// This criterion is bundle-level (`is_bundle_level() = true`).  It runs once
/// with the full [`crate::policy::v1::bundle::BundleView`] available.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::bundle_per_tx_cap::BundlePerTxCapCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let c = BundlePerTxCapCriterion::new("native".into(), 1_000_000_000);
/// assert_eq!(c.kind(), "bundle_per_tx_cap");
/// ```
#[derive(Debug, Clone)]
pub struct BundlePerTxCapCriterion {
    /// Asset identifier: `"native"` or `"CODE:G…ISSUER"`.
    asset: String,
    /// Maximum stroops per single inner transfer.
    ///
    /// `i128` because a single inner's token quantity (e.g. a Soroban SAC
    /// transfer) can exceed `i64::MAX`.
    max_stroops: i128,
}

impl BundlePerTxCapCriterion {
    /// Constructs a new [`BundlePerTxCapCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::bundle_per_tx_cap::BundlePerTxCapCriterion;
    ///
    /// let c = BundlePerTxCapCriterion::new("native".into(), 5_000_000_000);
    /// assert_eq!(c.max_stroops(), 5_000_000_000);
    /// ```
    #[must_use]
    pub fn new(asset: String, max_stroops: i128) -> Self {
        Self { asset, max_stroops }
    }

    /// Returns the configured maximum stroops per inner transfer.
    #[must_use]
    pub fn max_stroops(&self) -> i128 {
        self.max_stroops
    }
}

impl Criterion for BundlePerTxCapCriterion {
    fn kind(&self) -> &'static str {
        "bundle_per_tx_cap"
    }

    /// Returns `true` — this criterion runs once at bundle-level with the full
    /// bundle available.  It is skipped at per-inner evaluation.
    fn is_bundle_level(&self) -> bool {
        true
    }

    /// Evaluates the bundle per-inner transaction cap.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` — `ctx.bundle` is `None`, or no matching `TokenTransfer`
    ///   inner exceeds `max_stroops`.
    /// - `Ok(Some(DenyReason::BundleDenied { inner_index, deny_reason: PerTxCapExceeded { .. } }))` —
    ///   the first inner whose amount exceeds `max_stroops`.
    ///
    /// # Errors
    ///
    /// This criterion never returns `Err`; the return type satisfies [`Criterion`].
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let Some(view) = ctx.bundle else {
            return Ok(None);
        };

        let criterion_asset = asset_normalise(&self.asset);

        for (idx, inner) in view.inners.iter().enumerate() {
            let InnerOpDescriptor::TokenTransfer { asset, amount, .. } = inner else {
                continue;
            };

            let inner_asset = asset_normalise(asset);
            if inner_asset != criterion_asset {
                continue;
            }

            let inner_stroops = *amount;

            if inner_stroops > self.max_stroops {
                return Ok(Some(DenyReason::BundleDenied {
                    inner_index: u32::try_from(idx).unwrap_or(u32::MAX),
                    deny_reason: Box::new(DenyReason::PerTxCapExceeded {
                        asset: self.asset.clone(),
                        max_stroops: self.max_stroops,
                        attempted_stroops: inner_stroops,
                    }),
                }));
            }
        }

        Ok(None)
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
    const ADDR_FROM: &str = "GAQAA5L65LSYH7CQ3VTJ7F3HHLGCL3DSLAR2Y47263D56MNNGHSQSTVY";
    const ADDR_TO: &str = "GBPXXOA5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL";

    fn make_tool() -> ToolDescriptor {
        ToolDescriptor::from_registration(&McpToolRegistration {
            name: "wallet_multicall",
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        })
    }

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    fn token_transfer_native(amount: i128) -> InnerOpDescriptor {
        InnerOpDescriptor::TokenTransfer {
            asset: "native".to_owned(),
            from: ADDR_FROM.to_owned(),
            to: ADDR_TO.to_owned(),
            amount,
        }
    }

    fn make_ctx_with_bundle<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        store: &'a PolicyStateStore,
        view: Option<&'a BundleView<'a>>,
    ) -> EvalContext<'a> {
        EvalContext {
            tool,
            args: &serde_json::Value::Null,
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

    /// Single-tx path passes unconditionally.
    #[test]
    fn single_tx_bundle_none_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let c = BundlePerTxCapCriterion::new("native".into(), 0);
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, None);
        assert!(c.evaluate(&ctx).unwrap().is_none());
    }

    /// Inner under cap passes.
    #[test]
    fn inner_under_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let c = BundlePerTxCapCriterion::new("native".into(), 1_000_000_000); // 100
        let inners = vec![token_transfer_native(500_000_000)]; // 50
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(c.evaluate(&ctx).unwrap().is_none(), "50 < 100 must pass");
    }

    /// Inner exactly at cap passes (strict > boundary).
    #[test]
    fn inner_exactly_at_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let c = BundlePerTxCapCriterion::new("native".into(), 1_000_000_000);
        let inners = vec![token_transfer_native(1_000_000_000)]; // == cap
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "inner == max_stroops must pass"
        );
    }

    /// First over-cap inner is denied at correct index.
    #[test]
    fn first_over_cap_inner_denied_at_correct_index() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let c = BundlePerTxCapCriterion::new("native".into(), 1_000_000_000);
        let inners = vec![
            token_transfer_native(500_000_000),   // 50 — pass — idx 0
            token_transfer_native(1_100_000_000), // 110 — deny — idx 1
            token_transfer_native(100_000_000),   // 10 — never reached
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        let result = c.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::BundleDenied {
                    inner_index: 1,
                    ref deny_reason,
                }) if matches!(
                    deny_reason.as_ref(),
                    DenyReason::PerTxCapExceeded {
                        attempted_stroops: 1_100_000_000,
                        ..
                    }
                )
            ),
            "inner 1 must be denied; got {result:?}"
        );
    }

    /// Asset mismatch inners are skipped.
    #[test]
    fn asset_mismatch_inners_skipped() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let c = BundlePerTxCapCriterion::new("native".into(), 0); // cap=0 → deny any native
        let inners = vec![InnerOpDescriptor::TokenTransfer {
            asset: USDC_ASSET.to_owned(),
            from: ADDR_FROM.to_owned(),
            to: ADDR_TO.to_owned(),
            amount: 1_000_000_000,
        }];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "USDC inner must not trigger native cap"
        );
    }

    /// `is_bundle_level()` must return `true`.
    #[test]
    fn is_bundle_level_returns_true() {
        let c = BundlePerTxCapCriterion::new("native".into(), 1_000_000_000);
        assert!(c.is_bundle_level());
    }
}
