//! Bundle-aware per-period aggregate amount cap criterion.
//!
//! [`BundlePerPeriodCapCriterion`] enforces that the aggregate amount transferred
//! within a rolling time window does not exceed a configured maximum for a given
//! asset, when evaluated across a multicall bundle.
//!
//! This criterion is **bundle-level** (`is_bundle_level() = true`): it runs once
//! with the full `BundleView` available and inspects all `TokenTransfer` inners
//! in the bundle.  It does NOT participate in per-inner evaluation.
//!
//! # Why a separate criterion variant instead of extending `PerPeriodCapCriterion`
//!
//! Extending `PerPeriodCapCriterion::evaluate` to also fire under
//! `tool = "wallet_multicall"` would silently change the semantics of existing
//! rules that carry `per_period_cap` against `stellar_pay` — those rules would
//! also fire against multicall bundles, which operators may not intend.
//!
//! `BundlePerPeriodCapCriterion` is an additive variant: existing `per_period_cap`
//! rules are unaffected; operators who want per-period caps under multicall
//! explicitly install `bundle_per_period_cap`.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "bundle_per_period_cap", asset = "native", window = "1h", max_stroops = 10_000_000_000 }
//! ```
//!
//! Supported `window` values: `"1m"`, `"5m"`, `"1h"`, `"1d"`, `"1w"`.
//!
//! # Single-tx path
//!
//! When `ctx.bundle` is `None`, the criterion passes unconditionally.
//!
//! # State store interaction
//!
//! This criterion reads from the same `PolicyStateStore` and uses the same
//! `StateKey` derivation as `PerPeriodCapCriterion` so that period usage
//! recorded on single-tx calls also counts toward the bundle cap (shared sliding
//! window across both call paths).

use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::v1::EvalContext;
use crate::policy::v1::bundle::InnerOpDescriptor;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::criteria::per_period_cap::Window;
use crate::policy::v1::criteria::state_store::StateKey;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// BundlePerPeriodCapCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Bundle-aware per-period aggregate amount cap criterion.
///
/// Inspects all `TokenTransfer` inners in the bundle and checks that the sum
/// of their amounts plus the already-recorded period usage does not exceed
/// `max_stroops` for the configured asset within the rolling window.
///
/// Returns [`DenyReason::BundleDenied`] wrapping
/// [`DenyReason::PerPeriodCapExceeded`] at the first inner that tips the cap.
///
/// # Bundle semantics
///
/// This criterion is bundle-level (`is_bundle_level() = true`).  It runs once
/// with the full [`crate::policy::v1::bundle::BundleView`] available.
/// It does not run at per-inner evaluation.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
/// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let w = Window::parse("1h").unwrap();
/// let c = BundlePerPeriodCapCriterion::new("native".into(), w, 10_000_000_000);
/// assert_eq!(c.kind(), "bundle_per_period_cap");
/// ```
///
#[derive(Debug, Clone)]
pub struct BundlePerPeriodCapCriterion {
    /// Asset identifier: `"native"` or `"CODE:G…ISSUER"`.
    asset: String,
    /// Rolling window duration.
    window: Window,
    /// Maximum aggregate stroops within the window (per-period + bundle total).
    max_stroops: i64,
}

impl BundlePerPeriodCapCriterion {
    /// Constructs a new [`BundlePerPeriodCapCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::bundle_per_period_cap::BundlePerPeriodCapCriterion;
    /// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
    ///
    /// let w = Window::parse("1d").unwrap();
    /// let c = BundlePerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);
    /// assert_eq!(c.max_stroops(), 5_000_000_000);
    /// ```
    #[must_use]
    pub fn new(asset: String, window: Window, max_stroops: i64) -> Self {
        Self {
            asset,
            window,
            max_stroops,
        }
    }

    /// Returns the configured maximum stroops per window.
    #[must_use]
    pub fn max_stroops(&self) -> i64 {
        self.max_stroops
    }
}

impl Criterion for BundlePerPeriodCapCriterion {
    fn kind(&self) -> &'static str {
        "bundle_per_period_cap"
    }

    /// Returns `true` — this criterion runs once at bundle-level with the full
    /// bundle available.  It is skipped at per-inner evaluation.
    /// Its semantics are inherently bundle-scoped: iterate all inners and
    /// apply the per-period cap as a running sum.
    fn is_bundle_level(&self) -> bool {
        true
    }

    /// Evaluates the bundle per-period cap.
    ///
    /// Reads the period usage already recorded in the state store, then iterates
    /// through all `TokenTransfer` inners in the bundle that match the configured
    /// asset.  Accumulates their amounts as a running sum.  At each inner,
    /// checks whether `period_used + running_sum + inner_amount > max_stroops`.
    /// If the cap would be exceeded, returns
    /// [`DenyReason::BundleDenied`] wrapping
    /// [`DenyReason::PerPeriodCapExceeded`] for the first offending inner.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` — `ctx.bundle` is `None` (single-tx), or no matching
    ///   `TokenTransfer` inners exist, or the aggregate amount does not exceed
    ///   the cap.
    /// - `Ok(Some(DenyReason::BundleDenied { inner_index, deny_reason: PerPeriodCapExceeded { .. } }))` —
    ///   the running sum tips the cap at inner `inner_index`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when:
    /// - [`SystemTime`] is before UNIX epoch.
    /// - The state store detects clock skew exceeding 30 seconds.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let Some(view) = ctx.bundle else {
            // Single-tx path: criterion does not apply.
            return Ok(None);
        };

        let criterion_asset = asset_normalise(self.asset.clone());

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|e| PolicyError::CriterionEvaluationFailed {
                detail: format!("bundle_per_period_cap: system clock is before UNIX epoch: {e}"),
            })?;

        // Use the same StateKey derivation as PerPeriodCapCriterion so that
        // period usage recorded on single-tx `stellar_pay` calls counts toward
        // the bundle cap (shared sliding window).
        let state_key = StateKey::new(
            ctx.profile_name,
            // Scope specificity 1 (AllProfiles) — matches PerPeriodCapCriterion default.
            1,
            &criterion_asset,
            self.window.as_secs(),
        );

        let (period_used_recorded, _) =
            ctx.state_store
                .query_window(&state_key, now_ms)
                .map_err(|e| PolicyError::CriterionEvaluationFailed {
                    detail: format!("bundle_per_period_cap: state store error: {e}"),
                })?;

        // Accumulate inner amounts against the period cap, tracking which inner
        // tips the sum.  Only `TokenTransfer` inners whose asset matches fire.
        let mut running_sum: i64 = 0_i64;

        for (idx, inner) in view.inners.iter().enumerate() {
            let InnerOpDescriptor::TokenTransfer { asset, amount, .. } = inner else {
                // Generic inners do not contribute to the period cap.
                continue;
            };

            let inner_asset = asset_normalise(asset.clone());
            if inner_asset != criterion_asset {
                // Asset mismatch: this inner does not count toward this criterion.
                continue;
            }

            // Saturating cast: over-deny on i128 > i64::MAX is the correct
            // security posture.
            let inner_stroops = i64::try_from(*amount).unwrap_or(i64::MAX);

            // Check cap: period_used_recorded + running_sum + inner_stroops > max?
            let would_use = period_used_recorded
                .saturating_add(running_sum)
                .saturating_add(inner_stroops);

            if would_use > self.max_stroops {
                let period_used_stroops = period_used_recorded.saturating_add(running_sum);
                return Ok(Some(DenyReason::BundleDenied {
                    inner_index: u32::try_from(idx).unwrap_or(u32::MAX),
                    deny_reason: Box::new(DenyReason::PerPeriodCapExceeded {
                        asset: self.asset.clone(),
                        window: self.window.label().to_owned(),
                        max_stroops: self.max_stroops,
                        attempted_stroops: inner_stroops,
                        period_used_stroops,
                    }),
                }));
            }

            // Inner within cap — accumulate for next inner's check.
            running_sum = running_sum.saturating_add(inner_stroops);
        }

        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn asset_normalise(asset: String) -> String {
    if asset.eq_ignore_ascii_case("native") || asset.eq_ignore_ascii_case("xlm") {
        "native".to_owned()
    } else {
        asset
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

    use serial_test::serial;

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

    fn token_transfer_usdc(amount: i128) -> InnerOpDescriptor {
        InnerOpDescriptor::TokenTransfer {
            asset: USDC_ASSET.to_owned(),
            from: ADDR_FROM.to_owned(),
            to: ADDR_TO.to_owned(),
            amount,
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX epoch")
            .as_millis() as u64
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

    // ── single-tx path passes unconditionally ────────────────────────────

    /// Single-tx path (bundle=None) passes even with cap=0.
    #[test]
    #[serial]
    fn single_tx_bundle_none_always_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 0);
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, None);
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "bundle=None must always pass"
        );
    }

    // ── empty bundle passes ──────────────────────────────────────────────

    /// Empty bundle passes (no inners).
    #[test]
    #[serial]
    fn empty_bundle_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 0);
        let inners: Vec<InnerOpDescriptor> = vec![];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "empty bundle must always pass"
        );
    }

    // ── 3 inners under cap passes ───────────────────────────────────────

    /// Three inners of 30 each (90 total) under a 100 cap passes.
    #[test]
    #[serial]
    fn three_inners_under_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        // cap = 100 units
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let inners = vec![
            token_transfer_native(300_000_000), // 30
            token_transfer_native(300_000_000), // 30
            token_transfer_native(300_000_000), // 30 → total 90
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "90 total vs 100 cap must pass"
        );
    }

    // ── 4th inner tips the cap ───────────────────────────────────────────

    /// Four inners of 30 each; 4th inner tips 100 cap at index 3.
    #[test]
    #[serial]
    fn fourth_inner_tips_cap_denied_at_index_3() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 XLM
        // 4 inners × 30 XLM = 120 total > 100 cap; inner 3 (0-based) tips it.
        let inners = vec![
            token_transfer_native(300_000_000), // 30 XLM — 0
            token_transfer_native(300_000_000), // 30 XLM — 1
            token_transfer_native(300_000_000), // 30 XLM — 2; running=90
            token_transfer_native(300_000_000), // 30 XLM — 3; 90+30=120 > 100 → deny
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
                    inner_index: 3,
                    ref deny_reason,
                }) if matches!(
                    deny_reason.as_ref(),
                    DenyReason::PerPeriodCapExceeded {
                        attempted_stroops: 300_000_000,
                        period_used_stroops: 900_000_000,
                        max_stroops: 1_000_000_000,
                        ..
                    }
                )
            ),
            "inner 3 must be denied; got {result:?}"
        );
    }

    // ── period_used from state store adds to bundle running sum ──────────

    /// Pre-seeded 70 units in state store; 2 inners of 20 each.
    /// Inner 0: 70+20=90 ≤ 100 → pass.
    /// Inner 1: 70+20+20=110 > 100 → deny at index 1.
    #[test]
    #[serial]
    fn period_used_from_state_store_adds_to_bundle_total() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100

        // Pre-seed 70 units recorded in the last hour.
        let key = StateKey::new("alice", 1, "native", 3_600);
        store.append(&key, now_ms() - 1_000, 700_000_000).unwrap();

        let inners = vec![
            token_transfer_native(200_000_000), // 20; 70+20=90 ≤ 100
            token_transfer_native(200_000_000), // 20; 70+20+20=110 > 100 → deny
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
                    DenyReason::PerPeriodCapExceeded {
                        period_used_stroops: 900_000_000,
                        attempted_stroops: 200_000_000,
                        ..
                    }
                )
            ),
            "inner 1 must be denied with period_used=90; got {result:?}"
        );
    }

    // ── asset mismatch inners are skipped ────────────────────────────────

    /// Criterion configured for native; USDC inners are ignored.
    #[test]
    #[serial]
    fn asset_mismatch_inners_not_counted() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 native
        // All USDC — over any amount, no native inners.
        let inners = vec![
            token_transfer_usdc(10_000_000_000),
            token_transfer_usdc(10_000_000_000),
        ];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "USDC inners must not count toward native cap"
        );
    }

    // ── generic inners are skipped ──────────────────────────────────────

    /// Generic (non-transfer) inners are not counted.
    #[test]
    #[serial]
    fn generic_inners_not_counted() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 0); // cap=0 would deny
        let inners = vec![InnerOpDescriptor::Generic {
            target: "CSTRKEY".into(),
            fn_name: "something".into(),
        }];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "Generic inners must not trigger bundle_per_period_cap"
        );
    }

    // ── is_bundle_level returns true ─────────────────────────────────────

    /// `is_bundle_level()` must return `true` — this criterion runs once at bundle-level.
    #[test]
    fn is_bundle_level_returns_true() {
        let w = Window::parse("1d").unwrap();
        let c = BundlePerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        assert!(
            c.is_bundle_level(),
            "bundle_per_period_cap must be bundle-level"
        );
    }

    // ── XLM and native normalise ────────────────────────────────────────

    /// Cap configured as "XLM" matches inners with asset "native".
    #[test]
    #[serial]
    fn xlm_configured_matches_native_inners() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let c = BundlePerPeriodCapCriterion::new("XLM".into(), w, 1_000_000_000); // 100
        let inners = vec![
            token_transfer_native(600_000_000), // 60
            token_transfer_native(600_000_000), // 60 → total 120 > 100
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
                Some(DenyReason::BundleDenied { inner_index: 1, .. })
            ),
            "XLM and native must normalise to the same asset; got {result:?}"
        );
    }
}
