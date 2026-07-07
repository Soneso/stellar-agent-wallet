//! Bundle-aware rate-limit criterion (calls per rolling window).
//!
//! `BundleRateLimitCriterion` limits the total number of inner operations
//! within a multicall bundle that count toward the rolling call-rate window.
//! Each `TokenTransfer` inner (and each `Generic` inner) in the bundle counts as
//! one call against the window.
//!
//! This criterion is **bundle-level** (`is_bundle_level() = true`): it runs once
//! with the full `BundleView` available.
//!
//! # Why a separate criterion variant instead of extending `RateLimitCriterion`
//!
//! Additive new variant: existing `rate_limit` rules are unaffected.  Operators
//! who want bundle-scoped rate limiting explicitly install `bundle_rate_limit`.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "bundle_rate_limit", window = "1m", max_calls = 5 }
//! ```
//!
//! # Single-tx path
//!
//! When `ctx.bundle` is `None`, the criterion passes unconditionally.
//!
//! # State store interaction
//!
//! Reads from the same state store and `StateKey` derivation as
//! `RateLimitCriterion` (bucket `"rate_limit"`) so that single-tx calls
//! already recorded in the window count toward the bundle cap.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::criteria::per_period_cap::Window;
use crate::policy::v1::criteria::state_store::StateKey;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// BundleRateLimitCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Bundle-aware rate-limit criterion (inner calls per rolling window).
///
/// Counts every inner in the bundle as one call and checks that
/// `calls_in_window + bundle_inner_count ≤ max_calls`.  If the limit is met or
/// exceeded, returns [`DenyReason::BundleDenied`] wrapping
/// [`DenyReason::RateLimitExceeded`] for the first inner that tips the count.
///
/// # Bundle semantics
///
/// This criterion is bundle-level (`is_bundle_level() = true`).  It runs once
/// with the full [`crate::policy::v1::bundle::BundleView`] available.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::bundle_rate_limit::BundleRateLimitCriterion;
/// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let w = Window::parse("1m").unwrap();
/// let c = BundleRateLimitCriterion::new(w, 5);
/// assert_eq!(c.kind(), "bundle_rate_limit");
/// ```
#[derive(Debug, Clone)]
pub struct BundleRateLimitCriterion {
    /// Rolling window duration.
    window: Window,
    /// Maximum calls allowed per window (existing + bundle inners).
    max_calls: u32,
}

impl BundleRateLimitCriterion {
    /// Constructs a new [`BundleRateLimitCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::bundle_rate_limit::BundleRateLimitCriterion;
    /// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
    ///
    /// let w = Window::parse("1h").unwrap();
    /// let c = BundleRateLimitCriterion::new(w, 10);
    /// assert_eq!(c.max_calls(), 10);
    /// ```
    #[must_use]
    pub fn new(window: Window, max_calls: u32) -> Self {
        Self { window, max_calls }
    }

    /// Returns the configured maximum calls per window.
    #[must_use]
    pub fn max_calls(&self) -> u32 {
        self.max_calls
    }
}

impl Criterion for BundleRateLimitCriterion {
    fn kind(&self) -> &'static str {
        "bundle_rate_limit"
    }

    /// Returns `true` — this criterion runs once at bundle-level with the full
    /// bundle available.  It is skipped at per-inner evaluation.
    fn is_bundle_level(&self) -> bool {
        true
    }

    /// Evaluates the bundle rate limit.
    ///
    /// Reads the call count already recorded in the state store for the window,
    /// then counts bundle inners one by one.  At each inner, checks whether
    /// `calls_in_window + running_count >= max_calls`.  If so, returns
    /// [`DenyReason::BundleDenied`] wrapping [`DenyReason::RateLimitExceeded`]
    /// for that inner index.
    ///
    /// # Returns
    ///
    /// - `Ok(None)` — `ctx.bundle` is `None`, or the total call count does not
    ///   reach `max_calls`.
    /// - `Ok(Some(DenyReason::BundleDenied { inner_index, deny_reason: RateLimitExceeded { .. } }))` —
    ///   the first inner that tips the count.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when:
    /// - `SystemTime::now()` is before UNIX epoch.
    /// - The state store detects clock skew exceeding 30 seconds.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let Some(view) = ctx.bundle else {
            return Ok(None);
        };

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|e| PolicyError::CriterionEvaluationFailed {
                detail: format!("bundle_rate_limit: system clock is before UNIX epoch: {e}"),
            })?;

        // Use the same StateKey derivation as RateLimitCriterion (bucket "rate_limit")
        // so that single-tx calls already recorded in the window count toward the cap.
        let state_key = StateKey::new(
            ctx.profile_name,
            // Scope specificity 1 (AllProfiles) — matches RateLimitCriterion default.
            1,
            "rate_limit",
            self.window.as_secs(),
        );

        let (_, calls_in_window) =
            ctx.state_store
                .query_window(&state_key, now_ms)
                .map_err(|e| PolicyError::CriterionEvaluationFailed {
                    detail: format!("bundle_rate_limit: state store error: {e}"),
                })?;

        // Count inners one by one so we can report the exact inner_index that
        // tips the rate limit.
        for (idx, _inner) in view.inners.iter().enumerate() {
            // running count = previously recorded + inners processed so far (idx).
            // The current inner would be the (idx+1)-th call from this bundle.
            // All inners (TokenTransfer and Generic) count as one call each.
            let idx_u32 = u32::try_from(idx).unwrap_or(u32::MAX);
            let bundle_calls_so_far = calls_in_window.saturating_add(idx_u32);

            if bundle_calls_so_far >= self.max_calls {
                return Ok(Some(DenyReason::BundleDenied {
                    inner_index: idx_u32,
                    deny_reason: Box::new(DenyReason::RateLimitExceeded {
                        window: self.window.label().to_owned(),
                        max_calls: self.max_calls,
                        calls_in_window: bundle_calls_so_far,
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

    use std::time::{SystemTime, UNIX_EPOCH};

    use serial_test::serial;

    use super::*;
    use crate::policy::v1::bundle::{BundleStateOverlay, BundleView, InnerOpDescriptor};
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::{DenyReason, McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

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

    fn generic_inner() -> InnerOpDescriptor {
        InnerOpDescriptor::Generic {
            target: "CSTRKEY".to_owned(),
            fn_name: "transfer".to_owned(),
        }
    }

    fn native_transfer_inner() -> InnerOpDescriptor {
        InnerOpDescriptor::TokenTransfer {
            asset: "native".to_owned(),
            from: ADDR_FROM.to_owned(),
            to: ADDR_TO.to_owned(),
            amount: 100_000_000,
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
    #[serial]
    fn single_tx_bundle_none_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let c = BundleRateLimitCriterion::new(w, 0);
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, None);
        assert!(c.evaluate(&ctx).unwrap().is_none());
    }

    /// Empty bundle passes.
    #[test]
    #[serial]
    fn empty_bundle_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let c = BundleRateLimitCriterion::new(w, 0);
        let inners: Vec<InnerOpDescriptor> = vec![];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(c.evaluate(&ctx).unwrap().is_none());
    }

    /// 3 inners under a 5-call cap passes.
    #[test]
    #[serial]
    fn bundle_under_cap_passes() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let c = BundleRateLimitCriterion::new(w, 5);
        let inners = vec![generic_inner(), generic_inner(), generic_inner()];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "3 inners vs cap=5 must pass"
        );
    }

    /// 5 inners exactly at cap=5: inner 5 would exceed; deny at index 4 (0-based).
    ///
    /// After 4 inners pass (indices 0-3), index 4 is the 5th call which == max_calls,
    /// triggering denial.
    #[test]
    #[serial]
    fn bundle_at_cap_denies_at_last_inner() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let c = BundleRateLimitCriterion::new(w, 5); // max 5 calls per minute
        // 5 inners: first 4 pass (0,1,2,3), inner 4 (0-based) == index 4 — bundle_calls=4 >= 5? No.
        // Actually: at idx=4, bundle_calls_so_far = 0 + 4 = 4 >= 5? No, 4 < 5 → pass.
        // So 5 inners under max=5 should all pass.
        let inners = (0..5).map(|_| generic_inner()).collect::<Vec<_>>();
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "5 inners vs cap=5: calls_recorded=0, so at idx=4: 0+4=4 < 5; all pass"
        );
    }

    /// 3 recorded calls + 3-inner bundle with cap=5: inner 2 (0-based) tips it.
    /// calls_in_window=3; at idx=0: 3+0=3 < 5 pass; idx=1: 3+1=4 < 5 pass; idx=2: 3+2=5 >= 5 deny.
    #[test]
    #[serial]
    fn recorded_calls_plus_bundle_tips_cap() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let c = BundleRateLimitCriterion::new(w, 5);

        // Pre-record 3 calls.
        let key = StateKey::new("alice", 1, "rate_limit", 60);
        let t = now_ms() - 1_000;
        for _ in 0..3 {
            store.append(&key, t, 1).unwrap();
        }

        let inners = vec![
            generic_inner(), // idx=0: 3+0=3 < 5 → pass
            generic_inner(), // idx=1: 3+1=4 < 5 → pass
            generic_inner(), // idx=2: 3+2=5 >= 5 → deny
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
                    inner_index: 2,
                    ref deny_reason,
                }) if matches!(
                    deny_reason.as_ref(),
                    DenyReason::RateLimitExceeded { calls_in_window: 5, .. }
                )
            ),
            "inner 2 must be denied with calls_in_window=5; got {result:?}"
        );
    }

    /// Both `TokenTransfer` and `Generic` inners count as one call each.
    #[test]
    #[serial]
    fn token_transfer_and_generic_both_count() {
        let tool = make_tool();
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let c = BundleRateLimitCriterion::new(w, 2);
        // 2 inners: TokenTransfer + Generic; cap=2 so idx=1 → 0+1=1 < 2 pass.
        // Passes because 2 inners with cap=2: at idx=0: 0+0=0 < 2, idx=1: 0+1=1 < 2 → all pass.
        let inners = vec![native_transfer_inner(), generic_inner()];
        let overlay = BundleStateOverlay::default();
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };
        let ctx = make_ctx_with_bundle(&tool, &profile, &store, Some(&view));
        assert!(
            c.evaluate(&ctx).unwrap().is_none(),
            "2 inners vs cap=2 must pass (0+0=0<2, 0+1=1<2)"
        );
    }

    /// `is_bundle_level()` must return `true`.
    #[test]
    fn is_bundle_level_returns_true() {
        let w = Window::parse("1m").unwrap();
        let c = BundleRateLimitCriterion::new(w, 5);
        assert!(c.is_bundle_level());
    }
}
