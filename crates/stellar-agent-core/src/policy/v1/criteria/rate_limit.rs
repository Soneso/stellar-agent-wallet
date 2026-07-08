//! Rate-limit criterion (calls per rolling window).
//!
//! [`RateLimitCriterion`] limits the number of tool calls within a rolling
//! time window, regardless of asset or amount.  It uses the same sliding-window
//! design as [`crate::policy::v1::criteria::per_period_cap`] but counts calls
//! rather than amounts.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "rate_limit", window = "1m", max_calls = 5 }
//! ```
//!
//! Supported `window` values: `"1m"`, `"5m"`, `"1h"`, `"1d"`, `"1w"`.
//!
//! # State key
//!
//! State is keyed by `(profile_name, scope_specificity, "rate_limit",
//! window_secs)`.  The fixed bucket string `"rate_limit"` keeps call-count
//! state separate from per-asset amount state.
//!
//! # Read-only evaluation
//!
//! The criterion only reads accumulated state.  Recording a new call entry at
//! commit time is the dispatch site's responsibility.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::v1::EvalContext;
use crate::policy::v1::bundle::{BundleStateOverlay, InnerOpDescriptor};
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::criteria::per_period_cap::Window;
use crate::policy::v1::criteria::state_store::StateKey;
use crate::policy::{DenyReason, PolicyError};

/// Rate-limit criterion (calls per rolling window).
///
/// Returns [`DenyReason::RateLimitExceeded`] when the number of recorded calls
/// in the current window plus the pending call would exceed `max_calls`.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::rate_limit::RateLimitCriterion;
/// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let w = Window::parse("1m").unwrap();
/// let criterion = RateLimitCriterion::new(w, 5);
/// assert_eq!(criterion.kind(), "rate_limit");
/// ```
#[derive(Debug, Clone)]
pub struct RateLimitCriterion {
    /// Rolling window duration.
    window: Window,
    /// Maximum calls allowed per window.
    max_calls: u32,
}

impl RateLimitCriterion {
    /// Constructs a new [`RateLimitCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::rate_limit::RateLimitCriterion;
    /// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
    ///
    /// let w = Window::parse("1h").unwrap();
    /// let criterion = RateLimitCriterion::new(w, 10);
    /// assert_eq!(criterion.max_calls(), 10);
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

impl Criterion for RateLimitCriterion {
    fn kind(&self) -> &'static str {
        "rate_limit"
    }

    /// Evaluates the rate limit for the current call.
    ///
    /// Returns `Ok(None)` when the call is within the limit.  Returns
    /// `Ok(Some(DenyReason::RateLimitExceeded))` when the accumulated call
    /// count in the window is already at or above `max_calls`.
    ///
    /// Unlike amount caps, this criterion applies to every recognised tool call
    /// regardless of the specific tool — the rule match clause filters which
    /// tools the rule applies to.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when:
    /// - `SystemTime::now()` is before UNIX epoch.
    /// - The state store detects clock skew exceeding 30 seconds.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|e| PolicyError::CriterionEvaluationFailed {
                detail: format!("rate_limit: system clock is before UNIX epoch: {e}"),
            })?;

        let state_key = StateKey::new(
            ctx.profile_name,
            // Scope specificity 1 (AllProfiles) is the default; the dispatch
            // site can supply a narrower resolved specificity via EvalContext.
            1,
            "rate_limit",
            self.window.as_secs(),
        );

        let (_, calls_in_window_recorded) = ctx
            .state_store
            .query_window(&state_key, now_ms)
            .map_err(|e| PolicyError::CriterionEvaluationFailed {
                detail: format!("rate_limit: state store error: {e}"),
            })?;

        // Add any overlay call count accumulated from earlier inners in the
        // same multicall bundle.  The rate_limit overlay uses the same
        // state_key derivation ("rate_limit" bucket) so each inner in a bundle
        // contributes +1 call via the overlay.  On the single-tx path
        // (bundle = None) the overlay contributes 0.
        let bundle_accumulated_calls: i128 = ctx
            .bundle
            .map(|view| view.overlay.get(&state_key))
            .unwrap_or(0);

        // `.max(0)` is defence-in-depth: `BundleStateOverlay::accumulate` uses
        // `i128::saturating_add` with positive addends (call counts), so the
        // overlay value should never be negative.  The clamp protects against
        // future criterion implementations that might accumulate negative amounts
        // via `accumulate_overlay`, preventing a negative overlay from
        // under-counting the window total and silently raising the effective cap.
        // The subsequent saturating cast to u32 handles any `i128` value that
        // would overflow u32.
        let calls_in_window = calls_in_window_recorded
            .saturating_add(u32::try_from(bundle_accumulated_calls.max(0)).unwrap_or(u32::MAX));

        // Deny if the number of calls already in the window meets or exceeds
        // max_calls (the current call would push it over).
        if calls_in_window >= self.max_calls {
            return Ok(Some(DenyReason::RateLimitExceeded {
                window: self.window.label().to_owned(),
                max_calls: self.max_calls,
                calls_in_window,
            }));
        }

        Ok(None)
    }

    /// Accumulates one call count into the overlay using the SAME `StateKey`
    /// as `evaluate`.
    ///
    /// Derives `StateKey::new(ctx.profile_name, 1, "rate_limit", window_secs)` —
    /// matching the key constructed in `evaluate` — so that the overlay write is
    /// guaranteed to be read back correctly on the next inner's `evaluate` call.
    ///
    /// Each inner in a bundle that passes `evaluate` contributes exactly 1 call
    /// to the overlay, regardless of its descriptor kind (the rate limit is
    /// call-count-based, not amount-based).
    fn accumulate_overlay(
        &self,
        ctx: &EvalContext<'_>,
        _inner: &InnerOpDescriptor,
        overlay: &mut BundleStateOverlay,
    ) {
        // Derive the SAME state key as evaluate() uses — guarantees read-key equality.
        let state_key = StateKey::new(ctx.profile_name, 1, "rate_limit", self.window.as_secs());
        // Each passing inner counts as one call.
        overlay.accumulate(state_key, 1);
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

    use serde_json::json;
    use serial_test::serial;

    use super::*;
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::{McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

    /// Constructs a `ToolDescriptor` for `tool_name` with the registration
    /// attributes used by all criterion tests.
    fn make_tool(tool_name: &'static str) -> ToolDescriptor {
        let reg = McpToolRegistration {
            name: tool_name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind: crate::policy::ToolValueKind::ReadOnly,
        };
        ToolDescriptor::from_registration(&reg)
    }

    /// Constructs a standard testnet `Profile` for criterion tests.
    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

    /// Constructs an [`EvalContext`] from caller-owned `tool`, `profile`,
    /// `args`, and `store`.  Lifetimes are tied to the caller's stack so
    /// no heap allocation is leaked.
    fn make_ctx<'a>(
        tool: &'a ToolDescriptor,
        profile: &'a Profile,
        args: &'a serde_json::Value,
        store: &'a PolicyStateStore,
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
            bundle: None,
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after UNIX epoch")
            .as_millis() as u64
    }

    #[test]
    #[serial]
    fn zero_calls_in_window_allows() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(w, 5);
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "no previous calls should be allowed");
    }

    #[test]
    #[serial]
    fn calls_below_cap_minus_one_allows() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(w, 5);
        let key = StateKey::new("alice", 1, "rate_limit", 60);
        let t = now_ms() - 1_000;
        // 4 calls already recorded → 5th call is within limit (4 < 5).
        for _ in 0..4 {
            store.append(&key, t, 1).unwrap();
        }
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "4 calls should be under a 5-call cap");
    }

    #[test]
    #[serial]
    fn calls_at_cap_denies_next_call() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(w, 5);
        let key = StateKey::new("alice", 1, "rate_limit", 60);
        let t = now_ms() - 1_000;
        // 5 calls already recorded → the 6th call would exceed the cap.
        for _ in 0..5 {
            store.append(&key, t, 1).unwrap();
        }
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::RateLimitExceeded { .. })),
            "5 calls already in window should deny the next call"
        );
    }

    #[test]
    #[serial]
    fn expired_entries_are_evicted_before_count() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(w, 3);
        let key = StateKey::new("alice", 1, "rate_limit", 60);

        // Insert 3 old calls outside the window.
        let ancient = now_ms().saturating_sub(120_000); // 2 minutes ago
        for _ in 0..3 {
            store.append(&key, ancient, 1).unwrap();
        }
        // 1 recent call inside the window.
        store.append(&key, now_ms() - 1_000, 1).unwrap();

        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        // Only 1 recent call; 2 more allowed.
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "ancient entries should be evicted; 1 recent call should be under a 3-call cap"
        );
    }

    #[test]
    #[serial]
    fn clock_skew_over_30s_returns_evaluation_failed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(w, 5);
        let key = StateKey::new("alice", 1, "rate_limit", 60);
        // Insert a future entry with clock skew > 30 seconds.
        store.append(&key, now_ms() + 31_000, 1).unwrap();
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "clock skew > 30s should return CriterionEvaluationFailed"
        );
    }

    // ── Overlay tests ─────────────────────────────────────────────────────────

    /// Single-tx path (bundle=None) sees zero overlay contribution.
    #[test]
    #[serial]
    fn evaluate_with_bundle_overlay_single_tx_none_sees_zero_overlay() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(w, 5);
        let key = StateKey::new("alice", 1, "rate_limit", 60);
        let t = now_ms() - 1_000;
        // 4 calls already recorded.
        for _ in 0..4 {
            store.append(&key, t, 1).unwrap();
        }
        // Single-tx with bundle=None — overlay contributes 0, so 4+1 pending =
        // 5 which is NOT >= 5 by one-call-ahead semantics... wait: 4 recorded
        // means 4 < 5 so the next call is allowed.
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store); // bundle=None
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "bundle=None must see zero overlay; 4 recorded calls < 5 cap allows next call"
        );
    }

    /// Bundle path with non-zero overlay adds accumulated call count to the
    /// window total.
    #[test]
    #[serial]
    fn evaluate_with_bundle_overlay_accumulated_calls_added_to_window() {
        use crate::policy::v1::bundle::{BundleStateOverlay, BundleView};

        let tool = make_tool("stellar_pay");
        let _profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1m").unwrap();
        let criterion = RateLimitCriterion::new(w, 5);
        let rate_key = StateKey::new("alice", 1, "rate_limit", 60);
        let t = now_ms() - 1_000;
        // 3 calls recorded in the state store.
        for _ in 0..3 {
            store.append(&rate_key, t, 1).unwrap();
        }

        // Overlay simulates 2 calls already approved in earlier bundle inners.
        let mut overlay = BundleStateOverlay::default();
        // The overlay uses rate_limit key with i128 count.
        overlay.accumulate(rate_key.clone(), 2);
        let inners: Vec<crate::policy::v1::bundle::InnerOpDescriptor> = vec![];
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        // Effective calls = 3 (recorded) + 2 (overlay) = 5 >= 5 cap → deny.
        let args = json!({});
        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "alice",
            profile: &make_profile(),
            value: crate::policy::v1::value::ValueClass::ReadOnly,
            account_view: None,
            identity_view: None,
            quorum: None,
            counterparty_cache: None,
            sep10_sessions: None,
            sep45_sessions: None,
            state_store: &store,
            bundle: Some(&view),
        };
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(
                result,
                Some(DenyReason::RateLimitExceeded {
                    calls_in_window: 5,
                    ..
                })
            ),
            "3 recorded + 2 overlay = 5 >= 5 cap must deny"
        );
    }
}
