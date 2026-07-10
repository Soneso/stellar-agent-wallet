//! Per-period aggregate amount cap criterion.
//!
//! `PerPeriodCapCriterion` enforces that the aggregate amount transferred
//! within a rolling time window does not exceed a configured maximum in stroops
//! for a given asset.  It reads accumulated state from `PolicyStateStore`;
//! recording a new entry after a successful commit is the dispatch site's
//! responsibility.
//!
//! # Sliding-window design
//!
//! Entries accumulate in the state store and are evicted lazily on each query.
//! There is no background sweeper.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "per_period_cap", asset = "native", window = "1d", max_stroops = 5_000_000_000 }
//! ```
//!
//! Supported `window` values: `"1m"`, `"5m"`, `"1h"`, `"1d"`, `"1w"`.
//! Any other value is rejected at construction time with
//! [`PolicyError::PolicyFileParseFailed`].
//!
//! # Clock-skew tolerance
//!
//! `now_ms` is derived from `std::time::SystemTime::now()`.  Entries up to 30
//! seconds in the future are tolerated; beyond that,
//! [`PolicyError::CriterionEvaluationFailed`] is returned.
//!
//! # Read-only evaluation
//!
//! This criterion only reads accumulated state.  After a successful commit the
//! dispatch site must append a new entry to the state store via
//! `PolicyStateStore::append`.  This decoupling keeps the evaluator
//! side-effect-free and avoids double-counting on re-evaluation.
//!
//! # Tool argument parsing
//!
//! For `stellar_pay` / `stellar_pay_commit`: reads `args["amount_stroops"]`
//! (a decimal string; a legacy JSON number is tolerated for version-crossing)
//! and `args["asset"]` (e.g. `"native"` or `"CODE:Gissuer"`). Falls back to
//! the legacy `args["amount"]` (a `"N.NNNNNNN XLM"` string) only when
//! `amount_stroops` is absent — every args shape this criterion actually
//! receives in production (simulate-time `args_value` and commit-time
//! `authoritative_args`) carries `amount_stroops`.
//!
//! For `stellar_create_account` / `stellar_create_account_commit`: reads
//! `args["starting_balance_stroops"]` the same way (falling back to the
//! legacy `args["starting_balance"]`) and treats the asset as implicitly
//! native.
//!
//! For other tools: the criterion is driven entirely by the typed value
//! descriptor ([`crate::policy::v1::value::classify_value`]); it applies to
//! any `MovesValue` tool whose descriptor resolves debit legs in the
//! configured asset (see [`crate::policy::v1::value`]).
//!

use std::time::{SystemTime, UNIX_EPOCH};

use crate::policy::v1::EvalContext;
use crate::policy::v1::bundle::{BundleStateOverlay, InnerOpDescriptor};
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::criteria::state_store::StateKey;
use crate::policy::v1::value::{ValueGate, asset_normalise, classify_value};
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// Window
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed rolling-window duration for the per-period cap.
///
/// Constructed from the TOML `window` string field via [`Window::parse`].
/// Stores the window as seconds for key derivation and as milliseconds for
/// state-store eviction.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
///
/// let w = Window::parse("1d").unwrap();
/// assert_eq!(w.as_secs(), 86_400);
/// assert_eq!(w.label(), "1d");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    secs: u64,
    label: &'static str,
}

impl Window {
    /// Parses a window string.
    ///
    /// Accepted values: `"1m"`, `"5m"`, `"1h"`, `"1d"`, `"1w"`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::PolicyFileParseFailed`] for any other input.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::per_period_cap::Window;
    /// use stellar_agent_core::policy::PolicyError;
    ///
    /// assert_eq!(Window::parse("1m").unwrap().as_secs(), 60);
    /// assert_eq!(Window::parse("5m").unwrap().as_secs(), 300);
    /// assert_eq!(Window::parse("1h").unwrap().as_secs(), 3_600);
    /// assert_eq!(Window::parse("1d").unwrap().as_secs(), 86_400);
    /// assert_eq!(Window::parse("1w").unwrap().as_secs(), 604_800);
    ///
    /// assert!(matches!(
    ///     Window::parse("2d"),
    ///     Err(PolicyError::PolicyFileParseFailed { .. }),
    /// ));
    /// ```
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        match s {
            "1m" => Ok(Self {
                secs: 60,
                label: "1m",
            }),
            "5m" => Ok(Self {
                secs: 300,
                label: "5m",
            }),
            "1h" => Ok(Self {
                secs: 3_600,
                label: "1h",
            }),
            "1d" => Ok(Self {
                secs: 86_400,
                label: "1d",
            }),
            "1w" => Ok(Self {
                secs: 604_800,
                label: "1w",
            }),
            other => Err(PolicyError::PolicyFileParseFailed {
                detail: format!(
                    "per_period_cap: unsupported window '{}'; accepted: 1m, 5m, 1h, 1d, 1w",
                    other
                ),
            }),
        }
    }

    /// Returns the window duration in seconds.
    #[must_use]
    pub fn as_secs(self) -> u64 {
        self.secs
    }

    /// Returns the human-readable label (e.g. `"1d"`).
    #[must_use]
    pub fn label(self) -> &'static str {
        self.label
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PerPeriodCapCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Per-period aggregate amount cap criterion.
///
/// Checks that `period_used_stroops + attempted_stroops ≤ max_stroops` for the
/// configured asset within a rolling window.  If the cap would be exceeded,
/// returns [`DenyReason::PerPeriodCapExceeded`].
///
/// The criterion only reads accumulated state from [`crate::policy::v1::criteria::PolicyStateStore`].
/// Recording a new entry after a successful commit is the dispatch site's
/// responsibility.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let w = Window::parse("1d").unwrap();
/// let criterion = PerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);
/// assert_eq!(criterion.kind(), "per_period_cap");
/// ```
#[derive(Debug, Clone)]
pub struct PerPeriodCapCriterion {
    /// Asset identifier: `"native"` or `"CODE:G…ISSUER"`.
    asset: String,
    /// Rolling window duration.
    window: Window,
    /// Maximum aggregate stroops within the window.
    ///
    /// `i128` because a token quantity aggregated over many legs (e.g.
    /// Soroban SAC transfers) can exceed `i64::MAX`.
    max_stroops: i128,
}

impl PerPeriodCapCriterion {
    /// Constructs a new [`PerPeriodCapCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::per_period_cap::{PerPeriodCapCriterion, Window};
    ///
    /// let w = Window::parse("1h").unwrap();
    /// let cap = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
    /// assert_eq!(cap.max_stroops(), 1_000_000_000);
    /// ```
    #[must_use]
    pub fn new(asset: String, window: Window, max_stroops: i128) -> Self {
        Self {
            asset,
            window,
            max_stroops,
        }
    }

    /// Returns the configured maximum stroops per window.
    #[must_use]
    pub fn max_stroops(&self) -> i128 {
        self.max_stroops
    }
}

impl Criterion for PerPeriodCapCriterion {
    fn kind(&self) -> &'static str {
        "per_period_cap"
    }

    /// Evaluates the per-period cap.
    ///
    /// Returns `Ok(None)` when the criterion does not apply (unrecognised tool
    /// or asset mismatch).  Returns `Ok(Some(DenyReason::PerPeriodCapExceeded))`
    /// when adding the attempted amount would exceed the cap.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when:
    /// - The required amount field is missing or unparseable.
    /// - [`SystemTime`] is before UNIX epoch (should not occur in practice).
    /// - The state store detects clock skew exceeding 30 seconds.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let tool_name = ctx.tool.name.as_str();

        let criterion_asset = asset_normalise(&self.asset);

        // Descriptor-driven path with the fail-closed default: an unsizable
        // effect (MovesValue tool that resolved no effects, or an opaque-sign
        // call) denies here rather than passing silently.
        let effects = match classify_value(ctx) {
            ValueGate::NotApplicable => return Ok(None),
            ValueGate::Deny(reason) => return Ok(Some(reason)),
            ValueGate::Effects(effects) => effects,
        };

        // Aggregate the debit legs matching the configured asset (per-asset
        // aggregation across the N legs of a multi-leg call). A non-debit leg
        // (Claim/Trustline) contributes nothing; a debit leg with an
        // unresolvable amount or asset is refused fail-closed.
        let mut matched = false;
        let mut sum: i128 = 0;
        for leg in effects.legs() {
            if !leg.kind.carries_debit() {
                continue;
            }
            let leg_asset =
                leg.asset
                    .as_deref()
                    .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                        detail: format!(
                            "per_period_cap: debit leg of tool '{tool_name}' carries no asset"
                        ),
                    })?;
            if asset_normalise(leg_asset) != criterion_asset {
                continue;
            }
            let amount = leg
                .amount
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "per_period_cap: unresolvable amount for a debit leg of tool '{tool_name}'"
                    ),
                })?;
            matched = true;
            sum = sum.saturating_add(amount);
        }

        // The configured asset is not moved by this call — criterion not applicable.
        if !matched {
            return Ok(None);
        }

        self.check_window(ctx, &criterion_asset, sum)
    }

    /// Accumulates this inner's amount into the overlay using the SAME
    /// `StateKey` as `evaluate`.
    ///
    /// Derives `StateKey::new(ctx.profile_name, 1, criterion_asset, window_secs)` —
    /// matching the key constructed in `evaluate` — so that the overlay write
    /// is guaranteed to be read back correctly on the next inner's `evaluate`
    /// call.
    ///
    /// Only accumulates for `InnerOpDescriptor::TokenTransfer` inners whose
    /// asset matches `self.asset` (after normalisation).  `Generic` inners and
    /// asset-mismatched inners contribute 0.
    ///
    /// The amount is accumulated as `i128` (no clamp): both the overlay and
    /// the on-chain token quantity it accounts for are `i128`.
    fn accumulate_overlay(
        &self,
        ctx: &EvalContext<'_>,
        inner: &InnerOpDescriptor,
        overlay: &mut BundleStateOverlay,
    ) {
        let InnerOpDescriptor::TokenTransfer { asset, amount, .. } = inner else {
            // Generic inners contribute 0.
            return;
        };

        let criterion_asset = asset_normalise(&self.asset);
        let inner_asset = asset_normalise(asset);
        if criterion_asset != inner_asset {
            // Asset mismatch: this inner does not count toward this criterion.
            return;
        }

        // Derive the SAME state key as evaluate() uses — guarantees read-key equality.
        let state_key = StateKey::new(ctx.profile_name, 1, &criterion_asset, self.window.as_secs());
        overlay.accumulate(state_key, *amount);
    }
}

impl PerPeriodCapCriterion {
    /// Checks `attempted_stroops` against the rolling window for
    /// `criterion_asset`, combining the state-store-recorded total with any
    /// bundle overlay contribution.
    ///
    /// Called by the descriptor-driven path in `evaluate` after it resolves
    /// an `(asset, attempted_stroops)` pair.
    ///
    /// The decision arithmetic is `i128` end-to-end (no clamp): the
    /// state-store-recorded total (itself `i128`; see
    /// [`crate::policy::v1::criteria::state_store::PolicyStateStore`]) and the
    /// bundle overlay contribution are combined with `attempted_stroops` and
    /// compared against `self.max_stroops`, exact across the full `i128`
    /// range.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when [`SystemTime`]
    /// is before UNIX epoch, or the state store detects clock skew exceeding
    /// 30 seconds.
    fn check_window(
        &self,
        ctx: &EvalContext<'_>,
        criterion_asset: &str,
        attempted_stroops: i128,
    ) -> Result<Option<DenyReason>, PolicyError> {
        let now_ms = system_time_to_ms()?;

        let state_key = StateKey::new(
            ctx.profile_name,
            // Scope specificity 1 (AllProfiles) is the default; the dispatch
            // site can supply a narrower resolved specificity via EvalContext.
            // Defaulting to 1 avoids silently sharing state across scopes.
            1,
            criterion_asset,
            self.window.as_secs(),
        );

        let (period_used_stroops_recorded, _) = ctx
            .state_store
            .query_window(&state_key, now_ms)
            .map_err(|e| PolicyError::CriterionEvaluationFailed {
                detail: format!("per_period_cap: state store error: {e}"),
            })?;

        // Add any overlay amount accumulated from earlier inners in the same
        // multicall bundle.  On the single-tx path (bundle = None) the overlay
        // contributes 0.
        let bundle_accumulated_stroops: i128 = ctx
            .bundle
            .map(|view| view.overlay.get(&state_key))
            .unwrap_or(0);

        let period_used_stroops =
            period_used_stroops_recorded.saturating_add(bundle_accumulated_stroops);

        // Would-exceed check: period_used + attempted > max?
        let would_use = period_used_stroops.saturating_add(attempted_stroops);
        if would_use > self.max_stroops {
            return Ok(Some(DenyReason::PerPeriodCapExceeded {
                asset: self.asset.clone(),
                window: self.window.label().to_owned(),
                max_stroops: self.max_stroops,
                attempted_stroops,
                period_used_stroops,
            }));
        }

        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the current time as unix-milliseconds.
///
/// # Errors
///
/// Returns [`PolicyError::CriterionEvaluationFailed`] when `SystemTime::now()`
/// is before the UNIX epoch (should not occur on any supported platform).
fn system_time_to_ms() -> Result<u64, PolicyError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|e| PolicyError::CriterionEvaluationFailed {
            detail: format!("per_period_cap: system clock is before UNIX epoch: {e}"),
        })
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
            // Mirror the dispatch gate: derive the value descriptor the
            // criterion now reads through ctx.value.
            value: crate::policy::v1::value::derive_value_class(tool.name.as_str(), args),
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

    #[test]
    #[serial]
    fn empty_window_allows() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);
        let args = json!({ "amount": "100 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "empty window should allow");
    }

    #[test]
    #[serial]
    fn window_with_history_still_under_cap_allows() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);

        // Pre-seed 200 XLM spent (within a 1-day window).
        let key = StateKey::new("alice", 1, "native", 86_400);
        let now = system_time_to_ms().unwrap();
        store.append(&key, now - 1_000, 2_000_000_000).unwrap(); // 200 XLM

        // Try to spend another 100 XLM → total 300 XLM < 500 XLM cap.
        let args = json!({ "amount": "100 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "300 XLM total should be under 500 XLM cap"
        );
    }

    #[test]
    #[serial]
    fn would_exceed_cap_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);

        let key = StateKey::new("alice", 1, "native", 86_400);
        let now = system_time_to_ms().unwrap();
        // Pre-seed 450 XLM spent.
        store.append(&key, now - 1_000, 4_500_000_000).unwrap(); // 450 XLM

        // Try 100 XLM → total 550 XLM > 500 XLM cap.
        let args = json!({ "amount": "100 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "550 XLM total should be denied by a 500 XLM cap"
        );
    }

    #[test]
    #[serial]
    fn clock_skew_over_30s_returns_evaluation_failed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1h").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);

        let key = StateKey::new("alice", 1, "native", 3_600);
        let now = system_time_to_ms().unwrap();
        // Insert an entry 31 seconds in the future (clock skew violation).
        store.append(&key, now + 31_000, 1).unwrap();

        let args = json!({ "amount": "1 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "clock skew > 30s should return CriterionEvaluationFailed"
        );
    }

    #[test]
    #[serial]
    fn window_parse_rejects_unsupported_value() {
        let err = Window::parse("2d").unwrap_err();
        assert!(
            matches!(err, PolicyError::PolicyFileParseFailed { .. }),
            "unsupported window should return PolicyFileParseFailed"
        );
    }

    #[test]
    #[serial]
    fn asset_mismatch_criterion_does_not_apply() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);
        let args = json!({
            "amount": "100 XLM",
            "asset": "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "asset mismatch should not trigger criterion"
        );
    }

    #[test]
    #[serial]
    fn create_account_starting_balance_participates_in_period_cap() {
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let args = json!({ "starting_balance": "150 XLM" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();

        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "create-account starting_balance must be evaluated as native spend"
        );
    }

    #[test]
    #[serial]
    fn exact_period_cap_boundary_is_allowed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let args = json!({ "amount": "100 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();

        assert!(
            result.is_none(),
            "period cap is strict: attempted amount equal to cap is allowed"
        );
    }

    #[test]
    #[serial]
    fn exact_period_cap_boundary_with_existing_history_is_allowed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let key = StateKey::new("alice", 1, "native", w.as_secs());
        let now_ms = system_time_to_ms().unwrap();
        store.append(&key, now_ms, 1).unwrap();

        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let args = json!({ "amount": "99.9999999 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();

        assert!(
            result.is_none(),
            "period cap is strict: existing 1 stroop + attempted cap-1 is allowed"
        );
    }

    #[test]
    #[serial]
    fn xlm_configured_period_cap_matches_native_tool_asset() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("XLM".into(), w, 1_000_000_000);
        let args = json!({ "amount": "150 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();

        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "XLM and native must normalise to the same period-cap asset"
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
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);

        // Pre-seed 400 XLM in the state store.
        let key = StateKey::new("alice", 1, "native", 86_400);
        let now = system_time_to_ms().unwrap();
        store.append(&key, now - 1_000, 4_000_000_000).unwrap(); // 400 XLM

        // Single-tx attempt of 50 XLM — bundle=None should see 400+50=450 XLM total,
        // which is under the 500 XLM cap.
        let args = json!({ "amount": "50 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        // ctx.bundle is None via make_ctx.
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "bundle=None path must see zero overlay; 400+50=450 XLM < 500 XLM cap"
        );
    }

    /// Bundle path with non-zero overlay adds accumulated stroop total to the
    /// persisted window total.
    #[test]
    #[serial]
    fn evaluate_with_bundle_overlay_accumulated_stroops_added_to_window() {
        use crate::policy::v1::bundle::{BundleStateOverlay, BundleView};

        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 5_000_000_000);

        // Pre-seed 400 XLM in the state store.
        let key = StateKey::new("alice", 1, "native", 86_400);
        let now = system_time_to_ms().unwrap();
        store.append(&key, now - 1_000, 4_000_000_000).unwrap(); // 400 XLM

        // Overlay simulates 80 XLM already approved in earlier inners.
        let mut overlay = BundleStateOverlay::default();
        overlay.accumulate(key.clone(), 800_000_000); // 80 XLM
        let inners: Vec<crate::policy::v1::bundle::InnerOpDescriptor> = vec![];
        let view = BundleView {
            inners: &inners,
            overlay: &overlay,
        };

        // Attempt 50 XLM — effective total = 400 + 80 + 50 = 530 XLM > 500 XLM.
        let args = json!({ "amount": "50 XLM", "asset": "native" });
        let ctx = EvalContext {
            tool: &tool,
            args: &args,
            profile_name: "alice",
            profile: &profile,
            value: crate::policy::v1::value::derive_value_class(tool.name.as_str(), &args),
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
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { period_used_stroops, .. })
                if period_used_stroops == 4_800_000_000),
            "overlay 80 XLM + recorded 400 XLM = period_used=480 XLM; 480+50=530 > 500 must deny"
        );
    }

    // ── Real production args shapes (resolved-key re-point) ────────────────

    /// Simulate-time `stellar_pay` args_value shape when the caller used
    /// `amount_in_stroops`.
    #[test]
    #[serial]
    fn pay_simulate_amount_in_stroops_shape_cap_under_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 XLM
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "amount": serde_json::Value::Null,
            "amount_in_stroops": "500000000",
            "amount_stroops": "500000000",
            "asset": "native",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "50 XLM should pass a 100 XLM period cap");
    }

    /// Commit-time `stellar_pay_commit` authoritative_args shape, exactly as
    /// `envelope_decode::decode_authoritative_args` emits it.
    #[test]
    #[serial]
    fn pay_commit_authoritative_args_shape_cap_over_denies() {
        let tool = make_tool("stellar_pay_commit");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 XLM
        let args = json!({
            "source": "GAAA",
            "total_fee_stroops": 100u32,
            "destination": "GBBB",
            "amount_stroops": "1500000000",
            "asset": "XLM",
            "memo": serde_json::Value::Null,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "a 150 XLM commit must be denied by a 100 XLM period cap; the debit is sized \
             from 'amount_stroops', the only amount key authoritative_args carries: {result:?}"
        );
    }

    /// Simulate-time `stellar_create_account` args_value shape: ONLY
    /// `starting_balance_stroops` is ever present.
    #[test]
    #[serial]
    fn create_account_simulate_resolved_only_shape_cap_over_denies() {
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 XLM
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "starting_balance_stroops": "1500000000",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "150 XLM should be denied by a 100 XLM period cap; this is the pre-existing \
             fail-closed bug this re-point fixes: {result:?}"
        );
    }

    /// Commit-time `stellar_create_account_commit` authoritative_args shape.
    #[test]
    #[serial]
    fn create_account_commit_authoritative_args_shape_cap_over_denies() {
        let tool = make_tool("stellar_create_account_commit");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 XLM
        let args = json!({
            "source": "GAAA",
            "total_fee_stroops": 100u32,
            "destination": "GBBB",
            "starting_balance_stroops": "1500000000",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "150 XLM commit should be denied by a 100 XLM period cap: {result:?}"
        );
    }

    /// Regression: the legacy unit-string-only shape must still evaluate to
    /// the identical verdict as before this re-point.
    #[test]
    #[serial]
    fn legacy_amount_only_shape_still_evaluates_identically() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 XLM
        let args = json!({ "amount": "150 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "legacy-only shape must still deny 150 XLM against a 100 XLM period cap"
        );
    }

    /// Version-crossing: a resolved key carrying a legacy JSON number must
    /// still parse correctly.
    #[test]
    #[serial]
    fn version_crossing_numeric_amount_stroops_still_parses() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000); // 100 XLM
        let args = json!({ "amount_stroops": 1_500_000_000i64, "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "numeric amount_stroops must still be denied by the period cap"
        );
    }

    // ── Fail-closed value-descriptor matrix ─────────────────────────────────

    /// Constructs a `ToolDescriptor` with an explicit `value_kind` (rather
    /// than the fixed `ReadOnly` of [`make_tool`]).
    fn make_tool_with_kind(
        tool_name: &'static str,
        value_kind: crate::policy::ToolValueKind,
    ) -> ToolDescriptor {
        let reg = McpToolRegistration {
            name: tool_name,
            destructive_hint: true,
            read_only_hint: false,
            chain_id_required: true,
            value_kind,
        };
        ToolDescriptor::from_registration(&reg)
    }

    /// A `MovesValue` tool the descriptor derivation has not classified
    /// (`derive_value_class` falls through to `ReadOnly` for any name outside
    /// its match arms) must deny fail-closed rather than passing silently.
    #[test]
    #[serial]
    fn moves_value_tool_with_unpopulated_effects_denies_unsizable() {
        let tool = make_tool_with_kind(
            "stellar_blend_lend",
            crate::policy::ToolValueKind::MovesValue,
        );
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::UnsizableValueEffect { .. }))),
            "a MovesValue tool with no resolved effects must deny fail-closed, got {result:?}"
        );
    }

    /// An opaque-signing call on the single-tx path must deny fail-closed.
    #[test]
    #[serial]
    fn opaque_sign_call_denies_unsizable_on_single_tx() {
        let tool = make_tool("stellar_sep43_sign_transaction");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::UnsizableValueEffect { .. }))),
            "an opaque-signing call must deny fail-closed on the single-tx path, got {result:?}"
        );
    }

    /// A multi-leg native-asset value effect is aggregated per-asset: two
    /// legs individually under the cap must still deny when their sum exceeds
    /// it, with a fresh (empty) period window.
    #[test]
    #[serial]
    fn two_leg_native_value_aggregates_over_cap_denies() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_multicall");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        // Cap: 100 XLM. Each leg is 60 XLM (under cap individually); the
        // aggregate of 120 XLM must deny against an empty period window.
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let args = json!({});
        let leg_a = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(600_000_000),
            asset: Some("native".to_owned()),
            destination: Some("GAAA".to_owned()),
        };
        let leg_b = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(600_000_000),
            asset: Some("native".to_owned()),
            destination: Some("GBBB".to_owned()),
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_value(ValueClass::Value(ValueEffects::new(vec![leg_a, leg_b])));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { attempted_stroops, .. })
                if attempted_stroops == 1_200_000_000),
            "two 60 XLM legs must aggregate to 120 XLM and deny a 100 XLM period cap, \
             got {result:?}"
        );
    }

    /// A single debit leg carrying an i128 token quantity strictly greater
    /// than `i64::MAX` must be compared and reported without a lossy clamp,
    /// through the full `check_window` decision path (state-store total +
    /// overlay + attempted, all `i128`): the criterion denies and
    /// `attempted_stroops` carries the exact beyond-i64 value.
    #[test]
    #[serial]
    fn debit_leg_amount_beyond_i64_max_denies_without_clamp() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_multicall");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let beyond_i64_max: i128 = i128::from(i64::MAX) + 1_000;
        let cap: i128 = i128::from(i64::MAX);
        let criterion = PerPeriodCapCriterion::new("native".into(), w, cap);
        let args = json!({});
        let leg = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(beyond_i64_max),
            asset: Some("native".to_owned()),
            destination: Some("GAAA".to_owned()),
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_value(ValueClass::Value(ValueEffects::single(leg)));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded {
                attempted_stroops, max_stroops, period_used_stroops: 0, ..
            }) if attempted_stroops == beyond_i64_max && max_stroops == cap),
            "a debit beyond i64::MAX must deny with the exact i128 value, not a clamped \
             i64::MAX, got {result:?}"
        );
    }

    /// The period cap aggregates ONLY debit (outflow) legs; an inflow leg
    /// (`LendWithdraw`) is present in the descriptor but never summed into the
    /// window.
    #[test]
    #[serial]
    fn cap_aggregates_only_debit_legs_not_inflow_legs() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_blend_lend");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        // Cap 100 XLM, empty window. 60 XLM outflow (Lend) + 60 XLM inflow
        // (LendWithdraw). Summing both would deny; summing only the outflow is
        // 60 XLM and allows.
        let criterion = PerPeriodCapCriterion::new("native".into(), w, 1_000_000_000);
        let args = json!({});
        let outflow = ValueLeg {
            kind: ActionKind::Lend,
            amount: Some(600_000_000),
            asset: Some("native".to_owned()),
            destination: Some("CAAA".to_owned()),
        };
        let inflow = ValueLeg {
            kind: ActionKind::LendWithdraw,
            amount: Some(600_000_000),
            asset: Some("native".to_owned()),
            destination: Some("CAAA".to_owned()),
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_value(ValueClass::Value(ValueEffects::new(vec![outflow, inflow])));
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "the period cap must sum only the 60 XLM outflow leg, so a 100 XLM cap \
             allows the call, got {result:?}"
        );
    }

    /// Boundary test: a window total already recorded ABOVE `i64::MAX`
    /// (via real `PolicyStateStore::append` calls, simulating prior committed
    /// spend) is read back and combined with an attempted debit EXACTLY — no
    /// clamp, no fail-closed refusal at the store boundary. A cap set just
    /// below the exact resulting total denies with the precise
    /// `period_used_stroops` figure, proving the store no longer truncates
    /// silently at `i64::MAX`.
    #[test]
    #[serial]
    fn window_total_above_i64_max_denies_at_exact_cap_boundary() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_multicall");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();

        // Pre-record a window total strictly above i64::MAX.
        let recorded_total: i128 = i128::from(i64::MAX) + 1_000_000_000;
        let key = StateKey::new("alice", 1, "native", w.as_secs());
        let now_ms = system_time_to_ms().unwrap();
        store.append(&key, now_ms - 1_000, recorded_total).unwrap();

        // Cap set to exactly (recorded_total + attempted) - 1: the attempted
        // debit must tip it by exactly 1 stroop.
        let attempted: i128 = 500;
        let cap: i128 = recorded_total.saturating_add(attempted) - 1;
        let criterion = PerPeriodCapCriterion::new("native".into(), w, cap);
        let args = json!({});
        let leg = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(attempted),
            asset: Some("native".to_owned()),
            destination: Some("GAAA".to_owned()),
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_value(ValueClass::Value(ValueEffects::single(leg)));

        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded {
                period_used_stroops, attempted_stroops, ..
            }) if period_used_stroops == recorded_total && attempted_stroops == attempted),
            "a window total above i64::MAX must be read back and compared EXACTLY, \
             got {result:?}"
        );
    }

    /// Boundary test: a window total already recorded ABOVE `i64::MAX`
    /// still ALLOWS a further debit when the exact `i128` arithmetic keeps
    /// the resulting total under a (correspondingly large) cap — proving
    /// exact accounting works in both directions, not just the deny path.
    #[test]
    #[serial]
    fn window_total_above_i64_max_allows_when_still_under_cap() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_multicall");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();

        let recorded_total: i128 = i128::from(i64::MAX) + 1_000_000_000;
        let key = StateKey::new("alice", 1, "native", w.as_secs());
        let now_ms = system_time_to_ms().unwrap();
        store.append(&key, now_ms - 1_000, recorded_total).unwrap();

        // Cap set to exactly (recorded_total + attempted): the attempted debit
        // must land exactly AT the cap, which does not exceed it.
        let attempted: i128 = 500;
        let cap: i128 = recorded_total.saturating_add(attempted);
        let criterion = PerPeriodCapCriterion::new("native".into(), w, cap);
        let args = json!({});
        let leg = ValueLeg {
            kind: ActionKind::Payment,
            amount: Some(attempted),
            asset: Some("native".to_owned()),
            destination: Some("GAAA".to_owned()),
        };
        let ctx = EvalContext::new(&tool, &args, "alice", &profile, &store)
            .with_value(ValueClass::Value(ValueEffects::single(leg)));

        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "a debit landing exactly at the cap (both operands above i64::MAX) must \
             allow under exact i128 arithmetic, got {result:?}"
        );
    }
}
