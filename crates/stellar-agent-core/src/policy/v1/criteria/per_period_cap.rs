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
//! For `stellar_axelar_bridge`: reads `args["qty"]` (a raw i128 on-chain
//! integer) and `args["token_address"]` (the resolved C-strkey from the
//! token-egress pin, injected at dispatch time).  The raw integer is compared
//! directly against the period total without decimal parsing.
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
    max_stroops: i64,
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

        // Legacy args-based arm for the not-yet-migrated `stellar_axelar_bridge`
        // (an unregistered dead arm removed in #22). Reached only for that name;
        // every classified tool is sized through the value descriptor below.
        if tool_name == "stellar_axelar_bridge" {
            // `qty` is an on-chain i128 integer (not a unit-bearing string).
            // `token_address` is the resolved C-strkey from the token-egress
            // pin, injected by the dispatch site alongside qty.
            let qty_val = ctx
                .args
                .get("qty")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "per_period_cap: missing or non-integer field 'qty' \
                             in args for tool '{tool_name}'"
                    ),
                })?;
            let token_address = extract_string_field(ctx, "token_address")?;
            if criterion_asset != token_address {
                return Ok(None);
            }
            return self.check_window(ctx, &criterion_asset, qty_val);
        }

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

        let attempted_stroops = i64::try_from(sum).unwrap_or(i64::MAX);
        self.check_window(ctx, &criterion_asset, attempted_stroops)
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
    /// Amount is cast `i128 → i64` via saturating cast (over-deny direction on
    /// overflow).
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
        // Saturating cast: over-deny on i128 > i64::MAX is the correct security posture.
        let attempted_stroops = i64::try_from(*amount).unwrap_or(i64::MAX);
        overlay.accumulate(state_key, attempted_stroops);
    }
}

impl PerPeriodCapCriterion {
    /// Checks `attempted_stroops` against the rolling window for
    /// `criterion_asset`, combining the state-store-recorded total with any
    /// bundle overlay contribution.
    ///
    /// Shared by both the legacy `stellar_axelar_bridge` args arm and the
    /// descriptor-driven path in `evaluate` — both resolve an
    /// `(asset, attempted_stroops)` pair upstream and then check it against
    /// the identical window/overlay logic.
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
        attempted_stroops: i64,
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
        let bundle_accumulated_stroops: i64 = ctx
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

fn extract_string_field(ctx: &EvalContext<'_>, field: &str) -> Result<String, PolicyError> {
    ctx.args
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
            detail: format!(
                "per_period_cap: missing or non-string field '{}' in args for tool '{}'",
                field, ctx.tool.name
            ),
        })
}

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

    // ── stellar_axelar_bridge path ────────────────────────────────────────────

    const USDC_TOKEN_ADDRESS: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

    #[test]
    #[serial]
    fn bridge_empty_window_allows() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        // Cap: 1000 USDC (7 decimals) = 10_000_000_000 base units.
        let criterion =
            PerPeriodCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), w, 10_000_000_000);
        let args = json!({
            "qty": 1_000_000_000i64, // 100 USDC
            "token_address": USDC_TOKEN_ADDRESS,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "empty window must allow: {result:?}");
    }

    #[test]
    #[serial]
    fn bridge_qty_over_period_cap_denies() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion =
            PerPeriodCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), w, 10_000_000_000);

        let key = StateKey::new("alice", 1, USDC_TOKEN_ADDRESS, 86_400);
        let now = system_time_to_ms().unwrap();
        store.append(&key, now - 1_000, 9_000_000_000).unwrap(); // 900 USDC already spent

        // Try 200 USDC (2_000_000_000) → total 1100 USDC > 1000 USDC cap.
        let args = json!({
            "qty": 2_000_000_000i64,
            "token_address": USDC_TOKEN_ADDRESS,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerPeriodCapExceeded { .. })),
            "900+200=1100 USDC must be denied by 1000 USDC period cap: {result:?}"
        );
    }

    #[test]
    #[serial]
    fn bridge_token_address_mismatch_criterion_does_not_apply() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion =
            PerPeriodCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), w, 10_000_000_000);
        // Different token address.
        let args = json!({
            "qty": 99_990_000_000i64,
            "token_address": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "token address mismatch must not trigger period criterion: {result:?}"
        );
    }

    #[test]
    #[serial]
    fn bridge_missing_qty_returns_evaluation_failed() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let w = Window::parse("1d").unwrap();
        let criterion =
            PerPeriodCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), w, 10_000_000_000);
        let args = json!({ "token_address": USDC_TOKEN_ADDRESS });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "missing qty must return CriterionEvaluationFailed: {result:?}"
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
}
