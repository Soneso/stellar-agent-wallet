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
use crate::policy::v1::criteria::amount_extract::extract_pay_or_create_account_stroops;
use crate::policy::v1::criteria::state_store::StateKey;
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

        let (attempted_stroops, tool_asset) = match tool_name {
            "stellar_pay" | "stellar_pay_commit" => {
                let asset_str = extract_string_field(ctx, "asset")?;
                let stroops = extract_pay_or_create_account_stroops(ctx, "per_period_cap")?
                    .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                        detail: format!(
                            "per_period_cap: missing amount_stroops/amount field for tool '{tool_name}'"
                        ),
                    })?;
                (stroops, asset_normalise(asset_str))
            }
            "stellar_create_account" | "stellar_create_account_commit" => {
                let stroops = extract_pay_or_create_account_stroops(ctx, "per_period_cap")?
                    .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                        detail: format!(
                            "per_period_cap: missing starting_balance_stroops/starting_balance \
                             field for tool '{tool_name}'"
                        ),
                    })?;
                (stroops, "native".to_owned())
            }
            "stellar_axelar_bridge" => {
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
                                 in args for tool '{}'",
                            ctx.tool.name
                        ),
                    })?;
                let token_address = extract_string_field(ctx, "token_address")?;
                (qty_val, token_address)
            }
            _ => return Ok(None),
        };

        let criterion_asset = asset_normalise(self.asset.clone());
        if criterion_asset != tool_asset {
            return Ok(None);
        }
        let now_ms = system_time_to_ms()?;

        let state_key = StateKey::new(
            ctx.profile_name,
            // Scope specificity 1 (AllProfiles) is the default; the dispatch
            // site can supply a narrower resolved specificity via EvalContext.
            // Defaulting to 1 avoids silently sharing state across scopes.
            1,
            &criterion_asset,
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

        let criterion_asset = asset_normalise(self.asset.clone());
        let inner_asset = asset_normalise(asset.clone());
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

fn asset_normalise(asset: String) -> String {
    if asset.eq_ignore_ascii_case("native") || asset.eq_ignore_ascii_case("xlm") {
        "native".to_owned()
    } else {
        asset
    }
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
            "150 XLM commit should be denied by a 100 XLM period cap; this is the \
             pre-existing fail-closed bug this re-point fixes (authoritative_args never \
             carried 'amount', only 'amount_stroops'): {result:?}"
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
}
