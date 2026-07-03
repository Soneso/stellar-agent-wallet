//! Per-transaction amount cap criterion.
//!
//! [`PerTxCapCriterion`] enforces that a single tool call does not transfer
//! more than a configured maximum in stroops for a given asset.  The criterion
//! matches only when the tool's asset matches the configured asset; if the
//! assets differ the criterion returns `Ok(None)` (does not apply).
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "per_tx_cap", asset = "native", max_stroops = 1000_0000000 }
//! { kind = "per_tx_cap", asset = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", max_stroops = 100_0000000 }
//! ```
//!
//! # Tool argument parsing
//!
//! For `stellar_pay`: reads `args["amount"]` (a `"N.NNNNNNN XLM"` string) and
//! `args["asset"]` (e.g. `"native"` or `"CODE:Gissuer"`).
//!
//! For `stellar_create_account`: reads `args["starting_balance"]` and treats
//! the asset as implicitly native.
//!
//! For `stellar_axelar_bridge`: reads `args["qty"]` (a raw i128 on-chain
//! integer) and `args["token_address"]` (the resolved C-strkey from the
//! token-egress pin, injected at dispatch time).  The raw integer is compared
//! directly against `max_stroops` without decimal parsing.
//!
//! For other tools: the criterion returns `Ok(None)` (does not apply).
//!

use crate::amount::StellarAmount;
use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// PerTxCapCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Per-transaction amount cap criterion.
///
/// Checks that the attempted transfer in a single tool call does not exceed
/// `max_stroops` for the configured `asset`.  Returns `Ok(None)` when the
/// criterion does not apply to the current tool or asset.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = PerTxCapCriterion::new("native".into(), 1_000_0000000);
/// assert_eq!(criterion.kind(), "per_tx_cap");
/// ```
#[derive(Debug, Clone)]
pub struct PerTxCapCriterion {
    /// The asset this cap applies to.  `"native"` for XLM; `"CODE:Gissuer"`
    /// for non-native assets.
    asset: String,
    /// The maximum allowed amount in stroops for a single transaction.
    max_stroops: i64,
}

impl PerTxCapCriterion {
    /// Constructs a new [`PerTxCapCriterion`].
    ///
    /// `asset` is `"native"` for XLM or `"CODE:G…ISSUER"` for a non-native
    /// asset.  `max_stroops` is the per-transaction ceiling inclusive:
    /// an `attempted_stroops == max_stroops` is **allowed**; only
    /// `attempted_stroops > max_stroops` is denied.
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::per_tx_cap::PerTxCapCriterion;
    ///
    /// let cap = PerTxCapCriterion::new("native".into(), 5_000_0000000);
    /// assert_eq!(cap.max_stroops(), 5_000_0000000);
    /// ```
    #[must_use]
    pub fn new(asset: String, max_stroops: i64) -> Self {
        Self { asset, max_stroops }
    }

    /// Returns the configured maximum in stroops.
    #[must_use]
    pub fn max_stroops(&self) -> i64 {
        self.max_stroops
    }

    /// Returns the configured asset identifier.
    #[must_use]
    pub fn asset(&self) -> &str {
        &self.asset
    }
}

impl Criterion for PerTxCapCriterion {
    fn kind(&self) -> &'static str {
        "per_tx_cap"
    }

    /// Evaluates the per-transaction cap against the current tool call.
    ///
    /// Returns `Ok(None)` when the criterion does not apply (tool not
    /// recognised, or tool's asset does not match the configured asset).
    /// Returns `Ok(Some(DenyReason::PerTxCapExceeded { … }))` when the
    /// attempted amount exceeds `max_stroops`.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when the required
    /// argument field is missing or cannot be parsed as a valid Stellar amount.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let tool_name = ctx.tool.name.as_str();

        // Extract (attempted_stroops, tool_asset) per tool type.
        let (attempted_stroops, tool_asset) = match tool_name {
            "stellar_pay" | "stellar_pay_commit" => {
                let amount_str = extract_string_field(ctx, "amount")?;
                let asset_str = extract_string_field(ctx, "asset")?;
                let stroops = parse_amount_to_stroops(&amount_str, ctx)?;
                (stroops, asset_normalise(asset_str))
            }
            "stellar_create_account" | "stellar_create_account_commit" => {
                let amount_str = extract_string_field(ctx, "starting_balance")?;
                let stroops = parse_amount_to_stroops(&amount_str, ctx)?;
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
                            "per_tx_cap: missing or non-integer field 'qty' \
                                 in args for tool '{}'",
                            ctx.tool.name
                        ),
                    })?;
                let token_address = extract_string_field(ctx, "token_address")?;
                (qty_val, token_address)
            }
            _ => {
                // Criterion does not apply to other tools.
                return Ok(None);
            }
        };

        // Normalise the configured asset for comparison.
        let criterion_asset = asset_normalise(self.asset.clone());

        // Asset mismatch — criterion does not apply.
        if criterion_asset != tool_asset {
            return Ok(None);
        }

        if attempted_stroops > self.max_stroops {
            return Ok(Some(DenyReason::PerTxCapExceeded {
                asset: self.asset.clone(),
                max_stroops: self.max_stroops,
                attempted_stroops,
            }));
        }

        Ok(None)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts a string field from `ctx.args`.
///
/// Returns `PolicyError::CriterionEvaluationFailed` when the field is missing
/// or is not a JSON string.
fn extract_string_field(ctx: &EvalContext<'_>, field: &str) -> Result<String, PolicyError> {
    ctx.args
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
            detail: format!(
                "per_tx_cap: missing or non-string field '{}' in args for tool '{}'",
                field, ctx.tool.name
            ),
        })
}

/// Parses an amount string to stroops.
///
/// The amount can be either:
/// - `"N.NNNNNNN XLM"` (decimal XLM string from `stellar_pay` args).
/// - A bare stroop integer string (uncommon; forward-compat).
///
/// Prefers `StellarAmount::parse_with_unit` which handles the decimal form.
/// Falls back to `StellarAmount::parse_stroops` for bare integers.
fn parse_amount_to_stroops(amount_str: &str, ctx: &EvalContext<'_>) -> Result<i64, PolicyError> {
    // Try the unit-bearing form first ("N.NNNNNNN XLM").
    if let Ok(amt) = StellarAmount::parse_with_unit(amount_str) {
        return Ok(amt.as_stroops());
    }

    // Try bare stroop integer.
    StellarAmount::parse_stroops(amount_str)
        .map(|a| a.as_stroops())
        .map_err(|e| PolicyError::CriterionEvaluationFailed {
            detail: format!(
                "per_tx_cap: failed to parse amount '{}' for tool '{}': {e}",
                amount_str, ctx.tool.name
            ),
        })
}

/// Normalises an asset identifier to lowercase `"native"` for XLM, or
/// leaves non-native assets as-is (uppercased `CODE:Gissuer` is
/// preserved verbatim for allowlist matching).
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

    use serde_json::json;

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
    fn native_cap_not_exceeded_returns_none() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({ "amount": "50 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "50 XLM should pass a 100 XLM cap");
    }

    #[test]
    fn native_cap_exceeded_returns_deny() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({ "amount": "150 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "150 XLM should be denied by a 100 XLM cap"
        );
    }

    #[test]
    fn wrong_asset_criterion_does_not_apply() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // Cap is configured for "native" but payment is in USDC.
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
        let args = json!({
            "amount": "50 XLM",
            "asset": "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "USDC payment should not be matched by a native cap"
        );
    }

    #[test]
    fn asset_getter_returns_configured_native_asset() {
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);

        assert_eq!(criterion.asset(), "native");
    }

    #[test]
    fn asset_getter_returns_configured_non_native_asset() {
        let asset = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        let criterion = PerTxCapCriterion::new(asset.to_owned(), 1_000_000_000);

        assert_eq!(criterion.asset(), asset);
    }

    #[test]
    fn xlm_configured_cap_matches_native_tool_asset() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("XLM".into(), 1_000_000_000);
        let args = json!({ "amount": "150 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();

        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "XLM and native must normalise to the same policy asset"
        );
    }

    #[test]
    fn invalid_amount_returns_evaluation_failed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
        let args = json!({ "amount": "not-a-number", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "invalid amount should return CriterionEvaluationFailed"
        );
    }

    #[test]
    fn create_account_with_starting_balance_applies_native_cap() {
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({ "starting_balance": "200 XLM" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "200 XLM starting_balance should be denied by a 100 XLM cap"
        );
    }

    #[test]
    fn cap_at_exact_max_is_allowed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({ "amount": "100 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "amount == max_stroops should be allowed (inclusive bound)"
        );
    }

    #[test]
    fn unknown_tool_criterion_does_not_apply() {
        let tool = make_tool("stellar_balances");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "unknown tool should not trigger the criterion"
        );
    }

    #[test]
    fn missing_amount_field_returns_evaluation_failed() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
        // No "amount" field.
        let args = json!({ "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "missing amount field should return CriterionEvaluationFailed"
        );
    }

    // ── stellar_axelar_bridge path ────────────────────────────────────────────

    const USDC_TOKEN_ADDRESS: &str = "CBIELTK6YBZJU5UP2WWQEUCYKLPU6AUNZ2BQ4WWFEIE3USCIHMXQDAMA";

    #[test]
    fn bridge_qty_within_cap_returns_none() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // Cap: 1000 USDC (7 decimals) = 10_000_000_000 base units.
        let criterion = PerTxCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), 10_000_000_000);
        let args = json!({
            "qty": 5_000_000_000i64, // 500 USDC
            "token_address": USDC_TOKEN_ADDRESS,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "qty within cap must pass: {result:?}");
    }

    #[test]
    fn bridge_qty_over_cap_returns_deny() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), 10_000_000_000);
        let args = json!({
            "qty": 10_010_000_000i64, // 1001 USDC — just over cap
            "token_address": USDC_TOKEN_ADDRESS,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "qty over cap must deny: {result:?}"
        );
    }

    #[test]
    fn bridge_token_address_mismatch_criterion_does_not_apply() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // Cap configured for USDC, but bridge uses a different token.
        let criterion = PerTxCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), 10_000_000_000);
        let args = json!({
            "qty": 99_990_000_000i64,
            "token_address": "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "token address mismatch must not trigger criterion: {result:?}"
        );
    }

    #[test]
    fn bridge_missing_qty_returns_evaluation_failed() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), 10_000_000_000);
        // No "qty" field.
        let args = json!({ "token_address": USDC_TOKEN_ADDRESS });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Err(PolicyError::CriterionEvaluationFailed { .. })),
            "missing qty must return CriterionEvaluationFailed: {result:?}"
        );
    }

    #[test]
    fn bridge_qty_at_cap_limit_passes() {
        let tool = make_tool("stellar_axelar_bridge");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new(USDC_TOKEN_ADDRESS.to_owned(), 10_000_000_000);
        let args = json!({
            "qty": 10_000_000_000i64, // exactly at cap
            "token_address": USDC_TOKEN_ADDRESS,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "qty == cap must pass (inclusive bound): {result:?}"
        );
    }
}
