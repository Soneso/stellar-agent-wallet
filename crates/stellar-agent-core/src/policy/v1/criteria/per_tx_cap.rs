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
//! directly against `max_stroops` without decimal parsing.
//!
//! For other tools: the criterion returns `Ok(None)` (does not apply).
//!

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::v1::value::{ValueGate, asset_normalise, classify_value};
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

        let criterion_asset = asset_normalise(&self.asset);

        // Legacy args-based arm for the not-yet-migrated `stellar_axelar_bridge`
        // (an unregistered dead arm removed in #22). Reached only for that name;
        // every classified tool is sized through the value descriptor below.
        if tool_name == "stellar_axelar_bridge" {
            let qty_val = ctx
                .args
                .get("qty")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "per_tx_cap: missing or non-integer field 'qty' in args for tool \
                         '{tool_name}'"
                    ),
                })?;
            let token_address = extract_string_field(ctx, "token_address")?;
            if criterion_asset != token_address {
                return Ok(None);
            }
            if qty_val > self.max_stroops {
                return Ok(Some(DenyReason::PerTxCapExceeded {
                    asset: self.asset.clone(),
                    max_stroops: self.max_stroops,
                    attempted_stroops: qty_val,
                }));
            }
            return Ok(None);
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
                            "per_tx_cap: debit leg of tool '{tool_name}' carries no asset"
                        ),
                    })?;
            if asset_normalise(leg_asset) != criterion_asset {
                continue;
            }
            let amount = leg
                .amount
                .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                    detail: format!(
                        "per_tx_cap: unresolvable amount for a debit leg of tool '{tool_name}'"
                    ),
                })?;
            matched = true;
            sum = sum.saturating_add(amount);
        }

        // The configured asset is not moved by this call — criterion not applicable.
        if !matched {
            return Ok(None);
        }

        if sum > i128::from(self.max_stroops) {
            return Ok(Some(DenyReason::PerTxCapExceeded {
                asset: self.asset.clone(),
                max_stroops: self.max_stroops,
                // The decision is made in i128; only the reported figure on the
                // deny path saturates to i64. Widening the DenyReason payload to
                // i128 is a later step.
                attempted_stroops: i64::try_from(sum).unwrap_or(i64::MAX),
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
            // Mirror the dispatch gate: derive the value descriptor from the
            // same args the criterion now reads through ctx.value.
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

    // ── Real production args shapes (resolved-key re-point) ────────────────

    /// Simulate-time `stellar_pay` args_value shape when the caller used
    /// `amount_in_stroops` (exact fields `stellar_pay`'s handler emits).
    #[test]
    fn pay_simulate_amount_in_stroops_shape_cap_under_passes() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
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
        assert!(result.is_none(), "50 XLM should pass a 100 XLM cap");
    }

    #[test]
    fn pay_simulate_amount_in_stroops_shape_cap_over_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "amount": serde_json::Value::Null,
            "amount_in_stroops": "1500000000",
            "amount_stroops": "1500000000",
            "asset": "native",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "150 XLM should be denied by a 100 XLM cap"
        );
    }

    /// A cap configured for a NON-native asset must apply and deny on a pay
    /// simulate args_value carrying that same asset — pins the asset-match
    /// branch through the resolved `amount_stroops` key (not just the
    /// legacy-shape tests above, which only exercise the native path).
    #[test]
    fn pay_simulate_non_native_asset_cap_over_denies() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let usdc_asset = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        let criterion = PerTxCapCriterion::new(usdc_asset.to_owned(), 1_000_000_000); // 100 USDC
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "amount": serde_json::Value::Null,
            "amount_in_stroops": "1500000000",
            "amount_stroops": "1500000000",
            "asset": usdc_asset,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "150 USDC should be denied by a 100 USDC cap on the matching non-native asset: \
             {result:?}"
        );
    }

    /// A cap configured for a DIFFERENT non-native asset must not apply to a
    /// pay simulate args_value carrying a distinct asset — the asset mismatch
    /// branch is still reachable through the resolved key.
    #[test]
    fn pay_simulate_non_native_asset_mismatch_does_not_apply() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let usdc_asset = "USDC:GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        let other_asset = "EURC:GDHU6WRG4IEQXM5NZ4BMPKOXHW76MZM4Y2IEMFDVXBSDP6SJY4ITNPP2";
        let criterion = PerTxCapCriterion::new(usdc_asset.to_owned(), 1_000_000_000);
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "amount": serde_json::Value::Null,
            "amount_in_stroops": "9999999999",
            "amount_stroops": "9999999999",
            "asset": other_asset,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "a cap configured for USDC must not apply to an EURC payment: {result:?}"
        );
    }

    /// Commit-time `stellar_pay_commit` authoritative_args shape, exactly as
    /// `envelope_decode::decode_authoritative_args` emits it: no legacy
    /// "amount" key at all, `total_fee_stroops` numeric, `asset` present.
    #[test]
    fn pay_commit_authoritative_args_shape_cap_under_passes() {
        let tool = make_tool("stellar_pay_commit");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({
            "source": "GAAA",
            "total_fee_stroops": 100u32,
            "destination": "GBBB",
            "amount_stroops": "500000000",
            "asset": "XLM",
            "memo": serde_json::Value::Null,
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "50 XLM commit should pass a 100 XLM cap");
    }

    #[test]
    fn pay_commit_authoritative_args_shape_cap_over_denies() {
        let tool = make_tool("stellar_pay_commit");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
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
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "a 150 XLM commit must be denied by a 100 XLM cap; the descriptor sizes the \
             debit from 'amount_stroops', the only amount key authoritative_args carries"
        );
    }

    /// Simulate-time `stellar_create_account` args_value shape: ONLY
    /// `starting_balance_stroops` is ever present — the legacy
    /// `starting_balance` key never appears in production args.
    #[test]
    fn create_account_simulate_resolved_only_shape_cap_under_passes() {
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "starting_balance_stroops": "500000000",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "50 XLM should pass a 100 XLM cap");
    }

    #[test]
    fn create_account_simulate_resolved_only_shape_cap_over_denies() {
        let tool = make_tool("stellar_create_account");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({
            "chain_id": "stellar:testnet",
            "source": "GAAA",
            "destination": "GBBB",
            "starting_balance_stroops": "1500000000",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "150 XLM must be denied by a 100 XLM cap; the descriptor sizes the debit from \
             'starting_balance_stroops', the only amount key create_account args carry"
        );
    }

    /// Commit-time `stellar_create_account_commit` authoritative_args shape.
    #[test]
    fn create_account_commit_authoritative_args_shape_cap_over_denies() {
        let tool = make_tool("stellar_create_account_commit");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({
            "source": "GAAA",
            "total_fee_stroops": 100u32,
            "destination": "GBBB",
            "starting_balance_stroops": "1500000000",
        });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "150 XLM commit should be denied by a 100 XLM cap"
        );
    }

    /// Regression: the legacy unit-string-only shape (no resolved key present
    /// at all) must still evaluate to the identical verdict as before this
    /// re-point.
    #[test]
    fn legacy_amount_only_shape_still_evaluates_identically() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({ "amount": "150 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "legacy-only shape must still deny 150 XLM against a 100 XLM cap"
        );
    }

    /// Version-crossing: a resolved key carrying a legacy JSON number (rather
    /// than the current decimal-string encoding) must still parse correctly.
    #[test]
    fn version_crossing_numeric_amount_stroops_still_parses() {
        let tool = make_tool("stellar_pay");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000); // 100 XLM
        let args = json!({ "amount_stroops": 1_500_000_000i64, "asset": "native" });
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::PerTxCapExceeded { .. })),
            "numeric amount_stroops must still be denied by the cap"
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
    /// its match arms) must deny fail-closed rather than passing silently —
    /// this is a forgotten/failed population, not a legitimate no-op.
    #[test]
    fn moves_value_tool_with_unpopulated_effects_denies_unsizable() {
        let tool = make_tool_with_kind(
            "stellar_blend_lend",
            crate::policy::ToolValueKind::MovesValue,
        );
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
        let args = json!({});
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx);
        assert!(
            matches!(result, Ok(Some(DenyReason::UnsizableValueEffect { .. }))),
            "a MovesValue tool with no resolved effects must deny fail-closed, got {result:?}"
        );
    }

    /// An opaque-signing call (raw transaction / auth-entry XDR) on the
    /// single-tx path must deny fail-closed: the wallet cannot size a value
    /// cap against material it does not decode.
    #[test]
    fn opaque_sign_call_denies_unsizable_on_single_tx() {
        let tool = make_tool("stellar_sep43_sign_transaction");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
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
    /// it.
    #[test]
    fn two_leg_native_value_aggregates_over_cap_denies() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_multicall");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // Cap: 100 XLM. Each leg is 60 XLM (under cap individually); the
        // aggregate of 120 XLM must deny.
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
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
            matches!(result, Some(DenyReason::PerTxCapExceeded { attempted_stroops, .. })
                if attempted_stroops == 1_200_000_000),
            "two 60 XLM legs must aggregate to 120 XLM and deny a 100 XLM cap, got {result:?}"
        );
    }

    #[test]
    fn cap_aggregates_only_debit_legs_not_inflow_legs() {
        use crate::policy::v1::value::{ActionKind, ValueClass, ValueEffects, ValueLeg};

        let tool = make_tool("stellar_blend_lend");
        let profile = make_profile();
        let store = PolicyStateStore::new();
        // Cap 100 XLM. One 60 XLM outflow (Lend) + one 60 XLM inflow
        // (LendWithdraw), same asset. Summing both would be 120 XLM and deny;
        // summing only the debit (outflow) leg is 60 XLM and allows. The cap
        // must size ONLY the outflow, so the call is allowed.
        let criterion = PerTxCapCriterion::new("native".into(), 1_000_000_000);
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
            "the per-tx cap must sum only the 60 XLM outflow leg (not the 60 XLM \
             inflow leg), so a 100 XLM cap allows the call, got {result:?}"
        );
    }
}
