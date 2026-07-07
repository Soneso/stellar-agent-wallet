//! Soroban resource-fee and footprint-entry cap criterion.
//!
//! [`SorobanResourceFeeCriterion`] limits the resource fee and footprint-entry
//! count allowed for Soroban contract invocations.
//!
//! # Soroban tool scope
//!
//! Classic (non-Soroban) tools such as `stellar_pay`, `stellar_create_account`,
//! and `stellar_balances` return `Ok(None)` from this criterion.  Actual gating
//! applies only to tools whose names start with `"stellar_invoke"`.
//!
//! # Soroban tool detection heuristic
//!
//! A tool is treated as Soroban if its `name` starts with `"stellar_invoke"`.
//! All other tools are treated as non-Soroban and pass through.
//!
//! # TOML shape
//!
//! ```toml
//! { kind = "soroban_resource_fee_cap", max_resource_fee_stroops = 100_000_000, max_footprint_entries = 50 }
//! ```
//!

use crate::policy::v1::EvalContext;
use crate::policy::v1::criteria::Criterion;
use crate::policy::{DenyReason, PolicyError};

// ─────────────────────────────────────────────────────────────────────────────
// SorobanResourceFeeCriterion
// ─────────────────────────────────────────────────────────────────────────────

/// Soroban resource-fee and footprint-entry cap criterion.
///
/// Returns `Ok(None)` for all non-Soroban tools.  For Soroban tools (name
/// starts with `"stellar_invoke"`), evaluates the resource fee and
/// footprint-entry count against the configured caps.
///
/// # Examples
///
/// ```
/// use stellar_agent_core::policy::v1::criteria::soroban_resource_fee::SorobanResourceFeeCriterion;
/// use stellar_agent_core::policy::v1::criteria::Criterion;
///
/// let criterion = SorobanResourceFeeCriterion::new(100_000_000, 50);
/// assert_eq!(criterion.kind(), "soroban_resource_fee_cap");
/// assert_eq!(criterion.max_resource_fee_stroops(), 100_000_000);
/// assert_eq!(criterion.max_footprint_entries(), 50);
/// ```
#[derive(Debug, Clone)]
pub struct SorobanResourceFeeCriterion {
    /// Maximum resource fee allowed in stroops.
    max_resource_fee_stroops: i64,
    /// Maximum number of footprint entries allowed.
    max_footprint_entries: u32,
}

impl SorobanResourceFeeCriterion {
    /// Constructs a new [`SorobanResourceFeeCriterion`].
    ///
    /// # Examples
    ///
    /// ```
    /// use stellar_agent_core::policy::v1::criteria::soroban_resource_fee::SorobanResourceFeeCriterion;
    ///
    /// let criterion = SorobanResourceFeeCriterion::new(100_000_000, 50);
    /// assert_eq!(criterion.max_resource_fee_stroops(), 100_000_000);
    /// assert_eq!(criterion.max_footprint_entries(), 50);
    /// ```
    #[must_use]
    pub fn new(max_resource_fee_stroops: i64, max_footprint_entries: u32) -> Self {
        Self {
            max_resource_fee_stroops,
            max_footprint_entries,
        }
    }

    /// Returns the configured maximum resource fee in stroops.
    #[must_use]
    pub fn max_resource_fee_stroops(&self) -> i64 {
        self.max_resource_fee_stroops
    }

    /// Returns the configured maximum footprint entry count.
    #[must_use]
    pub fn max_footprint_entries(&self) -> u32 {
        self.max_footprint_entries
    }
}

impl Criterion for SorobanResourceFeeCriterion {
    fn kind(&self) -> &'static str {
        "soroban_resource_fee_cap"
    }

    /// Evaluates the Soroban resource-fee and footprint-entry cap.
    ///
    /// For non-Soroban tools, returns `Ok(None)`.  For Soroban tools
    /// (`stellar_invoke` and related), evaluates the `resource_fee_stroops`
    /// and `footprint_entries` fields from `ctx.args` against the configured
    /// caps.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CriterionEvaluationFailed`] when a Soroban
    /// tool's `resource_fee_stroops` or `footprint_entries` field is missing
    /// or has an invalid type.
    fn evaluate(&self, ctx: &EvalContext<'_>) -> Result<Option<DenyReason>, PolicyError> {
        let tool_name = ctx.tool.name.as_str();

        // Soroban tool iff its name starts with "stellar_invoke".
        if !tool_name.starts_with("stellar_invoke") {
            // Non-Soroban tool — criterion does not apply.
            return Ok(None);
        }

        // ── Soroban evaluation path ───────────────────────────────────────────
        // Reached only for stellar_invoke tools.

        let resource_fee_stroops = ctx
            .args
            .get("resource_fee_stroops")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "soroban_resource_fee_cap: missing or non-integer \
                     'resource_fee_stroops' field in args for tool '{}'",
                    tool_name
                ),
            })?;

        let footprint_entries = ctx
            .args
            .get("footprint_entries")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "soroban_resource_fee_cap: missing or out-of-range \
                     'footprint_entries' field in args for tool '{}'",
                    tool_name
                ),
            })?;

        if resource_fee_stroops > self.max_resource_fee_stroops {
            return Ok(Some(DenyReason::EvaluationError {
                detail: format!(
                    "soroban_resource_fee_cap: resource_fee_stroops {} exceeds \
                     max_resource_fee_stroops {}",
                    resource_fee_stroops, self.max_resource_fee_stroops
                ),
            }));
        }

        if footprint_entries > self.max_footprint_entries {
            return Ok(Some(DenyReason::EvaluationError {
                detail: format!(
                    "soroban_resource_fee_cap: footprint_entries {} exceeds \
                     max_footprint_entries {}",
                    footprint_entries, self.max_footprint_entries
                ),
            }));
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

    use serde_json::json;

    use super::*;
    use crate::policy::v1::criteria::state_store::PolicyStateStore;
    use crate::policy::{McpToolRegistration, ToolDescriptor};
    use crate::profile::schema::Profile;

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

    fn make_profile() -> Profile {
        Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build()
    }

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

    #[test]
    fn non_soroban_tool_returns_none() {
        let store = PolicyStateStore::new();
        let criterion = SorobanResourceFeeCriterion::new(100_000_000, 50);
        for tool_name in &["stellar_pay", "stellar_create_account", "stellar_balances"] {
            let args = json!({});
            // Use a local variable to avoid dangling references.
            let tool_reg = McpToolRegistration {
                name: tool_name,
                destructive_hint: false,
                read_only_hint: false,
                chain_id_required: false,
                value_kind: crate::policy::ToolValueKind::ReadOnly,
            };
            let tool = ToolDescriptor::from_registration(&tool_reg);
            let profile = Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build();
            let ctx = EvalContext {
                tool: &tool,
                args: &args,
                profile_name: "alice",
                profile: &profile,
                value: crate::policy::v1::value::ValueClass::ReadOnly,
                account_view: None,
                identity_view: None,
                quorum: None,
                counterparty_cache: None,
                sep10_sessions: None,
                sep45_sessions: None,
                state_store: &store,
                bundle: None,
            };
            let result = criterion.evaluate(&ctx).unwrap();
            assert!(
                result.is_none(),
                "non-Soroban tool '{}' should return Ok(None)",
                tool_name
            );
        }
    }

    #[test]
    fn soroban_tool_within_caps_passes() {
        let store = PolicyStateStore::new();
        let criterion = SorobanResourceFeeCriterion::new(100_000_000, 50);
        let args = json!({ "resource_fee_stroops": 50_000_000, "footprint_entries": 10 });
        let tool = make_tool("stellar_invoke");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(result.is_none(), "Soroban tool within caps should pass");
    }

    #[test]
    fn soroban_tool_exceeding_resource_fee_denies() {
        let store = PolicyStateStore::new();
        let criterion = SorobanResourceFeeCriterion::new(100_000_000, 50);
        let args = json!({ "resource_fee_stroops": 200_000_000, "footprint_entries": 10 });
        let tool = make_tool("stellar_invoke");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::EvaluationError { .. })),
            "exceeding resource fee should deny"
        );
    }

    #[test]
    fn soroban_tool_at_resource_fee_cap_passes() {
        let store = PolicyStateStore::new();
        let criterion = SorobanResourceFeeCriterion::new(1_000_000, 50);
        let args = json!({ "resource_fee_stroops": 1_000_000, "footprint_entries": 10 });
        let tool = make_tool("stellar_invoke");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "resource fee exactly equal to the cap should pass"
        );
    }

    #[test]
    fn soroban_tool_at_footprint_cap_passes() {
        let store = PolicyStateStore::new();
        let criterion = SorobanResourceFeeCriterion::new(1_000_000, 10);
        let args = json!({ "resource_fee_stroops": 100_000, "footprint_entries": 10 });
        let tool = make_tool("stellar_invoke");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            result.is_none(),
            "footprint_entries exactly equal to the cap should pass"
        );
    }

    #[test]
    fn soroban_tool_exceeding_footprint_entries_denies() {
        let store = PolicyStateStore::new();
        let criterion = SorobanResourceFeeCriterion::new(1_000_000, 10);
        let args = json!({ "resource_fee_stroops": 100_000, "footprint_entries": 11 });
        let tool = make_tool("stellar_invoke");
        let profile = make_profile();
        let ctx = make_ctx(&tool, &profile, &args, &store);
        let result = criterion.evaluate(&ctx).unwrap();
        assert!(
            matches!(result, Some(DenyReason::EvaluationError { .. })),
            "footprint_entries greater than the cap should deny"
        );
    }

    #[test]
    fn constructor_stores_both_fields() {
        let criterion = SorobanResourceFeeCriterion::new(42_000_000, 25);
        assert_eq!(criterion.max_resource_fee_stroops(), 42_000_000);
        assert_eq!(criterion.max_footprint_entries(), 25);
    }
}
