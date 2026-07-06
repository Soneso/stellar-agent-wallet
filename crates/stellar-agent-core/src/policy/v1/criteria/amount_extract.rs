//! Shared amount-extraction helper for criteria that read a transaction's
//! debit amount from `EvalContext::args`.
//!
//! `args` is either the caller-supplied simulate-time `args_value` or the
//! HMAC-bound commit-time `authoritative_args`
//! ([`crate::envelope_decode::decode_authoritative_args`]). For
//! `stellar_pay(_commit)` and `stellar_create_account(_commit)` both shapes
//! always carry the resolved key (`amount_stroops` / `starting_balance_stroops`,
//! a decimal string). The legacy unit-string keys (`amount`, `starting_balance`)
//! are read only as a fallback, for callers whose args predate the resolved
//! key.

use crate::amount::StellarAmount;
use crate::policy::PolicyError;
use crate::policy::v1::EvalContext;
/// Reads a stroop amount from a `serde_json::Value`, tolerating both the
/// decimal-string wire encoding and a legacy JSON number (and rejecting a
/// negative value — every resolved-key consumer here is a non-negative
/// amount).
pub(crate) use crate::wire_stroops::value_as_stroops_i64;

/// Resolves the debit amount in stroops for `stellar_pay(_commit)` /
/// `stellar_create_account(_commit)`.
///
/// Tries the resolved key first (`amount_stroops` for pay, or
/// `starting_balance_stroops` for create_account — string-tolerant, number
/// tolerated for version-crossing). Falls back to the legacy unit-string key
/// (`amount` / `starting_balance`, a `"N.NNNNNNN XLM"` string) only when the
/// resolved key is absent.
///
/// Returns `Ok(None)` when the tool is not one of the two this function
/// understands, or when NEITHER key is present in `args` (both are expected
/// to be absent together only for a tool this function does not recognise;
/// for pay/create_account the resolved key is always present in produced
/// args).
///
/// # Errors
///
/// Returns [`PolicyError::CriterionEvaluationFailed`] when a present key does
/// not parse as a valid amount.
pub(crate) fn extract_pay_or_create_account_stroops(
    ctx: &EvalContext<'_>,
    caller: &'static str,
) -> Result<Option<i64>, PolicyError> {
    let tool_name = ctx.tool.name.as_str();
    let (resolved_key, legacy_key) = match tool_name {
        "stellar_pay" | "stellar_pay_commit" => ("amount_stroops", "amount"),
        "stellar_create_account" | "stellar_create_account_commit" => {
            ("starting_balance_stroops", "starting_balance")
        }
        _ => return Ok(None),
    };

    if let Some(v) = ctx.args.get(resolved_key) {
        return value_as_stroops_i64(v).map(Some).ok_or_else(|| {
            PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "{caller}: field '{resolved_key}' present but not a valid stroop \
                     amount for tool '{tool_name}'"
                ),
            }
        });
    }

    if let Some(v) = ctx.args.get(legacy_key).and_then(|v| v.as_str()) {
        let stroops = StellarAmount::parse_with_unit(v)
            .or_else(|_| StellarAmount::parse_stroops(v))
            .map(|a| a.as_stroops())
            .map_err(|e| PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "{caller}: failed to parse legacy field '{legacy_key}' value \
                     '{v}' for tool '{tool_name}': {e}"
                ),
            })?;
        return Ok(Some(stroops));
    }

    Ok(None)
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
        };
        ToolDescriptor::from_registration(&reg)
    }

    fn make_ctx<'a>(tool: &'a ToolDescriptor, args: &'a serde_json::Value) -> EvalContext<'a> {
        // `profile`/`state_store` are leaked intentionally for the 'static
        // lifetime this helper needs across many small tests; acceptable in a
        // unit-test-only helper.
        let profile: &'a Profile = Box::leak(Box::new(
            Profile::builder_testnet("alice", "acct", "n-svc", "n-acct").build(),
        ));
        let store: &'a PolicyStateStore = Box::leak(Box::new(PolicyStateStore::new()));
        EvalContext::new(tool, args, "alice", profile, store)
    }

    #[test]
    fn value_as_stroops_i64_reads_string() {
        assert_eq!(
            value_as_stroops_i64(&json!("9007199254740993")),
            Some(9_007_199_254_740_993)
        );
    }

    #[test]
    fn value_as_stroops_i64_reads_legacy_number() {
        assert_eq!(value_as_stroops_i64(&json!(42)), Some(42));
    }

    #[test]
    fn value_as_stroops_i64_rejects_malformed_string() {
        assert_eq!(value_as_stroops_i64(&json!("not-a-number")), None);
    }

    #[test]
    fn resolved_key_negative_value_is_an_error_not_a_silent_negative_amount() {
        // A negative resolved-key value is always forged/corrupted (pay and
        // create_account amounts are never negative); the shared reader's
        // `>= 0` guard turns it into "malformed", which this extractor
        // reports as an error rather than silently returning a negative stroop
        // amount.
        let tool = make_tool("stellar_pay");
        let args = json!({ "amount_stroops": "-100000000" });
        let ctx = make_ctx(&tool, &args);
        assert!(extract_pay_or_create_account_stroops(&ctx, "test").is_err());
    }

    #[test]
    fn pay_resolved_key_present_is_used() {
        let tool = make_tool("stellar_pay");
        let args = json!({ "amount_stroops": "100000000", "amount": "999 XLM" });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            Some(100_000_000),
            "resolved key must win over the legacy key when both are present"
        );
    }

    #[test]
    fn pay_commit_resolved_key_only_no_legacy_key() {
        // Matches envelope_decode's authoritative_args shape exactly: no
        // "amount" key at all.
        let tool = make_tool("stellar_pay_commit");
        let args = json!({ "source": "G...", "destination": "G...", "amount_stroops": "100000000", "asset": "XLM" });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            Some(100_000_000)
        );
    }

    #[test]
    fn pay_falls_back_to_legacy_amount_when_resolved_key_absent() {
        let tool = make_tool("stellar_pay");
        let args = json!({ "amount": "10 XLM", "asset": "native" });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            Some(100_000_000)
        );
    }

    #[test]
    fn pay_version_crossing_numeric_amount_stroops_still_parses() {
        let tool = make_tool("stellar_pay");
        let args = json!({ "amount_stroops": 100_000_000 });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            Some(100_000_000)
        );
    }

    #[test]
    fn create_account_resolved_key_only_matches_production_shape() {
        // Matches both simulate-time args_value AND commit-time
        // authoritative_args: only starting_balance_stroops, never
        // "starting_balance".
        let tool = make_tool("stellar_create_account");
        let args = json!({ "starting_balance_stroops": "50000000" });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            Some(50_000_000)
        );
    }

    #[test]
    fn create_account_commit_resolved_key_only() {
        let tool = make_tool("stellar_create_account_commit");
        let args = json!({ "source": "G...", "destination": "G...", "starting_balance_stroops": "50000000" });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            Some(50_000_000)
        );
    }

    #[test]
    fn create_account_falls_back_to_legacy_starting_balance() {
        let tool = make_tool("stellar_create_account");
        let args = json!({ "starting_balance": "5 XLM" });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            Some(50_000_000)
        );
    }

    #[test]
    fn unrecognised_tool_returns_ok_none() {
        let tool = make_tool("stellar_balances");
        let args = json!({});
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            None
        );
    }

    #[test]
    fn neither_key_present_returns_ok_none() {
        let tool = make_tool("stellar_pay");
        let args = json!({ "asset": "native" });
        let ctx = make_ctx(&tool, &args);
        assert_eq!(
            extract_pay_or_create_account_stroops(&ctx, "test").unwrap(),
            None
        );
    }

    #[test]
    fn malformed_resolved_key_is_an_error_not_a_silent_fallback() {
        // A malformed resolved-key value must NOT silently fall back to the
        // legacy key (which could mask a genuine wire-shape bug) — it errors.
        let tool = make_tool("stellar_pay");
        let args = json!({ "amount_stroops": "not-a-number", "amount": "10 XLM" });
        let ctx = make_ctx(&tool, &args);
        assert!(extract_pay_or_create_account_stroops(&ctx, "test").is_err());
    }

    #[test]
    fn malformed_legacy_key_is_an_error() {
        let tool = make_tool("stellar_pay");
        let args = json!({ "amount": "not-a-number" });
        let ctx = make_ctx(&tool, &args);
        assert!(extract_pay_or_create_account_stroops(&ctx, "test").is_err());
    }
}
