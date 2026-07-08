//! Shared amount-extraction helper for the pay/create-account tool family.
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
/// Reads a stroop amount from a `serde_json::Value`, tolerating both the
/// decimal-string wire encoding and a legacy JSON number (and rejecting a
/// negative value — every resolved-key consumer here is a non-negative
/// amount).
pub(crate) use crate::wire_stroops::value_as_stroops_i64;

/// Resolves the debit amount in stroops for `stellar_pay(_commit)` /
/// `stellar_create_account(_commit)` directly from `(tool_name, args)`.
///
/// This is the [`crate::policy::v1::EvalContext`]-free core the descriptor
/// derivation ([`crate::policy::v1::value::derive_value_class`]) calls before
/// an `EvalContext` exists.
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
pub(crate) fn resolve_pay_or_create_account_stroops(
    tool_name: &str,
    args: &serde_json::Value,
    caller: &str,
) -> Result<Option<i64>, PolicyError> {
    let (resolved_key, legacy_key) = match tool_name {
        "stellar_pay" | "stellar_pay_commit" => ("amount_stroops", "amount"),
        "stellar_create_account" | "stellar_create_account_commit" => {
            ("starting_balance_stroops", "starting_balance")
        }
        _ => return Ok(None),
    };

    if let Some(v) = args.get(resolved_key) {
        return value_as_stroops_i64(v).map(Some).ok_or_else(|| {
            PolicyError::CriterionEvaluationFailed {
                detail: format!(
                    "{caller}: field '{resolved_key}' present but not a valid stroop \
                     amount for tool '{tool_name}'"
                ),
            }
        });
    }

    if let Some(v) = args.get(legacy_key).and_then(|v| v.as_str()) {
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
        let args = json!({ "amount_stroops": "-100000000" });
        assert!(resolve_pay_or_create_account_stroops("stellar_pay", &args, "test").is_err());
    }

    #[test]
    fn pay_resolved_key_present_is_used() {
        let args = json!({ "amount_stroops": "100000000", "amount": "999 XLM" });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_pay", &args, "test").unwrap(),
            Some(100_000_000),
            "resolved key must win over the legacy key when both are present"
        );
    }

    #[test]
    fn pay_commit_resolved_key_only_no_legacy_key() {
        // Matches envelope_decode's authoritative_args shape exactly: no
        // "amount" key at all.
        let args = json!({ "source": "G...", "destination": "G...", "amount_stroops": "100000000", "asset": "XLM" });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_pay_commit", &args, "test").unwrap(),
            Some(100_000_000)
        );
    }

    #[test]
    fn pay_falls_back_to_legacy_amount_when_resolved_key_absent() {
        let args = json!({ "amount": "10 XLM", "asset": "native" });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_pay", &args, "test").unwrap(),
            Some(100_000_000)
        );
    }

    #[test]
    fn pay_version_crossing_numeric_amount_stroops_still_parses() {
        let args = json!({ "amount_stroops": 100_000_000 });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_pay", &args, "test").unwrap(),
            Some(100_000_000)
        );
    }

    #[test]
    fn create_account_resolved_key_only_matches_production_shape() {
        // Matches both simulate-time args_value AND commit-time
        // authoritative_args: only starting_balance_stroops, never
        // "starting_balance".
        let args = json!({ "starting_balance_stroops": "50000000" });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_create_account", &args, "test").unwrap(),
            Some(50_000_000)
        );
    }

    #[test]
    fn create_account_commit_resolved_key_only() {
        let args = json!({ "source": "G...", "destination": "G...", "starting_balance_stroops": "50000000" });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_create_account_commit", &args, "test")
                .unwrap(),
            Some(50_000_000)
        );
    }

    #[test]
    fn create_account_falls_back_to_legacy_starting_balance() {
        let args = json!({ "starting_balance": "5 XLM" });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_create_account", &args, "test").unwrap(),
            Some(50_000_000)
        );
    }

    #[test]
    fn unrecognised_tool_returns_ok_none() {
        let args = json!({});
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_balances", &args, "test").unwrap(),
            None
        );
    }

    #[test]
    fn neither_key_present_returns_ok_none() {
        let args = json!({ "asset": "native" });
        assert_eq!(
            resolve_pay_or_create_account_stroops("stellar_pay", &args, "test").unwrap(),
            None
        );
    }

    #[test]
    fn malformed_resolved_key_is_an_error_not_a_silent_fallback() {
        // A malformed resolved-key value must NOT silently fall back to the
        // legacy key (which could mask a genuine wire-shape bug) — it errors.
        let args = json!({ "amount_stroops": "not-a-number", "amount": "10 XLM" });
        assert!(resolve_pay_or_create_account_stroops("stellar_pay", &args, "test").is_err());
    }

    #[test]
    fn malformed_legacy_key_is_an_error() {
        let args = json!({ "amount": "not-a-number" });
        assert!(resolve_pay_or_create_account_stroops("stellar_pay", &args, "test").is_err());
    }
}
