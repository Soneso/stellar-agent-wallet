//! Shared decimal-string <-> `i128` wire-encoding helpers for MCP tool args.
//!
//! Every raw on-chain `i128` token-quantity field on the MCP tool wire is
//! JSON-typed as a decimal string, not a JSON number: `serde_json::from_value`
//! backs JSON numbers with `f64`, which cannot represent an `i128` exactly
//! above `2^53`, and no standard-conforming JSON parser round-trips an
//! integer literal past that bound either. A raw JSON number for one of these
//! fields is REJECTED — the field is String-typed, so the schema itself
//! refuses a number — rather than silently accepted and possibly corrupted
//! client-side before the server ever sees it.
//!
//! This module generalises the parse-at-use error shape already established
//! by `stellar_rule_create.policies[].limit_stroops` (`rule_create.rs`) and
//! both x402 tools (`amount: String` end-to-end). The same convention
//! applies to every raw `i64` Stellar stroop field (payment amounts,
//! trustline limits, starting balances): [`parse_stroops_i64_field`] and
//! [`parse_stroops_u64_field`] are the `i64`/`u64`-width siblings of
//! [`parse_i128_field`], and [`value_as_stroops_i64`] reads a stroop field
//! back out of a `serde_json::Value` that may carry either the current
//! decimal-string encoding or a legacy JSON number, for callers decoding
//! [`crate::server::WalletServer`]-internal values that cross a version
//! boundary (e.g. [`stellar_agent_core::envelope_decode::decode_authoritative_args`]
//! output).
//!
//! # Dispatch-safety
//!
//! The toolset dispatch matrix (`route_to_matrix_tool`) deserialises tool
//! args via `serde_json::from_value`, which cannot decode an `i128`-typed
//! field at all. String-typed fields are what make an args struct eligible
//! for toolset dispatch; every MCP args struct migrated to use this module
//! becomes eligible-by-shape as a result, whether or not it is currently
//! wired into the matrix.

use rmcp::ErrorData;

/// Parses a single decimal-string field to `i128`.
///
/// Accepts an optional leading `-` or `+` sign followed by ASCII digits only
/// (leading zeros permitted, e.g. `"007"` parses to `7`); rejects
/// surrounding whitespace, decimal points, exponents, empty input, and any
/// value outside `i128::MIN..=i128::MAX`. This function only proves `s`
/// denotes a well-formed decimal integer — domain constraints such as
/// non-negativity are enforced by the caller after a successful parse.
///
/// # Errors
///
/// Returns `rmcp::ErrorData::invalid_params` naming `field` and the raw
/// value when `s` is not a valid decimal `i128`.
pub(crate) fn parse_i128_field(field: &str, s: &str) -> Result<i128, ErrorData> {
    s.parse::<i128>().map_err(|_| {
        ErrorData::invalid_params(format!("{field}: not a valid decimal i128: {s:?}"), None)
    })
}

/// Parses each element of a decimal-string `Vec` field to `i128`.
///
/// On the first parse failure, the error names `field` and the failing
/// index — e.g. `"amounts_desired[2]: not a valid decimal i128: ..."` — so a
/// caller with a long vector can locate the bad entry without a linear scan
/// of the raw request.
///
/// # Errors
///
/// Returns `rmcp::ErrorData::invalid_params` as described in
/// [`parse_i128_field`], with the field name suffixed by the failing index.
pub(crate) fn parse_i128_vec_field(field: &str, v: &[String]) -> Result<Vec<i128>, ErrorData> {
    v.iter()
        .enumerate()
        .map(|(idx, s)| parse_i128_field(&format!("{field}[{idx}]"), s))
        .collect()
}

/// Parses a single decimal-string field to `i64` (a raw Stellar stroop
/// amount).
///
/// Accepts an optional leading `-` or `+` sign followed by ASCII digits
/// only, identically to [`parse_i128_field`] but bounded to `i64::MIN..=
/// i64::MAX` — the width of every classic-operation amount and limit field
/// in Stellar XDR (`Payment.amount`, `ChangeTrustOp.limit`,
/// `CreateAccountOp.starting_balance`). This function only proves `s`
/// denotes a well-formed decimal `i64` — domain constraints such as
/// non-negativity are enforced by the caller after a successful parse, the
/// same discipline as [`parse_i128_field`].
///
/// # Errors
///
/// Returns `rmcp::ErrorData::invalid_params` naming `field` and the raw
/// value when `s` is not a valid decimal `i64`.
pub(crate) fn parse_stroops_i64_field(field: &str, s: &str) -> Result<i64, ErrorData> {
    s.parse::<i64>().map_err(|_| {
        ErrorData::invalid_params(
            format!("{field}: not a valid decimal i64 (stroops): {s:?}"),
            None,
        )
    })
}

/// Parses an optional decimal-string field to `Option<i64>` via
/// [`parse_stroops_i64_field`]. `None` maps to `Ok(None)`.
///
/// # Errors
///
/// Returns the same error as [`parse_stroops_i64_field`] when `s` is
/// `Some` and not a valid decimal `i64`.
pub(crate) fn parse_stroops_i64_opt_field(
    field: &str,
    s: Option<&str>,
) -> Result<Option<i64>, ErrorData> {
    s.map(|s| parse_stroops_i64_field(field, s)).transpose()
}

/// Parses a single decimal-string field to `u64` (a raw, structurally
/// non-negative Stellar stroop amount).
///
/// Used where the field's domain never permits a sign — e.g. an input
/// amount before its `<= i64::MAX` bound is checked — so the non-negativity
/// guarantee is carried by this parse: a decimal string has no type-level
/// sign restriction on its own.
///
/// # Errors
///
/// Returns `rmcp::ErrorData::invalid_params` naming `field` and the raw
/// value when `s` is not a valid non-negative decimal `u64`.
pub(crate) fn parse_stroops_u64_field(field: &str, s: &str) -> Result<u64, ErrorData> {
    s.parse::<u64>().map_err(|_| {
        ErrorData::invalid_params(
            format!("{field}: not a valid non-negative decimal u64 (stroops): {s:?}"),
            None,
        )
    })
}

/// Reads a stroop amount from a decoded `serde_json::Value`, tolerating
/// both the current decimal-string wire encoding and a legacy JSON number.
///
/// `stellar_agent_core::envelope_decode::decode_authoritative_args` emits
/// `amount_stroops` / `starting_balance_stroops` / `limit_stroops` as decimal
/// strings; this reader accepts both forms so a caller on either side of the
/// wire-format migration can decode a value produced by either an old or a
/// new build of this crate. Delegates to the single shared implementation in
/// [`stellar_agent_core::wire_stroops::value_as_stroops_i64`], which also
/// rejects a negative value (every consumer here is a non-negative amount or
/// a `0..=i64::MAX` limit).
pub(crate) use stellar_agent_core::wire_stroops::value_as_stroops_i64;

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
    use super::*;

    #[test]
    fn parses_ordinary_decimal() {
        assert_eq!(
            parse_i128_field("qty_in", "250000000").unwrap(),
            250_000_000
        );
    }

    #[test]
    fn parses_negative_decimal_leaving_domain_check_to_caller() {
        // The wire parser itself does not reject sign; a positivity guard
        // downstream (e.g. dex_trade.rs's qty_in check) is what refuses it.
        assert_eq!(parse_i128_field("qty_in", "-5").unwrap(), -5);
    }

    #[test]
    fn parses_explicit_plus_sign_to_the_correct_value() {
        // `str::parse::<i128>` accepts a leading `+`; the parsed value is
        // identical to the unsigned form. JSON numbers cannot carry a `+`,
        // so this only widens what a well-formed decimal STRING may look
        // like — it never changes a value.
        assert_eq!(parse_i128_field("qty_in", "+5").unwrap(), 5);
    }

    #[test]
    fn parses_value_above_f64_precision_limit_exactly() {
        // 2^53 + 1: the first integer an f64-backed JSON number cannot
        // represent exactly. The decimal-string parser must round-trip it
        // byte-for-byte.
        let s = "9007199254740993";
        assert_eq!(
            parse_i128_field("qty_in", s).unwrap(),
            9_007_199_254_740_993_i128
        );
    }

    #[test]
    fn parses_i128_min_exactly() {
        let s = i128::MIN.to_string();
        assert_eq!(parse_i128_field("qty_in", &s).unwrap(), i128::MIN);
    }

    #[test]
    fn parses_i128_max_exactly() {
        let s = i128::MAX.to_string();
        assert_eq!(parse_i128_field("qty_in", &s).unwrap(), i128::MAX);
    }

    #[test]
    fn parses_leading_zeros_to_the_correct_value() {
        assert_eq!(parse_i128_field("qty_in", "007").unwrap(), 7);
    }

    #[test]
    fn rejects_surrounding_whitespace() {
        assert!(parse_i128_field("qty_in", " 5 ").is_err());
        assert!(parse_i128_field("qty_in", "5 ").is_err());
        assert!(parse_i128_field("qty_in", " 5").is_err());
    }

    #[test]
    fn rejects_decimal_point() {
        assert!(parse_i128_field("qty_in", "1.5").is_err());
    }

    #[test]
    fn rejects_exponent_notation() {
        assert!(parse_i128_field("qty_in", "1e9").is_err());
    }

    #[test]
    fn rejects_empty_string() {
        assert!(parse_i128_field("qty_in", "").is_err());
    }

    #[test]
    fn rejects_malformed_sign() {
        assert!(parse_i128_field("qty_in", "+-3").is_err());
    }

    #[test]
    fn rejects_overflow_beyond_i128_max() {
        let overflow = format!("{}0", i128::MAX); // one digit past MAX
        assert!(parse_i128_field("qty_in", &overflow).is_err());
    }

    #[test]
    fn rejects_underflow_beyond_i128_min() {
        let underflow = format!("{}0", i128::MIN); // one digit past MIN
        assert!(parse_i128_field("qty_in", &underflow).is_err());
    }

    #[test]
    fn error_message_names_the_field_and_the_raw_value() {
        let err = parse_i128_field("qty_out_min", "1.5").unwrap_err();
        let msg = err.message.to_string();
        assert!(
            msg.contains("qty_out_min"),
            "error must name the field: {msg}"
        );
        assert!(msg.contains("1.5"), "error must echo the raw value: {msg}");
    }

    #[test]
    fn vec_field_parses_every_element() {
        let v = vec!["1".to_owned(), "2".to_owned(), "3".to_owned()];
        assert_eq!(
            parse_i128_vec_field("amounts_desired", &v).unwrap(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn vec_field_names_the_failing_index() {
        let v = vec!["1".to_owned(), "not-a-number".to_owned(), "3".to_owned()];
        let err = parse_i128_vec_field("amounts_desired", &v).unwrap_err();
        let msg = err.message.to_string();
        assert!(
            msg.contains("amounts_desired[1]"),
            "error must name the failing index: {msg}"
        );
    }

    #[test]
    fn empty_vec_field_parses_to_empty_vec() {
        assert_eq!(
            parse_i128_vec_field("amounts_desired", &[]).unwrap(),
            Vec::<i128>::new()
        );
    }

    // ── parse_stroops_i64_field / parse_stroops_u64_field ──────────────────

    #[test]
    fn stroops_i64_parses_ordinary_decimal() {
        assert_eq!(
            parse_stroops_i64_field("amount_stroops", "250000000").unwrap(),
            250_000_000
        );
    }

    #[test]
    fn stroops_i64_parses_negative_leaving_domain_check_to_caller() {
        assert_eq!(parse_stroops_i64_field("limit_stroops", "-5").unwrap(), -5);
    }

    #[test]
    fn stroops_i64_parses_i64_max_exactly() {
        let s = i64::MAX.to_string();
        assert_eq!(
            parse_stroops_i64_field("limit_stroops", &s).unwrap(),
            i64::MAX
        );
    }

    #[test]
    fn stroops_i64_parses_i64_min_exactly() {
        let s = i64::MIN.to_string();
        assert_eq!(
            parse_stroops_i64_field("limit_stroops", &s).unwrap(),
            i64::MIN
        );
    }

    #[test]
    fn stroops_i64_rejects_overflow_beyond_i64_max() {
        let overflow = format!("{}0", i64::MAX);
        assert!(parse_stroops_i64_field("limit_stroops", &overflow).is_err());
    }

    #[test]
    fn stroops_i64_rejects_decimal_point() {
        assert!(parse_stroops_i64_field("amount_stroops", "1.5").is_err());
    }

    #[test]
    fn stroops_i64_rejects_empty_string() {
        assert!(parse_stroops_i64_field("amount_stroops", "").is_err());
    }

    #[test]
    fn stroops_i64_error_names_field_and_raw_value() {
        let err = parse_stroops_i64_field("limit_stroops", "1.5").unwrap_err();
        let msg = err.message.to_string();
        assert!(msg.contains("limit_stroops"));
        assert!(msg.contains("1.5"));
    }

    #[test]
    fn stroops_i64_opt_none_maps_to_ok_none() {
        assert_eq!(
            parse_stroops_i64_opt_field("limit_stroops", None).unwrap(),
            None
        );
    }

    #[test]
    fn stroops_i64_opt_some_parses() {
        assert_eq!(
            parse_stroops_i64_opt_field("limit_stroops", Some("42")).unwrap(),
            Some(42)
        );
    }

    #[test]
    fn stroops_i64_opt_some_invalid_errors() {
        assert!(parse_stroops_i64_opt_field("limit_stroops", Some("nope")).is_err());
    }

    #[test]
    fn stroops_u64_parses_ordinary_decimal() {
        assert_eq!(
            parse_stroops_u64_field("amount_in_stroops", "250000000").unwrap(),
            250_000_000
        );
    }

    #[test]
    fn stroops_u64_rejects_negative() {
        assert!(parse_stroops_u64_field("amount_in_stroops", "-5").is_err());
    }

    #[test]
    fn stroops_u64_parses_u64_max_exactly() {
        let s = u64::MAX.to_string();
        assert_eq!(
            parse_stroops_u64_field("amount_in_stroops", &s).unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn stroops_u64_rejects_decimal_point() {
        assert!(parse_stroops_u64_field("amount_in_stroops", "1.5").is_err());
    }

    #[test]
    fn stroops_u64_rejects_empty_string() {
        assert!(parse_stroops_u64_field("amount_in_stroops", "").is_err());
    }

    // ── value_as_stroops_i64 ─────────────────────────────────────────────────

    #[test]
    fn value_as_stroops_i64_reads_string() {
        let v = serde_json::json!("9007199254740993");
        assert_eq!(value_as_stroops_i64(&v), Some(9_007_199_254_740_993_i64));
    }

    #[test]
    fn value_as_stroops_i64_reads_number() {
        let v = serde_json::json!(42);
        assert_eq!(value_as_stroops_i64(&v), Some(42_i64));
    }

    #[test]
    fn value_as_stroops_i64_rejects_malformed_string() {
        let v = serde_json::json!("not-a-number");
        assert_eq!(value_as_stroops_i64(&v), None);
    }

    #[test]
    fn value_as_stroops_i64_rejects_null() {
        assert_eq!(value_as_stroops_i64(&serde_json::Value::Null), None);
    }

    #[test]
    fn value_as_stroops_i64_string_round_trips_i64_max() {
        let s = i64::MAX.to_string();
        let v = serde_json::json!(s);
        assert_eq!(value_as_stroops_i64(&v), Some(i64::MAX));
    }

    #[test]
    fn value_as_stroops_i64_rejects_negative() {
        // Delegated to `stellar_agent_core::wire_stroops::value_as_stroops_i64`:
        // every reader call site in this crate (amount_stroops,
        // starting_balance_stroops, limit_stroops) is a non-negative amount or
        // a 0..=MAX limit, so a negative value is always forged/corrupted.
        assert_eq!(value_as_stroops_i64(&serde_json::json!("-1")), None);
        assert_eq!(value_as_stroops_i64(&serde_json::json!(-1)), None);
    }
}
