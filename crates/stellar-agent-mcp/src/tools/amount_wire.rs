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
//! both x402 tools (`amount: String` end-to-end).
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
}
