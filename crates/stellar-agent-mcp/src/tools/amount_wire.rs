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
/// Returns `rmcp::ErrorData::invalid_params` naming `field` and the expected
/// form when `s` is not a valid decimal `i128`. The message never repeats
/// `s`, because a refused argument can hold a secret pasted into the wrong
/// field.
pub(crate) fn parse_i128_field(field: &str, s: &str) -> Result<i128, ErrorData> {
    s.parse::<i128>()
        .map_err(|_| ErrorData::invalid_params(format!("{field}: not a valid decimal i128"), None))
}

/// Parses each element of a decimal-string `Vec` field to `i128`.
///
/// On the first parse failure, the error names `field` and the failing
/// index, for example `"amounts_desired[2]: not a valid decimal i128"`, so a
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
/// Returns `rmcp::ErrorData::invalid_params` naming `field` and the expected
/// form when `s` is not a valid decimal `i64`; the message never repeats `s`.
pub(crate) fn parse_stroops_i64_field(field: &str, s: &str) -> Result<i64, ErrorData> {
    s.parse::<i64>().map_err(|_| {
        ErrorData::invalid_params(format!("{field}: not a valid decimal i64 (stroops)"), None)
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
/// Returns `rmcp::ErrorData::invalid_params` naming `field` and the expected
/// form when `s` is not a valid non-negative decimal `u64`; the message never
/// repeats `s`.
pub(crate) fn parse_stroops_u64_field(field: &str, s: &str) -> Result<u64, ErrorData> {
    s.parse::<u64>().map_err(|_| {
        ErrorData::invalid_params(
            format!("{field}: not a valid non-negative decimal u64 (stroops)"),
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

    enum ErrCheck {
        Any,
        Exact {
            message: &'static str,
            forbidden: &'static str,
        },
    }

    /// `parse_i128_field` parses valid decimal strings exactly and rejects
    /// malformed or out-of-range inputs without echoing raw values.
    #[test]
    fn parse_i128_field_parses_valid_and_rejects_invalid_decimals() {
        let cases = [
            (
                "ordinary_decimal",
                "qty_in",
                "250000000".to_owned(),
                Ok(250_000_000_i128),
            ),
            ("negative_decimal", "qty_in", "-5".to_owned(), Ok(-5)),
            ("explicit_plus_sign", "qty_in", "+5".to_owned(), Ok(5)),
            (
                "above_f64_precision_limit",
                "qty_in",
                "9007199254740993".to_owned(),
                Ok(9_007_199_254_740_993_i128),
            ),
            ("i128_min", "qty_in", i128::MIN.to_string(), Ok(i128::MIN)),
            ("i128_max", "qty_in", i128::MAX.to_string(), Ok(i128::MAX)),
            ("leading_zeros", "qty_in", "007".to_owned(), Ok(7)),
            (
                "surrounding_whitespace_both",
                "qty_in",
                " 5 ".to_owned(),
                Err(ErrCheck::Any),
            ),
            (
                "surrounding_whitespace_trailing",
                "qty_in",
                "5 ".to_owned(),
                Err(ErrCheck::Any),
            ),
            (
                "surrounding_whitespace_leading",
                "qty_in",
                " 5".to_owned(),
                Err(ErrCheck::Any),
            ),
            (
                "decimal_point",
                "qty_in",
                "1.5".to_owned(),
                Err(ErrCheck::Any),
            ),
            (
                "exponent_notation",
                "qty_in",
                "1e9".to_owned(),
                Err(ErrCheck::Any),
            ),
            ("empty_string", "qty_in", String::new(), Err(ErrCheck::Any)),
            (
                "malformed_sign",
                "qty_in",
                "+-3".to_owned(),
                Err(ErrCheck::Any),
            ),
            (
                "overflow_beyond_i128_max",
                "qty_in",
                format!("{}0", i128::MAX),
                Err(ErrCheck::Any),
            ),
            (
                "underflow_beyond_i128_min",
                "qty_in",
                format!("{}0", i128::MIN),
                Err(ErrCheck::Any),
            ),
            (
                "error_names_field_not_raw_value",
                "qty_out_min",
                "1.5".to_owned(),
                Err(ErrCheck::Exact {
                    message: "qty_out_min: not a valid decimal i128",
                    forbidden: "1.5",
                }),
            ),
        ];

        for (name, field, input, expected) in cases {
            let res = parse_i128_field(field, &input);
            match expected {
                Ok(want) => {
                    assert!(res.is_ok(), "case {name}: expected Ok({want}), got {res:?}");
                    if let Ok(got) = res {
                        assert_eq!(got, want, "case {name}");
                    }
                }
                Err(check) => {
                    assert!(res.is_err(), "case {name}: expected Err, got {res:?}");
                    if let (
                        Err(err),
                        ErrCheck::Exact {
                            message: want_msg,
                            forbidden,
                        },
                    ) = (res, check)
                    {
                        let msg = err.message.to_string();
                        assert_eq!(msg, want_msg, "case {name}");
                        assert!(
                            !msg.contains(forbidden),
                            "case {name}: error must not echo the raw value: {msg}"
                        );
                    }
                }
            }
        }
    }

    /// `parse_i128_vec_field` parses every element in order, accepts empty
    /// slices, and names the failing element index on invalid entries.
    #[test]
    fn parse_i128_vec_field_parses_elements_and_names_failing_index() {
        struct VecCase {
            name: &'static str,
            raw: &'static [&'static str],
            expected: Result<Vec<i128>, &'static str>,
        }

        let cases = [
            VecCase {
                name: "all_valid",
                raw: &["1", "2", "3"],
                expected: Ok(vec![1, 2, 3]),
            },
            VecCase {
                name: "invalid_element_names_index",
                raw: &["1", "not-a-number", "3"],
                expected: Err("amounts_desired[1]"),
            },
            VecCase {
                name: "empty_slice",
                raw: &[],
                expected: Ok(Vec::new()),
            },
        ];

        for case in cases {
            let name = case.name;
            let values: Vec<String> = case.raw.iter().map(|s| (*s).to_owned()).collect();
            let res = parse_i128_vec_field("amounts_desired", &values);
            match case.expected {
                Ok(want) => {
                    assert!(
                        res.is_ok(),
                        "case {name}: expected Ok({want:?}), got {res:?}"
                    );
                    if let Ok(got) = res {
                        assert_eq!(got, want, "case {name}");
                    }
                }
                Err(want_substr) => {
                    assert!(res.is_err(), "case {name}: expected Err, got {res:?}");
                    if let Err(err) = res {
                        let msg = err.message.to_string();
                        assert!(
                            msg.contains(want_substr),
                            "case {name}: error must name the failing index: {msg}"
                        );
                    }
                }
            }
        }
    }

    // ── parse_stroops_i64_field / parse_stroops_u64_field ──────────────────

    /// `parse_stroops_i64_field` parses signed `i64` decimals across the full
    /// range and rejects invalid inputs without echoing raw values.
    #[test]
    fn parse_stroops_i64_field_parses_valid_and_rejects_invalid_decimals() {
        let cases = [
            (
                "ordinary_decimal",
                "amount_stroops",
                "250000000".to_owned(),
                Ok(250_000_000_i64),
            ),
            ("negative_decimal", "limit_stroops", "-5".to_owned(), Ok(-5)),
            (
                "i64_max",
                "limit_stroops",
                i64::MAX.to_string(),
                Ok(i64::MAX),
            ),
            (
                "i64_min",
                "limit_stroops",
                i64::MIN.to_string(),
                Ok(i64::MIN),
            ),
            (
                "overflow_beyond_i64_max",
                "limit_stroops",
                format!("{}0", i64::MAX),
                Err(ErrCheck::Any),
            ),
            (
                "decimal_point",
                "amount_stroops",
                "1.5".to_owned(),
                Err(ErrCheck::Any),
            ),
            (
                "empty_string",
                "amount_stroops",
                String::new(),
                Err(ErrCheck::Any),
            ),
            (
                "error_names_field_not_raw_value",
                "limit_stroops",
                "1.5".to_owned(),
                Err(ErrCheck::Exact {
                    message: "limit_stroops: not a valid decimal i64 (stroops)",
                    forbidden: "1.5",
                }),
            ),
        ];

        for (name, field, input, expected) in cases {
            let res = parse_stroops_i64_field(field, &input);
            match expected {
                Ok(want) => {
                    assert!(res.is_ok(), "case {name}: expected Ok({want}), got {res:?}");
                    if let Ok(got) = res {
                        assert_eq!(got, want, "case {name}");
                    }
                }
                Err(check) => {
                    assert!(res.is_err(), "case {name}: expected Err, got {res:?}");
                    if let (
                        Err(err),
                        ErrCheck::Exact {
                            message: want_msg,
                            forbidden,
                        },
                    ) = (res, check)
                    {
                        let msg = err.message.to_string();
                        assert_eq!(msg, want_msg, "case {name}");
                        assert!(
                            !msg.contains(forbidden),
                            "case {name}: error must not echo the raw value: {msg}"
                        );
                    }
                }
            }
        }
    }

    /// `parse_stroops_i64_opt_field` maps `None` to `Ok(None)`, parses valid
    /// `Some` values, and rejects malformed `Some` values.
    #[test]
    fn parse_stroops_i64_opt_field_handles_none_valid_and_invalid() {
        let cases = [
            ("none", None, Ok(None)),
            ("some_valid", Some("42"), Ok(Some(42_i64))),
            ("some_invalid", Some("nope"), Err(())),
        ];

        for (name, input, expected) in cases {
            let res = parse_stroops_i64_opt_field("limit_stroops", input);
            match expected {
                Ok(want) => {
                    assert!(
                        res.is_ok(),
                        "case {name}: expected Ok({want:?}), got {res:?}"
                    );
                    if let Ok(got) = res {
                        assert_eq!(got, want, "case {name}");
                    }
                }
                Err(()) => {
                    assert!(res.is_err(), "case {name}: expected Err, got {res:?}");
                }
            }
        }
    }

    /// `parse_stroops_u64_field` parses unsigned `u64` decimals up to `u64::MAX`
    /// and rejects negative, fractional, and empty inputs.
    #[test]
    fn parse_stroops_u64_field_parses_valid_and_rejects_invalid_decimals() {
        let cases = [
            (
                "ordinary_decimal",
                "250000000".to_owned(),
                Ok(250_000_000_u64),
            ),
            ("negative", "-5".to_owned(), Err(())),
            ("u64_max", u64::MAX.to_string(), Ok(u64::MAX)),
            ("decimal_point", "1.5".to_owned(), Err(())),
            ("empty_string", String::new(), Err(())),
        ];

        for (name, input, expected) in cases {
            let res = parse_stroops_u64_field("amount_in_stroops", &input);
            match expected {
                Ok(want) => {
                    assert!(res.is_ok(), "case {name}: expected Ok({want}), got {res:?}");
                    if let Ok(got) = res {
                        assert_eq!(got, want, "case {name}");
                    }
                }
                Err(()) => {
                    assert!(res.is_err(), "case {name}: expected Err, got {res:?}");
                }
            }
        }
    }
}
