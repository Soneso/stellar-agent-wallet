//! `serde(with = ...)` boundary encoders for stroop-denominated struct
//! fields.
//!
//! A JSON number never carries a value-denominated quantity on any
//! machine-readable wire: `serde_json::from_value` backs a JSON number with
//! `f64`, which cannot represent an `i64`/`u32` stroop amount exactly once it
//! exceeds `2^53`. The modules here let a struct keep its internal numeric
//! field type (so arithmetic call sites are unaffected) while its `Serialize`
//! impl emits a decimal string. `Deserialize` accepts either a decimal
//! string or a legacy JSON number, so a value produced by an older build of
//! the same struct still parses.
//!
//! Apply via `#[serde(with = "stellar_agent_core::wire_stroops::i64")]` (or
//! the sibling modules below) on the field itself.

use serde::{Deserialize, Deserializer, Serializer};

/// Either form a stroop field may arrive in when deserializing: the current
/// decimal-string encoding, or a legacy JSON number.
#[derive(Deserialize)]
#[serde(untagged)]
enum StrOrNum<N> {
    Str(String),
    Num(N),
}

/// Boundary encoder for an `i64` stroop field.
pub mod i64 {
    use super::{Deserialize, Deserializer, Serializer, StrOrNum};

    /// Serializes `value` as a decimal string.
    ///
    /// # Errors
    ///
    /// Never fails; infallible for any `i64` value.
    pub fn serialize<S>(value: &i64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    /// Deserializes an `i64` from either a decimal string or a JSON number.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when the value is neither a
    /// well-formed decimal `i64` string nor an in-range JSON number.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<i64, D::Error>
    where
        D: Deserializer<'de>,
    {
        match StrOrNum::<i64>::deserialize(deserializer)? {
            StrOrNum::Str(s) => s.parse::<i64>().map_err(serde::de::Error::custom),
            StrOrNum::Num(n) => Ok(n),
        }
    }
}

/// Boundary encoder for an `Option<i64>` stroop field.
pub mod i64_opt {
    use super::{Deserialize, Deserializer, Serializer, StrOrNum};

    /// Serializes `value` as `null` or a decimal string.
    ///
    /// # Errors
    ///
    /// Never fails; infallible for any `Option<i64>` value.
    pub fn serialize<S>(value: &Option<i64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.collect_str(v),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an `Option<i64>` from `null`, a decimal string, or a
    /// JSON number.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when a present value is neither a
    /// well-formed decimal `i64` string nor an in-range JSON number.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<StrOrNum<i64>>::deserialize(deserializer)? {
            None => Ok(None),
            Some(StrOrNum::Str(s)) => s.parse::<i64>().map(Some).map_err(serde::de::Error::custom),
            Some(StrOrNum::Num(n)) => Ok(Some(n)),
        }
    }
}

/// Boundary encoder for a `u32` stroop field (e.g. classic per-operation
/// fees).
pub mod u32 {
    use super::{Deserialize, Deserializer, Serializer, StrOrNum};

    /// Serializes `value` as a decimal string.
    ///
    /// # Errors
    ///
    /// Never fails; infallible for any `u32` value.
    pub fn serialize<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    /// Deserializes a `u32` from either a decimal string or a JSON number.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when the value is neither a
    /// well-formed non-negative decimal `u32` string nor an in-range JSON
    /// number.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        match StrOrNum::<u32>::deserialize(deserializer)? {
            StrOrNum::Str(s) => s.parse::<u32>().map_err(serde::de::Error::custom),
            StrOrNum::Num(n) => Ok(n),
        }
    }
}

/// Boundary encoder for an `Option<u32>` stroop field.
pub mod u32_opt {
    use super::{Deserialize, Deserializer, Serializer, StrOrNum};

    /// Serializes `value` as `null` or a decimal string.
    ///
    /// # Errors
    ///
    /// Never fails; infallible for any `Option<u32>` value.
    pub fn serialize<S>(value: &Option<u32>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(v) => serializer.collect_str(v),
            None => serializer.serialize_none(),
        }
    }

    /// Deserializes an `Option<u32>` from `null`, a decimal string, or a
    /// JSON number.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when a present value is neither a
    /// well-formed non-negative decimal `u32` string nor an in-range JSON
    /// number.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<StrOrNum<u32>>::deserialize(deserializer)? {
            None => Ok(None),
            Some(StrOrNum::Str(s)) => s.parse::<u32>().map(Some).map_err(serde::de::Error::custom),
            Some(StrOrNum::Num(n)) => Ok(Some(n)),
        }
    }
}

/// Boundary encoder for a `u64` stroop field.
pub mod u64 {
    use super::{Deserialize, Deserializer, Serializer, StrOrNum};

    /// Serializes `value` as a decimal string.
    ///
    /// # Errors
    ///
    /// Never fails; infallible for any `u64` value.
    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    /// Deserializes a `u64` from either a decimal string or a JSON number.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error when the value is neither a
    /// well-formed non-negative decimal `u64` string nor an in-range JSON
    /// number.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        match StrOrNum::<u64>::deserialize(deserializer)? {
            StrOrNum::Str(s) => s.parse::<u64>().map_err(serde::de::Error::custom),
            StrOrNum::Num(n) => Ok(n),
        }
    }
}

/// Reads a stroop amount out of a decoded `serde_json::Value`, tolerating
/// both the current decimal-string wire encoding and a legacy JSON number.
///
/// Used by readers that pull a stroop-denominated field back out of a
/// `serde_json::Value` obtained some other way than through a typed
/// `Deserialize` derive (e.g. a policy-criterion `args: &serde_json::Value`,
/// or an MCP commit handler re-deriving a field from
/// [`crate::envelope_decode::decode_authoritative_args`]'s output).
///
/// Every legitimate stroop field read via this function is a non-negative
/// amount or a `0..=i64::MAX` limit; a negative value is therefore always a
/// forged or corrupted payload rather than a valid domain value, so it is
/// treated the same as "absent" — this returns `None`, and the caller's own
/// "field missing or malformed" error path applies.
#[must_use]
pub fn value_as_stroops_i64(value: &serde_json::Value) -> Option<i64> {
    let parsed = match value {
        serde_json::Value::String(s) => s.parse::<i64>().ok()?,
        _ => value.as_i64()?,
    };
    (parsed >= 0).then_some(parsed)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "test-only; panics acceptable in unit tests"
    )]

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct I64Wrapper {
        #[serde(with = "crate::wire_stroops::i64")]
        v: i64,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct I64OptWrapper {
        #[serde(with = "crate::wire_stroops::i64_opt")]
        v: Option<i64>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct U32Wrapper {
        #[serde(with = "crate::wire_stroops::u32")]
        v: u32,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct U32OptWrapper {
        #[serde(with = "crate::wire_stroops::u32_opt")]
        v: Option<u32>,
    }

    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct U64Wrapper {
        #[serde(with = "crate::wire_stroops::u64")]
        v: u64,
    }

    #[test]
    fn i64_serializes_as_decimal_string() {
        let w = I64Wrapper {
            v: 9_007_199_254_740_993,
        };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], "9007199254740993");
    }

    #[test]
    fn i64_deserializes_from_decimal_string() {
        let json = serde_json::json!({ "v": "9007199254740993" });
        let w: I64Wrapper = serde_json::from_value(json).unwrap();
        assert_eq!(w.v, 9_007_199_254_740_993);
    }

    #[test]
    fn i64_deserializes_from_legacy_number() {
        let json = serde_json::json!({ "v": 42 });
        let w: I64Wrapper = serde_json::from_value(json).unwrap();
        assert_eq!(w.v, 42);
    }

    #[test]
    fn i64_round_trips_i64_min_and_max() {
        for v in [i64::MIN, i64::MAX, 0] {
            let w = I64Wrapper { v };
            let json = serde_json::to_value(&w).unwrap();
            let round_tripped: I64Wrapper = serde_json::from_value(json).unwrap();
            assert_eq!(round_tripped.v, v);
        }
    }

    #[test]
    fn i64_rejects_malformed_string() {
        let json = serde_json::json!({ "v": "not-a-number" });
        assert!(serde_json::from_value::<I64Wrapper>(json).is_err());
    }

    #[test]
    fn i64_opt_serializes_none_as_null() {
        let w = I64OptWrapper { v: None };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], serde_json::Value::Null);
    }

    #[test]
    fn i64_opt_round_trips_some() {
        let w = I64OptWrapper { v: Some(i64::MAX) };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], "9223372036854775807");
        let round_tripped: I64OptWrapper = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped.v, Some(i64::MAX));
    }

    #[test]
    fn i64_opt_deserializes_null_as_none() {
        let json = serde_json::json!({ "v": null });
        let w: I64OptWrapper = serde_json::from_value(json).unwrap();
        assert_eq!(w.v, None);
    }

    #[test]
    fn u32_round_trips_max() {
        let w = U32Wrapper { v: u32::MAX };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], u32::MAX.to_string());
        let round_tripped: U32Wrapper = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped.v, u32::MAX);
    }

    #[test]
    fn u32_deserializes_from_legacy_number() {
        let json = serde_json::json!({ "v": 100 });
        let w: U32Wrapper = serde_json::from_value(json).unwrap();
        assert_eq!(w.v, 100);
    }

    #[test]
    fn u32_rejects_negative_string() {
        let json = serde_json::json!({ "v": "-1" });
        assert!(serde_json::from_value::<U32Wrapper>(json).is_err());
    }

    #[test]
    fn u32_opt_serializes_none_as_null() {
        let w = U32OptWrapper { v: None };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], serde_json::Value::Null);
    }

    #[test]
    fn u32_opt_round_trips_some() {
        let w = U32OptWrapper { v: Some(250) };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], "250");
        let round_tripped: U32OptWrapper = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped.v, Some(250));
    }

    #[test]
    fn u32_opt_deserializes_from_legacy_number() {
        let json = serde_json::json!({ "v": 250 });
        let w: U32OptWrapper = serde_json::from_value(json).unwrap();
        assert_eq!(w.v, Some(250));
    }

    #[test]
    fn u64_round_trips_max() {
        let w = U64Wrapper { v: u64::MAX };
        let json = serde_json::to_value(&w).unwrap();
        assert_eq!(json["v"], u64::MAX.to_string());
        let round_tripped: U64Wrapper = serde_json::from_value(json).unwrap();
        assert_eq!(round_tripped.v, u64::MAX);
    }

    #[test]
    fn u64_deserializes_from_legacy_number() {
        let json = serde_json::json!({ "v": 100 });
        let w: U64Wrapper = serde_json::from_value(json).unwrap();
        assert_eq!(w.v, 100);
    }

    // ── value_as_stroops_i64 ─────────────────────────────────────────────────

    #[test]
    fn value_as_stroops_i64_reads_string() {
        let v = serde_json::json!("9007199254740993");
        assert_eq!(
            super::value_as_stroops_i64(&v),
            Some(9_007_199_254_740_993_i64)
        );
    }

    #[test]
    fn value_as_stroops_i64_reads_legacy_number() {
        let v = serde_json::json!(42);
        assert_eq!(super::value_as_stroops_i64(&v), Some(42_i64));
    }

    #[test]
    fn value_as_stroops_i64_rejects_malformed_string() {
        let v = serde_json::json!("not-a-number");
        assert_eq!(super::value_as_stroops_i64(&v), None);
    }

    #[test]
    fn value_as_stroops_i64_rejects_null() {
        assert_eq!(super::value_as_stroops_i64(&serde_json::Value::Null), None);
    }

    #[test]
    fn value_as_stroops_i64_string_round_trips_i64_max() {
        let s = i64::MAX.to_string();
        let v = serde_json::json!(s);
        assert_eq!(super::value_as_stroops_i64(&v), Some(i64::MAX));
    }

    #[test]
    fn value_as_stroops_i64_rejects_negative_string() {
        let v = serde_json::json!("-1");
        assert_eq!(
            super::value_as_stroops_i64(&v),
            None,
            "a negative value is always forged/corrupted for every current \
             consumer (non-negative amounts and 0..=MAX limits); treat it as absent"
        );
    }

    #[test]
    fn value_as_stroops_i64_rejects_negative_number() {
        let v = serde_json::json!(-1);
        assert_eq!(super::value_as_stroops_i64(&v), None);
    }

    #[test]
    fn value_as_stroops_i64_accepts_zero() {
        assert_eq!(
            super::value_as_stroops_i64(&serde_json::json!("0")),
            Some(0)
        );
        assert_eq!(super::value_as_stroops_i64(&serde_json::json!(0)), Some(0));
    }
}
